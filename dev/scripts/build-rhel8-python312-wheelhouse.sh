#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/dev/packages/rhel8.10-py312}"
REQUIREMENTS_FILE="$REPO_ROOT/dev/requirements-rhel8-runtime.txt"
UBI_IMAGE="${UBI_IMAGE:-registry.access.redhat.com/ubi8/python-312:latest}"
CONTAINER_ENGINE="${CONTAINER_ENGINE:-}"

if [ -z "$CONTAINER_ENGINE" ]; then
    if command -v podman >/dev/null 2>&1; then
        CONTAINER_ENGINE=podman
    elif command -v docker >/dev/null 2>&1; then
        CONTAINER_ENGINE=docker
    else
        echo "Error: install Podman or Docker to build the RHEL wheelhouse" >&2
        exit 1
    fi
fi

if ! "$CONTAINER_ENGINE" info >/dev/null 2>&1; then
    echo "Error: $CONTAINER_ENGINE is unavailable; start its Linux container service" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
STAGING_DIR="$(mktemp -d "${OUTPUT_DIR}.tmp.XXXXXX")"
trap 'rm -rf "$STAGING_DIR"' EXIT
"$CONTAINER_ENGINE" pull --platform linux/amd64 "$UBI_IMAGE"
IMAGE_ID=$("$CONTAINER_ENGINE" image inspect --format '{{.Id}}' "$UBI_IMAGE")
BUILD_DATE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

"$CONTAINER_ENGINE" run --rm --platform linux/amd64 --user 0:0 \
    --env BUILD_IMAGE="$UBI_IMAGE" \
    --env BUILD_IMAGE_ID="$IMAGE_ID" \
    --env BUILD_DATE="$BUILD_DATE" \
    -v "$REQUIREMENTS_FILE:/tmp/requirements.txt:ro" \
    -v "$STAGING_DIR:/wheelhouse:rw" \
    "$UBI_IMAGE" sh -ec '
        python -m venv /tmp/resolve
        /tmp/resolve/bin/python -m pip install --disable-pip-version-check -r /tmp/requirements.txt
        /tmp/resolve/bin/python -m pip freeze | sort > /wheelhouse/requirements.lock
        /tmp/resolve/bin/python -m pip download --disable-pip-version-check \
            --only-binary=:all: --dest /wheelhouse -r /wheelhouse/requirements.lock
        printf "TrapNinja Python dependency wheelhouse\\n\\nTarget: RHEL 8.10, x86_64, CPython 3.12\\nBuild date (UTC): %s\\nPython resolver: %s\\nRequirements source: dev/requirements-rhel8-runtime.txt\\nRedis client: omitted; cache disabled for this deployment profile\\nBuild image: %s\\nBuild image ID: %s\\nValidation: dependency wheels install and import offline; application tests and Redis integration are not covered by this check.\\n" \
            "$BUILD_DATE" "$(python --version 2>&1)" "$BUILD_IMAGE" "$BUILD_IMAGE_ID" > /wheelhouse/BUNDLE-INFO.txt
        cd /wheelhouse
        sha256sum ./*.whl requirements.lock BUNDLE-INFO.txt > SHA256SUMS
    '

find "$OUTPUT_DIR" -maxdepth 1 -type f \
    \( -name '*.whl' -o -name 'requirements.lock' -o -name 'BUNDLE-INFO.txt' -o -name 'SHA256SUMS' \) \
    -exec rm -f {} +
cp "$STAGING_DIR"/* "$OUTPUT_DIR/"

echo "Wheelhouse ready: $OUTPUT_DIR"
echo "Resolved package versions:"
cat "$OUTPUT_DIR/requirements.lock"
echo "Verify with: (cd '$OUTPUT_DIR' && sha256sum -c SHA256SUMS)"