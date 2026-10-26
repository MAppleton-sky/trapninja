#!/bin/bash
# =============================================================================
# TrapNinja Offline Package Installer for RHEL 8 / CentOS Stream 8
# =============================================================================
#
# Installs Python packages from local directory (for air-gapped systems)
#
# Usage:
#   ./install-packages.sh [packages-dir]
#
# Prerequisites:
#   - Python 3.12 installed: dnf install -y python3.12 python3.12-pip
#   - This wheelhouse contains binary wheels; a compiler is not required
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGES_DIR="${1:-$REPO_ROOT/dev/packages/rhel8.10-py312}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "TrapNinja Offline Package Installer"
echo "=============================================="
echo ""

# Check if running as root (needed for --break-system-packages on some systems)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as root. You may need sudo.${NC}"
fi

# Check Python 3.12
if ! command -v python3.12 &> /dev/null; then
    echo -e "${RED}Error: Python 3.12 not found${NC}"
    echo "Install with: sudo dnf install -y python3.12 python3.12-pip"
    exit 1
fi

echo "Python version: $(python3.12 --version)"
echo "Packages directory: $PACKAGES_DIR"
echo ""

# Check packages directory exists
if [ ! -d "$PACKAGES_DIR" ]; then
    echo -e "${RED}Error: Packages directory not found: $PACKAGES_DIR${NC}"
    echo ""
    echo "Did you extract the tarball?"
    echo "  tar xzvf trapninja-packages.tar.gz"
    exit 1
fi

if [ ! -f "$PACKAGES_DIR/requirements.lock" ] || [ ! -f "$PACKAGES_DIR/SHA256SUMS" ]; then
    echo -e "${RED}Error: package lock or checksum file missing from $PACKAGES_DIR${NC}"
    exit 1
fi
(cd "$PACKAGES_DIR" && sha256sum -c SHA256SUMS)

PKG_COUNT=$(find "$PACKAGES_DIR" -maxdepth 1 -type f -name '*.whl' | wc -l)
echo "Found $PKG_COUNT wheel files"
echo ""

echo "Installing locked TrapNinja dependencies..."
echo "----------------------------------------"
python3.12 -m pip install --break-system-packages --no-index \
    --find-links="$PACKAGES_DIR/" \
    -r "$PACKAGES_DIR/requirements.lock"

echo ""
echo "=============================================="
echo "Verifying installation..."
echo "=============================================="
echo ""

# Verify installations
python3.12 -c "import scapy, pysnmp, pyasn1, cryptography; from Crypto.Cipher import AES"
echo -e "${GREEN}All locked runtime dependencies import successfully${NC}"

echo ""
echo "=============================================="
echo -e "${GREEN}Installation complete${NC}"
echo "=============================================="
echo ""
echo "You can now run TrapNinja:"
echo "  sudo python3.12 -O trapninja.py"
echo ""
