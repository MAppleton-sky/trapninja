#!/bin/bash
# =============================================================================
# TrapNinja Package Downloader for Air-Gapped Installation
# =============================================================================
#
# Downloads Python packages on macOS for installation on RHEL 8 / CentOS 8
#
# Usage:
#   ./download-packages.sh [output-dir]
#
# Output:
#   trapninja-packages.tar.gz - Ready for transfer to target server
#
# On target server:
#   tar xzvf trapninja-packages.tar.gz
#   pip3.9 install --break-system-packages --no-index \
#       --find-links=./trapninja-packages/ \
#       scapy redis pysnmp pyasn1 cryptography
# =============================================================================

set -e

OUTPUT_DIR="${1:-$HOME/trapninja-packages}"
TARBALL="trapninja-packages.tar.gz"

# Package lists
REQUIRED_PACKAGES="scapy"
OPTIONAL_PACKAGES="redis pysnmp pyasn1 cryptography"
ALL_PACKAGES="$REQUIRED_PACKAGES $OPTIONAL_PACKAGES"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "TrapNinja Package Downloader"
echo "=============================================="
echo ""
echo "Output directory: $OUTPUT_DIR"
echo "Packages: $ALL_PACKAGES"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Check if Docker is available (preferred method)
if command -v docker &> /dev/null; then
    echo -e "${GREEN}Docker detected - using container method (most reliable)${NC}"
    echo ""
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        echo -e "${YELLOW}Docker is installed but not running. Starting...${NC}"
        open -a Docker
        echo "Waiting for Docker to start..."
        sleep 10
    fi
    
    echo "Pulling CentOS Stream 8 image..."
    docker pull quay.io/centos/centos:stream8
    
    echo ""
    echo "Downloading packages using CentOS container..."
    docker run --rm -v "$OUTPUT_DIR:/packages" \
        quay.io/centos/centos:stream8 \
        bash -c "
            echo 'Installing Python 3.9...'
            dnf install -y python39 python39-pip > /dev/null 2>&1
            
            echo 'Downloading packages...'
            pip3.9 download -d /packages \
                scapy \
                redis \
                pysnmp \
                pyasn1 \
                cryptography
            
            echo 'Setting permissions...'
            chmod 644 /packages/*.whl /packages/*.tar.gz 2>/dev/null || true
        "
    
    echo ""
    echo -e "${GREEN}Download complete using Docker method${NC}"
    
else
    echo -e "${YELLOW}Docker not available - using pip download with platform flags${NC}"
    echo ""
    echo "Note: This method may not work for all packages."
    echo "Consider installing Docker for most reliable results."
    echo ""
    
    # Method 1: Try to get Linux wheels
    echo "Attempting to download Linux x86_64 wheels..."
    pip3 download \
        --dest "$OUTPUT_DIR" \
        --platform manylinux2014_x86_64 \
        --platform manylinux_2_17_x86_64 \
        --python-version 3.9 \
        --only-binary=:all: \
        $ALL_PACKAGES 2>/dev/null || true
    
    # Method 2: Download source distributions as fallback
    echo ""
    echo "Downloading source distributions as fallback..."
    pip3 download \
        --dest "$OUTPUT_DIR" \
        --no-binary=:all: \
        $ALL_PACKAGES 2>/dev/null || true
    
    echo ""
    echo -e "${YELLOW}Download complete using pip method${NC}"
    echo -e "${YELLOW}Note: Target server will need gcc and python39-devel for source packages${NC}"
fi

# List downloaded files
echo ""
echo "Downloaded files:"
echo "----------------------------------------"
ls -la "$OUTPUT_DIR"
echo "----------------------------------------"

# Count packages
PKG_COUNT=$(ls -1 "$OUTPUT_DIR"/*.whl "$OUTPUT_DIR"/*.tar.gz 2>/dev/null | wc -l)
echo ""
echo "Total packages: $PKG_COUNT"

# Create tarball
echo ""
echo "Creating tarball..."
cd "$(dirname "$OUTPUT_DIR")"
DIRNAME=$(basename "$OUTPUT_DIR")
tar czvf "$TARBALL" "$DIRNAME"

TARBALL_PATH="$(dirname "$OUTPUT_DIR")/$TARBALL"
TARBALL_SIZE=$(du -h "$TARBALL_PATH" | cut -f1)

echo ""
echo "=============================================="
echo -e "${GREEN}SUCCESS${NC}"
echo "=============================================="
echo ""
echo "Tarball created: $TARBALL_PATH"
echo "Size: $TARBALL_SIZE"
echo ""
echo "Transfer this file to your RHEL 8 server, then run:"
echo ""
echo "  tar xzvf $TARBALL"
echo "  pip3.9 install --break-system-packages --no-index \\"
echo "      --find-links=./$DIRNAME/ \\"
echo "      scapy redis pysnmp pyasn1 cryptography"
echo ""
