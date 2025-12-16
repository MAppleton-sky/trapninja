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
#   - Python 3.9 installed: dnf install -y python39 python39-pip
#   - For source packages: dnf install -y python39-devel gcc libffi-devel openssl-devel
# =============================================================================

set -e

PACKAGES_DIR="${1:-./trapninja-packages}"

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

# Check Python 3.9
if ! command -v python3.9 &> /dev/null; then
    echo -e "${RED}Error: Python 3.9 not found${NC}"
    echo "Install with: sudo dnf install -y python39 python39-pip"
    exit 1
fi

echo "Python version: $(python3.9 --version)"
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

# Count available packages
PKG_COUNT=$(ls -1 "$PACKAGES_DIR"/*.whl "$PACKAGES_DIR"/*.tar.gz 2>/dev/null | wc -l)
echo "Found $PKG_COUNT package files"
echo ""

# Install required package
echo "Installing required package: scapy"
echo "----------------------------------------"
pip3.9 install --break-system-packages --no-index \
    --find-links="$PACKAGES_DIR/" \
    scapy

echo ""
echo -e "${GREEN}Core package installed successfully${NC}"
echo ""

# Install optional packages
echo "Installing optional packages..."
echo "----------------------------------------"

for pkg in redis pysnmp pyasn1 cryptography; do
    echo -n "  $pkg: "
    if pip3.9 install --break-system-packages --no-index \
        --find-links="$PACKAGES_DIR/" \
        "$pkg" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}SKIPPED (not in package dir or missing dependencies)${NC}"
    fi
done

echo ""
echo "=============================================="
echo "Verifying installation..."
echo "=============================================="
echo ""

# Verify installations
echo -n "scapy: "
python3.9 -c "import scapy; print(scapy.VERSION)" 2>/dev/null || echo -e "${RED}FAILED${NC}"

echo -n "redis: "
python3.9 -c "import redis; print(redis.__version__)" 2>/dev/null || echo "Not installed"

echo -n "pysnmp: "
python3.9 -c "import pysnmp; print('OK')" 2>/dev/null || echo "Not installed"

echo -n "pyasn1: "
python3.9 -c "import pyasn1; print(pyasn1.__version__)" 2>/dev/null || echo "Not installed"

echo -n "cryptography: "
python3.9 -c "import cryptography; print(cryptography.__version__)" 2>/dev/null || echo "Not installed"

echo ""
echo "=============================================="
echo -e "${GREEN}Installation complete${NC}"
echo "=============================================="
echo ""
echo "You can now run TrapNinja:"
echo "  sudo python3.9 -O trapninja.py"
echo ""
