# TrapNinja Installation Guide

This guide covers installing TrapNinja on RHEL 8/9 and compatible systems.

## Quick Install (Minimal)

For basic trap forwarding without optional features:

```bash
# Install system packages
sudo dnf install -y python39 python39-pip libpcap libpcap-devel

# Install Python packages
pip3.9 install --break-system-packages scapy
```

## Full Installation

### 1. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | RHEL 8.4+ / CentOS 8 / Rocky 8 | RHEL 8.10 |
| Python | 3.9+ | 3.9.x |
| Kernel | 4.18+ | 4.18+ (RHEL 8 default) |
| Memory | 512 MB | 2 GB+ |
| CPU | 1 core | 4+ cores |

### 2. Install System Packages

#### RHEL 8 / CentOS 8 / Rocky 8

```bash
# Enable required repositories
sudo dnf install -y epel-release

# Core packages (required)
sudo dnf install -y \
    python39 \
    python39-pip \
    python39-devel \
    libpcap \
    libpcap-devel \
    gcc

# Redis (optional - for trap caching/replay)
sudo dnf install -y redis
sudo systemctl enable redis
sudo systemctl start redis

# eBPF acceleration (optional - for kernel 4.18+)
sudo dnf install -y \
    bcc \
    bcc-tools \
    python3-bcc \
    kernel-devel-$(uname -r) \
    kernel-headers-$(uname -r)
```

#### RHEL 9 / Rocky 9 / AlmaLinux 9

```bash
# Enable required repositories
sudo dnf install -y epel-release

# Core packages
sudo dnf install -y \
    python3 \
    python3-pip \
    python3-devel \
    libpcap \
    libpcap-devel \
    gcc

# Redis (optional)
sudo dnf install -y redis
sudo systemctl enable redis
sudo systemctl start redis

# eBPF acceleration (optional)
sudo dnf install -y \
    bcc \
    bcc-tools \
    python3-bcc \
    kernel-devel \
    kernel-headers
```

### 3. Install Python Packages

#### Standard Installation (Internet Access)

```bash
# Install all dependencies
pip3.9 install --break-system-packages -r requirements.txt

# Or install individually:

# Required
pip3.9 install --break-system-packages scapy

# Optional - Redis caching
pip3.9 install --break-system-packages redis

# Optional - SNMPv3 decryption
pip3.9 install --break-system-packages pysnmp pyasn1 cryptography
```

#### Air-Gapped Installation (No Internet)

On a machine with internet access:

```bash
# Download packages
mkdir -p /tmp/trapninja-packages
pip3.9 download -d /tmp/trapninja-packages \
    scapy \
    redis \
    pysnmp \
    pyasn1 \
    cryptography

# Create tarball
cd /tmp
tar czvf trapninja-packages.tar.gz trapninja-packages/
```

On the air-gapped system:

```bash
# Transfer trapninja-packages.tar.gz to the system, then:
tar xzvf trapninja-packages.tar.gz
pip3.9 install --break-system-packages --no-index \
    --find-links=/path/to/trapninja-packages/ \
    scapy redis pysnmp pyasn1 cryptography
```

### 4. Verify Installation

```bash
# Check Python version
python3.9 --version

# Verify required packages
python3.9 -c "import scapy; print(f'Scapy: {scapy.VERSION}')"

# Verify optional packages
python3.9 -c "import redis; print(f'Redis: {redis.__version__}')" 2>/dev/null || echo "Redis: Not installed"
python3.9 -c "import pysnmp; print(f'PySNMP: Available')" 2>/dev/null || echo "PySNMP: Not installed"
python3.9 -c "from bcc import BPF; print('BCC: Available')" 2>/dev/null || echo "BCC: Not installed"

# Test Redis connection (if installed)
redis-cli ping
```

### 5. Create Required Directories

```bash
# Create directories
sudo mkdir -p /etc/trapninja
sudo mkdir -p /var/log/trapninja/metrics
sudo mkdir -p /var/run/trapninja

# Set permissions (adjust user as needed)
sudo chown -R root:root /etc/trapninja
sudo chmod 750 /etc/trapninja
sudo chown -R root:root /var/log/trapninja
sudo chmod 755 /var/log/trapninja
```

### 6. Initial Configuration

```bash
# Copy configuration files
cp -r config/* /etc/trapninja/

# Create minimal destinations.json
cat > /etc/trapninja/destinations.json << 'EOF'
[
    ["192.168.1.100", 162]
]
EOF

# Verify configuration
python3.9 -O trapninja.py --check-config
```

## Package Dependencies Summary

### Required

| Package | Purpose | Install Command |
|---------|---------|-----------------|
| scapy | Packet capture/forwarding | `pip3.9 install --break-system-packages scapy` |
| libpcap | Packet capture library | `dnf install libpcap libpcap-devel` |

### Optional

| Package | Purpose | Install Command |
|---------|---------|-----------------|
| redis (Python) | Trap caching backend | `pip3.9 install --break-system-packages redis` |
| redis-server | Redis daemon | `dnf install redis` |
| pysnmp | SNMPv3 decryption | `pip3.9 install --break-system-packages pysnmp` |
| pyasn1 | ASN.1 parsing for SNMP | `pip3.9 install --break-system-packages pyasn1` |
| cryptography | Encryption support | `pip3.9 install --break-system-packages cryptography` |
| bcc/python3-bcc | eBPF acceleration | `dnf install bcc python3-bcc` |

## Feature Availability

| Feature | Required Packages | Notes |
|---------|-------------------|-------|
| Basic trap forwarding | scapy, libpcap | Core functionality |
| IP/OID filtering | scapy | Included in core |
| Service-based routing | scapy | Included in core |
| High Availability | scapy | Uses TCP sockets |
| Trap caching/replay | redis, redis-server | Requires Redis 5.0+ |
| SNMPv3 decryption | pysnmp, pyasn1, cryptography | Optional |
| Prometheus metrics | (none) | Built-in |
| eBPF acceleration | bcc, kernel-headers | Kernel 4.18+, optional |

## Troubleshooting

### Scapy Permission Errors

TrapNinja requires root privileges for raw socket access:

```bash
# Run with sudo
sudo python3.9 -O trapninja.py

# Or set capabilities (less secure)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.9
```

### Redis Connection Failed

```bash
# Check Redis is running
systemctl status redis

# Check Redis is listening
redis-cli ping

# Check firewall (if connecting remotely)
sudo firewall-cmd --list-ports
```

### BCC/eBPF Not Working

```bash
# Verify kernel headers match running kernel
uname -r
rpm -qa | grep kernel-devel

# Check BCC installation
python3 -c "from bcc import BPF; print('OK')"

# If mismatched, install matching headers
sudo dnf install kernel-devel-$(uname -r)
```

### SNMPv3 Decryption Issues

```bash
# Verify pysnmp installation
python3.9 -c "from pysnmp.entity import engine; print('OK')"

# Check cryptography
python3.9 -c "from cryptography.fernet import Fernet; print('OK')"
```

## Updating

```bash
# Update Python packages
pip3.9 install --break-system-packages --upgrade \
    scapy redis pysnmp pyasn1 cryptography

# Restart service
sudo systemctl restart trapninja
```

## Uninstalling

```bash
# Stop service
sudo systemctl stop trapninja
sudo systemctl disable trapninja

# Remove Python packages
pip3.9 uninstall -y scapy redis pysnmp pyasn1 cryptography

# Remove configuration (optional)
sudo rm -rf /etc/trapninja
sudo rm -rf /var/log/trapninja
```
