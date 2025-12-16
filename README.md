# TrapNinja

**High-Performance SNMP Trap Forwarder for Telecommunications Networks**

TrapNinja is an enterprise-grade SNMP trap forwarding system designed for telecommunications environments requiring 99.999% availability. It handles trap volumes from steady-state operations to burst scenarios of 100,000+ traps during network events.

## Features

- **High-Performance Processing**: 10,000+ traps/second sustained throughput
- **High Availability**: Primary/Secondary deployment with sub-3-second failover
- **Service-Based Routing**: Route traps to specialized NOCs by IP or OID
- **IP/OID Filtering**: Block unwanted traps at the forwarder level
- **Trap Caching**: Redis-based 2-hour retention for replay during outages
- **SNMPv3 Support**: Decrypt SNMPv3 traps and forward as SNMPv2c
- **Prometheus Metrics**: Comprehensive monitoring and alerting
- **eBPF Acceleration**: Optional kernel-level packet filtering

## Quick Start

```bash
# Install dependencies
pip3.9 install --break-system-packages scapy

# Configure destinations
echo '[["192.168.1.100", 162]]' > config/destinations.json

# Start forwarding
sudo python3.9 -O trapninja.py
```

## Installation

### Requirements

- RHEL 8.x / CentOS 8 / Rocky Linux 8 (or compatible)
- Python 3.9+
- Root privileges (for raw socket access)

### Install Python Dependencies

```bash
# Full installation (all features)
pip3.9 install --break-system-packages -r requirements.txt

# Minimal installation (basic forwarding only)
pip3.9 install --break-system-packages -r requirements-minimal.txt
```

### Install System Packages

```bash
# Required
sudo dnf install -y python39 python39-pip libpcap libpcap-devel

# Optional - Redis for trap caching
sudo dnf install -y redis
sudo systemctl enable --now redis

# Optional - eBPF acceleration
sudo dnf install -y bcc python3-bcc kernel-devel-$(uname -r)
```

See [documentation/INSTALL.md](documentation/INSTALL.md) for detailed installation instructions.

## Usage

```bash
# Start the service
sudo python3.9 -O trapninja.py

# Check status
sudo python3.9 -O trapninja.py --status

# View statistics
sudo python3.9 -O trapninja.py --stats-summary
sudo python3.9 -O trapninja.py --stats-top-ips
sudo python3.9 -O trapninja.py --stats-top-oids

# Block an IP
sudo python3.9 -O trapninja.py --block-ip 10.0.0.1

# Block an OID
sudo python3.9 -O trapninja.py --block-oid 1.3.6.1.4.1.9.9.41.2.0.1
```

See [documentation/USER_GUIDE.md](documentation/USER_GUIDE.md) for complete usage instructions.

## Configuration

Configuration files are stored in `/etc/trapninja/` (or `./config/` for development):

| File | Purpose |
|------|---------|
| `destinations.json` | Forward destinations |
| `blocked_ips.json` | Blocked source IPs |
| `blocked_traps.json` | Blocked OIDs |
| `ha_config.json` | High Availability settings |
| `cache_config.json` | Redis cache settings |
| `redirection_config.json` | Service-based routing |

## Documentation

| Document | Description |
|----------|-------------|
| [USER_GUIDE.md](documentation/USER_GUIDE.md) | Operations guide with examples |
| [INSTALL.md](documentation/INSTALL.md) | Detailed installation instructions |
| [CLI.md](documentation/CLI.md) | Complete CLI reference |
| [ARCHITECTURE.md](documentation/ARCHITECTURE.md) | System design and internals |
| [HA.md](documentation/HA.md) | High Availability configuration |
| [CACHE.md](documentation/CACHE.md) | Trap caching and replay |
| [METRICS.md](documentation/METRICS.md) | Prometheus metrics reference |
| [GRANULAR_STATS.md](documentation/GRANULAR_STATS.md) | Per-IP/OID statistics |
| [TROUBLESHOOTING.md](documentation/TROUBLESHOOTING.md) | Common issues and solutions |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Elements                          │
│         (Cisco ASR/NCS, Nokia 7750SR/7950XRS, etc.)         │
└─────────────────────┬───────────────────────────────────────┘
                      │ SNMP Traps (UDP 162)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                     TrapNinja                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Capture  │→ │ Filter   │→ │ Route    │→ │ Forward  │    │
│  │ (eBPF/   │  │ (IP/OID) │  │ (Service)│  │ (UDP)    │    │
│  │  Scapy)  │  │          │  │          │  │          │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│        │              │             │             │          │
│        └──────────────┴─────────────┴─────────────┘          │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │ Redis Cache │                          │
│                    └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Destinations                              │
│     Voice NOC    Broadband NOC    Transmission    Core      │
└─────────────────────────────────────────────────────────────┘
```

## Performance

| Metric | Value |
|--------|-------|
| Sustained throughput | 10,000+ traps/second |
| Burst handling | 100,000 traps |
| Queue capacity | 200,000 packets |
| HA failover time | < 3 seconds |
| Memory footprint | ~100-500 MB |

## Version

TrapNinja 0.7.0 (Beta)

## License

Proprietary - Internal Use Only
