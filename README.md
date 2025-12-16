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
# Clone repository
git clone <repository-url>
cd trapninja

# Install dependencies
pip3.9 install --break-system-packages -r dev/requirements.txt

# Configure destinations
echo '[["192.168.1.100", 162]]' > src/config/destinations.json

# Start forwarding (from src directory)
cd src
sudo python3.9 -O trapninja.py
```

## Repository Structure

```
trapninja/
├── src/                    # Deployable source code
│   ├── trapninja.py        # Main entry point
│   ├── trapninja/          # Python package
│   │   ├── cli/            # Command-line interface modules
│   │   ├── cache/          # Redis caching module
│   │   ├── core/           # Core types and constants
│   │   ├── ha/             # High Availability module
│   │   ├── processing/     # Packet processing
│   │   ├── stats/          # Statistics collection
│   │   └── ...             # Other modules
│   ├── config/             # Default configuration files
│   └── VERSION             # Version file
├── dev/                    # Development files (not deployed)
│   ├── requirements.txt    # Full dependencies
│   ├── requirements-minimal.txt  # Minimal dependencies
│   ├── CHANGELOG.md        # Change history
│   ├── scripts/            # Development scripts
│   ├── tests/              # Test files
│   └── tools/              # Development tools
├── docs/                   # Documentation (not deployed)
│   ├── USER_GUIDE.md
│   ├── INSTALL.md
│   ├── CLI.md
│   └── ...
├── ansible/                # Deployment automation
│   ├── deploy.yml
│   └── templates/
├── README.md               # This file
└── .gitignore
```

## Installation

### Requirements

- RHEL 8.x / CentOS 8 / Rocky Linux 8 (or compatible)
- Python 3.9+
- Root privileges (for raw socket access)

### Install Python Dependencies

```bash
# Full installation (all features)
pip3.9 install --break-system-packages -r dev/requirements.txt

# Minimal installation (basic forwarding only)
pip3.9 install --break-system-packages -r dev/requirements-minimal.txt
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

See [docs/INSTALL.md](docs/INSTALL.md) for detailed installation instructions.

## Usage

```bash
# Run from the src directory
cd src

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

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for complete usage instructions.

## Deployment with Ansible

The ansible playbook deploys only the `src/` directory, keeping the target system clean:

```bash
# Deploy to servers defined in inventory
ansible-playbook -i inventory/hosts ansible/deploy.yml

# Deploy specific components
ansible-playbook -i inventory/hosts ansible/deploy.yml --tags install
ansible-playbook -i inventory/hosts ansible/deploy.yml --tags config
ansible-playbook -i inventory/hosts ansible/deploy.yml --tags service
```

### What Gets Deployed

Only the contents of `src/` are deployed to `/opt/trapninja/`:
- `trapninja.py` - Entry point
- `trapninja/` - Python package
- `config/` - Default configurations
- `VERSION` - Version file

### What Stays Local

- `dev/` - Development files, requirements, changelog
- `docs/` - Documentation
- `ansible/` - Deployment configs
- `README.md` - Repository readme

## Configuration

Configuration files are stored in `/etc/trapninja/` (production) or `./config/` (development):

| File | Purpose |
|------|---------|
| `destinations.json` | Forward destinations |
| `blocked_ips.json` | Blocked source IPs |
| `blocked_traps.json` | Blocked OIDs |
| `ha_config.json` | High Availability settings |
| `cache_config.json` | Redis cache settings |
| `stats_config.json` | Statistics configuration |

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Operations guide with examples |
| [docs/INSTALL.md](docs/INSTALL.md) | Detailed installation instructions |
| [docs/CLI.md](docs/CLI.md) | Complete CLI reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and internals |
| [docs/HA.md](docs/HA.md) | High Availability configuration |
| [docs/CACHE.md](docs/CACHE.md) | Trap caching and replay |
| [docs/METRICS.md](docs/METRICS.md) | Prometheus metrics reference |
| [docs/GRANULAR_STATS.md](docs/GRANULAR_STATS.md) | Per-IP/OID statistics |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |

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

See [dev/CHANGELOG.md](dev/CHANGELOG.md) for version history.

## License

Proprietary - Internal Use Only
