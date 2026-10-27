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

## Production Deployment

```bash
# From the gnoa-network-assurance-automation-ansible checkout:
bash run_playbook.sh samplicator playbooks/trapninja/deploy_code.yaml stage
```

The wrapper prompts for the Ansible Vault password. The playbook then prompts
for the TrapNinja branch; press Enter to use the branch configured for that
inventory, or enter a branch/tag explicitly. Replace `samplicator` and `stage`
with the required host-group limit and inventory environment (`prod`, `stage`,
or `dev`).

Production deployment is Ansible-managed: it installs Python 3.12, creates
`/opt/trapninja-venv`, verifies and installs the locked offline wheelhouse,
deploys the application and configuration, and manages the systemd service.
Do not install production dependencies manually with `pip`.
See [docs/INSTALL.md](docs/INSTALL.md) for prerequisites and verification.

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
├── README.md               # This file
└── .gitignore
```

## Installation

### Requirements

- RHEL 8.x / CentOS 8 / Rocky Linux 8 (or compatible)
- Python 3.12+
- Root privileges (for raw socket access)

### Production Installation

Use the Ansible deployment command above. It installs the locked Python runtime
dependencies into `/opt/trapninja-venv`; do not install production packages
manually with system `pip`.

### Developer Package Build (Not Used for Production)

```bash
# Clone and build
git clone <repository-url>
cd trapninja
pip3.12 install --break-system-packages build
python3.12 -m build

# Install built wheel
pip3.12 install --break-system-packages dist/trapninja-*.whl
```

### Development Installation

```bash
# Clone repository
git clone <repository-url>
cd trapninja

# Install from requirements (all features)
pip3.12 install --break-system-packages -r dev/requirements.txt

# Or install in editable mode
pip3.12 install --break-system-packages -e ".[dev]"
```

Host-level dependencies such as BCC, libpcap, and matching kernel headers are
provided by the server's base provisioning; the application playbook only
installs Python 3.12 and the locked application wheels. Redis caching is disabled
in the current runtime profile.

See [docs/INSTALL.md](docs/INSTALL.md) for detailed installation instructions.

## Usage

```bash
trapninja daemon status
trapninja stats summary
```

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for complete usage instructions.

## Deployment

Production deployment is driven by playbooks in the separate
`gnoa-network-assurance-automation-ansible` repository. The playbook deploys
source to `/opt/trapninja/` and its isolated Python environment to
`/opt/trapninja-venv/`:

- `trapninja.py` - Entry point
- `trapninja/` - Python package
- `config/` - Default configurations
- `VERSION` - Version file

The versioned wheelhouse under `dev/packages/` is transferred for an offline
install. Test fixtures, docs, and other development tools are not copied into
the application directory.

## Configuration

Configuration files are stored in `/etc/trapninja/` (production) or `./config/` (development):

| File | Purpose |
|------|---------|
| `trapninja.json` | Main config (interface, bind_address, capture mode) |
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
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, directory structure, and deployment |
| [docs/HA.md](docs/HA.md) | High Availability configuration |
| [docs/CACHE.md](docs/CACHE.md) | Trap caching and replay |
| [docs/METRICS.md](docs/METRICS.md) | Prometheus metrics reference |
| [docs/GRANULAR_STATS.md](docs/GRANULAR_STATS.md) | Per-IP/OID statistics |
| [docs/SNMPV3_CREDENTIALS.md](docs/SNMPV3_CREDENTIALS.md) | SNMPv3 decryption setup |
| [docs/SECURITY.md](docs/SECURITY.md) | Security measures and CWE remediation |
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

Current version is read from `src/VERSION` (currently 0.8.8 Beta).

See [dev/CHANGELOG.md](dev/CHANGELOG.md) for version history.

## License

Proprietary - Internal Use Only
