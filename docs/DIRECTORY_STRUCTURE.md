# TrapNinja Directory Structure

This document describes the repository layout and deployment architecture.

## Repository Layout

```
trapninja/
├── src/                      # ← DEPLOYABLE CODE
│   ├── trapninja.py          # Main entry point
│   ├── VERSION               # Version file (read by code)
│   ├── trapninja/            # Python package
│   │   ├── __init__.py
│   │   ├── __version__.py    # Reads VERSION file
│   │   ├── main.py           # CLI argument handling
│   │   ├── service.py        # Main service logic
│   │   ├── config.py         # Configuration loading
│   │   ├── cli/              # CLI command modules
│   │   ├── cache/            # Redis caching module
│   │   ├── core/             # Types, constants, exceptions
│   │   ├── ha/               # High Availability module
│   │   ├── processing/       # Packet processing
│   │   ├── stats/            # Statistics collection
│   │   └── ...               # Other modules
│   └── config/               # Default configuration files
│       ├── destinations.json
│       ├── blocked_ips.json
│       ├── blocked_traps.json
│       ├── ha_config.json
│       ├── cache_config.json
│       └── ...
│
├── dev/                      # ← DEVELOPMENT FILES (not deployed)
│   ├── CHANGELOG.md          # Version history
│   ├── requirements.txt      # Full Python dependencies
│   ├── requirements-minimal.txt  # Minimal dependencies
│   ├── scripts/              # Development scripts
│   │   ├── download-packages.sh
│   │   └── install-packages.sh
│   ├── tests/                # Test files
│   │   ├── trapninja-tests.py
│   │   ├── network-tests.py
│   │   └── ...
│   └── tools/                # Development tools
│       ├── cleanup.sh
│       └── snmp_trap_tracker.sh
│
├── docs/                     # ← DOCUMENTATION (not deployed)
│   ├── USER_GUIDE.md
│   ├── INSTALL.md
│   ├── CLI.md
│   ├── ARCHITECTURE.md
│   ├── HA.md
│   ├── CACHE.md
│   ├── METRICS.md
│   ├── GRANULAR_STATS.md
│   ├── TROUBLESHOOTING.md
│   └── ...
│
├── ansible/                  # ← DEPLOYMENT AUTOMATION
│   ├── deploy.yml            # Main deployment playbook
│   └── templates/            # Jinja2 templates
│       ├── trapninja.service.j2
│       ├── destinations.json.j2
│       ├── ha_config.json.j2
│       └── cache_config.json.j2
│
├── README.md                 # Repository documentation
├── .gitignore               
└── tests/                    # Legacy (empty, can be removed)
```

## Deployment Model

### What Gets Deployed

Only the contents of `src/` are deployed to the target system:

```
/opt/trapninja/               # trapninja_dest
├── trapninja.py              # Entry point
├── VERSION                   # Version file
├── trapninja/                # Python package
│   └── ...
└── config/                   # Default configs (copied to /etc/)
```

### Configuration Directory

Site-specific configurations are stored separately:

```
/etc/trapninja/               # trapninja_config_dest
├── destinations.json
├── blocked_ips.json
├── blocked_traps.json
├── ha_config.json
├── cache_config.json
└── ...
```

## Ansible Deployment

### Simple Deployment

The ansible playbook syncs only `src/`:

```yaml
# From ansible/deploy.yml
- name: Sync TrapNinja application files
  synchronize:
    src: "{{ trapninja_src }}/src/"     # Only deploy src/
    dest: "{{ trapninja_dest }}/"
    delete: yes
    rsync_opts:
      - "--exclude=__pycache__/"
      - "--exclude=*.pyc"
      - "--exclude=*.pyo"
      - "--exclude=.DS_Store"
```

### Manual Deployment

```bash
# Sync source files to target
rsync -avz --delete \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    src/ root@target:/opt/trapninja/

# Copy default configs (first time only)
scp -r src/config/* root@target:/etc/trapninja/
```

## Development Workflow

### Running Locally

```bash
# Install dependencies
pip3.9 install --break-system-packages -r dev/requirements.txt

# Run from src directory
cd src
sudo python3.9 -O trapninja.py

# Run tests
cd src
python3.9 ../dev/tests/trapninja-tests.py
```

### Running in Production

```bash
# Via systemd service
sudo systemctl start trapninja

# Direct execution
cd /opt/trapninja
sudo python3.9 -O trapninja.py
```

## Directory Purposes

| Directory | Purpose | Deployed? |
|-----------|---------|-----------|
| `src/` | Production code | ✅ Yes |
| `src/trapninja/` | Python package | ✅ Yes |
| `src/config/` | Default configs | ✅ Yes (copied to /etc/) |
| `dev/` | Development files | ❌ No |
| `docs/` | Documentation | ❌ No |
| `ansible/` | Deployment automation | ❌ No |

## Version Management

The version is stored in a single location:

```
src/VERSION          # Contains version string e.g., "0.7.0"
```

This is read by `src/trapninja/__version__.py` which provides:
- `__version__` - Version string
- `VERSION_INFO` - Version tuple for comparisons
- `FEATURES` - Feature flags based on version
- Helper functions for version display

## Air-Gapped Deployment

For systems without internet access:

1. **On build machine**: Download packages using `dev/scripts/download-packages.sh`
2. **Transfer**: Copy packages and `src/` directory to target
3. **On target**: Install packages using `dev/scripts/install-packages.sh`
4. **Deploy**: Copy `src/` contents to `/opt/trapninja/`

## Related Documentation

- [INSTALL.md](INSTALL.md) - Detailed installation instructions
- [USER_GUIDE.md](USER_GUIDE.md) - Operations guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
