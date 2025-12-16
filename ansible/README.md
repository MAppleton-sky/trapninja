# TrapNinja Ansible Deployment

This directory contains Ansible playbooks and templates for deploying TrapNinja to production servers.

## Overview

The deployment process:
1. Clones the TrapNinja git repository to the Ansible controller
2. Syncs `src/` directory to target servers (`/opt/trapninja/`)
3. Installs Python dependencies
4. Deploys configuration to `/etc/trapninja/` (without overwriting existing configs)
5. Configures and starts the systemd service
6. Cleans up the local git clone

## Quick Start

```bash
# 1. Copy and customize inventory
cp inventory/hosts.example inventory/production
vi inventory/production

# 2. Copy and customize group variables
cp inventory/group_vars/trapninja_servers.yml.example inventory/group_vars/trapninja_servers.yml
vi inventory/group_vars/trapninja_servers.yml

# 3. For HA deployments, customize host variables
cp inventory/host_vars/trapninja-primary.yml.example inventory/host_vars/trapninja-primary.yml
cp inventory/host_vars/trapninja-secondary.yml.example inventory/host_vars/trapninja-secondary.yml

# 4. Run deployment
ansible-playbook -i inventory/production deploy.yml
```

## Directory Structure

```
ansible/
├── deploy.yml                    # Main deployment playbook
├── README.md                     # This file
├── templates/                    # Jinja2 templates
│   ├── trapninja.service.j2      # Systemd service unit
│   ├── destinations.json.j2      # Destination config template
│   ├── ha_config.json.j2         # HA config template
│   └── cache_config.json.j2      # Cache config template
└── inventory/                    # Inventory examples
    ├── hosts.example             # Host inventory template
    ├── group_vars/
    │   └── trapninja_servers.yml.example
    └── host_vars/
        ├── trapninja-primary.yml.example
        └── trapninja-secondary.yml.example
```

## Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `trapninja_git_repo` | Git repository URL | `git@gitlab.example.com:network/trapninja.git` |
| `trapninja_git_branch` | Branch or tag to deploy | `main`, `v0.7.0` |

## Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `trapninja_dest` | `/opt/trapninja` | Installation directory |
| `trapninja_config_dest` | `/etc/trapninja` | Configuration directory |
| `trapninja_user` | `root` | Service user |
| `trapninja_group` | `root` | Service group |
| `trapninja_python` | `python3.9` | Python interpreter |
| `trapninja_minimal_install` | `false` | Use minimal dependencies |
| `trapninja_enable_cache` | `true` | Install Redis |
| `trapninja_enable_metrics` | `true` | Open metrics firewall port |

## Configuration Variables

### Destinations (`trapninja_destinations`)

```yaml
trapninja_destinations:
  - ["192.168.1.100", 162]   # Primary NMS
  - ["192.168.1.101", 162]   # Secondary NMS
```

### HA Configuration (`trapninja_ha_config`)

```yaml
trapninja_ha_config:
  enabled: true
  mode: "primary"              # or "secondary"
  peer_host: "10.234.83.134"
  peer_port: 60006
  priority: 150                # Higher = preferred primary
  heartbeat_interval: 1.0
  heartbeat_timeout: 3.0
  failover_delay: 2.0
```

### Cache Configuration (`trapninja_cache_config`)

```yaml
trapninja_cache_config:
  enabled: true
  host: "localhost"
  port: 6379
  retention_hours: 2.0
```

## Deployment Tags

Run specific parts of the deployment:

```bash
# Prerequisites only (Python, Redis)
ansible-playbook -i inventory/production deploy.yml --tags prereq

# Install/update code only
ansible-playbook -i inventory/production deploy.yml --tags install

# Configuration only
ansible-playbook -i inventory/production deploy.yml --tags config

# Service management only
ansible-playbook -i inventory/production deploy.yml --tags service

# Firewall configuration only
ansible-playbook -i inventory/production deploy.yml --tags firewall

# Python packages only
ansible-playbook -i inventory/production deploy.yml --tags pip
```

## Environment Variables

You can also set variables via environment:

```bash
export TRAPNINJA_GIT_REPO="git@gitlab.example.com:network/trapninja.git"
export TRAPNINJA_GIT_BRANCH="v0.7.0"
ansible-playbook -i inventory/production deploy.yml
```

## HA Deployment

For High Availability deployments with Primary/Secondary servers:

1. **Configure inventory** with both servers:
   ```ini
   [trapninja_servers]
   trapninja-primary   ansible_host=10.234.83.133
   trapninja-secondary ansible_host=10.234.83.134
   ```

2. **Set host-specific HA config** in `host_vars/`:
   
   Primary (`host_vars/trapninja-primary.yml`):
   ```yaml
   trapninja_ha_config:
     enabled: true
     mode: "primary"
     peer_host: "10.234.83.134"
     priority: 150
   ```
   
   Secondary (`host_vars/trapninja-secondary.yml`):
   ```yaml
   trapninja_ha_config:
     enabled: true
     mode: "secondary"
     peer_host: "10.234.83.133"
     priority: 100
   ```

3. **Deploy to both servers**:
   ```bash
   ansible-playbook -i inventory/production deploy.yml
   ```

## Upgrading

The deployment is designed for safe upgrades:

- **Code** in `/opt/trapninja/` is replaced on each deployment
- **Configuration** in `/etc/trapninja/` is **never overwritten** if files exist
- New default configs are only copied if no existing config is present

To force a config update, either:
- Delete the config file on the target and redeploy
- Manually update the config file
- Use templates with variables (e.g., `trapninja_destinations`)

## Troubleshooting

### SSH Key Issues

Ensure the Ansible controller can access the git repository:
```bash
ssh -T git@gitlab.example.com
```

### Deployment Fails Mid-Way

The local clone is in `/tmp/trapninja-deploy-*`. Clean up manually if needed:
```bash
rm -rf /tmp/trapninja-deploy-*
```

### Service Won't Start

Check logs on the target server:
```bash
journalctl -u trapninja -f
cat /var/log/trapninja/trapninja.log
```

### Config Directory

Verify the service is using the correct config:
```bash
# In the logs, you should see:
# Configuration directory: /etc/trapninja
```

## File Locations After Deployment

| Location | Contents |
|----------|----------|
| `/opt/trapninja/` | Application code |
| `/opt/trapninja/trapninja.py` | Entry point |
| `/opt/trapninja/trapninja/` | Python package |
| `/opt/trapninja/config/` | Default configs (reference) |
| `/etc/trapninja/` | **Live configuration** |
| `/var/log/trapninja/` | Log files |
| `/var/run/trapninja.pid` | PID file |
| `/etc/systemd/system/trapninja.service` | Systemd unit |
