# TrapNinja Documentation Index

**Last Updated**: 2025-01-08  
**TrapNinja Version**: 0.7.13 (Beta)

This index provides an overview of all documentation files and their purposes.

---

## User-Facing Documentation

### Core Documentation

| Document | Purpose | Status | Last Updated |
|----------|---------|--------|--------------|
| **USER_GUIDE.md** | Primary user guide with modern CLI syntax | ✅ Current | 2025-01-08 |
| **CLI.md** | Complete CLI reference for all commands | ✅ Current | 2025-01-08 |
| **INSTALL.md** | Installation and deployment guide | 📝 Needs Review | - |
| **README.md** (root) | Project overview and quick start | 📝 Needs Review | - |

### Feature Documentation

| Document | Purpose | Status | Last Updated |
|----------|---------|--------|--------------|
| **HA.md** | High Availability configuration | 📝 Needs Review | - |
| **CACHE.md** | Redis caching and replay | 📝 Needs Review | - |
| **GRANULAR_STATS.md** | Statistics system details | 📝 Needs Review | - |
| **METRICS.md** | Prometheus metrics reference | 📝 Needs Review | - |
| **SNMPV3_CREDENTIALS.md** | SNMPv3 user management | 📝 Needs Review | - |
| **SHADOW_MODE.md** | Testing and observation modes | 📝 Needs Review | - |
| **FAILOVER_REPLAY.md** | Automatic gap replay | 📝 Needs Review | - |
| **CONFIG_SYNC.md** | HA configuration synchronization | 📝 Needs Review | - |
| **FRAGMENTATION.md** | Packet fragmentation handling | 📝 Needs Review | - |

### Operational Documentation

| Document | Purpose | Status | Last Updated |
|----------|---------|--------|--------------|
| **TROUBLESHOOTING.md** | Problem diagnosis guide | 📝 Needs Review | - |
| **CONFIG.md** | Configuration file reference | 📝 Needs Review | - |

---

## Developer Documentation

### Architecture

| Document | Purpose | Status | Last Updated |
|----------|---------|--------|--------------|
| **ARCHITECTURE.md** | System architecture and design | 📝 Needs Review | - |
| **ARCHITECTURE_BRIEF.md** | Brief architecture overview | 📝 Needs Review | - |
| **DIRECTORY_STRUCTURE.md** | Code organization | 📝 Needs Review | - |

### Module Documentation

| Document | Purpose | Status | Last Updated |
|----------|---------|--------|--------------|
| **CLI_MODULE.md** | CLI module internals | 📝 Needs Review | - |
| **CODE_REVIEW.md** | Code review and quality notes | 📝 Needs Review | - |

### Development Process

| Document | Purpose | Status | Last Updated |
|----------|---------|--------|--------------|
| **CHANGELOG.md** (dev/) | Version history | 📝 Needs Review | - |
| **refactoring/REFACTORING_PLAN.md** | Refactoring roadmap | 📝 Needs Review | - |
| **refactoring/CLEANUP_SUMMARY.md** | Cleanup tasks summary | 📝 Needs Review | - |

---

## Documentation Standards

### Command Invocation Syntax

**Standard Format** (used throughout documentation):
```bash
# Modern subcommand style (recommended)
trapninja daemon start

# Legacy flat-style (backward compatible)
python3.9 -O trapninja.py --start
```

**Note**: `trapninja` is used as shorthand. Actual invocation depends on installation:
- From src directory: `python3.9 -O trapninja.py`
- Module invocation: `python3.9 -O -m trapninja.main`
- Installed command: `trapninja`

### CLI Changes

**v3.0.0** introduced subcommand-based CLI structure:
- Organized into categories (daemon, filter, ha, snmpv3, cache, stats, etc.)
- Better help system with category-specific help
- Improved error messages with suggestions
- Full backward compatibility with legacy flags

### Documentation Updates Required

When CLI changes occur:
1. Update command examples in USER_GUIDE.md
2. Update CLI.md reference documentation
3. Update relevant feature documentation (HA.md, CACHE.md, etc.)
4. Update README.md quick start section
5. Update INSTALL.md if deployment changes
6. Update this index with change date

---

## Quick Navigation

### For Users

**Getting Started:**
1. Start with [INSTALL.md](INSTALL.md) for installation
2. Read [USER_GUIDE.md](USER_GUIDE.md) for basic operations
3. Reference [CLI.md](CLI.md) for detailed command syntax

**Specific Features:**
- HA Setup → [HA.md](HA.md)
- Trap Caching → [CACHE.md](CACHE.md)
- SNMPv3 Decryption → [SNMPV3_CREDENTIALS.md](SNMPV3_CREDENTIALS.md)
- Monitoring → [METRICS.md](METRICS.md) and [GRANULAR_STATS.md](GRANULAR_STATS.md)
- Problems → [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

### For Developers

**Understanding the System:**
1. [ARCHITECTURE_BRIEF.md](ARCHITECTURE_BRIEF.md) - Quick overview
2. [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed design
3. [DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md) - Code organization

**Contributing:**
1. [CODE_REVIEW.md](CODE_REVIEW.md) - Code standards
2. [refactoring/REFACTORING_PLAN.md](refactoring/REFACTORING_PLAN.md) - Roadmap
3. [CHANGELOG.md](../dev/CHANGELOG.md) - Version history

---

## Maintenance Checklist

### When Adding New Commands

- [ ] Update parser.py with new command/subcommand
- [ ] Add command implementation in appropriate cli/ module
- [ ] Update CLI.md with new command documentation
- [ ] Update USER_GUIDE.md with usage examples
- [ ] Add tests for new command
- [ ] Update CHANGELOG.md

### When Changing Existing Commands

- [ ] Check for backward compatibility or document breaking changes
- [ ] Update CLI.md command reference
- [ ] Update USER_GUIDE.md examples
- [ ] Update relevant feature docs (HA.md, CACHE.md, etc.)
- [ ] Update legacy argument mapping if affected
- [ ] Update tests
- [ ] Document in CHANGELOG.md

### When Adding New Features

- [ ] Create feature-specific documentation (e.g., NEW_FEATURE.md)
- [ ] Add CLI commands to parser.py
- [ ] Update CLI.md with new commands
- [ ] Update USER_GUIDE.md with feature usage
- [ ] Update ARCHITECTURE.md if significant architectural change
- [ ] Add to this index
- [ ] Update CHANGELOG.md

### Quarterly Documentation Review

- [ ] Review all user-facing docs for accuracy
- [ ] Check command examples still work
- [ ] Update version numbers
- [ ] Consolidate or remove outdated information
- [ ] Check internal cross-references
- [ ] Update "Last Updated" dates

---

## Document Dependencies

### USER_GUIDE.md References:
- CLI.md (for detailed command syntax)
- HA.md (for HA configuration)
- CACHE.md (for Redis setup)
- METRICS.md (for Prometheus metrics)
- GRANULAR_STATS.md (for statistics details)
- SNMPV3_CREDENTIALS.md (for SNMPv3 setup)
- TROUBLESHOOTING.md (for problem diagnosis)
- ARCHITECTURE.md (for internals)

### CLI.md References:
- Individual feature docs (HA.md, CACHE.md, etc.) via "See X.md for details"

### Feature Docs Reference:
- CLI.md (for command syntax)
- USER_GUIDE.md (for basic usage patterns)

---

## Common Documentation Patterns

### Command Examples

**Format:**
```bash
# Brief description
trapninja category command [options]

# Example with specific values
trapninja daemon start --interface eth0

# Example with output shown
trapninja daemon status
# Shows:
# Running: Yes
# Traps received: 1234
```

### Options Tables

**Format:**
| Option | Description | Default |
|--------|-------------|---------|
| `--name` | Option description | default value |

### Configuration Examples

**Format:**
```json
{
  "setting": "value",
  "array": [1, 2, 3]
}
```

With explanation of each field.

---

## File Locations

### Documentation Directory Structure

```
docs/
├── USER_GUIDE.md              # Primary user guide
├── CLI.md                     # CLI reference
├── INSTALL.md                 # Installation guide
├── ARCHITECTURE.md            # Architecture details
├── ARCHITECTURE_BRIEF.md      # Quick architecture overview
├── HA.md                      # High Availability
├── CACHE.md                   # Trap caching
├── GRANULAR_STATS.md          # Statistics system
├── METRICS.md                 # Prometheus metrics
├── SNMPV3_CREDENTIALS.md      # SNMPv3 management
├── SHADOW_MODE.md             # Testing modes
├── FAILOVER_REPLAY.md         # Automatic replay
├── CONFIG_SYNC.md             # HA config sync
├── CONFIG.md                  # Configuration reference
├── TROUBLESHOOTING.md         # Problem diagnosis
├── DIRECTORY_STRUCTURE.md     # Code organization
├── CLI_MODULE.md              # CLI module details
├── CODE_REVIEW.md             # Code standards
├── FRAGMENTATION.md           # Packet fragmentation
├── DOCUMENTATION_INDEX.md     # This file
└── refactoring/
    ├── REFACTORING_PLAN.md    # Refactoring roadmap
    └── CLEANUP_SUMMARY.md     # Cleanup tasks
```

### Other Documentation

```
dev/
└── CHANGELOG.md               # Version history

README.md                      # Project overview (root)

ansible/
└── README.md                  # Ansible deployment (if exists)
```

---

## Contact & Contributions

For documentation improvements:
1. Create an issue describing the documentation gap or error
2. Submit a pull request with proposed changes
3. Follow the standards outlined in this index

---

*Documentation Index Version: 1.0.0*
