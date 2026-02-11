# TrapNinja Documentation Index

**Last Updated**: 2026-02-11  
**TrapNinja Version**: 0.7.16 (Beta)

All project documentation lives in this `docs/` directory. The `documentation/` directory has been consolidated here.

---

## User-Facing Documentation

### Core

| Document | Purpose | Status |
|----------|---------|--------|
| [USER_GUIDE.md](USER_GUIDE.md) | Primary user guide with modern CLI syntax | ✅ Current |
| [CLI.md](CLI.md) | Complete CLI reference for all commands | ✅ Current |
| [INSTALL.md](INSTALL.md) | Installation and deployment guide | 📝 Needs Review |
| [CONFIG.md](CONFIG.md) | Configuration file reference | ✅ Current |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Problem diagnosis guide | 📝 Needs Review |

### Features

| Document | Purpose | Status |
|----------|---------|--------|
| [HA.md](HA.md) | High Availability configuration | ✅ Current |
| [CACHE.md](CACHE.md) | Redis caching and replay | ✅ Current |
| [FAILOVER_REPLAY.md](FAILOVER_REPLAY.md) | Automatic gap replay | ✅ Current |
| [CONFIG_SYNC.md](CONFIG_SYNC.md) | HA configuration synchronisation | ✅ Current |
| [GRANULAR_STATS.md](GRANULAR_STATS.md) | Statistics system details | ✅ Current |
| [METRICS.md](METRICS.md) | Prometheus metrics reference | ✅ Current |
| [SNMPV3_CREDENTIALS.md](SNMPV3_CREDENTIALS.md) | SNMPv3 user management | ✅ Current |
| [SHADOW_MODE.md](SHADOW_MODE.md) | Testing and observation modes | ✅ Current |
| [FRAGMENTATION.md](FRAGMENTATION.md) | Packet fragmentation handling | 📝 Needs Review |
| [SECURITY.md](SECURITY.md) | Security measures and CWE remediation | ✅ Current |

---

## Developer Documentation

### Architecture

| Document | Purpose | Status |
|----------|---------|--------|
| [ARCHITECTURE_BRIEF.md](ARCHITECTURE_BRIEF.md) | Quick architecture overview | 📝 Needs Review |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detailed system design | 📝 Needs Review |
| [DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md) | Code organisation | 📝 Needs Review |
| [CLI_MODULE.md](CLI_MODULE.md) | CLI module internals | ✅ Current |

### Code Quality & Refactoring

| Document | Purpose | Status |
|----------|---------|--------|
| [CODE_REVIEW.md](CODE_REVIEW.md) | Security code review (Dec 2024) | ✅ Complete |
| [refactoring/CODE-REVIEW-REFACTORING-ANALYSIS.md](refactoring/CODE-REVIEW-REFACTORING-ANALYSIS.md) | Duplication/bloat analysis & refactoring plan (Feb 2026) | 🔄 In Progress |
| [refactoring/OPTIONAL-MODULES-SYSTEM.md](refactoring/OPTIONAL-MODULES-SYSTEM.md) | Optional modules registry design | ✅ Implemented |
| [refactoring/LEGACY_CODE_REVIEW.md](refactoring/LEGACY_CODE_REVIEW.md) | Legacy code identification (Phase 1) | ✅ Complete |
| [refactoring/PHASE2_LEGACY_CODE_REVIEW.md](refactoring/PHASE2_LEGACY_CODE_REVIEW.md) | Legacy code identification (Phase 2) | ✅ Complete |
| [refactoring/REFACTORING_PLAN.md](refactoring/REFACTORING_PLAN.md) | Original refactoring roadmap | Superseded by CODE-REVIEW-REFACTORING-ANALYSIS.md |
| [refactoring/CLEANUP_SUMMARY.md](refactoring/CLEANUP_SUMMARY.md) | Cleanup tasks summary | ✅ Complete |
| [fixes/CACHE_INTEGRATION_FIX.md](fixes/CACHE_INTEGRATION_FIX.md) | Cache integration bug fix | ✅ Complete |

---

## Refactoring Status (Feb 2026)

See [refactoring/CODE-REVIEW-REFACTORING-ANALYSIS.md](refactoring/CODE-REVIEW-REFACTORING-ANALYSIS.md) for full details.

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Optional modules registry (`core/optional_modules.py`) | ✅ Complete |
| Phase 2 | Service refactor (`core/service_init.py`) | ✅ Complete |
| Phase 3 | CLI refactor (`cli/command_base.py`, `cli/registry.py`) | ✅ Complete |
| Phase 4 | Testing & documentation | 🔄 In Progress |

| Priority 2 | Description | Status |
|-------------|-------------|--------|
| R2.1 | Command registry system | ✅ Complete (`cli/registry.py`) |
| R2.2 | Centralised configuration I/O | Not Started |
| R2.3 | Validation consolidation | Not Started |

---

## Quick Navigation

### For Users

1. [INSTALL.md](INSTALL.md) → Installation
2. [USER_GUIDE.md](USER_GUIDE.md) → Daily operations
3. [CLI.md](CLI.md) → Command reference
4. [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → Problem solving

### For Developers

1. [ARCHITECTURE_BRIEF.md](ARCHITECTURE_BRIEF.md) → System overview
2. [DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md) → Code layout
3. [refactoring/CODE-REVIEW-REFACTORING-ANALYSIS.md](refactoring/CODE-REVIEW-REFACTORING-ANALYSIS.md) → Active refactoring plan

---

## Directory Structure

```
docs/
├── DOCUMENTATION_INDEX.md          # This file
├── USER_GUIDE.md                   # Primary user guide
├── CLI.md                          # CLI reference
├── INSTALL.md                      # Installation guide
├── CONFIG.md                       # Configuration reference
├── TROUBLESHOOTING.md              # Problem diagnosis
├── ARCHITECTURE.md                 # Detailed architecture
├── ARCHITECTURE_BRIEF.md           # Quick architecture overview
├── DIRECTORY_STRUCTURE.md          # Code organisation
├── HA.md                           # High Availability
├── CACHE.md                        # Trap caching
├── FAILOVER_REPLAY.md              # Automatic replay
├── CONFIG_SYNC.md                  # HA config sync
├── GRANULAR_STATS.md               # Statistics system
├── METRICS.md                      # Prometheus metrics
├── SNMPV3_CREDENTIALS.md           # SNMPv3 management
├── SHADOW_MODE.md                  # Testing modes
├── FRAGMENTATION.md                # Packet fragmentation
├── SECURITY.md                     # Security measures
├── CLI_MODULE.md                   # CLI module internals
├── CODE_REVIEW.md                  # Security code review
├── refactoring/                    # Refactoring documentation
│   ├── CODE-REVIEW-REFACTORING-ANALYSIS.md  # Active refactoring plan
│   ├── OPTIONAL-MODULES-SYSTEM.md           # Optional modules design
│   ├── LEGACY_CODE_REVIEW.md                # Legacy code Phase 1
│   ├── PHASE2_LEGACY_CODE_REVIEW.md         # Legacy code Phase 2
│   ├── REFACTORING_PLAN.md                  # Original roadmap
│   └── CLEANUP_SUMMARY.md                   # Cleanup tasks
└── fixes/
    └── CACHE_INTEGRATION_FIX.md             # Cache fix details
```

---

*Documentation Index Version: 2.0.0*
