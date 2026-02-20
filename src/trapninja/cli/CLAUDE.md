# CLI Module — Scoped Rules

> Read `../../CLAUDE.md` for project-wide rules. This file adds **CLI-specific constraints**.

## CLI Design Principles

The CLI is the primary operational interface for NOC staff and automation tooling.
It must be discoverable, consistent, and produce clear output under all conditions.

### Subcommand Structure (Enforced)
All commands follow the pattern: `trapninja <group> <action> [options]`

| Group | Actions |
|-------|---------|
| `config` | `show`, `reload`, `validate`, `set`, `diff` |
| `stats` | `show`, `reset`, `export` |
| `ha` | `status`, `promote`, `demote`, `sync` |
| `cache` | `status`, `flush`, `replay` |
| `daemon` | `start`, `stop`, `restart`, `status` |
| `metrics` | `show`, `export` |
| `filtering` | `show`, `test`, `reload` |
| `failover` | `status`, `trigger`, `cancel` |

**No flat/legacy argument style.** The subcommand structure is canonical.

### Command Registry Pattern
- All commands registered via `registry.py` — no direct conditional dispatch in `parser.py`.
- Each command group has its own file in `cli/` and corresponding parser in `cli/parsers/`.
- Adding a new command: add to the registry and parser — no changes to core CLI logic.

### Output Formatting Rules
- Default output: human-readable tables / key-value for NOC operators.
- `--json` flag: machine-readable JSON for all status commands (for automation/monitoring).
- `--quiet` flag: suppress decorative output, return only essential data.
- Errors to stderr, data to stdout — always.
- Exit codes: 0 = success, 1 = operational error, 2 = usage/argument error, 3 = connection error.

### Error Messages
Format: `ERROR [<component>]: <what failed>. <why it failed>. <what to do>.`

Example:
```
ERROR [ha]: Cannot promote to Primary. Redis connection refused at 10.0.0.5:6379.
Check that Redis is running and reachable, then retry.
```

### Validation (`validation.py`)
- Validate all user-supplied values before sending to the daemon.
- Reject invalid IP addresses, port numbers out of range, unknown OID formats.
- Path inputs: validate against traversal (`../`) and enforce allowed base directories.

### Control Socket (`control.py`)
- CLI communicates with the daemon via Unix domain socket.
- Socket path must be validated (no traversal, within expected directory).
- Timeout all socket operations — never hang indefinitely waiting for daemon response.
- Rate-limit control operations at the socket level.

### Testing Requirements
- Parser tests: all valid and invalid argument combinations
- Executor tests: command dispatch, error propagation
- Output tests: correct formatting for both human and JSON modes
- Validation tests: all rejection cases (bad IP, bad path, bad OID, etc.)
- Control socket tests: timeout handling, connection refused, daemon response errors
