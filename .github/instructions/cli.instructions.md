---
applyTo: "src/trapninja/cli/**"
---

# CLI — Structure and Standards

## Subcommand Structure

TrapNinja uses a **Command Registry pattern** — not a monolithic if/elif CLI handler. All subcommands are registered handlers. New commands are added by registering, not by editing a dispatcher.

Current command structure:
```
trapninja start [options]
trapninja stop
trapninja status
trapninja config show
trapninja config validate
trapninja stats show
trapninja stats baseline save <name>
trapninja stats baseline compare <name>
trapninja metrics
```

## No Legacy Flat-Flag Support

All legacy flat-flag invocations (`trapninja --start`, `trapninja --stats`) were removed in v0.8.0. Do not re-introduce them. There is no compatibility shim and there will not be one.

## Error Messages

CLI error messages must be:
- Specific about what failed
- Specific about why
- Specific about what the operator should do to fix it

```python
# GOOD
print(f"ERROR: Config key 'destinations' is missing. "
      f"Add at least one destination in /etc/trapninja/trapninja.yaml")
sys.exit(1)

# BAD
print("Configuration error")
sys.exit(1)
```

## No Sensitive Data in CLI Output

CLI output must never display SNMPv3 credentials, auth keys, priv keys, or community strings. When showing config, display masked values (`***`) for credential fields.

## Baseline Commands

`trapninja stats baseline save <name>` — saves current stats snapshot to `/etc/trapninja/baselines/<name>.json`
`trapninja stats baseline compare <name>` — compares current stats against a saved baseline

These are node-local operations. They do not involve Redis. They do not communicate with the peer node.
