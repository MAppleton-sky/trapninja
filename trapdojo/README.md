# TrapDojo — TrapNinja Load Test Rig

> **Status:** design phase (R0). No implementation yet.

TrapDojo is a standalone load-testing rig for **TrapNinja**. It runs alongside TrapNinja in this repository during initial design and R0/R1 development, and will move to its own repository when the R2 exit criterion is met.

## Documentation

Start here depending on your audience:

| Reader | Start with | Approx read time |
|---|---|---|
| Anyone new to TrapDojo — NOC ops leads, PMs, sponsors, security reviewers, auditors | [docs/Overview-TestRig.md](docs/Overview-TestRig.md) | 10 minutes |
| Engineering / architecture reviewers | [docs/HighLevel-TestRig.md](docs/HighLevel-TestRig.md) | 30 minutes |
| Developers implementing the rig | [docs/LowLevel-TestRig.md](docs/LowLevel-TestRig.md) | 60 minutes |

The three documents are consistent by design. The Overview is deliberately kept jargon-free; the HLD explains *what* and *why*; the LLD is the implementation specification.

## Directory layout

The layout mirrors what will exist in the standalone TrapDojo repo when the split happens. All directories except `docs/` are placeholders until R0 code lands.

```
trapdojo/
├── docs/                  # Overview, HLD, LLD (design phase artefacts)
├── src/                   # R0+ Python source (packages per the LLD)
├── dev/
│   ├── tests/             # R0+ unit + integration tests
│   └── scripts/           # download-packages.sh, install-packages.sh, host prep
├── config.example/        # example configs (per-host config, scenarios)
├── scenarios/             # scenario JSON files
│   └── oid-mixes/         # weighted OID pools referenced by scenarios
├── ansible/
│   └── roles/trapdojo/    # host prep + container image deploy
├── containers/
│   ├── Dockerfile         # single OCI image, all subcommands
│   ├── entrypoint.sh
│   └── profiles/          # host sysctl drop-ins, systemd units
└── README.md              # this file
```

## Relationship to TrapNinja in this repo

Two independent products, one repository (for now):

- **TrapNinja** lives at the top level (`src/trapninja/`, top-level `docs/`, top-level `dev/tests/`, etc.). It is the **System Under Test** (SUT) from TrapDojo's perspective.
- **TrapDojo** lives entirely under this `trapdojo/` directory. It is the **rig**. It never modifies or runs on TrapNinja hosts.

The two projects share nothing at the code level. TrapDojo consumes TrapNinja's public surface only — the CLI (`trapninja metrics show --json`, `trapninja config show --json --canonical`), the Prometheus `.prom` files, and a small whitelist of SSH-invoked actions.

## TrapNinja prerequisites

Three small additions to TrapNinja must land before TrapDojo's R2 phase begins. Full detail in the [LLD § SUT Counter Uncertainty Handling](docs/LowLevel-TestRig.md#sut-counter-uncertainty-handling); summary:

- **P1** `trapninja_process_start_tai_ns` gauge
- **P2** `trapninja_metrics_snapshot_id` counter
- **P3** `trapninja config show --json --canonical` deterministic output

Plus the previously agreed forward-failure metrics work.

## Repository split

When R2 exits, TrapDojo becomes a separate git repository. The move is expected to be mechanical:

1. `git subtree split --prefix=trapdojo/ -b trapdojo-split`
2. Push the split branch to the new repository.
3. Drop `trapdojo/` from this repository.

The layout above is chosen so that step 1 produces a valid standalone repository with no rearrangement.
