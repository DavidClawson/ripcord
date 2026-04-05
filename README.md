# ripcord

A firmware reverse-engineering pipeline targeted at the cord project:
an ArteryTek AT32F403A (Cortex-M4, STM32F4-compatible-ish) driving an
opaque FPGA over the EXMC/FSMC external bus.

Pull the cord on a parachute and a packed structure tumbles out and
inflates into something functional. This pipeline does the same for
firmware binaries — one command takes an opaque binary in, and a
queryable structured fact database expands out.

## Status

Design phase. No pipeline code yet. The complete design is captured in
[`notes/`](./notes/), and the concrete bootstrapping steps are in
[`notes/PLAN.md`](./notes/PLAN.md).

The first runnable milestone (Phase 0) is a Snakemake pipeline that:

1. Runs Ghidra headless with a Ghidrathon extraction script
2. Dumps functions, basic blocks, P-Code, xrefs, and strings to Parquet
3. Ingests into a DuckDB warehouse
4. Boots the firmware in Renode with FSMC bus logging and captures a
   first MMIO trace into the same warehouse

From there the pipeline grows through library identification, dynamic
trace analysis, Datalog derivation, targeted angr analysis, an LLM
agent swarm coordinated through a blackboard, and Unicorn-based
differential verification.

## Design overview

Start with [`notes/README.md`](./notes/README.md) for the index. The
recommended reading order is roughly:

1. [`notes/goal-and-approach.md`](./notes/goal-and-approach.md) — why
   the goal is a hardware-boundary spec, not clean code
2. [`notes/pipeline-architecture.md`](./notes/pipeline-architecture.md)
   — the full pipeline design and database model
3. [`notes/tooling.md`](./notes/tooling.md) — every tool involved and
   when to reach for it
4. [`notes/prior-art.md`](./notes/prior-art.md) — who does adjacent
   work and what to steal from them
5. [`notes/fingerprinting.md`](./notes/fingerprinting.md) and
   [`notes/local-ml-fingerprinting.md`](./notes/local-ml-fingerprinting.md)
   — the function classification research thread
6. [`notes/test-corpus-and-validation.md`](./notes/test-corpus-and-validation.md)
   — validation methodology and fingerprint library
7. [`notes/use-cases-and-strategy.md`](./notes/use-cases-and-strategy.md)
   — who else cares about firmware RE and why
8. [`notes/PLAN.md`](./notes/PLAN.md) — concrete next steps

## Getting started

See [`SETUP.md`](./SETUP.md) for the inputs this pipeline expects and
where they should live on disk. The firmware binary and vendor SDKs
are not tracked in this repository — they live in the parent
directory and are referenced at pipeline runtime.

## License

The pipeline code in this repository (once it exists beyond design
notes) will likely be released under a permissive license. The
firmware binary this pipeline analyzes is the original vendor's
property and is not part of this repository.

## Repository structure

```
ripcord/
├── README.md          (this file)
├── SETUP.md           (inputs and prerequisites)
├── .gitignore
└── notes/             (design notes — the authoritative current state)
```

Directories for pipeline code, scripts, platform files, and schema
migrations will be added as they gain content. Intentionally minimal
until there is something real to put in them.
