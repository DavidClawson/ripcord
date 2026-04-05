# ripcord

A research pipeline for reverse engineering embedded firmware. Takes
an opaque binary in and expands it into a queryable, structured fact
database that downstream tools — deterministic analyzers, formal
methods, and LLM agents — can operate on without ever having to read
the raw binary.

Pull the cord on a parachute and a carefully packed structure tumbles
out and inflates. The goal of this pipeline is the same operation
applied to firmware: one command, binary in, structure out.

## Design goals

- **Fast deterministic pre-processing.** Everything that doesn't
  require human judgment — Ghidra extraction, library identification,
  hardware trace capture, static derivation — runs unattended in
  minutes, not hours. LLM budget is spent only on the residue that
  deterministic tools can't handle.
- **The database is the artifact.** The deliverable is not clean
  source code; it is a queryable database of facts about the binary
  (functions, basic blocks, call graph, MMIO access patterns,
  hardware interactions, behavioral traces). Rendered source code, if
  it exists at all, is a late-stage view over the database.
- **Execution-based verification, not compiler-based.** Every claim
  about what a function does is verified by running it in Unicorn and
  diffing register/memory/MMIO deltas against the original, not by
  whether the replacement compiles. Compilers catch type errors;
  execution catches logic errors.
- **Function fingerprinting as a first-class capability.** A
  multi-signal classifier (rules → gradient-boosted features →
  learned embeddings) identifies library code cheaply so the
  agent swarm can focus on the genuinely novel.
- **Hardware-boundary trace capture as ground truth.** When the
  target has an opaque hardware peripheral (FPGA, ASIC, external
  coprocessor), the only observable surface is the MCU's MMIO
  interactions with it. Renode captures those traces; they anchor
  every subsequent analysis.

## Status

**Design complete, Phase 0 scaffolding in progress.** The architecture
is captured in [`notes/`](./notes/) across a dozen design documents.
This repo now contains an initial Snakemake pipeline that runs Ghidra
headless against a target binary, extracts function metadata via a
Ghidrathon script, and ingests the results into a DuckDB warehouse.
See [`notes/PLAN.md`](./notes/PLAN.md) for the phased roadmap.

The first test target is a Raspberry Pi Pico SDK blinky example —
Cortex-M0+, bare metal, known ground truth. Subsequent targets will
add an RTOS (FreeRTOS on Pico, or Zephyr on a QEMU Cortex-M3), then
vendor HAL exposure (STM32 CubeMX samples), then AVR and RISC-V for
architecture diversity.

## Design overview

Start with [`notes/README.md`](./notes/README.md) for the index. The
recommended reading order:

1. [`notes/goal-and-approach.md`](./notes/goal-and-approach.md) — why
   a structured fact database is the right artifact, not clean code
2. [`notes/pipeline-architecture.md`](./notes/pipeline-architecture.md)
   — the full pipeline design, warehouse model, and blackboard
3. [`notes/tooling.md`](./notes/tooling.md) — every tool involved and
   when to reach for it
4. [`notes/prior-art.md`](./notes/prior-art.md) — adjacent communities
   and what to steal from them
5. [`notes/fingerprinting.md`](./notes/fingerprinting.md) and
   [`notes/local-ml-fingerprinting.md`](./notes/local-ml-fingerprinting.md)
   — the function classification research thread
6. [`notes/test-corpus-and-validation.md`](./notes/test-corpus-and-validation.md)
   — validation methodology and the fingerprint library
7. [`notes/use-cases-and-strategy.md`](./notes/use-cases-and-strategy.md)
   — who else does firmware RE and why
8. [`notes/PLAN.md`](./notes/PLAN.md) — concrete next steps

## Getting started

See [`SETUP.md`](./SETUP.md) for toolchain prerequisites (Ghidra,
Ghidrathon, Python 3.11+, Snakemake, DuckDB, and optionally the
Pico SDK for building the first test target).

Quick start once tools are installed:

```bash
# Build a test target (see targets/README.md for options)
cd targets && <build a blinky> && cd ..

# Run the pipeline
snakemake --cores 4

# Query the warehouse
duckdb build/warehouse.duckdb "SELECT source, name, size FROM functions ORDER BY size DESC LIMIT 10"
```

## Origin

ripcord was originally inspired by manual reverse-engineering work on
a proprietary firmware target with an opaque FPGA peripheral (the
"cord" project). The design arguments throughout the notes are
informed by that work — the hardware-boundary spec framing in
particular came from the FPGA case — but the pipeline is built to be
general-purpose and is not coupled to any specific target. The cord
firmware may become a stress-test target once ripcord is proven
against simpler well-behaved binaries.

## License

Pipeline code in this repository will be released under a permissive
open-source license once there's enough of it to be useful. Firmware
binaries analyzed by the pipeline are not included in this
repository and their licensing is the property of their original
authors.

## Repository structure

```
ripcord/
├── README.md              (this file)
├── SETUP.md               (toolchain prerequisites)
├── Snakefile              (pipeline definition)
├── config.yaml            (target binary list)
├── .gitignore
├── notes/                 (design notes)
├── scripts/
│   ├── ghidra/            (Ghidrathon extraction scripts)
│   └── ingest/            (DuckDB ingest scripts)
├── schema/                (warehouse schema migrations)
└── targets/               (test binaries, gitignored)
```
