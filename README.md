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

## Status (2026-04-05)

**Phase 0 complete, Stage 0 wide, Phase 1 rule-based fingerprinting
validated end-to-end on a same-build target pair.** The pipeline
runs Ghidra headless (via PyGhidra's `pyghidraRun -H`) against every
target in `config.yaml`, extracts per-function metadata as JSONL,
and writes six typed Parquet tables per target under
`build/<target>/tables/`:

- `functions` — one row per Ghidra-discovered function
- `calls` — one row per call site
- `basic_blocks` — one row per CodeBlock
- `xrefs` — non-call references (reads, writes, jumps, data)
- `strings` — defined strings in loaded memory
- `ground_truth_functions` — nm -S symbols (regression signal)

DuckDB is the query engine over the Parquet tree — there is no
persistent database file. See
[`notes/PLAN.md`](./notes/PLAN.md) for the phased roadmap and
[`notes/design-decisions.md`](./notes/design-decisions.md) §D15 for
the Parquet-as-truth rationale.

**Three targets currently in the warehouse:** Raspberry Pi Pico SDK
blinky (Cortex-M0+, newlib, -O3), Zephyr hello_world on
qemu_cortex_m3 (Cortex-M3, picolibc, -Os), and Zephyr
synchronization on the same qemu_cortex_m3 board.

**Phase 1 baseline result:** the rule-based structural fingerprinting
query in `notes/queries/structural_signatures.sql` hits **~96%
cluster-level precision** matching functions between the two Zephyr
targets (72 of 75 cross-target clusters carry identical names). The
same query finds essentially nothing between Pico and Zephyr because
the build configs differ on four axes (ISA, -O level, libc, link
surface). Empirical write-up in
[`notes/fingerprinting-baseline.md`](./notes/fingerprinting-baseline.md);
design decision D18 records the corpus build-matrix constraint that
came out of this validation.

## Design overview

Start with [`notes/README.md`](./notes/README.md) for the index. The
recommended reading order:

1. [`notes/goal-and-approach.md`](./notes/goal-and-approach.md) — why
   a structured fact database is the right artifact, not clean code
2. [`notes/pipeline-architecture.md`](./notes/pipeline-architecture.md)
   — the full pipeline design, warehouse model, and blackboard
3. [`notes/design-decisions.md`](./notes/design-decisions.md) — the
   architectural choices and their reasoning (append-only log)
4. [`notes/fingerprinting-baseline.md`](./notes/fingerprinting-baseline.md)
   — the empirical Phase 1 current state (96% precision result and
   what it means)
5. [`notes/ghidra-extraction-notes.md`](./notes/ghidra-extraction-notes.md)
   — calibrated extractor findings against `nm` ground truth
6. [`notes/PLAN.md`](./notes/PLAN.md) — phased roadmap with current
   status markers
7. [`notes/tooling.md`](./notes/tooling.md) — every tool involved and
   when to reach for it
8. [`notes/prior-art.md`](./notes/prior-art.md) — adjacent communities
   and what to steal from them
9. [`notes/fingerprinting.md`](./notes/fingerprinting.md) and
   [`notes/local-ml-fingerprinting.md`](./notes/local-ml-fingerprinting.md)
   — the function classification research design (the baseline file
   above is the empirical status)
10. [`notes/test-corpus-and-validation.md`](./notes/test-corpus-and-validation.md)
    — validation methodology and the fingerprint library
11. [`notes/use-cases-and-strategy.md`](./notes/use-cases-and-strategy.md)
    — who else does firmware RE and why

## Getting started

See [`SETUP.md`](./SETUP.md) for toolchain prerequisites (Ghidra,
Python 3.11+ with `pyghidra`, Snakemake, DuckDB, and optionally the
Pico SDK for building the first test target).

Quick start once tools are installed:

```bash
# Build a test target (see targets/README.md for options)
cd targets && <build a blinky> && cd ..

# Run the pipeline
snakemake --cores 4

# Query the warehouse (Parquet tables under build/<target>/tables/)
scripts/query "SELECT source, name, size FROM functions ORDER BY size DESC LIMIT 10"
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
├── CLAUDE.md              (project orientation for Claude Code sessions)
├── SETUP.md               (toolchain prerequisites)
├── Snakefile              (pipeline definition)
├── config.yaml            (target binary list)
├── .gitignore
├── notes/                 (design notes + committed queries)
│   └── queries/           (SQL files, executable documentation)
├── scripts/
│   ├── query              (SQL over build/*/tables/*.parquet)
│   ├── ghidra/            (PyGhidra extraction scripts, one per table)
│   └── ingest/            (schemas.py, load_table.py, load_ground_truth.py)
└── targets/               (test binaries, gitignored)
```

For the full file-level layout (every extractor, every committed
query, every notes file) see the "Repository layout" section in
[`CLAUDE.md`](./CLAUDE.md).
