# ripcord — Firmware RE Pipeline Design Notes

Working notes for **ripcord**, a tooling-heavy reverse-engineering pipeline
targeted at the `APP_2C53T_V1.2.0_251015.bin` firmware in the cord project.
The firmware runs on an ArteryTek AT32F403A (Cortex-M4, STM32F4-compatible-ish)
and talks to an opaque FPGA over what is almost certainly the EXMC/FSMC
external bus.

The name: pull the cord on a parachute, and a carefully packed structure
tumbles out and inflates into something functional. That's what this
pipeline does — one command takes an opaque binary in, and a structured,
queryable fact database expands out. "Rip" also fits: ripping ROMs,
ripping apart code. Cord is the target; ripcord is the tool that opens it.

## Project context

- **End goal:** write replacement firmware that drives the existing hardware
  (MCU + FPGA) faithfully enough to be a drop-in.
- **Hard constraint:** the FPGA is a black box. The only way to characterize
  its interface is through the MCU's interactions with it, as encoded in this
  binary.
- **Current state:** ~2 weeks of traditional manual RE completed. AT32-vs-STM32
  divergences already discovered during that work; those are real and need to
  be tracked explicitly.

## Core thesis

The firmware is, by construction, a complete executable specification of the
FPGA's interface. Every register, every sequence, every timing constraint is
in there — the MCU could not drive the FPGA otherwise. The problem is bounded.

The pipeline's job is to extract that specification at a scale and speed that
manual reading cannot match, using a combination of static analysis, dynamic
emulation, formal tools, and an LLM agent swarm coordinated through a
structured fact database.

## Documents in this folder

- [`goal-and-approach.md`](./goal-and-approach.md) — the reframe from
  "produce clean code" to "produce a hardware-boundary spec," and why Rust is
  probably not the right lift target.
- [`pipeline-architecture.md`](./pipeline-architecture.md) — stages of the
  pipeline, the blackboard/database coordination model, contracts-as-headers,
  locking, evidence log, convergence.
- [`tooling.md`](./tooling.md) — reference sheet for every tool discussed
  (Ghidra, Renode, Unicorn, angr, Soufflé, DuckDB, Snakemake, etc.) with
  what each does and when to reach for it.
- [`prior-art.md`](./prior-art.md) — communities doing adjacent work and what
  to steal from them. The N64 decomp scene and Asahi Linux are the most
  relevant references.
- [`test-corpus-and-validation.md`](./test-corpus-and-validation.md) —
  running the pipeline against open-source firmware where the ground
  truth is known, the test-difficulty ramp, and open-source hardware
  targets (ULX3S is the standout MCU+FPGA analog).
- [`fingerprinting.md`](./fingerprinting.md) — multi-signal function
  classification as a research thread: constants, strings, MMIO, CFG
  shape, call-graph neighborhood, learned embeddings, and the
  self-improving classifier+corpus loop.
- [`local-ml-fingerprinting.md`](./local-ml-fingerprinting.md) — the
  learned-model extension of the fingerprinting thread: P-Code
  tokenization (the potentially novel angle), multi-modal
  architecture, Apple Silicon deployment specifics, realistic model
  sizes, corpus generation, and a sidebar on whether Ghidra pseudo-C
  actually compiles (short answer: not reliably).
- [`use-cases-and-strategy.md`](./use-cases-and-strategy.md) — who
  reverse engineers firmware and why, the market landscape, existing
  tools, open-source-vs-paid-service tradeoffs, and honest framing
  about niche size.
- [`PLAN.md`](./PLAN.md) — concrete next steps in phases, with open questions.

## One-line summary of the whole approach

Populate a queryable database of facts about the binary; let small, verifiable
agent tasks refine it in parallel; anchor everything to ground-truth MMIO
traces from Renode; verify lifts with Unicorn-based differential testing;
treat the database itself as the deliverable.

## A key architectural observation

Everything in Stages 0-5 (Ghidra extraction, library identification, Renode
trace capture, static trace analysis, Datalog derivation, targeted angr
analysis) is **deterministic automation**. With a well-written Snakemake
pipeline and prewarmed caches, a bare firmware `.bin` can go from "input"
to "fully populated fact database, ready for LLM work" **in a few minutes**,
not days. That matters because:

- You can iterate on the pre-LLM pipeline cheaply, rerunning the full
  thing many times a day while tuning.
- The expensive phase (LLM agent swarm) only runs against a warehouse
  that's already been maximally enriched by free deterministic tools.
- Every agent dollar is spent on the actual unknown, not on work that
  static analysis could have done for free.
- You can onboard a new firmware target in minutes — which makes the
  test corpus strategy (`test-corpus-and-validation.md`) practical.

The pipeline's shape is specifically designed to make the pre-LLM path
fast and unattended. Treat that as a hard design constraint, not an
aspiration.
