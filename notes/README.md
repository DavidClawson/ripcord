# ripcord — Firmware RE Pipeline Design Notes

Working notes for **ripcord**, a research pipeline for reverse engineering
embedded firmware. The pipeline takes an opaque binary in and expands it
into a queryable, structured fact database that downstream tools —
deterministic analyzers, formal methods, and LLM agents — can operate on
without ever having to read the raw binary.

The name: pull a ripcord on a parachute, and a carefully packed structure
tumbles out and inflates into something functional. That's what this
pipeline does to firmware binaries. "Rip" also fits: ripping ROMs,
ripping apart code.

## Core thesis

Most of the work of reverse-engineering a well-behaved embedded binary
is not creative. Library code can be identified by structural matching.
Control flow can be recovered by static analysis. Hardware interactions
can be observed by emulation. Semantic equivalence can be verified by
differential execution. All of this is **deterministic automation** that
should run in minutes, not days, and should happen before any human
judgment or LLM involvement.

What remains after the deterministic pre-pass is the genuinely
application-specific code — the code that matters, the code that makes
the device distinctive. That residue is where an LLM agent swarm earns
its keep, operating against a pre-enriched structured database rather
than a raw 700KB binary. Every claim the swarm makes is verified by
execution before entering the canonical state.

The pipeline is built around this structure: heavy investment in the
deterministic fast path, so that when agents finally run, they spend
their budget exclusively on the things deterministic tools genuinely
cannot do.

## Inspiration and running example

ripcord was originally inspired by manual reverse-engineering work on a
proprietary firmware with an opaque FPGA peripheral (the "cord" project).
Several design arguments in these notes — the hardware-boundary spec
framing, the FPGA-API-is-encoded-in-the-firmware observation, the
Renode-as-ground-truth thesis — were sharpened on that specific case.
The notes occasionally use the cord case as a running example or as an
illustrative extreme.

**The pipeline is not coupled to any specific target.** It is designed
to work on any embedded firmware. The cord case is a motivating example
and a possible future stress test; it is not a requirement and not the
scope.

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
