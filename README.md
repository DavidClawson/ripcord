# ripcord

**Opaque firmware binary in, queryable fact database out — one command.**

ripcord is a research pipeline for reverse engineering embedded firmware.
It takes a binary with no symbols, no source, and an undocumented hardware
peripheral, and expands it into a structured warehouse of facts —
functions, call graph, MMIO access patterns, decompiled C, behavioral
traces — that deterministic analyzers, formal methods, and LLM agents can
all query without ever re-reading the raw bytes.

> Pull the ripcord on a parachute and a carefully packed structure tumbles
> out and inflates into something functional. Same operation, applied to
> firmware.

The driving target is the **FNIRSI 2C53T oscilloscope** (AT32F403A MCU + an
opaque Gowin FPGA). The hardest, most valuable part of that firmware is the
FPGA acquisition path — timing-critical code talking to a chip with *no
public documentation and no source*. The only way to know what the FPGA
does is to watch the MCU talk to it. ripcord is built to capture that
conversation and turn it into an execution-verified protocol spec.

---

## The idea in one picture

```
   firmware.bin
        │
        ▼
┌───────────────────┐   deterministic, runs in minutes, no human judgment
│  IDENTIFY         │   ISA · load address · chip family  (scripts/identify.py)
├───────────────────┤
│  EXTRACT (Ghidra) │   functions · calls · blocks · xrefs · strings
│                   │   pcode · decompiled C            (PyGhidra headless)
├───────────────────┤
│  RECOVER          │   vector tables, func-ptr dispatch, veneers, registrars
│                   │   → closes the call-graph reachability gap
├───────────────────┤
│  CLASSIFY         │   SVD-resolved peripheral register access · fingerprint
│                   │   match library code across compilers
├───────────────────┤
│  TRACE (Renode)   │   boot the binary, capture MMIO transcript = ground truth
└─────────┬─────────┘
          ▼
   ┌─────────────────────────────────────────┐
   │   THE WAREHOUSE                          │   per-target Parquet tables,
   │   build/<target>/tables/*.parquet        │   queried with DuckDB.
   │   (no database file — Parquet is truth)  │   THIS is the artifact.
   └─────────┬───────────────────────────────┘
             │
     ┌───────┴────────┬─────────────────┬──────────────────┐
     ▼                ▼                 ▼                  ▼
  scripts/query   LLM agent swarm   Unicorn / Renode    Claude Code
  (SQL / DuckDB)  (bulk labeling)   (VERIFY by          (skills + CLI:
                                     execution)          drives it all)
```

Two principles do the heavy lifting:

1. **Execution is the verification oracle — not the compiler.** A claim about
   what a function does is confirmed by *running* it (Unicorn) or *tracing*
   it (Renode) and diffing register/memory/MMIO deltas against the original.
   Compilers catch type errors; execution catches logic errors. No claim
   becomes canonical until execution backs it. This is the part most RE
   tooling skips (see [Related work](#related-work)).

2. **The database is the artifact — not clean source code.** The deliverable
   is a queryable set of facts about the binary. Rendered C, if it exists at
   all, is a late-stage *view* over the database, never the goal. (Why:
   [`notes/goal-and-approach.md`](./notes/goal-and-approach.md).)

LLM budget is spent only on the *residue* deterministic tools can't resolve.
Everything mechanical — Ghidra extraction, library identification, call
recovery, trace capture — runs unattended in minutes.

---

## Quick start

```bash
# Identify ISA / load address / chip before committing to a full run
scripts/identify.py firmware.bin

# One command: identify → extract → ingest → recover calls → classify → summarize
scripts/ripcord.py firmware.elf                                   # ELF: flags inferred
scripts/ripcord.py firmware.bin --chip AT32F403A --base-addr 0x08004000  # raw binary

# Ask questions over the warehouse + decompiled C + an LLM
scripts/analyze --target stock_v120 "what writes to USART2_DR?"

# Full bottom-up comprehension: smoke-test every function, name them,
# decompose monsters, synthesize subsystem → architecture narratives
uv run python scripts/agents/deep_analysis.py --target stock_v120

# Render a self-contained HTML report
scripts/render/report.py stock_v120

# (optional) Expose the warehouse over MCP for a client without shell access.
# The primary path is Claude Code running the tools + skills above directly.
uv run python scripts/mcp_server.py --build-dir ./build
```

See [`SETUP.md`](./SETUP.md) for toolchain prerequisites (Ghidra 11.2+ with
PyGhidra, Python 3.11+, `uv`, Snakemake, DuckDB; optionally Renode and a
cross-toolchain to build the test corpus).

---

## Why the harness is the point

Most "LLM + Ghidra" tools feed a single decompiled function to a model and
ask "what does this do?" — a fragment with no surrounding context. That
starves the model exactly where embedded RE is hardest.

ripcord inverts it. The deterministic pipeline builds a rich, *queryable*
context first; then **Claude Code drives** — running the CLI tools and
skills (`.claude/skills/`) directly to pull precisely the tables, decompiled
bodies, peripheral maps, and execution traces it needs, iteratively, while
reasoning about the binary as a whole *and building new tools mid-task* when
a target demands them. Reusable procedures harden into skills
(`firmware-bringup`, `execution-verify`); execution-verified conclusions land
in the contract ledger (`scripts/contracts/ledger.py`), which is the durable
product. The single-shot API paths (`scripts/analyze`, the agent swarm) stay
for cheap, scoped, *measurable* sub-tasks — fingerprint matching, bulk
function labeling — where a fragment genuinely is enough. An
[MCP server](./scripts/mcp_server.py) remains as optional interop for a
client that can't run the shell; it isn't the primary surface, because
ripcord's data is local Parquet the driver already reads directly.
Comprehension lives in the harness, not the access protocol.

---

## What's in the warehouse

A `snakemake --cores 4 --resources ghidra=1` run produces typed Parquet
tables per target under `build/<target>/tables/`. Agent and validation
stages add more. Highlights:

| table                  | grain                                                        |
|------------------------|--------------------------------------------------------------|
| `functions`            | one row per Ghidra-discovered function (incl. `body_hash`)   |
| `calls` / `xrefs`      | call sites; non-call references (reads, writes, jumps, data) |
| `basic_blocks`         | one row per CodeBlock, with containing function              |
| `strings`              | defined strings in loaded memory                             |
| `decompiled`           | Ghidra decompiled pseudo-C, one row per function             |
| `pcode_features`       | per-function P-Code opcode histogram + sequence hash         |
| `recovered_calls`      | recovered indirect call edges (vector table, func ptr, …)    |
| `peripheral_xrefs`     | SVD-resolved peripheral register accesses                    |
| `mmio_events`          | MemoryIORead/Write from a Renode trace, joinable by PC       |
| `unicorn_smoke`        | per-function executability (catches code-vs-data misdecode)  |
| `ground_truth_functions` | `nm -S` symbols, the regression signal                     |

All tables are auto-discovered as DuckDB views by `scripts/query`. The
[`notes/queries/`](./notes/queries/) directory holds committed SQL that
doubles as executable documentation and regression tests.

---

## Current state (2026-05)

Phase 0 complete; Phase 1 library-ID validated end-to-end including blind
recovery on a stripped binary; Phase 3 agent swarm validated end-to-end.
Renode trace capture and Datalog (Souffle) derivations are wired into the
Snakemake DAG. Deep hierarchical analysis, context enrichment, and Unicorn
execution-validation are built on top.

**Fifteen targets across four build ecosystems** live in the warehouse:
5 Raspberry Pi Pico (Cortex-M0+), 2 Zephyr (Cortex-M3), 1 stripped blind-
recovery target, 3 AT32F403A reference builds (GCC + LLVM, the cross-compiler
corpus), and 4 stock FNIRSI 2C53T firmware versions (V1.0.3–V1.2.0) — the
primary target *and* its own differential ground truth.

A few empirical results that fell out (full list and provenance in
[`CLAUDE.md`](./CLAUDE.md) → "Key empirical findings"):

- **Blind recovery on a stripped binary: 86.6% recall, 94.9% precision** —
  171/197 functions re-identified with zero symbols.
- **Computed-call recovery closes the reachability gap from 70% unreachable
  to 12%** via five recovery mechanisms at ~95% blended precision.
- **Constant-based fingerprinting: 100% precision, cross-compiler.**
- **Execution catches what static analysis can't** — the Unicorn smoke test
  flags Ghidra decoding data as code, the #1 failure mode for raw imports.
- **The FNIRSI V1.0.3→V1.0.7 transition was a full architectural rewrite of
  the FPGA acquisition path** (USART2-only → DMA/SPI3), confirmed by
  byte-identical FreeRTOS port code against a GCC reference build.

---

## Related work

ripcord's individual ingredients all exist in the wild; the combination —
a structured fact warehouse **plus** an execution-as-verification oracle
**plus** a skills-driven Claude Code harness with a provenance-tracked
contract ledger, pointed at *comprehending* an opaque binary — is the part I
haven't found assembled elsewhere. Honest positioning:

- **LLM + disassembler tools** (Gepetto, G-3PO, aiDAPal, DeGPT) mostly send a
  decompiled snippet to a model and write back a rename/comment. ripcord
  builds queryable context *first*, so the model never reasons from a
  context-free fragment.
- **Persistent structured state is no longer a differentiator.**
  [GhidrAssist](https://github.com/jtang613/GhidrAssist) (open source, a
  SQLite+graph knowledge DB with a 5-level hierarchy) and **Binary Ninja
  Sidekick** (commercial, with provenance and a background validation agent)
  both build it. ripcord's separation is that **their validation is static**
  — re-analysis and cross-reference queries — whereas ripcord gates every
  canonical claim on *execution*.
- **MCP-over-a-disassembler is table stakes — and not where ripcord's value
  is.** [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (9k+ stars) and
  [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp) are mature; they
  expose *live tool calls* over a protocol. ripcord keeps an MCP surface only
  as optional interop — the driver (Claude Code) reads the local warehouse
  directly via the CLI, so the access protocol is incidental. What's behind
  the surface — a *warehouse of execution-verified facts* and the skills that
  produce it — is the interesting part.
- **Binary-analysis-as-a-database predates ripcord** —
  [ddisasm/GTIRB](https://github.com/GrammaTech/ddisasm) (which shares
  ripcord's Souffle/Datalog layer) and CodeQL. ripcord *uses* that technique;
  it didn't invent it.
- **Firmware rehosting** (PRETENDER, P2IM, DICE, Fuzzware) already infers
  MMIO peripheral models from traces — but the deliverable is "enough model
  to fuzz," **not** a legible, falsifiable MCU↔peripheral protocol spec.
  Same input class, different output. ripcord aims at the legible boundary
  contract those tools leave on the table.
- **Matched-source decomp** (decomp.me, the N64/PSX projects) verifies by
  byte-identical recompilation — a *stricter* oracle than ripcord's
  behavioral execution diff, but aimed at perfect source recovery, which
  ripcord explicitly is **not** trying to produce.
- **Closest precedent to the core thesis:** Patrick Hulin's
  [SimTower reimplementation](https://phulin.me/blog/simtower) put an LLM in
  a closed loop against a Unicorn emulator as ground truth — the same
  execution-as-oracle idea, as a one-off project rather than a general
  pipeline.

---

## Where to go deeper

- [`CLAUDE.md`](./CLAUDE.md) — the dense, authoritative project orientation:
  every script, every table, every committed query, current findings.
- [`notes/`](./notes/) — the design log and the FNIRSI target dossier. Start
  with [`notes/README.md`](./notes/README.md). Key files:
  [`design-decisions.md`](./notes/design-decisions.md) (why each choice was
  made), [`pipeline-architecture.md`](./notes/pipeline-architecture.md),
  [`scope_acquisition_spec.md`](./notes/scope_acquisition_spec.md) (the
  MCU↔FPGA protocol), and
  [`renode-at32-bringup.md`](./notes/renode-at32-bringup.md) (the FPGA
  emulation oracle in action).

---

## Scope, honesty, and the FPGA caveat

ripcord is deliberately **generic**. The scope firmware is the proving
ground, not a license to hard-code 2C53T specifics into the core pipeline —
target knowledge lives in `notes/` and in queries, never in the extractors.

The FPGA timing code has *no external ground truth*. ripcord tags every
claim with a provenance level and never presents inferred FPGA behavior as
established fact: an internal dispatch/selector code is not a wire-level
hardware transaction, and a value the firmware *wrote* is observed while a
reply a stub *invented* is unverified until a hardware trace confirms it.
That discipline is the whole reason the execution oracle exists.

---

## License

[MIT](./LICENSE). Firmware binaries analyzed by the pipeline are **not**
included in this repository; their licensing belongs to their original
authors. The test corpus is built from open SDKs (Pico SDK, Zephyr, the
AT32 SDK) or supplied by the user.
