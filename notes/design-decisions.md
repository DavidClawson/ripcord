# Design Decisions Log

Major architectural and scoping decisions for ripcord, with the
reasoning that led to each. This file exists so future work can
revisit decisions intelligently rather than re-deriving them.

Decisions are numbered for reference. Numbering is historical order,
not priority order. If a decision is later reversed, add a new entry
rather than editing the old one — the full history is the point.

Format for each entry:

- **Considered:** the alternatives that were actually on the table.
- **Decided:** the choice made.
- **Reasoning:** why that choice beat the alternatives.
- **Status:** active, revisited, or superseded.

## D1. The artifact is a structured fact database, not source code

**Considered:** producing clean lifted C or Rust source code as the
primary deliverable, with the database as internal state.

**Decided:** the deliverable is a queryable database (DuckDB
warehouse) of facts about the binary. Source code, if it exists at
all, is a late-stage render over the database.

**Reasoning:** most real reverse-engineering goals (vulnerability
analysis, SBOM extraction, protocol recovery, hardware-boundary
specification, interoperability firmware) are better served by
queryable structured facts than by pretty source code. Source code is
a rendering choice, not the thing the tool is fundamentally
producing. Different consumers want different renderings; the
database answers all of them. See `goal-and-approach.md`.

**Status:** active.

## D2. Rust is not a viable lift target

**Considered:** lifting the binary to Rust specifically to gain
borrow-checker and type-system guarantees for correctness.

**Decided:** rejected. C is acceptable as a secondary rendering
target; Rust is not.

**Reasoning:** Rust's compiler catches memory safety and data-race
bugs, not logical bugs. A Rust program can be fully type-safe,
borrow-check clean, and still write `0x5B` where the original wrote
`0x5A`. The bugs that matter in firmware reverse engineering are not
the ones Rust catches. Meanwhile, the type system actively fights
firmware idioms (volatile MMIO, bit twiddling, ISR globals, union
punning) to the point where a faithful lift has to wrap everything in
`unsafe` with raw pointers — losing most of the type-system benefit
anyway. Execution-based verification (Unicorn differential testing,
Renode trace comparison) is the only thing that catches logic bugs,
and it works regardless of target language. See `goal-and-approach.md`.

**Status:** active.

## D3. DuckDB for analytics, SQLite for coordination

**Considered:** SQLite for everything; Postgres as a hosted option;
custom flat-file formats; pure Parquet with no embedded database.

**Decided:** two-warehouse split. DuckDB holds the analytical layer
(functions, basic blocks, traces, derived facts — read-heavy
analytical queries over potentially millions of rows). SQLite holds
the coordination layer (task queue, leases, contracts, evidence log
— high-frequency transactional writes).

**Reasoning:** DuckDB is 10-100x faster than SQLite on analytical
workloads, supports recursive CTEs, reads Parquet files directly, and
is Arrow-native. SQLite is unmatched for small high-frequency
transactional writes and is the right tool for the coordination layer
once an agent swarm exists. Using both, each for what it's good at,
is better than compromising on one. See `pipeline-architecture.md`.

**Status:** active. DuckDB is in place; SQLite coordination layer is
deferred until the agent swarm phase.

## D4. JSONL intermediate format, not Parquet (for v1)

**Considered:** Parquet as the intermediate format between Ghidra
extraction and DuckDB ingest; direct writes from Ghidrathon into
DuckDB; JSONL as the intermediate.

**Decided:** JSONL for Phase 0. Migrate to Parquet if row volume or
ingest speed demands it.

**Reasoning:** Parquet requires pyarrow inside the Ghidrathon Python
environment, which adds a setup step and potential dependency
conflicts. JSONL needs only the standard library. DuckDB reads JSONL
directly via `read_json_auto`. At Phase 0 scale (a few thousand
functions per target) the speed difference is negligible. Deferring
Parquet keeps the initial setup friction low without foreclosing the
option.

**Status:** active. Revisit when a target binary pushes intermediate
files over ~100 MB or when ingest time becomes noticeable.

## D5. Ghidrathon over bundled Jython 2

**Considered:** writing the extraction script in Ghidra's bundled
Jython 2 environment (no extra install) vs. installing Ghidrathon
and using Python 3.

**Decided:** Ghidrathon from the start.

**Reasoning:** Jython 2 is Python 2, which has been end-of-life
since 2020. Modern libraries (f-strings, type hints, dataclasses,
pathlib, duckdb, pyarrow) are not available. Ghidrathon gives the
same scripts the same Python environment the rest of the pipeline
uses, which is essential for sharing code between the extraction
step and the ingest step. The one-time install cost is small; the
ongoing cost of writing Jython 2 would be significant. See
`SETUP.md`.

**Status:** active.

## D6. Snakemake as the orchestrator

**Considered:** bare Makefiles, Snakemake, Nextflow, Dagster,
Prefect, a bespoke Python orchestrator.

**Decided:** Snakemake for the deterministic file-DAG pipeline
layer; a bespoke Python worker loop (not yet written) for the future
iterative agent-swarm layer.

**Reasoning:** Snakemake is the bioinformatics-community tool for
exactly this pattern — input files → transform → output files, with
parallelism, caching, and DAG resolution all handled. Python-embedded
so conditional logic is natural. Zero infrastructure. Well
documented. Handles the "static extraction" side of ripcord
perfectly. The iterative "agent swarm" side is not a file DAG and
needs a different abstraction (blackboard polling loop), so
Snakemake isn't the right tool there and won't be forced into it.
See `pipeline-architecture.md` and `tooling.md`.

**Status:** active.

## D7. Execution is the verification oracle, not the compiler

**Considered:** relying on compiler checks (type systems, lints,
static analysis) to validate lifted code. Alternative: run every
proposed lift in an emulator and differentially test against the
original.

**Decided:** execution-based differential testing is the canonical
verification mechanism. Compiler checks are welcome but not trusted
as sufficient.

**Reasoning:** the class of bugs that matter in firmware RE (wrong
constants, wrong branch conditions, wrong MMIO sequences, wrong
timing) are all invisible to compilers. Only running the code and
comparing behavior catches them. Unicorn provides per-function
differential testing at tens of thousands of runs per second; Renode
provides full-system scenario comparison. Both produce deterministic,
diffable output. No language-level check replaces them. See
`goal-and-approach.md`.

**Status:** active. Unicorn harness not yet written.

## D8. Blackboard architecture for the future agent swarm

**Considered:** a bespoke RPC protocol between agents; a message
queue (Redis, NATS); direct database sharing with optimistic
concurrency.

**Decided:** blackboard architecture with SQLite as the shared
coordination database. Agents claim tasks via advisory leases, post
proposals to an append-only evidence log, and update contracts
optimistically via compare-and-swap.

**Reasoning:** blackboard architectures were invented for exactly
this problem (multi-agent coordination with heterogeneous
specialists and shared state). Well-studied failure modes
(thrashing, starvation, convergence detection) have known
mitigations. SQLite handles the write load trivially, is
zero-infrastructure, and the append-only evidence log gives free
audit trail. No external dependencies. See `pipeline-architecture.md`.

**Status:** deferred until after Phase 0 and library identification
stabilize. Design is locked in but implementation has not started.

## D9. Train function embeddings on P-Code, not disassembly

**Considered:** training a learned function classifier on normalized
disassembly (the published academic default, used by Asm2Vec,
PalmTree, jTrans, etc.) vs. training on Ghidra P-Code.

**Decided:** train on P-Code.

**Reasoning:** P-Code is already architecture-independent,
register-allocation-independent, and operation-level. By the time
P-Code is generated, Ghidra has already normalized most of the
things a model trained on disassembly has to learn to ignore.
Cross-architecture generalization is essentially free. Published
work predates Ghidra's 2019 open release and inherited the "assembly
is the input" convention from earlier tools. This is the single
cheapest-to-try improvement over existing methods and a plausibly
novel contribution. See `local-ml-fingerprinting.md`.

**Status:** research thread, not yet implemented. No earlier than
Fingerprinting Phase 3.

## D10. Open framework with optional hosted premium

**Considered:** fully open source, fully closed commercial product,
hybrid with proprietary corpus/models as paid tier.

**Decided:** open-source the framework (Snakefile, schemas,
extraction scripts, Renode platforms, orchestration); keep the
trained models and labeled corpus as an optional premium layer with
a hosted-service option for enterprise customers.

**Reasoning:** binary analysis tools need trust, and trust comes
from openness. A closed-source security-adjacent tool struggles to
gain adoption. At the same time, the corpus and trained models are
the real moat and can be monetized without closing the framework.
The GitLab/Sentry/HashiCorp pattern is the right reference. Honest
framing: this is a niche market, not a unicorn opportunity. See
`use-cases-and-strategy.md`.

**Status:** speculative — deferred until the project has something
worth open-sourcing. Captured here so future scope decisions can
consider generality.

## D11. Decoupled from the cord target

**Considered:** keeping ripcord tightly scoped to reverse engineering
the cord firmware (ArteryTek AT32F403A driving an opaque FPGA), with
cord as the primary validation target and the running example
throughout the notes.

**Decided:** decoupled 2026-04-04. cord is a motivating example and
possible future stress-test target, not the scope. The cord binary
is not a required input. Phase 0 targets Raspberry Pi Pico SDK
blinky instead.

**Reasoning:** cord is proprietary, buggy, and has no ground truth.
It makes a *bad* first validation target because pipeline failures
are ambiguous — is it the pipeline or the weird binary? Clean
open-source targets with known ground truth are the right
calibration set. Tying ripcord to one specific broken target pulls
design decisions toward accommodating that target's warts, which
don't generalize. Reframing ripcord as a general-purpose research
tool validated against clean targets produces a healthier design,
opens the research and productization directions that require
generality, and avoids the motivation trap of working on tooling for
a codebase you already know is bad. The FPGA/hardware-boundary
framing remains in the notes as an illustrative extreme — a useful
stress test for the design — but not as the target.

**Status:** active. Do not reopen without explicit discussion.

## D12. Raspberry Pi Pico SDK blinky as the first test target

**Considered:** Arduino Uno blink (AVR, simplest setup), ESP32 +
FreeRTOS (relevant architecture but Xtensa), custom minimal
Cortex-M4 main, a FreeRTOS-only build (no demo app), Zephyr
`hello_world` on QEMU Cortex-M3.

**Decided:** Raspberry Pi Pico SDK blinky.

**Reasoning:** Pico SDK is the single easiest modern embedded
toolchain to get running on macOS in 2026. Cortex-M0+ is ARM-family,
which matches the architecture that dominates real embedded work.
Blinky builds first-try with `cmake`/`ninja` once
`gcc-arm-embedded` is installed. Produces an ELF with full DWARF
for ground truth. A FreeRTOS port sample exists for target #2. No
hardware required to run the pipeline (you only need hardware to
*execute* the firmware, and the pipeline only needs the static
binary). Arduino Uno was a close second because of the 5-minute
setup, but starting on AVR locks in design decisions that don't
transfer to the architecture that matters long-term. See `PLAN.md`
Phase 0.

**Status:** active.

## D13. Repo location: `~/Desktop/ripcord/`

**Considered:** `cord/ripcord/` (co-located with the inspiring
target), `~/Desktop/ripcord/` (sibling to cord), a
`~/code/ripcord/` layout, moving inside a broader monorepo.

**Decided:** `~/Desktop/ripcord/`, moved from `cord/ripcord/` on
2026-04-04 when the project was decoupled.

**Reasoning:** co-locating ripcord under cord made the conceptual
coupling feel stronger than it should, and made the path itself
slightly misleading once the decoupling was explicit. A sibling
location in `~/Desktop/` makes the independence visible in the shell
and doesn't require any directory renaming if the user moves on from
cord entirely. The GitHub remote is unaffected by the local move.

**Status:** active.

## D14. Minimum scaffolding, no speculative organization

**Considered:** creating a full directory layout up front
(`scripts/ghidra/`, `scripts/renode/`, `scripts/ingest/`,
`scripts/unicorn/`, `scripts/analysis/`, plus subdirectories for
every future pipeline stage) vs. creating only the directories
needed for what's actually being committed.

**Decided:** only create directories that have real content. Empty
scaffolding directories with `.gitkeep` placeholders are forbidden.

**Reasoning:** premature organization encodes assumptions about the
shape of future code that often turn out to be wrong. Three files in
a flat directory beat three files scattered across six empty
subdirectories. When a natural grouping appears (two scripts share a
purpose, or a set of files wants its own namespace), create the
subdirectory then. The PLAN.md advice "don't over-abstract the
Snakemake rules; simple, explicit, one rule per logical stage;
generalize only when you've written the same pattern three times"
applies to the filesystem too. See `PLAN.md` "What NOT to do early".

**Status:** active.

## How to use this log

When proposing a new architectural direction, first check whether
it would reverse or complicate a decision in this log. If so, name
the decision by number (e.g., "this revisits D2") and explain what
new information justifies reopening it. Reversing a decision is
fine; doing so without acknowledging the prior reasoning is not.

When adding a new entry, append at the bottom with the next number.
Don't renumber old entries, don't edit the reasoning of old entries
(superseded entries get a new entry referencing the old one). This
file is append-only by convention.
