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

**Status:** revisited by D15. The two-warehouse split (analytical vs.
coordination) and the DuckDB-as-query-engine choice survive; the
specific decision to persist analytical data in a DuckDB *file* is
reversed in favor of Parquet-as-truth. SQLite for coordination is
unchanged.

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

**Status:** revisited by D16. JSONL is still the Ghidra→ingest
intermediate for Phase 0, but the reasoning has changed (the
Ghidrathon-pyarrow premise is obsolete) and the decision is now
scoped specifically to the extractor→ingest hop, not to the warehouse
format.

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

**Status:** superseded by D17. The decision to use Python 3 instead
of Jython 2 stands; the specific choice of *Ghidrathon* as the
delivery mechanism is obsolete because Ghidra 11.2+ ships PyGhidra
natively.

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

## D15. Parquet-as-truth for the analytical warehouse (revisits D3)

**Considered:** keeping the analytical warehouse as a monolithic
`build/warehouse.duckdb` file (status quo from D3); switching to a
tree of per-(target, table) Parquet files queried by DuckDB; a hybrid
where DuckDB is the source of truth but periodically exports Parquet
snapshots.

**Decided:** Parquet files are the analytical warehouse. Layout:
`build/<target>/tables/<table>.parquet`, one file per (target, table)
tuple. There is no persistent `.duckdb` file. DuckDB remains the
primary query engine, but it runs queries *over* the Parquet tree,
not *from* a database file. A thin helper, `scripts/query`,
discovers parquets and registers them as DuckDB views on each
invocation. SQLite for coordination (D3's other half) is unchanged.

**Reasoning:**

- *Per-target isolation.* Regenerating one target touches only its
  own parquet files. With a single DuckDB file, rebuilding one target
  means deleting rows from every table in a shared file, which is
  error-prone and racy once the pipeline runs in parallel.
- *Exact Snakemake caching.* Parquet files have deterministic content
  hashes. Snakemake can tell exactly which downstream rules need to
  rerun after a change. A `.duckdb` file is one opaque binary blob —
  any write to any table bumps its mtime and forces wide
  invalidation. This is a direct contribution to the "minutes, not
  days" constraint.
- *Tool agnosticism where it will matter.* Fingerprinting Phase 2-3
  feeds data into ML pipelines that want Arrow or Polars frames, not
  DuckDB query results. With Parquet-as-truth, training data is
  already in the right format and a notebook can
  `pl.scan_parquet('build/**/functions.parquet')` directly.
- *Columnar storage from day one at essentially zero query cost.*
  DuckDB's Parquet reader is within a few percent of its native-table
  reader for ripcord's row counts. The difference is noise relative
  to the actual query cost.
- *Failed writes leave no state behind.* D3 was revisited in part
  because a failed ingest run left an empty `warehouse.duckdb` file
  that fooled Snakemake into thinking everything was up-to-date. With
  atomic per-file writes, failures leave no output and the next run
  simply retries.
- *Reproducibility.* A commit plus a set of parquet content hashes
  pins the warehouse exactly. The mutable `.duckdb` file did not.

**Tradeoffs accepted:**

- *No DB-enforced PRIMARY KEY / FOREIGN KEY.* Parquet has no
  constraint model. Invariants that matter (e.g. every `calls.callee`
  resolves to a `functions.addr`) will be enforced by a validation
  rule in the Snakefile once the first cross-table references exist.
- *Slightly clunkier ad-hoc CLI.* `scripts/query 'SELECT ...'` or
  `scripts/query --repl` replaces `duckdb build/warehouse.duckdb`.
  The helper auto-discovers every table, so adding new tables
  requires no changes to the helper.
- *Schema evolution by convention.* The schema is defined in the
  Python ingest scripts (pyarrow schemas) rather than in DDL. Adding
  a column is "append, don't rename, don't change type"; DuckDB's
  `read_parquet(..., union_by_name=true)` NULL-fills missing columns
  in old files so old and new parquets coexist.

**Timing:** made before widening Stage 0 in order to minimize churn.
With one table and one ingest rule in place, the migration was ~half
a day of work. Delayed until after Stage 0 widening (five tables,
five ingest rules) it would have been 5× larger.

**Status:** active. The former `build/warehouse.duckdb` file and the
`schema/001_init.sql` DDL file are both removed; the latter is
replaced by the pyarrow schema in `scripts/ingest/load_functions.py`.

## D16. JSONL as the extractor→ingest intermediate (revisits D4)

**Considered:** keeping JSONL (D4's choice); switching the extractor
to write Parquet directly now that it runs under PyGhidra and can
import pyarrow; writing directly into the warehouse from the
extractor.

**Decided:** keep JSONL as the per-target hop between the Ghidra
extractor and the ingest script.

**Reasoning:** D4's original reasoning leaned on *"Parquet requires
pyarrow inside the Ghidrathon Python environment."* That premise is
obsolete — PyGhidra runs under the project venv, which already has
pyarrow (see D17). However, JSONL still wins on the merits for this
specific hop:

- *Debuggability.* A JSONL file can be `head`ed, `grep`ped, diffed
  across runs, and eyeballed without tools. Parquet cannot.
- *Extractor simplicity.* The Ghidra extractor only depends on the
  standard library; no pyarrow import overhead on every run.
- *Schema flexibility during early iteration.* While the extraction
  surface is still churning, JSONL lets the extractor emit new fields
  without a schema migration on the writer side. The ingest script
  is the single place that enforces types.
- *Performance is still irrelevant at this scale.* At tens of
  thousands of functions per target, the JSONL→parquet conversion is
  milliseconds. Parquet would only pay off on vastly larger data,
  which is a later problem.

The decision is now scoped specifically to the extractor→ingest hop.
The *warehouse* format is Parquet (D15); the *extractor output*
format is JSONL.

**Status:** active. Revisit if extraction surface grows to the point
where JSONL parse time is measurable, or if a future extractor needs
to emit schema information the ingest script cannot reconstruct.

## D17. PyGhidra (built-in) for Python 3 scripting, not Ghidrathon (revisits D5)

**Considered:** continuing with Mandiant's Ghidrathon extension for
CPython 3 inside Ghidra; switching to PyGhidra, which ships natively
with Ghidra 11.2+ and claims `.py` script files at the JVM level via
its `PyGhidraScriptProvider`.

**Decided:** PyGhidra. The `pyghidraRun -H` launcher is used instead
of `analyzeHeadless`; it is functionally `analyzeHeadless` wrapped in
a Python 3 runtime. The `pyghidra` pip package is installed in the
project venv, and `JAVA_HOME` is pointed at Homebrew's `openjdk@21`
(a transitive dependency of `brew install ghidra`).

**Reasoning:**

- *Ghidrathon is redundant on modern Ghidra.* In 11.2+, Ghidra's own
  `PyGhidraScriptProvider` claims `.py` files before any extension
  gets a chance. A Ghidrathon install on Ghidra 12.x is dead weight —
  the extension registers but its script provider never runs.
- *No extension install step.* PyGhidra ships with Ghidra. The only
  install is `pip install pyghidra` into the venv. No downloading
  release zips, no matching extension versions to Ghidra versions,
  no unzipping into `~/.config/ghidra/<version>/Extensions/`.
- *Version tracking follows Ghidra directly.* PyGhidra's Python
  bindings ship in the same release as Ghidra itself, so there is no
  Ghidra-version × Ghidrathon-version matrix to maintain. A Ghidra
  upgrade is a Ghidra upgrade.
- *Discovered by failure mode.* Phase 0 was originally scaffolded
  assuming Ghidrathon would handle the extraction script. The first
  real pipeline run failed with `Ghidra was not started with
  PyGhidra. Python is not available` — PyGhidra had claimed the
  script but the launcher wasn't in PyGhidra mode. Fixing that
  surfaced the obsolescence of D5.

**Tradeoffs accepted:**

- *`JAVA_HOME` must be set explicitly.* Unlike `analyzeHeadless`,
  which has its own Java-detection logic, PyGhidra reads `JAVA_HOME`
  directly and fails if it's missing or points at an incompatible
  JDK. Documented in SETUP.md and committed to `~/.zshrc`.
- *Ghidra 11.1 and earlier do not have PyGhidra.* Ripcord pins
  Ghidra 11.2+ as a minimum. This is fine — there is no reason to
  support older Ghidra versions on a fresh project.

**Status:** active. Ghidrathon has been uninstalled and the Phase 0
pipeline runs end-to-end under PyGhidra.

## D18. Phase 1 reference corpus must span the target build matrix

**Considered:** build a single "canonical" reference corpus
(FreeRTOS + Zephyr + vendor HALs, one compilation each) and match
every target against it; build a corpus that mirrors each target's
build configuration separately; do no corpus work until a learned
model replaces the need for one; defer the question.

**Decided:** the reference corpus must span the build matrix the
targets span. Each library compiles once per (ISA, -O level, libc,
major toolchain version) combination that any target in the
pipeline uses. Corpus entries are tagged with the build tuple and
only match targets that share that tuple.

**Reasoning — empirical, from `notes/fingerprinting-baseline.md`:**

On 2026-04-05 the structural fingerprinting baseline was run across
three targets: `pico_blinky` (Cortex-M0+, -O3, newlib),
`zephyr_hello_world` (Cortex-M3, -Os, picolibc), and
`zephyr_synchronization` (Cortex-M3, -Os, picolibc).

- Pico ↔ Zephyr: **essentially zero useful matches**. The only
  strict-match cluster was a tiny stub group. Even functions that
  share a name across targets (`main`, `memcpy`) have different
  sizes and block counts.
- Zephyr hello_world ↔ Zephyr synchronization: **72 of 75 matches
  have identical names across both targets, ~96% cluster-level
  precision.** Matches include vfprintf (1278 bytes / 158 blocks),
  z_thread_abort, skip_to_arg, k_sched_unlock, z_arm_fatal_error,
  sys_clock_announce, and the rest of the real Zephyr kernel.

The same query file, the same feature vector, the same day —
radically different results depending on whether the target pair
shared a build config.

The working hypothesis going in ("same toolchain = same code") was
too weak. The actual condition is *same ISA + same -O level + same
libc + overlapping link surface*. Pico and Zephyr shared only
`arm-none-eabi-gcc 15.2.1`; they differed on all four of the
actually-load-bearing axes. The Zephyr pair shared all four.

**Consequences:**

1. **Rule-based fingerprinting (Phase 1) requires a corpus built
   with matching flags.** A single FreeRTOS build for Cortex-M4
   will not match a Cortex-M0+ target, even with the same source
   code. The corpus build infrastructure has to treat the build
   tuple as a first-class key, not an afterthought.

2. **Cross-build-tuple matching requires ISA-invariant features.**
   This is the use case for P-Code embeddings (D9 — train on
   Ghidra P-Code, not raw disassembly). D18 does not replace D9;
   the two are complementary. D18 says "for rule-based matching,
   restrict to homogeneous builds"; D9 says "for the learned path,
   use features that are invariant to the differences." Both are
   correct; the right choice depends on whether you have a
   matching-build corpus or not.

3. **Corpus scope v1 is now concrete.** Start with FreeRTOS built
   for `cortex-m0plus -O3` with newlib to match the Pico build
   config. That's one library × one build tuple, a few hours of
   work, and it immediately unlocks library ID on any Pico-class
   target. Expand the matrix axis-by-axis as targets are added.

4. **The build infrastructure should be Snakemake-driven from day
   one.** Each (library, version, ISA, -O, libc, toolchain)
   combination is a separate pipeline target with its own
   `build/<libname>_<tuple>/tables/*.parquet`. Reference corpora
   and targets of analysis share the same schema; a "match" is
   just a join.

**What this does not change:**

- D9 remains correct. P-Code embeddings are still the right
  approach for cross-ISA work. D18 is about what the rule-based
  path needs; D9 is about what the learned path needs.
- `pipeline-architecture.md` Stage 1 library identification still
  works the way it's described. D18 sharpens the corpus
  requirements without changing the stage's interface.
- The "minutes, not days" constraint still applies to pipeline
  runs. The corpus build can take longer; it's amortized across
  every future target.

**Status:** active. Corpus build has not started; FreeRTOS for
`cortex-m0plus -O3` is the recommended first entry.

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
