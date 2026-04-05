# Plan — Next Steps

Broad, phased, intentionally preserving every thread from the design
discussion. Steps within a phase are roughly sequential; phases overlap in
practice.

## Phase 0 — Bootstrapping (days, not weeks)

**Goal:** minimal viable pipeline skeleton that the rest can grow into.
No LLMs, no agents, no Datalog. Just extract, store, and query.

### 0.1 Repo structure

- Create a dedicated pipeline repo or subdirectory alongside this one.
  Keep the firmware `.bin` as an input, not a mutable artifact.
- Version everything together: Ghidra scripts, Renode platform file,
  Snakemake rules, schema migrations, Python tools.
- Set up a `build/` directory as the Snakemake output root. Treat it as
  fully regeneratable — nothing in `build/` is manually edited.

### 0.2 Data layer decisions (locked in early)

- **SQLite** for the coordination layer (`tasks.db` or similar). Task
  queue, leases, contracts, evidence log, type proposals.
- **DuckDB** for the analytical layer (`warehouse.duckdb`). Functions,
  basic blocks, P-Code instructions, MMIO events, register accesses,
  derived facts. This is the single highest-leverage architectural
  choice in the whole plan — the 10-100x analytical query speedup over
  SQLite pays for itself on day one of real use.
- **Parquet** as the intermediate format between pipeline stages. Ghidra
  dumps to Parquet; Renode traces dump to Parquet; everything ingests
  from Parquet. DuckDB can query Parquet files directly without
  importing them, which makes debugging and iterative schema work
  dramatically easier than with JSON or ad-hoc SQL imports.
- Sketch a first schema based on `pipeline-architecture.md`. Expect it
  to change; schema migrations are cheap when everything is rebuildable
  from source.

### 0.3 Ghidra extraction (Stage 0)

- Install Ghidrathon so scripts can be written in Python 3.
- Write an extraction script that dumps: functions, basic blocks, call
  graph edges, xrefs, strings, HighFunction IR, decompiler output.
- Output format: Parquet files, one per table (`functions.parquet`,
  `basic_blocks.parquet`, etc.), in `build/ghidra_export/`.
- Write an ingest rule that loads the Parquet into DuckDB.
- Run it against the firmware and confirm counts are sane.

### 0.4 Renode platform port (Stage 2 prerequisite)

- Start from a mainline STM32F4 `.repl` file and patch for AT32F403A.
  Adjust clock tree, flash size, SRAM size, and any peripherals that
  differ.
- **Explicitly capture every AT32-vs-STM divergence already discovered
  during manual RE in a `platform_quirks` table and in comments in the
  `.repl` file.** These are load-bearing facts; losing them is expensive.
- Confirm the firmware boots at least to the point of touching the
  EXMC/FSMC bus. That is the first meaningful milestone and should
  happen within the first few hundred instructions.

### 0.5 MMIO trace capture

- Add a `BusPeripheral` model for the FPGA address range (EXMC/FSMC
  bank). Log every access with full context: cycle, PC, address, value,
  direction, access size.
- Capture the first scenario: "boot and idle 2 seconds."
- Dump the trace as Parquet, ingest into DuckDB.
- Run one ad-hoc query: "show me every distinct FPGA register touched in
  the first 100ms of boot." This is your first piece of novel insight
  from the pipeline, and it should arrive on day 3 or 4.

### 0.6 Snakemake orchestration

- Write a minimal `Snakefile` with three rules: `ghidra_export`,
  `ingest_ghidra`, `renode_trace_boot`, `ingest_trace`.
- Confirm the DAG runs end-to-end from a clean state.
- From here, every new pipeline stage is one more rule.

**Phase 0 exit criteria:** you can run `snakemake` from scratch and end
up with a DuckDB warehouse containing functions, call graph, and one
Renode MMIO trace. You can write a SQL query against it and get answers.

## Phase 1 — Library identification and fact population

**Goal:** collapse the unknown surface before spending any LLM budget.

### 1.1 Build FreeRTOS and AT32 SDK

- Compile FreeRTOS with likely toolchain flags for the AT32F403A target.
- Compile the AT32 SDK HAL and driver library.
- Produce ELF files with full symbol tables preserved.

### 1.2 Signature matching

- Extract byte patterns, basic-block hashes, and structural features
  from the compiled libraries.
- Match against functions in the firmware DuckDB warehouse.
- Populate `functions.inferred_name` and `functions.contract_json` for
  matches. Tag confidence levels (exact match vs. structural match vs.
  fuzzy).
- Produce a coverage report: "X% of firmware bytes identified as
  library code."

### 1.3 More scenario captures

- Add Renode scenarios for every feature reachable in emulation: button
  presses, USB events, LCD operations, UART traffic, any sensor reads.
- Each scenario produces its own Parquet trace file, ingested into the
  warehouse tagged with `scenario_id`.
- The more scenarios captured, the more signal the downstream stages
  have to work with.

### 1.4 Static trace analysis

- Cluster MMIO events by address to discover FPGA registers.
- Classify access patterns: read-only, write-only, polled, FIFO-like,
  command/status.
- Correlate events with functions via recorded PC values.
- Populate `fpga_registers` and `register_accesses` tables.
- Produce a draft register map as a rendered `build/registers.md`.

**Phase 1 exit criteria:** you have a first-pass FPGA register map and
you know which firmware functions touch the FPGA and which are library
code. This alone is a huge jump forward versus the current manual
approach and could already be enough to start writing replacement
firmware for simple features.

## Phase 2 — Derivation and formal analysis

**Goal:** amplify base facts into higher-level structure without LLMs.

### 2.1 Datalog derivation (Soufflé)

- Write initial rules: transitive call reachability, orchestrator
  detection, subsystem clustering, register-driven function grouping.
- Run against base facts; materialize derived tables back into DuckDB.
- Query: "every function that can transitively cause a write to FPGA
  register 0x14." Query: "functions that touch both USB FIFO and FPGA
  registers." Query: "registers read but never written."

### 2.2 Targeted angr analysis

- Set up angr with a bare-metal harness for this firmware: memory map,
  load address, stubbed peripherals.
- Identify 5-10 functions where trace analysis is ambiguous or where
  the hardware boundary behavior is unclear.
- Run angr on those specifically; extract path conditions and value
  constraints.
- Post results to the evidence log with high confidence.

**Phase 2 exit criteria:** recursive queries about the firmware answer
in seconds; a handful of key functions have formally-verified
preconditions; the register map is substantially more complete.

## Phase 3 — Agent swarm

**Goal:** LLM-driven refinement of contracts and function understanding,
with execution-level verification.

### 3.1 Task queue and worker loop

- Design the task schema: kind, target, priority, lease, status, payload.
- Write a worker script that claims tasks, runs them, posts results.
- Start with a single worker, no concurrency, to validate the loop.

### 3.2 Agent task types

- **`propose_contract(function_id)`** — given neighbor contracts and
  trace evidence, propose a signature and side-effect summary for a
  function.
- **`name_variables(function_id)`** — given the function body and
  contract, propose names for locals.
- **`classify_register(register_addr)`** — given access patterns and
  traces, propose a role for a register.
- **`lift_function(function_id, tier)`** — produce a C (or other)
  implementation at a given tier of fidelity.
- **`adjudicate_conflict(type_proposal_id)`** — when two type proposals
  conflict, examine evidence and propose a resolution.

### 3.3 Context assembly for agents

- Each task builds its own context: the target plus neighbor contracts
  plus relevant trace slices plus evidence log entries. Never the whole
  binary, never even a whole file.
- Use DuckDB queries to assemble context in milliseconds.
- Structure the prompt as: facts (high-confidence) + proposals
  (low-confidence) + task + output schema.

### 3.4 Structured output + validation

- Agents return JSON matching a schema. Parse-fail = reject.
- Every claim carries a confidence score.
- Claims enter the evidence log first, not the canonical state.
- Canonical state updates only after verification.

### 3.5 Parallelize

- Once one worker is stable, scale to N workers, each pulling from the
  shared SQLite queue with lease-based claiming.
- Monitor for thrashing, starvation, and herd behavior (see failure
  modes in `pipeline-architecture.md`).

**Phase 3 exit criteria:** a working agent swarm producing and refining
contracts for unknown functions, with proposals queueing for
verification.

## Phase 4 — Verification

**Goal:** close the loop. Every agent proposal gets checked by execution.

### 4.1 Unicorn per-function harness

- Build a harness that can load an arbitrary function from the original
  binary and run it with synthetic inputs.
- Capture post-execution state: registers, memory delta, MMIO trace.
- Build a second harness that does the same for a replacement
  implementation.
- Diff the two; mark the proposal verified or rejected.

### 4.2 Differential testing at scale

- For each `lift_function` proposal, generate randomized inputs.
- Run 100-10,000 trials per function in parallel.
- Aggregate pass rates. A function with 10,000/10,000 passes is
  effectively verified; one with 9,950/10,000 has a subtle bug that
  becomes a new task.

### 4.3 Renode-based whole-scenario verification

- For any replacement implementation assembled from verified functions,
  run the same Renode scenarios against it that were captured from the
  original.
- Diff MMIO traces. Any difference is a bug.
- This is the ultimate ground truth: if your replacement produces the
  same bus behavior as the original under every captured scenario, it
  is functionally equivalent at the hardware boundary.

**Phase 4 exit criteria:** agent output is routinely verified or
rejected automatically; convergence toward verified contracts is
measurable and trending up.

## Phase 5 — Rendered views and replacement firmware

**Goal:** produce the actual deliverable — replacement firmware.

### 5.1 Spec rendering

- Generate `registers.md`, per-feature spec files, annotated call
  graphs, subsystem summaries. All queries against the DB.
- These are for humans to read and to reference while writing
  replacement code.

### 5.2 Write replacement firmware

- Written fresh against the spec, in whatever language makes sense
  (probably C with the AT32 SDK, but the option is open).
- Verified against captured Renode scenarios continuously in CI.
- Coverage metric: percent of original feature scenarios that the
  replacement reproduces with matching MMIO traces.

### 5.3 Hardware bring-up

- Once the replacement passes all emulated scenarios, flash it to real
  hardware and test.
- Expect discrepancies; they are new evidence that goes back into the
  DB and drives another iteration.

## Open questions / decisions to make early

These are unresolved and will block later phases if left unanswered:

1. **Python version, Ghidra version, Ghidrathon version matrix.** Lock
   these at the start and document them.
2. **Exact Renode platform file base** — which upstream STM32F4 `.repl`
   to fork from. Probably `Nucleo_F401RE` or similar, but the AT32F403A
   is closer to an F103/F107 in some respects. Worth 30 minutes of
   research before committing.
3. **How to scope scenarios.** A "feature" is fuzzy. Probably: every
   user-observable behavior gets its own scenario, plus one or two
   catch-all boot/idle scenarios. Iterate.
4. **Confidence scoring scheme.** 0-1 float? Categorical (low/med/high)?
   The evidence log's usefulness depends on this being consistent.
5. **Which LLM(s) to use, and what API budget per iteration.** This
   drives Phase 3 cost directly and needs a rough sanity check before
   the swarm goes live.
6. **Where to host the task queue once it outgrows SQLite.** Probably
   never, for a solo project — SQLite handles millions of rows fine —
   but worth knowing the escape hatch exists (Redis, Postgres, LMDB).
7. **Licensing / legal posture.** Reverse engineering for
   interoperability is generally defensible but the specifics depend on
   jurisdiction and the exact replication goal. Worth a brief read of
   the relevant rules before publishing anything.

## What NOT to do early

Things that are tempting but should wait:

- **Don't build agents before Phase 2 is solid.** Throwing LLMs at an
  empty warehouse wastes money. Agents are force multipliers on
  existing structure, not substitutes for it.
- **Don't try to lift everything.** Library code is already identified;
  you don't need to re-understand `xTaskCreate`. Focus agent budget on
  the unknown.
- **Don't pursue "idiomatic Rust" or even "clean C" as a goal.** The
  goal is spec extraction. Rendered code is a side effect.
- **Don't build a web UI.** Use DuckDB's CLI, Jupyter, or Polars for
  exploration. A UI is a Phase 5 concern at earliest.
- **Don't over-abstract the Snakemake rules.** Simple, explicit, one
  rule per logical stage. Generalize only when you've written the same
  pattern three times.
- **Don't lose the AT32 quirks you've already found.** Every one of them
  should end up in `platform_quirks` and in comments in the Renode
  `.repl` file by the end of Phase 0.

## Highest-leverage single action right now

If only one thing gets done this week: **port the Renode platform file
and capture a boot trace with FSMC bus logging.** Everything else in the
pipeline is about amplifying and querying that trace. Without it, the
rest of the pipeline has nothing to anchor against. With it, you already
know more about what the firmware does to the FPGA than you could learn
from a week of staring at Ghidra.

## Where learned fingerprinting fits into the roadmap

The fingerprinting work has its own internal phasing that runs
alongside the main pipeline phases above. See `fingerprinting.md` for
the rule-based foundation and `local-ml-fingerprinting.md` for the
learned extension. The phasing:

- **Fingerprinting Phase 1 — Rules.** Slots into main Phase 1
  (Library identification). Constants database, string matching,
  MMIO-range classification, structural matching against compiled
  FreeRTOS and AT32 SDK references. No ML. Probably covers 60-80% of
  library code alone.
- **Fingerprinting Phase 2 — Hand-crafted features + GBDT.** Slots in
  after main Phase 1 is stable. XGBoost or LightGBM over explicit
  features. Adds incremental coverage, stays interpretable, no deep
  learning infrastructure. Feature extraction code also feeds the
  later deep model.
- **Fingerprinting Phase 3 — P-Code embedding model on Apple
  Silicon.** Slots in parallel with main Phase 3 (Agent swarm), or
  before it as a cost-reducer. Catches the fuzzy cases rules and
  GBDTs miss. Requires the labeled corpus effort described in
  `test-corpus-and-validation.md` and `local-ml-fingerprinting.md`.
- **Fingerprinting Phase 4 — Multi-modal model.** Optional, only if
  Phase 3 plateaus. Combines P-Code sequence, CFG graph, constants,
  strings, and call-graph neighborhood encoders.

Each fingerprinting phase is independently useful and each makes the
downstream agent work cheaper. Stopping at Phase 1 still leaves the
main pipeline working; stopping at Phase 2 gives most of the
practical value with no ML dependencies; Phases 3 and 4 are the
research directions that also happen to improve cord-specific work.

For cord specifically, Phases 1 and 2 of fingerprinting are almost
certainly sufficient. Phases 3 and 4 are worth pursuing if the broader
research direction is interesting on its own merits. See
`use-cases-and-strategy.md` for framing on when the research angle is
worth the additional investment.

## The "minutes, not days" design constraint

Everything in Phases 0, 1, and 2 is deterministic automation: Ghidra
extraction, library identification, Renode trace capture, static trace
analysis, Datalog derivation, targeted angr queries. None of it requires
human judgment or an LLM. With a well-written Snakemake pipeline and
reasonable caching, **a bare firmware `.bin` should go from "input" to
"fully populated fact database, ready for agent work" in a few minutes**,
end-to-end, unattended.

This is a load-bearing design constraint, not an aspiration. It makes
several things possible that are otherwise impractical:

- **Fast iteration on the pipeline itself.** Change a Ghidra extractor,
  rerun the whole thing in three minutes, check metrics against the
  validation corpus, iterate. Versus: change something, wait a day,
  discover it broke.
- **Regression testing against many targets.** With a few-minutes-per-run
  pipeline, rerunning against the whole validation corpus after every
  pipeline change is trivial. You immediately catch any change that
  silently regresses one target while improving another.
- **Cheap onboarding of new firmware.** Drop in a new `.bin`, hit run,
  come back in minutes with a populated warehouse and a first-pass
  register map. This is what makes the corpus strategy in
  `test-corpus-and-validation.md` affordable.
- **Spending LLM budget only where it counts.** Every dollar of agent
  compute goes to work that deterministic tools genuinely cannot do.
  The fast path maximizes the enrichment of the warehouse *before* any
  LLM sees it, which shrinks the remaining unknown by a big factor.
- **Fast failure.** A broken pipeline stage fails in seconds, not hours.

Concrete implications for how Phases 0-2 should be built:

1. **Ghidra headless with warm project caching.** The first run analyzes
   the binary; subsequent runs reuse the Ghidra project database. Ghidra
   re-analysis is the slowest deterministic step; caching collapses it.
2. **Incremental DuckDB ingestion.** Only re-ingest Parquet files whose
   hashes changed. Snakemake handles this naturally.
3. **Renode scenarios run in parallel.** Each scenario is independent.
   A multi-core machine runs 8-16 scenarios simultaneously.
4. **Soufflé runs on seconds of input, produces seconds of output.**
   Datalog is designed for this. Don't over-engineer.
5. **No stage-internal state that outlives a run.** Every stage reads
   from the warehouse and writes to the warehouse. A crash mid-run
   leaves the warehouse consistent, and rerunning picks up where it
   left off.

Treat every minute added to the pre-LLM path as expensive, because it
costs you in every iteration forever. A five-minute pipeline run hit ten
times a day is fifty minutes; a fifty-minute pipeline run hit twice a day
is a hundred. The slope matters more than the intercept.
