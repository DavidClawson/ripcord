# Plan — Next Steps

Broad, phased, intentionally preserving every thread from the design
discussion. Steps within a phase are roughly sequential; phases overlap in
practice.

## Status snapshot (2026-04-08)

**Phase 0:** ✅ complete. 15 targets in warehouse (5 Pico + 2
Zephyr + 1 stripped + 4 stock FNIRSI + 3 AT32 reference), nine
table types per target (`functions`, `calls`, `basic_blocks`,
`xrefs`, `strings`, `pcode_features`, `recovered_calls`,
`mmio_events`, `ground_truth_functions`).

**Phase 1:** library-ID validated end-to-end with multiple matching
signals. Structural fingerprinting: 96% precision same-build. Blind
recovery: 86.6% recall, 94.9% precision. P-Code: within-ISA 93-94%,
cross-ISA fails (histogram cosine tested and killed). Constant
fingerprinting: 100% precision, cross-compiler. Multi-signal
cross-compiler scoring: 6 high-confidence FreeRTOS matches in stock
Keil firmware from GCC reference builds. AT32F403A reference corpus
built (GCC + LLVM). `vPortEnableVFP` byte-identical match confirms
stock firmware uses FreeRTOS ARM_CM4F GCC port.

**Computed call recovery:** 5 mechanisms at ~95% blended precision.
Reachability gap: 70% unreachable → 12% truly unreachable. Works on
ELF, stripped, and raw binary targets. Stock firmware: 37-47 edges
including undiscovered vector table entry points.

**Phase 1 §1.3 (Renode):** proven standalone + wired into Snakemake.
Renode boots Zephyr targets; 394 MMIO events from 2s boot. DAG
verified clean.

**Phase 2 §2.1 (Datalog):** proven standalone + wired into Snakemake
with recovered call edges. Souffle reachability on
`pico_freertos_hello`: 211/265 reachable from `main` (79.6%) with
recovery edges.

**Phase 3 (Agent swarm):** infrastructure built (task queue, context
assembly, worker, validation) but not exercised end-to-end on a real
target.

**Phases 2.2+ (angr), 4 (Unicorn verification):** not started.

## Phase 0 — Bootstrapping (days, not weeks) ✅ COMPLETE

**Goal:** minimal viable pipeline skeleton that the rest can grow
into. No LLMs, no agents, no Datalog. Just extract, store, and query.

**First test target: Raspberry Pi Pico SDK blinky.** Cortex-M0+, bare
metal, single peripheral (the LED GPIO), full DWARF ground truth,
trivially easy to build on any Mac or Linux machine. This is
target-of-opportunity #1 — validation against it proves the pipeline
works end-to-end against a known-good binary before anything harder
is attempted.

### 0.1 Repo structure

- The ripcord repository lives at `~/Desktop/ripcord/` (or wherever
  it was cloned). It is self-contained and has no external input
  requirements.
- Version everything together: Ghidra scripts, Snakemake rules,
  schema migrations, Python tools, config files.
- `build/` is the Snakemake output root. Treat it as fully
  regeneratable — nothing in `build/` is manually edited.
- `targets/` is where test binaries live (gitignored). Each target
  gets its own subdirectory with the ELF and optional metadata.

### 0.2 Data layer decisions (locked in early)

- **SQLite** for the coordination layer (`tasks.db` or similar). Task
  queue, leases, contracts, evidence log, type proposals. Not needed
  in Phase 0 but reserved as a design decision.
- **DuckDB as the analytical query engine, Parquet as the storage
  format.** Per-(target, table) Parquet files under
  `build/<target>/tables/`. Functions, basic blocks, P-Code
  instructions, MMIO events, register accesses, derived facts. No
  persistent `.duckdb` file; DuckDB is invoked ad hoc (via
  `scripts/query`) to run queries over the Parquet tree. This is
  the single highest-leverage architectural choice in the whole
  plan — columnar storage plus a 10-100x analytical query speedup
  over SQLite pays for itself on day one of real use. See
  `design-decisions.md` §D15 for the reasoning behind Parquet-as-truth
  vs. a single DuckDB file.
- **Parquet or JSONL** as the intermediate format between pipeline
  stages. Ghidra dumps structured output; everything ingests from it.
  JSONL is simpler to write from the Ghidra extractor (standard
  library only, eyeballable for debugging); Parquet is faster once
  the volume grows. Start with
  JSONL.
- First schema has just the `functions` table. Every other table is
  added by migration as later stages need them.

### 0.3 Build the first test target

- Install the ARM toolchain: `brew install --cask gcc-arm-embedded`.
- Clone the Raspberry Pi Pico SDK somewhere convenient and export
  `PICO_SDK_PATH`.
- Build the `blink` example: `cmake -B build && cmake --build build`.
- Copy the resulting `blink.elf` into `ripcord/targets/pico_blinky/`
  and add an entry to `config.yaml`.

This is maybe 15 minutes of setup time from zero on a machine that
already has CMake installed.

### 0.4 Ghidra extraction (Stage 0)

- Ghidra 11.2+ ships PyGhidra natively; install the companion
  `pyghidra` Python package into the pipeline venv (see `SETUP.md`).
- The extraction script `scripts/ghidra/export_functions.py` dumps
  per-function metadata: address, size, name, is_thunk, num_params,
  calling convention, basic block count, signature.
- Output format: JSONL, one file per target, in
  `build/<target>/functions.jsonl`.
- The ingest script `scripts/ingest/load_functions.py` loads JSONL
  into a typed Parquet file at `build/<target>/tables/functions.parquet`.
- Run it against the Pico blinky and confirm the function count
  matches the unstripped ELF's symbol table.

### 0.5 Snakemake orchestration

- `Snakefile` has two rules for Phase 0: `ghidra_export` and
  `ingest_to_duckdb`.
- Target list comes from `config.yaml`. Adding a new target is one
  edit to the config — no rule changes needed.
- Confirm the DAG runs end-to-end from a clean state:
  `rm -rf build && snakemake --cores 4`.

### 0.6 First query against the warehouse

- After the pipeline runs, query the warehouse:
  ```bash
  scripts/query \
    "SELECT source, COUNT(*) AS functions FROM functions GROUP BY source"
  ```
- Compare against ground truth from the unstripped ELF
  (`arm-none-eabi-nm blink.elf | grep ' [Tt] ' | wc -l`). The numbers
  should match or be very close.

**Phase 0 exit criteria:** ✅ met. Running `snakemake` from scratch
produces `build/<target>/tables/functions.parquet` for every target
in `config.yaml`; `scripts/query` executes arbitrary SQL against
the warehouse. Three targets currently pass.

### 0.7 Add a second test target ✅ done (and a third)

Once the pipeline works on one target, adding more is cheap. Target
candidates in rough order of value:

1. **Pico SDK with FreeRTOS port.** Same toolchain as the first
   target, adds RTOS code to the mix. Tests library identification.
2. **Zephyr `samples/hello_world` on `qemu_cortex_m3`.** Different
   RTOS, QEMU-runnable (no hardware needed for emulation testing).
3. **STM32 CubeMX blinky sample.** Exposes ST HAL for vendor library
   identification.
4. **Arduino Uno blink.** AVR architecture, 8-bit, drastically
   different. Tests cross-architecture generality of the pipeline.
5. **An ESP32-C3 blinky (RISC-V).** Yet another architecture.

Aim for three targets working through the full pipeline before moving
to Phase 1.

**What actually happened (2026-04-05):** targets added were Pico
SDK blinky (Cortex-M0+, newlib), Zephyr hello_world on
qemu_cortex_m3 (Cortex-M3, picolibc), and Zephyr synchronization
on the same qemu_cortex_m3 board. The two Zephyr targets share a
build config, which turned out to matter a lot for Phase 1 — see
`notes/fingerprinting-baseline.md`. A Pico SDK FreeRTOS build was
skipped in favor of the second Zephyr sample because that test
was specifically needed to validate the structural fingerprinting
primitive under same-build conditions.

### 0.8 Stage 0 widening (done 2026-04-05)

The original Phase 0 scaffold only emitted the `functions` table.
All five Stage 0 tables from `pipeline-architecture.md` are now
populated by the pipeline:

- `functions` — address, size, name, calling convention, params, etc.
- `calls` — one row per call site (caller_addr, call_site_addr, callee_addr, ref_type, is_computed)
- `basic_blocks` — per CodeBlock with containing function, block size, instruction count
- `xrefs` — every non-call reference from within function bodies (reads, writes, jumps, data)
- `strings` — defined strings in loaded memory only (debug section overlays filtered out)

Plus the Phase 0.6 regression signal:

- `ground_truth_functions` — T/t symbols extracted from `nm -S`, per target arch

Every table was designed, added to `scripts/ingest/schemas.py`,
extracted via a `scripts/ghidra/export_<table>.py` PyGhidra
postScript, and ingested via the generic `scripts/ingest/load_table.py`
loader. Adding new tables is now a ~3-file addition with no
surprises.

## Phase 1 — Library identification and fact population

**Goal:** collapse the unknown surface of each target before spending
any LLM budget.

### 1.1 Build a library reference set

- Compile FreeRTOS with canonical toolchain flags for Cortex-M
  targets (multiple versions, multiple optimization levels).
- Compile Zephyr for a handful of sample boards.
- Compile common vendor HALs (ST STM32, Nordic nRF, Silabs, NXP,
  Artery AT32) against their published SDKs.
- Compile common embedded libraries (lwIP, mbedTLS, FatFS, LittleFS,
  tinyusb) in representative configurations.
- Produce ELF files with full symbol tables preserved. These become
  the signature corpus.

### 1.2 Signature matching

- Extract byte patterns, basic-block hashes, structural features,
  and constant sets from the compiled libraries.
- Match against functions in the target DuckDB warehouse.
- Populate `functions.inferred_name` and `functions.contract_json`
  for matches. Tag confidence levels (exact match vs. structural
  match vs. fuzzy).
- Produce a coverage report per target: "X% of bytes identified as
  library code, with Y distinct libraries recognized."

**Implementation status (2026-04-08):** Structural + byte-hash
matching fully validated. `notes/queries/structural_signatures.sql`
implements the feature vector `(size, basic_block_count,
instruction_count, outgoing_calls, distinct_callees, reads, writes,
jumps)` with name-aware precision analysis and byte-hash
disambiguation. 96% cluster-level precision on same-build pairs;
100% with body_hash.

Cross-target library-ID demonstrated: 173 structural matches
between two Pico-FreeRTOS targets (105 FreeRTOS-specific).

**Blind recovery validated:** `pico_freertos_hello_stripped` (all
symbols removed) matched against the full-symbol corpus. Result:
86.6% recall (171/197 functions identified), 94.9% precision
(162/171 correct). The 9 false positives are structural twins —
the expected failure mode for rule-based matching alone.

**P-Code features extracted** for all 8 targets (`pcode_features`
table). Exact `pcode_sequence_hash` matching works within-ISA
(93-94% precision at ops >= 50 within Pico M0+ targets) but
produces zero true positives cross-ISA (M0+ vs M3). The opcode
histogram column is already in the table; cosine similarity over
histograms is the next test for cross-ISA matching. See
`notes/queries/cross_isa_pcode.sql`.

**Remaining for §1.2:** fingerprint write-back (populating
`functions.inferred_name` / `inferred_library` / `confidence` /
`evidence_method` per `notes/confidence-scheme.md`), and P-Code
histogram cosine similarity for cross-ISA matching.

### 1.3 Renode platform and trace capture

- Pick a test target suitable for Renode emulation (Pico, Zephyr
  QEMU target, or STM32 Discovery board sample).
- Add Renode scenarios for every observable behavior the target
  exposes: boot, idle, any interactive events, any sensor activity,
  any peripheral use.
- Each scenario produces its own trace, ingested into the warehouse
  tagged with `scenario_id`.

### 1.4 Static trace analysis

- Cluster MMIO events by address to discover the peripheral register
  map for each target.
- Classify access patterns: read-only, write-only, polled, FIFO-like,
  command/status.
- Correlate events with functions via recorded PC values.
- Populate `registers` and `register_accesses` tables.
- Produce a draft register map per target as a rendered
  `build/<target>/registers.md`.

**Phase 1 exit criteria:** for each target, you have a first-pass
peripheral register map and you know which functions are library code
vs. application-specific. The deterministic pre-pass is doing most of
the work; the LLM swarm in later phases will only see the residue.

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

### 5.2 Write replacement firmware (if that is the goal)

- For projects where the goal is a replacement binary: written fresh
  against the spec, in whatever language makes sense for the target
  (usually C with the vendor SDK).
- Verified against captured Renode scenarios continuously in CI.
- Coverage metric: percent of original feature scenarios that the
  replacement reproduces with matching MMIO traces.
- For projects with other goals (SBOM extraction, vulnerability
  analysis, protocol recovery), this phase is replaced by whatever
  downstream consumption pattern the goal requires — the database is
  already populated.

### 5.3 Hardware bring-up

- Once the replacement passes all emulated scenarios, flash it to real
  hardware and test.
- Expect discrepancies; they are new evidence that goes back into the
  DB and drives another iteration.

## Open questions / decisions to make early

These are unresolved and will block later phases if left unanswered.

**Resolved or answered this session (kept for history):**

- ~~Python version, Ghidra version, Ghidrathon version matrix.~~
  Resolved. Ghidra 11.2+ ships PyGhidra natively; Ghidrathon is
  obsolete; see D17. Currently running Ghidra 12.0.4 + pyghidra
  3.0.2 + jpype1 1.5.2 + Python 3.14. JAVA_HOME must point at
  Homebrew openjdk@21 for PyGhidra.

- ~~How to cross-target match compiled library code.~~ Partially
  answered. The "same toolchain = same code" hypothesis was too
  weak; the correct condition is matching (ISA, -O, libc, link
  surface). For rule-based Phase 1 fingerprinting this constrains
  the reference corpus to span the build matrix; for cross-ISA
  fingerprinting it points at P-Code-level features (see D9).
  Empirical backing in `notes/fingerprinting-baseline.md`.

**Still open:**

1. **Renode platform baselines per target.** Partially resolved
   2026-04-08. A custom `lm3s6965.repl` platform file was written
   for the `qemu_cortex_m3` targets (Cortex-M3, UART0/1/2, NVIC).
   Boots `zephyr_hello_world` successfully with 394 MMIO events
   from 2s trace. GPIO and SysCtl peripherals are unmapped stubs
   (produce warnings but don't block execution). See
   `notes/renode-setup.md`. Remaining: platform files for RP2040
   (Pico targets) and any future STM32/nRF boards.
2. **How to scope scenarios.** A "scenario" is a unit of observable
   behavior. For blinky it's trivial ("boot, watch the LED GPIO for
   2s"). For richer targets, scope is an open question. Iterate.
3. ~~**Confidence scoring scheme.**~~ Resolved 2026-04-08. 0.0–1.0
   float with named thresholds, `evidence_method` companion column,
   composition via max, conflict detection. See
   `notes/confidence-scheme.md`.
4. **Reference corpus build matrix.** Further expanded 2026-04-08.
   FreeRTOS × cortex-m0plus × -O3 × newlib: two variants (heap4,
   static alloc) plus a stripped blind-recovery test. Pico SDK
   examples: `hello_usb` (TinyUSB), `hello_timer`. Total: 8 targets
   spanning two ISAs and two build ecosystems. Build infrastructure
   proven (clone FreeRTOS-Kernel at `~/FreeRTOS-Kernel`, build via
   pico-examples with `FREERTOS_KERNEL_PATH`, copy ELF, add to
   config.yaml, run pipeline). Each new matrix point is ~30 minutes.
   Next axis: FreeRTOS × cortex-m3 × -Os × picolibc (matching
   Zephyr build config for cross-ecosystem library-ID).
5. **Which LLM(s) to use, and what API budget per iteration.** This
   drives Phase 3 cost directly and needs a rough sanity check before
   the swarm goes live. Not urgent — Phase 3 is far off.
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
- **Don't lose chip-specific quirks once you start finding them.**
  For any target, platform divergences from the baseline (e.g., AT32
  vs STM32F4, vendor silicon errata) are load-bearing facts that
  should live in a `platform_quirks` table and in comments in the
  Renode `.repl` file. Losing them is expensive.

## Highest-leverage single action right now (updated 2026-04-08)

**Peripheral-semantic function classification.** Using xrefs + a
chip register map (SVD file or manual JSON), classify every function
by the hardware peripherals it accesses. This works on any Cortex-M
target without reference builds and provides the most immediately
useful output for firmware RE: "this function is an SPI driver,"
"this function configures DMA," etc. The data is already in the
warehouse; the missing piece is a peripheral register map per chip.

After that, three parallel threads:

- **Productize the multi-signal scorer.** Wrap
  `notes/queries/multi_signal_score.sql` in a Python tool that
  takes reference + target and produces a ranked identification
  report. Integrate into the agent swarm and interactive REPL.

- **Ghidra import enhancement for raw binaries.** Feed vector table
  addresses as function creation hints. Stock firmware currently has
  305 Ghidra-discovered functions but 20+ undiscovered ISR handlers
  visible in the vector table.

- **Agent swarm dry run.** Validate the Phase 3 infrastructure
  end-to-end on `pico_freertos_hello` (ground truth available).

**Done this session (2026-04-08):**

- ~~P-Code histogram cosine cross-ISA~~ → killed. 92% of pairs
  score >= 0.80, no discrimination. See `pcode_cosine.sql`.
- ~~Computed call recovery~~ → 70% unreachable → 12%. Five
  mechanisms at ~95% precision. See `recover_calls.py`.
- ~~Constant fingerprinting~~ → 100% precision, cross-compiler.
  See `constant_fingerprint.sql`.
- ~~Multi-signal cross-compiler scoring~~ → 6 high-confidence
  FreeRTOS matches in stock Keil firmware. The cross-compiler
  unlock. See `multi_signal_score.sql`.
- ~~AT32 reference corpus~~ → GCC + LLVM builds, vPortEnableVFP
  byte-identical match confirms FreeRTOS in stock firmware.
- ~~Registrar dispatch precision fix~~ → 7.3% → 89.5%.
- ~~Recovery precision audit~~ → 4 mechanisms at 95-100%, 1 fixed.
- ~~Snakemake DAG verification~~ → clean, all chains correct.
- ~~Stock firmware recovery~~ → 0 → 37-47 edges per version.

**Done in previous sessions (preserved for history):**

- ~~Blind recovery experiment~~ (2026-04-08). Stripped binary: 86.6%
  recall, 94.9% precision. First end-to-end blind ID demo.
- ~~Renode trace capture~~ (2026-04-08). 394 MMIO events from 2s
  `zephyr_hello_world` boot. Custom LM3S6965 platform file.
- ~~Datalog derivation layer~~ (2026-04-08). Souffle reachability on
  `pico_freertos_hello`: 80/265 reachable, 20 orchestrators.
- ~~P-Code feature extraction~~ (2026-04-08). `export_pcode.py` +
  `pcode_features` table for all 8 targets.
- ~~Close the 3-of-75 collision gap~~ (2026-04-08). Name-aware
  precision query and byte-hash matching. All collisions resolved.
- ~~Build FreeRTOS reference corpus~~ (2026-04-08). Two
  Pico-FreeRTOS variants built and ingested. 173 cross-target
  matches, 105 FreeRTOS-specific.
- ~~Add Pico SDK examples~~ (2026-04-08). `hello_usb` (237 fn)
  and `hello_timer` (155 fn) added.
- ~~Write confidence-scheme.md~~ (2026-04-08). Done.
- ~~Fix parallel Ghidra extraction~~ (2026-04-08). Snakemake
  `resources: ghidra=1` constraint added.

---

*Previous 2026-04-08 (early) snapshot:* "Write the fingerprint
write-back, cross-ecosystem matching, export_pcode.py." P-Code
extraction done; write-back deferred in favor of blind recovery
experiment and cross-ISA empirical testing.

*Previous 2026-04-05 snapshot:* "Close the 3-of-75 collision gap,
start the reference corpus with FreeRTOS, add a Pico-FreeRTOS
target." All done.

*Previous 2026-04-04 snapshot:* "Build the Pico SDK blinky target
and get the Phase 0 pipeline running end-to-end." Done.

## Where learned fingerprinting fits into the roadmap

The fingerprinting work has its own internal phasing that runs
alongside the main pipeline phases above. See `fingerprinting.md` for
the rule-based foundation and `local-ml-fingerprinting.md` for the
learned extension. The phasing:

- **Fingerprinting Phase 1 — Rules.** Slots into main Phase 1
  (Library identification). Constants database, string matching,
  MMIO-range classification, structural matching against compiled
  reference libraries (FreeRTOS, Zephyr, vendor HALs). No ML.
  Probably covers 60-80% of library code alone.
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
research directions. See `use-cases-and-strategy.md` for framing on
when the research angle is worth the additional investment.

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
