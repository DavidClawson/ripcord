# Pipeline Architecture

## Thesis in one sentence

Populate a structured fact database about the binary; let small, verifiable
agent tasks refine it in parallel; anchor everything to ground-truth MMIO
traces from Renode; verify every claim with execution-based differential
testing.

## Architectural principles

1. **Everything derived is reproducible; everything observed is stored
   forever.** Ghidra's output is a pure function of the binary — rerun any
   time. A Renode trace of "power-on + button press" is an observation of a
   specific scenario at a specific point in development — store it
   permanently, tagged with provenance.
2. **The database is the product, not the rendered code.** Source code is a
   downstream render of the database.
3. **Agents propose; tools verify.** LLMs are creative and wrong; emulators
   and SMT solvers are boring and right. Every LLM output must pass through
   a deterministic check before entering the canonical state.
4. **Small units of work.** No agent ever reads the whole binary or even a
   whole module. The pipeline pre-chews the binary into locally-understandable
   pieces plus neighbor context.
5. **Append-only evidence.** Observations are never deleted, even when
   superseded. Contradictions are data, not errors.

## Stages

### Stage 0 — Ingest (current state: wide, five tables live)

- Run Ghidra headless via `pyghidraRun -H` (Ghidra's native PyGhidra
  launcher = `analyzeHeadless` under a Python 3 runtime) on the
  firmware binary. One Ghidra session per target, multiple
  `-postScript` flags emit all the JSONL outputs in parallel so
  auto-analysis runs once per target.
- Each extractor script emits a JSONL file; a generic ingest
  script (`scripts/ingest/load_table.py`) converts each JSONL to
  a typed Parquet table using the schema in
  `scripts/ingest/schemas.py`.
- The warehouse is the tree of Parquet files under
  `build/<target>/tables/`. There is no embedded DB file; DuckDB
  is invoked ad hoc via `scripts/query` over the tree. Rationale:
  design-decision D15.

Current tables produced by Stage 0:

| table                    | extractor                          |
|--------------------------|------------------------------------|
| `functions`              | `export_functions.py`              |
| `calls`                  | `export_calls.py`                  |
| `basic_blocks`           | `export_basic_blocks.py`           |
| `xrefs`                  | `export_xrefs.py` (non-call refs)  |
| `strings`                | `export_strings.py` (loaded memory only) |
| `ground_truth_functions` | `load_ground_truth.py` (nm -S)     |

Not yet produced (deferred):

- **P-Code / HighFunction IR** — `export_pcode.py` does not exist
  yet. Prerequisite for D9 (learned P-Code embeddings) and for
  cross-ISA fingerprinting generally.
- **Data references separate from xrefs** — currently folded into
  `xrefs` with a `ref_type` column. Split if a use case demands
  it.
- **Decompiler output** — not captured at Stage 0. Ghidra's
  decompiler produces per-function pseudo-C that would be
  useful for LLM context assembly in Phase 3, but it's not a
  free extraction (the decompiler is slow relative to the static
  API) and deferring it preserves the "minutes, not days"
  constraint.

### Stage 1 — Library identification

- Compile candidate libraries — FreeRTOS, Zephyr, vendor HALs (ST,
  Nordic, Artery, NXP, Silabs, TI), common libraries (lwIP, mbedTLS,
  FatFS, LittleFS, tinyusb) — with appropriate toolchain flags for
  the target architecture (`arm-none-eabi-gcc -mcpu=cortex-m4 -Os`,
  plus variations across GCC versions and optimization levels).
- Extract function-level signatures (byte patterns, basic-block
  hashes, structural features, constant sets).
- Match against functions in the target binary.
- Mark matched functions with their real names, signatures, and
  behavior from source. Tag confidence.

This step alone typically resolves 50–80% of a well-behaved embedded
binary without any LLMs involved, and gives every remaining unknown
function *typed boundaries* at its call edges.

Output: `functions.inferred_name`, `functions.contract_json`,
`functions.confidence` populated for matched functions.

### Stage 2 — Dynamic trace capture with Renode

- Select (or build) a Renode platform file (`.repl`) matching the
  target's chip. Most common Cortex-M targets already have usable
  platforms in the Renode repo; unusual targets need a custom one
  derived from the closest relative. Any chip-specific quirks
  discovered during analysis are documented in the platform file and
  versioned alongside the pipeline.
- Enable bus logging across all memory regions of interest. For
  targets with external peripherals, add a custom `BusPeripheral`
  model for each peripheral's address range that logs every access
  with full context: PC, cycle count, address, value, direction.
- Write one scenario script per observable behavior: power-on, idle,
  each user-facing action, each external event. Each scenario is a
  Renode script that boots the firmware, exercises one behavior, and
  records what happens.
- Run each scenario; capture the MMIO trace; ingest into the
  `mmio_events` table tagged with `scenario_id` and
  `platform_version`.

Output: ground-truth traces that anchor the rest of the pipeline.

### Stage 3 — Static trace analysis

Pure computation over traces and the function database:

- Cluster memory accesses by address to discover the peripheral
  register map.
- Infer register widths from access sizes.
- Classify registers: read-only, write-only, polled (read-in-loop),
  FIFO-like (sequential writes to same address), command/status
  pairs.
- Correlate each MMIO event with the function that issued it via
  recorded PC.
- Populate `registers`, `register_accesses`, `feature_traces`.

Output: a first-draft register map, automatically derived from
observed behavior.

### Stage 4 — Derivation layer (Datalog/Soufflé)

Run rules over base facts to derive higher-level facts:

- Transitive call reachability ("every function that can eventually write
  register X")
- Orchestrator detection (functions that drive multiple registers in
  sequence)
- Subsystem clustering (functions that share register sets)
- Taint-like flows (data from this UART RX reaches this FPGA register)
- Contradiction detection (two agents claim different types for the same
  struct)

Derived facts are materialized into their own tables, invalidated and
recomputed whenever base facts change.

### Stage 5 — Targeted symbolic analysis with angr

Not for the whole binary — surgical. For specific functions where the
agent swarm is uncertain or the hardware boundary is unclear, invoke angr
to derive formal facts:

- Path conditions: "this function writes 0x5A iff arg0 > 0 and g_mode == 2"
- Value ranges: "this loop iterates exactly 32 times"
- Unreachable branches: "this `if` is dead code given known preconditions"

Results land in the evidence log with high confidence because they come
from a formal tool.

### Stage 6 — Agent swarm (the blackboard loop)

A long-running worker process pulls tasks from a queue (a SQLite table,
not Redis — keep infrastructure minimal). Tasks are small and specific:

- "Propose a contract for function 0x8004a20 given these neighbor contracts
  and this trace evidence"
- "Name variables in this basic block"
- "Lift this function to C (Tier 0: unsafe, just compile)"
- "Refine this contract given new evidence from its callers"
- "Adjudicate this type proposal conflict"

Each agent reads structured context from the DB (never raw 700KB of
binary), produces a proposal with a confidence score, writes it to the
evidence log. Contracts are updated optimistically with compare-and-swap
on version numbers.

### Stage 7 — Verification with Unicorn

For every agent-proposed lift, spin up a Unicorn harness:

- Load original function bytes + the replacement implementation
- Run both with randomized inputs against a stubbed memory map
- Compare resulting register state, memory deltas, and MMIO traces
- Mark the proposal `verified` or `rejected` with diff evidence

Failed proposals become new evidence for the next iteration. This is the
filter that makes the agent swarm safe: nothing enters the canonical state
without execution-level verification.

### Stage 8 — Rendered views

Materialized outputs generated from the DB on demand:

- `registers.md` — the current FPGA register map
- `feature-specs/*.md` — per-feature MMIO sequences, annotated
- `functions/*.c` or `*.rs` — the current lifted form of each function
- Call graph visualizations
- Coverage metrics ("X% of functions have verified contracts")

Never edited by hand. Always regeneratable.

## Database design

### Two-warehouse split

- **SQLite** for the coordination layer: `tasks`, `leases`, `contracts`,
  `evidence_log`, `type_proposals`. Small writes, high-frequency transactions.
  SQLite is unmatched for this.
- **DuckDB** for the analytical layer: `pcode_instructions`,
  `basic_blocks`, `mmio_events`, `register_accesses`, derived facts.
  Large reads, recursive CTEs, joins across millions of rows. DuckDB is
  10-100x faster than SQLite for this kind of query and can read Parquet
  directly.

Both live in the same repo, same process, speak Arrow to each other.

### Core tables (sketch)

```
functions(id, addr, size, inferred_name, confidence, contract_version,
          contract_json, first_seen, last_modified)

basic_blocks(id, function_id, addr, size, pcode_blob)

calls(caller_id, callee_id, call_site_addr)

registers(addr, inferred_name, width, access_type, confidence,
               first_observed_scenario)

register_accesses(id, function_id, basic_block_id, register_addr,
                  direction, value_source, sequence_idx)

scenarios(id, name, description, platform_version, captured_at)

mmio_events(scenario_id, sequence_idx, cycle, pc, addr, value, direction)

feature_traces(feature_name, scenario_id, start_event_idx, end_event_idx)

type_proposals(id, type_name, layout_json, proposed_by, confidence,
               superseded_by)

evidence_log(id, function_id, agent_id, kind, claim_json, confidence,
             contradicts_id, created_at)  -- append-only, never deleted

tasks(id, kind, target_id, priority, status, lease_holder, lease_expires)

platform_quirks(id, subsystem, observation, consequence, discovered_at)
```

The exact shape will evolve. Start with something close to this and
migrate as needed — schema migrations are cheap when the whole DB is
rebuildable from source.

## Contracts as headers

Each function row has a `contract_json` field containing the current
best-known interface: signature, reads, writes, side effects, ISR-safety,
preconditions. This is what neighbor agents read when they work on callers
or callees. They never read the full implementation of a neighbor — they
read its contract, cheaply.

Contracts are **versioned**. When a contract changes, every function that
reads it is marked stale (not wrong — stale means "re-verify"). This is
incremental compilation applied to reverse engineering.

## Locking and concurrency

- **Optimistic CAS for contracts.** Read with version N, write with
  compare-and-swap. If someone else wrote first, re-read and merge.
- **Advisory leases with TTLs for expensive tasks.** Agent claims
  function X for 5 minutes. Other agents skip it. If the agent dies, the
  lease expires and someone else picks it up. Never a hard lock.
- **Append-only evidence log.** Multi-writer, no conflicts possible.
- **Type proposals versioned, not locked.** Types are shared across many
  functions; locking them would serialize the whole swarm. Instead, each
  agent proposes a refinement and a periodic reconciliation step merges
  proposals (voting, evidence weight, deferred disambiguation by caller
  evidence).

## Failure modes to watch for

Blackboard architectures have well-known failure modes that apply here:

- **Thrashing** — two agents keep flipping a contract back and forth.
  Mitigation: confidence scores + "don't overwrite higher-confidence
  claims without new evidence."
- **Starvation** — hard functions never get picked up. Mitigation: priority
  queue weighted by call-graph centrality and staleness age.
- **Herd behavior** — every agent grabs the same task. Mitigation:
  randomized offset into the top-K, lease-based claim.
- **Convergence detection** — when to stop. Proxy: iteration where fewer
  than X% of contracts change AND verification pass rate is above
  threshold AND Datalog-derived invariants are stable.
- **Bad evidence propagation** — a high-confidence wrong claim corrupts
  downstream work. Mitigation: every claim traceable to a specific
  agent/tool, with the evidence chain queryable, so a bad claim can be
  retracted and everything downstream re-verified.
