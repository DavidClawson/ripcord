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

### Stage 0 — Ingest

- Run Ghidra headless (`analyzeHeadless`) on the firmware binary with a
  Ghidrathon-based (Python 3) script.
- Export: function list, basic blocks, P-Code / HighFunction IR, call graph,
  xrefs, strings, data references, initial decompiler output.
- Emit as Parquet files (typed, compressed, columnar — far better than JSON
  for millions of rows). JSON is acceptable as a debugging intermediate.
- A separate ingest step reads the Parquet and populates the database.

Output: populated `functions`, `basic_blocks`, `calls`, `xrefs`, `strings`
tables with zero analysis applied.

### Stage 1 — Library identification

- Compile FreeRTOS (already in this repo) and the AT32 SDK with the likely
  toolchain flags (`arm-none-eabi-gcc -mcpu=cortex-m4 -Os` or similar).
- Extract function-level signatures (byte patterns, basic-block hashes,
  structural features).
- Match against functions in the firmware binary.
- Mark matched functions with their real names, signatures, and behavior
  from source. Tag confidence.

This step alone probably resolves 50–80% of the binary without any LLMs
involved, and gives every remaining unknown function *typed boundaries* at
its call edges.

Output: `functions.inferred_name`, `functions.contract_json`,
`functions.confidence` populated for matched functions.

### Stage 2 — Dynamic trace capture with Renode

- Port an STM32F4 Renode platform file (`.repl`) to AT32F403A. Patch for the
  known AT32-vs-STM divergences discovered during manual RE. Version the
  platform file alongside the pipeline code.
- Add a custom `BusPeripheral` model for the FPGA address range (EXMC/FSMC
  bank) that logs every access with full context: PC, cycle count, address,
  value, direction.
- Write one scenario script per feature exercised: power-on, idle, each
  button press, each USB event, LCD refresh, etc.
- Run each scenario; capture the MMIO trace; ingest into the `mmio_events`
  table tagged with `scenario_id` and `platform_version`.

Output: ground-truth traces that anchor the rest of the pipeline.

### Stage 3 — Static trace analysis

Pure computation over traces and the function database:

- Cluster register accesses by address to discover FPGA registers.
- Infer register widths from access sizes.
- Classify registers: read-only, write-only, polled (read-in-loop), FIFO-like
  (sequential writes to same address), command/status pairs.
- Correlate each MMIO event with the function that issued it via recorded PC.
- Populate `fpga_registers`, `register_accesses`, `feature_traces`.

Output: a first-draft register map, automatically derived.

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

fpga_registers(addr, inferred_name, width, access_type, confidence,
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
