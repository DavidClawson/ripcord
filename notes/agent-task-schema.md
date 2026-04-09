# Agent task schema — Phase 3 design

Design for the SQLite-based task queue, evidence log, and context
assembly system that drives the Phase 3 LLM agent swarm. This is
the concrete schema behind the blackboard architecture described in
`pipeline-architecture.md` Stage 6, constrained by the confidence
scheme in `confidence-scheme.md` and the coordination-layer decision
in D3/D8.

This is a design document, not implementation. Read before starting
Phase 3 implementation.

## a) Task types

Five initial task types. Each operates on a single entity (one
function or one MMIO register address) and produces a single
claim for the evidence log. No task reads the full binary or
operates on more than one function at a time.

### `propose_name(function_addr)`

Given the function's structural features, P-Code histogram,
callee/caller names, referenced strings, and any existing
`inferred_name` from fingerprinting, propose a human-readable
name.

**Precondition:** function exists in the warehouse with at least
one named neighbor (caller or callee) OR at least one referenced
string. Functions with zero context are deprioritized, not
blocked — an agent can still propose from structural features
alone, but at lower expected confidence.

**Output:** `claim_type = 'name'`, `claim_json = {"name": "...",
"rationale": "..."}`.

### `propose_contract(function_addr)`

Propose the function's signature (param types, return type),
side effects (MMIO writes, global mutations), and preconditions.

**Precondition:** function has a name (from fingerprinting or a
prior `propose_name` task) OR has decompiled pseudo-C available.
Contracts proposed for unnamed functions are low-value because
downstream consumers can't use them without knowing what the
function is.

**Output:** `claim_type = 'contract'`, `claim_json = {"params":
[...], "return_type": "...", "side_effects": [...],
"preconditions": [...], "rationale": "..."}`.

### `classify_register(mmio_addr)`

Given all observed access events for an MMIO address, the
functions that access it, and those functions' names/contracts,
propose a role (e.g., "UART TX data register", "SPI status
register", "GPIO output set").

**Precondition:** the `mmio_events` table has at least one event
for this address. Requires Stage 2 (Renode traces) to have run.

**Output:** `claim_type = 'register_role'`, `claim_json =
{"role": "...", "width": 32, "access_pattern": "write_only",
"rationale": "..."}`.

### `describe_function(function_addr)`

Write a natural-language description of what the function does,
suitable for documentation or code comments. Requires a name
and ideally a contract to already exist.

**Precondition:** function has a name at confidence >= 0.50.

**Output:** `claim_type = 'description'`, `claim_json =
{"description": "...", "rationale": "..."}`.

### `resolve_conflict(function_addr)`

When two or more evidence log entries for the same function and
claim type disagree (the `conflict` flag is TRUE in the canonical
table), examine the competing evidence and pick the best one or
propose a synthesis.

**Precondition:** the canonical table row has `conflict = TRUE`.

**Output:** `claim_type` matches the conflicted claim type,
`claim_json` includes `{"resolution": "...", "chosen_evidence_id":
N, "rationale": "..."}`.

## b) SQLite schema

Three tables in the coordination database
(`build/coordination.sqlite`). These are the transactional layer
described in D3; the analytical warehouse (Parquet/DuckDB) is
unchanged.

```sql
-- The task queue. Workers poll this table for pending work.
-- One row per unit of work.
CREATE TABLE tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL CHECK (kind IN (
                        'propose_name', 'propose_contract',
                        'classify_register', 'describe_function',
                        'resolve_conflict'
                    )),
    target          TEXT NOT NULL,           -- e.g. 'pico_blinky'
    entity_addr     INTEGER NOT NULL,        -- function_addr or mmio_addr
    priority        REAL NOT NULL DEFAULT 0, -- higher = more important
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending', 'claimed', 'completed', 'failed'
                    )),
    lease_holder    TEXT,                     -- agent_id of current worker
    lease_expires   TEXT,                     -- ISO-8601 timestamp
    payload_json    TEXT,                     -- task-specific input context
    depends_on      INTEGER REFERENCES tasks(id),  -- optional: wait for this task first
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at    TEXT,

    -- Prevent duplicate tasks for the same entity and kind
    UNIQUE (kind, target, entity_addr, status)
        -- SQLite partial indexes are limited; enforce in application
        -- layer for status='pending' only.
);

CREATE INDEX idx_tasks_poll ON tasks (status, priority DESC)
    WHERE status = 'pending';
CREATE INDEX idx_tasks_lease ON tasks (lease_expires)
    WHERE status = 'claimed';


-- Append-only evidence log. Every agent proposal lands here.
-- Never deleted, never updated. The canonical warehouse table
-- (functions.inferred_name, etc.) is a materialized view of the
-- highest-confidence entry per (target, entity_addr, claim_type).
CREATE TABLE evidence_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER REFERENCES tasks(id),
    target          TEXT NOT NULL,
    entity_addr     INTEGER NOT NULL,
    agent_id        TEXT NOT NULL,           -- e.g. 'sonnet-4-worker-03'
    claim_type      TEXT NOT NULL CHECK (claim_type IN (
                        'name', 'contract', 'register_role', 'description'
                    )),
    claim_json      TEXT NOT NULL,           -- JSON: the proposal itself
    confidence      REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_method TEXT NOT NULL,           -- per confidence-scheme.md
    supersedes_id   INTEGER REFERENCES evidence_log(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_evidence_entity ON evidence_log (target, entity_addr, claim_type);
CREATE INDEX idx_evidence_task   ON evidence_log (task_id);


-- Agent run accounting. One row per worker invocation.
CREATE TABLE agent_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT NOT NULL,
    model           TEXT NOT NULL,           -- e.g. 'claude-sonnet-4-20250514'
    task_id         INTEGER REFERENCES tasks(id),
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at    TEXT,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    cost_usd        REAL
);

CREATE INDEX idx_runs_agent ON agent_runs (agent_id);
```

### Claim/poll protocol

1. **Poll:** `SELECT id, kind, target, entity_addr, payload_json
   FROM tasks WHERE status = 'pending' AND (depends_on IS NULL
   OR depends_on IN (SELECT id FROM tasks WHERE status =
   'completed')) ORDER BY priority DESC LIMIT 1;`

2. **Claim:** `UPDATE tasks SET status = 'claimed', lease_holder
   = ?, lease_expires = datetime('now', '+5 minutes') WHERE id =
   ? AND status = 'pending';` Check `changes()` — if 0, another
   worker claimed it first. Retry the poll.

3. **Complete:** Insert into `evidence_log`, then `UPDATE tasks
   SET status = 'completed', completed_at = ... WHERE id = ?;`

4. **Expire stale leases:** periodic sweep: `UPDATE tasks SET
   status = 'pending', lease_holder = NULL, lease_expires = NULL
   WHERE status = 'claimed' AND lease_expires < datetime('now');`

SQLite's implicit serialization on write makes this safe without
explicit advisory locks. WAL mode recommended for concurrent
readers.

## c) Context assembly

Each task type has a DuckDB query that pulls the relevant facts
from the Parquet warehouse into a structured prompt. The worker
process runs the query, formats the result as text, and prepends
it to the LLM prompt. The agent never touches the warehouse
directly.

### `propose_name` context query

```sql
-- Input: :target, :addr
WITH
    target_fn AS (
        SELECT f.addr, f.name, f.size, f.basic_block_count,
               f.signature, f.body_hash, f.calling_convention
        FROM functions f
        WHERE f.source = :target AND f.addr = :addr
    ),
    callers AS (
        SELECT DISTINCT f.name AS caller_name, f.addr AS caller_addr
        FROM calls c
        JOIN functions f ON f.source = c.source AND f.addr = c.caller_addr
        WHERE c.source = :target AND c.callee_addr = :addr
    ),
    callees AS (
        SELECT DISTINCT f.name AS callee_name, f.addr AS callee_addr
        FROM calls c
        JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
        WHERE c.source = :target AND c.caller_addr = :addr
    ),
    ref_strings AS (
        SELECT s.value
        FROM xrefs x
        JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
        WHERE x.source = :target AND x.function_addr = :addr
    ),
    structural AS (
        SELECT fv.size, fv.blocks, fv.instructions,
               fv.out_calls, fv.distinct_callees,
               fv.reads, fv.writes, fv.jumps
        FROM feature_vector fv
        WHERE fv.source = :target AND fv.addr = :addr
    ),
    pcode AS (
        SELECT pcode_ops_total, pcode_unique_opcodes, pcode_histogram
        FROM pcode_features
        WHERE source = :target AND addr = :addr
    ),
    -- fingerprint matches from other targets (inferred_name if any)
    fingerprint_hits AS (
        SELECT f2.source AS ref_source, f2.name AS ref_name,
               f2.body_hash AS ref_hash
        FROM functions f2
        JOIN target_fn tf ON f2.body_hash = tf.body_hash
        WHERE f2.source != :target
          AND f2.body_hash IS NOT NULL
          AND f2.name NOT LIKE 'FUN_%'
        LIMIT 5
    )
SELECT
    tf.*, callers.*, callees.*, ref_strings.*,
    structural.*, pcode.*, fingerprint_hits.*
FROM target_fn tf;
-- (In practice, each CTE is serialized separately into prompt sections.)
```

**Prompt structure for `propose_name`:**

```
## Target function
Address: 0x{addr:x}  Size: {size}  Blocks: {blocks}  Calling convention: {cc}
Signature (Ghidra): {signature}

## Structural features
{size}, {blocks}, {instructions}, {out_calls}, {distinct_callees}, {reads}, {writes}, {jumps}

## P-Code histogram
{histogram_json}

## Callers (functions that call this one)
- {caller_name} @ 0x{caller_addr:x}
...

## Callees (functions this one calls)
- {callee_name} @ 0x{callee_addr:x}
...

## Referenced strings
- "{string_value}"
...

## Fingerprint matches (from reference corpus)
- {ref_source}: {ref_name} (body_hash match)
...

## Task
Propose a human-readable name for this function. Return JSON:
{"name": "...", "confidence": 0.0-1.0, "rationale": "..."}
```

### `propose_contract` context query

```sql
-- Input: :target, :addr
-- Same CTEs as propose_name, plus:
WITH
    -- ...callers, callees, ref_strings, structural, pcode as above...
    caller_contracts AS (
        SELECT e.claim_json, e.confidence
        FROM evidence_log e
        WHERE e.target = :target
          AND e.entity_addr IN (
              SELECT c.caller_addr FROM calls c
              WHERE c.source = :target AND c.callee_addr = :addr
          )
          AND e.claim_type = 'contract'
        ORDER BY e.confidence DESC
        LIMIT 5
    ),
    callee_contracts AS (
        SELECT e.claim_json, e.confidence
        FROM evidence_log e
        WHERE e.target = :target
          AND e.entity_addr IN (
              SELECT c.callee_addr FROM calls c
              WHERE c.source = :target AND c.caller_addr = :addr
          )
          AND e.claim_type = 'contract'
        ORDER BY e.confidence DESC
        LIMIT 5
    ),
    mmio_accesses AS (
        SELECT m.address, m.direction, m.value, m.sequence_idx
        FROM mmio_events m
        WHERE m.source = :target
          AND m.pc IN (
              SELECT bb.block_addr
              FROM basic_blocks bb
              WHERE bb.source = :target AND bb.function_addr = :addr
          )
        ORDER BY m.sequence_idx
        LIMIT 50
    )
SELECT ...;
```

**Additional prompt sections for `propose_contract`:**

```
## Caller contracts (how callers expect to use this function)
- caller_name: {contract_json} (confidence: {confidence})

## Callee contracts (what this function delegates to)
- callee_name: {contract_json} (confidence: {confidence})

## MMIO accesses from traces (if available)
- [seq {idx}] {direction} 0x{address:x} = 0x{value:x}

## Task
Propose a contract for this function. Return JSON:
{"params": [{"name": "...", "type": "..."}], "return_type": "...",
 "side_effects": ["writes MMIO 0x..."], "preconditions": ["..."],
 "confidence": 0.0-1.0, "rationale": "..."}
```

### `classify_register` context query

```sql
-- Input: :target, :mmio_addr
WITH
    accesses AS (
        SELECT m.direction, m.value, m.pc, m.sequence_idx, m.scenario
        FROM mmio_events m
        WHERE m.source = :target AND m.address = :mmio_addr
        ORDER BY m.scenario, m.sequence_idx
    ),
    accessing_functions AS (
        SELECT DISTINCT f.addr, f.name
        FROM mmio_events m
        JOIN functions f ON f.source = m.source
            AND m.pc >= f.addr AND m.pc < f.addr + f.size
        WHERE m.source = :target AND m.address = :mmio_addr
    ),
    fn_contracts AS (
        SELECT e.entity_addr, e.claim_json, e.confidence
        FROM evidence_log e
        WHERE e.target = :target
          AND e.entity_addr IN (SELECT addr FROM accessing_functions)
          AND e.claim_type = 'contract'
        ORDER BY e.confidence DESC
    ),
    access_stats AS (
        SELECT
            COUNT(*) AS total_accesses,
            SUM(CASE WHEN direction = 'read' THEN 1 ELSE 0 END) AS reads,
            SUM(CASE WHEN direction = 'write' THEN 1 ELSE 0 END) AS writes,
            COUNT(DISTINCT value) AS distinct_values,
            COUNT(DISTINCT scenario) AS scenarios_observed
        FROM accesses
    )
SELECT ...;
```

**Prompt structure for `classify_register`:**

```
## MMIO register
Address: 0x{mmio_addr:x}

## Access statistics
Total accesses: {total}  Reads: {reads}  Writes: {writes}
Distinct values written: {distinct_values}
Scenarios observed in: {scenarios_observed}

## Access log (first 50 events)
- [{scenario}:{seq}] {direction} 0x{value:x}  (PC: 0x{pc:x} in {fn_name})

## Functions that access this register
- {fn_name} @ 0x{fn_addr:x}  (contract: {contract_summary})

## Task
Classify this MMIO register. Return JSON:
{"role": "...", "width": N, "access_pattern": "read_only|write_only|read_write|polled|fifo",
 "confidence": 0.0-1.0, "rationale": "..."}
```

## d) Priority scheme

Tasks are created with a numeric priority in `tasks.priority`.
Higher values are dequeued first. The priority combines three
signals:

### 1. Call-graph centrality (weight: 0.5)

Functions with high fan-in + fan-out benefit the most downstream
work — naming them unlocks better context for their neighbors.

```sql
-- Precompute centrality per function
WITH centrality AS (
    SELECT source, addr,
        (SELECT COUNT(*) FROM calls c
         WHERE c.source = f.source AND c.callee_addr = f.addr) AS fan_in,
        (SELECT COUNT(DISTINCT callee_addr) FROM calls c
         WHERE c.source = f.source AND c.caller_addr = f.addr) AS fan_out
    FROM functions f
)
SELECT addr, fan_in + fan_out AS degree_centrality,
       NTILE(100) OVER (ORDER BY fan_in + fan_out) / 100.0 AS centrality_score
FROM centrality;
```

`centrality_score` ranges 0.0–1.0. Functions like `memcpy` or
`printk` with high fan-in get high scores. Leaf functions with
one caller get low scores.

### 2. Evidence gap (weight: 0.35)

The most productive tasks are those where partial evidence
exists — the agent has something to work with but the
identification isn't yet confident. This beats both zero-evidence
(agent is working blind) and already-confident (effort is wasted).

```
evidence_gap_score:
  confidence IS NULL              → 0.3  (no evidence at all)
  confidence < 0.50               → 0.8  (weak evidence, high leverage)
  confidence >= 0.50 AND < 0.80   → 1.0  (partial evidence, highest leverage)
  confidence >= 0.80 AND < 0.95   → 0.5  (decent evidence, diminishing returns)
  confidence >= 0.95              → 0.0  (already confident, skip)
```

### 3. Frontier proximity (weight: 0.15)

Functions one hop away from a confidently-identified function
(confidence >= 0.80) in the call graph are higher priority than
functions deep in unidentified territory. The agent can use the
confident neighbor's name and contract as strong context.

```sql
-- Functions one hop from a confident function
WITH confident AS (
    SELECT source, addr FROM functions
    WHERE confidence >= 0.80
),
frontier AS (
    SELECT DISTINCT c.source,
        CASE WHEN c.callee_addr IN (SELECT addr FROM confident WHERE source = c.source)
             THEN c.caller_addr
             ELSE c.callee_addr
        END AS frontier_addr
    FROM calls c
    WHERE c.caller_addr IN (SELECT addr FROM confident WHERE source = c.source)
       OR c.callee_addr IN (SELECT addr FROM confident WHERE source = c.source)
)
SELECT frontier_addr, 1.0 AS frontier_score FROM frontier;
-- Non-frontier functions get 0.0.
```

### Combined priority

```
priority = 0.50 * centrality_score
         + 0.35 * evidence_gap_score
         + 0.15 * frontier_score
```

Range: 0.0–1.0. Tasks are created by a periodic "task planner"
that scans the warehouse, computes priorities, and inserts
`pending` tasks. The planner runs after each pipeline stage
completes and after each batch of agent completions. It is
idempotent — re-running it updates priorities on existing pending
tasks rather than creating duplicates.

## e) Verification gates

No proposal enters the canonical warehouse table until it passes
the applicable gate. Failed proposals remain in the evidence log
with their original confidence; they are not deleted.

### Name proposals

**Gate:** structural match against the reference corpus at
confidence >= 0.85.

- If the agent proposes "k_mutex_lock" for a function, check
  whether any reference corpus function named "k_mutex_lock"
  has a structural 8-tuple or body_hash match against the
  target function.
- If yes: the proposal is corroborated. Promote confidence to
  `max(agent_confidence, structural_match_confidence)` with
  `evidence_method = 'agent_proposal+structural_8tuple_name_match'`.
- If no matching corpus entry exists (novel function, not in
  any library): accept the agent proposal at face value but
  cap confidence at 0.70 until execution-based verification
  (Phase 4) can confirm behavior.
- If the corpus has a *different* name for a structurally
  matching function: flag as conflict. Do not auto-accept
  either name.

### Contract proposals

**Gate:** type-compatibility check against caller expectations.

- For each caller of the function that already has a contract,
  verify that the proposed parameter types are compatible with
  how the caller passes arguments (register assignments at the
  call site, inferred from P-Code or decompiler output).
- For each callee the function calls, verify that the proposed
  return type is compatible with how the function uses the
  return value.
- Incompatible contracts are flagged, not rejected outright —
  the incompatibility may indicate the caller's contract is
  wrong, not the proposal.

### Register proposals

**Gate:** consistency with observed access patterns.

- A register classified as "read_only" must have zero write
  events in `mmio_events`. A "write_only" register must have
  zero read events. A "polled" register must have multiple
  sequential reads from the same PC.
- Violations are automatic rejections — the trace is ground
  truth.

### Full verification (Phase 4, deferred)

**Gate:** Unicorn differential testing.

- Load original function bytes and the proposed C
  implementation.
- Run both with randomized inputs.
- Compare register state, memory deltas, MMIO trace.
- Pass → `evidence_method = 'agent_proposal_verified'`,
  confidence promoted to 0.90+.
- Fail → evidence logged as contradiction; function re-queued
  for agent refinement with the diff as additional context.

## f) Cost model

Token estimates per task type, based on the context assembly
queries above and typical LLM output lengths.

### Per-task token budget

| task type            | context (input) | output  | total   |
|----------------------|----------------:|--------:|--------:|
| `propose_name`       |         ~2,000  |   ~200  |  ~2,200 |
| `propose_contract`   |         ~5,000  |   ~500  |  ~5,500 |
| `classify_register`  |         ~3,000  |   ~300  |  ~3,300 |
| `describe_function`  |         ~3,000  |   ~400  |  ~3,400 |
| `resolve_conflict`   |         ~4,000  |   ~400  |  ~4,400 |

### Cost per task at Claude Sonnet pricing

Using $3/M input tokens, $15/M output tokens (Claude Sonnet 4,
2026 pricing):

| task type            | input cost | output cost | total    |
|----------------------|-----------:|------------:|---------:|
| `propose_name`       |    $0.006  |     $0.003  |  $0.009  |
| `propose_contract`   |    $0.015  |     $0.0075 |  $0.023  |
| `classify_register`  |    $0.009  |     $0.0045 |  $0.014  |
| `describe_function`  |    $0.009  |     $0.006  |  $0.015  |
| `resolve_conflict`   |    $0.012  |     $0.006  |  $0.018  |

### Worked example: `pico_freertos_hello` (~265 functions)

Assumptions:
- Stage 1 fingerprinting identifies ~170 functions (64%) from
  the FreeRTOS + Pico SDK reference corpus at confidence >= 0.85.
  These do not need agent work.
- ~95 functions remain for the agent swarm.

Task distribution for the 95 unknown functions:

| task type            | count | cost/task | subtotal |
|----------------------|------:|----------:|---------:|
| `propose_name`       |    95 |    $0.009 |    $0.86 |
| `propose_contract`   |    60 |    $0.023 |    $1.38 |
| `describe_function`  |    40 |    $0.015 |    $0.60 |
| `resolve_conflict`   |    10 |    $0.018 |    $0.18 |

Not all functions need contracts or descriptions on the first
pass. `resolve_conflict` tasks arise only when proposals
disagree. Some functions will need a second `propose_name` pass
after neighbors are identified (the frontier effect).

**Estimated total: $3–8 for a 265-function binary.** The range
accounts for 1–2 refinement rounds on ~30% of functions. A
worst-case scenario with full contracts on every function and
three rounds of refinement: ~$15.

### Cost scaling

The dominant cost scales with the number of *unknown* functions
after fingerprinting, not the total binary size. A 1,000-function
binary where fingerprinting resolves 800 costs about the same as
a 300-function binary where fingerprinting resolves 100: both
have ~200 functions for agent work, at $6–16.

The "minutes, not days" constraint applies to wall-clock time,
not cost. At Sonnet's throughput (~100 tokens/sec output), 95
`propose_name` tasks complete in ~3 minutes sequentially, ~30
seconds with 8 parallel workers. The full task suite for 95
functions completes in under 10 minutes with modest parallelism.

### When to use a cheaper model

`propose_name` and `describe_function` are low-stakes tasks where
Haiku-class models ($0.25/M input, $1.25/M output) may suffice.
At Haiku pricing the 95-function `propose_name` pass drops from
$0.86 to $0.14. The `agent_runs` table tracks model and cost per
task, enabling A/B comparison: run the same task with Sonnet and
Haiku, compare evidence-log confidence distributions, switch to
the cheaper model when precision is indistinguishable.

## Relationship to existing schema

This design does not modify the Parquet warehouse or the
pyarrow schemas in `scripts/ingest/schemas.py`. The SQLite
coordination database is a new file (`build/coordination.sqlite`)
that references warehouse entities by `(target, entity_addr)`
but does not contain analytical data.

The `functions` table will eventually gain `inferred_name`,
`confidence`, `evidence_method`, and `conflict` columns (per
`confidence-scheme.md`). These are materialized from the
evidence log: a periodic "canonicalize" step reads the
highest-confidence evidence per (target, entity_addr,
claim_type) and writes the result back to the Parquet table.
The evidence log is the source of truth; the Parquet columns
are a cache for fast analytical queries.

## Open questions for implementation

1. **Decompiler output.** `propose_contract` would benefit from
   Ghidra's decompiled pseudo-C, which is not yet extracted
   (noted in `pipeline-architecture.md`). Add `export_decompiled.py`
   before or concurrent with Phase 3 implementation.

2. **P-Code features.** The `pcode_features` schema exists but
   the extractor is not yet wired into the pipeline. Context
   assembly for `propose_name` is better with it but works
   without it (falls back to structural features only).

3. **Task planner granularity.** Should the planner create all
   tasks at once (simple, large initial batch) or incrementally
   (create `propose_name` first, create `propose_contract` only
   after names stabilize)? Incremental is more efficient but
   adds orchestration complexity. Start with batched; switch if
   cost is a problem.

4. **Multi-agent consistency.** Two agents working on adjacent
   functions may propose mutually inconsistent contracts. The
   `resolve_conflict` task type handles detected conflicts, but
   the detection relies on a periodic scan rather than real-time
   constraint propagation. Acceptable for v1; revisit if
   thrashing is observed.
