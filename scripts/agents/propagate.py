"""Iterative propagation engine for the agent swarm.

Runs multiple rounds of LLM analysis where each round's evidence
feeds the next round's context, propagating understanding outward
from known functions through the call graph.

After round N names some functions, round N+1 uses those names as
context for neighboring functions. Convergence is detected when the
information gain per round drops below a threshold.

Usage:
    uv run python scripts/agents/propagate.py \
        --target pico_freertos_hello_stripped \
        --build-dir build \
        --max-rounds 4 \
        --tasks-per-round 50 \
        --model claude-sonnet-4-6 \
        --domain-hint "FreeRTOS-based embedded application" \
        --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
import time
from pathlib import Path
from uuid import uuid4

import duckdb

# Ensure scripts/agents is importable
_AGENTS_DIR = str(Path(__file__).resolve().parent)
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)

from context import (
    assemble_propose_name_context,
    format_propose_name_prompt,
    register_warehouse,
)
from peripheral_affinity import compute_transitive_affinity
from data_flow import compute_shared_globals
from worker import (
    call_claude,
    claim_next_task,
    complete_task,
    fail_task,
    log_agent_run,
    parse_proposal,
    write_evidence,
)


# ---------------------------------------------------------------------------
# Schema migration: add round columns if missing
# ---------------------------------------------------------------------------

def _ensure_round_columns(conn: sqlite3.Connection) -> None:
    """Add round columns to tasks and evidence_log if not yet present.

    Idempotent — silently skips if columns already exist.
    """
    for table, col_def in [
        ("tasks", "round INTEGER NOT NULL DEFAULT 0"),
        ("evidence_log", "round INTEGER NOT NULL DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
            conn.commit()
        except sqlite3.OperationalError:
            # Column already exists
            pass


# ---------------------------------------------------------------------------
# Evidence promotion: make prior-round results visible to DuckDB
# ---------------------------------------------------------------------------

def promote_evidence(
    conn_sqlite: sqlite3.Connection,
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    db_path: str,
) -> int:
    """Create a DuckDB view of best agent claims from evidence_log.

    Uses DuckDB's SQLite attach to read evidence_log directly and
    expose the best (highest-confidence) name proposal per function
    as the `agent_claims` view. Context assembly can LEFT JOIN against
    this to pick up names from prior rounds.

    Returns the number of distinct functions with agent-proposed names.
    """
    # DuckDB can attach SQLite databases natively
    # Detach first if already attached (re-attach to pick up new evidence)
    try:
        conn_duckdb.execute("DETACH coord")
    except (duckdb.CatalogException, duckdb.BinderException):
        pass
    conn_duckdb.execute(f"ATTACH '{db_path}' AS coord (TYPE sqlite, READ_ONLY)")

    conn_duckdb.execute(f"""
        CREATE OR REPLACE VIEW agent_claims AS
        SELECT
            target AS source,
            entity_addr AS addr,
            json_extract_string(claim_json, '$.name') AS inferred_name,
            confidence,
            evidence_method,
            round
        FROM coord.evidence_log
        WHERE claim_type = 'name'
          AND target = '{target}'
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY target, entity_addr
            ORDER BY confidence DESC, id DESC
        ) = 1
    """)

    count = conn_duckdb.execute(
        "SELECT COUNT(*) FROM agent_claims WHERE confidence >= 0.50"
    ).fetchone()[0]
    return count


# ---------------------------------------------------------------------------
# Frontier detection: which functions benefit from new context?
# ---------------------------------------------------------------------------

def find_frontier_functions(
    conn_sqlite: sqlite3.Connection,
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    prev_round: int,
) -> list[int]:
    """Find functions whose neighbors gained names in the previous round.

    Returns a list of function addresses that are one call-graph hop
    from a function that was newly named in prev_round.
    """
    # Get addresses that were named in the previous round
    newly_named = conn_sqlite.execute(
        """
        SELECT DISTINCT entity_addr FROM evidence_log
        WHERE target = ? AND round = ? AND claim_type = 'name'
              AND confidence >= 0.50
        """,
        (target, prev_round),
    ).fetchall()

    if not newly_named:
        return []

    named_addrs = [row[0] for row in newly_named]

    # Find their call-graph neighbors via DuckDB
    frontier = set()
    for addr in named_addrs:
        # Callers of this newly-named function
        rows = conn_duckdb.execute(
            """
            SELECT DISTINCT caller_addr FROM calls
            WHERE source = $1 AND callee_addr = $2
            """,
            [target, addr],
        ).fetchall()
        frontier.update(r[0] for r in rows)

        # Callees of this newly-named function
        rows = conn_duckdb.execute(
            """
            SELECT DISTINCT callee_addr FROM calls
            WHERE source = $1 AND caller_addr = $2
            """,
            [target, addr],
        ).fetchall()
        frontier.update(r[0] for r in rows)

    # Exclude the already-named functions themselves
    frontier -= set(named_addrs)
    return sorted(frontier)


# ---------------------------------------------------------------------------
# Task generation for a propagation round
# ---------------------------------------------------------------------------

def _get_data_addrs(conn_duckdb: duckdb.DuckDBPyConnection, target: str) -> set[int]:
    """Get addresses classified as DATA by the Unicorn smoke test.

    Returns empty set if unicorn_smoke table doesn't exist.
    """
    try:
        rows = conn_duckdb.execute(f"""
            SELECT addr FROM unicorn_smoke
            WHERE source = '{target}' AND classification = 'data'
        """).fetchall()
        return {r[0] for r in rows}
    except duckdb.CatalogException:
        return set()


def generate_round_tasks(
    conn_sqlite: sqlite3.Connection,
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    round_num: int,
    max_tasks: int,
    frontier_addrs: list[int] | None = None,
) -> int:
    """Generate propose_name tasks for this round.

    Round 0: all unnamed functions (same as generate_tasks.py).
    Round N>0: prioritize frontier functions (neighbors of newly-named),
    then fill remaining slots with other unnamed functions.

    Functions classified as DATA by the Unicorn smoke test are excluded.

    Returns the number of tasks inserted.
    """
    # Get addresses to exclude (data, not code)
    data_addrs = _get_data_addrs(conn_duckdb, target)
    if data_addrs:
        print(f"  smoke filter: excluding {len(data_addrs)} data-classified functions")

    # Get all functions that still lack a confident name
    # Check both functions_enriched and agent_claims
    try:
        unnamed_rows = conn_duckdb.execute(f"""
            WITH
            best_names AS (
                -- From structural fingerprinting
                SELECT addr, inferred_name, confidence
                FROM functions_enriched
                WHERE source = '{target}'
                  AND inferred_name IS NOT NULL
                  AND confidence >= 0.50
                UNION ALL
                -- From agent claims
                SELECT addr, inferred_name, confidence
                FROM agent_claims
                WHERE source = '{target}'
                  AND inferred_name IS NOT NULL
                  AND confidence >= 0.50
            ),
            -- Best confidence per function from any source
            named AS (
                SELECT addr, MAX(confidence) AS best_conf
                FROM best_names
                GROUP BY addr
            ),
            all_fns AS (
                SELECT f.addr, f.name, f.size, f.basic_block_count
                FROM functions f
                WHERE f.source = '{target}'
            ),
            -- Functions without a confident name
            unnamed AS (
                SELECT a.addr, a.name, a.size, a.basic_block_count
                FROM all_fns a
                LEFT JOIN named n ON n.addr = a.addr
                WHERE n.addr IS NULL
            ),
            -- Call-graph degree
            fan_in AS (
                SELECT callee_addr AS addr, COUNT(*) AS n
                FROM calls WHERE source = '{target}'
                GROUP BY callee_addr
            ),
            fan_out AS (
                SELECT caller_addr AS addr, COUNT(DISTINCT callee_addr) AS n
                FROM calls WHERE source = '{target}'
                GROUP BY caller_addr
            )
            SELECT u.addr, u.name, u.size, u.basic_block_count,
                   COALESCE(fi.n, 0) AS fan_in,
                   COALESCE(fo.n, 0) AS fan_out,
                   COALESCE(fi.n, 0) + COALESCE(fo.n, 0) AS degree
            FROM unnamed u
            LEFT JOIN fan_in fi ON fi.addr = u.addr
            LEFT JOIN fan_out fo ON fo.addr = u.addr
            ORDER BY degree DESC
        """).fetchall()
    except duckdb.CatalogException:
        # agent_claims view may not exist yet (round 0)
        unnamed_rows = conn_duckdb.execute(f"""
            WITH
            named AS (
                SELECT addr, confidence
                FROM functions_enriched
                WHERE source = '{target}'
                  AND inferred_name IS NOT NULL
                  AND confidence >= 0.50
            ),
            all_fns AS (
                SELECT f.addr, f.name, f.size, f.basic_block_count
                FROM functions f
                WHERE f.source = '{target}'
            ),
            unnamed AS (
                SELECT a.addr, a.name, a.size, a.basic_block_count
                FROM all_fns a
                LEFT JOIN named n ON n.addr = a.addr
                WHERE n.addr IS NULL
            ),
            fan_in AS (
                SELECT callee_addr AS addr, COUNT(*) AS n
                FROM calls WHERE source = '{target}'
                GROUP BY callee_addr
            ),
            fan_out AS (
                SELECT caller_addr AS addr, COUNT(DISTINCT callee_addr) AS n
                FROM calls WHERE source = '{target}'
                GROUP BY caller_addr
            )
            SELECT u.addr, u.name, u.size, u.basic_block_count,
                   COALESCE(fi.n, 0) AS fan_in,
                   COALESCE(fo.n, 0) AS fan_out,
                   COALESCE(fi.n, 0) + COALESCE(fo.n, 0) AS degree
            FROM unnamed u
            LEFT JOIN fan_in fi ON fi.addr = u.addr
            LEFT JOIN fan_out fo ON fo.addr = u.addr
            ORDER BY degree DESC
        """).fetchall()

    # Filter out data-classified functions
    if data_addrs:
        before = len(unnamed_rows)
        unnamed_rows = [r for r in unnamed_rows if r[0] not in data_addrs]
        filtered = before - len(unnamed_rows)
        if filtered > 0:
            print(f"  smoke filter: removed {filtered} data functions from candidates")

    if not unnamed_rows:
        return 0

    # Build priority-ordered candidate list
    # Frontier functions get a bonus
    frontier_set = set(frontier_addrs) if frontier_addrs else set()
    candidates = []
    for row in unnamed_rows:
        addr, name, size, bb_count, fan_in, fan_out, degree = row
        is_frontier = addr in frontier_set
        # Priority: centrality + frontier bonus
        centrality = degree / max(1, max(r[6] for r in unnamed_rows))
        priority = 0.60 * centrality + 0.40 * (1.0 if is_frontier else 0.0)
        candidates.append((addr, name, size, bb_count, fan_in, fan_out, priority))

    # Sort by priority descending, take top max_tasks
    candidates.sort(key=lambda x: x[6], reverse=True)
    candidates = candidates[:max_tasks]

    # Clear any pending tasks from this round for idempotency
    conn_sqlite.execute(
        "DELETE FROM tasks WHERE kind = 'propose_name' AND target = ? "
        "AND status = 'pending' AND round = ?",
        (target, round_num),
    )

    inserted = 0
    for addr, name, size, bb_count, fan_in, fan_out, priority in candidates:
        payload = {
            "addr": addr,
            "current_name": name,
            "size": size,
            "basic_block_count": bb_count,
            "fan_in": fan_in,
            "fan_out": fan_out,
            "round": round_num,
        }
        conn_sqlite.execute(
            """INSERT INTO tasks
               (kind, target, entity_addr, priority, round, status, payload_json)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            ("propose_name", target, addr, round(priority, 4), round_num,
             json.dumps(payload)),
        )
        inserted += 1

    conn_sqlite.commit()
    return inserted


# ---------------------------------------------------------------------------
# Async Claude API call
# ---------------------------------------------------------------------------

async def _call_claude_async(
    client,  # anthropic.AsyncAnthropic
    prompt: str,
    model: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """Call the Claude API asynchronously with concurrency control."""
    async with semaphore:
        message = await client.messages.create(
            model=model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return {
            "content": message.content[0].text,
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens,
        }


# ---------------------------------------------------------------------------
# Run worker for a single round's tasks (parallel API calls)
# ---------------------------------------------------------------------------

def run_round_worker(
    conn_sqlite: sqlite3.Connection,
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    round_num: int,
    model: str,
    agent_id: str,
    domain_hint: str | None,
    dry_run: bool,
    concurrency: int = 5,
    peripheral_affinities: dict | None = None,
    shared_globals: dict | None = None,
) -> dict:
    """Process all pending tasks for this round with parallel API calls.

    Phase 1 (serial): claim all tasks and assemble prompts (DuckDB/SQLite
    are not thread-safe, so this must be single-threaded).
    Phase 2 (parallel): fire up to `concurrency` API calls concurrently.
    Phase 3 (serial): parse responses and write evidence.

    Returns a dict with: tasks_completed, input_tokens, output_tokens, cost_usd.
    """
    # --- Phase 1: claim tasks and assemble prompts (serial) ---
    work_items = []  # list of (task, prompt)
    while True:
        task = _claim_round_task(conn_sqlite, agent_id, target, round_num)
        if task is None:
            break

        addr = task["entity_addr"]
        try:
            ctx = assemble_propose_name_context(
                conn_duckdb, target, addr,
                domain_hint=domain_hint,
                conn_sqlite=conn_sqlite,
                peripheral_affinities=peripheral_affinities,
                shared_globals=shared_globals,
            )
            prompt = format_propose_name_prompt(ctx)
            work_items.append((task, prompt))
        except Exception as exc:
            print(f"  task {task['id']}: 0x{addr:08x} ERROR assembling context: {exc}")
            fail_task(conn_sqlite, task["id"])

    if not work_items:
        return {"tasks_completed": 0, "input_tokens": 0,
                "output_tokens": 0, "cost_usd": 0.0}

    print(f"  assembled {len(work_items)} prompts, "
          f"firing with concurrency={concurrency}")

    # --- Dry run path ---
    if dry_run:
        for task, prompt in work_items:
            addr = task["entity_addr"]
            print(f"  task {task['id']}: 0x{addr:08x} [DRY RUN] {len(prompt)} chars")
            complete_task(conn_sqlite, task["id"], "completed")
        return {"tasks_completed": len(work_items), "input_tokens": 0,
                "output_tokens": 0, "cost_usd": 0.0}

    # --- Phase 2: parallel API calls ---
    import anthropic

    async def _run_all():
        client = anthropic.AsyncAnthropic()
        sem = asyncio.Semaphore(concurrency)

        async def _do_one(idx, task, prompt):
            try:
                return await _call_claude_async(client, prompt, model, sem)
            except Exception as exc:
                return {"error": str(exc)}

        tasks_async = [
            _do_one(i, task, prompt)
            for i, (task, prompt) in enumerate(work_items)
        ]
        return await asyncio.gather(*tasks_async)

    t0 = time.monotonic()
    responses = asyncio.run(_run_all())
    wall_time = time.monotonic() - t0

    # --- Phase 3: parse responses and write evidence (serial) ---
    tasks_completed = 0
    total_input_tokens = 0
    total_output_tokens = 0

    for (task, prompt), response in zip(work_items, responses):
        addr = task["entity_addr"]
        if "error" in response:
            print(f"  task {task['id']}: 0x{addr:08x} ERROR: {response['error']}")
            fail_task(conn_sqlite, task["id"])
            continue

        total_input_tokens += response["input_tokens"]
        total_output_tokens += response["output_tokens"]

        proposal = parse_proposal(response["content"])
        print(f"  task {task['id']}: 0x{addr:08x} -> {proposal['name']!r}  "
              f"conf={proposal['confidence']:.2f}  "
              f"({response['input_tokens']}+{response['output_tokens']} tok)")

        _write_evidence_with_round(
            conn_sqlite, task, agent_id, proposal, round_num,
        )
        complete_task(conn_sqlite, task["id"], "completed")
        tasks_completed += 1

    cost = (total_input_tokens * 3.0 + total_output_tokens * 15.0) / 1_000_000
    print(f"  wall time: {wall_time:.1f}s for {tasks_completed} tasks "
          f"({wall_time/max(1,tasks_completed):.1f}s/task effective)")

    return {
        "tasks_completed": tasks_completed,
        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
        "cost_usd": cost,
    }


def _claim_round_task(
    conn: sqlite3.Connection,
    agent_id: str,
    target: str,
    round_num: int,
    lease_seconds: int = 300,
) -> dict | None:
    """Claim the next pending task for a specific round and target."""
    # Expire stale leases
    conn.execute("""
        UPDATE tasks SET status='pending', lease_holder=NULL, lease_expires=NULL
        WHERE status='claimed'
          AND lease_expires < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    """)
    conn.commit()

    row = conn.execute("""
        SELECT id, kind, target, entity_addr, payload_json, priority
        FROM tasks
        WHERE status='pending' AND target=? AND round=?
          AND kind='propose_name'
        ORDER BY priority DESC
        LIMIT 1
    """, (target, round_num)).fetchone()

    if row is None:
        return None

    task_id = row[0]
    conn.execute("""
        UPDATE tasks
        SET status='claimed',
            lease_holder=?,
            lease_expires=strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+' || ? || ' seconds')
        WHERE id=? AND status='pending'
    """, (agent_id, lease_seconds, task_id))
    conn.commit()

    if conn.execute("SELECT changes()").fetchone()[0] == 0:
        return _claim_round_task(conn, agent_id, target, round_num, lease_seconds)

    return {
        "id": row[0],
        "kind": row[1],
        "target": row[2],
        "entity_addr": row[3],
        "payload_json": row[4],
        "priority": row[5],
    }


def _write_evidence_with_round(
    conn: sqlite3.Connection,
    task: dict,
    agent_id: str,
    proposal: dict,
    round_num: int,
) -> None:
    """Insert a name proposal into evidence_log with round tracking."""
    from context import VALID_PROVENANCE_TAGS

    claim_json = json.dumps({
        "name": proposal["name"],
        "rationale": proposal["rationale"],
    })

    raw_provenance = proposal.get("provenance", "")
    evidence_method = VALID_PROVENANCE_TAGS.get(raw_provenance, "agent_proposal")

    conn.execute("""
        INSERT INTO evidence_log
            (task_id, target, entity_addr, agent_id, claim_type,
             claim_json, confidence, evidence_method, round)
        VALUES (?, ?, ?, ?, 'name', ?, ?, ?, ?)
    """, (
        task["id"],
        task["target"],
        task["entity_addr"],
        agent_id,
        claim_json,
        proposal["confidence"],
        evidence_method,
        round_num,
    ))
    conn.commit()


# ---------------------------------------------------------------------------
# Convergence measurement
# ---------------------------------------------------------------------------

def measure_convergence(
    conn_sqlite: sqlite3.Connection,
    target: str,
    round_num: int,
) -> dict:
    """Measure information gain from this round.

    Returns dict with: new_names, confidence_gains, total_named, total_functions.
    """
    # Functions newly named this round (first appearance in evidence_log)
    new_names = conn_sqlite.execute("""
        SELECT COUNT(DISTINCT entity_addr) FROM evidence_log
        WHERE target = ? AND round = ? AND claim_type = 'name'
              AND confidence >= 0.50
              AND entity_addr NOT IN (
                  SELECT DISTINCT entity_addr FROM evidence_log
                  WHERE target = ? AND round < ? AND claim_type = 'name'
                        AND confidence >= 0.50
              )
    """, (target, round_num, target, round_num)).fetchone()[0]

    # Functions whose confidence increased this round
    confidence_gains = conn_sqlite.execute("""
        WITH
        prev_best AS (
            SELECT entity_addr, MAX(confidence) AS conf
            FROM evidence_log
            WHERE target = ? AND round < ? AND claim_type = 'name'
            GROUP BY entity_addr
        ),
        curr_best AS (
            SELECT entity_addr, MAX(confidence) AS conf
            FROM evidence_log
            WHERE target = ? AND round = ? AND claim_type = 'name'
            GROUP BY entity_addr
        )
        SELECT COUNT(*) FROM curr_best c
        JOIN prev_best p ON p.entity_addr = c.entity_addr
        WHERE c.conf > p.conf
    """, (target, round_num, target, round_num)).fetchone()[0]

    # Total named (across all rounds)
    total_named = conn_sqlite.execute("""
        SELECT COUNT(DISTINCT entity_addr) FROM evidence_log
        WHERE target = ? AND claim_type = 'name' AND confidence >= 0.50
    """, (target,)).fetchone()[0]

    return {
        "new_names": new_names,
        "confidence_gains": confidence_gains,
        "total_named": total_named,
    }


# ---------------------------------------------------------------------------
# Confidence distribution
# ---------------------------------------------------------------------------

def _confidence_distribution(conn_sqlite: sqlite3.Connection, target: str) -> str:
    """Return a text summary of confidence distribution across all evidence."""
    rows = conn_sqlite.execute("""
        WITH best AS (
            SELECT entity_addr, MAX(confidence) AS conf
            FROM evidence_log
            WHERE target = ? AND claim_type = 'name'
            GROUP BY entity_addr
        )
        SELECT
            SUM(CASE WHEN conf >= 0.90 THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN conf >= 0.70 AND conf < 0.90 THEN 1 ELSE 0 END) AS med,
            SUM(CASE WHEN conf >= 0.50 AND conf < 0.70 THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN conf < 0.50 THEN 1 ELSE 0 END) AS very_low,
            COUNT(*) AS total
        FROM best
    """, (target,)).fetchone()

    if not rows or rows[4] == 0:
        return "  (no evidence yet)"

    high, med, low, very_low, total = rows
    return (
        f"  >= 0.90: {high}  |  0.70-0.89: {med}  |  "
        f"0.50-0.69: {low}  |  < 0.50: {very_low}  |  total: {total}"
    )


# ---------------------------------------------------------------------------
# Main propagation loop
# ---------------------------------------------------------------------------

def run_revisit_pass(
    conn_sqlite: sqlite3.Connection,
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    model: str,
    agent_id: str,
    domain_hint: str | None,
    dry_run: bool,
    concurrency: int,
    confidence_threshold: float,
    peripheral_affinities: dict | None,
    shared_globals: dict | None,
    revisit_round: int,
    db_path: str,
    max_revisit: int = 50,
) -> dict:
    """Re-analyze functions whose best confidence is below threshold.

    These functions were analyzed early when context was sparse.
    Now that their neighbors are named and modules are assigned,
    re-analysis with richer context often improves accuracy.

    Only re-analyzes functions that now have MORE named neighbors
    than when they were first analyzed (otherwise re-analysis
    won't help).

    Returns dict with: candidates, context_gained, tasks_completed,
    input_tokens, output_tokens, cost_usd, upgrades.
    """
    # --- Find functions with best confidence below threshold ---
    rows = conn_sqlite.execute("""
        SELECT entity_addr, MAX(confidence) AS best_conf, MIN(round) AS first_round,
               id AS best_id
        FROM evidence_log
        WHERE target = ? AND claim_type = 'name'
        GROUP BY entity_addr
        HAVING MAX(confidence) < ?
    """, (target, confidence_threshold)).fetchall()

    if not rows:
        print(f"  no functions below threshold {confidence_threshold}")
        return {"candidates": 0, "context_gained": 0, "tasks_completed": 0,
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
                "upgrades": 0}

    print(f"  {len(rows)} functions below confidence {confidence_threshold}")

    # --- For each candidate, check if it gained named neighbors ---
    # Get the best evidence ID per entity (for supersedes_id linkage)
    best_evidence = {}
    for row in rows:
        entity_addr, best_conf, first_round, eid = row
        best_evidence[entity_addr] = {"conf": best_conf, "first_round": first_round, "id": eid}

    # Get all currently named functions (conf >= 0.50)
    all_named = set()
    named_rows = conn_sqlite.execute("""
        SELECT DISTINCT entity_addr FROM evidence_log
        WHERE target = ? AND claim_type = 'name' AND confidence >= 0.50
    """, (target,)).fetchall()
    for r in named_rows:
        all_named.add(r[0])

    # For each candidate, count named neighbors now vs at first_round
    context_gained_addrs = []
    for entity_addr, info in best_evidence.items():
        first_round = info["first_round"]

        # Get call-graph neighbors via DuckDB
        neighbors = set()
        for q, params in [
            ("SELECT DISTINCT caller_addr FROM calls WHERE source = $1 AND callee_addr = $2",
             [target, entity_addr]),
            ("SELECT DISTINCT callee_addr FROM calls WHERE source = $1 AND caller_addr = $2",
             [target, entity_addr]),
        ]:
            neighbor_rows = conn_duckdb.execute(q, params).fetchall()
            neighbors.update(r[0] for r in neighbor_rows)

        # Named neighbors NOW
        named_now = len(neighbors & all_named)

        # Named neighbors at the time of first analysis
        # (functions named in rounds strictly before first_round)
        named_before = set()
        if first_round > 0:
            before_rows = conn_sqlite.execute("""
                SELECT DISTINCT entity_addr FROM evidence_log
                WHERE target = ? AND claim_type = 'name'
                  AND confidence >= 0.50 AND round < ?
            """, (target, first_round)).fetchall()
            named_before = {r[0] for r in before_rows}
        named_then = len(neighbors & named_before)

        new_named_neighbors = named_now - named_then
        if new_named_neighbors >= 2:
            context_gained_addrs.append((entity_addr, new_named_neighbors, info))

    print(f"  {len(context_gained_addrs)} gained >= 2 new named neighbors")

    if not context_gained_addrs:
        return {"candidates": len(rows), "context_gained": 0, "tasks_completed": 0,
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
                "upgrades": 0}

    # Sort by context gain descending, cap at max_revisit
    context_gained_addrs.sort(key=lambda x: x[1], reverse=True)
    context_gained_addrs = context_gained_addrs[:max_revisit]

    print(f"  revisiting {len(context_gained_addrs)} functions (capped at {max_revisit})")

    # --- Ensure evidence is promoted so context assembly sees latest names ---
    promote_evidence(conn_sqlite, conn_duckdb, target, db_path)

    # --- Generate tasks for revisit round ---
    # Clear any existing revisit-round tasks
    conn_sqlite.execute(
        "DELETE FROM tasks WHERE kind = 'propose_name' AND target = ? "
        "AND status = 'pending' AND round = ?",
        (target, revisit_round),
    )

    for entity_addr, gain, info in context_gained_addrs:
        # Get function metadata from DuckDB
        fn_row = conn_duckdb.execute("""
            SELECT name, size, basic_block_count FROM functions
            WHERE source = $1 AND addr = $2
        """, [target, entity_addr]).fetchone()
        if fn_row is None:
            continue

        name, size, bb_count = fn_row
        payload = {
            "addr": entity_addr,
            "current_name": name,
            "size": size,
            "basic_block_count": bb_count,
            "round": revisit_round,
            "revisit": True,
            "prior_confidence": info["conf"],
            "context_gain": gain,
        }
        conn_sqlite.execute(
            """INSERT INTO tasks
               (kind, target, entity_addr, priority, round, status, payload_json)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            ("propose_name", target, entity_addr, 1.0, revisit_round,
             json.dumps(payload)),
        )
    conn_sqlite.commit()

    # --- Run through the standard worker pipeline ---
    result = run_round_worker(
        conn_sqlite, conn_duckdb, target, revisit_round,
        model, agent_id, domain_hint, dry_run, concurrency,
        peripheral_affinities=peripheral_affinities,
        shared_globals=shared_globals,
    )

    # --- Post-process: link supersedes_id and only keep upgrades ---
    upgrades = 0
    if not dry_run:
        # For each revisit evidence entry, check if it beat the old one
        revisit_evidence = conn_sqlite.execute("""
            SELECT id, entity_addr, confidence FROM evidence_log
            WHERE target = ? AND round = ? AND claim_type = 'name'
        """, (target, revisit_round)).fetchall()

        for eid, entity_addr, new_conf in revisit_evidence:
            if entity_addr in best_evidence:
                old_info = best_evidence[entity_addr]
                # Always set supersedes_id for traceability
                conn_sqlite.execute(
                    "UPDATE evidence_log SET supersedes_id = ? WHERE id = ?",
                    (old_info["id"], eid),
                )
                if new_conf > old_info["conf"]:
                    upgrades += 1
        conn_sqlite.commit()

    result["candidates"] = len(rows)
    result["context_gained"] = len(context_gained_addrs)
    result["upgrades"] = upgrades
    return result


def run_propagation(
    target: str,
    build_dir: str,
    max_rounds: int,
    tasks_per_round: int,
    model: str,
    domain_hint: str | None,
    dry_run: bool,
    convergence_threshold: float = 0.05,
    concurrency: int = 5,
    binary_path: str | None = None,
    base_addr: int = 0x08000000,
    revisit_threshold: float = 0.75,
) -> None:
    """Main propagation loop: multiple rounds of agent analysis."""
    build_path = Path(build_dir)
    db_path = str(build_path / "coordination.sqlite")

    # --- Initialize ---
    print(f"propagate: target={target}, max_rounds={max_rounds}, "
          f"tasks/round={tasks_per_round}")
    print(f"propagate: model={model}, dry_run={dry_run}")
    if domain_hint:
        print(f"propagate: domain_hint={domain_hint!r}")
    print()

    # --- Unicorn smoke test (run once, produces parquet) ---
    smoke_path = build_path / target / "tables" / "unicorn_smoke.parquet"
    if binary_path and not smoke_path.exists():
        print("propagate: running Unicorn smoke test (first time)...")
        _VALIDATION_DIR = str(Path(__file__).resolve().parent.parent / "validation")
        if _VALIDATION_DIR not in sys.path:
            sys.path.insert(0, _VALIDATION_DIR)
        from unicorn_validate import run_smoke_test
        run_smoke_test(target, build_dir, binary_path, base_addr)
        print()
    elif smoke_path.exists():
        print(f"propagate: unicorn smoke test exists, will filter data functions")
    else:
        print(f"propagate: no --binary provided, skipping smoke test")

    # Create/verify coordination DB
    db = Path(db_path)
    if not db.exists():
        print(f"propagate: creating coordination DB at {db_path}")
        db.parent.mkdir(parents=True, exist_ok=True)
        conn_init = sqlite3.connect(db_path)
        conn_init.execute("PRAGMA journal_mode=WAL")
        # Import and run init schema
        from init_db import SCHEMA_SQL
        conn_init.executescript(SCHEMA_SQL)
        conn_init.close()

    conn_sqlite = sqlite3.connect(db_path)
    conn_sqlite.execute("PRAGMA journal_mode=WAL")
    _ensure_round_columns(conn_sqlite)

    conn_duckdb = duckdb.connect(":memory:")
    register_warehouse(conn_duckdb, build_dir, targets=[target])

    # Count total functions (excluding data-classified)
    total_functions = conn_duckdb.execute(
        f"SELECT COUNT(*) FROM functions WHERE source = '{target}'"
    ).fetchone()[0]
    data_count = len(_get_data_addrs(conn_duckdb, target))
    analyzable = total_functions - data_count
    print(f"propagate: {total_functions} functions in {target}"
          + (f" ({data_count} data, {analyzable} analyzable)" if data_count else ""))

    # Compute transitive peripheral affinities once (shared across all rounds)
    print("propagate: computing transitive peripheral affinities...")
    try:
        peripheral_affinities = compute_transitive_affinity(conn_duckdb, target)
        print(f"propagate: {len(peripheral_affinities)} functions with peripheral affinity")
    except Exception as exc:
        print(f"propagate: peripheral affinity failed ({exc}), continuing without")
        peripheral_affinities = None

    # Compute shared globals once (shared across all rounds)
    print("propagate: computing shared globals for data flow...")
    try:
        shared_globals = compute_shared_globals(conn_duckdb, target)
        print(f"propagate: {len(shared_globals)} shared global addresses")
    except Exception as exc:
        print(f"propagate: shared globals failed ({exc}), continuing without")
        shared_globals = None

    agent_id = f"propagate-{uuid4().hex[:8]}"
    cumulative_cost = 0.0
    cumulative_tokens_in = 0
    cumulative_tokens_out = 0
    rounds_completed = 0

    for round_num in range(max_rounds):
        print(f"\n{'='*60}")
        print(f"  ROUND {round_num}")
        print(f"{'='*60}")

        # --- Promote evidence from prior rounds ---
        if round_num > 0:
            named_count = promote_evidence(
                conn_sqlite, conn_duckdb, target, db_path,
            )
            print(f"  promoted: {named_count} functions with agent names "
                  f"(conf >= 0.50)")

        # --- Find frontier ---
        if round_num > 0:
            frontier = find_frontier_functions(
                conn_sqlite, conn_duckdb, target, round_num - 1,
            )
            print(f"  frontier: {len(frontier)} functions adjacent to "
                  f"round {round_num - 1} names")
        else:
            frontier = None

        # --- Generate tasks ---
        n_tasks = generate_round_tasks(
            conn_sqlite, conn_duckdb, target, round_num,
            tasks_per_round, frontier,
        )
        print(f"  tasks: {n_tasks} generated for round {round_num}")

        if n_tasks == 0:
            print("  no tasks to process -- all functions named or no candidates")
            rounds_completed = round_num + 1
            break

        # --- Run workers ---
        result = run_round_worker(
            conn_sqlite, conn_duckdb, target, round_num,
            model, agent_id, domain_hint, dry_run, concurrency,
            peripheral_affinities=peripheral_affinities,
            shared_globals=shared_globals,
        )

        cumulative_cost += result["cost_usd"]
        cumulative_tokens_in += result["input_tokens"]
        cumulative_tokens_out += result["output_tokens"]

        print(f"  completed: {result['tasks_completed']} tasks, "
              f"${result['cost_usd']:.4f}")

        # --- Measure convergence ---
        conv = measure_convergence(conn_sqlite, target, round_num)
        print(f"  new names: {conv['new_names']}, "
              f"confidence gains: {conv['confidence_gains']}, "
              f"total named: {conv['total_named']}/{total_functions}")

        # Confidence distribution
        print(f"  confidence distribution:")
        print(_confidence_distribution(conn_sqlite, target))

        rounds_completed = round_num + 1

        # --- Check convergence ---
        remaining = total_functions - conv["total_named"]
        gain = conv["new_names"] + conv["confidence_gains"]

        if remaining == 0:
            print("\n  CONVERGED: all functions named")
            break

        if round_num > 0 and remaining > 0:
            gain_ratio = gain / remaining
            print(f"  gain ratio: {gain_ratio:.3f} "
                  f"(threshold: {convergence_threshold:.3f})")
            if gain_ratio < convergence_threshold:
                print(f"\n  CONVERGED: gain ratio {gain_ratio:.3f} < "
                      f"threshold {convergence_threshold:.3f}")
                break

    # --- Final summary ---
    print(f"\n{'='*60}")
    print(f"  PROPAGATION COMPLETE")
    print(f"{'='*60}")
    print(f"  rounds completed: {rounds_completed}/{max_rounds}")

    # Final counts
    final_named = conn_sqlite.execute("""
        SELECT COUNT(DISTINCT entity_addr) FROM evidence_log
        WHERE target = ? AND claim_type = 'name' AND confidence >= 0.50
    """, (target,)).fetchone()[0]
    total_evidence = conn_sqlite.execute("""
        SELECT COUNT(*) FROM evidence_log
        WHERE target = ? AND claim_type = 'name'
    """, (target,)).fetchone()[0]

    print(f"  functions named: {final_named}/{total_functions} "
          f"({100*final_named/max(1,total_functions):.1f}%)")
    print(f"  total evidence entries: {total_evidence}")
    print(f"  tokens: {cumulative_tokens_in} in + {cumulative_tokens_out} out")
    print(f"  total cost: ${cumulative_cost:.4f}")
    print(f"  confidence distribution:")
    print(_confidence_distribution(conn_sqlite, target))

    # --- Revisit pass: re-analyze low-confidence functions with richer context ---
    if revisit_threshold > 0:
        print(f"\n{'='*60}")
        print(f"  REVISIT PASS (threshold={revisit_threshold})")
        print(f"{'='*60}")
        revisit_round = max_rounds + 1  # Distinct round number
        revisit_result = run_revisit_pass(
            conn_sqlite=conn_sqlite,
            conn_duckdb=conn_duckdb,
            target=target,
            model=model,
            agent_id=agent_id,
            domain_hint=domain_hint,
            dry_run=dry_run,
            concurrency=concurrency,
            confidence_threshold=revisit_threshold,
            peripheral_affinities=peripheral_affinities,
            shared_globals=shared_globals,
            revisit_round=revisit_round,
            db_path=db_path,
        )
        print(f"  candidates below threshold: {revisit_result['candidates']}")
        print(f"  gained context (revisited): {revisit_result['context_gained']}")
        print(f"  tasks completed: {revisit_result['tasks_completed']}")
        if not dry_run:
            print(f"  confidence upgrades: {revisit_result['upgrades']}")
            print(f"  revisit cost: ${revisit_result['cost_usd']:.4f}")
            cumulative_cost += revisit_result["cost_usd"]
            cumulative_tokens_in += revisit_result["input_tokens"]
            cumulative_tokens_out += revisit_result["output_tokens"]
        print(f"  confidence distribution (post-revisit):")
        print(_confidence_distribution(conn_sqlite, target))

    # Log the agent run
    if not dry_run:
        try:
            log_agent_run(
                conn_sqlite, agent_id, model, rounds_completed,
                cumulative_tokens_in, cumulative_tokens_out, cumulative_cost,
            )
        except Exception as exc:
            print(f"  WARNING: failed to log agent run: {exc}")

    conn_sqlite.close()
    conn_duckdb.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Iterative propagation engine: multi-round agent analysis"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target name (e.g. pico_freertos_hello_stripped)",
    )
    parser.add_argument(
        "--build-dir", default="build",
        help="Path to build directory with parquet warehouse",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=4,
        help="Maximum number of propagation rounds (default: 4)",
    )
    parser.add_argument(
        "--tasks-per-round", type=int, default=50,
        help="Maximum tasks to generate per round (default: 50)",
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-6",
        help="Claude model to use (default: claude-sonnet-4-6)",
    )
    parser.add_argument(
        "--domain-hint",
        help="Domain context hint (e.g. 'FreeRTOS-based embedded application')",
    )
    parser.add_argument(
        "--convergence-threshold", type=float, default=0.05,
        help="Stop when gain/remaining < threshold (default: 0.05)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=5,
        help="Max concurrent API calls per round (default: 5)",
    )
    parser.add_argument(
        "--binary",
        help="Path to firmware binary for Unicorn smoke test "
             "(auto-runs on first invocation to filter data-as-code)",
    )
    parser.add_argument(
        "--base-addr", type=lambda x: int(x, 0), default=0x08000000,
        help="Binary load address for smoke test (default: 0x08000000)",
    )
    parser.add_argument(
        "--revisit-threshold", type=float, default=0.75,
        help="After propagation, re-analyze functions below this confidence "
             "(default: 0.75, 0 to disable)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Generate tasks and print prompts without calling the API",
    )
    args = parser.parse_args()

    run_propagation(
        target=args.target,
        build_dir=args.build_dir,
        max_rounds=args.max_rounds,
        tasks_per_round=args.tasks_per_round,
        model=args.model,
        domain_hint=args.domain_hint,
        dry_run=args.dry_run,
        convergence_threshold=args.convergence_threshold,
        concurrency=args.concurrency,
        binary_path=args.binary,
        base_addr=args.base_addr,
        revisit_threshold=args.revisit_threshold,
    )


if __name__ == "__main__":
    main()
