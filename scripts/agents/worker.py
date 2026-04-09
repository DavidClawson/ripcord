"""Agent worker loop: claims tasks from SQLite, calls Claude, writes evidence.

Claims propose_name tasks from build/coordination.sqlite, assembles context
from the Parquet warehouse via DuckDB, calls the Claude API for a name
proposal, and writes the result to the evidence_log table.

Depends on:
    scripts/agents/init_db.py       — creates the SQLite schema
    scripts/agents/generate_tasks.py — populates the tasks table
    scripts/agents/context.py       — assembles warehouse context into prompts

Usage:
    uv run python scripts/agents/worker.py \\
        --db build/coordination.sqlite \\
        --build-dir build \\
        --model claude-sonnet-4-20250514 \\
        --max-tasks 5 \\
        --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Warehouse registration (mirrors scripts/query discovery)
# ---------------------------------------------------------------------------

def register_warehouse(conn_duckdb, build_dir: str | Path):
    """Discover parquet files and create DuckDB views, same as scripts/query."""
    import glob as globmod

    groups: dict[str, list[str]] = defaultdict(list)
    pattern = str(Path(build_dir) / "*" / "tables" / "*.parquet")
    for path in globmod.glob(pattern):
        import os
        name = os.path.splitext(os.path.basename(path))[0]
        groups[name].append(path)

    for name, paths in sorted(groups.items()):
        paths_sql = ", ".join(f"'{p}'" for p in sorted(paths))
        conn_duckdb.execute(
            f"CREATE OR REPLACE VIEW {name} AS "
            f"SELECT * FROM read_parquet([{paths_sql}], union_by_name=true);"
        )
    return sorted(groups.keys())


# ---------------------------------------------------------------------------
# Task claim/complete protocol (matches agent-task-schema.md section b)
# ---------------------------------------------------------------------------

def claim_next_task(conn: sqlite3.Connection, agent_id: str,
                    lease_seconds: int = 300) -> dict | None:
    """Atomically claim the highest-priority pending task.

    Uses the two-step poll-then-claim protocol from the schema doc:
    poll for eligible task, then UPDATE with status check to handle races.
    """
    # First expire stale leases
    conn.execute("""
        UPDATE tasks SET status='pending', lease_holder=NULL, lease_expires=NULL
        WHERE status='claimed' AND lease_expires < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    """)
    conn.commit()

    # Poll for next eligible task
    row = conn.execute("""
        SELECT id, kind, target, entity_addr, payload_json, priority
        FROM tasks
        WHERE status='pending'
          AND (depends_on IS NULL
               OR depends_on IN (SELECT id FROM tasks WHERE status='completed'))
        ORDER BY priority DESC
        LIMIT 1
    """).fetchone()

    if row is None:
        return None

    task_id = row[0]

    # Claim it — check status again to handle concurrent workers
    conn.execute("""
        UPDATE tasks
        SET status='claimed',
            lease_holder=?,
            lease_expires=strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+' || ? || ' seconds')
        WHERE id=? AND status='pending'
    """, (agent_id, lease_seconds, task_id))
    conn.commit()

    if conn.execute("SELECT changes()").fetchone()[0] == 0:
        # Another worker grabbed it; recurse to try the next one
        return claim_next_task(conn, agent_id, lease_seconds)

    return {
        "id": row[0],
        "kind": row[1],
        "target": row[2],
        "entity_addr": row[3],
        "payload_json": row[4],
        "priority": row[5],
    }


def complete_task(conn: sqlite3.Connection, task_id: int, status: str = "completed"):
    """Mark a task as completed (or failed)."""
    conn.execute("""
        UPDATE tasks
        SET status=?, completed_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE id=?
    """, (status, task_id))
    conn.commit()


def fail_task(conn: sqlite3.Connection, task_id: int):
    """Mark a task as failed and release the lease."""
    conn.execute("""
        UPDATE tasks
        SET status='failed',
            lease_holder=NULL,
            lease_expires=NULL,
            completed_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE id=?
    """, (task_id,))
    conn.commit()


# ---------------------------------------------------------------------------
# Claude API call
# ---------------------------------------------------------------------------

def call_claude(prompt: str, model: str) -> dict:
    """Call the Claude API and return the full message response.

    Returns dict with keys: content, input_tokens, output_tokens.
    """
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    message = client.messages.create(
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
# Response parsing
# ---------------------------------------------------------------------------

def parse_proposal(response_text: str) -> dict:
    """Extract JSON proposal from Claude's response.

    Handles raw JSON, markdown code blocks, and falls back to regex extraction.
    Expected shape: {"name": "...", "confidence": 0.0-1.0, "rationale": "..."}
    The schema doc uses "name"/"rationale"; the prompt uses
    "proposed_name"/"reasoning" — accept either.
    """
    # Strip markdown code fences if present
    cleaned = response_text.strip()
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # Try direct JSON parse
    try:
        obj = json.loads(cleaned)
        return _normalize_proposal(obj)
    except json.JSONDecodeError:
        pass

    # Try to find a JSON object anywhere in the text
    brace_match = re.search(r"\{[^{}]*\}", response_text, re.DOTALL)
    if brace_match:
        try:
            obj = json.loads(brace_match.group(0))
            return _normalize_proposal(obj)
        except json.JSONDecodeError:
            pass

    # Last resort: extract fields with regex
    name_match = re.search(r'"(?:proposed_name|name)"\s*:\s*"([^"]+)"', response_text)
    conf_match = re.search(r'"confidence"\s*:\s*([\d.]+)', response_text)
    rationale_match = re.search(
        r'"(?:rationale|reasoning)"\s*:\s*"([^"]*)"', response_text
    )
    provenance_match = re.search(r'"provenance"\s*:\s*"([^"]*)"', response_text)

    return {
        "name": name_match.group(1) if name_match else "PARSE_FAILED",
        "confidence": float(conf_match.group(1)) if conf_match else 0.1,
        "rationale": rationale_match.group(1) if rationale_match else response_text[:200],
        "provenance": provenance_match.group(1) if provenance_match else "",
    }


def _normalize_proposal(obj: dict) -> dict:
    """Normalize key names to the canonical form used in evidence_log."""
    name = obj.get("name") or obj.get("proposed_name", "UNKNOWN")
    confidence = float(obj.get("confidence", 0.5))
    rationale = obj.get("rationale") or obj.get("reasoning", "")
    provenance = obj.get("provenance", "")
    return {
        "name": name,
        "confidence": confidence,
        "rationale": rationale,
        "provenance": provenance,
    }


# ---------------------------------------------------------------------------
# Evidence log + agent run accounting
# ---------------------------------------------------------------------------

def write_evidence(conn: sqlite3.Connection, task: dict, agent_id: str,
                   proposal: dict):
    """Insert a name proposal into the evidence_log table.

    If the agent returned a provenance tag, map it to the evidence_method
    column instead of the default 'agent_proposal'.
    """
    # Import the provenance mapping from context module
    from context import VALID_PROVENANCE_TAGS

    claim_json = json.dumps({
        "name": proposal["name"],
        "rationale": proposal["rationale"],
    })

    # Map agent provenance tag to evidence_method, fall back to default
    raw_provenance = proposal.get("provenance", "")
    evidence_method = VALID_PROVENANCE_TAGS.get(raw_provenance, "agent_proposal")

    conn.execute("""
        INSERT INTO evidence_log
            (task_id, target, entity_addr, agent_id, claim_type,
             claim_json, confidence, evidence_method)
        VALUES (?, ?, ?, ?, 'name', ?, ?, ?)
    """, (
        task["id"],
        task["target"],
        task["entity_addr"],
        agent_id,
        claim_json,
        proposal["confidence"],
        evidence_method,
    ))
    conn.commit()


def parse_trace_result(response_text: str) -> dict:
    """Extract the layered trace JSON from a trace_data_source response.

    Expected shape:
    {
        "register": "USART2_DR",
        "write_function": "...",
        "value_source": [{"layer": 0, "description": "...", "provenance": "..."}],
        "final_answer": "...",
        "confidence": 0.0-1.0
    }
    """
    cleaned = response_text.strip()
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # Try direct JSON parse
    try:
        obj = json.loads(cleaned)
        return obj
    except json.JSONDecodeError:
        pass

    # Try to find a JSON object with value_source array
    # Look for the outermost braces
    brace_start = response_text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(response_text)):
            if response_text[i] == "{":
                depth += 1
            elif response_text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(response_text[brace_start:i + 1])
                        return obj
                    except json.JSONDecodeError:
                        break

    # Fallback
    return {
        "register": "UNKNOWN",
        "write_function": "UNKNOWN",
        "value_source": [],
        "final_answer": response_text[:500],
        "confidence": 0.1,
    }


def write_trace_evidence(conn: sqlite3.Connection, task: dict, agent_id: str,
                         trace_result: dict):
    """Insert a trace_data_source result into the evidence_log table."""
    claim_json = json.dumps(trace_result)
    confidence = float(trace_result.get("confidence", 0.5))
    # Clamp confidence to valid range
    confidence = max(0.0, min(1.0, confidence))

    conn.execute("""
        INSERT INTO evidence_log
            (task_id, target, entity_addr, agent_id, claim_type,
             claim_json, confidence, evidence_method)
        VALUES (?, ?, ?, ?, 'data_trace', ?, ?, 'agent_proposal')
    """, (
        task["id"],
        task["target"],
        task["entity_addr"],
        agent_id,
        claim_json,
        confidence,
    ))
    conn.commit()


def log_agent_run(conn: sqlite3.Connection, agent_id: str, model: str,
                  tasks_completed: int, total_input_tokens: int,
                  total_output_tokens: int, total_cost: float):
    """Log summary of this worker's run to agent_runs.

    The schema has one row per task, but for the initial implementation
    we log one summary row per worker invocation.
    """
    conn.execute("""
        INSERT INTO agent_runs
            (agent_id, model, input_tokens, output_tokens, cost_usd)
        VALUES (?, ?, ?, ?, ?)
    """, (agent_id, model, total_input_tokens, total_output_tokens, total_cost))
    conn.commit()


# ---------------------------------------------------------------------------
# Context assembly — delegates to scripts/agents/context.py when available
# ---------------------------------------------------------------------------

def _try_import_context():
    """Try to import the context module; return None if not available yet."""
    try:
        # Add scripts/agents to path so we can import context
        agents_dir = str(Path(__file__).resolve().parent)
        if agents_dir not in sys.path:
            sys.path.insert(0, agents_dir)
        import context as ctx_mod
        return ctx_mod
    except ImportError:
        return None


def assemble_context_fallback(conn_duckdb, target: str, entity_addr: int) -> str:
    """Minimal context assembly when context.py is not yet available.

    Queries the warehouse directly to build a basic prompt.
    """
    sections = []

    # Target function info
    try:
        row = conn_duckdb.execute("""
            SELECT name, size, basic_block_count
            FROM functions
            WHERE source = ? AND addr = ?
        """, [target, entity_addr]).fetchone()
        if row:
            sections.append(
                f"## Target function\n"
                f"Address: 0x{entity_addr:08x}  Size: {row[1]}  "
                f"Blocks: {row[2]}\n"
                f"Current name: {row[0]}"
            )
    except Exception:
        sections.append(
            f"## Target function\n"
            f"Address: 0x{entity_addr:08x}\n"
            f"(function details unavailable)"
        )

    # Callers
    try:
        callers = conn_duckdb.execute("""
            SELECT DISTINCT f.name, f.addr
            FROM calls c
            JOIN functions f ON f.source = c.source AND f.addr = c.caller_addr
            WHERE c.source = ? AND c.callee_addr = ?
            LIMIT 10
        """, [target, entity_addr]).fetchall()
        if callers:
            lines = [f"- {name} @ 0x{addr:08x}" for name, addr in callers]
            sections.append("## Callers\n" + "\n".join(lines))
    except Exception:
        pass

    # Callees
    try:
        callees = conn_duckdb.execute("""
            SELECT DISTINCT f.name, f.addr
            FROM calls c
            JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
            WHERE c.source = ? AND c.caller_addr = ?
            LIMIT 10
        """, [target, entity_addr]).fetchall()
        if callees:
            lines = [f"- {name} @ 0x{addr:08x}" for name, addr in callees]
            sections.append("## Callees\n" + "\n".join(lines))
    except Exception:
        pass

    # Referenced strings
    try:
        strings = conn_duckdb.execute("""
            SELECT s.value
            FROM xrefs x
            JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
            WHERE x.source = ? AND x.function_addr = ?
            LIMIT 10
        """, [target, entity_addr]).fetchall()
        if strings:
            lines = [f'- "{row[0]}"' for row in strings]
            sections.append("## Referenced strings\n" + "\n".join(lines))
    except Exception:
        pass

    context_text = "\n\n".join(sections)

    # Add task instruction
    context_text += (
        "\n\n## Task\n"
        "Propose a human-readable name for this function. Return JSON:\n"
        '{"name": "...", "confidence": 0.0-1.0, "rationale": "..."}\n'
        "Only return the JSON object, no other text."
    )

    return context_text


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------

def run_worker(db_path: str, build_dir: str, model: str, max_tasks: int,
               dry_run: bool = False):
    import duckdb

    conn_sqlite = sqlite3.connect(db_path)
    conn_sqlite.execute("PRAGMA journal_mode=WAL")

    conn_duckdb = duckdb.connect(":memory:")
    views = register_warehouse(conn_duckdb, build_dir)
    print(f"worker: registered {len(views)} warehouse views: {', '.join(views)}")

    # Try to import the context module from the other agent
    ctx_mod = _try_import_context()
    if ctx_mod:
        print("worker: using context.py for prompt assembly")
    else:
        print("worker: context.py not available, using fallback context assembly")

    agent_id = f"worker-{uuid4().hex[:8]}"
    print(f"worker: agent_id={agent_id}, model={model}, max_tasks={max_tasks}, "
          f"dry_run={dry_run}")

    tasks_completed = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost = 0.0

    while tasks_completed < max_tasks:
        task = claim_next_task(conn_sqlite, agent_id)
        if task is None:
            print("worker: no pending tasks, stopping")
            break

        addr = task["entity_addr"]
        target = task["target"]
        kind = task["kind"]
        print(f"\n--- Task {task['id']}: {kind} for {target} 0x{addr:08x} "
              f"(priority={task['priority']:.3f}) ---")

        # Assemble context
        try:
            if kind == "trace_data_source":
                payload = json.loads(task["payload_json"]) if task["payload_json"] else {}
                register_addr = payload.get("register_addr")
                if register_addr is None:
                    print(f"  ERROR: trace_data_source task missing register_addr in payload")
                    fail_task(conn_sqlite, task["id"])
                    continue
                if ctx_mod and hasattr(ctx_mod, "assemble_trace_data_source_context"):
                    ctx = ctx_mod.assemble_trace_data_source_context(
                        conn_duckdb, target, addr, register_addr
                    )
                    prompt = ctx_mod.format_trace_data_source_prompt(ctx)
                else:
                    print(f"  ERROR: trace_data_source requires context.py")
                    fail_task(conn_sqlite, task["id"])
                    continue
            elif ctx_mod and hasattr(ctx_mod, "assemble_propose_name_context"):
                ctx = ctx_mod.assemble_propose_name_context(
                    conn_duckdb, target, addr
                )
                prompt = ctx_mod.format_propose_name_prompt(ctx)
            else:
                prompt = assemble_context_fallback(conn_duckdb, target, addr)
        except Exception as exc:
            print(f"  ERROR assembling context: {exc}")
            fail_task(conn_sqlite, task["id"])
            continue

        print(f"  Prompt: {len(prompt)} chars")

        if dry_run:
            print(f"  [DRY RUN] Prompt preview:")
            # Print first 800 chars, indented
            for line in prompt[:800].splitlines():
                print(f"    {line}")
            if len(prompt) > 800:
                print(f"    ... ({len(prompt) - 800} more chars)")
            complete_task(conn_sqlite, task["id"], "completed")
            tasks_completed += 1
            continue

        # Call Claude API
        try:
            t0 = time.monotonic()
            response = call_claude(prompt, model)
            elapsed = time.monotonic() - t0
        except Exception as exc:
            print(f"  ERROR calling Claude API: {exc}")
            fail_task(conn_sqlite, task["id"])
            continue

        total_input_tokens += response["input_tokens"]
        total_output_tokens += response["output_tokens"]
        print(f"  Response: {len(response['content'])} chars, "
              f"{response['input_tokens']}+{response['output_tokens']} tokens, "
              f"{elapsed:.1f}s")

        # Parse response and write evidence
        if kind == "trace_data_source":
            trace_result = parse_trace_result(response["content"])
            print(f"  Trace: {len(trace_result.get('value_source', []))} layers, "
                  f"confidence={trace_result.get('confidence', '?')}")
            if trace_result.get("final_answer"):
                print(f"  Answer: {trace_result['final_answer'][:120]}")
            write_trace_evidence(conn_sqlite, task, agent_id, trace_result)
        else:
            proposal = parse_proposal(response["content"])
            print(f"  Proposal: name={proposal['name']!r}, "
                  f"confidence={proposal['confidence']:.2f}, "
                  f"provenance={proposal.get('provenance', 'none')!r}")
            print(f"  Rationale: {proposal['rationale'][:120]}")
            write_evidence(conn_sqlite, task, agent_id, proposal)

        # Mark complete
        complete_task(conn_sqlite, task["id"], "completed")
        tasks_completed += 1

    # Estimate cost (Sonnet 4 pricing: $3/M input, $15/M output)
    total_cost = (total_input_tokens * 3.0 + total_output_tokens * 15.0) / 1_000_000

    print(f"\nworker: completed {tasks_completed} tasks")
    print(f"worker: tokens used: {total_input_tokens} input + "
          f"{total_output_tokens} output = ${total_cost:.4f}")

    # Log the run
    try:
        log_agent_run(conn_sqlite, agent_id, model, tasks_completed,
                      total_input_tokens, total_output_tokens, total_cost)
    except Exception as exc:
        print(f"worker: failed to log agent run: {exc}")

    conn_sqlite.close()
    conn_duckdb.close()


def main():
    parser = argparse.ArgumentParser(
        description="Agent worker: claim tasks, call Claude, write evidence"
    )
    parser.add_argument("--db", required=True,
                        help="Path to coordination.sqlite")
    parser.add_argument("--build-dir", default="build",
                        help="Path to build directory with parquet warehouse")
    parser.add_argument("--model", default="claude-sonnet-4-20250514",
                        help="Claude model to use")
    parser.add_argument("--max-tasks", type=int, default=5,
                        help="Max number of tasks to process")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print prompts without calling the API")
    args = parser.parse_args()

    run_worker(
        db_path=args.db,
        build_dir=args.build_dir,
        model=args.model,
        max_tasks=args.max_tasks,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
