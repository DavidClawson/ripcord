"""Generate agent tasks for the coordination database.

Supports two task types:
  propose_name       — name unmatched functions (default)
  trace_data_source  — trace data flow to peripheral register writes

Usage:
    # propose_name tasks (default)
    python scripts/agents/generate_tasks.py \
        --db build/coordination.sqlite \
        --target pico_freertos_hello_stripped \
        --build-dir build

    # trace_data_source tasks
    python scripts/agents/generate_tasks.py \
        --db build/coordination.sqlite \
        --target stock_v120 \
        --build-dir build \
        --task-type trace_data_source \
        --register-addr 0x40004404
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

import duckdb


def build_candidate_query(target: str) -> str:
    """SQL to find functions needing agent work + their priority signals."""
    return f"""
    WITH
    enriched AS (
        SELECT addr, name, size, basic_block_count, inferred_name,
               confidence, conflict
        FROM functions_enriched
        WHERE source = '{target}'
    ),

    -- Functions that need work: no name, low confidence, or conflict
    candidates AS (
        SELECT addr, name, size, basic_block_count, inferred_name,
               confidence, conflict
        FROM enriched
        WHERE inferred_name IS NULL
           OR confidence < 0.85
           OR conflict = TRUE
    ),

    -- Call-graph degree per function (fan_in + fan_out)
    fan_in AS (
        SELECT callee_addr AS addr, COUNT(*) AS n
        FROM calls
        WHERE source = '{target}'
        GROUP BY callee_addr
    ),
    fan_out AS (
        SELECT caller_addr AS addr, COUNT(DISTINCT callee_addr) AS n
        FROM calls
        WHERE source = '{target}'
        GROUP BY caller_addr
    ),
    centrality AS (
        SELECT c.addr,
               COALESCE(fi.n, 0) AS fan_in,
               COALESCE(fo.n, 0) AS fan_out,
               COALESCE(fi.n, 0) + COALESCE(fo.n, 0) AS degree
        FROM candidates c
        LEFT JOIN fan_in fi ON fi.addr = c.addr
        LEFT JOIN fan_out fo ON fo.addr = c.addr
    ),
    -- Percentile rank for centrality (0-1)
    centrality_scored AS (
        SELECT addr, fan_in, fan_out, degree,
               PERCENT_RANK() OVER (ORDER BY degree) AS centrality_score
        FROM centrality
    ),

    -- Confident functions (for frontier detection)
    confident AS (
        SELECT addr FROM enriched
        WHERE confidence >= 0.80 AND confidence IS NOT NULL
    ),
    -- Frontier: candidates one hop from a confident function
    frontier AS (
        SELECT DISTINCT c2.addr
        FROM candidates c2
        WHERE c2.addr IN (
            -- callers of confident functions
            SELECT caller_addr FROM calls
            WHERE source = '{target}'
              AND callee_addr IN (SELECT addr FROM confident)
            UNION
            -- callees of confident functions
            SELECT callee_addr FROM calls
            WHERE source = '{target}'
              AND caller_addr IN (SELECT addr FROM confident)
        )
    )

    SELECT
        c.addr,
        c.name,
        c.size,
        c.basic_block_count,
        c.inferred_name,
        c.confidence,
        c.conflict,
        cs.fan_in,
        cs.fan_out,
        cs.degree,
        cs.centrality_score,
        -- Evidence gap score
        CASE
            WHEN c.confidence IS NULL              THEN 0.3
            WHEN c.confidence < 0.50               THEN 0.8
            WHEN c.confidence >= 0.50 AND c.confidence < 0.80 THEN 1.0
            WHEN c.confidence >= 0.80 AND c.confidence < 0.95 THEN 0.5
            ELSE 0.0
        END AS evidence_gap_score,
        -- Frontier score
        CASE WHEN f.addr IS NOT NULL THEN 1.0 ELSE 0.0 END AS frontier_score
    FROM candidates c
    JOIN centrality_scored cs ON cs.addr = c.addr
    LEFT JOIN frontier f ON f.addr = c.addr
    ORDER BY (0.50 * cs.centrality_score + 0.35 *
        CASE
            WHEN c.confidence IS NULL              THEN 0.3
            WHEN c.confidence < 0.50               THEN 0.8
            WHEN c.confidence >= 0.50 AND c.confidence < 0.80 THEN 1.0
            WHEN c.confidence >= 0.80 AND c.confidence < 0.95 THEN 0.5
            ELSE 0.0
        END
        + 0.15 * CASE WHEN f.addr IS NOT NULL THEN 1.0 ELSE 0.0 END) DESC
    """


def register_views(conn: duckdb.DuckDBPyConnection, target: str,
                   build_dir: Path) -> None:
    """Register parquet tables as DuckDB views."""
    tables_dir = build_dir / target / "tables"
    for table in ("functions_enriched", "functions", "calls", "basic_blocks",
                  "xrefs", "strings", "decompiled"):
        p = tables_dir / f"{table}.parquet"
        if p.exists():
            conn.execute(
                f"CREATE OR REPLACE VIEW {table} AS "
                f"SELECT * FROM read_parquet('{p}')"
            )


def generate_trace_data_source_tasks(
    duck: duckdb.DuckDBPyConnection,
    sq: sqlite3.Connection,
    target: str,
    register_addr: int,
) -> int:
    """Generate trace_data_source tasks for functions that write to a register.

    Returns the number of tasks inserted.
    """
    # Find all functions that write to this register
    writers = duck.execute(
        """
        SELECT DISTINCT x.function_addr, f.name, f.size
        FROM xrefs x
        JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
        WHERE x.source = $1
          AND x.to_addr = $2
          AND x.ref_type = 'WRITE'
        ORDER BY f.size DESC
        """,
        [target, register_addr],
    ).fetchall()

    if not writers:
        print(f"generate_tasks: no functions write to 0x{register_addr:08x} "
              f"in {target}")
        return 0

    # Clear existing pending trace_data_source tasks for this
    # target+register to make re-runs idempotent
    sq.execute(
        """DELETE FROM tasks
           WHERE kind = 'trace_data_source'
             AND target = ?
             AND status = 'pending'
             AND json_extract(payload_json, '$.register_addr') = ?""",
        (target, register_addr),
    )

    inserted = 0
    for fn_addr, fn_name, fn_size in writers:
        payload = {
            "register_addr": register_addr,
            "register_hex": f"0x{register_addr:08x}",
            "function_name": fn_name or f"FUN_{fn_addr:08x}",
            "function_size": fn_size,
        }
        # Priority: larger functions get higher priority (more likely to be
        # interesting dispatch functions)
        priority = min(1.0, (fn_size or 100) / 500.0)

        sq.execute(
            """INSERT INTO tasks (kind, target, entity_addr, priority, status, payload_json)
               VALUES (?, ?, ?, ?, 'pending', ?)""",
            ("trace_data_source", target, fn_addr, round(priority, 4),
             json.dumps(payload)),
        )
        inserted += 1

    sq.commit()
    return inserted


def main():
    parser = argparse.ArgumentParser(
        description="Generate agent tasks (propose_name or trace_data_source)"
    )
    parser.add_argument("--db", required=True, help="Path to coordination.sqlite")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--build-dir", default="build", help="Build directory")
    parser.add_argument(
        "--task-type", default="propose_name",
        choices=["propose_name", "trace_data_source"],
        help="Type of tasks to generate (default: propose_name)",
    )
    parser.add_argument(
        "--register-addr", type=lambda x: int(x, 0),
        help="Register address for trace_data_source tasks (e.g. 0x40004404)",
    )
    args = parser.parse_args()

    build_dir = Path(args.build_dir)
    db_path = Path(args.db)

    if not db_path.exists():
        print(f"ERROR: {db_path} does not exist. Run init_db.py first.")
        raise SystemExit(1)

    # Query the warehouse via DuckDB
    duck = duckdb.connect(":memory:")
    register_views(duck, args.target, build_dir)

    sq = sqlite3.connect(str(db_path))

    if args.task_type == "trace_data_source":
        if args.register_addr is None:
            print("ERROR: --register-addr is required for trace_data_source tasks")
            raise SystemExit(1)

        inserted = generate_trace_data_source_tasks(
            duck, sq, args.target, args.register_addr,
        )
        print(f"generate_tasks: {inserted} trace_data_source tasks created "
              f"for {args.target} register 0x{args.register_addr:08x}")
        sq.close()
        duck.close()
        return

    # --- propose_name path (original behavior) ---
    sql = build_candidate_query(args.target)
    rows = duck.execute(sql).fetchall()
    columns = [desc[0] for desc in duck.execute(sql).description]
    duck.close()

    if not rows:
        print(f"generate_tasks: no candidate functions found for {args.target}")
        sq.close()
        return

    # Clear existing pending propose_name tasks for this target to make
    # re-runs idempotent
    sq.execute(
        "DELETE FROM tasks WHERE kind = 'propose_name' AND target = ? AND status = 'pending'",
        (args.target,)
    )

    inserted = 0
    priorities = []
    for row in rows:
        row_dict = dict(zip(columns, row))

        addr = row_dict["addr"]
        name = row_dict["name"]
        size = row_dict["size"]
        bb_count = row_dict["basic_block_count"]
        inferred_name = row_dict["inferred_name"]
        confidence = row_dict["confidence"]
        conflict = row_dict["conflict"]
        fan_in = row_dict["fan_in"]
        fan_out = row_dict["fan_out"]
        centrality_score = float(row_dict["centrality_score"])
        evidence_gap_score = float(row_dict["evidence_gap_score"])
        frontier_score = float(row_dict["frontier_score"])

        priority = (0.50 * centrality_score
                    + 0.35 * evidence_gap_score
                    + 0.15 * frontier_score)

        payload = {
            "addr": addr,
            "current_name": name,
            "size": size,
            "basic_block_count": bb_count,
            "fan_in": fan_in,
            "fan_out": fan_out,
        }
        if inferred_name:
            payload["inferred_name"] = inferred_name
        if confidence is not None:
            payload["confidence"] = round(confidence, 4)
        if conflict:
            payload["conflict"] = True

        sq.execute(
            """INSERT INTO tasks (kind, target, entity_addr, priority, status, payload_json)
               VALUES (?, ?, ?, ?, 'pending', ?)""",
            ("propose_name", args.target, addr, round(priority, 4), json.dumps(payload))
        )
        inserted += 1
        priorities.append(priority)

    sq.commit()
    sq.close()

    # Print summary
    print(f"generate_tasks: {inserted} propose_name tasks created for {args.target}")
    print()

    # Priority distribution
    buckets = {"0.0-0.2": 0, "0.2-0.4": 0, "0.4-0.6": 0, "0.6-0.8": 0, "0.8-1.0": 0}
    for p in priorities:
        if p < 0.2:
            buckets["0.0-0.2"] += 1
        elif p < 0.4:
            buckets["0.2-0.4"] += 1
        elif p < 0.6:
            buckets["0.4-0.6"] += 1
        elif p < 0.8:
            buckets["0.6-0.8"] += 1
        else:
            buckets["0.8-1.0"] += 1

    print("Priority distribution:")
    for bucket, count in buckets.items():
        bar = "#" * count
        print(f"  {bucket}: {count:3d}  {bar}")
    print(f"  min={min(priorities):.4f}  max={max(priorities):.4f}  "
          f"mean={sum(priorities)/len(priorities):.4f}")


if __name__ == "__main__":
    main()
