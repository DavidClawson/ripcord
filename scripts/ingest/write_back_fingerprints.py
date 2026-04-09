"""Write structural fingerprint matches back as enriched function tables.

Reads all targets' parquet tables, computes cross-target structural
matches within build-tuple groups, and writes
build/<target>/tables/functions_enriched.parquet per target with five
new columns: inferred_name, inferred_library, confidence,
evidence_method, conflict.

Confidence values follow notes/confidence-scheme.md calibration anchors.
The original functions.parquet is never modified.

Usage:
    python write_back_fingerprints.py --config config.yaml --build-dir build
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import duckdb
import yaml


# ---------------------------------------------------------------------------
# SQL: feature vector CTE (reused from structural_signatures.sql)
# ---------------------------------------------------------------------------

FEATURE_VECTOR_CTE = """
bb_agg AS (
    SELECT source, function_addr,
           SUM(instruction_count) AS instructions
    FROM basic_blocks
    WHERE function_addr IS NOT NULL
    GROUP BY source, function_addr
),
call_agg AS (
    SELECT source, caller_addr AS function_addr,
           COUNT(*)                    AS out_calls,
           COUNT(DISTINCT callee_addr) AS distinct_callees
    FROM calls
    GROUP BY source, caller_addr
),
xref_agg AS (
    SELECT source, function_addr,
           SUM(CASE WHEN ref_type = 'READ'  THEN 1 ELSE 0 END) AS reads,
           SUM(CASE WHEN ref_type = 'WRITE' THEN 1 ELSE 0 END) AS writes,
           SUM(CASE WHEN ref_type IN ('CONDITIONAL_JUMP','UNCONDITIONAL_JUMP')
                    THEN 1 ELSE 0 END) AS jumps
    FROM xrefs
    GROUP BY source, function_addr
),
feature_vector AS (
    SELECT
        f.source, f.addr, f.name, f.size, f.body_hash,
        f.basic_block_count                      AS blocks,
        COALESCE(bb.instructions,       0)       AS instructions,
        COALESCE(ca.out_calls,          0)       AS out_calls,
        COALESCE(ca.distinct_callees,   0)       AS distinct_callees,
        COALESCE(xa.reads,              0)       AS reads,
        COALESCE(xa.writes,             0)       AS writes,
        COALESCE(xa.jumps,              0)       AS jumps
    FROM functions f
    LEFT JOIN bb_agg   bb ON bb.source = f.source AND bb.function_addr = f.addr
    LEFT JOIN call_agg ca ON ca.source = f.source AND ca.function_addr = f.addr
    LEFT JOIN xref_agg xa ON xa.source = f.source AND xa.function_addr = f.addr
    WHERE COALESCE(f.is_thunk, FALSE) = FALSE
      AND f.size IS NOT NULL
      AND f.size >= 8
      AND f.source IN ({target_list})
)
"""

# ---------------------------------------------------------------------------
# SQL: matching + best-match selection
# ---------------------------------------------------------------------------

MATCHING_SQL = """
WITH
{feature_vector_cte},

-- Tier 1: body_hash exact matches (confidence 1.0)
hash_pairs AS (
    SELECT
        a.source AS src_a, a.addr AS addr_a, a.name AS name_a,
        b.source AS src_b, b.addr AS addr_b, b.name AS name_b
    FROM feature_vector a
    JOIN feature_vector b
        ON  a.size = b.size AND a.blocks = b.blocks
        AND a.instructions = b.instructions
        AND a.out_calls = b.out_calls
        AND a.distinct_callees = b.distinct_callees
        AND a.reads = b.reads AND a.writes = b.writes AND a.jumps = b.jumps
        AND a.source < b.source
    WHERE a.body_hash IS NOT NULL
      AND a.body_hash = b.body_hash
),

-- Tier 2: 8-tuple structural match, names agree (confidence 0.96)
struct_name_pairs AS (
    SELECT
        a.source AS src_a, a.addr AS addr_a, a.name AS name_a,
        b.source AS src_b, b.addr AS addr_b, b.name AS name_b
    FROM feature_vector a
    JOIN feature_vector b
        ON  a.size = b.size AND a.blocks = b.blocks
        AND a.instructions = b.instructions
        AND a.out_calls = b.out_calls
        AND a.distinct_callees = b.distinct_callees
        AND a.reads = b.reads AND a.writes = b.writes AND a.jumps = b.jumps
        AND a.source < b.source
    WHERE a.name NOT LIKE 'FUN_%' AND b.name NOT LIKE 'FUN_%'
      AND a.name = b.name
      AND NOT EXISTS (
          SELECT 1 FROM hash_pairs h
          WHERE h.src_a = a.source AND h.addr_a = a.addr
            AND h.src_b = b.source AND h.addr_b = b.addr
      )
),

-- Tier 3: 8-tuple structural match, one side has FUN_* (confidence 0.85)
struct_noname_pairs AS (
    SELECT
        a.source AS src_a, a.addr AS addr_a, a.name AS name_a,
        b.source AS src_b, b.addr AS addr_b, b.name AS name_b
    FROM feature_vector a
    JOIN feature_vector b
        ON  a.size = b.size AND a.blocks = b.blocks
        AND a.instructions = b.instructions
        AND a.out_calls = b.out_calls
        AND a.distinct_callees = b.distinct_callees
        AND a.reads = b.reads AND a.writes = b.writes AND a.jumps = b.jumps
        AND a.source < b.source
    WHERE (a.name LIKE 'FUN_%' OR b.name LIKE 'FUN_%')
      AND NOT (a.name LIKE 'FUN_%' AND b.name LIKE 'FUN_%')
      AND NOT EXISTS (
          SELECT 1 FROM hash_pairs h
          WHERE h.src_a = a.source AND h.addr_a = a.addr
            AND h.src_b = b.source AND h.addr_b = b.addr
      )
),

-- Symmetrize: each pair generates a row for BOTH sides
-- inferred_name = the other side's name (if this side is FUN_* or as confirmation)
all_directed AS (
    -- Hash matches: A's perspective
    SELECT src_a AS source, addr_a AS addr, name_a AS own_name,
           name_b AS other_name, src_b AS ref_source,
           CASE WHEN name_a NOT LIKE 'FUN_%' AND name_b NOT LIKE 'FUN_%' AND name_a = name_b
                THEN 'body_hash_exact+structural_8tuple_name_match'
                WHEN name_a LIKE 'FUN_%' AND name_b NOT LIKE 'FUN_%'
                THEN 'body_hash_exact+structural_8tuple_no_name'
                ELSE 'body_hash_exact'
           END AS evidence_method,
           1.0 AS confidence
    FROM hash_pairs
    UNION ALL
    -- Hash matches: B's perspective
    SELECT src_b, addr_b, name_b, name_a, src_a,
           CASE WHEN name_b NOT LIKE 'FUN_%' AND name_a NOT LIKE 'FUN_%' AND name_a = name_b
                THEN 'body_hash_exact+structural_8tuple_name_match'
                WHEN name_b LIKE 'FUN_%' AND name_a NOT LIKE 'FUN_%'
                THEN 'body_hash_exact+structural_8tuple_no_name'
                ELSE 'body_hash_exact'
           END,
           1.0
    FROM hash_pairs
    UNION ALL
    -- Structural name matches: both sides
    SELECT src_a, addr_a, name_a, name_b, src_b,
           'structural_8tuple_name_match', 0.96
    FROM struct_name_pairs
    UNION ALL
    SELECT src_b, addr_b, name_b, name_a, src_a,
           'structural_8tuple_name_match', 0.96
    FROM struct_name_pairs
    UNION ALL
    -- Structural no-name matches: both sides
    SELECT src_a, addr_a, name_a, name_b, src_b,
           'structural_8tuple_no_name', 0.85
    FROM struct_noname_pairs
    UNION ALL
    SELECT src_b, addr_b, name_b, name_a, src_a,
           'structural_8tuple_no_name', 0.85
    FROM struct_noname_pairs
),

-- Pick best match per (source, addr), detect conflicts
ranked AS (
    SELECT *,
           ROW_NUMBER() OVER (PARTITION BY source, addr ORDER BY confidence DESC, evidence_method) AS rn,
           COUNT(DISTINCT other_name) FILTER (
               WHERE other_name NOT LIKE 'FUN_%'
           ) OVER (PARTITION BY source, addr) AS distinct_other_names
    FROM all_directed
)

SELECT
    source, addr, own_name,
    -- inferred_name: the best match's other_name (only if it's a real name)
    CASE WHEN other_name NOT LIKE 'FUN_%' THEN other_name ELSE NULL END AS inferred_name,
    CAST(NULL AS VARCHAR) AS inferred_library,
    confidence,
    evidence_method,
    CASE WHEN distinct_other_names > 1 THEN TRUE ELSE FALSE END AS conflict
FROM ranked
WHERE rn = 1
"""


def register_tables(conn: duckdb.DuckDBPyConnection, targets: list[str],
                    build_dir: Path) -> None:
    """Register parquet files as DuckDB views."""
    for table in ("functions", "basic_blocks", "calls", "xrefs"):
        paths = []
        for t in targets:
            p = build_dir / t / "tables" / f"{table}.parquet"
            if p.exists():
                paths.append(str(p))
        if paths:
            path_list = ", ".join(f"'{p}'" for p in paths)
            conn.execute(
                f"CREATE OR REPLACE VIEW {table} AS "
                f"SELECT * FROM read_parquet([{path_list}], union_by_name=true)"
            )


def run_matching(conn: duckdb.DuckDBPyConnection,
                 targets: list[str]) -> duckdb.DuckDBPyRelation:
    """Run the matching query and return the results."""
    target_list = ", ".join(f"'{t}'" for t in targets)
    fv_cte = FEATURE_VECTOR_CTE.format(target_list=target_list)
    sql = MATCHING_SQL.format(feature_vector_cte=fv_cte)
    return conn.execute(sql).fetchall()


def main():
    parser = argparse.ArgumentParser(
        description="Write structural fingerprint matches to enriched parquet"
    )
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--build-dir", default="build")
    args = parser.parse_args()

    build_dir = Path(args.build_dir)
    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    # Group targets by build_tuple
    all_targets = list(cfg["targets"].keys())
    groups: dict[str, list[str]] = defaultdict(list)
    for name, info in cfg["targets"].items():
        bt = info.get("build_tuple")
        if bt:
            groups[bt].append(name)

    conn = duckdb.connect(":memory:")
    register_tables(conn, all_targets, build_dir)

    # Collect matches from all build-tuple groups
    conn.execute("CREATE TABLE best_matches (source VARCHAR, addr BIGINT, "
                 "own_name VARCHAR, inferred_name VARCHAR, "
                 "inferred_library VARCHAR, confidence FLOAT, "
                 "evidence_method VARCHAR, conflict BOOLEAN)")

    total_matches = 0
    for bt, targets in groups.items():
        if len(targets) < 2:
            continue
        target_list = ", ".join(f"'{t}'" for t in targets)
        fv_cte = FEATURE_VECTOR_CTE.format(target_list=target_list)
        sql = MATCHING_SQL.format(feature_vector_cte=fv_cte)
        conn.execute(f"INSERT INTO best_matches {sql}")
        count = conn.execute(
            f"SELECT COUNT(*) FROM best_matches WHERE source IN ({target_list})"
        ).fetchone()[0]
        print(f"  {bt}: {len(targets)} targets, {count} functions with matches")
        total_matches += count

    # Write enriched parquet per target
    for target in all_targets:
        func_path = build_dir / target / "tables" / "functions.parquet"
        out_path = build_dir / target / "tables" / "functions_enriched.parquet"
        if not func_path.exists():
            continue

        conn.execute(f"""
            COPY (
                SELECT f.*,
                       m.inferred_name,
                       m.inferred_library,
                       m.confidence,
                       m.evidence_method,
                       COALESCE(m.conflict, FALSE) AS conflict
                FROM read_parquet('{func_path}') f
                LEFT JOIN best_matches m
                    ON m.source = f.source AND m.addr = f.addr
            ) TO '{out_path}' (FORMAT PARQUET, COMPRESSION ZSTD)
        """)

    print(f"write_back_fingerprints: {total_matches} matches across "
          f"{len(all_targets)} targets")


if __name__ == "__main__":
    main()
