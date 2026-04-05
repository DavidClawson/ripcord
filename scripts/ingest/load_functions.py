#!/usr/bin/env python3
"""Load per-target function JSONL files into a DuckDB warehouse.

Each JSONL file is expected at build/<target>/functions.jsonl, and its
target name is inferred from the directory. Re-ingest is idempotent:
rows for a given source are deleted and reinserted, so the warehouse
reflects the most recent extraction.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import duckdb


TARGET_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path, help="path to DuckDB file")
    parser.add_argument("--schema", required=True, type=Path, help="SQL schema file to apply")
    parser.add_argument("jsonl", nargs="+", type=Path, help="JSONL files to ingest")
    return parser.parse_args()


def target_name_from_path(path: Path) -> str:
    """Extract the target name from a build/<target>/functions.jsonl path."""
    name = path.parent.name
    if not TARGET_NAME_RE.match(name):
        raise ValueError(f"Unsafe target name derived from path {path}: {name!r}")
    return name


def ingest_one(conn: duckdb.DuckDBPyConnection, jsonl_path: Path) -> int:
    target = target_name_from_path(jsonl_path)
    abs_path = str(jsonl_path.resolve())

    # Delete any existing rows for this source so reruns are idempotent.
    conn.execute("DELETE FROM functions WHERE source = ?", [target])

    # DuckDB's read_json_auto needs a literal string path, but the target
    # name is a validated identifier so parameterising via f-string is safe.
    # The path is also quoted below.
    conn.execute(
        f"""
        INSERT INTO functions (
            source, addr, name, size,
            is_thunk, is_external, num_params, has_varargs,
            calling_convention, basic_block_count, signature
        )
        SELECT
            '{target}'            AS source,
            addr,
            name,
            size,
            is_thunk,
            is_external,
            num_params,
            has_varargs,
            calling_convention,
            basic_block_count,
            signature
        FROM read_json_auto('{abs_path}', format='newline_delimited')
        """
    )

    (count,) = conn.execute(
        "SELECT COUNT(*) FROM functions WHERE source = ?", [target]
    ).fetchone()
    return count


def main() -> int:
    args = parse_args()

    args.db.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(args.db))

    # Apply schema (idempotent via CREATE ... IF NOT EXISTS).
    schema_sql = args.schema.read_text()
    conn.execute(schema_sql)

    total = 0
    for jsonl_path in args.jsonl:
        if not jsonl_path.exists():
            print(f"warning: {jsonl_path} does not exist, skipping", file=sys.stderr)
            continue
        ingested = ingest_one(conn, jsonl_path)
        print(f"ingested {ingested} rows from {jsonl_path}")
        total += ingested

    (warehouse_total,) = conn.execute("SELECT COUNT(*) FROM functions").fetchone()
    print(f"warehouse now contains {warehouse_total} function rows across all sources")

    summary = conn.execute(
        """
        SELECT source,
               COUNT(*) AS functions,
               COALESCE(SUM(size), 0) AS total_bytes
        FROM functions
        GROUP BY source
        ORDER BY source
        """
    ).fetchall()
    if summary:
        print("per-source summary:")
        for source, n, total_bytes in summary:
            print(f"  {source}: {n} functions, {total_bytes} bytes of code")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
