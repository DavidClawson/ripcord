#!/usr/bin/env -S uv run python
"""Export base facts from the ripcord warehouse for Souffle consumption.

For each target with a calls table, writes:
  build/<target>/datalog/calls.facts      (caller_addr, callee_addr)
  build/<target>/datalog/functions.facts   (addr, name)
  build/<target>/datalog/entry_points.facts (addr)

The calls.facts file includes both static call edges from the `calls`
table AND recovered edges from `recovered_calls` (vector table entries,
function-pointer references, veneer jumps, registrar dispatch).

Previously this file contained ~170 lines of hardcoded per-target SQL
heuristics (B1-B11+C categories). Those heuristics are now replaced by
the `recovered_calls` table populated by export_recovered_calls.py
running inside Ghidra — which works on stripped binaries and generalizes
across targets without per-target name lists.

These are tab-separated, no header, matching the .input declarations
in reachability.dl.

Usage:
    scripts/datalog/export_facts.py                  # all targets
    scripts/datalog/export_facts.py pico_freertos_hello  # one target
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"
QUERY_SCRIPT = REPO_ROOT / "scripts" / "query"


def export_target(target: str) -> None:
    datalog_dir = BUILD_DIR / target / "datalog"
    datalog_dir.mkdir(parents=True, exist_ok=True)

    calls_path = datalog_dir / "calls.facts"
    functions_path = datalog_dir / "functions.facts"
    entry_points_path = datalog_dir / "entry_points.facts"

    has_recovered = (BUILD_DIR / target / "tables" / "recovered_calls.parquet").exists()

    # Build the calls query: static edges UNION recovered edges
    if has_recovered:
        calls_sql = f"""COPY (
            -- Static call edges from Ghidra's standard analysis
            SELECT caller_addr AS c1, callee_addr AS c2
            FROM calls
            WHERE source = '{target}'
              AND callee_addr IS NOT NULL

            UNION

            -- Recovered edges: func_ptr_ref, veneer_jump, registrar_dispatch
            SELECT caller_addr, callee_addr
            FROM recovered_calls
            WHERE source = '{target}'
              AND caller_addr IS NOT NULL
              AND callee_addr IS NOT NULL

        ) TO '{calls_path}'
        WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)"""
    else:
        # Fallback: only static edges if recovered_calls not yet populated
        calls_sql = f"""COPY (
            SELECT caller_addr AS c1, callee_addr AS c2
            FROM calls
            WHERE source = '{target}'
              AND callee_addr IS NOT NULL
        ) TO '{calls_path}'
        WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)"""

    subprocess.run([str(QUERY_SCRIPT), calls_sql], check=True)

    # Export function names
    subprocess.run(
        [
            str(QUERY_SCRIPT),
            f"""COPY (
                SELECT addr, name
                FROM functions
                WHERE source = '{target}'
            ) TO '{functions_path}'
            WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)""",
        ],
        check=True,
    )

    # Export entry points: vector_table targets + name-based fallbacks
    if has_recovered:
        entry_sql = f"""COPY (
            -- Vector table entries are hardware entry points (no caller)
            SELECT DISTINCT callee_addr AS addr
            FROM recovered_calls
            WHERE source = '{target}'
              AND mechanism = 'vector_table'

            UNION

            -- main is always an entry point
            SELECT addr FROM functions
            WHERE source = '{target}' AND name = 'main'

            UNION

            -- Name-based ISR/handler patterns (supplement vector table)
            SELECT addr FROM functions
            WHERE source = '{target}'
              AND (
                name LIKE 'isr!_%' ESCAPE '!'
                OR name IN ('xPortPendSVHandler', 'xPortSysTickHandler',
                            'vPortSVCHandler', '_entry_point', '_reset_handler',
                            '_init', '_fini', 'frame_dummy',
                            'register_tm_clones', 'data_cpy',
                            'irq_handler_chain_first_slot',
                            'ulSetInterruptMaskFromISR',
                            'vClearInterruptMaskFromISR')
              )
        ) TO '{entry_points_path}'
        WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)"""
    else:
        entry_sql = f"""COPY (
            SELECT addr FROM functions
            WHERE source = '{target}'
              AND (
                name = 'main'
                OR name LIKE 'isr!_%' ESCAPE '!'
                OR name IN ('xPortPendSVHandler', 'xPortSysTickHandler',
                            'vPortSVCHandler', '_entry_point', '_reset_handler',
                            '_init', '_fini', 'frame_dummy',
                            'register_tm_clones', 'data_cpy',
                            'irq_handler_chain_first_slot',
                            'ulSetInterruptMaskFromISR',
                            'vClearInterruptMaskFromISR')
              )
        ) TO '{entry_points_path}'
        WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)"""

    subprocess.run([str(QUERY_SCRIPT), entry_sql], check=True)

    print(f"  {target}: {calls_path} + {functions_path} + {entry_points_path}")


def discover_targets() -> list[str]:
    """Find targets that have a calls.parquet table."""
    targets = []
    if BUILD_DIR.exists():
        for d in sorted(BUILD_DIR.iterdir()):
            if d.is_dir() and (d / "tables" / "calls.parquet").exists():
                targets.append(d.name)
    return targets


def main() -> int:
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        targets = discover_targets()

    if not targets:
        print("no targets with calls tables found", file=sys.stderr)
        return 1

    print(f"exporting facts for {len(targets)} target(s):")
    for t in targets:
        export_target(t)

    return 0


if __name__ == "__main__":
    sys.exit(main())
