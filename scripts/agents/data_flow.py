"""Cross-function data flow analysis via shared global variables.

Many firmware functions are connected not through direct calls but through
shared RAM globals: function A writes to 0x200000F8+0x10, function B reads
it. The call graph shows them as unrelated, but they form producer-consumer
pairs. This module finds those pairs by analyzing READ/WRITE xrefs to RAM
addresses.

Peripheral-mapped addresses (>= 0x40000000) are excluded — those are
handled by peripheral_xrefs. This module focuses on RAM globals
(0x20000000-0x20040000).

Usage as library:
    from scripts.agents.data_flow import (
        compute_shared_globals,
        get_data_flow_context,
        format_data_flow_context,
    )

    conn = duckdb.connect(':memory:')
    register_warehouse(conn, 'build')
    shared = compute_shared_globals(conn, 'stock_v120')
    flow = get_data_flow_context(shared, 0x08001234)
    print(format_data_flow_context(flow))

Usage as CLI:
    python scripts/agents/data_flow.py --target stock_v120 --build-dir build
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import duckdb

# Ensure scripts/ and scripts/agents/ are importable
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
    sys.path.insert(0, str(_SCRIPTS_DIR / "agents"))


# RAM address range for global variables
_RAM_LO = 0x20000000
_RAM_HI = 0x20040000


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------

def compute_shared_globals(
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    min_writers: int = 1,
    min_readers: int = 1,
) -> dict[int, dict]:
    """Find global addresses shared between functions via READ/WRITE xrefs.

    Returns: {global_addr: {
        "writers": [addr1, addr2, ...],    # functions that WRITE to this address
        "readers": [addr3, addr4, ...],    # functions that READ from this address
    }}

    Only includes globals with at least min_writers writers AND min_readers
    readers. Excludes peripheral addresses (>= 0x40000000) — those are
    handled by peripheral_xrefs. Focuses on RAM globals (0x20000000-0x20040000).
    """
    # Single query: get all READ/WRITE xrefs to RAM addresses, grouped by
    # target address and ref_type, collecting distinct function addresses.
    sql = """
        SELECT
            to_addr,
            ref_type,
            LIST(DISTINCT function_addr ORDER BY function_addr) AS fn_addrs
        FROM xrefs
        WHERE source = $1
          AND ref_type IN ('READ', 'WRITE')
          AND to_addr >= $2
          AND to_addr < $3
          AND to_addr IS NOT NULL
        GROUP BY to_addr, ref_type
    """
    try:
        rows = conn_duckdb.execute(sql, [target, _RAM_LO, _RAM_HI]).fetchall()
    except duckdb.CatalogException:
        return {}

    # Build per-address writer/reader sets
    writers: dict[int, list[int]] = defaultdict(list)
    readers: dict[int, list[int]] = defaultdict(list)

    for to_addr, ref_type, fn_addrs in rows:
        if ref_type == "WRITE":
            writers[to_addr] = fn_addrs
        elif ref_type == "READ":
            readers[to_addr] = fn_addrs

    # Collect all addresses that appear in either set
    all_addrs = set(writers.keys()) | set(readers.keys())

    # Filter by min_writers and min_readers
    result: dict[int, dict] = {}
    for addr in all_addrs:
        w = writers.get(addr, [])
        r = readers.get(addr, [])
        if len(w) >= min_writers and len(r) >= min_readers:
            result[addr] = {"writers": w, "readers": r}

    return result


# ---------------------------------------------------------------------------
# Per-function accessor
# ---------------------------------------------------------------------------

def get_data_flow_context(
    shared_globals: dict[int, dict],
    function_addr: int,
    conn_duckdb: duckdb.DuckDBPyConnection | None = None,
    target: str | None = None,
) -> dict:
    """Get data flow context for a specific function.

    Returns: {
        "writes_to": [
            {"global_addr": 0x200000F8, "also_read_by": [addr1, addr2, ...]},
            ...
        ],
        "reads_from": [
            {"global_addr": 0x200000F8, "also_written_by": [addr1, addr2, ...]},
            ...
        ],
    }

    The conn_duckdb and target parameters are reserved for future use
    (e.g. fetching additional context per global). Currently all data
    comes from the precomputed shared_globals dict.
    """
    writes_to: list[dict] = []
    reads_from: list[dict] = []

    for global_addr, info in shared_globals.items():
        w = info["writers"]
        r = info["readers"]

        if function_addr in w:
            # This function writes here — who else reads it?
            other_readers = [a for a in r if a != function_addr]
            if other_readers:
                writes_to.append({
                    "global_addr": global_addr,
                    "also_read_by": other_readers,
                })

        if function_addr in r:
            # This function reads here — who else writes it?
            other_writers = [a for a in w if a != function_addr]
            if other_writers:
                reads_from.append({
                    "global_addr": global_addr,
                    "also_written_by": other_writers,
                })

    # Sort by number of connected functions (most shared first)
    writes_to.sort(key=lambda d: len(d["also_read_by"]), reverse=True)
    reads_from.sort(key=lambda d: len(d["also_written_by"]), reverse=True)

    return {"writes_to": writes_to, "reads_from": reads_from}


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------

def _fmt_addr(addr: int, names: dict[int, str] | None) -> str:
    """Format a function address, using its name if available."""
    if names and addr in names:
        return names[addr]
    return f"FUN_{addr:08x}"


def format_data_flow_context(
    flow: dict,
    function_names: dict[int, str] | None = None,
    max_globals: int = 10,
) -> str:
    """Format data flow context for inclusion in LLM prompts.

    Example output:
        ## Cross-function data flow (shared globals)
        Writes to globals also read by:
        - 0x200000F8: read by usart2_handler, main_loop, display_update
        - 0x20004E00: read by spi3_upload, dma_handler
        Reads globals also written by:
        - 0x20002000: written by adc_sample_isr, timer_handler

    Prioritizes globals shared with the most other functions.
    Uses function_names dict to resolve addresses to names when available.
    """
    writes_to = flow.get("writes_to", [])
    reads_from = flow.get("reads_from", [])

    if not writes_to and not reads_from:
        return ""

    lines = ["## Cross-function data flow (shared globals)"]

    if writes_to:
        lines.append("Writes to globals also read by:")
        for entry in writes_to[:max_globals]:
            addr = entry["global_addr"]
            readers = [_fmt_addr(a, function_names) for a in entry["also_read_by"]]
            lines.append(f"- 0x{addr:08x}: read by {', '.join(readers[:8])}"
                         + (f" (+{len(readers) - 8} more)" if len(readers) > 8 else ""))

    if reads_from:
        lines.append("Reads globals also written by:")
        for entry in reads_from[:max_globals]:
            addr = entry["global_addr"]
            writers = [_fmt_addr(a, function_names) for a in entry["also_written_by"]]
            lines.append(f"- 0x{addr:08x}: written by {', '.join(writers[:8])}"
                         + (f" (+{len(writers) - 8} more)" if len(writers) > 8 else ""))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-function data flow analysis via shared RAM globals"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target name (e.g. stock_v120)",
    )
    parser.add_argument(
        "--build-dir", default="build",
        help="Path to build directory with Parquet warehouse",
    )
    parser.add_argument(
        "--min-writers", type=int, default=1,
        help="Minimum number of writer functions per global (default: 1)",
    )
    parser.add_argument(
        "--min-readers", type=int, default=1,
        help="Minimum number of reader functions per global (default: 1)",
    )
    parser.add_argument(
        "--limit", type=int, default=30,
        help="Max globals to display (default: 30)",
    )
    args = parser.parse_args()

    # Set up DuckDB with warehouse views (lazy import to avoid circular dep)
    from context import register_warehouse
    conn = duckdb.connect(":memory:")
    register_warehouse(conn, args.build_dir, targets=[args.target])

    # Compute shared globals
    shared = compute_shared_globals(
        conn, args.target,
        min_writers=args.min_writers,
        min_readers=args.min_readers,
    )

    if not shared:
        print(f"No shared RAM globals found for target '{args.target}'.")
        conn.close()
        return

    # Fetch function names for display
    try:
        name_rows = conn.execute(
            "SELECT addr, name FROM functions WHERE source = $1",
            [args.target],
        ).fetchall()
    except duckdb.CatalogException:
        name_rows = []

    addr_to_name: dict[int, str] = {addr: name for addr, name in name_rows}

    # Build display rows sorted by total reader+writer count
    display: list[tuple[int, int, int, list[str], list[str]]] = []
    for global_addr, info in shared.items():
        w = info["writers"]
        r = info["readers"]
        w_names = [addr_to_name.get(a, f"FUN_{a:08x}") for a in w]
        r_names = [addr_to_name.get(a, f"FUN_{a:08x}") for a in r]
        display.append((global_addr, len(w), len(r), w_names, r_names))

    display.sort(key=lambda t: t[1] + t[2], reverse=True)
    display = display[: args.limit]

    # Print table
    print(f"{'global_addr':>12s}  {'#wr':>4s}  {'#rd':>4s}  {'writers':<40s}  readers")
    print("-" * 120)
    for global_addr, nw, nr, w_names, r_names in display:
        w_str = ", ".join(w_names[:5]) + (f" +{len(w_names)-5}" if len(w_names) > 5 else "")
        r_str = ", ".join(r_names[:5]) + (f" +{len(r_names)-5}" if len(r_names) > 5 else "")
        print(f"  0x{global_addr:08x}  {nw:>4d}  {nr:>4d}  {w_str:<40s}  {r_str}")

    # Summary
    total_globals = len(shared)
    total_writers = len({a for info in shared.values() for a in info["writers"]})
    total_readers = len({a for info in shared.values() for a in info["readers"]})
    print(f"\n{total_globals} shared RAM globals connecting "
          f"{total_writers} writer functions and {total_readers} reader functions.")

    conn.close()


if __name__ == "__main__":
    main()
