"""Transitive peripheral affinity via call-graph propagation.

Computes per-function peripheral affinity scores by combining direct
peripheral register accesses (from peripheral_xrefs) with transitive
accesses through callees, weighted by call depth.

A function that directly accesses SPI3 10 times and calls a function
that accesses DMA1 5 times gets: SPI3=1.0 (direct), DMA1=0.25
(callee access discounted by 0.5 per hop).

Algorithm: reverse-topological pass over the call graph. Each function
accumulates its own direct peripheral counts plus 0.5 * each callee's
accumulated counts. O(V+E) total, not per-function BFS.

Usage as library:
    from scripts.agents.peripheral_affinity import (
        compute_transitive_affinity,
        get_primary_peripheral,
        format_affinity_context,
    )

    conn = duckdb.connect(':memory:')
    register_warehouse(conn, 'build')
    affinities = compute_transitive_affinity(conn, 'stock_v120')
    for addr, aff in affinities.items():
        print(addr, get_primary_peripheral(aff), format_affinity_context(aff))

Usage as CLI:
    python scripts/agents/peripheral_affinity.py --target stock_v120 --build-dir build
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict, deque
from pathlib import Path

import duckdb

# Ensure scripts/agents is importable
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
    sys.path.insert(0, str(_SCRIPTS_DIR / "agents"))


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------

def compute_transitive_affinity(
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    max_depth: int = 3,
) -> dict[int, dict[str, float]]:
    """Compute transitive peripheral affinity for every function in a target.

    Returns a dict mapping function_addr -> {peripheral_name: score}.
    Scores are normalized per-function so the highest = 1.0.
    Functions with zero affinity at any depth are omitted.

    Uses a reverse-topological pass: process leaves first, propagate
    accumulated counts upward through callers with 0.5 decay per hop.
    For cycles (recursion), falls back to BFS capped at max_depth.
    """
    # -- Fetch direct peripheral access counts --
    try:
        rows = conn_duckdb.execute(
            "SELECT function_addr, peripheral, COUNT(*) AS n "
            "FROM peripheral_xrefs WHERE source = $1 "
            "GROUP BY function_addr, peripheral",
            [target],
        ).fetchall()
    except duckdb.CatalogException:
        return {}

    # direct_counts: addr -> {peripheral: count}
    direct_counts: dict[int, dict[str, float]] = {}
    for addr, periph, n in rows:
        direct_counts.setdefault(addr, {})[periph] = float(n)

    # -- Fetch call edges --
    try:
        edge_rows = conn_duckdb.execute(
            "SELECT caller_addr, callee_addr FROM calls WHERE source = $1",
            [target],
        ).fetchall()
    except duckdb.CatalogException:
        edge_rows = []

    # Also include recovered_calls if available
    try:
        recovered_rows = conn_duckdb.execute(
            "SELECT caller_addr, callee_addr FROM recovered_calls WHERE source = $1",
            [target],
        ).fetchall()
        edge_rows = edge_rows + recovered_rows
    except duckdb.CatalogException:
        pass

    # Build adjacency: caller -> set of callees
    callees_of: dict[int, set[int]] = defaultdict(set)
    callers_of: dict[int, set[int]] = defaultdict(set)
    all_nodes: set[int] = set()
    for caller, callee in edge_rows:
        callees_of[caller].add(callee)
        callers_of[callee].add(caller)
        all_nodes.add(caller)
        all_nodes.add(callee)

    # Include nodes that have direct peripheral accesses but no edges
    all_nodes.update(direct_counts.keys())

    # -- Topological sort (Kahn's algorithm) --
    # in-degree = number of callees (we process callees before callers)
    in_degree: dict[int, int] = {addr: 0 for addr in all_nodes}
    for addr in all_nodes:
        in_degree[addr] = len(callees_of.get(addr, set()))

    queue: deque[int] = deque()
    for addr, deg in in_degree.items():
        if deg == 0:
            queue.append(addr)

    topo_order: list[int] = []
    while queue:
        node = queue.popleft()
        topo_order.append(node)
        for caller in callers_of.get(node, set()):
            in_degree[caller] -= 1
            if in_degree[caller] == 0:
                queue.append(caller)

    # Nodes not in topo_order are in cycles
    cycle_nodes = all_nodes - set(topo_order)

    # -- Propagate affinities in topological order --
    # accumulated: addr -> {peripheral: weighted_count}
    accumulated: dict[int, dict[str, float]] = {}

    for addr in topo_order:
        acc: dict[str, float] = {}
        # Start with direct counts
        if addr in direct_counts:
            for periph, count in direct_counts[addr].items():
                acc[periph] = count
        # Add 0.5 * each callee's accumulated affinity
        for callee in callees_of.get(addr, set()):
            if callee in accumulated:
                for periph, val in accumulated[callee].items():
                    acc[periph] = acc.get(periph, 0.0) + 0.5 * val
        if acc:
            accumulated[addr] = acc

    # -- Handle cycle nodes with BFS capped at max_depth --
    for addr in cycle_nodes:
        acc: dict[str, float] = {}
        if addr in direct_counts:
            for periph, count in direct_counts[addr].items():
                acc[periph] = count

        # BFS through callees, tracking depth
        visited: set[int] = {addr}
        frontier: list[int] = list(callees_of.get(addr, set()))
        depth = 1
        while frontier and depth <= max_depth:
            next_frontier: list[int] = []
            weight = 0.5 ** depth
            for callee in frontier:
                if callee in visited:
                    continue
                visited.add(callee)
                # Use accumulated if available (callee was in topo order),
                # otherwise use direct counts only
                source = accumulated.get(callee, direct_counts.get(callee, {}))
                for periph, val in source.items():
                    acc[periph] = acc.get(periph, 0.0) + weight * val
                next_frontier.extend(
                    c for c in callees_of.get(callee, set()) if c not in visited
                )
            frontier = next_frontier
            depth += 1

        if acc:
            accumulated[addr] = acc

    # -- Normalize: highest affinity per function = 1.0 --
    result: dict[int, dict[str, float]] = {}
    for addr, acc in accumulated.items():
        max_val = max(acc.values())
        if max_val > 0:
            result[addr] = {periph: val / max_val for periph, val in acc.items()}

    return result


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def get_primary_peripheral(affinity: dict[str, float]) -> str | None:
    """Return the peripheral with the highest affinity score, or None."""
    if not affinity:
        return None
    return max(affinity, key=affinity.get)  # type: ignore[arg-type]


def format_affinity_context(affinity: dict[str, float], top_n: int = 5) -> str:
    """Format top N peripherals as a human-readable string for LLM prompts.

    Example output:
        Peripheral affinity (including callees): SPI3 (1.00), DMA1 (0.45), CRM (0.20)
    """
    if not affinity:
        return "Peripheral affinity: none"
    ranked = sorted(affinity.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    parts = [f"{name} ({score:.2f})" for name, score in ranked]
    return f"Peripheral affinity (including callees): {', '.join(parts)}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute transitive peripheral affinity for a firmware target"
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
        "--max-depth", type=int, default=3,
        help="Maximum call-graph hops for transitive propagation (default: 3)",
    )
    parser.add_argument(
        "--limit", type=int, default=30,
        help="Max rows to display (default: 30)",
    )
    args = parser.parse_args()

    # Set up DuckDB with warehouse views (lazy import to avoid circular dep)
    from context import register_warehouse
    conn = duckdb.connect(":memory:")
    register_warehouse(conn, args.build_dir, targets=[args.target])

    # Compute affinities
    affinities = compute_transitive_affinity(conn, args.target, max_depth=args.max_depth)

    if not affinities:
        print(f"No peripheral affinity data for target '{args.target}'.")
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

    # Build display rows: (addr, name, primary, num_peripherals, affinity_str)
    display_rows: list[tuple[int, str, str, int, str]] = []
    for addr, aff in affinities.items():
        name = addr_to_name.get(addr, f"FUN_{addr:08x}")
        primary = get_primary_peripheral(aff) or "?"
        n_periph = len(aff)
        aff_str = format_affinity_context(aff, top_n=5)
        display_rows.append((addr, name, primary, n_periph, aff_str))

    # Sort by number of peripherals (most diverse first)
    display_rows.sort(key=lambda r: r[3], reverse=True)
    display_rows = display_rows[: args.limit]

    # Print table
    print(f"{'addr':>10s}  {'name':<40s}  {'primary':<16s}  {'#periph':>7s}  affinity")
    print("-" * 120)
    for addr, name, primary, n_periph, aff_str in display_rows:
        print(f"0x{addr:08x}  {name:<40s}  {primary:<16s}  {n_periph:>7d}  {aff_str}")

    # Summary
    total_fn = len(name_rows) if name_rows else 0
    with_affinity = len(affinities)
    direct_only = sum(1 for addr in affinities if addr in {r[0] for r in name_rows})
    print(f"\n{with_affinity} functions with peripheral affinity out of {total_fn} total.")

    conn.close()


if __name__ == "__main__":
    main()
