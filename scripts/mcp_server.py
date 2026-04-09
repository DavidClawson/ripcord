#!/usr/bin/env -S uv run python
"""MCP server exposing the ripcord firmware analysis warehouse.

Queries the Parquet warehouse via DuckDB, usable from any MCP client.

Usage:  uv run python scripts/mcp_server.py [--build-dir ./build]
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import traceback
from collections import defaultdict
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError:
    print(
        "ERROR: mcp package not found. Install with:\n"
        "  uv pip install mcp\n"
        "or:\n"
        "  pip install mcp",
        file=sys.stderr,
    )
    sys.exit(1)

import duckdb

# ---------------------------------------------------------------------------
# Warehouse discovery (mirrors scripts/query)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent


def discover_tables(build_dir: Path) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = defaultdict(list)
    pattern = str(build_dir / "*" / "tables" / "*.parquet")
    for path in glob.glob(pattern):
        name = os.path.splitext(os.path.basename(path))[0]
        groups[name].append(path)
    return {k: sorted(v) for k, v in sorted(groups.items())}


def create_connection(tables: dict[str, list[str]]) -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect(":memory:")
    for name, paths in tables.items():
        paths_sql = ", ".join(f"'{p}'" for p in paths)
        conn.execute(
            f"CREATE OR REPLACE VIEW {name} AS "
            f"SELECT * FROM read_parquet([{paths_sql}], union_by_name=true);"
        )
    return conn


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def run_sql(conn: duckdb.DuckDBPyConnection, sql: str) -> str:
    """Execute SQL and return markdown-formatted results."""
    try:
        result = conn.sql(sql)
    except duckdb.Error as exc:
        return f"**SQL error:** {exc}"
    if result is None:
        return "(no result)"
    cols = result.columns
    rows = result.fetchall()
    if not rows:
        return "(0 rows)"
    # Format as markdown table
    def fmt(v):
        if v is None:
            return ""
        if isinstance(v, int) and abs(v) > 0xFFFF:
            return f"0x{v:08X}"
        if isinstance(v, float):
            return f"{v:.4f}"
        s = str(v)
        return s[:120] + "..." if len(s) > 120 else s

    lines = []
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("| " + " | ".join("---" for _ in cols) + " |")
    for row in rows[:200]:  # cap at 200 rows
        lines.append("| " + " | ".join(fmt(v) for v in row) + " |")
    if len(rows) > 200:
        lines.append(f"\n*({len(rows)} total rows, showing first 200)*")
    else:
        lines.append(f"\n*({len(rows)} rows)*")
    return "\n".join(lines)


def fmt_hex(v: int | None) -> str:
    if v is None:
        return ""
    return f"0x{v:08X}"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_query(conn: duckdb.DuckDBPyConnection, args: dict) -> str:
    sql = args.get("sql", "").strip()
    if not sql:
        return "**Error:** `sql` parameter is required."
    return run_sql(conn, sql)


def tool_list_targets(conn: duckdb.DuckDBPyConnection, args: dict) -> str:
    return run_sql(conn, """
    WITH fc AS (SELECT source, COUNT(*) n FROM functions GROUP BY source),
         cc AS (SELECT source, COUNT(*) n FROM calls GROUP BY source),
         bc AS (SELECT source, COUNT(*) n FROM basic_blocks GROUP BY source),
         sc AS (SELECT source, COUNT(*) n FROM strings GROUP BY source),
         pc AS (SELECT source, COUNT(DISTINCT peripheral) n FROM peripheral_xrefs GROUP BY source)
    SELECT fc.source AS target, fc.n AS functions, COALESCE(cc.n,0) AS calls,
           COALESCE(bc.n,0) AS basic_blocks, COALESCE(sc.n,0) AS strings,
           COALESCE(pc.n,0) AS peripherals
    FROM fc LEFT JOIN cc ON fc.source=cc.source LEFT JOIN bc ON fc.source=bc.source
    LEFT JOIN sc ON fc.source=sc.source LEFT JOIN pc ON fc.source=pc.source
    ORDER BY fc.source""")


def tool_function_info(conn: duckdb.DuckDBPyConnection, args: dict) -> str:
    target = args.get("target", "")
    address = args.get("address", "")
    name = args.get("name", "")

    if not target:
        return "**Error:** `target` parameter is required."
    if not address and not name:
        return "**Error:** provide either `address` (hex) or `name`."

    # Resolve function
    if address:
        addr_int = int(address, 16) if isinstance(address, str) else int(address)
        fn_row = conn.sql(
            f"SELECT addr, name, size, basic_block_count, body_hash, is_thunk, signature "
            f"FROM functions WHERE source='{target}' AND addr={addr_int}"
        ).fetchone()
    else:
        fn_row = conn.sql(
            f"SELECT addr, name, size, basic_block_count, body_hash, is_thunk, signature "
            f"FROM functions WHERE source='{target}' AND name ILIKE '%{name}%' "
            f"ORDER BY size DESC LIMIT 1"
        ).fetchone()

    if not fn_row:
        return f"**No function found** in `{target}` matching {'address ' + address if address else 'name ' + name}."

    addr, fname, size, bb_count, body_hash, is_thunk, sig = fn_row
    lines = [
        f"## {fname} ({target})",
        f"**Address:** {fmt_hex(addr)}",
        f"**Size:** {size} bytes ({bb_count or '?'} basic blocks)",
        f"**Thunk:** {'yes' if is_thunk else 'no'}",
    ]
    if sig:
        lines.append(f"**Signature:** `{sig}`")
    if body_hash:
        lines.append(f"**Body hash:** `{body_hash[:16]}...`")

    # Peripheral accesses
    try:
        periph_rows = conn.sql(
            f"SELECT peripheral, register_name, ref_type, peripheral_group, COUNT(*) AS n "
            f"FROM peripheral_xrefs "
            f"WHERE source='{target}' AND function_addr={addr} "
            f"GROUP BY peripheral, register_name, ref_type, peripheral_group "
            f"ORDER BY peripheral, register_name"
        ).fetchall()
        if periph_rows:
            lines.append("\n### Peripheral Accesses")
            current_periph = None
            for periph, reg, ref_type, group, n in periph_rows:
                if periph != current_periph:
                    current_periph = periph
                    lines.append(f"- **{periph}** ({group})")
                rtype = ref_type.replace("DATA_", "").replace("_", " ") if ref_type else "?"
                lines.append(f"  - {reg or '?'}: {rtype} (x{n})")
    except duckdb.Error:
        pass  # peripheral_xrefs may not exist for all targets

    # Callers
    try:
        callers = conn.sql(
            f"SELECT DISTINCT c.caller_addr, COALESCE(f.name, '') AS name, COALESCE(f.size, 0) AS size "
            f"FROM calls c LEFT JOIN functions f ON c.source = f.source AND c.caller_addr = f.addr "
            f"WHERE c.source='{target}' AND c.callee_addr={addr} "
            f"ORDER BY c.caller_addr LIMIT 20"
        ).fetchall()
        if callers:
            lines.append(f"\n### Callers ({len(callers)})")
            for caddr, cname, csize in callers:
                lines.append(f"- {fmt_hex(caddr)} {cname} (size: {csize})")
    except duckdb.Error:
        pass

    # Callees
    try:
        callees = conn.sql(
            f"SELECT DISTINCT c.callee_addr, COALESCE(f.name, '') AS name, COALESCE(f.size, 0) AS size "
            f"FROM calls c LEFT JOIN functions f ON c.source = f.source AND c.callee_addr = f.addr "
            f"WHERE c.source='{target}' AND c.caller_addr={addr} AND c.callee_addr IS NOT NULL "
            f"ORDER BY c.callee_addr LIMIT 30"
        ).fetchall()
        if callees:
            lines.append(f"\n### Callees ({len(callees)})")
            for caddr, cname, csize in callees:
                lines.append(f"- {fmt_hex(caddr)} {cname} (size: {csize})")
    except duckdb.Error:
        pass

    # String references
    try:
        str_refs = conn.sql(
            f"SELECT s.addr, s.value "
            f"FROM xrefs x JOIN strings s ON x.source = s.source AND x.to_addr = s.addr "
            f"WHERE x.source='{target}' AND x.function_addr={addr} "
            f"ORDER BY s.addr LIMIT 20"
        ).fetchall()
        if str_refs:
            lines.append("\n### Strings Referenced")
            for saddr, sval in str_refs:
                display = sval[:80] + "..." if len(sval) > 80 else sval
                lines.append(f'- "{display}" at {fmt_hex(saddr)}')
    except duckdb.Error:
        pass

    return "\n".join(lines)


def tool_peripheral_map(conn: duckdb.DuckDBPyConnection, args: dict) -> str:
    target = args.get("target", "")
    peripheral = args.get("peripheral", "")

    if not target:
        return "**Error:** `target` parameter is required."

    where = f"source='{target}'"
    if peripheral:
        where += f" AND peripheral ILIKE '%{peripheral}%'"

    result = run_sql(conn, f"""
    SELECT peripheral, peripheral_group, register_name, ref_type,
           COUNT(DISTINCT function_addr) AS functions, COUNT(*) AS accesses
    FROM peripheral_xrefs WHERE {where}
    GROUP BY peripheral, peripheral_group, register_name, ref_type
    ORDER BY peripheral, register_name, ref_type""")
    try:
        fn_rows = conn.sql(f"""
        SELECT peripheral, function_addr, f.name, f.size, COUNT(*) AS n
        FROM peripheral_xrefs px JOIN functions f ON px.source=f.source AND px.function_addr=f.addr
        WHERE px.{where} GROUP BY ALL ORDER BY peripheral, n DESC""").fetchall()
        if fn_rows:
            result += "\n\n### Top Functions by Peripheral\n"
            cur, cnt = None, 0
            for periph, faddr, fname, fsize, n in fn_rows:
                if periph != cur:
                    cur, cnt = periph, 0
                    result += f"\n**{periph}:**\n"
                if cnt < 5:
                    result += f"- {fmt_hex(faddr)} {fname} ({fsize}B, {n} accesses)\n"
                    cnt += 1
    except duckdb.Error:
        pass
    return result


def tool_analyze(conn: duckdb.DuckDBPyConnection, args: dict, *, build_dir: Path) -> str:
    """Run the full ripcord analysis pipeline on a binary."""
    binary_path = args.get("binary_path", "")
    chip = args.get("chip", "")
    base_addr = args.get("base_addr", "")
    name = args.get("name", "")

    if not binary_path:
        return "**Error:** `binary_path` is required (absolute path to firmware .bin or .elf)."

    binary = Path(binary_path)
    if not binary.exists():
        return f"**Error:** file not found: `{binary_path}`"

    # Build the ripcord.py command
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "ripcord.py"),
        str(binary),
        "--no-open",
    ]
    if chip:
        cmd.extend(["--chip", chip])
    if base_addr:
        cmd.extend(["--base-addr", base_addr])
    if name:
        cmd.extend(["--name", name])

    import subprocess
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "**Error:** analysis timed out after 10 minutes."

    output = result.stdout
    if result.returncode != 0:
        return f"**Analysis failed** (exit code {result.returncode}):\n```\n{result.stderr}\n```"

    # Refresh the warehouse connection so new tables are queryable
    tables = discover_tables(build_dir)
    new_conn = create_connection(tables)
    # Swap the connection in the closure (caller handles this)
    return f"**Analysis complete.**\n\n```\n{output}\n```\n\nUse `list_targets` to see the new target, then query with `function_info`, `peripheral_map`, etc."


def tool_report(conn: duckdb.DuckDBPyConnection, args: dict) -> str:
    """Generate an HTML report for a target."""
    target = args.get("target", "")
    if not target:
        return "**Error:** `target` parameter is required."

    import subprocess
    output_path = REPO_ROOT / "build" / target / "report.html"
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "render" / "report.py"),
         target, "--output", str(output_path)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        return f"**Report generation failed:**\n```\n{result.stderr}\n```"
    return f"**Report generated:** `{output_path}`\n\n{result.stdout}"


def tool_find_functions(conn: duckdb.DuckDBPyConnection, args: dict) -> str:
    target = args.get("target", "")
    if not target:
        return "**Error:** `target` parameter is required."
    conds = [f"f.source='{target}'"]
    joins = []
    pg = args.get("peripheral_group", "")
    if pg:
        joins.append(
            "JOIN (SELECT DISTINCT source, function_addr FROM peripheral_xrefs "
            f"WHERE peripheral_group ILIKE '%{pg}%') px "
            "ON f.source=px.source AND f.addr=px.function_addr")
    if args.get("min_size") is not None:
        conds.append(f"f.size >= {int(args['min_size'])}")
    if args.get("name_pattern"):
        conds.append(f"f.name ILIKE '%{args['name_pattern']}%'")
    return run_sql(conn, f"""
    SELECT f.addr, f.name, f.size, f.basic_block_count
    FROM functions f {' '.join(joins)}
    WHERE {' AND '.join(conds)} ORDER BY f.size DESC LIMIT 50""")


# ---------------------------------------------------------------------------
# MCP server definition
# ---------------------------------------------------------------------------

def _tool(name, desc, props, required=None):
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return Tool(name=name, description=desc, inputSchema=schema)

TOOLS = [
    _tool("analyze",
          "Run the full ripcord analysis pipeline on a firmware binary. Extracts functions, "
          "calls, peripherals, and more. Takes a few minutes for Ghidra analysis. "
          "After completion, use list_targets/function_info/peripheral_map to explore results.",
          {"binary_path": {"type": "string", "description": "Absolute path to firmware .bin or .elf"},
           "chip": {"type": "string", "description": "Chip family (e.g. 'AT32F403A', 'RP2040'). Enables SVD peripheral resolution."},
           "base_addr": {"type": "string", "description": "Load address for raw binaries (e.g. '0x08004000'). Auto-detected if omitted."},
           "name": {"type": "string", "description": "Target name (default: derived from filename)"}},
          ["binary_path"]),
    _tool("query",
          "Run DuckDB SQL against the ripcord warehouse. Views: functions, calls, "
          "basic_blocks, xrefs, strings, pcode_features, recovered_calls, mmio_events, "
          "peripheral_xrefs, ground_truth_functions, decompiled. All have 'source' column.",
          {"sql": {"type": "string", "description": "DuckDB SQL query"}},
          ["sql"]),
    _tool("list_targets",
          "List all analyzed firmware targets with summary statistics.", {}),
    _tool("function_info",
          "Get detailed info about a function: metadata, peripherals, callers, callees, strings.",
          {"target": {"type": "string", "description": "Target name (e.g. 'stock_v120')"},
           "address": {"type": "string", "description": "Hex address (e.g. '0x08027A50')"},
           "name": {"type": "string", "description": "Function name pattern (partial match)"}},
          ["target"]),
    _tool("peripheral_map",
          "Peripheral register access summary: which functions touch which hardware.",
          {"target": {"type": "string", "description": "Target name"},
           "peripheral": {"type": "string", "description": "Filter peripheral (e.g. 'USART2')"}},
          ["target"]),
    _tool("find_functions",
          "Search functions by peripheral group, min size, or name pattern. Up to 50 results.",
          {"target": {"type": "string", "description": "Target name"},
           "peripheral_group": {"type": "string", "description": "e.g. 'communication', 'gpio'"},
           "min_size": {"type": "integer", "description": "Minimum size in bytes"},
           "name_pattern": {"type": "string", "description": "Name pattern (case-insensitive)"}},
          ["target"]),
    _tool("report",
          "Generate a self-contained HTML report for an analyzed target. Returns the file path.",
          {"target": {"type": "string", "description": "Target name"}},
          ["target"]),
]

DISPATCH = {t.name: globals()[f"tool_{t.name}"] for t in TOOLS}


def build_server(build_dir: Path) -> Server:
    tables = discover_tables(build_dir)
    if not tables:
        print(
            f"warning: no parquet tables found under {build_dir}/*/tables/ — "
            "use the 'analyze' tool to process a firmware binary",
            file=sys.stderr,
        )
    # Mutable container so analyze can refresh the connection
    state = {"conn": create_connection(tables), "build_dir": build_dir}

    def refresh_conn():
        """Re-discover tables and recreate the DuckDB connection."""
        new_tables = discover_tables(state["build_dir"])
        state["conn"] = create_connection(new_tables)

    server = Server("ripcord")

    @server.list_tools()
    async def list_tools():
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        handler = DISPATCH.get(name)
        if not handler:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        try:
            if name == "analyze":
                result = handler(state["conn"], arguments, build_dir=state["build_dir"])
                refresh_conn()  # pick up new parquet files
            else:
                result = handler(state["conn"], arguments)
        except Exception:
            result = f"**Internal error:**\n```\n{traceback.format_exc()}\n```"
        return [TextContent(type="text", text=result)]

    return server


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=REPO_ROOT / "build",
        help="Path to build directory containing target parquet files",
    )
    args = parser.parse_args()

    server = build_server(args.build_dir)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
