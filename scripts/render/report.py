#!/usr/bin/env -S uv run python
"""Render a static HTML report for a target from the ripcord warehouse.

Reads all available Parquet tables for a target and produces a
self-contained HTML file with:
  - Summary header (target, arch, counts)
  - Function table (sortable, with inferred names + confidence)
  - Peripheral access map (functions grouped by hardware)
  - Call graph from entry points (collapsible tree)
  - Match results (if scored against a reference)

Usage:
    scripts/render/report.py stock_v120
    scripts/render/report.py pico_freertos_hello --output /tmp/report.html
    scripts/render/report.py stock_v120 --reference at32_freertos_hello
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

import duckdb

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"


def load_config() -> dict:
    import yaml
    with open(REPO_ROOT / "config.yaml") as f:
        return yaml.safe_load(f)


def connect_target(target: str) -> duckdb.DuckDBPyConnection:
    """Create DuckDB connection with all available tables for a target."""
    con = duckdb.connect()
    tables_dir = BUILD_DIR / target / "tables"
    if not tables_dir.exists():
        print(f"ERROR: {tables_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    for p in sorted(tables_dir.glob("*.parquet")):
        name = p.stem
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM read_parquet('{p}')")
    return con


def q(con, sql):
    """Execute SQL and return list of dicts."""
    result = con.execute(sql)
    cols = [d[0] for d in result.description]
    return [dict(zip(cols, row)) for row in result.fetchall()]


def esc(s):
    """HTML-escape a string."""
    return html.escape(str(s)) if s else ""


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def collect_summary(con, target: str, config: dict) -> dict:
    tcfg = config.get("targets", {}).get(target, {})
    counts = q(con, """
        SELECT
            (SELECT COUNT(*) FROM functions) AS functions,
            (SELECT COUNT(*) FROM calls) AS calls,
            (SELECT COUNT(*) FROM basic_blocks) AS basic_blocks,
            (SELECT COUNT(*) FROM xrefs) AS xrefs,
            (SELECT COUNT(*) FROM strings) AS strings
    """)[0]

    periph_count = 0
    periph_groups = 0
    try:
        pr = q(con, """
            SELECT COUNT(*) AS n, COUNT(DISTINCT peripheral_group) AS groups
            FROM peripheral_xrefs
        """)[0]
        periph_count = pr["n"]
        periph_groups = pr["groups"]
    except Exception:
        pass

    return {
        "target": target,
        "description": tcfg.get("description", ""),
        "arch": tcfg.get("arch", "unknown"),
        "build_tuple": tcfg.get("build_tuple", ""),
        **counts,
        "peripheral_xrefs": periph_count,
        "peripheral_groups": periph_groups,
    }


def collect_functions(con) -> list[dict]:
    # Check if functions_enriched exists
    tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
    if "functions_enriched" in tables:
        return q(con, """
            SELECT
                f.addr, f.name, f.size, f.basic_block_count,
                f.body_hash, f.is_thunk, f.num_params,
                fe.inferred_name, fe.confidence, fe.inferred_library
            FROM functions f
            LEFT JOIN functions_enriched fe ON f.addr = fe.addr
            ORDER BY f.size DESC
        """)
    return q(con, """
        SELECT
            addr, name, size, basic_block_count,
            body_hash, is_thunk, num_params,
            NULL AS inferred_name, NULL AS confidence, NULL AS inferred_library
        FROM functions
        ORDER BY size DESC
    """)


def collect_peripheral_map(con) -> list[dict]:
    try:
        return q(con, """
            SELECT
                p.peripheral_group,
                p.peripheral,
                f.name AS function_name,
                printf('0x%08X', p.function_addr) AS addr,
                f.size,
                LIST(DISTINCT p.register_name ORDER BY p.register_name)
                    FILTER (WHERE p.register_name != '') AS registers,
                SUM(CASE WHEN p.ref_type IN ('READ','DATA') THEN 1 ELSE 0 END) AS reads,
                SUM(CASE WHEN p.ref_type = 'WRITE' THEN 1 ELSE 0 END) AS writes,
                COUNT(*) AS accesses
            FROM peripheral_xrefs p
            JOIN functions f ON p.function_addr = f.addr
            GROUP BY p.peripheral_group, p.peripheral, f.name, p.function_addr, f.size
            ORDER BY p.peripheral_group, p.peripheral, accesses DESC
        """)
    except Exception:
        return []


def collect_call_tree(con) -> list[dict]:
    """Get top-level entry points and their immediate callees."""
    try:
        return q(con, """
            WITH entry_points AS (
                SELECT DISTINCT callee_addr AS addr
                FROM recovered_calls
                WHERE mechanism = 'vector_table'
                UNION
                SELECT addr FROM functions WHERE name = 'main'
            )
            SELECT
                ep.addr AS entry_addr,
                f.name AS entry_name,
                f.size AS entry_size,
                c.callee_addr,
                f2.name AS callee_name,
                f2.size AS callee_size
            FROM entry_points ep
            JOIN functions f ON ep.addr = f.addr
            LEFT JOIN calls c ON c.caller_addr = ep.addr
            LEFT JOIN functions f2 ON c.callee_addr = f2.addr
            ORDER BY f.name, f2.name
        """)
    except Exception:
        return []


def collect_strings(con) -> list[dict]:
    try:
        return q(con, "SELECT addr, value, length FROM strings ORDER BY addr")
    except Exception:
        return []


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

CSS = """
:root { --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff; --border: #30363d;
        --card: #161b22; --green: #3fb950; --yellow: #d29922; --red: #f85149;
        --subtle: #8b949e; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
       font-size: 14px; line-height: 1.5; padding: 20px; max-width: 1400px; margin: 0 auto; }
h1 { color: var(--accent); font-size: 24px; margin-bottom: 4px; }
h2 { color: var(--fg); font-size: 18px; margin: 32px 0 12px 0; padding-bottom: 8px;
     border-bottom: 1px solid var(--border); }
h3 { color: var(--subtle); font-size: 14px; margin: 16px 0 8px 0; }
.subtitle { color: var(--subtle); font-size: 14px; margin-bottom: 24px; }
.stats { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 6px;
        padding: 12px 20px; min-width: 120px; }
.stat-value { font-size: 24px; font-weight: 600; color: var(--accent); }
.stat-label { font-size: 12px; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.5px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13px; }
th { background: var(--card); color: var(--subtle); text-align: left; padding: 8px 12px;
     border-bottom: 2px solid var(--border); cursor: pointer; user-select: none;
     position: sticky; top: 0; z-index: 1; }
th:hover { color: var(--accent); }
td { padding: 6px 12px; border-bottom: 1px solid var(--border); }
tr:hover td { background: var(--card); }
.mono { font-family: 'SF Mono', 'Fira Code', Consolas, monospace; font-size: 12px; }
.addr { color: var(--subtle); }
.name { color: var(--accent); }
.inferred { color: var(--green); }
.conf-high { color: var(--green); }
.conf-med { color: var(--yellow); }
.conf-low { color: var(--red); }
.thunk { opacity: 0.5; }
.group-header { background: var(--card); font-weight: 600; }
.group-header td { padding: 10px 12px; color: var(--accent); border-bottom: 2px solid var(--border); }
.periph-tag { display: inline-block; background: var(--card); border: 1px solid var(--border);
              border-radius: 4px; padding: 1px 8px; margin: 1px; font-size: 11px; }
.string-val { color: var(--yellow); max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge { display: inline-block; border-radius: 10px; padding: 1px 8px; font-size: 11px; font-weight: 600; }
.badge-comm { background: #1f3a5f; color: #58a6ff; }
.badge-gpio { background: #1f3f1f; color: #3fb950; }
.badge-timer { background: #3f2f1f; color: #d29922; }
.badge-analog { background: #3f1f2f; color: #f778ba; }
.badge-clock { background: #2f1f3f; color: #bc8cff; }
.badge-dma { background: #1f3f3f; color: #56d4dd; }
.badge-system { background: #2f2f2f; color: #8b949e; }
.badge-other { background: #1f1f1f; color: #6e7681; }
.search { background: var(--card); border: 1px solid var(--border); color: var(--fg);
          padding: 8px 12px; border-radius: 6px; width: 300px; margin-bottom: 12px; font-size: 14px; }
.search:focus { outline: none; border-color: var(--accent); }
.tab-bar { display: flex; gap: 0; margin: 24px 0 0 0; border-bottom: 2px solid var(--border); }
.tab { padding: 8px 20px; cursor: pointer; color: var(--subtle); border-bottom: 2px solid transparent;
       margin-bottom: -2px; transition: all 0.15s; }
.tab:hover { color: var(--fg); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
.tree-node { margin-left: 20px; }
.tree-toggle { cursor: pointer; color: var(--subtle); user-select: none; }
.tree-toggle:hover { color: var(--accent); }
.hidden { display: none; }
footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border);
         color: var(--subtle); font-size: 12px; }
"""

JS = """
function sortTable(tableId, colIdx) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const header = table.querySelectorAll('th')[colIdx];
    const asc = header.dataset.sort !== 'asc';
    header.dataset.sort = asc ? 'asc' : 'desc';
    rows.sort((a, b) => {
        let va = a.cells[colIdx].dataset.val || a.cells[colIdx].textContent;
        let vb = b.cells[colIdx].dataset.val || b.cells[colIdx].textContent;
        const na = parseFloat(va), nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
        return asc ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    rows.forEach(r => tbody.appendChild(r));
}
function filterTable(inputId, tableId) {
    const q = document.getElementById(inputId).value.toLowerCase();
    const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
    rows.forEach(r => { r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
}
function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelector('[data-tab="' + tabId + '"]').classList.add('active');
    document.getElementById(tabId).classList.add('active');
}
"""


def badge_class(group: str) -> str:
    mapping = {
        "communication": "comm", "gpio": "gpio", "timer": "timer",
        "analog": "analog", "clock": "clock", "dma": "dma",
        "system": "system",
    }
    return "badge-" + mapping.get(group, "other")


def conf_class(conf) -> str:
    if conf is None:
        return ""
    if conf >= 0.90:
        return "conf-high"
    if conf >= 0.70:
        return "conf-med"
    return "conf-low"


def render_summary(s: dict) -> str:
    return f"""
    <h1>ripcord report: {esc(s['target'])}</h1>
    <div class="subtitle">{esc(s['description'])} &mdash; {esc(s['arch'])} / {esc(s['build_tuple'])}</div>
    <div class="stats">
        <div class="stat"><div class="stat-value">{s['functions']}</div><div class="stat-label">Functions</div></div>
        <div class="stat"><div class="stat-value">{s['calls']}</div><div class="stat-label">Call Edges</div></div>
        <div class="stat"><div class="stat-value">{s['basic_blocks']}</div><div class="stat-label">Basic Blocks</div></div>
        <div class="stat"><div class="stat-value">{s['xrefs']}</div><div class="stat-label">Cross-refs</div></div>
        <div class="stat"><div class="stat-value">{s['strings']}</div><div class="stat-label">Strings</div></div>
        <div class="stat"><div class="stat-value">{s['peripheral_xrefs']}</div><div class="stat-label">Peripheral Accesses</div></div>
        <div class="stat"><div class="stat-value">{s['peripheral_groups']}</div><div class="stat-label">HW Groups</div></div>
    </div>
    """


def render_functions_table(functions: list[dict]) -> str:
    rows = []
    for f in functions:
        addr = f["addr"]
        name = f["name"] or ""
        inferred = f.get("inferred_name") or ""
        conf = f.get("confidence")
        size = f.get("size") or 0
        bbs = f.get("basic_block_count") or 0
        is_thunk = f.get("is_thunk", False)
        tr_class = ' class="thunk"' if is_thunk else ""
        display_name = inferred if inferred else name
        name_class = "inferred" if inferred else "name"
        conf_str = f'<span class="{conf_class(conf)}">{conf:.2f}</span>' if conf is not None else '<span class="addr">—</span>'
        match_src = esc(f.get("inferred_library") or "")

        rows.append(f"""<tr{tr_class}>
            <td class="mono addr" data-val="{addr}">0x{addr:08X}</td>
            <td class="{name_class}">{esc(display_name)}</td>
            <td class="mono addr">{esc(name) if inferred and name != display_name else ""}</td>
            <td data-val="{size}">{size}</td>
            <td data-val="{bbs}">{bbs}</td>
            <td>{conf_str}</td>
            <td class="addr">{match_src}</td>
        </tr>""")

    return f"""
    <input class="search" id="fn-search" placeholder="Filter functions..." oninput="filterTable('fn-search','fn-table')">
    <table id="fn-table">
    <thead><tr>
        <th onclick="sortTable('fn-table',0)">Address</th>
        <th onclick="sortTable('fn-table',1)">Name</th>
        <th onclick="sortTable('fn-table',2)">Original</th>
        <th onclick="sortTable('fn-table',3)">Size</th>
        <th onclick="sortTable('fn-table',4)">Blocks</th>
        <th onclick="sortTable('fn-table',5)">Confidence</th>
        <th onclick="sortTable('fn-table',6)">Library</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
    </table>
    """


def render_peripheral_map(periph_data: list[dict]) -> str:
    if not periph_data:
        return "<p>No peripheral data available (no SVD configured for this target).</p>"

    # Group by peripheral_group then peripheral
    groups: dict[str, dict[str, list]] = {}
    for row in periph_data:
        g = row["peripheral_group"]
        p = row["peripheral"]
        groups.setdefault(g, {}).setdefault(p, []).append(row)

    html_parts = []
    for group_name in sorted(groups.keys()):
        peripherals = groups[group_name]
        bc = badge_class(group_name)
        html_parts.append(f'<h3><span class="badge {bc}">{esc(group_name)}</span></h3>')
        html_parts.append('<table><thead><tr>')
        html_parts.append('<th>Peripheral</th><th>Function</th><th>Address</th><th>Size</th>')
        html_parts.append('<th>Registers</th><th>R</th><th>W</th><th>Total</th>')
        html_parts.append('</tr></thead><tbody>')

        for periph_name in sorted(peripherals.keys()):
            funcs = peripherals[periph_name]
            for i, row in enumerate(funcs):
                pname = esc(periph_name) if i == 0 else ""
                regs = row.get("registers") or []
                reg_tags = " ".join(f'<span class="periph-tag">{esc(r)}</span>' for r in regs[:8])
                if len(regs) > 8:
                    reg_tags += f' <span class="addr">+{len(regs)-8} more</span>'
                html_parts.append(f"""<tr>
                    <td class="mono">{pname}</td>
                    <td class="name">{esc(row['function_name'])}</td>
                    <td class="mono addr">{esc(row['addr'])}</td>
                    <td>{row['size']}</td>
                    <td>{reg_tags}</td>
                    <td>{row['reads']}</td>
                    <td>{row['writes']}</td>
                    <td>{row['accesses']}</td>
                </tr>""")

        html_parts.append('</tbody></table>')

    return "\n".join(html_parts)


def render_strings(strings: list[dict]) -> str:
    if not strings:
        return "<p>No strings found.</p>"
    rows = []
    for s in strings:
        rows.append(f"""<tr>
            <td class="mono addr">0x{s['addr']:08X}</td>
            <td class="string-val">{esc(s['value'])}</td>
            <td>{s['length']}</td>
        </tr>""")
    return f"""
    <input class="search" id="str-search" placeholder="Filter strings..." oninput="filterTable('str-search','str-table')">
    <table id="str-table">
    <thead><tr><th>Address</th><th>Value</th><th>Length</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
    </table>"""


def render_call_tree(tree_data: list[dict]) -> str:
    if not tree_data:
        return "<p>No entry point data available.</p>"

    # Group by entry point
    entries: dict[int, dict] = {}
    for row in tree_data:
        ea = row["entry_addr"]
        if ea not in entries:
            entries[ea] = {
                "name": row["entry_name"],
                "size": row["entry_size"],
                "callees": [],
            }
        if row.get("callee_addr"):
            entries[ea]["callees"].append({
                "addr": row["callee_addr"],
                "name": row["callee_name"],
                "size": row["callee_size"],
            })

    parts = []
    for addr in sorted(entries.keys()):
        e = entries[addr]
        n_callees = len(e["callees"])
        parts.append(f'<div style="margin-bottom: 12px;">')
        parts.append(f'<span class="name mono">0x{addr:08X}</span> '
                     f'<strong>{esc(e["name"])}</strong> '
                     f'<span class="addr">({e["size"]} bytes, {n_callees} callees)</span>')
        if e["callees"]:
            parts.append('<div class="tree-node">')
            for c in sorted(e["callees"], key=lambda x: x.get("name") or ""):
                cname = c.get("name") or f"FUN_{c['addr']:08X}"
                parts.append(f'<div class="mono"><span class="addr">0x{c["addr"]:08X}</span> '
                             f'<span class="name">{esc(cname)}</span> '
                             f'<span class="addr">({c.get("size", "?")} bytes)</span></div>')
            parts.append('</div>')
        parts.append('</div>')

    return "\n".join(parts)


def render_html(target: str, config: dict, con) -> str:
    summary = collect_summary(con, target, config)
    functions = collect_functions(con)
    periph = collect_peripheral_map(con)
    strings = collect_strings(con)
    tree = collect_call_tree(con)

    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ripcord: {esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
{render_summary(summary)}

<div class="tab-bar">
    <div class="tab active" data-tab="tab-functions" onclick="switchTab('tab-functions')">Functions ({len(functions)})</div>
    <div class="tab" data-tab="tab-peripherals" onclick="switchTab('tab-peripherals')">Peripherals</div>
    <div class="tab" data-tab="tab-strings" onclick="switchTab('tab-strings')">Strings ({len(strings)})</div>
    <div class="tab" data-tab="tab-entries" onclick="switchTab('tab-entries')">Entry Points</div>
</div>

<div id="tab-functions" class="tab-panel active">
<h2>Functions</h2>
{render_functions_table(functions)}
</div>

<div id="tab-peripherals" class="tab-panel">
<h2>Peripheral Access Map</h2>
{render_peripheral_map(periph)}
</div>

<div id="tab-strings" class="tab-panel">
<h2>Strings</h2>
{render_strings(strings)}
</div>

<div id="tab-entries" class="tab-panel">
<h2>Entry Points &amp; Call Tree</h2>
{render_call_tree(tree)}
</div>

<footer>
    Generated by <strong>ripcord</strong> on {generated} &mdash;
    <a href="https://github.com/DavidClawson/ripcord" style="color: var(--accent);">github.com/DavidClawson/ripcord</a>
</footer>

<script>{JS}</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Render ripcord HTML report")
    parser.add_argument("target", help="Target name from config.yaml")
    parser.add_argument("--output", help="Output HTML path (default: build/<target>/report.html)")
    parser.add_argument("--reference", help="Reference target for match results (not yet implemented)")
    args = parser.parse_args()

    config = load_config()
    if args.target not in config.get("targets", {}):
        print(f"ERROR: target '{args.target}' not in config.yaml", file=sys.stderr)
        sys.exit(1)

    con = connect_target(args.target)
    html_content = render_html(args.target, config, con)
    con.close()

    output = Path(args.output) if args.output else BUILD_DIR / args.target / "report.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_content)
    print(f"report: wrote {output} ({len(html_content):,} bytes)")


if __name__ == "__main__":
    main()
