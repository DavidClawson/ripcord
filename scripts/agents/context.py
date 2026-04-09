"""Context assembly for agent tasks: propose_name and trace_data_source.

Pulls relevant facts from the ripcord Parquet warehouse via DuckDB and
assembles them into a structured dict, then formats a prompt string for
the LLM agent.

Usage:
    from scripts.agents.context import (
        register_warehouse,
        assemble_propose_name_context,
        format_propose_name_prompt,
        assemble_trace_data_source_context,
        format_trace_data_source_prompt,
    )

    conn = duckdb.connect(':memory:')
    register_warehouse(conn, 'build')
    ctx = assemble_propose_name_context(conn, 'pico_freertos_hello_stripped', 0x10006bac)
    prompt = format_propose_name_prompt(ctx)
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import duckdb

# Ensure sibling modules are importable
_AGENTS_DIR = str(Path(__file__).resolve().parent)
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)

from register_map import decode_register, annotate_decompiled_c, REGISTER_NAMES
from peripheral_affinity import compute_transitive_affinity, format_affinity_context
from data_flow import compute_shared_globals, get_data_flow_context, format_data_flow_context
from known_constants import scan_decompiled_c, format_constants_context


# ---------------------------------------------------------------------------
# Warehouse registration
# ---------------------------------------------------------------------------

# Tables we need for context assembly (propose_name + trace_data_source).
_WAREHOUSE_TABLES = [
    "functions",
    "functions_enriched",
    "calls",
    "basic_blocks",
    "xrefs",
    "strings",
    "pcode_features",
    "decompiled",
    "peripheral_xrefs",
    "recovered_calls",
    "unicorn_smoke",
]


def register_warehouse(
    conn: duckdb.DuckDBPyConnection,
    build_dir: str,
    targets: list[str] | None = None,
) -> None:
    """Register Parquet files as DuckDB views, one view per table.

    If targets is None, discovers all target directories under build_dir.
    Each view unions all matching Parquet files across targets (same
    pattern as scripts/query).
    """
    build_path = Path(build_dir)
    if targets is None:
        targets = sorted(
            d.name
            for d in build_path.iterdir()
            if d.is_dir() and (d / "tables").is_dir()
        )

    for table in _WAREHOUSE_TABLES:
        paths = []
        for t in targets:
            p = build_path / t / "tables" / f"{table}.parquet"
            if p.exists():
                paths.append(str(p))
        if paths:
            path_list = ", ".join(f"'{p}'" for p in paths)
            conn.execute(
                f"CREATE OR REPLACE VIEW {table} AS "
                f"SELECT * FROM read_parquet([{path_list}], union_by_name=true)"
            )


# ---------------------------------------------------------------------------
# Context assembly: propose_name
# ---------------------------------------------------------------------------


def _get_module_info(
    conn_sqlite: sqlite3.Connection | None,
    target: str,
    function_addr: int,
) -> dict | None:
    """Get module membership for a function from the coordination DB."""
    if conn_sqlite is None:
        return None
    try:
        row = conn_sqlite.execute(
            """
            SELECT m.module_name, m.description, m.function_count, m.seed_peripheral
            FROM function_modules fm
            JOIN modules m ON m.id = fm.module_id
            WHERE fm.target = ? AND fm.function_addr = ?
            """,
            (target, function_addr),
        ).fetchone()
        if row:
            return {
                "module_name": row[0],
                "description": row[1],
                "function_count": row[2],
                "seed_peripheral": row[3],
            }
    except Exception:
        pass
    return None


def _batch_module_lookup(
    conn_sqlite: sqlite3.Connection | None,
    target: str,
    addrs: list[int],
) -> dict[int, str | None]:
    """Batch-query module names for a list of function addresses.

    Returns a dict mapping address -> module_name (or None).
    """
    result: dict[int, str | None] = {a: None for a in addrs}
    if conn_sqlite is None or not addrs:
        return result
    try:
        placeholders = ",".join("?" for _ in addrs)
        rows = conn_sqlite.execute(
            f"""
            SELECT fm.function_addr, m.module_name
            FROM function_modules fm
            JOIN modules m ON m.id = fm.module_id
            WHERE fm.target = ? AND fm.function_addr IN ({placeholders})
            """,
            [target] + addrs,
        ).fetchall()
        for addr, module_name in rows:
            result[addr] = module_name
    except Exception:
        pass
    return result


def _get_neighbor_rationales(
    conn_sqlite: sqlite3.Connection | None,
    target: str,
    addrs: list[int],
) -> dict[int, str]:
    """Get the best evidence rationale for each neighbor address.

    Returns: {addr: "one-line rationale"} for neighbors that have evidence.
    """
    if conn_sqlite is None or not addrs:
        return {}
    try:
        placeholders = ",".join("?" for _ in addrs)
        rows = conn_sqlite.execute(
            f"""
            SELECT entity_addr,
                   json_extract(claim_json, '$.rationale') AS rationale,
                   confidence
            FROM evidence_log
            WHERE target = ? AND claim_type = 'name'
                  AND entity_addr IN ({placeholders})
                  AND confidence >= 0.50
            ORDER BY confidence DESC
            """,
            [target] + addrs,
        ).fetchall()
        result: dict[int, str] = {}
        for addr, rationale, conf in rows:
            if addr not in result and rationale:
                # Truncate and clean
                r = rationale.strip().strip('"')
                if len(r) > 100:
                    r = r[:97] + "..."
                result[addr] = r
        return result
    except Exception:
        return {}


def assemble_propose_name_context(
    conn: duckdb.DuckDBPyConnection,
    target: str,
    function_addr: int,
    domain_hint: str | None = None,
    conn_sqlite: sqlite3.Connection | None = None,
    peripheral_affinities: dict[int, dict[str, float]] | None = None,
    shared_globals: dict[int, dict] | None = None,
) -> dict:
    """Query the warehouse and return everything the LLM needs to name a function.

    Returns a dict with keys: function, callees, callers, strings,
    structural_matches, neighbor_context, pcode.
    """
    ctx: dict = {}

    # --- (a) Function's own features ---
    row = conn.execute(
        """
        SELECT f.addr, f.name, f.size, f.basic_block_count,
               f.signature, f.body_hash, f.calling_convention
        FROM functions f
        WHERE f.source = $1 AND f.addr = $2
        """,
        [target, function_addr],
    ).fetchone()
    if row is None:
        return {"error": f"function {function_addr:#x} not found in {target}"}

    fn = {
        "addr": f"0x{row[0]:08x}",
        "current_name": row[1] or f"FUN_{row[0]:08x}",
        "size": row[2],
        "basic_block_count": row[3],
        "signature": row[4],
        "body_hash": row[5],
        "calling_convention": row[6],
    }

    # Instruction count from basic_blocks
    ic_row = conn.execute(
        """
        SELECT COALESCE(SUM(instruction_count), 0)
        FROM basic_blocks
        WHERE source = $1 AND function_addr = $2
        """,
        [target, function_addr],
    ).fetchone()
    fn["instruction_count"] = ic_row[0] if ic_row else 0

    # P-Code features
    pcode_row = conn.execute(
        """
        SELECT pcode_ops_total, pcode_unique_opcodes, pcode_histogram
        FROM pcode_features
        WHERE source = $1 AND addr = $2
        """,
        [target, function_addr],
    ).fetchone()
    if pcode_row:
        fn["pcode_ops_total"] = pcode_row[0]
        fn["pcode_unique_opcodes"] = pcode_row[1]
        histogram = pcode_row[2]
        if histogram:
            try:
                hist_dict = json.loads(histogram)
                # Top opcodes by count (up to 8)
                sorted_ops = sorted(hist_dict.items(), key=lambda x: -x[1])
                fn["pcode_top_opcodes"] = dict(sorted_ops[:8])
            except (json.JSONDecodeError, TypeError):
                fn["pcode_top_opcodes"] = {}
        else:
            fn["pcode_top_opcodes"] = {}

    # Structural feature vector (from aggregated tables)
    fv_row = conn.execute(
        """
        WITH call_agg AS (
            SELECT COUNT(*) AS out_calls,
                   COUNT(DISTINCT callee_addr) AS distinct_callees
            FROM calls
            WHERE source = $1 AND caller_addr = $2
        ),
        xref_agg AS (
            SELECT
                SUM(CASE WHEN ref_type = 'READ' THEN 1 ELSE 0 END) AS reads,
                SUM(CASE WHEN ref_type = 'WRITE' THEN 1 ELSE 0 END) AS writes,
                SUM(CASE WHEN ref_type IN ('CONDITIONAL_JUMP','UNCONDITIONAL_JUMP')
                         THEN 1 ELSE 0 END) AS jumps
            FROM xrefs
            WHERE source = $1 AND function_addr = $2
        )
        SELECT ca.out_calls, ca.distinct_callees,
               xa.reads, xa.writes, xa.jumps
        FROM call_agg ca, xref_agg xa
        """,
        [target, function_addr],
    ).fetchone()
    if fv_row:
        fn["out_calls"] = fv_row[0] or 0
        fn["distinct_callees"] = fv_row[1] or 0
        fn["reads"] = fv_row[2] or 0
        fn["writes"] = fv_row[3] or 0
        fn["jumps"] = fv_row[4] or 0

    ctx["function"] = fn

    # --- (b) Call graph neighborhood ---

    # Callees: functions this one calls
    callee_rows = conn.execute(
        """
        SELECT DISTINCT f.addr, f.name,
               fe.inferred_name, fe.confidence
        FROM calls c
        JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
        LEFT JOIN functions_enriched fe ON fe.source = c.source AND fe.addr = c.callee_addr
        WHERE c.source = $1 AND c.caller_addr = $2
              AND c.callee_addr IS NOT NULL
        ORDER BY f.addr
        """,
        [target, function_addr],
    ).fetchall()
    ctx["callees"] = [
        {
            "addr": f"0x{r[0]:08x}",
            "name": r[1] or f"FUN_{r[0]:08x}",
            "inferred_name": r[2],
            "confidence": r[3],
        }
        for r in callee_rows
    ]

    # Callers: functions that call this one
    caller_rows = conn.execute(
        """
        SELECT DISTINCT f.addr, f.name,
               fe.inferred_name, fe.confidence
        FROM calls c
        JOIN functions f ON f.source = c.source AND f.addr = c.caller_addr
        LEFT JOIN functions_enriched fe ON fe.source = c.source AND fe.addr = c.caller_addr
        WHERE c.source = $1 AND c.callee_addr = $2
              AND c.caller_addr IS NOT NULL
        ORDER BY f.addr
        """,
        [target, function_addr],
    ).fetchall()
    ctx["callers"] = [
        {
            "addr": f"0x{r[0]:08x}",
            "name": r[1] or f"FUN_{r[0]:08x}",
            "inferred_name": r[2],
            "confidence": r[3],
        }
        for r in caller_rows
    ]

    # Add module membership to callers and callees (batch query)
    all_neighbor_addrs = (
        [r[0] for r in callee_rows] + [r[0] for r in caller_rows]
    )
    mod_map = _batch_module_lookup(conn_sqlite, target, all_neighbor_addrs)
    for entry in ctx["callees"]:
        entry["module"] = mod_map.get(int(entry["addr"], 16))
    for entry in ctx["callers"]:
        entry["module"] = mod_map.get(int(entry["addr"], 16))

    # --- (c) Referenced strings ---
    string_rows = conn.execute(
        """
        SELECT DISTINCT s.value
        FROM xrefs x
        JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
        WHERE x.source = $1 AND x.function_addr = $2
        LIMIT 20
        """,
        [target, function_addr],
    ).fetchall()
    ctx["strings"] = [r[0] for r in string_rows if r[0]]

    # --- (d) Structural matches from other targets ---
    match_rows = conn.execute(
        """
        SELECT fe.inferred_name, fe.confidence, fe.evidence_method
        FROM functions_enriched fe
        WHERE fe.source = $1 AND fe.addr = $2
              AND fe.inferred_name IS NOT NULL
        """,
        [target, function_addr],
    ).fetchall()
    ctx["structural_matches"] = [
        {
            "inferred_name": r[0],
            "confidence": r[1],
            "evidence_method": r[2],
        }
        for r in match_rows
    ]

    # Also check body_hash matches against other targets directly
    if fn.get("body_hash"):
        hash_match_rows = conn.execute(
            """
            SELECT f.source AS ref_target, f.name, f.body_hash
            FROM functions f
            WHERE f.body_hash = $1
              AND f.source != $2
              AND f.name NOT LIKE 'FUN_%'
            LIMIT 5
            """,
            [fn["body_hash"], target],
        ).fetchall()
        for r in hash_match_rows:
            ctx["structural_matches"].append(
                {
                    "ref_target": r[0],
                    "inferred_name": r[1],
                    "confidence": 1.0,
                    "evidence_method": "body_hash_exact_cross_target",
                }
            )

    # --- (e) Neighbor context (2-hop summary) ---
    ctx["neighbor_context"] = _build_neighbor_context(conn, target, function_addr, ctx)

    # --- (f) Peripheral register accesses ---
    periph_rows = conn.execute(
        """
        SELECT register_name, peripheral, ref_type, peripheral_group
        FROM peripheral_xrefs
        WHERE source = $1 AND function_addr = $2
        ORDER BY peripheral, register_name
        """,
        [target, function_addr],
    ).fetchall()
    ctx["peripheral_accesses"] = [
        {
            "register": r[0],
            "peripheral": r[1],
            "ref_type": r[2],
            "group": r[3],
        }
        for r in periph_rows
    ]

    # --- (g) Transitive peripheral affinity ---
    # Caller can pre-compute and pass in via peripheral_affinities kwarg
    # to avoid recomputing the full graph per function.
    ctx["peripheral_affinity"] = peripheral_affinities.get(function_addr, {}) if peripheral_affinities else {}

    # --- (h) Cross-function data flow via shared globals ---
    if shared_globals:
        ctx["data_flow"] = get_data_flow_context(shared_globals, function_addr)
    else:
        ctx["data_flow"] = {"writes_to": [], "reads_from": []}

    # --- (i) Decompiled pseudo-C ---
    ctx["decompiled_c"] = _get_decompiled_c(conn, target, function_addr)

    # --- (j) Known constants in decompiled C ---
    if ctx["decompiled_c"]:
        ctx["known_constants"] = scan_decompiled_c(ctx["decompiled_c"])
    else:
        ctx["known_constants"] = []

    # --- (k) Evidence rationale from prior rounds ---
    ctx["caller_rationales"] = _get_neighbor_rationales(
        conn_sqlite, target,
        [int(c["addr"], 16) for c in ctx.get("callers", [])]
        + [int(c["addr"], 16) for c in ctx.get("callees", [])],
    )

    # --- (l) Domain hint ---
    ctx["domain_hint"] = domain_hint

    # --- (m) Module membership ---
    ctx["module_info"] = _get_module_info(conn_sqlite, target, function_addr)

    return ctx


def _best_name(entry: dict) -> str:
    """Return the best available name for a caller/callee entry."""
    if entry.get("inferred_name"):
        return entry["inferred_name"]
    name = entry.get("name", "")
    if name and not name.startswith("FUN_"):
        return name
    return entry.get("addr", "unknown")


def _build_neighbor_context(
    conn: duckdb.DuckDBPyConnection,
    target: str,
    function_addr: int,
    ctx: dict,
) -> str:
    """Build a 2-hop text summary from call graph data."""
    parts = []

    # Callers' other callees (what else do our callers call?)
    caller_addrs = [int(c["addr"], 16) for c in ctx.get("callers", [])]
    if caller_addrs:
        for caller in ctx["callers"][:3]:  # limit to 3 callers
            caller_addr = int(caller["addr"], 16)
            sibling_rows = conn.execute(
                """
                SELECT DISTINCT f.name, fe.inferred_name
                FROM calls c
                JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
                LEFT JOIN functions_enriched fe ON fe.source = c.source AND fe.addr = c.callee_addr
                WHERE c.source = $1 AND c.caller_addr = $2
                      AND c.callee_addr != $3
                      AND c.callee_addr IS NOT NULL
                LIMIT 8
                """,
                [target, caller_addr, function_addr],
            ).fetchall()
            if sibling_rows:
                caller_name = _best_name(caller)
                siblings = []
                for r in sibling_rows:
                    n = r[1] if r[1] else (r[0] if r[0] and not r[0].startswith("FUN_") else None)
                    if n:
                        siblings.append(n)
                if siblings:
                    parts.append(
                        f"{caller_name} also calls: {', '.join(siblings)}"
                    )

    # Callees' other callers (who else calls our callees?)
    for callee in ctx.get("callees", [])[:3]:
        callee_addr = int(callee["addr"], 16)
        other_caller_rows = conn.execute(
            """
            SELECT DISTINCT f.name, fe.inferred_name
            FROM calls c
            JOIN functions f ON f.source = c.source AND f.addr = c.caller_addr
            LEFT JOIN functions_enriched fe ON fe.source = c.source AND fe.addr = c.caller_addr
            WHERE c.source = $1 AND c.callee_addr = $2
                  AND c.caller_addr != $3
                  AND c.caller_addr IS NOT NULL
            LIMIT 8
            """,
            [target, callee_addr, function_addr],
        ).fetchall()
        if other_caller_rows:
            callee_name = _best_name(callee)
            others = []
            for r in other_caller_rows:
                n = r[1] if r[1] else (r[0] if r[0] and not r[0].startswith("FUN_") else None)
                if n:
                    others.append(n)
            if others:
                parts.append(
                    f"{callee_name} is also called by: {', '.join(others)}"
                )

    return "; ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Provenance discipline (injected into all agent prompts)
# ---------------------------------------------------------------------------

PROVENANCE_INSTRUCTIONS = """
## Evidence Discipline

For EVERY claim you make, tag it with exactly one provenance level:

- [hardware-confirmed] — verified on physical hardware (bench probing, logic analyzer)
- [direct-xref] — observed directly in the warehouse xref/call/string table
- [decompile-derived] — read from Ghidra decompiled pseudo-C
- [synthesized-model] — combined from multiple evidence sources
- [hypothesis] — plausible inference, not directly observed

Rules:
- Never present a [synthesized-model] as [direct-xref]
- Never present a [hypothesis] as [decompile-derived]
- Pin roles, task names, and protocol claims from xrefs alone are [hypothesis] until hardware-confirmed
- Structural matches and body hashes are [direct-xref]
- When multiple signals agree, state the strongest individual evidence level, not a composite
- If you trace a value through multiple layers (state structure → queue → UART), mark each layer's evidence level separately

In your JSON response, add a "provenance" field:
{"proposed_name": "...", "confidence": 0.0-1.0, "provenance": "direct-xref", "reasoning": "..."}
"""

# Valid provenance tags for validation/mapping to evidence_method column.
VALID_PROVENANCE_TAGS = {
    "hardware-confirmed": "hardware_confirmed",
    "direct-xref": "direct_xref",
    "decompile-derived": "decompile_derived",
    "synthesized-model": "synthesized_model",
    "hypothesis": "hypothesis",
}


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def format_propose_name_prompt(ctx: dict) -> str:
    """Format the context dict into an LLM prompt string for propose_name."""
    if "error" in ctx:
        return f"Error: {ctx['error']}"

    fn = ctx["function"]
    sections = []

    # System framing
    sections.append(
        "You are a firmware reverse engineer analyzing a stripped ARM Cortex-M binary. "
        "Your task is to propose a human-readable function name based on the evidence below."
    )

    # Provenance discipline
    sections.append(PROVENANCE_INSTRUCTIONS.strip())

    # Domain hint (early — frames all subsequent interpretation)
    if ctx.get("domain_hint"):
        sections.append(
            f"## Domain context\n"
            f"This binary is from: {ctx['domain_hint']}\n"
            f"Use domain-appropriate naming when the evidence supports it."
        )

    # Module membership
    if ctx.get("module_info"):
        mi = ctx["module_info"]
        lines = ["## Module membership"]
        lines.append(f"This function belongs to: **{mi['module_name']}**")
        if mi.get("description"):
            lines.append(f"Module description: {mi['description']}")
        lines.append(f"Module size: {mi['function_count']} functions")
        if mi.get("seed_peripheral"):
            lines.append(f"Seed peripheral: {mi['seed_peripheral']}")
        sections.append("\n".join(lines))

    # Target function
    lines = [
        "## Target function",
        f"Address: {fn['addr']}",
        f"Current name: {fn['current_name']}",
        f"Size: {fn.get('size', '?')} bytes",
        f"Basic blocks: {fn.get('basic_block_count', '?')}",
        f"Instructions: {fn.get('instruction_count', '?')}",
    ]
    if fn.get("signature"):
        lines.append(f"Signature (Ghidra): {fn['signature']}")
    if fn.get("calling_convention"):
        lines.append(f"Calling convention: {fn['calling_convention']}")
    if fn.get("body_hash"):
        lines.append(f"Body hash: {fn['body_hash']}")
    sections.append("\n".join(lines))

    # Structural features
    fv_keys = ["size", "basic_block_count", "instruction_count",
               "out_calls", "distinct_callees", "reads", "writes", "jumps"]
    fv_parts = [f"{k}={fn.get(k, 0)}" for k in fv_keys if fn.get(k) is not None]
    if fv_parts:
        sections.append("## Structural features\n" + ", ".join(fv_parts))

    # P-Code histogram
    if fn.get("pcode_ops_total"):
        pcode_lines = [
            "## P-Code features",
            f"Total ops: {fn['pcode_ops_total']}, Unique opcodes: {fn.get('pcode_unique_opcodes', '?')}",
        ]
        if fn.get("pcode_top_opcodes"):
            top = ", ".join(f"{k}: {v}" for k, v in fn["pcode_top_opcodes"].items())
            pcode_lines.append(f"Top opcodes: {top}")
        sections.append("\n".join(pcode_lines))

    # Callers
    rationales = ctx.get("caller_rationales", {})
    if ctx.get("callers"):
        lines = ["## Callers (functions that call this one)"]
        for c in ctx["callers"]:
            name = _best_name(c)
            conf = f" (confidence: {c['confidence']:.2f})" if c.get("confidence") else ""
            mod = f" [{c['module']}]" if c.get("module") else ""
            addr_int = int(c["addr"], 16)
            rat = f' — "{rationales[addr_int]}"' if addr_int in rationales else ""
            lines.append(f"- {name} @ {c['addr']}{conf}{mod}{rat}")
        sections.append("\n".join(lines))

    # Callees
    if ctx.get("callees"):
        lines = ["## Callees (functions this one calls)"]
        for c in ctx["callees"]:
            name = _best_name(c)
            conf = f" (confidence: {c['confidence']:.2f})" if c.get("confidence") else ""
            mod = f" [{c['module']}]" if c.get("module") else ""
            addr_int = int(c["addr"], 16)
            rat = f' — "{rationales[addr_int]}"' if addr_int in rationales else ""
            lines.append(f"- {name} @ {c['addr']}{conf}{mod}{rat}")
        sections.append("\n".join(lines))

    # Referenced strings
    if ctx.get("strings"):
        lines = ["## Referenced strings"]
        for s in ctx["strings"]:
            lines.append(f'- "{s}"')
        sections.append("\n".join(lines))

    # Structural/fingerprint matches
    if ctx.get("structural_matches"):
        lines = ["## Fingerprint matches (from reference corpus)"]
        for m in ctx["structural_matches"]:
            ref = m.get("ref_target", "")
            ref_str = f" from {ref}" if ref else ""
            lines.append(
                f"- {m['inferred_name']}{ref_str} "
                f"(confidence: {m.get('confidence', '?')}, method: {m.get('evidence_method', '?')})"
            )
        sections.append("\n".join(lines))

    # 2-hop neighbor context
    if ctx.get("neighbor_context"):
        sections.append(f"## Neighbor context (2-hop call graph)\n{ctx['neighbor_context']}")

    # Peripheral register accesses
    if ctx.get("peripheral_accesses"):
        lines = ["## Peripheral register accesses"]
        for pa in ctx["peripheral_accesses"]:
            lines.append(f"- {pa['register']} ({pa['peripheral']}, {pa['group']}): {pa['ref_type']}")
        sections.append("\n".join(lines))

    # Transitive peripheral affinity
    if ctx.get("peripheral_affinity"):
        sections.append(f"## {format_affinity_context(ctx['peripheral_affinity'])}")

    # Cross-function data flow
    flow = ctx.get("data_flow", {})
    if flow.get("writes_to") or flow.get("reads_from"):
        sections.append(format_data_flow_context(flow))

    # Known constants
    if ctx.get("known_constants"):
        sections.append(format_constants_context(ctx["known_constants"]))

    # Decompiled pseudo-C
    if ctx.get("decompiled_c"):
        sections.append(f"## Decompiled pseudo-C\n```c\n{ctx['decompiled_c']}\n```")

    # Task instruction
    domain_note = ""
    if ctx.get("domain_hint"):
        domain_note = (
            f"\nThis binary is from a {ctx['domain_hint']}. "
            "Prefer domain-specific names when evidence supports them."
        )

    sections.append(
        "## Task\n"
        "Propose a human-readable function name for the function at "
        f"{fn['addr']}. "
        "Use standard naming conventions (snake_case for C functions). "
        "If the function appears to be from a known library (FreeRTOS, newlib, "
        "Pico SDK, Zephyr), use the canonical library name. "
        "If uncertain, describe what the function does "
        f"(e.g., 'uart_write_byte', 'init_timer_subsystem').{domain_note}\n\n"
        'Respond with JSON: {"proposed_name": "...", "confidence": 0.0-1.0, '
        '"provenance": "direct-xref|decompile-derived|synthesized-model|hypothesis", '
        '"reasoning": "..."}'
    )

    return "\n\n".join(sections)


def format_analysis_prompt(context: dict, question: str) -> str:
    """Format a prompt for general firmware analysis questions.

    Takes the same context dict as format_propose_name_prompt but allows
    an arbitrary analysis question instead of the fixed propose_name task.
    Includes provenance discipline instructions so agents tag claims
    with evidence levels.

    Args:
        context: Dict from assemble_propose_name_context (or similar).
        question: The analysis question to answer.
    """
    if "error" in context:
        return f"Error: {context['error']}"

    fn = context["function"]
    sections = []

    # System framing
    sections.append(
        "You are a firmware reverse engineer analyzing a stripped ARM Cortex-M binary. "
        "Answer the analysis question below using ONLY the evidence provided."
    )

    # Provenance discipline
    sections.append(PROVENANCE_INSTRUCTIONS.strip())

    # Target function
    lines = [
        "## Target function",
        f"Address: {fn['addr']}",
        f"Current name: {fn['current_name']}",
        f"Size: {fn.get('size', '?')} bytes",
        f"Basic blocks: {fn.get('basic_block_count', '?')}",
        f"Instructions: {fn.get('instruction_count', '?')}",
    ]
    if fn.get("signature"):
        lines.append(f"Signature (Ghidra): {fn['signature']}")
    if fn.get("body_hash"):
        lines.append(f"Body hash: {fn['body_hash']}")
    sections.append("\n".join(lines))

    # Structural features
    fv_keys = ["size", "basic_block_count", "instruction_count",
               "out_calls", "distinct_callees", "reads", "writes", "jumps"]
    fv_parts = [f"{k}={fn.get(k, 0)}" for k in fv_keys if fn.get(k) is not None]
    if fv_parts:
        sections.append("## Structural features\n" + ", ".join(fv_parts))

    # Callers
    if context.get("callers"):
        lines = ["## Callers"]
        for c in context["callers"]:
            lines.append(f"- {_best_name(c)} @ {c['addr']}")
        sections.append("\n".join(lines))

    # Callees
    if context.get("callees"):
        lines = ["## Callees"]
        for c in context["callees"]:
            lines.append(f"- {_best_name(c)} @ {c['addr']}")
        sections.append("\n".join(lines))

    # Referenced strings
    if context.get("strings"):
        lines = ["## Referenced strings"]
        for s in context["strings"]:
            lines.append(f'- "{s}"')
        sections.append("\n".join(lines))

    # Structural matches
    if context.get("structural_matches"):
        lines = ["## Fingerprint matches"]
        for m in context["structural_matches"]:
            ref = m.get("ref_target", "")
            ref_str = f" from {ref}" if ref else ""
            lines.append(
                f"- {m['inferred_name']}{ref_str} "
                f"(confidence: {m.get('confidence', '?')}, method: {m.get('evidence_method', '?')})"
            )
        sections.append("\n".join(lines))

    # Neighbor context
    if context.get("neighbor_context"):
        sections.append(f"## Neighbor context\n{context['neighbor_context']}")

    # Analysis question
    sections.append(
        f"## Analysis question\n{question}\n\n"
        "Respond with JSON:\n"
        '{"answer": "...", "provenance": "direct-xref|decompile-derived|'
        'synthesized-model|hypothesis", "confidence": 0.0-1.0, "reasoning": "..."}\n\n'
        "Tag each sub-claim in your reasoning with its provenance level."
    )

    return "\n\n".join(sections)


# Maximum decompiled C length to include in a trace prompt (chars).
_MAX_DECOMPILED_C_LEN = 10_000


def _get_decompiled_c(
    conn: duckdb.DuckDBPyConnection, target: str, addr: int
) -> str | None:
    """Fetch decompiled C for a function, truncating if too long."""
    row = conn.execute(
        """
        SELECT decompiled_c FROM decompiled
        WHERE source = $1 AND addr = $2 AND decompile_success = TRUE
        """,
        [target, addr],
    ).fetchone()
    if row is None or row[0] is None:
        return None
    c_text = row[0]
    if len(c_text) > _MAX_DECOMPILED_C_LEN:
        c_text = c_text[:_MAX_DECOMPILED_C_LEN] + f"\n\n... [truncated at {_MAX_DECOMPILED_C_LEN} chars, original {len(row[0])} chars]"
    c_text = annotate_decompiled_c(c_text)
    return c_text


# ---------------------------------------------------------------------------
# Context assembly: trace_data_source
# ---------------------------------------------------------------------------


def assemble_trace_data_source_context(
    conn: duckdb.DuckDBPyConnection,
    target: str,
    function_addr: int,
    register_addr: int,
) -> dict:
    """Query the warehouse and return everything needed to trace a register write.

    Returns a dict with keys: function, register, write_sites, callees,
    callers. The function and callee entries include decompiled C when
    available.
    """
    ctx: dict = {}

    # --- (a) Function metadata + decompiled C ---
    row = conn.execute(
        """
        SELECT f.addr, f.name, f.size, f.basic_block_count
        FROM functions f
        WHERE f.source = $1 AND f.addr = $2
        """,
        [target, function_addr],
    ).fetchone()
    if row is None:
        return {"error": f"function {function_addr:#x} not found in {target}"}

    fn_name = row[1] or f"FUN_{row[0]:08x}"
    decompiled = _get_decompiled_c(conn, target, function_addr)

    ctx["function"] = {
        "addr": f"0x{row[0]:08x}",
        "name": fn_name,
        "size": row[2],
        "basic_block_count": row[3],
        "decompiled_c": decompiled,
    }

    # --- (b) Register info ---
    reg_name = decode_register(register_addr)
    ctx["register"] = {
        "addr": f"0x{register_addr:08x}",
        "name": reg_name,
    }

    # --- (c) Write sites: xrefs FROM this function TO the register ---
    write_rows = conn.execute(
        """
        SELECT from_addr, ref_type
        FROM xrefs
        WHERE source = $1
          AND function_addr = $2
          AND to_addr = $3
        ORDER BY from_addr
        """,
        [target, function_addr, register_addr],
    ).fetchall()
    ctx["write_sites"] = [
        {"from_addr": f"0x{r[0]:08x}", "ref_type": r[1]}
        for r in write_rows
    ]

    # --- (d) Callees with decompiled C ---
    # Budget: include decompiled C for callees up to ~20KB total,
    # prioritizing callees that also reference the target register.
    callee_rows = conn.execute(
        """
        SELECT DISTINCT f.addr, f.name, f.size,
               EXISTS(
                   SELECT 1 FROM xrefs x2
                   WHERE x2.source = $1
                     AND x2.function_addr = f.addr
                     AND x2.to_addr = $3
               ) AS refs_register
        FROM calls c
        JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
        WHERE c.source = $1 AND c.caller_addr = $2
              AND c.callee_addr IS NOT NULL
        ORDER BY refs_register DESC, f.size DESC
        """,
        [target, function_addr, register_addr],
    ).fetchall()
    callees = []
    callee_c_budget = 20_000  # chars of decompiled C across all callees
    for r in callee_rows:
        callee_name = r[1] or f"FUN_{r[0]:08x}"
        callee_c = None
        if callee_c_budget > 0:
            callee_c = _get_decompiled_c(conn, target, r[0])
            if callee_c:
                callee_c_budget -= len(callee_c)
        callees.append({
            "addr": f"0x{r[0]:08x}",
            "name": callee_name,
            "size": r[2],
            "decompiled_c": callee_c,
        })
    ctx["callees"] = callees

    # --- (e) Callers ---
    caller_rows = conn.execute(
        """
        SELECT DISTINCT f.addr, f.name, f.size
        FROM calls c
        JOIN functions f ON f.source = c.source AND f.addr = c.caller_addr
        WHERE c.source = $1 AND c.callee_addr = $2
              AND c.caller_addr IS NOT NULL
        ORDER BY f.addr
        """,
        [target, function_addr],
    ).fetchall()
    ctx["callers"] = [
        {"addr": f"0x{r[0]:08x}", "name": r[1] or f"FUN_{r[0]:08x}", "size": r[2]}
        for r in caller_rows
    ]

    return ctx


# ---------------------------------------------------------------------------
# Prompt formatting: trace_data_source
# ---------------------------------------------------------------------------


def format_trace_data_source_prompt(ctx: dict) -> str:
    """Format the trace_data_source context into an LLM prompt.

    The prompt instructs the agent to trace backward from a register
    write through decompiled C, identifying each dispatch layer between
    the original data source and the peripheral register.
    """
    if "error" in ctx:
        return f"Error: {ctx['error']}"

    fn = ctx["function"]
    reg = ctx["register"]
    sections = []

    # System framing
    sections.append(
        "You are a firmware reverse engineer analyzing a stripped ARM Cortex-M "
        "binary. Your task is to trace the DATA SOURCE for a peripheral register "
        "write. You must find where the written value originates, tracing backward "
        "through the code layer by layer."
    )

    # Provenance discipline
    sections.append(PROVENANCE_INSTRUCTIONS.strip())

    # Target register
    sections.append(
        f"## Target register write\n"
        f"Register: {reg['name']} @ {reg['addr']}\n"
        f"Writing function: {fn['name']} @ {fn['addr']} ({fn['size']} bytes, "
        f"{fn['basic_block_count']} basic blocks)"
    )

    # Write sites
    if ctx["write_sites"]:
        lines = ["## Write sites (xrefs to register from this function)"]
        for ws in ctx["write_sites"]:
            lines.append(f"- Instruction at {ws['from_addr']}, type: {ws['ref_type']}")
        sections.append("\n".join(lines))

    # Decompiled C of the writing function
    if fn.get("decompiled_c"):
        sections.append(
            f"## Decompiled C: {fn['name']}\n"
            f"```c\n{fn['decompiled_c']}\n```"
        )
    else:
        sections.append(
            f"## Decompiled C: {fn['name']}\n"
            "(decompiled output not available)"
        )

    # Callees with decompiled C (these may be the actual data source)
    if ctx.get("callees"):
        lines = [f"## Callees of {fn['name']} ({len(ctx['callees'])} functions)"]
        for callee in ctx["callees"]:
            lines.append(f"\n### {callee['name']} @ {callee['addr']} ({callee['size']} bytes)")
            if callee.get("decompiled_c"):
                lines.append(f"```c\n{callee['decompiled_c']}\n```")
            else:
                lines.append("(decompiled output not available)")
        sections.append("\n".join(lines))

    # Callers (for tracing arguments passed in)
    if ctx.get("callers"):
        lines = ["## Callers (functions that call the writing function)"]
        for c in ctx["callers"]:
            lines.append(f"- {c['name']} @ {c['addr']} ({c['size']} bytes)")
        sections.append("\n".join(lines))

    # Task instruction with output format
    sections.append(
        "## Task: Trace the data source\n\n"
        f"1. Find where {reg['name']} ({reg['addr']}) is written in the decompiled C.\n"
        "2. Trace the written value backward: is it a constant? A local variable? "
        "A function argument? A global state read?\n"
        "3. If it comes from a function argument, trace the caller to find what was "
        "passed.\n"
        "4. If it comes from a global state read, identify the state structure and "
        "offset.\n"
        "5. If it comes from a queue read or buffer, identify the queue/buffer and "
        "what enqueues to it.\n"
        "6. Produce a LAYERED TRACE showing each dispatch layer between the "
        "original data source and the register write.\n\n"
        "Respond with JSON:\n"
        "```json\n"
        "{\n"
        f'  "register": "{reg["name"]}",\n'
        f'  "write_function": "{fn["name"]}",\n'
        '  "value_source": [\n'
        '    {"layer": 0, "description": "...", "provenance": "decompile-derived"},\n'
        '    {"layer": 1, "description": "...", "provenance": "decompile-derived"},\n'
        '    {"layer": 2, "description": "...", "provenance": "synthesized-model"}\n'
        '  ],\n'
        '  "final_answer": "One-sentence summary of the full data path",\n'
        '  "confidence": 0.0-1.0\n'
        "}\n"
        "```\n\n"
        "Rules:\n"
        "- Each layer must have a separate provenance tag.\n"
        "- Layer 0 is always the immediate write to the register.\n"
        "- Higher layers trace further back toward the original data source.\n"
        "- Stop when you reach a constant, a hardware read, or a source you "
        "cannot trace further.\n"
        "- Distinguish clearly between what you can see in the decompiled C "
        "(decompile-derived) and what you infer from the structure "
        "(synthesized-model)."
    )

    return "\n\n".join(sections)
