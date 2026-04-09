"""Module detection: cluster functions into subsystems and label them.

Groups functions by peripheral affinity and call-graph connectivity,
then uses an LLM to produce human-readable module names and descriptions.

The clustering is fully deterministic (no LLM). Only the final labeling
step calls Claude, one request per cluster, keeping cost low.

Usage:
    uv run python scripts/agents/detect_modules.py \
        --target pico_freertos_hello_stripped \
        --build-dir build \
        --model claude-sonnet-4-20250514 \
        --domain-hint "FreeRTOS-based embedded application" \
        --dry-run
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from uuid import uuid4

import duckdb

# Ensure scripts/agents is importable
_AGENTS_DIR = str(Path(__file__).resolve().parent)
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)

from context import register_warehouse, _get_decompiled_c
from worker import call_claude, log_agent_run


# ---------------------------------------------------------------------------
# Schema migration: modules and function_modules tables
# ---------------------------------------------------------------------------

_MODULE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS modules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT NOT NULL,
    module_name     TEXT NOT NULL,
    description     TEXT,
    seed_peripheral TEXT,
    function_count  INTEGER,
    confidence      REAL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS function_modules (
    target          TEXT NOT NULL,
    function_addr   INTEGER NOT NULL,
    module_id       INTEGER REFERENCES modules(id),
    assignment_method TEXT NOT NULL,
    PRIMARY KEY (target, function_addr)
);

CREATE INDEX IF NOT EXISTS idx_modules_target ON modules (target);
CREATE INDEX IF NOT EXISTS idx_function_modules_module ON function_modules (module_id);
"""


def _ensure_module_tables(conn: sqlite3.Connection) -> None:
    """Create modules and function_modules tables if not present."""
    conn.executescript(_MODULE_SCHEMA_SQL)
    conn.commit()


# ---------------------------------------------------------------------------
# Pass 1: Peripheral-based seed clusters
# ---------------------------------------------------------------------------

def build_peripheral_clusters(
    conn_duckdb: duckdb.DuckDBPyConnection, target: str
) -> dict[str, list[int]]:
    """Group functions by their primary peripheral.

    Returns a dict mapping peripheral name -> list of function addresses.
    Empty dict if peripheral_xrefs table doesn't exist or has no data.
    """
    try:
        rows = conn_duckdb.execute(f"""
            WITH periph_counts AS (
                SELECT function_addr, peripheral, COUNT(*) AS n
                FROM peripheral_xrefs
                WHERE source = '{target}'
                GROUP BY function_addr, peripheral
            ),
            primary_periph AS (
                SELECT function_addr, peripheral,
                       ROW_NUMBER() OVER (
                           PARTITION BY function_addr ORDER BY n DESC
                       ) AS rn
                FROM periph_counts
            )
            SELECT function_addr, peripheral
            FROM primary_periph
            WHERE rn = 1
        """).fetchall()
    except duckdb.CatalogException:
        # peripheral_xrefs table doesn't exist for this target
        return {}

    clusters: dict[str, list[int]] = {}
    for addr, periph in rows:
        clusters.setdefault(periph, []).append(addr)
    return clusters


# ---------------------------------------------------------------------------
# Pass 2: Call-graph expansion
# ---------------------------------------------------------------------------

def expand_clusters_by_calls(
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    clusters: dict[str, list[int]],
    all_addrs: set[int],
) -> dict[str, list[int]]:
    """Add non-peripheral functions to clusters based on call-graph affinity.

    For each unclustered function, count how many of its callers/callees
    are in each cluster. Assign to the cluster with the most connections,
    requiring at least 2 connections to avoid noise.

    Modifies clusters in place and returns it.
    """
    clustered = set()
    for addrs in clusters.values():
        clustered.update(addrs)
    unclustered = all_addrs - clustered

    if not unclustered:
        return clusters

    # Pre-build cluster membership index for fast lookup
    addr_to_cluster: dict[int, str] = {}
    for cluster_name, addrs in clusters.items():
        for a in addrs:
            addr_to_cluster[a] = cluster_name

    # Fetch all call edges for this target at once (much faster than per-function)
    call_rows = conn_duckdb.execute(f"""
        SELECT caller_addr, callee_addr
        FROM calls
        WHERE source = '{target}'
    """).fetchall()

    # Build adjacency: addr -> set of neighbors
    neighbors: dict[int, set[int]] = {}
    for caller, callee in call_rows:
        neighbors.setdefault(caller, set()).add(callee)
        neighbors.setdefault(callee, set()).add(caller)

    for addr in unclustered:
        if addr not in neighbors:
            continue
        connections: dict[str, int] = {}
        for neighbor in neighbors[addr]:
            cname = addr_to_cluster.get(neighbor)
            if cname:
                connections[cname] = connections.get(cname, 0) + 1

        if connections:
            best = max(connections, key=connections.get)
            if connections[best] >= 2:
                clusters[best].append(addr)
                addr_to_cluster[addr] = best

    return clusters


# ---------------------------------------------------------------------------
# Pass 3: Classify remaining functions
# ---------------------------------------------------------------------------

def classify_remaining(
    conn_duckdb: duckdb.DuckDBPyConnection,
    conn_sqlite: sqlite3.Connection | None,
    target: str,
    clusters: dict[str, list[int]],
    all_addrs: set[int],
) -> dict[str, list[int]]:
    """Put remaining functions into 'library' or 'unknown' groups.

    Functions with a high-confidence structural fingerprint match
    (>= 0.80 from functions_enriched) go into 'library'.
    Everything else goes into 'unknown'.

    Returns new clusters dict with 'library' and/or 'unknown' added.
    """
    clustered = set()
    for addrs in clusters.values():
        clustered.update(addrs)
    remaining = all_addrs - clustered

    if not remaining:
        return clusters

    # Check functions_enriched for library matches
    library_addrs = []
    unknown_addrs = []

    try:
        enriched_rows = conn_duckdb.execute(f"""
            SELECT addr, inferred_name, confidence
            FROM functions_enriched
            WHERE source = '{target}'
              AND inferred_name IS NOT NULL
              AND confidence >= 0.80
        """).fetchall()
        enriched_set = {r[0] for r in enriched_rows}
    except duckdb.CatalogException:
        enriched_set = set()

    # Also check evidence_log for agent-identified library functions
    agent_library_set: set[int] = set()
    if conn_sqlite is not None:
        try:
            rows = conn_sqlite.execute("""
                SELECT DISTINCT entity_addr FROM evidence_log
                WHERE target = ? AND claim_type = 'name'
                      AND confidence >= 0.80
            """, (target,)).fetchall()
            agent_library_set = {r[0] for r in rows}
        except sqlite3.OperationalError:
            pass

    high_conf = enriched_set | agent_library_set

    for addr in remaining:
        if addr in high_conf:
            library_addrs.append(addr)
        else:
            unknown_addrs.append(addr)

    if library_addrs:
        clusters["library"] = library_addrs
    if unknown_addrs:
        clusters["unknown"] = unknown_addrs

    return clusters


# ---------------------------------------------------------------------------
# Function name resolution
# ---------------------------------------------------------------------------

def get_function_names(
    conn_duckdb: duckdb.DuckDBPyConnection,
    conn_sqlite: sqlite3.Connection | None,
    target: str,
    addrs: list[int],
) -> dict[int, str]:
    """Get best available name for each function address.

    Priority: evidence_log (agent claims) > functions_enriched > functions table.
    """
    if not addrs:
        return {}

    names: dict[int, str] = {}

    # Start with functions table (lowest priority)
    addr_list = ", ".join(str(a) for a in addrs)
    rows = conn_duckdb.execute(f"""
        SELECT addr, name FROM functions
        WHERE source = '{target}' AND addr IN ({addr_list})
    """).fetchall()
    for addr, name in rows:
        names[addr] = name or f"FUN_{addr:08x}"

    # Override with functions_enriched
    try:
        rows = conn_duckdb.execute(f"""
            SELECT addr, inferred_name, confidence
            FROM functions_enriched
            WHERE source = '{target}'
              AND addr IN ({addr_list})
              AND inferred_name IS NOT NULL
        """).fetchall()
        for addr, inferred, conf in rows:
            if inferred and not inferred.startswith("FUN_"):
                names[addr] = inferred
    except duckdb.CatalogException:
        pass

    # Override with evidence_log (highest priority)
    if conn_sqlite is not None:
        try:
            placeholders = ", ".join("?" for _ in addrs)
            rows = conn_sqlite.execute(f"""
                SELECT entity_addr,
                       json_extract(claim_json, '$.name') AS name,
                       confidence
                FROM evidence_log
                WHERE target = ? AND claim_type = 'name'
                      AND entity_addr IN ({placeholders})
                      AND confidence >= 0.50
                ORDER BY confidence DESC
            """, [target] + list(addrs)).fetchall()
            # Best per address (already ordered by conf DESC)
            seen = set()
            for addr, name, conf in rows:
                if addr not in seen and name:
                    names[addr] = name.strip('"')
                    seen.add(addr)
        except sqlite3.OperationalError:
            pass

    # Fill in any missing
    for addr in addrs:
        if addr not in names:
            names[addr] = f"FUN_{addr:08x}"

    return names


# ---------------------------------------------------------------------------
# LLM labeling
# ---------------------------------------------------------------------------

def _build_label_prompt(
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    cluster_name: str,
    addrs: list[int],
    function_names: dict[int, str],
    domain_hint: str | None,
) -> str:
    """Build a prompt for Claude to label a cluster.

    Includes the cluster's peripheral (if peripheral-seeded),
    function names, and decompiled C for the top functions by size.
    """
    sections = []

    sections.append(
        "You are a firmware reverse engineer analyzing a stripped ARM Cortex-M binary. "
        "Your task is to assign a concise MODULE NAME and description to a group of "
        "related functions."
    )

    if domain_hint:
        sections.append(
            f"## Domain context\n"
            f"This binary is from: {domain_hint}"
        )

    # Cluster info
    lines = [f"## Function cluster: {cluster_name}"]
    lines.append(f"Functions in cluster: {len(addrs)}")
    if cluster_name not in ("library", "unknown"):
        lines.append(f"Seed peripheral: {cluster_name}")
    sections.append("\n".join(lines))

    # Function list with names
    fn_lines = ["## Functions in this cluster"]
    # Get sizes for sorting
    addr_list = ", ".join(str(a) for a in addrs)
    try:
        size_rows = conn_duckdb.execute(f"""
            SELECT addr, size FROM functions
            WHERE source = '{target}' AND addr IN ({addr_list})
            ORDER BY size DESC
        """).fetchall()
        addr_sizes = {r[0]: r[1] for r in size_rows}
    except Exception:
        addr_sizes = {}

    sorted_addrs = sorted(addrs, key=lambda a: addr_sizes.get(a, 0), reverse=True)
    for addr in sorted_addrs[:30]:  # cap at 30 for prompt size
        name = function_names.get(addr, f"FUN_{addr:08x}")
        size = addr_sizes.get(addr, "?")
        fn_lines.append(f"- 0x{addr:08x}  {name}  ({size} bytes)")
    if len(addrs) > 30:
        fn_lines.append(f"  ... and {len(addrs) - 30} more")
    sections.append("\n".join(fn_lines))

    # Peripheral accesses summary (if peripheral-seeded)
    if cluster_name not in ("library", "unknown"):
        try:
            periph_rows = conn_duckdb.execute(f"""
                SELECT register_name, ref_type, COUNT(*) AS n
                FROM peripheral_xrefs
                WHERE source = '{target}'
                  AND function_addr IN ({addr_list})
                  AND peripheral = '{cluster_name}'
                GROUP BY register_name, ref_type
                ORDER BY n DESC
                LIMIT 20
            """).fetchall()
            if periph_rows:
                plines = [f"## Peripheral register accesses ({cluster_name})"]
                for reg, ref_type, n in periph_rows:
                    plines.append(f"- {reg}: {ref_type} x{n}")
                sections.append("\n".join(plines))
        except Exception:
            pass

    # Decompiled C for top functions by size (budget ~15KB)
    c_budget = 15_000
    c_included = 0
    for addr in sorted_addrs[:5]:
        if c_budget <= 0:
            break
        try:
            c_text = _get_decompiled_c(conn_duckdb, target, addr)
        except Exception:
            c_text = None
        if c_text:
            name = function_names.get(addr, f"FUN_{addr:08x}")
            sections.append(
                f"## Decompiled C: {name} (0x{addr:08x})\n```c\n{c_text}\n```"
            )
            c_budget -= len(c_text)
            c_included += 1

    # Task
    sections.append(
        "## Task\n"
        "Assign a concise module name and description to this cluster of functions. "
        "The module name should be a short snake_case identifier "
        "(e.g., 'display_driver', 'sensor_acquisition', 'serial_debug', 'rtos_glue'). "
        "The description should be one sentence explaining what this module does.\n\n"
        "Respond with JSON:\n"
        '{"module_name": "...", "description": "...", "confidence": 0.0-1.0, '
        '"reasoning": "..."}\n\n'
        "Only return the JSON object, no other text."
    )

    return "\n\n".join(sections)


def _parse_label_response(response_text: str) -> dict:
    """Parse the LLM's module label response.

    Returns dict with: module_name, description, confidence, reasoning.
    """
    import re

    cleaned = response_text.strip()
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    try:
        obj = json.loads(cleaned)
        return {
            "module_name": obj.get("module_name", "unknown"),
            "description": obj.get("description", ""),
            "confidence": float(obj.get("confidence", 0.5)),
            "reasoning": obj.get("reasoning", ""),
        }
    except json.JSONDecodeError:
        pass

    # Try to find JSON object in the text
    brace_match = re.search(r"\{[^{}]*\}", response_text, re.DOTALL)
    if brace_match:
        try:
            obj = json.loads(brace_match.group(0))
            return {
                "module_name": obj.get("module_name", "unknown"),
                "description": obj.get("description", ""),
                "confidence": float(obj.get("confidence", 0.5)),
                "reasoning": obj.get("reasoning", ""),
            }
        except json.JSONDecodeError:
            pass

    return {
        "module_name": "unknown",
        "description": response_text[:200],
        "confidence": 0.3,
        "reasoning": "failed to parse LLM response",
    }


def label_cluster_with_llm(
    conn_duckdb: duckdb.DuckDBPyConnection,
    target: str,
    cluster_name: str,
    addrs: list[int],
    function_names: dict[int, str],
    model: str,
    domain_hint: str | None,
    dry_run: bool,
) -> dict:
    """Call Claude to produce a module label for a cluster.

    Returns dict with: module_name, description, confidence, reasoning,
    input_tokens, output_tokens.
    """
    prompt = _build_label_prompt(
        conn_duckdb, target, cluster_name, addrs, function_names, domain_hint,
    )

    if dry_run:
        print(f"    [DRY RUN] prompt: {len(prompt)} chars")
        for line in prompt[:400].splitlines()[:6]:
            print(f"      {line}")
        return {
            "module_name": f"{cluster_name}_module",
            "description": f"(dry run) cluster seeded by {cluster_name}",
            "confidence": 0.0,
            "reasoning": "dry run",
            "input_tokens": 0,
            "output_tokens": 0,
        }

    t0 = time.monotonic()
    response = call_claude(prompt, model)
    elapsed = time.monotonic() - t0

    label = _parse_label_response(response["content"])
    print(f"    -> {label['module_name']!r}  conf={label['confidence']:.2f}  "
          f"({elapsed:.1f}s, {response['input_tokens']}+{response['output_tokens']} tok)")

    label["input_tokens"] = response["input_tokens"]
    label["output_tokens"] = response["output_tokens"]
    return label


# ---------------------------------------------------------------------------
# Results persistence
# ---------------------------------------------------------------------------

def save_results(
    conn_sqlite: sqlite3.Connection,
    target: str,
    clusters: dict[str, list[int]],
    labels: dict[str, dict],
    assignment_methods: dict[str, str],
) -> None:
    """Write module and function_modules rows to SQLite.

    Clears prior module data for this target before inserting.
    """
    # Clear previous results for this target
    conn_sqlite.execute(
        "DELETE FROM function_modules WHERE target = ?", (target,)
    )
    conn_sqlite.execute(
        "DELETE FROM modules WHERE target = ?", (target,)
    )
    conn_sqlite.commit()

    for cluster_name, addrs in clusters.items():
        label = labels.get(cluster_name, {})
        module_name = label.get("module_name", cluster_name)
        description = label.get("description", "")
        confidence = label.get("confidence")
        seed_periph = cluster_name if cluster_name not in ("library", "unknown") else None

        conn_sqlite.execute("""
            INSERT INTO modules (target, module_name, description,
                                 seed_peripheral, function_count, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (target, module_name, description, seed_periph,
              len(addrs), confidence))
        module_id = conn_sqlite.execute("SELECT last_insert_rowid()").fetchone()[0]

        method = assignment_methods.get(cluster_name, "unknown")
        for addr in addrs:
            conn_sqlite.execute("""
                INSERT OR REPLACE INTO function_modules
                    (target, function_addr, module_id, assignment_method)
                VALUES (?, ?, ?, ?)
            """, (target, addr, module_id, method))

    conn_sqlite.commit()


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def print_report(
    target: str,
    clusters: dict[str, list[int]],
    labels: dict[str, dict],
    function_names: dict[int, str],
    assignment_methods: dict[str, str],
    per_cluster_methods: dict[str, dict[str, int]],
) -> None:
    """Print the module summary report."""
    print(f"\n{'='*60}")
    print(f"  Module Report: {target}")
    print(f"{'='*60}\n")

    # Sort clusters: peripheral-seeded first (by size desc), then library, then unknown
    def sort_key(name):
        if name == "unknown":
            return (2, 0, name)
        if name == "library":
            return (1, 0, name)
        return (0, -len(clusters[name]), name)

    for cluster_name in sorted(clusters, key=sort_key):
        addrs = clusters[cluster_name]
        label = labels.get(cluster_name, {})
        module_name = label.get("module_name", cluster_name)
        description = label.get("description", "")
        confidence = label.get("confidence")

        conf_str = f", conf={confidence:.2f}" if confidence is not None else ""
        print(f"[{module_name}] {description} ({len(addrs)} functions{conf_str})")

        # Assignment method breakdown
        methods = per_cluster_methods.get(cluster_name, {})
        if methods:
            method_parts = []
            for m, count in sorted(methods.items(), key=lambda x: -x[1]):
                method_parts.append(f"{count} {m}")
            seed_str = f"  seed: {cluster_name}" if cluster_name not in ("library", "unknown") else ""
            if seed_str:
                print(f"{seed_str}  |  assignment: {', '.join(method_parts)}")
            else:
                print(f"  assignment: {', '.join(method_parts)}")

        # Top function names
        top_names = []
        for addr in addrs[:8]:
            name = function_names.get(addr, f"FUN_{addr:08x}")
            if not name.startswith("FUN_"):
                top_names.append(name)
        if top_names:
            print(f"  top functions: {', '.join(top_names[:6])}")
        print()

    # Summary
    total = sum(len(a) for a in clusters.values())
    n_modules = len([c for c in clusters if c not in ("library", "unknown")])
    n_library = len(clusters.get("library", []))
    n_unknown = len(clusters.get("unknown", []))
    print(f"summary: {total} functions -> {n_modules} modules, "
          f"{n_library} library, {n_unknown} unclassified")


# ---------------------------------------------------------------------------
# Datalog subsystem pairs integration
# ---------------------------------------------------------------------------

def _load_subsystem_pairs(build_dir: str, target: str) -> dict[int, set[int]]:
    """Load datalog-derived subsystem pairs if available.

    Returns adjacency dict: addr -> set of addrs in same subsystem.
    """
    csv_path = Path(build_dir) / target / "datalog" / "subsystem_pairs.csv"
    if not csv_path.exists():
        return {}

    adjacency: dict[int, set[int]] = {}
    try:
        with open(csv_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("fn_a"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 2:
                    try:
                        a, b = int(parts[0]), int(parts[1])
                        adjacency.setdefault(a, set()).add(b)
                        adjacency.setdefault(b, set()).add(a)
                    except ValueError:
                        continue
    except Exception:
        pass
    return adjacency


# ---------------------------------------------------------------------------
# Main detection flow
# ---------------------------------------------------------------------------

def run_detection(
    target: str,
    build_dir: str,
    model: str,
    domain_hint: str | None,
    dry_run: bool,
    min_cluster_size: int = 2,
) -> None:
    """Main detection flow: cluster, label, report."""
    build_path = Path(build_dir)
    db_path = str(build_path / "coordination.sqlite")

    print(f"detect_modules: target={target}, model={model}, dry_run={dry_run}")
    if domain_hint:
        print(f"detect_modules: domain_hint={domain_hint!r}")
    print()

    # --- Initialize DuckDB warehouse ---
    conn_duckdb = duckdb.connect(":memory:")
    register_warehouse(conn_duckdb, build_dir, targets=[target])

    # --- Initialize SQLite coordination DB ---
    db = Path(db_path)
    if not db.exists():
        print(f"detect_modules: creating coordination DB at {db_path}")
        db.parent.mkdir(parents=True, exist_ok=True)
        conn_init = sqlite3.connect(db_path)
        conn_init.execute("PRAGMA journal_mode=WAL")
        from init_db import SCHEMA_SQL
        conn_init.executescript(SCHEMA_SQL)
        conn_init.close()

    conn_sqlite = sqlite3.connect(db_path)
    conn_sqlite.execute("PRAGMA journal_mode=WAL")
    _ensure_module_tables(conn_sqlite)

    # --- Get all function addresses ---
    all_fn_rows = conn_duckdb.execute(f"""
        SELECT addr FROM functions WHERE source = '{target}'
    """).fetchall()
    all_addrs = {r[0] for r in all_fn_rows}
    print(f"detect_modules: {len(all_addrs)} functions in {target}")

    # --- Pass 1: Peripheral-based seed clusters ---
    print("\nPass 1: Peripheral-based seed clusters...")
    clusters = build_peripheral_clusters(conn_duckdb, target)
    if clusters:
        for name, addrs in sorted(clusters.items(), key=lambda x: -len(x[1])):
            print(f"  {name}: {len(addrs)} functions")
    else:
        print("  (no peripheral_xrefs data — skipping peripheral seeding)")

    # Track assignment methods per cluster
    # Key: cluster_name -> { method -> count }
    per_cluster_methods: dict[str, dict[str, int]] = {}
    for cname, addrs in clusters.items():
        per_cluster_methods[cname] = {"peripheral_seed": len(addrs)}

    # --- Pass 2: Call-graph expansion ---
    print("\nPass 2: Call-graph expansion...")
    pre_expansion = {k: len(v) for k, v in clusters.items()}
    clusters = expand_clusters_by_calls(conn_duckdb, target, clusters, all_addrs)
    for cname, addrs in clusters.items():
        added = len(addrs) - pre_expansion.get(cname, 0)
        if added > 0:
            print(f"  {cname}: +{added} call-expansion (total {len(addrs)})")
            methods = per_cluster_methods.setdefault(cname, {})
            methods["call_expansion"] = added

    # --- Pass 3: Classify remaining ---
    print("\nPass 3: Classifying remaining functions...")
    clusters = classify_remaining(
        conn_duckdb, conn_sqlite, target, clusters, all_addrs,
    )
    for cname in ("library", "unknown"):
        if cname in clusters:
            count = len(clusters[cname])
            print(f"  {cname}: {count} functions")
            per_cluster_methods[cname] = {cname: count}

    # --- Resolve function names ---
    all_clustered_addrs = []
    for addrs in clusters.values():
        all_clustered_addrs.extend(addrs)
    function_names = get_function_names(
        conn_duckdb, conn_sqlite, target, all_clustered_addrs,
    )

    # --- LLM labeling ---
    print("\nLLM labeling...")
    labels: dict[str, dict] = {}
    assignment_methods: dict[str, str] = {}
    total_input_tokens = 0
    total_output_tokens = 0

    for cluster_name, addrs in sorted(clusters.items(), key=lambda x: -len(x[1])):
        # Skip LLM calls for library and unknown groups
        if cluster_name == "library":
            labels[cluster_name] = {
                "module_name": "library",
                "description": "Known library functions (FreeRTOS, SDK, libc) "
                               "identified by structural fingerprinting",
                "confidence": 0.95,
                "reasoning": "Structural fingerprint match",
            }
            assignment_methods[cluster_name] = "library"
            continue

        if cluster_name == "unknown":
            labels[cluster_name] = {
                "module_name": "unclassified",
                "description": "Functions not assigned to any module",
                "confidence": None,
                "reasoning": "No peripheral affinity or call-graph connection",
            }
            assignment_methods[cluster_name] = "unknown"
            continue

        # Skip tiny clusters (< min_cluster_size)
        if len(addrs) < min_cluster_size:
            labels[cluster_name] = {
                "module_name": f"{cluster_name.lower()}_misc",
                "description": f"Small cluster seeded by {cluster_name} "
                               f"({len(addrs)} function{'s' if len(addrs) != 1 else ''})",
                "confidence": 0.4,
                "reasoning": "Too few functions for confident module identification",
            }
            assignment_methods[cluster_name] = "peripheral_seed"
            continue

        print(f"\n  Labeling cluster '{cluster_name}' ({len(addrs)} functions)...")
        assignment_methods[cluster_name] = "peripheral_seed"

        try:
            label = label_cluster_with_llm(
                conn_duckdb, target, cluster_name, addrs, function_names,
                model, domain_hint, dry_run,
            )
            labels[cluster_name] = label
            total_input_tokens += label.get("input_tokens", 0)
            total_output_tokens += label.get("output_tokens", 0)
        except Exception as exc:
            print(f"    ERROR: {exc}")
            labels[cluster_name] = {
                "module_name": f"{cluster_name.lower()}_module",
                "description": f"Cluster seeded by {cluster_name} (labeling failed)",
                "confidence": 0.3,
                "reasoning": f"LLM labeling failed: {exc}",
            }

    # --- Save results ---
    print("\nSaving results to coordination DB...")
    save_results(conn_sqlite, target, clusters, labels, assignment_methods)

    # --- Cost summary ---
    cost = (total_input_tokens * 3.0 + total_output_tokens * 15.0) / 1_000_000

    # --- Log agent run ---
    agent_id = f"detect-modules-{uuid4().hex[:8]}"
    n_llm_calls = sum(
        1 for c in clusters
        if c not in ("library", "unknown") and len(clusters[c]) >= min_cluster_size
    )
    if not dry_run and (total_input_tokens > 0 or total_output_tokens > 0):
        try:
            log_agent_run(
                conn_sqlite, agent_id, model, n_llm_calls,
                total_input_tokens, total_output_tokens, cost,
            )
        except Exception as exc:
            print(f"  WARNING: failed to log agent run: {exc}")

    # --- Print report ---
    print_report(
        target, clusters, labels, function_names,
        assignment_methods, per_cluster_methods,
    )

    print(f"tokens: {total_input_tokens} in + {total_output_tokens} out")
    print(f"total cost: ${cost:.4f}")
    print(f"LLM calls: {n_llm_calls}")

    conn_sqlite.close()
    conn_duckdb.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Module detection: cluster functions into subsystems and label them"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target name (e.g. pico_freertos_hello_stripped)",
    )
    parser.add_argument(
        "--build-dir", default="build",
        help="Path to build directory with parquet warehouse",
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-20250514",
        help="Claude model to use (default: claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--domain-hint",
        help="Domain context hint (e.g. 'FreeRTOS-based embedded application')",
    )
    parser.add_argument(
        "--min-cluster-size", type=int, default=2,
        help="Minimum functions in a cluster to trigger LLM labeling (default: 2)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run clustering but skip LLM calls (print prompts instead)",
    )
    args = parser.parse_args()

    run_detection(
        target=args.target,
        build_dir=args.build_dir,
        model=args.model,
        domain_hint=args.domain_hint,
        dry_run=args.dry_run,
        min_cluster_size=args.min_cluster_size,
    )


if __name__ == "__main__":
    main()
