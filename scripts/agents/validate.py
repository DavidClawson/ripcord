#!/usr/bin/env -S uv run python
"""Validation harness: compare agent proposals against ground truth.

Loads fingerprint results from functions_enriched parquet, agent
proposals from the coordination SQLite evidence_log, and ground truth
from the un-stripped reference target's functions parquet. Produces a
per-function comparison table and summary statistics.

Works before agents have run (fingerprint-only baseline), and again
after agents run to measure the delta.

Usage:
    uv run python scripts/agents/validate.py \
        --db build/coordination.sqlite \
        --build-dir build \
        --stripped-target pico_freertos_hello_stripped \
        --reference-target pico_freertos_hello
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

import duckdb


# ---------------------------------------------------------------------------
# Name matching
# ---------------------------------------------------------------------------

def match_quality(proposed: str, truth: str) -> str:
    """Return match quality: exact, contained, similar, or wrong."""
    if proposed == truth:
        return "exact"
    # Substring containment (either direction)
    p_lower, t_lower = proposed.lower(), truth.lower()
    if p_lower in t_lower or t_lower in p_lower:
        return "contained"
    # Token overlap: >50% of underscore-delimited tokens shared
    p_tokens = set(p_lower.split("_"))
    t_tokens = set(t_lower.split("_"))
    # Remove empty tokens from leading/trailing underscores
    p_tokens.discard("")
    t_tokens.discard("")
    if p_tokens and t_tokens:
        overlap = len(p_tokens & t_tokens)
        max_tokens = max(len(p_tokens), len(t_tokens))
        if max_tokens > 0 and overlap / max_tokens > 0.5:
            return "similar"
    return "wrong"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_ground_truth(build_dir: Path, reference_target: str) -> dict[int, str]:
    """Load true function names from the reference target, keyed by address."""
    parquet = build_dir / reference_target / "tables" / "functions.parquet"
    if not parquet.exists():
        print(f"ERROR: reference parquet not found: {parquet}", file=sys.stderr)
        sys.exit(1)
    conn = duckdb.connect(":memory:")
    rows = conn.execute(
        f"SELECT addr, name FROM read_parquet('{parquet}')"
    ).fetchall()
    conn.close()
    return {addr: name for addr, name in rows}


def load_fingerprints(build_dir: Path, stripped_target: str) -> dict[int, dict]:
    """Load fingerprint results from functions_enriched parquet.

    Returns {addr: {name, inferred_name, confidence, evidence_method}}.
    """
    parquet = build_dir / stripped_target / "tables" / "functions_enriched.parquet"
    if not parquet.exists():
        print(f"ERROR: enriched parquet not found: {parquet}", file=sys.stderr)
        sys.exit(1)
    conn = duckdb.connect(":memory:")
    rows = conn.execute(
        f"SELECT addr, name, inferred_name, confidence, evidence_method "
        f"FROM read_parquet('{parquet}')"
    ).fetchall()
    conn.close()
    return {
        addr: {
            "name": name,
            "inferred_name": inferred_name,
            "confidence": confidence,
            "evidence_method": evidence_method,
        }
        for addr, name, inferred_name, confidence, evidence_method in rows
    }


def load_agent_proposals(db_path: Path, stripped_target: str) -> dict[int, dict]:
    """Load agent name proposals from the evidence_log.

    Returns {addr: {proposed_name, confidence, evidence_method, reasoning}}.
    If the DB or tables don't exist, returns empty dict.
    """
    if not db_path.exists():
        return {}
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        # Check if tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('evidence_log', 'tasks')"
        ).fetchall()
        table_names = {t[0] for t in tables}
        if "evidence_log" not in table_names:
            conn.close()
            return {}

        # Use a simpler query if tasks table doesn't exist
        if "tasks" in table_names:
            rows = conn.execute(
                """
                SELECT e.entity_addr, e.claim_json, e.confidence, e.evidence_method
                FROM evidence_log e
                JOIN tasks t ON t.id = e.task_id
                WHERE t.target = ? AND e.claim_type = 'name'
                ORDER BY e.confidence DESC
                """,
                (stripped_target,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT entity_addr, claim_json, confidence, evidence_method
                FROM evidence_log
                WHERE target = ? AND claim_type = 'name'
                ORDER BY confidence DESC
                """,
                (stripped_target,),
            ).fetchall()
        conn.close()
    except sqlite3.Error as exc:
        print(f"WARNING: could not read evidence_log: {exc}", file=sys.stderr)
        return {}

    # Deduplicate: keep highest-confidence proposal per address
    proposals: dict[int, dict] = {}
    for addr, claim_json, confidence, evidence_method in rows:
        if addr in proposals:
            continue  # already have a higher-confidence one (ordered DESC)
        try:
            claim = json.loads(claim_json)
        except json.JSONDecodeError:
            continue
        proposed_name = claim.get("proposed_name") or claim.get("name")
        if not proposed_name:
            continue
        reasoning = claim.get("reasoning", "")
        proposals[addr] = {
            "proposed_name": proposed_name,
            "confidence": confidence,
            "evidence_method": evidence_method,
            "reasoning": reasoning,
        }
    return proposals


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_comparison_table(
    fingerprints: dict[int, dict],
    ground_truth: dict[int, str],
    agent_proposals: dict[int, dict],
) -> list[dict]:
    """Build per-function comparison records."""
    rows = []
    for addr, fp in sorted(fingerprints.items()):
        true_name = ground_truth.get(addr)
        inferred = fp.get("inferred_name")
        fp_conf = fp.get("confidence")
        agent = agent_proposals.get(addr)

        fp_correct = None
        if inferred and true_name:
            fp_correct = (inferred == true_name)
        elif inferred and not true_name:
            fp_correct = None  # can't verify

        agent_name = agent["proposed_name"] if agent else None
        agent_conf = agent["confidence"] if agent else None
        agent_correct = None
        agent_match_quality = None
        if agent_name and true_name:
            agent_match_quality = match_quality(agent_name, true_name)
            agent_correct = agent_match_quality in ("exact", "contained", "similar")

        rows.append({
            "addr": addr,
            "ghidra_name": fp["name"],
            "true_name": true_name,
            "fingerprint_name": inferred,
            "fingerprint_conf": fp_conf,
            "agent_name": agent_name,
            "agent_conf": agent_conf,
            "fp_correct": fp_correct,
            "agent_correct": agent_correct,
            "agent_match_quality": agent_match_quality,
            "agent_reasoning": agent.get("reasoning", "") if agent else "",
            "agent_evidence_method": agent.get("evidence_method", "") if agent else "",
        })
    return rows


def print_summary(
    rows: list[dict],
    stripped_target: str,
    reference_target: str,
) -> None:
    """Print the summary statistics report."""
    total = len(rows)
    has_truth = [r for r in rows if r["true_name"] is not None]

    # Fingerprint stats
    fp_matched = [r for r in rows if r["fingerprint_name"] is not None]
    fp_correct = [r for r in fp_matched if r["fp_correct"] is True]
    fp_incorrect = [r for r in fp_matched if r["fp_correct"] is False]
    fp_unverifiable = [r for r in fp_matched if r["fp_correct"] is None]
    fp_no_match = [r for r in rows if r["fingerprint_name"] is None]

    # Agent stats — scope to functions fingerprinting didn't name
    fp_unnamed = [r for r in rows if r["fingerprint_name"] is None]
    agent_proposed = [r for r in fp_unnamed if r["agent_name"] is not None]
    agent_exact = [r for r in agent_proposed if r["agent_match_quality"] == "exact"]
    agent_contained = [r for r in agent_proposed if r["agent_match_quality"] == "contained"]
    agent_similar = [r for r in agent_proposed if r["agent_match_quality"] == "similar"]
    agent_wrong = [r for r in agent_proposed if r["agent_match_quality"] == "wrong"]
    agent_unverifiable = [r for r in agent_proposed if r["agent_match_quality"] is None]
    no_proposal = [r for r in fp_unnamed if r["agent_name"] is None]

    # Also count agent proposals on already-fingerprinted functions
    agent_on_fp = [r for r in rows if r["fingerprint_name"] is not None and r["agent_name"] is not None]

    # Combined
    correct_either = [
        r for r in rows
        if r["fp_correct"] is True
        or (r["fingerprint_name"] is None and r["agent_correct"] is True)
    ]

    still_unnamed = [
        r for r in rows
        if r["fingerprint_name"] is None and r["agent_name"] is None
    ]

    print()
    print("=" * 55)
    print("  Ripcord Agent Validation Report")
    print("=" * 55)
    print()
    print(f"  Target:      {stripped_target}")
    print(f"  Reference:   {reference_target}")
    print(f"  Total functions (stripped):   {total}")
    print(f"  With ground truth (addr match): {len(has_truth)}")
    print()

    # Fingerprint section
    print("--- Fingerprint Recovery ---")
    print(f"  Matched:     {len(fp_matched):>4}  ({_pct(len(fp_matched), total)})")
    if fp_correct:
        print(f"  Correct:     {len(fp_correct):>4}  ({_pct(len(fp_correct), len(fp_matched))} precision)")
    if fp_incorrect:
        print(f"  Incorrect:   {len(fp_incorrect):>4}")
    if fp_unverifiable:
        print(f"  Unverifiable:{len(fp_unverifiable):>4}  (no ground truth at address)")
    print(f"  No match:    {len(fp_no_match):>4}")
    print()

    # Agent section
    print(f"--- Agent Recovery (of {len(fp_unnamed)} unmatched by fingerprint) ---")
    print(f"  Proposed:      {len(agent_proposed):>4}")
    if agent_proposed:
        print(f"  Exact match:   {len(agent_exact):>4}")
        print(f"  Contained:     {len(agent_contained):>4}")
        print(f"  Similar:       {len(agent_similar):>4}")
        print(f"  Wrong:         {len(agent_wrong):>4}")
        if agent_unverifiable:
            print(f"  Unverifiable:  {len(agent_unverifiable):>4}")
    else:
        print("  (no agent proposals found)")
    print(f"  No proposal:   {len(no_proposal):>4}")
    if agent_on_fp:
        print(f"  (Also {len(agent_on_fp)} agent proposals on already-fingerprinted functions)")
    print()

    # Combined section
    print("--- Combined Recovery ---")
    print(
        f"  Correct name (fingerprint OR agent): "
        f"{len(correct_either)} / {total}  ({_pct(len(correct_either), total)})"
    )
    print(f"  Remaining unnamed: {len(still_unnamed)}")
    print()


def print_agent_details(rows: list[dict]) -> None:
    """Print detailed results for each agent proposal."""
    proposals = [r for r in rows if r["agent_name"] is not None]
    if not proposals:
        return
    print("--- Agent Proposal Details ---")
    print()
    for r in sorted(proposals, key=lambda x: x["addr"]):
        quality = r["agent_match_quality"] or "UNVERIFIABLE"
        truth_str = r["true_name"] or "(no ground truth)"
        line = (
            f"  0x{r['addr']:08x}: agent=\"{r['agent_name']}\" "
            f"(conf={r['agent_conf']:.2f}) | "
            f"truth=\"{truth_str}\" | result={quality.upper()}"
        )
        print(line)
        if r["agent_reasoning"]:
            # Truncate reasoning to first 100 chars for readability
            reason = r["agent_reasoning"]
            if len(reason) > 120:
                reason = reason[:117] + "..."
            print(f"    Reasoning: \"{reason}\"")
    print()


def print_unnamed(rows: list[dict]) -> None:
    """Print functions that remain unnamed after both fingerprint and agent."""
    unnamed = [
        r for r in rows
        if r["fingerprint_name"] is None and r["agent_name"] is None
    ]
    if not unnamed:
        print("All functions have a name proposal.")
        return
    print(f"--- Still Unnamed ({len(unnamed)} functions) ---")
    print()
    for r in sorted(unnamed, key=lambda x: x["addr"]):
        truth_str = r["true_name"] or "(no ground truth)"
        print(f"  0x{r['addr']:08x}: ghidra=\"{r['ghidra_name']}\" | truth=\"{truth_str}\"")
    print()


def print_fingerprint_errors(rows: list[dict]) -> None:
    """Print fingerprint mismatches for debugging."""
    errors = [r for r in rows if r["fp_correct"] is False]
    if not errors:
        return
    print(f"--- Fingerprint Errors ({len(errors)}) ---")
    print()
    for r in sorted(errors, key=lambda x: x["addr"]):
        print(
            f"  0x{r['addr']:08x}: "
            f"fingerprint=\"{r['fingerprint_name']}\" "
            f"(conf={r['fingerprint_conf']:.2f}) | "
            f"truth=\"{r['true_name']}\""
        )
    print()


def _pct(num: int, denom: int) -> str:
    if denom == 0:
        return "N/A"
    return f"{100.0 * num / denom:.1f}%"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate agent proposals against ground truth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--db", default="build/coordination.sqlite",
        help="Path to coordination SQLite database",
    )
    parser.add_argument(
        "--build-dir", default="build",
        help="Path to build directory containing parquet warehouse",
    )
    parser.add_argument(
        "--stripped-target", required=True,
        help="Name of the stripped target (e.g. pico_freertos_hello_stripped)",
    )
    parser.add_argument(
        "--reference-target", required=True,
        help="Name of the un-stripped reference target (e.g. pico_freertos_hello)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed per-function table",
    )
    args = parser.parse_args()

    build_dir = Path(args.build_dir)
    db_path = Path(args.db)

    # Load data
    ground_truth = load_ground_truth(build_dir, args.reference_target)
    fingerprints = load_fingerprints(build_dir, args.stripped_target)
    agent_proposals = load_agent_proposals(db_path, args.stripped_target)

    # Build comparison
    rows = build_comparison_table(fingerprints, ground_truth, agent_proposals)

    # Reports
    print_summary(rows, args.stripped_target, args.reference_target)
    print_fingerprint_errors(rows)
    print_agent_details(rows)
    print_unnamed(rows)

    if args.verbose:
        print("--- Full Comparison Table ---")
        print()
        header = (
            f"{'addr':>12s}  {'true_name':30s}  {'fp_name':30s}  "
            f"{'fp_c':>5s}  {'agent_name':30s}  {'ag_c':>5s}  "
            f"{'fp_ok':>5s}  {'ag_ok':>7s}"
        )
        print(header)
        print("-" * len(header))
        for r in rows:
            tn = (r["true_name"] or "")[:30]
            fn = (r["fingerprint_name"] or "")[:30]
            fc = f"{r['fingerprint_conf']:.2f}" if r["fingerprint_conf"] else ""
            an = (r["agent_name"] or "")[:30]
            ac = f"{r['agent_conf']:.2f}" if r["agent_conf"] else ""
            fpok = str(r["fp_correct"]) if r["fp_correct"] is not None else ""
            agok = (r["agent_match_quality"] or "") if r["agent_name"] else ""
            print(
                f"  0x{r['addr']:08x}  {tn:30s}  {fn:30s}  "
                f"{fc:>5s}  {an:30s}  {ac:>5s}  "
                f"{fpok:>5s}  {agok:>7s}"
            )
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
