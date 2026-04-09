#!/usr/bin/env -S uv run python
"""Multi-signal function matching between reference and target binaries.

Takes one or more reference targets and a single unknown target from the
ripcord warehouse and produces a ranked identification report using
weighted multi-signal scoring. This is the CLI wrapper around the logic
in notes/queries/multi_signal_score.sql.

Signals (each normalized to 0.0-1.0):
  1. Size similarity     (weight 0.15) - gaussian decay, 30% tolerance
  2. Block count match   (weight 0.15) - exact=1.0, off-by-1=0.7, off-by-3=0.3
  3. Call fan-out match   (weight 0.10) - exact callees=1.0, off-by-1=0.5
  4. Peripheral overlap   (weight 0.25) - Jaccard on peripheral address sets
  5. String overlap       (weight 0.20) - Jaccard on string reference sets
  6. Body hash            (weight 0.05) - exact byte match bonus
  7. Read/write pattern   (weight 0.10) - read/write count similarity

Usage:
    scripts/match/match_functions.py --reference at32_freertos_hello --target stock_v120
    scripts/match/match_functions.py --reference at32_freertos_hello,at32_hal_blinky --target stock_v120
    scripts/match/match_functions.py --reference at32_freertos_hello --target stock_v120 --min-score 0.5 --min-signals 3
    scripts/match/match_functions.py --reference at32_freertos_hello --target stock_v120 --output build/stock_v120/match_report.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"

# Signal weights — peripheral overlap and strings are most compiler-invariant
WEIGHTS = {
    "size": 0.15,
    "blocks": 0.15,
    "calls": 0.10,
    "periph": 0.25,
    "strings": 0.20,
    "hash": 0.05,
    "rw": 0.10,
}


def discover_tables() -> dict[str, list[str]]:
    """Find all parquet files grouped by table name."""
    groups: dict[str, list[str]] = defaultdict(list)
    if not BUILD_DIR.exists():
        return {}
    for target_dir in sorted(BUILD_DIR.iterdir()):
        tables_dir = target_dir / "tables"
        if not tables_dir.is_dir():
            continue
        for pq in sorted(tables_dir.glob("*.parquet")):
            name = pq.stem
            if name == "functions_enriched" or name.startswith("mmio_events_"):
                continue
            groups[name].append(str(pq))
    return dict(groups)


def get_db():
    """Create a DuckDB connection with all warehouse views registered."""
    import duckdb

    conn = duckdb.connect(":memory:")
    tables = discover_tables()
    for name, paths in tables.items():
        paths_sql = ", ".join(f"'{p}'" for p in paths)
        conn.execute(
            f"CREATE OR REPLACE VIEW {name} AS "
            f"SELECT * FROM read_parquet([{paths_sql}], union_by_name=true);"
        )
    return conn


def build_feature_vectors(conn, sources: list[str]) -> list[dict]:
    """Build per-function feature vectors from the warehouse.

    Executes the same aggregation as multi_signal_score.sql but returns
    Python dicts for in-memory scoring.
    """
    sources_sql = ", ".join(f"'{s}'" for s in sources)

    sql = f"""
    WITH
        bb_agg AS (
            SELECT source, function_addr,
                   SUM(instruction_count) AS instructions
            FROM basic_blocks
            WHERE function_addr IS NOT NULL
            GROUP BY source, function_addr
        ),
        call_agg AS (
            SELECT source, caller_addr AS function_addr,
                   COUNT(*) AS outgoing_calls,
                   COUNT(DISTINCT callee_addr) AS distinct_callees
            FROM calls
            GROUP BY source, caller_addr
        ),
        xref_agg AS (
            SELECT source, function_addr,
                   COUNT(DISTINCT CASE WHEN ref_type IN ('READ','DATA') THEN to_addr END) AS reads,
                   COUNT(DISTINCT CASE WHEN ref_type = 'WRITE' THEN to_addr END) AS writes
            FROM xrefs
            GROUP BY source, function_addr
        ),
        periph_agg AS (
            SELECT source, function_addr,
                   LIST(DISTINCT to_addr ORDER BY to_addr) AS periph_addrs,
                   COUNT(DISTINCT to_addr) AS periph_count
            FROM xrefs
            WHERE ref_type IN ('DATA', 'READ', 'WRITE', 'PARAM')
              AND to_addr IS NOT NULL
              AND (to_addr BETWEEN 1073741824 AND 1610612735
                   OR to_addr >= 3758096384)
            GROUP BY source, function_addr
        ),
        string_agg AS (
            SELECT x.source, x.function_addr,
                   LIST(DISTINCT s.value ORDER BY s.value) AS string_set,
                   COUNT(DISTINCT s.value) AS string_count
            FROM xrefs x
            JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
            WHERE x.ref_type IN ('DATA', 'READ', 'PARAM')
            GROUP BY x.source, x.function_addr
        )
    SELECT
        f.source, f.addr, f.name, f.size, f.body_hash,
        f.basic_block_count,
        COALESCE(bb.instructions, 0) AS instructions,
        COALESCE(ca.outgoing_calls, 0) AS outgoing_calls,
        COALESCE(ca.distinct_callees, 0) AS distinct_callees,
        COALESCE(xa.reads, 0) AS reads,
        COALESCE(xa.writes, 0) AS writes,
        COALESCE(pa.periph_addrs, []) AS periph_addrs,
        COALESCE(pa.periph_count, 0) AS periph_count,
        COALESCE(sa.string_set, []) AS string_set,
        COALESCE(sa.string_count, 0) AS string_count
    FROM functions f
    LEFT JOIN bb_agg bb ON bb.source = f.source AND bb.function_addr = f.addr
    LEFT JOIN call_agg ca ON ca.source = f.source AND ca.function_addr = f.addr
    LEFT JOIN xref_agg xa ON xa.source = f.source AND xa.function_addr = f.addr
    LEFT JOIN periph_agg pa ON pa.source = f.source AND pa.function_addr = f.addr
    LEFT JOIN string_agg sa ON sa.source = f.source AND sa.function_addr = f.addr
    WHERE f.is_thunk = false AND f.size >= 16
      AND f.source IN ({sources_sql})
    """

    result = conn.execute(sql).fetchall()
    columns = [
        "source", "addr", "name", "size", "body_hash",
        "basic_block_count", "instructions", "outgoing_calls",
        "distinct_callees", "reads", "writes", "periph_addrs",
        "periph_count", "string_set", "string_count",
    ]
    return [dict(zip(columns, row)) for row in result]


def jaccard(set_a: list | set, set_b: list | set) -> float:
    """Jaccard similarity between two sets."""
    a = set(set_a) if not isinstance(set_a, set) else set_a
    b = set(set_b) if not isinstance(set_b, set) else set_b
    if not a and not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0


def compute_signals(ref: dict, tgt: dict) -> dict[str, float]:
    """Compute all 7 signal scores between a reference and target function."""
    # Signal 1: Size similarity (gaussian decay)
    if ref["size"] == 0 or tgt["size"] == 0:
        size_sim = 0.0
    else:
        ratio = (ref["size"] - tgt["size"]) / max(ref["size"], tgt["size"])
        size_sim = math.exp(-3.0 * ratio * ratio)

    # Signal 2: Block count similarity
    block_diff = abs(ref["basic_block_count"] - tgt["basic_block_count"])
    if block_diff == 0:
        block_sim = 1.0
    elif block_diff == 1:
        block_sim = 0.7
    elif block_diff <= 3:
        block_sim = 0.3
    else:
        block_sim = 0.0

    # Signal 3: Call pattern similarity
    if (ref["outgoing_calls"] == tgt["outgoing_calls"]
            and ref["distinct_callees"] == tgt["distinct_callees"]):
        call_sim = 1.0
    elif ref["distinct_callees"] == tgt["distinct_callees"]:
        call_sim = 0.8
    elif abs(ref["distinct_callees"] - tgt["distinct_callees"]) <= 1:
        call_sim = 0.5
    elif abs(ref["distinct_callees"] - tgt["distinct_callees"]) <= 2:
        call_sim = 0.2
    else:
        call_sim = 0.0

    # Signal 4: Peripheral address overlap (Jaccard)
    ref_periph = ref["periph_addrs"] or []
    tgt_periph = tgt["periph_addrs"] or []
    if not ref_periph and not tgt_periph:
        periph_sim = 0.0
    elif not ref_periph or not tgt_periph:
        periph_sim = 0.0
    else:
        periph_sim = jaccard(ref_periph, tgt_periph)

    # Signal 5: String overlap (Jaccard)
    ref_strings = ref["string_set"] or []
    tgt_strings = tgt["string_set"] or []
    if not ref_strings and not tgt_strings:
        string_sim = 0.0
    elif not ref_strings or not tgt_strings:
        string_sim = 0.0
    else:
        string_sim = jaccard(ref_strings, tgt_strings)

    # Signal 6: Body hash exact match
    ref_hash = ref["body_hash"]
    tgt_hash = tgt["body_hash"]
    if ref_hash and tgt_hash and ref_hash == tgt_hash:
        hash_match = 1.0
    else:
        hash_match = 0.0

    # Signal 7: Read/write pattern similarity
    if ref["reads"] == tgt["reads"] and ref["writes"] == tgt["writes"]:
        rw_sim = 1.0
    elif (abs(ref["reads"] - tgt["reads"]) <= 2
          and abs(ref["writes"] - tgt["writes"]) <= 2):
        rw_sim = 0.5
    else:
        rw_sim = 0.0

    return {
        "size": size_sim,
        "blocks": block_sim,
        "calls": call_sim,
        "periph": periph_sim,
        "strings": string_sim,
        "hash": hash_match,
        "rw": rw_sim,
    }


def composite_score(signals: dict[str, float]) -> float:
    """Compute weighted composite score from individual signals."""
    return sum(WEIGHTS[k] * signals[k] for k in WEIGHTS)


def signals_active(signals: dict[str, float]) -> int:
    """Count how many signals are meaningfully active."""
    count = 0
    if signals["size"] > 0.5:
        count += 1
    if signals["blocks"] > 0.5:
        count += 1
    if signals["calls"] > 0.5:
        count += 1
    if signals["periph"] > 0:
        count += 1
    if signals["strings"] > 0:
        count += 1
    if signals["hash"] > 0:
        count += 1
    if signals["rw"] > 0.5:
        count += 1
    return count


def match_functions(
    ref_features: list[dict],
    tgt_features: list[dict],
    min_score: float = 0.3,
    min_signals: int = 1,
) -> list[dict]:
    """Compute pairwise matches between reference and target functions.

    Pre-filters by size (target within 50%-200% of reference) to avoid
    N^2 blowup.
    """
    matches = []

    for ref in ref_features:
        best_for_ref = []
        ref_size = ref["size"]
        size_lo = ref_size * 0.5
        size_hi = ref_size * 2.0

        for tgt in tgt_features:
            # Pre-filter: size within 50%-200%
            if not (size_lo <= tgt["size"] <= size_hi):
                continue

            sigs = compute_signals(ref, tgt)
            score = composite_score(sigs)
            active = signals_active(sigs)

            if score >= min_score and active >= min_signals:
                best_for_ref.append({
                    "ref_name": ref["name"],
                    "ref_source": ref["source"],
                    "ref_addr": "0x{:08x}".format(ref["addr"]),
                    "ref_size": ref["size"],
                    "tgt_name": tgt["name"],
                    "tgt_source": tgt["source"],
                    "tgt_addr": "0x{:08x}".format(tgt["addr"]),
                    "tgt_size": tgt["size"],
                    "composite_score": round(score, 4),
                    "signals_active": active,
                    "signal_detail": {k: round(v, 3) for k, v in sigs.items()},
                })

        # Keep top 3 per reference function
        best_for_ref.sort(key=lambda m: m["composite_score"], reverse=True)
        matches.extend(best_for_ref[:3])

    # Sort all matches by composite score descending
    matches.sort(key=lambda m: m["composite_score"], reverse=True)
    return matches


def classify_match(score: float, active: int) -> str:
    """Classify a match into confidence tiers."""
    if score >= 0.5 and active >= 3:
        return "high"
    elif score >= 0.3:
        return "medium"
    else:
        return "low"


def format_table(
    matches: list[dict],
    ref_sources: list[str],
    tgt_source: str,
    ref_count: int,
    tgt_count: int,
) -> str:
    """Format matches as a human-readable table to stdout."""
    lines = []
    lines.append(f"Reference: {', '.join(ref_sources)} ({ref_count} functions)")
    lines.append(f"Target: {tgt_source} ({tgt_count} functions)")
    lines.append("Pre-filter: size within 50%-200%")
    lines.append("")

    # Classify matches
    high = [m for m in matches if classify_match(m["composite_score"], m["signals_active"]) == "high"]
    medium = [m for m in matches if classify_match(m["composite_score"], m["signals_active"]) == "medium" and m not in high]

    # Deduplicate: best match per reference function for the summary sections
    seen_ref = set()

    if high:
        lines.append(f"HIGH CONFIDENCE (score >= 0.5, signals >= 3): {len(high)} matches")
        lines.append(f"  {'ref_name':<30s} {'tgt_name':<20s} {'tgt_addr':<14s} {'score':>6s} {'sig':>4s}  detail")
        lines.append("  " + "-" * 100)
        for m in high:
            key = (m["ref_name"], m["ref_source"])
            if key in seen_ref:
                continue
            seen_ref.add(key)
            d = m["signal_detail"]
            detail_parts = []
            for sig_name in ["size", "blocks", "calls", "periph", "strings", "hash", "rw"]:
                v = d[sig_name]
                if v > 0:
                    detail_parts.append(f"{sig_name}={v:.2f}")
            lines.append(
                f"  {m['ref_name']:<30s} {m['tgt_name']:<20s} {m['tgt_addr']:<14s} "
                f"{m['composite_score']:>6.3f} {m['signals_active']:>3d}/7  "
                f"{', '.join(detail_parts)}"
            )
        lines.append("")

    # All candidates (best per ref, above min_score)
    seen_ref_all = set()
    all_best = []
    for m in matches:
        key = (m["ref_name"], m["ref_source"])
        if key not in seen_ref_all:
            seen_ref_all.add(key)
            all_best.append(m)

    if all_best:
        lines.append(f"ALL CANDIDATES (best match per reference function): {len(all_best)} ref functions with candidates")
        lines.append(f"  {'ref_name':<30s} {'tgt_name':<20s} {'tgt_addr':<14s} {'score':>6s} {'sig':>4s}")
        lines.append("  " + "-" * 80)
        for m in all_best:
            lines.append(
                f"  {m['ref_name']:<30s} {m['tgt_name']:<20s} {m['tgt_addr']:<14s} "
                f"{m['composite_score']:>6.3f} {m['signals_active']:>3d}/7"
            )
        lines.append("")

    # Summary
    high_count = len([m for m in all_best if classify_match(m["composite_score"], m["signals_active"]) == "high"])
    medium_count = len([m for m in all_best if classify_match(m["composite_score"], m["signals_active"]) == "medium"])
    low_count = len([m for m in all_best if classify_match(m["composite_score"], m["signals_active"]) == "low"])
    lines.append(f"Summary: {high_count} high-confidence, {medium_count} medium, {low_count} low matches")

    return "\n".join(lines)


def format_json(
    matches: list[dict],
    ref_sources: list[str],
    tgt_source: str,
) -> dict:
    """Format matches as a JSON-serializable dict."""
    # Best per reference function for summary counts
    seen_ref = set()
    best_per_ref = []
    for m in matches:
        key = (m["ref_name"], m["ref_source"])
        if key not in seen_ref:
            seen_ref.add(key)
            best_per_ref.append(m)

    high_count = len([m for m in best_per_ref if classify_match(m["composite_score"], m["signals_active"]) == "high"])
    medium_count = len([m for m in best_per_ref if classify_match(m["composite_score"], m["signals_active"]) == "medium"])
    low_count = len([m for m in best_per_ref if classify_match(m["composite_score"], m["signals_active"]) == "low"])

    return {
        "reference_sources": ref_sources,
        "target_source": tgt_source,
        "matches": matches,
        "summary": {"high": high_count, "medium": medium_count, "low": low_count},
    }


def validate_source(conn, source: str) -> int:
    """Check that a source exists in the warehouse. Returns function count."""
    try:
        result = conn.execute(
            f"SELECT COUNT(*) FROM functions WHERE source = '{source}'"
        ).fetchone()
        return result[0] if result else 0
    except Exception:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Multi-signal function matching between reference and target binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--reference", "-r",
        required=True,
        help="Comma-separated reference target names (e.g. at32_freertos_hello,at32_hal_blinky)",
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target binary name (e.g. stock_v120)",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.3,
        help="Minimum composite score to include (default: 0.3)",
    )
    parser.add_argument(
        "--min-signals",
        type=int,
        default=1,
        help="Minimum active signals to include (default: 1)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write JSON report to this path (default: table to stdout)",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=3,
        help="Keep top N candidates per reference function (default: 3)",
    )
    args = parser.parse_args()

    ref_sources = [s.strip() for s in args.reference.split(",")]
    tgt_source = args.target.strip()

    try:
        import duckdb  # noqa: F401
    except ImportError:
        print("duckdb not available; install with: uv add duckdb", file=sys.stderr)
        return 1

    conn = get_db()

    # Validate sources exist
    for src in ref_sources:
        count = validate_source(conn, src)
        if count == 0:
            print(f"error: reference source '{src}' not found in warehouse", file=sys.stderr)
            print("available sources:", file=sys.stderr)
            rows = conn.execute("SELECT DISTINCT source FROM functions ORDER BY source").fetchall()
            for row in rows:
                print(f"  {row[0]}", file=sys.stderr)
            return 1

    tgt_count = validate_source(conn, tgt_source)
    if tgt_count == 0:
        print(f"error: target source '{tgt_source}' not found in warehouse", file=sys.stderr)
        print("available sources:", file=sys.stderr)
        rows = conn.execute("SELECT DISTINCT source FROM functions ORDER BY source").fetchall()
        for row in rows:
            print(f"  {row[0]}", file=sys.stderr)
        return 1

    # Build feature vectors
    print(f"loading features for {len(ref_sources)} reference source(s)...", file=sys.stderr)
    ref_features = build_feature_vectors(conn, ref_sources)
    print(f"  {len(ref_features)} reference functions (after thunk/size filter)", file=sys.stderr)

    print(f"loading features for target '{tgt_source}'...", file=sys.stderr)
    tgt_features = build_feature_vectors(conn, [tgt_source])
    print(f"  {len(tgt_features)} target functions (after thunk/size filter)", file=sys.stderr)

    # Compute matches
    print("computing pairwise scores...", file=sys.stderr)
    matches = match_functions(
        ref_features, tgt_features,
        min_score=args.min_score,
        min_signals=args.min_signals,
    )
    print(f"  {len(matches)} candidate matches", file=sys.stderr)

    if args.output:
        report = format_json(matches, ref_sources, tgt_source)
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"wrote {len(matches)} matches to {output_path}", file=sys.stderr)
    else:
        table = format_table(
            matches, ref_sources, tgt_source,
            ref_count=len(ref_features),
            tgt_count=len(tgt_features),
        )
        print(table)

    return 0


if __name__ == "__main__":
    sys.exit(main())
