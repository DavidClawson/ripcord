#!/usr/bin/env -S uv run python
"""Decompose a large function into phases based on peripheral access patterns.

Splits monolithic init/driver functions into logical phases by analyzing
peripheral register accesses (from the xrefs table). Phase boundaries are
detected using two complementary signals:

  1. Address gaps: a gap > threshold between consecutive peripheral accesses
     (the function is doing computation, calling sub-functions, or executing
     delays between peripheral setup blocks).

  2. Peripheral-set change: the "dominant peripheral" shifts from one sliding
     window to the next, indicating a new hardware setup phase even when
     accesses are dense.

RCC and SYSTICK accesses are treated as "infrastructure" peripherals that
appear throughout init sequences and don't trigger phase boundaries on their
own.

Usage:
    uv run python scripts/analysis/decompose.py --target stock_v120 --function 0x08027a50
    uv run python scripts/analysis/decompose.py --target stock_v120 --function 0x08027a50 --json
    uv run python scripts/analysis/decompose.py --target stock_v120 --function 0x08027a50 --decompiled
    uv run python scripts/analysis/decompose.py --target stock_v120 --function 0x08027a50 --agent-mode
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Peripheral classification — AT32F403A / STM32F1-compatible address map
# ---------------------------------------------------------------------------

PERIPHERAL_MAP = [
    # APB1
    (0x40000000, 0x400003FF, "TMR2"),
    (0x40000400, 0x400007FF, "TMR3"),
    (0x40000800, 0x40000BFF, "TMR4"),
    (0x40000C00, 0x40000FFF, "TMR5"),
    (0x40001000, 0x400013FF, "TMR12"),
    (0x40001400, 0x400017FF, "TMR13"),
    (0x40001800, 0x40001BFF, "TMR6"),
    (0x40001C00, 0x40001FFF, "TMR7"),
    (0x40003000, 0x400033FF, "USART6/7/8"),
    (0x40003800, 0x40003BFF, "SPI2"),
    (0x40003C00, 0x40003FFF, "SPI3"),
    (0x40004400, 0x400047FF, "USART2"),
    (0x40004800, 0x40004BFF, "USART3"),
    (0x40004C00, 0x40004FFF, "UART4"),
    (0x40005400, 0x400057FF, "I2C1"),
    (0x40005800, 0x40005BFF, "I2C2"),
    (0x40005C00, 0x40005FFF, "I2C3"),
    (0x40007000, 0x400073FF, "DAC"),
    (0x40007400, 0x400077FF, "PWR"),
    # APB2
    (0x40010000, 0x400103FF, "AFIO/IOMUX"),
    (0x40010400, 0x400107FF, "EXTI"),
    (0x40010800, 0x40010BFF, "GPIOA"),
    (0x40010C00, 0x40010FFF, "GPIOB"),
    (0x40011000, 0x400113FF, "GPIOC"),
    (0x40011400, 0x400117FF, "GPIOD"),
    (0x40011800, 0x40011BFF, "GPIOE"),
    (0x40012400, 0x400127FF, "ADC1"),
    (0x40012800, 0x40012BFF, "ADC2"),
    (0x40013400, 0x400137FF, "TMR1"),
    (0x40013800, 0x40013BFF, "SPI1"),
    (0x40013C00, 0x40013FFF, "TMR8"),
    (0x40014000, 0x400143FF, "USART1"),
    (0x40014C00, 0x40014FFF, "TMR9"),
    (0x40015000, 0x400153FF, "TMR10"),
    (0x40015400, 0x400157FF, "TMR11"),
    (0x40015800, 0x40015BFF, "TMR11_EXT"),
    # AHB
    (0x40020000, 0x400203FF, "DMA1"),
    (0x40020400, 0x400207FF, "DMA2"),
    (0x40021000, 0x400210FF, "RCC"),
    (0x40022000, 0x400220FF, "FLASH_CTRL"),
    # SDIO
    (0xA0000000, 0xA00003FF, "SDIO"),
    # FSMC / external LCD
    (0x60000000, 0x6FFFFFFF, "FSMC/LCD"),
    # Cortex-M4 system peripherals
    (0xE000E010, 0xE000E01F, "SYSTICK"),
    (0xE000E100, 0xE000ECFF, "NVIC"),
    (0xE000ED00, 0xE000EDFF, "SCB"),
    (0xE000EF00, 0xE000EFFF, "FPU"),
]

PERIPHERAL_MAP.sort(key=lambda t: t[0])

# Peripherals that appear throughout init sequences and shouldn't
# dominate phase identity on their own.
INFRA_PERIPHERALS = {"RCC", "SYSTICK", "NVIC", "SCB"}


def classify_peripheral(addr: int) -> str | None:
    """Return the peripheral name for a register address, or None."""
    for start, end, name in PERIPHERAL_MAP:
        if start <= addr <= end:
            return name
    if addr >= 0x40000000:
        return f"UNKNOWN_0x{addr:08x}"
    return None


# ---------------------------------------------------------------------------
# DuckDB connection setup
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def get_connection():
    """Return a DuckDB connection with all warehouse views registered."""
    import duckdb
    import glob as globmod
    import os

    conn = duckdb.connect(":memory:")
    groups: dict[str, list[str]] = defaultdict(list)
    pattern = str(REPO_ROOT / "build" / "*" / "tables" / "*.parquet")
    for path in globmod.glob(pattern):
        name = os.path.splitext(os.path.basename(path))[0]
        groups[name].append(path)

    for name, paths in sorted(groups.items()):
        paths_sql = ", ".join(f"'{p}'" for p in sorted(paths))
        conn.execute(
            f"CREATE OR REPLACE VIEW {name} AS "
            f"SELECT * FROM read_parquet([{paths_sql}], union_by_name=true);"
        )
    return conn


# ---------------------------------------------------------------------------
# Phase boundary detection — multi-signal approach
# ---------------------------------------------------------------------------

# Default gap threshold (bytes in instruction address space)
DEFAULT_GAP = 100

# Sliding window size for peripheral-set change detection
WINDOW_SIZE = 8


def _dominant_peripheral(xrefs: list[dict], start: int, end: int) -> str | None:
    """Return the most common non-infrastructure peripheral in a range of xrefs."""
    counts = Counter()
    for x in xrefs[start:end]:
        p = x["peripheral"]
        if p not in INFRA_PERIPHERALS:
            counts[p] += 1
    if counts:
        return counts.most_common(1)[0][0]
    # All infrastructure -- return the most common one
    infra_counts = Counter(x["peripheral"] for x in xrefs[start:end])
    return infra_counts.most_common(1)[0][0] if infra_counts else None


def _find_phase_boundaries(xrefs: list[dict], gap_threshold: int) -> list[int]:
    """Return indices into xrefs where phase boundaries should occur.

    Uses two signals:
      1. Gap > threshold between consecutive peripheral accesses
      2. Dominant non-infra peripheral changes in a sliding window

    Returns sorted list of xref indices that start new phases.
    """
    n = len(xrefs)
    if n == 0:
        return []

    boundaries = {0}  # first xref always starts phase 1

    # Signal 1: address gaps
    for i in range(1, n):
        gap = xrefs[i]["from_addr"] - xrefs[i - 1]["from_addr"]
        if gap > gap_threshold:
            boundaries.add(i)

    # Signal 2: sliding window peripheral-set change
    # Compare dominant peripheral in [i-W, i) vs [i, i+W)
    w = WINDOW_SIZE
    for i in range(w, n - w):
        dom_before = _dominant_peripheral(xrefs, i - w, i)
        dom_after = _dominant_peripheral(xrefs, i, i + w)
        if dom_before and dom_after and dom_before != dom_after:
            # Check that this isn't just noise: require at least 3 accesses
            # to the new dominant peripheral in the forward window
            fwd_counts = Counter(
                x["peripheral"] for x in xrefs[i:i + w]
                if x["peripheral"] not in INFRA_PERIPHERALS
            )
            if fwd_counts and fwd_counts.most_common(1)[0][1] >= 3:
                boundaries.add(i)

    return sorted(boundaries)


def decompose_function(conn, target: str, function_addr: int,
                       gap_threshold: int = DEFAULT_GAP) -> dict:
    """Split a function into phases based on peripheral access patterns."""

    # Get function metadata
    fn = conn.execute("""
        SELECT name, size, basic_block_count
        FROM functions WHERE source = ? AND addr = ?
    """, [target, function_addr]).fetchone()

    if fn is None:
        print(f"error: function 0x{function_addr:08x} not found in {target}",
              file=sys.stderr)
        sys.exit(1)

    fn_name, fn_size, fn_bb_count = fn

    # Get all peripheral xrefs, ordered by instruction address
    rows = conn.execute("""
        SELECT from_addr, to_addr, ref_type
        FROM xrefs
        WHERE source = ? AND function_addr = ?
          AND to_addr >= 1073741824
        ORDER BY from_addr
    """, [target, function_addr]).fetchall()

    if not rows:
        return {
            "function": fn_name,
            "addr": f"0x{function_addr:08x}",
            "size": fn_size,
            "basic_blocks": fn_bb_count,
            "peripheral_xrefs": 0,
            "phases": [],
            "note": "No peripheral xrefs; function does not directly access MMIO registers.",
        }

    # Classify each xref
    xrefs = []
    for from_addr, to_addr, ref_type in rows:
        periph = classify_peripheral(to_addr)
        xrefs.append({
            "from_addr": from_addr,
            "to_addr": to_addr,
            "ref_type": ref_type,
            "peripheral": periph,
        })

    # Get call sites (for delay / sub-function detection)
    call_rows = conn.execute("""
        SELECT c.call_site_addr, c.callee_addr,
               COALESCE(f2.name, printf('0x%%08x', c.callee_addr)) AS callee_name
        FROM calls c
        LEFT JOIN functions f2 ON f2.source = c.source AND f2.addr = c.callee_addr
        WHERE c.source = ? AND c.caller_addr = ?
        ORDER BY c.call_site_addr
    """, [target, function_addr]).fetchall()

    call_site_map = {}
    for site_addr, callee_addr, callee_name in call_rows:
        call_site_map[site_addr] = {
            "callee_addr": callee_addr,
            "callee_name": callee_name,
        }

    # Find phase boundaries
    boundary_indices = _find_phase_boundaries(xrefs, gap_threshold)

    # Build phase objects
    raw_phases = []
    for bi in range(len(boundary_indices)):
        start_idx = boundary_indices[bi]
        end_idx = boundary_indices[bi + 1] if bi + 1 < len(boundary_indices) else len(xrefs)
        phase_xrefs = xrefs[start_idx:end_idx]

        peripherals = Counter()
        registers = Counter()
        ref_types = Counter()
        for x in phase_xrefs:
            peripherals[x["peripheral"]] += 1
            registers[f"0x{x['to_addr']:08x}"] += 1
            ref_types[x["ref_type"]] += 1

        start_addr = phase_xrefs[0]["from_addr"]
        end_addr = phase_xrefs[-1]["from_addr"]

        # Find calls in the gap *after* this phase (between this phase's
        # last xref and the next phase's first xref)
        if bi + 1 < len(boundary_indices):
            next_start = xrefs[boundary_indices[bi + 1]]["from_addr"]
            gap_calls = [
                call_site_map[addr] for addr in sorted(call_site_map)
                if end_addr < addr < next_start
            ]
        else:
            gap_calls = []

        raw_phases.append({
            "start_addr": start_addr,
            "end_addr": end_addr,
            "peripherals": dict(peripherals),
            "access_count": len(phase_xrefs),
            "registers": dict(registers),
            "ref_types": dict(ref_types),
            "gap_calls": gap_calls,
        })

    # Merge tiny phases (< 3 non-infra accesses) into predecessor
    phases = _merge_tiny_phases(raw_phases, min_accesses=3)

    # Merge consecutive phases with the same dominant non-infra peripheral
    phases = _merge_same_dominant(phases)

    # Number and label
    for i, phase in enumerate(phases, 1):
        phase["phase"] = i
        phase["label"] = _infer_label(phase)

    return {
        "function": fn_name,
        "addr": f"0x{function_addr:08x}",
        "size": fn_size,
        "basic_blocks": fn_bb_count,
        "peripheral_xrefs": len(xrefs),
        "total_phases": len(phases),
        "phases": phases,
    }


def _merge_tiny_phases(phases: list[dict], min_accesses: int = 3) -> list[dict]:
    """Merge phases with fewer than min_accesses non-infra peripheral hits."""
    if len(phases) <= 1:
        return phases

    merged = [phases[0]]
    for phase in phases[1:]:
        non_infra = sum(
            count for periph, count in phase["peripherals"].items()
            if periph not in INFRA_PERIPHERALS
        )
        if non_infra < min_accesses:
            prev = merged[-1]
            for periph, count in phase["peripherals"].items():
                prev["peripherals"][periph] = prev["peripherals"].get(periph, 0) + count
            for reg, count in phase["registers"].items():
                prev["registers"][reg] = prev["registers"].get(reg, 0) + count
            for rt, count in phase["ref_types"].items():
                prev["ref_types"][rt] = prev["ref_types"].get(rt, 0) + count
            prev["access_count"] += phase["access_count"]
            prev["end_addr"] = phase["end_addr"]
            prev["gap_calls"].extend(phase.get("gap_calls", []))
        else:
            merged.append(phase)

    return merged


def _get_dominant(phase: dict) -> str | None:
    """Return the dominant non-infra peripheral of a phase."""
    non_infra = {p: c for p, c in phase["peripherals"].items()
                 if p not in INFRA_PERIPHERALS}
    if non_infra:
        return max(non_infra, key=non_infra.get)
    return max(phase["peripherals"], key=phase["peripherals"].get) if phase["peripherals"] else None


def _merge_same_dominant(phases: list[dict]) -> list[dict]:
    """Merge consecutive phases that share the same dominant non-infra peripheral."""
    if len(phases) <= 1:
        return phases

    merged = [phases[0]]
    for phase in phases[1:]:
        prev = merged[-1]
        prev_dom = _get_dominant(prev)
        curr_dom = _get_dominant(phase)
        if prev_dom and curr_dom and prev_dom == curr_dom:
            # Merge into previous
            for periph, count in phase["peripherals"].items():
                prev["peripherals"][periph] = prev["peripherals"].get(periph, 0) + count
            for reg, count in phase["registers"].items():
                prev["registers"][reg] = prev["registers"].get(reg, 0) + count
            for rt, count in phase["ref_types"].items():
                prev["ref_types"][rt] = prev["ref_types"].get(rt, 0) + count
            prev["access_count"] += phase["access_count"]
            prev["end_addr"] = phase["end_addr"]
            prev["gap_calls"].extend(phase.get("gap_calls", []))
        else:
            merged.append(phase)

    return merged


def _infer_label(phase: dict) -> str:
    """Heuristic label based on dominant peripheral(s)."""
    periphs = phase["peripherals"]
    if not periphs:
        return "Unknown"

    # Find dominant non-infra peripheral
    non_infra = {p: c for p, c in periphs.items() if p not in INFRA_PERIPHERALS}
    if non_infra:
        dominant = max(non_infra, key=non_infra.get)
        dominant_count = non_infra[dominant]
        total_non_infra = sum(non_infra.values())
    else:
        dominant = max(periphs, key=periphs.get)
        dominant_count = periphs[dominant]
        total_non_infra = sum(periphs.values())

    dominant_pct = dominant_count / total_non_infra if total_non_infra else 0
    has_delays = len(phase.get("gap_calls", [])) > 0

    # Multi-GPIO check
    gpio_names = sorted(p for p in non_infra if p.startswith("GPIO"))
    if len(gpio_names) >= 2 and all(p.startswith("GPIO") for p in non_infra if non_infra[p] > 2):
        return f"GPIO Configuration ({', '.join(gpio_names)})"

    # Specific peripheral labels
    simple_labels = {
        "FLASH_CTRL": "Flash Configuration",
        "SYSTICK": "SysTick Timer Setup",
        "NVIC": "Interrupt Configuration",
        "SCB": "System Control",
        "FPU": "FPU Configuration",
        "DMA1": "DMA1 Setup",
        "DMA2": "DMA2 Setup",
        "FSMC/LCD": "LCD/FSMC Access",
        "AFIO/IOMUX": "Pin Remapping (AFIO/IOMUX)",
        "EXTI": "External Interrupt Configuration",
        "PWR": "Power Control",
        "DAC": "DAC Configuration",
        "SDIO": "SDIO Configuration",
        "RCC": "Clock/Reset Configuration",
    }

    if dominant in simple_labels and dominant_pct > 0.4:
        label = simple_labels[dominant]
        if has_delays:
            label += " + Delays"
        return label

    # Prefix-based labels for families
    for prefix, family_name in [
        ("USART", "USART"), ("UART", "UART"), ("SPI", "SPI"),
        ("I2C", "I2C"), ("TMR", "Timer"), ("ADC", "ADC"),
        ("GPIO", "GPIO"),
    ]:
        if dominant.startswith(prefix):
            suffix = " + Handshake" if has_delays and prefix in ("SPI", "USART", "I2C") else " Setup"
            if has_delays and prefix == "TMR":
                suffix = " + Delays"
            return f"{dominant}{suffix}"

    if dominant_pct > 0.5:
        return f"{dominant} Access"
    else:
        top3 = sorted(non_infra or periphs, key=lambda p: -(non_infra or periphs)[p])[:3]
        return f"Mixed: {', '.join(top3)}"


# ---------------------------------------------------------------------------
# Decompiled code slicing
# ---------------------------------------------------------------------------

def get_decompiled_phases(conn, target: str, function_addr: int,
                          phases: list[dict]) -> list[dict]:
    """Enrich phases with approximate decompiled code line ranges.

    Uses DAT_XXXXXXXX references in the decompiled C to associate code
    lines with phases by matching peripheral register addresses.
    """
    import re

    row = conn.execute("""
        SELECT decompiled_c FROM decompiled
        WHERE source = ? AND addr = ?
    """, [target, function_addr]).fetchone()

    if not row or not row[0]:
        return phases

    code = row[0]
    lines = code.split("\n")

    # For each line, collect the set of peripherals it references
    dat_pattern = re.compile(r"DAT_([0-9a-fA-F]{8})")
    line_periphs: list[set[str]] = []
    for line in lines:
        periphs_in_line = set()
        for m in dat_pattern.findall(line):
            addr = int(m, 16)
            periph = classify_peripheral(addr)
            if periph:
                periphs_in_line.add(periph)
        line_periphs.append(periphs_in_line)

    # Assign decompiled line ranges to phases.
    # Each phase claims lines that reference its non-infra peripherals
    # and haven't been claimed by a prior phase.
    claimed = set()

    for phase in phases:
        phase_periphs = {
            p for p in phase["peripherals"]
            if p not in INFRA_PERIPHERALS
        }
        if not phase_periphs:
            phase_periphs = set(phase["peripherals"])

        matching = []
        for i, lp in enumerate(line_periphs):
            if i not in claimed and lp & phase_periphs:
                matching.append(i)

        if matching:
            first = max(0, matching[0] - 2)
            last = min(len(lines) - 1, matching[-1] + 2)
            phase["decompiled_line_range"] = (first + 1, last + 1)
            phase["decompiled_lines"] = last - first + 1
            for i in matching:
                claimed.add(i)
        else:
            phase["decompiled_line_range"] = None
            phase["decompiled_lines"] = 0

    return phases


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_text(result: dict) -> str:
    """Format decomposition result as readable text."""
    out = []
    out.append(f"=== Function Decomposition: {result['function']} "
               f"({result['size']} bytes, {result['basic_blocks']} basic blocks) ===")
    out.append(f"    Peripheral xrefs: {result['peripheral_xrefs']}")
    out.append("")

    if not result["phases"]:
        out.append(result.get("note", "No phases found."))
        return "\n".join(out)

    out.append(f"Total phases: {result['total_phases']}")
    out.append("")

    for phase in result["phases"]:
        start = f"0x{phase['start_addr']:08x}"
        end = f"0x{phase['end_addr']:08x}"
        span = phase["end_addr"] - phase["start_addr"]

        out.append(f"Phase {phase['phase']}: {phase['label']} "
                   f"({start} - {end}, ~{span} bytes)")

        periphs = sorted(phase["peripherals"].items(), key=lambda x: -x[1])
        periph_str = ", ".join(f"{name} ({count})" for name, count in periphs)
        out.append(f"  Peripherals: {periph_str}")

        reads = phase["ref_types"].get("READ", 0)
        writes = phase["ref_types"].get("WRITE", 0)
        out.append(f"  Accesses: {phase['access_count']} total "
                   f"({reads} R, {writes} W), "
                   f"{len(phase['registers'])} distinct registers")

        if phase.get("gap_calls"):
            # Deduplicate call names
            names = []
            seen = set()
            for c in phase["gap_calls"]:
                n = c["callee_name"]
                if n not in seen:
                    names.append(n)
                    seen.add(n)
            out.append(f"  Trailing calls: {', '.join(names)}")

        if phase.get("decompiled_line_range"):
            lr = phase["decompiled_line_range"]
            out.append(f"  Decompiled lines: {lr[0]}-{lr[1]} "
                       f"({phase['decompiled_lines']} lines)")

        out.append("")

    return "\n".join(out)


def format_json(result: dict) -> str:
    """Format decomposition result as JSON."""
    output = {
        "function": result["function"],
        "addr": result["addr"],
        "size": result["size"],
        "basic_blocks": result["basic_blocks"],
        "peripheral_xrefs": result["peripheral_xrefs"],
        "total_phases": result.get("total_phases", 0),
        "phases": [],
    }
    for phase in result.get("phases", []):
        p = {
            "phase": phase["phase"],
            "label": phase["label"],
            "start": f"0x{phase['start_addr']:08x}",
            "end": f"0x{phase['end_addr']:08x}",
            "peripherals": phase["peripherals"],
            "access_count": phase["access_count"],
            "distinct_registers": len(phase["registers"]),
            "ref_types": phase["ref_types"],
        }
        if phase.get("gap_calls"):
            p["gap_calls"] = list({c["callee_name"] for c in phase["gap_calls"]})
        if phase.get("decompiled_line_range"):
            p["decompiled_line_range"] = phase["decompiled_line_range"]
        output["phases"].append(p)
    return json.dumps(output, indent=2)


def format_agent_mode(conn, target: str, function_addr: int,
                      result: dict) -> str:
    """Format each phase as a self-contained agent prompt."""
    row = conn.execute("""
        SELECT decompiled_c FROM decompiled
        WHERE source = ? AND addr = ?
    """, [target, function_addr]).fetchone()

    code = row[0] if row and row[0] else None
    lines = code.split("\n") if code else []

    out = []
    out.append(f"# Agent decomposition: {result['function']}")
    out.append(f"# {result['size']} bytes, {result['basic_blocks']} BBs, "
               f"{result['total_phases']} phases")
    out.append("")

    for phase in result["phases"]:
        out.append("=" * 72)
        out.append(f"## Phase {phase['phase']}: {phase['label']}")
        out.append(f"Address range: 0x{phase['start_addr']:08x} - "
                   f"0x{phase['end_addr']:08x}")
        periphs = sorted(phase["peripherals"].items(), key=lambda x: -x[1])
        out.append(f"Peripherals: {', '.join(f'{n} ({c})' for n, c in periphs)}")
        out.append("")

        if phase.get("decompiled_line_range") and lines:
            lr = phase["decompiled_line_range"]
            start_line = max(0, lr[0] - 1)
            end_line = min(len(lines), lr[1])
            out.append("### Decompiled code (approximate slice):")
            out.append("```c")
            for i in range(start_line, end_line):
                out.append(lines[i])
            out.append("```")
            out.append("")

        if phase["registers"]:
            top_regs = sorted(phase["registers"].items(),
                              key=lambda x: -x[1])[:10]
            out.append("### Most-accessed registers:")
            for reg, count in top_regs:
                periph = classify_peripheral(int(reg, 16))
                out.append(f"  {reg} ({periph}): {count} accesses")
            out.append("")

        out.append(f"PROMPT: What does Phase {phase['phase']} of "
                   f"{result['function']} do? It accesses "
                   f"{', '.join(p for p, _ in periphs)}. "
                   f"Describe the hardware configuration being performed.")
        out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_addr(s: str) -> int:
    """Parse an address from hex or decimal string."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return int(s, 16)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decompose a function into phases based on peripheral access patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True,
                        help="Target name (e.g. stock_v120)")
    parser.add_argument("--function", required=True,
                        help="Function address (hex or decimal, e.g. 0x08027a50)")
    parser.add_argument("--gap", type=int, default=DEFAULT_GAP,
                        help=f"Gap threshold in bytes (default: {DEFAULT_GAP})")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--decompiled", action="store_true",
                        help="Include decompiled code line ranges")
    parser.add_argument("--agent-mode", action="store_true",
                        help="Output per-phase prompts for agent consumption")

    args = parser.parse_args()
    func_addr = parse_addr(args.function)

    conn = get_connection()
    result = decompose_function(conn, args.target, func_addr,
                                gap_threshold=args.gap)

    if args.decompiled or args.agent_mode:
        get_decompiled_phases(conn, args.target, func_addr,
                              result.get("phases", []))

    if args.agent_mode:
        print(format_agent_mode(conn, args.target, func_addr, result))
    elif args.json:
        print(format_json(result))
    else:
        print(format_text(result))

    return 0


if __name__ == "__main__":
    sys.exit(main())
