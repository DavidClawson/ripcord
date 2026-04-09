"""Recursive phase analysis for large firmware functions.

Automatically detects functions above a size threshold, decomposes
them into peripheral-coherent phases using the decomposer, and sends
each phase to the LLM for focused analysis. Produces per-phase
descriptions that reveal hardware configuration details hidden inside
monolithic init/driver functions.

Designed to run after propagation: propagation names all functions
(breadth-first), then phase analysis goes deep on the big ones.

Usage:
    uv run python scripts/agents/analyze_phases.py \
        --target stock_v120 \
        --build-dir build \
        --model claude-sonnet-4-20250514 \
        --domain-hint "FNIRSI handheld digital oscilloscope" \
        --min-size 2000

    # Analyze a specific function:
    uv run python scripts/agents/analyze_phases.py \
        --target stock_v120 \
        --build-dir build \
        --function 0x08027a50
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
import time
from pathlib import Path
from uuid import uuid4

import duckdb

# Ensure sibling dirs importable
_AGENTS_DIR = str(Path(__file__).resolve().parent)
_ANALYSIS_DIR = str(Path(__file__).resolve().parent.parent / "analysis")
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)
if _ANALYSIS_DIR not in sys.path:
    sys.path.insert(0, _ANALYSIS_DIR)

from context import register_warehouse, PROVENANCE_INSTRUCTIONS
from worker import parse_proposal, complete_task, fail_task, log_agent_run
from decompose import decompose_function, get_decompiled_phases, get_connection


# ---------------------------------------------------------------------------
# Async Claude API call (same pattern as propagate.py)
# ---------------------------------------------------------------------------

async def _call_claude_async(client, prompt: str, model: str,
                              semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        message = await client.messages.create(
            model=model,
            max_tokens=1024,  # phases need more room for detailed descriptions
            messages=[{"role": "user", "content": prompt}],
        )
        return {
            "content": message.content[0].text,
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens,
        }


# ---------------------------------------------------------------------------
# Phase prompt builder
# ---------------------------------------------------------------------------

def build_phase_prompt(
    function_name: str,
    function_addr: int,
    function_size: int,
    phase: dict,
    decompiled_lines: list[str] | None,
    domain_hint: str | None,
    total_phases: int,
) -> str:
    """Build an LLM prompt for analyzing a single phase of a large function."""
    sections = []

    sections.append(
        "You are a firmware reverse engineer analyzing a specific PHASE "
        "of a large initialization function in a stripped ARM Cortex-M binary. "
        "Focus on the hardware configuration in THIS phase only."
    )

    sections.append(PROVENANCE_INSTRUCTIONS.strip())

    if domain_hint:
        sections.append(
            f"## Domain context\n"
            f"This binary is from: {domain_hint}"
        )

    # Function context
    sections.append(
        f"## Parent function\n"
        f"Function: {function_name} at 0x{function_addr:08x}\n"
        f"Total size: {function_size} bytes\n"
        f"This is phase {phase['phase']} of {total_phases} phases."
    )

    # Phase details
    start = f"0x{phase['start_addr']:08x}"
    end = f"0x{phase['end_addr']:08x}"
    span = phase['end_addr'] - phase['start_addr']

    sections.append(
        f"## Phase {phase['phase']}: {phase['label']}\n"
        f"Address range: {start} - {end} (~{span} bytes)\n"
        f"Total peripheral accesses: {phase['access_count']}"
    )

    # Peripherals
    periphs = sorted(phase["peripherals"].items(), key=lambda x: -x[1])
    lines = ["## Peripherals accessed"]
    for name, count in periphs:
        lines.append(f"- {name}: {count} accesses")
    sections.append("\n".join(lines))

    # Key registers
    if phase.get("registers"):
        top_regs = sorted(phase["registers"].items(), key=lambda x: -x[1])[:15]
        lines = ["## Key registers (most accessed)"]
        for reg_addr_str, count in top_regs:
            # Decode register address to name if possible
            addr_val = int(reg_addr_str, 16)
            reg_name = _decode_register(addr_val)
            lines.append(f"- {reg_addr_str} ({reg_name}): {count} accesses")
        sections.append("\n".join(lines))

    # Trailing calls (sub-functions called after this phase)
    if phase.get("gap_calls"):
        names = list(dict.fromkeys(c["callee_name"] for c in phase["gap_calls"]))
        sections.append(
            f"## Functions called after this phase\n"
            + "\n".join(f"- {n}" for n in names[:10])
        )

    # Decompiled C slice
    if decompiled_lines and phase.get("decompiled_line_range"):
        lr = phase["decompiled_line_range"]
        start_line = max(0, lr[0] - 1)
        end_line = min(len(decompiled_lines), lr[1])
        code_slice = "\n".join(decompiled_lines[start_line:end_line])
        if len(code_slice) > 12000:
            code_slice = code_slice[:12000] + "\n// ... truncated"
        sections.append(f"## Decompiled C (phase slice)\n```c\n{code_slice}\n```")

    # Task instruction
    sections.append(
        f"## Task\n"
        f"Analyze Phase {phase['phase']} of {function_name}. Describe:\n"
        f"1. What hardware peripheral(s) this phase configures\n"
        f"2. The specific register values and what they mean\n"
        f"3. What data path or functionality this enables\n"
        f"4. Any DMA source/dest addresses and what they connect\n"
        f"5. Whether this phase relates to signal acquisition, display, "
        f"communication, or other subsystem\n\n"
        f"Respond with JSON:\n"
        '{"phase_name": "descriptive_name", '
        '"description": "One paragraph describing what this phase does", '
        '"peripheral_config": {"register": "value and meaning", ...}, '
        '"data_path": "source → destination description if applicable", '
        '"subsystem": "acquisition|display|communication|timing|power|other", '
        '"confidence": 0.0-1.0, '
        '"provenance": "decompile-derived|synthesized-model|hypothesis", '
        '"reasoning": "..."}'
    )

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# AT32F403A register decoder (common registers)
# ---------------------------------------------------------------------------

_REGISTER_NAMES = {
    # DMA1
    0x40020000: "DMA1_STS", 0x40020004: "DMA1_CLR",
    0x4002001C: "DMA1_C2CTRL", 0x40020020: "DMA1_C2DTCNT",
    0x40020024: "DMA1_C2MADDR", 0x40020028: "DMA1_C2PADDR",
    # DMA2
    0x40020400: "DMA2_STS", 0x40020404: "DMA2_CLR",
    0x40020440: "DMA2_C4CTRL", 0x40020444: "DMA2_C4CTRL",
    0x40020448: "DMA2_C4DTCNT", 0x4002044C: "DMA2_C4DTCNT",
    0x40020450: "DMA2_C4PADDR", 0x40020454: "DMA2_C4MADDR",
    0x400204A0: "DMA2_DMA_SRC_SEL0", 0x400204A4: "DMA2_DMA_SRC_SEL1",
    # SPI3
    0x40003C00: "SPI3_CTRL1", 0x40003C04: "SPI3_CTRL2",
    0x40003C08: "SPI3_STS", 0x40003C0C: "SPI3_DT",
    # SPI2
    0x40003800: "SPI2_CTRL1", 0x40003804: "SPI2_CTRL2",
    0x40003808: "SPI2_STS", 0x4000380C: "SPI2_DT",
    # SPI1
    0x40013400: "SPI1_CTRL1", 0x40013404: "SPI1_CTRL2",
    0x40013408: "SPI1_STS", 0x4001340C: "SPI1_DT",
    # USART2
    0x40004400: "USART2_STS", 0x40004404: "USART2_DT",
    0x40004408: "USART2_BAUDR", 0x4000440C: "USART2_CTRL1",
    0x40004410: "USART2_CTRL2", 0x40004414: "USART2_CTRL3",
    # CRM/RCC
    0x40021000: "CRM_CTRL", 0x40021004: "CRM_CFG",
    0x40021008: "CRM_CLKINT", 0x4002100C: "CRM_APB2RST",
    0x40021010: "CRM_APB1RST", 0x40021014: "CRM_AHBEN",
    0x40021018: "CRM_APB2EN", 0x4002101C: "CRM_APB1EN",
    0x40021028: "CRM_MISC1", 0x40021030: "CRM_MISC2",
    0x40021054: "CRM_MISC3",
    # FSMC
    0x6001FFFE: "FSMC_CMD (LCD/FPGA)", 0x60020000: "FSMC_DATA (LCD/FPGA)",
    # DAC
    0x40007408: "DAC_CTRL", 0x40007414: "DAC_D1DTH12R",
    # System
    0xE000E010: "SYSTICK_CTRL", 0xE000E014: "SYSTICK_LOAD",
    0xE000E018: "SYSTICK_VAL",
    0xE000E100: "NVIC_ISER0", 0xE000E104: "NVIC_ISER1",
    0xE000ED04: "SCB_ICSR", 0xE000ED08: "SCB_VTOR",
    0xE000ED0C: "SCB_AIRCR",
}


def _decode_register(addr: int) -> str:
    """Decode a peripheral register address to a human-readable name."""
    if addr in _REGISTER_NAMES:
        return _REGISTER_NAMES[addr]

    # Generic peripheral family detection
    if 0x40020000 <= addr < 0x40020400:
        return f"DMA1+{addr - 0x40020000:#x}"
    if 0x40020400 <= addr < 0x40020800:
        return f"DMA2+{addr - 0x40020400:#x}"
    if 0x40003C00 <= addr < 0x40004000:
        return f"SPI3+{addr - 0x40003C00:#x}"
    if 0x40021000 <= addr < 0x40021100:
        return f"CRM+{addr - 0x40021000:#x}"
    if 0xE000E000 <= addr < 0xE000F000:
        return f"NVIC+{addr - 0xE000E000:#x}"

    return f"0x{addr:08x}"


# ---------------------------------------------------------------------------
# Phase response parser
# ---------------------------------------------------------------------------

def _parse_phase_response(text: str) -> dict:
    """Parse LLM phase analysis response."""
    import re

    cleaned = text.strip()
    fence = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Try finding JSON object
    brace_start = cleaned.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(cleaned)):
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[brace_start:i + 1])
                    except json.JSONDecodeError:
                        break

    return {
        "phase_name": "parse_failed",
        "description": text[:500],
        "confidence": 0.3,
        "reasoning": "failed to parse JSON response",
    }


# ---------------------------------------------------------------------------
# Main analysis flow
# ---------------------------------------------------------------------------

def run_phase_analysis(
    target: str,
    build_dir: str,
    model: str,
    domain_hint: str | None,
    min_size: int,
    function_addr: int | None,
    concurrency: int,
    dry_run: bool,
) -> None:
    """Analyze phases of large functions."""
    build_path = Path(build_dir)
    db_path = str(build_path / "coordination.sqlite")

    print(f"analyze_phases: target={target}, min_size={min_size}")
    print(f"analyze_phases: model={model}, concurrency={concurrency}")
    if domain_hint:
        print(f"analyze_phases: domain_hint={domain_hint!r}")
    print()

    # Connect to warehouse (using decomposer's connection helper)
    conn_duckdb = get_connection()

    # Connect to coordination DB
    db = Path(db_path)
    if not db.exists():
        print(f"analyze_phases: creating coordination DB at {db_path}")
        db.parent.mkdir(parents=True, exist_ok=True)
        conn_init = sqlite3.connect(db_path)
        conn_init.execute("PRAGMA journal_mode=WAL")
        from init_db import SCHEMA_SQL
        conn_init.executescript(SCHEMA_SQL)
        conn_init.close()

    conn_sqlite = sqlite3.connect(db_path)
    conn_sqlite.execute("PRAGMA journal_mode=WAL")

    # Ensure describe_phase kind is supported (migrate if needed)
    try:
        conn_sqlite.execute(
            "INSERT INTO tasks (kind, target, entity_addr) "
            "VALUES ('describe_phase', 'test', 0)")
        conn_sqlite.execute("DELETE FROM tasks WHERE target='test'")
        conn_sqlite.commit()
    except sqlite3.IntegrityError:
        print("WARNING: describe_phase task kind not in schema. "
              "Run init_db.py to update, or recreate coordination.sqlite.")
        conn_sqlite.close()
        return

    # Find large functions to decompose
    if function_addr is not None:
        rows = conn_duckdb.execute(
            f"SELECT addr, name, size FROM functions "
            f"WHERE source = '{target}' AND addr = {function_addr}"
        ).fetchall()
    else:
        rows = conn_duckdb.execute(
            f"SELECT addr, name, size FROM functions "
            f"WHERE source = '{target}' AND size >= {min_size} "
            f"ORDER BY size DESC"
        ).fetchall()

    if not rows:
        print("  no functions match criteria")
        return

    print(f"  {len(rows)} functions to decompose (>= {min_size} bytes)")

    # Get decompiled C for all target functions
    decompiled_cache: dict[int, list[str]] = {}
    for addr, name, size in rows:
        row = conn_duckdb.execute(
            f"SELECT decompiled_c FROM decompiled "
            f"WHERE source = '{target}' AND addr = {addr}"
        ).fetchone()
        if row and row[0]:
            decompiled_cache[addr] = row[0].split("\n")

    # Decompose each function and collect all phase tasks
    all_tasks: list[dict] = []  # (function info + phase info + prompt)

    for addr, name, size in rows:
        name = name or f"FUN_{addr:08x}"
        print(f"\n  Decomposing {name} (0x{addr:08x}, {size} bytes)...")

        result = decompose_function(conn_duckdb, target, addr)

        if not result.get("phases"):
            print(f"    no phases detected (no peripheral xrefs)")
            continue

        # Enrich with decompiled line ranges
        get_decompiled_phases(conn_duckdb, target, addr, result["phases"])

        total_phases = result["total_phases"]
        print(f"    {total_phases} phases found")

        for phase in result["phases"]:
            # Skip tiny phases (< 5 peripheral accesses)
            if phase["access_count"] < 5:
                continue

            prompt = build_phase_prompt(
                function_name=name,
                function_addr=addr,
                function_size=size,
                phase=phase,
                decompiled_lines=decompiled_cache.get(addr),
                domain_hint=domain_hint,
                total_phases=total_phases,
            )

            all_tasks.append({
                "function_addr": addr,
                "function_name": name,
                "phase_num": phase["phase"],
                "phase_label": phase["label"],
                "prompt": prompt,
                "phase": phase,
            })

    if not all_tasks:
        print("\n  no phases to analyze")
        conn_sqlite.close()
        conn_duckdb.close()
        return

    print(f"\n  Total phase tasks: {len(all_tasks)}")

    # --- Dry run ---
    if dry_run:
        for t in all_tasks:
            print(f"  {t['function_name']} Phase {t['phase_num']}: "
                  f"{t['phase_label']} ({len(t['prompt'])} chars)")
        conn_sqlite.close()
        conn_duckdb.close()
        return

    # --- Parallel LLM calls ---
    import anthropic

    async def _run_all():
        client = anthropic.AsyncAnthropic()
        sem = asyncio.Semaphore(concurrency)
        coros = [
            _call_claude_async(client, t["prompt"], model, sem)
            for t in all_tasks
        ]
        return await asyncio.gather(*coros, return_exceptions=True)

    print(f"\n  Calling LLM ({len(all_tasks)} tasks, concurrency={concurrency})...")
    t0 = time.monotonic()
    responses = asyncio.run(_run_all())
    wall_time = time.monotonic() - t0

    # --- Process responses ---
    agent_id = f"phase-analyzer-{uuid4().hex[:8]}"
    total_input = 0
    total_output = 0
    success_count = 0

    for task, response in zip(all_tasks, responses):
        fn_name = task["function_name"]
        phase_num = task["phase_num"]
        label = task["phase_label"]

        if isinstance(response, Exception):
            print(f"  {fn_name} Phase {phase_num}: ERROR {response}")
            continue

        if "error" in response:
            print(f"  {fn_name} Phase {phase_num}: ERROR {response['error']}")
            continue

        total_input += response["input_tokens"]
        total_output += response["output_tokens"]

        result = _parse_phase_response(response["content"])
        phase_name = result.get("phase_name", label)
        description = result.get("description", "")
        subsystem = result.get("subsystem", "other")
        confidence = float(result.get("confidence", 0.5))
        data_path = result.get("data_path", "")

        print(f"  {fn_name} Phase {phase_num}: {phase_name} "
              f"[{subsystem}] conf={confidence:.2f}")
        if data_path:
            print(f"    data path: {data_path}")
        if description:
            desc_preview = description[:120] + "..." if len(description) > 120 else description
            print(f"    {desc_preview}")

        # Write to evidence_log
        claim = {
            "phase_num": phase_num,
            "phase_name": phase_name,
            "phase_label": label,
            "description": description,
            "subsystem": subsystem,
            "data_path": data_path,
            "peripheral_config": result.get("peripheral_config", {}),
            "reasoning": result.get("reasoning", ""),
        }
        conn_sqlite.execute("""
            INSERT INTO evidence_log
                (target, entity_addr, agent_id, claim_type,
                 claim_json, confidence, evidence_method)
            VALUES (?, ?, ?, 'phase_description', ?, ?, ?)
        """, (
            target,
            task["function_addr"],
            agent_id,
            json.dumps(claim),
            confidence,
            result.get("provenance", "decompile-derived"),
        ))
        success_count += 1

    conn_sqlite.commit()

    # --- Summary ---
    cost = (total_input * 3.0 + total_output * 15.0) / 1_000_000

    print(f"\n{'='*60}")
    print(f"  Phase Analysis Complete: {target}")
    print(f"{'='*60}")
    print(f"  functions decomposed: {len(rows)}")
    print(f"  phases analyzed:      {success_count}/{len(all_tasks)}")
    print(f"  wall time:            {wall_time:.1f}s")
    print(f"  tokens:               {total_input} in + {total_output} out")
    print(f"  cost:                 ${cost:.4f}")

    # Log agent run
    try:
        log_agent_run(
            conn_sqlite, agent_id, model, success_count,
            total_input, total_output, cost,
        )
    except Exception as exc:
        print(f"  WARNING: failed to log agent run: {exc}")

    conn_sqlite.close()
    conn_duckdb.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Recursive phase analysis for large firmware functions"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--model", default="claude-sonnet-4-20250514")
    parser.add_argument("--domain-hint")
    parser.add_argument("--min-size", type=int, default=2000,
                        help="Min function size in bytes to decompose (default: 2000)")
    parser.add_argument("--function", type=lambda x: int(x, 0),
                        help="Analyze a specific function (hex addr)")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_phase_analysis(
        target=args.target,
        build_dir=args.build_dir,
        model=args.model,
        domain_hint=args.domain_hint,
        min_size=args.min_size,
        function_addr=args.function,
        concurrency=args.concurrency,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
