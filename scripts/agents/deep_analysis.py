"""Deep hierarchical firmware analysis — drop in a binary, get a full report.

Orchestrates the complete ripcord pipeline with bottom-up synthesis:

  Level 0 (Leaves):   Unicorn smoke test → propagation (name all functions)
                       → phase decomposition (split large functions)
  Level 1 (Phases):   LLM analyzes each phase independently (Sonnet)
  Level 2 (Groups):   LLM synthesizes phases into subsystem groups (Sonnet)
  Level 3 (Function): LLM synthesizes groups into function narratives (Sonnet)
  Level 4 (Binary):   LLM synthesizes everything into architecture doc (Opus)

Each level only sees the output of the level below — compressed, high-signal
context that lets the model reason about architecture, not raw code.

Usage:
    uv run python scripts/agents/deep_analysis.py \
        --target stock_v120 \
        --build-dir build \
        --binary targets/stock_v120/stock_v120.bin \
        --domain-hint "FNIRSI handheld digital oscilloscope (AT32F403A + FPGA)" \
        --output build/stock_v120/report.md
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path
from uuid import uuid4

import duckdb

# Ensure sibling dirs importable
_AGENTS_DIR = str(Path(__file__).resolve().parent)
_ANALYSIS_DIR = str(Path(__file__).resolve().parent.parent / "analysis")
_VALIDATION_DIR = str(Path(__file__).resolve().parent.parent / "validation")
for d in (_AGENTS_DIR, _ANALYSIS_DIR, _VALIDATION_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from context import register_warehouse, PROVENANCE_INSTRUCTIONS
from worker import log_agent_run


# ---------------------------------------------------------------------------
# Async Claude API
# ---------------------------------------------------------------------------

async def _call_async(client, prompt: str, model: str,
                      sem: asyncio.Semaphore, max_tokens: int = 1024) -> dict:
    async with sem:
        msg = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return {
            "content": msg.content[0].text,
            "input_tokens": msg.usage.input_tokens,
            "output_tokens": msg.usage.output_tokens,
        }


def _run_parallel(prompts: list[str], model: str, concurrency: int,
                  max_tokens: int = 1024) -> list[dict]:
    """Run multiple LLM calls in parallel. Returns list of responses."""
    import anthropic

    async def _go():
        client = anthropic.AsyncAnthropic()
        sem = asyncio.Semaphore(concurrency)
        return await asyncio.gather(*[
            _call_async(client, p, model, sem, max_tokens)
            for p in prompts
        ], return_exceptions=True)

    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

class CostTracker:
    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0
        self.calls = 0

    def add(self, response: dict):
        self.input_tokens += response.get("input_tokens", 0)
        self.output_tokens += response.get("output_tokens", 0)
        self.calls += 1

    @property
    def cost(self) -> float:
        return (self.input_tokens * 3.0 + self.output_tokens * 15.0) / 1_000_000

    def __str__(self):
        return (f"{self.calls} calls, {self.input_tokens} in + "
                f"{self.output_tokens} out = ${self.cost:.4f}")


# ---------------------------------------------------------------------------
# JSON response parser
# ---------------------------------------------------------------------------

def _parse_json(text: str) -> dict:
    import re
    cleaned = text.strip()
    fence = re.search(r"```(?:json)?\s*\n?(.*?)```", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Find outermost braces
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i+1])
                    except json.JSONDecodeError:
                        break
    return {"raw": text[:2000]}


# ---------------------------------------------------------------------------
# Level 0: Foundation (smoke test + propagation + decomposition)
# ---------------------------------------------------------------------------

def run_level0(target: str, build_dir: str, binary_path: str | None,
               base_addr: int, domain_hint: str | None, model: str,
               concurrency: int, max_rounds: int, tasks_per_round: int,
               dry_run: bool) -> dict:
    """Run smoke test + propagation. Returns summary stats."""
    build_path = Path(build_dir)

    # --- Smoke test ---
    smoke_path = build_path / target / "tables" / "unicorn_smoke.parquet"
    if binary_path and not smoke_path.exists():
        print("\n=== Level 0a: Unicorn Smoke Test ===")
        from unicorn_validate import run_smoke_test
        run_smoke_test(target, build_dir, binary_path, base_addr)

    # --- Propagation ---
    print("\n=== Level 0b: Propagation (function naming) ===")
    if not dry_run:
        from propagate import run_propagation
        run_propagation(
            target=target, build_dir=build_dir,
            max_rounds=max_rounds, tasks_per_round=tasks_per_round,
            model=model, domain_hint=domain_hint, dry_run=False,
            concurrency=concurrency, binary_path=binary_path,
            base_addr=base_addr,
        )
    else:
        print("  [DRY RUN] skipping propagation")

    # Count results
    db_path = build_path / "coordination.sqlite"
    conn = sqlite3.connect(str(db_path))
    named = conn.execute(
        "SELECT COUNT(DISTINCT entity_addr) FROM evidence_log "
        "WHERE target=? AND claim_type='name' AND confidence >= 0.50",
        (target,)
    ).fetchone()[0]
    conn.close()

    conn_dk = duckdb.connect(":memory:")
    register_warehouse(conn_dk, build_dir, targets=[target])
    total = conn_dk.execute(
        f"SELECT COUNT(*) FROM functions WHERE source = '{target}'"
    ).fetchone()[0]
    conn_dk.close()

    print(f"\n  Level 0 complete: {named}/{total} functions named")
    return {"named": named, "total": total}


# ---------------------------------------------------------------------------
# Level 1: Leaf phase analysis (reuses analyze_phases.py)
# ---------------------------------------------------------------------------

def run_level1(target: str, build_dir: str, domain_hint: str | None,
               model: str, concurrency: int, min_size: int,
               dry_run: bool) -> list[dict]:
    """Decompose large functions and analyze each phase. Returns phase results."""
    print("\n=== Level 1: Phase Decomposition + Leaf Analysis ===")

    if dry_run:
        print("  [DRY RUN] skipping phase analysis")
        return []

    from analyze_phases import run_phase_analysis
    run_phase_analysis(
        target=target, build_dir=build_dir, model=model,
        domain_hint=domain_hint, min_size=min_size,
        function_addr=None, concurrency=concurrency, dry_run=False,
    )

    # Retrieve phase results from evidence_log
    db_path = Path(build_dir) / "coordination.sqlite"
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        "SELECT entity_addr, claim_json, confidence FROM evidence_log "
        "WHERE target=? AND claim_type='phase_description' "
        "ORDER BY entity_addr, json_extract(claim_json, '$.phase_num')",
        (target,)
    ).fetchall()
    conn.close()

    results = []
    for addr, claim_json, conf in rows:
        claim = json.loads(claim_json)
        claim["function_addr"] = addr
        claim["confidence"] = conf
        results.append(claim)

    print(f"  Level 1 complete: {len(results)} phases analyzed")
    return results


# ---------------------------------------------------------------------------
# Level 2: Subsystem group synthesis (Sonnet)
# ---------------------------------------------------------------------------

def run_level2(phase_results: list[dict], domain_hint: str | None,
               model: str, concurrency: int,
               cost: CostTracker) -> dict[int, dict[str, dict]]:
    """Group phases by function + subsystem, synthesize each group.

    Returns: {function_addr: {subsystem: synthesis_result}}
    """
    print("\n=== Level 2: Subsystem Group Synthesis ===")

    if not phase_results:
        print("  no phases to synthesize")
        return {}

    # Group by (function_addr, subsystem)
    groups: dict[int, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for p in phase_results:
        fn_addr = p["function_addr"]
        subsystem = p.get("subsystem", "other")
        groups[fn_addr][subsystem].append(p)

    # Build synthesis prompts
    prompts = []
    prompt_keys = []  # (fn_addr, subsystem)

    for fn_addr, subsystems in groups.items():
        for subsystem, phases in subsystems.items():
            if len(phases) < 2:
                # Single-phase subsystems don't need synthesis
                continue

            phase_descriptions = []
            for p in sorted(phases, key=lambda x: x.get("phase_num", 0)):
                name = p.get("phase_name", "unknown")
                desc = p.get("description", "")
                data_path = p.get("data_path", "")
                phase_descriptions.append(
                    f"- **Phase {p.get('phase_num', '?')}: {name}**\n"
                    f"  {desc}\n"
                    + (f"  Data path: {data_path}\n" if data_path else "")
                )

            prompt = (
                "You are synthesizing multiple initialization phases that belong "
                "to the same hardware subsystem in an ARM Cortex-M firmware.\n\n"
            )
            if domain_hint:
                prompt += f"Domain: {domain_hint}\n\n"
            prompt += (
                f"## Subsystem: {subsystem}\n"
                f"Function: 0x{fn_addr:08x}\n"
                f"Phases in this group ({len(phases)}):\n\n"
                + "\n".join(phase_descriptions)
                + "\n## Task\n"
                "Synthesize these phases into a coherent subsystem description:\n"
                "1. What is the overall purpose of this subsystem?\n"
                "2. What is the data flow from input to output?\n"
                "3. What are the temporal dependencies (what must happen first)?\n"
                "4. What hardware resources does this subsystem use?\n\n"
                "Respond with JSON:\n"
                '{"subsystem_name": "...", "purpose": "one sentence", '
                '"data_flow": "source → intermediate → destination", '
                '"temporal_order": ["step1", "step2", ...], '
                '"hardware": ["periph1", "periph2", ...], '
                '"confidence": 0.0-1.0}'
            )

            prompts.append(prompt)
            prompt_keys.append((fn_addr, subsystem))

    if not prompts:
        print("  no multi-phase groups to synthesize")
        return {}

    print(f"  {len(prompts)} subsystem groups to synthesize")
    responses = _run_parallel(prompts, model, concurrency)

    # Process responses
    results: dict[int, dict[str, dict]] = defaultdict(dict)
    for (fn_addr, subsystem), resp in zip(prompt_keys, responses):
        if isinstance(resp, Exception) or "error" in resp:
            continue
        cost.add(resp)
        parsed = _parse_json(resp["content"])
        results[fn_addr][subsystem] = parsed
        name = parsed.get("subsystem_name", subsystem)
        purpose = parsed.get("purpose", "")[:100]
        print(f"  0x{fn_addr:08x} [{name}]: {purpose}")

    # Also include single-phase subsystems without synthesis
    for fn_addr, subsystems in groups.items():
        for subsystem, phases in subsystems.items():
            if len(phases) == 1 and subsystem not in results.get(fn_addr, {}):
                p = phases[0]
                results[fn_addr][subsystem] = {
                    "subsystem_name": p.get("phase_name", subsystem),
                    "purpose": p.get("description", ""),
                    "data_flow": p.get("data_path", ""),
                    "confidence": p.get("confidence", 0.5),
                    "single_phase": True,
                }

    print(f"  Level 2 complete: {sum(len(v) for v in results.values())} subsystems")
    return dict(results)


# ---------------------------------------------------------------------------
# Level 3: Function-level synthesis (Sonnet)
# ---------------------------------------------------------------------------

def run_level3(subsystem_results: dict[int, dict[str, dict]],
               domain_hint: str | None, model: str, concurrency: int,
               cost: CostTracker) -> dict[int, dict]:
    """Synthesize subsystem groups into function-level narratives.

    Returns: {function_addr: synthesis_result}
    """
    print("\n=== Level 3: Function-Level Synthesis ===")

    if not subsystem_results:
        print("  no functions to synthesize")
        return {}

    prompts = []
    addrs = []

    for fn_addr, subsystems in subsystem_results.items():
        if len(subsystems) < 2:
            continue

        subsys_descriptions = []
        for subsystem, result in sorted(subsystems.items()):
            name = result.get("subsystem_name", subsystem)
            purpose = result.get("purpose", "")
            data_flow = result.get("data_flow", "")
            temporal = result.get("temporal_order", [])
            subsys_descriptions.append(
                f"### {name.upper()}\n"
                f"Purpose: {purpose}\n"
                + (f"Data flow: {data_flow}\n" if data_flow else "")
                + (f"Sequence: {' → '.join(temporal)}\n" if temporal else "")
            )

        prompt = (
            "You are synthesizing a complete firmware function from its "
            "analyzed subsystems.\n\n"
        )
        if domain_hint:
            prompt += f"Domain: {domain_hint}\n\n"
        prompt += (
            f"## Function at 0x{fn_addr:08x}\n"
            f"Contains {len(subsystems)} subsystems:\n\n"
            + "\n".join(subsys_descriptions)
            + "\n## Task\n"
            "Produce a complete narrative of what this function does:\n"
            "1. Boot/init sequence from first instruction to last\n"
            "2. Cross-subsystem dependencies\n"
            "3. What state the system is in when this function returns\n"
            "4. Any prerequisites or post-conditions\n\n"
            "Respond with JSON:\n"
            '{"function_purpose": "one sentence", '
            '"boot_sequence": ["step1", "step2", ...], '
            '"cross_dependencies": ["dep1", "dep2", ...], '
            '"system_state_after": "description of system state when function returns", '
            '"confidence": 0.0-1.0}'
        )

        prompts.append(prompt)
        addrs.append(fn_addr)

    if not prompts:
        print("  no multi-subsystem functions to synthesize")
        return {}

    print(f"  {len(prompts)} functions to synthesize")
    responses = _run_parallel(prompts, model, concurrency)

    results = {}
    for fn_addr, resp in zip(addrs, responses):
        if isinstance(resp, Exception) or "error" in resp:
            continue
        cost.add(resp)
        parsed = _parse_json(resp["content"])
        results[fn_addr] = parsed
        purpose = parsed.get("function_purpose", "")[:120]
        print(f"  0x{fn_addr:08x}: {purpose}")

    print(f"  Level 3 complete: {len(results)} function narratives")
    return results


# ---------------------------------------------------------------------------
# Level 4: Binary-level architectural synthesis (Opus)
# ---------------------------------------------------------------------------

def run_level4(target: str, build_dir: str, domain_hint: str | None,
               function_syntheses: dict[int, dict],
               subsystem_results: dict[int, dict[str, dict]],
               level0_stats: dict,
               model: str, cost: CostTracker) -> str:
    """Final architectural synthesis — one Opus call.

    Returns the synthesis text.
    """
    print("\n=== Level 4: Architectural Synthesis (Opus) ===")

    # Gather all evidence into a dense summary
    sections = []

    if domain_hint:
        sections.append(f"## Domain\n{domain_hint}")

    sections.append(
        f"## Binary overview\n"
        f"- {level0_stats['total']} functions total\n"
        f"- {level0_stats['named']} named by LLM analysis"
    )

    # Module info if available
    db_path = Path(build_dir) / "coordination.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        modules = conn.execute(
            "SELECT module_name, description, function_count, confidence "
            "FROM modules WHERE target=? ORDER BY function_count DESC",
            (target,)
        ).fetchall()
        if modules:
            lines = ["## Modules detected"]
            for name, desc, count, conf in modules:
                lines.append(f"- **{name}** ({count} functions): {desc}")
            sections.append("\n".join(lines))
    except sqlite3.OperationalError:
        pass

    # Function-level syntheses
    if function_syntheses:
        lines = ["## Key function analyses"]
        for fn_addr, synth in function_syntheses.items():
            purpose = synth.get("function_purpose", "")
            boot_seq = synth.get("boot_sequence", [])
            deps = synth.get("cross_dependencies", [])
            state = synth.get("system_state_after", "")

            lines.append(f"\n### Function 0x{fn_addr:08x}")
            lines.append(f"Purpose: {purpose}")
            if boot_seq:
                lines.append("Boot sequence:")
                for i, step in enumerate(boot_seq, 1):
                    lines.append(f"  {i}. {step}")
            if deps:
                lines.append(f"Cross-dependencies: {'; '.join(deps)}")
            if state:
                lines.append(f"System state after: {state}")
        sections.append("\n".join(lines))

    # Subsystem details for functions without full synthesis
    if subsystem_results:
        for fn_addr, subsystems in subsystem_results.items():
            if fn_addr in function_syntheses:
                continue  # already covered
            lines = [f"\n### Function 0x{fn_addr:08x} subsystems"]
            for subsystem, result in subsystems.items():
                name = result.get("subsystem_name", subsystem)
                purpose = result.get("purpose", "")
                data_flow = result.get("data_flow", "")
                lines.append(f"- **{name}**: {purpose}")
                if data_flow:
                    lines.append(f"  Data flow: {data_flow}")
            sections.append("\n".join(lines))

    # Top named functions
    top_names = conn.execute(
        "SELECT printf('0x%08x', entity_addr), "
        "json_extract(claim_json, '$.name'), MAX(confidence) "
        "FROM evidence_log WHERE target=? AND claim_type='name' "
        "AND confidence >= 0.70 GROUP BY entity_addr "
        "ORDER BY MAX(confidence) DESC LIMIT 30",
        (target,)
    ).fetchall()
    conn.close()

    if top_names:
        lines = ["## Top named functions (highest confidence)"]
        for addr, name, conf in top_names:
            lines.append(f"- {addr}: {name} (conf={conf:.2f})")
        sections.append("\n".join(lines))

    # Build the Opus prompt
    evidence = "\n\n".join(sections)

    prompt = (
        "You are a senior firmware architect producing the definitive "
        "architectural analysis of a complete firmware binary. All the "
        "evidence below was produced by automated analysis tools and "
        "LLM-assisted reverse engineering.\n\n"
        f"{evidence}\n\n"
        "## Task\n"
        "Produce a comprehensive firmware architecture document covering:\n\n"
        "1. **System overview**: What is this device? What does it do?\n"
        "2. **Hardware architecture**: MCU, peripherals, external devices, "
        "communication buses\n"
        "3. **Software architecture**: RTOS tasks, interrupt handlers, "
        "main loop structure\n"
        "4. **Signal/data paths**: How does data flow from input (sensors, "
        "ADC, FPGA) through processing to output (display, USB, storage)?\n"
        "5. **Boot sequence**: What happens from reset to operational state?\n"
        "6. **Key subsystems**: For each major subsystem, describe its "
        "purpose, interfaces, and dependencies\n"
        "7. **Open questions**: What aspects of the firmware remain "
        "unclear or need hardware verification?\n\n"
        "Write in clear technical prose. Use headers. Be specific about "
        "register addresses, data formats, and timing. This document will "
        "be used by engineers working on a clean-room replacement firmware."
    )

    print(f"  Synthesis prompt: {len(prompt)} chars")

    responses = _run_parallel([prompt], model, 1, max_tokens=4096)
    resp = responses[0]

    if isinstance(resp, Exception):
        print(f"  ERROR: {resp}")
        return f"Synthesis failed: {resp}"

    cost.add(resp)
    text = resp["content"]
    print(f"  Synthesis complete: {len(text)} chars, "
          f"{resp['input_tokens']}+{resp['output_tokens']} tokens")

    return text


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def write_report(output_path: str, synthesis: str, target: str,
                 domain_hint: str | None, cost: CostTracker,
                 level0_stats: dict):
    """Write the final markdown report."""
    with open(output_path, "w") as f:
        f.write(f"# Firmware Architecture: {target}\n\n")
        if domain_hint:
            f.write(f"*Domain: {domain_hint}*\n\n")
        f.write(
            f"*Generated by ripcord deep analysis pipeline. "
            f"{level0_stats['named']}/{level0_stats['total']} functions analyzed. "
            f"Total cost: ${cost.cost:.2f} ({cost.calls} LLM calls).*\n\n"
            f"---\n\n"
        )
        f.write(synthesis)
        f.write("\n")

    print(f"\n  Report written to {output_path}")


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Deep hierarchical firmware analysis — full pipeline"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--binary", help="Firmware binary for Unicorn smoke test")
    parser.add_argument("--base-addr", type=lambda x: int(x, 0), default=0x08000000)
    parser.add_argument("--domain-hint", help="e.g. 'FNIRSI digital oscilloscope'")
    parser.add_argument("--output", help="Output report path (markdown)")
    # Model selection
    parser.add_argument("--model", default="claude-sonnet-4-6",
                        help="Model for levels 0-3 (default: Sonnet)")
    parser.add_argument("--synthesis-model", default="claude-opus-4-8",
                        help="Model for level 4 synthesis (default: Opus)")
    # Tuning
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--max-rounds", type=int, default=4)
    parser.add_argument("--tasks-per-round", type=int, default=50)
    parser.add_argument("--min-fn-size", type=int, default=2000,
                        help="Min function size for phase decomposition")
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    output_path = args.output or f"build/{args.target}/report.md"

    cost = CostTracker()
    t_start = time.monotonic()

    print("=" * 60)
    print(f"  RIPCORD DEEP ANALYSIS: {args.target}")
    print("=" * 60)
    if args.domain_hint:
        print(f"  Domain: {args.domain_hint}")
    print(f"  Models: {args.model} (L0-L3), {args.synthesis_model} (L4)")
    print()

    # --- Level 0: Foundation ---
    level0_stats = run_level0(
        target=args.target, build_dir=args.build_dir,
        binary_path=args.binary, base_addr=args.base_addr,
        domain_hint=args.domain_hint, model=args.model,
        concurrency=args.concurrency, max_rounds=args.max_rounds,
        tasks_per_round=args.tasks_per_round, dry_run=args.dry_run,
    )

    # --- Level 1: Leaf phase analysis ---
    phase_results = run_level1(
        target=args.target, build_dir=args.build_dir,
        domain_hint=args.domain_hint, model=args.model,
        concurrency=args.concurrency, min_size=args.min_fn_size,
        dry_run=args.dry_run,
    )

    # --- Level 2: Subsystem group synthesis ---
    subsystem_results = {}
    if phase_results and not args.dry_run:
        subsystem_results = run_level2(
            phase_results, args.domain_hint, args.model,
            args.concurrency, cost,
        )

    # --- Level 3: Function-level synthesis ---
    function_syntheses = {}
    if subsystem_results and not args.dry_run:
        function_syntheses = run_level3(
            subsystem_results, args.domain_hint, args.model,
            args.concurrency, cost,
        )

    # --- Level 4: Architectural synthesis (Opus) ---
    synthesis = ""
    if not args.dry_run:
        synthesis = run_level4(
            target=args.target, build_dir=args.build_dir,
            domain_hint=args.domain_hint,
            function_syntheses=function_syntheses,
            subsystem_results=subsystem_results,
            level0_stats=level0_stats,
            model=args.synthesis_model, cost=cost,
        )

        # Write report
        write_report(output_path, synthesis, args.target,
                     args.domain_hint, cost, level0_stats)

    # --- Final summary ---
    elapsed = time.monotonic() - t_start
    print(f"\n{'=' * 60}")
    print(f"  DEEP ANALYSIS COMPLETE: {args.target}")
    print(f"{'=' * 60}")
    print(f"  Total wall time:  {elapsed:.0f}s ({elapsed/60:.1f}m)")
    print(f"  Level 0 (naming): {level0_stats['named']}/{level0_stats['total']} functions")
    print(f"  Level 1 (phases): {len(phase_results)} phases analyzed")
    print(f"  Level 2 (groups): {sum(len(v) for v in subsystem_results.values())} subsystems")
    print(f"  Level 3 (funcs):  {len(function_syntheses)} function narratives")
    print(f"  Level 4 (binary): {'done' if synthesis else 'skipped'}")
    print(f"  Total LLM cost:   {cost}")
    if not args.dry_run:
        print(f"  Report: {output_path}")


if __name__ == "__main__":
    main()
