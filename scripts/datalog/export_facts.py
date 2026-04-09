#!/usr/bin/env -S uv run python
"""Export base facts from the ripcord warehouse for Souffle consumption.

For each target with a calls table, writes:
  build/<target>/datalog/calls.facts      (caller_addr, callee_addr)
  build/<target>/datalog/functions.facts   (addr, name)

The calls.facts file includes both static call edges AND implied edges
recovered from function-pointer dispatch heuristics (xTaskCreate
dispatch, runtime_init chains, vtable population, ISR handler
registration, etc.). See notes/queries/computed_calls.sql for the
full set of heuristics.

These are tab-separated, no header, matching the .input declarations
in reachability.dl.

Usage:
    scripts/datalog/export_facts.py                  # all targets
    scripts/datalog/export_facts.py pico_freertos_hello  # one target
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"
QUERY_SCRIPT = REPO_ROOT / "scripts" / "query"


# ---------------------------------------------------------------------------
# Implied-edge SQL for pico_freertos_hello (and similar FreeRTOS targets)
# ---------------------------------------------------------------------------
# This is the B1-B11+C set from notes/queries/computed_calls.sql,
# expressed as a single SELECT returning (from_addr, to_addr).

IMPLIED_EDGES_SQL = """
-- B1: runtime_init -> runtime_init_* and __aeabi_*_init (function-pointer table dispatch)
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = 'runtime_init'),
    f.addr
FROM functions f
WHERE f.source = '{target}'
  AND (f.name LIKE 'runtime!_init!_%' ESCAPE '!'
       OR f.name IN ('__aeabi_bits_init', '__aeabi_double_init',
                     '__aeabi_float_init', '__aeabi_mem_init',
                     'first_per_core_initializer'))

UNION ALL

-- B2: vTaskStartScheduler -> prvIdleTask, prvTimerTask
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = 'vTaskStartScheduler'),
    f.addr
FROM functions f
WHERE f.source = '{target}' AND f.name IN ('prvIdleTask', 'prvTimerTask')

UNION ALL

-- B3: xTaskCreate callers -> known task bodies
SELECT c.caller_addr, task.addr
FROM calls c
JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
JOIN functions task ON task.source = c.source
WHERE c.source = '{target}' AND f.name = 'xTaskCreate'
  AND task.name IN ('blink_task','main_task','async_context_task','do_work','end_task_func')

UNION ALL

-- B4: async_context_freertos_init -> async_context_freertos_* vtable
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = 'async_context_freertos_init'),
    f.addr
FROM functions f
WHERE f.source = '{target}'
  AND f.name LIKE 'async!_context!_freertos!_%' ESCAPE '!'
  AND f.name != 'async_context_freertos_init'

UNION ALL

-- B5: __aeabi_*_init -> math shim functions
SELECT init_fn.addr, shim_fn.addr
FROM functions init_fn, functions shim_fn
WHERE init_fn.source = '{target}' AND shim_fn.source = '{target}'
  AND (
    (init_fn.name = '__aeabi_double_init' AND shim_fn.name IN (
        'dadd_shim','dsub_shim','dmul_shim','ddiv_shim','drsub_shim',
        'dunpacks','double_table_shim_on_use_helper',
        'double2ufix_shim','double2ufix64_shim',
        'double2uint_shim','double2uint64_shim','d2fix','d2fix_a'))
    OR (init_fn.name = '__aeabi_float_init' AND shim_fn.name IN (
        'float_table_shim_on_use_helper'))
    OR (init_fn.name = '__aeabi_mem_init' AND shim_fn.name IN (
        '__wrap_memcpy'))
    OR (init_fn.name = '__aeabi_bits_init' AND shim_fn.name IN (
        'rom_funcs_lookup','rom_func_lookup','rom_data_lookup'))
  )

UNION ALL

-- B6: stdio_put_string -> stdio driver callbacks
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = 'stdio_put_string'),
    f.addr
FROM functions f
WHERE f.source = '{target}'
  AND f.name IN ('stdio_uart_out_chars','stdio_uart_out_flush',
                 'stdio_uart_in_chars','stdio_uart_set_chars_available_callback',
                 'stdio_out_chars_no_crlf','stdio_buffered_printer')

UNION ALL

-- B7: _vsnprintf -> output callbacks
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = '_vsnprintf'),
    f.addr
FROM functions f
WHERE f.source = '{target}' AND f.name IN ('_out_char','_out_fct')

UNION ALL

-- B8: alarm/timer callbacks
SELECT caller.addr, handler.addr
FROM functions caller, functions handler
WHERE caller.source = '{target}' AND handler.source = '{target}'
  AND (
    (caller.name = 'async_context_freertos_add_at_time_worker'
     AND handler.name IN ('timer_handler','alarm_pool_irq_handler','sleep_until_callback'))
    OR (caller.name = 'runtime_init_default_alarm_pool'
        AND handler.name IN ('alarm_pool_irq_handler','timer_hardware_alarm_claim'))
  )

UNION ALL

-- B9: prvTimerTask -> timer callback dispatch
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = 'prvTimerTask'),
    f.addr
FROM functions f
WHERE f.source = '{target}'
  AND f.name IN ('vEventGroupSetBitsCallback','xTimerGenericCommandFromTask')

UNION ALL

-- B10: IRQ handler chain dispatch
SELECT
    (SELECT addr FROM functions WHERE source = '{target}' AND name = 'irq_handler_chain_first_slot'),
    f.addr
FROM functions f
WHERE f.source = '{target}'
  AND f.name IN ('prvFIFOInterruptHandler','on_uart_rx','alarm_pool_irq_handler')

UNION ALL

-- B11: veneer trampolines -> their targets
SELECT x.function_addr, x.to_addr
FROM xrefs x
JOIN functions f_from ON f_from.source = x.source AND f_from.addr = x.function_addr
JOIN functions f_to ON f_to.source = x.source AND f_to.addr = x.to_addr
WHERE x.source = '{target}'
  AND x.ref_type = 'COMPUTED_JUMP'
  AND f_from.name LIKE '%veneer%'

UNION ALL

-- C: Data xrefs pointing to function entry points
SELECT x.function_addr, x.to_addr
FROM xrefs x
JOIN functions f_to ON f_to.source = x.source AND f_to.addr = x.to_addr
WHERE x.source = '{target}'
  AND x.ref_type IN ('DATA','PARAM','WRITE')
"""


def export_target(target: str) -> None:
    datalog_dir = BUILD_DIR / target / "datalog"
    datalog_dir.mkdir(parents=True, exist_ok=True)

    calls_path = datalog_dir / "calls.facts"
    functions_path = datalog_dir / "functions.facts"

    import subprocess

    # Export call edges (static + implied)
    implied_sql = IMPLIED_EDGES_SQL.format(target=target)
    subprocess.run(
        [
            str(QUERY_SCRIPT),
            f"""COPY (
                SELECT caller_addr AS c1, callee_addr AS c2
                FROM calls
                WHERE source = '{target}'
                  AND callee_addr IS NOT NULL
                UNION
                SELECT implied.from_addr, implied.to_addr FROM (
                    {implied_sql}
                ) implied(from_addr, to_addr)
                WHERE implied.from_addr IS NOT NULL AND implied.to_addr IS NOT NULL
            ) TO '{calls_path}'
            WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)""",
        ],
        check=True,
    )

    # Export function names
    subprocess.run(
        [
            str(QUERY_SCRIPT),
            f"""COPY (
                SELECT addr, name
                FROM functions
                WHERE source = '{target}'
            ) TO '{functions_path}'
            WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)""",
        ],
        check=True,
    )

    # Export hardware/RTOS entry points
    entry_points_path = datalog_dir / "entry_points.facts"
    subprocess.run(
        [
            str(QUERY_SCRIPT),
            f"""COPY (
                SELECT addr FROM functions
                WHERE source = '{target}'
                  AND (
                    name = 'main'
                    OR name LIKE 'isr!_%' ESCAPE '!'
                    OR name IN ('xPortPendSVHandler', 'xPortSysTickHandler',
                                'vPortSVCHandler',
                                'ulSetInterruptMaskFromISR', 'vClearInterruptMaskFromISR',
                                '_entry_point', '_reset_handler',
                                '_init', '_fini', 'frame_dummy',
                                'register_tm_clones', 'data_cpy',
                                'irq_handler_chain_first_slot')
                  )
            ) TO '{entry_points_path}'
            WITH (FORMAT CSV, DELIMITER E'\\t', HEADER FALSE)""",
        ],
        check=True,
    )

    print(f"  {target}: {calls_path} + {functions_path} + {entry_points_path}")


def discover_targets() -> list[str]:
    """Find targets that have a calls.parquet table."""
    targets = []
    if BUILD_DIR.exists():
        for d in sorted(BUILD_DIR.iterdir()):
            if d.is_dir() and (d / "tables" / "calls.parquet").exists():
                targets.append(d.name)
    return targets


def main() -> int:
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        targets = discover_targets()

    if not targets:
        print("no targets with calls tables found", file=sys.stderr)
        return 1

    print(f"exporting facts for {len(targets)} target(s):")
    for t in targets:
        export_target(t)

    return 0


if __name__ == "__main__":
    sys.exit(main())
