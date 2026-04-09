-- computed_calls.sql — Recover implied call edges from function-pointer dispatch
--
-- The static call graph captures only direct calls and Ghidra-resolved
-- computed calls. On an RTOS target like pico_freertos_hello, this
-- misses three major categories of control flow:
--
--   1. Hardware dispatch: ISR handlers, PendSV, SysTick, SVCall are
--      entered by the CPU, not by a call instruction.
--   2. RTOS dispatch: xTaskCreate receives a function pointer; the
--      scheduler later calls it. prvIdleTask and prvTimerTask are
--      created internally by vTaskStartScheduler.
--   3. Initialization chains: runtime_run_initializers dispatches
--      through a linker-generated function-pointer table to all
--      runtime_init_* functions. Async context init populates a
--      vtable of async_context_freertos_* callbacks. The __aeabi_*_init
--      functions populate shim tables for math library dispatch.
--
-- This query constructs "implied edges" from structural and naming
-- heuristics, then recomputes reachability to measure gap closure.
--
-- Note: LIKE patterns use ESCAPE '!' (not backslash) because the
-- scripts/query statement splitter treats backslash-quote as an escaped
-- quote, breaking multi-statement SQL files.
--
-- Note: all_edges is materialized as a temp table rather than a CTE
-- because DuckDB incorrectly treats UNION-based CTEs as recursive when
-- they appear inside a WITH RECURSIVE block.
--
-- Usage: scripts/query < notes/queries/computed_calls.sql

-- ================================================================
-- Section 1: Baseline — static reachability from main
-- ================================================================

WITH RECURSIVE
static_reach AS (
    SELECT addr AS fn FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
    UNION
    SELECT c.callee_addr
    FROM static_reach r
    JOIN calls c ON c.source = 'pico_freertos_hello'
        AND c.caller_addr = r.fn AND c.callee_addr IS NOT NULL
)
SELECT COUNT(*) AS static_reachable_from_main FROM static_reach;

-- ================================================================
-- Section 2: Build implied edge table
-- ================================================================

CREATE OR REPLACE TEMP TABLE implied_edges AS

-- B1: runtime_init -> all runtime_init_* and __aeabi_*_init functions
-- runtime_init calls runtime_run_initializers which iterates a
-- linker-generated function-pointer table. This table includes both
-- runtime_init_* functions and __aeabi_*_init / first_per_core_initializer.
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = 'runtime_init') AS from_addr,
    f.addr AS to_addr,
    'runtime_init_dispatch' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND (f.name LIKE 'runtime!_init!_%' ESCAPE '!'
       OR f.name IN ('__aeabi_bits_init', '__aeabi_double_init',
                     '__aeabi_float_init', '__aeabi_mem_init',
                     'first_per_core_initializer'))

UNION ALL

-- B2: vTaskStartScheduler -> prvIdleTask, prvTimerTask
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = 'vTaskStartScheduler') AS from_addr,
    f.addr AS to_addr,
    'scheduler_internal_task' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.name IN ('prvIdleTask', 'prvTimerTask')

UNION ALL

-- B3: Callers of xTaskCreate -> known task body functions
SELECT
    c.caller_addr AS from_addr,
    task.addr AS to_addr,
    'xTaskCreate_dispatch' AS edge_type,
    task.name AS to_name
FROM calls c
JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
JOIN functions task ON task.source = c.source
WHERE c.source = 'pico_freertos_hello'
  AND f.name = 'xTaskCreate'
  AND task.name IN (
      'blink_task', 'main_task', 'async_context_task',
      'do_work', 'end_task_func'
  )

UNION ALL

-- B4: async_context_freertos_init -> async_context_freertos_* callbacks
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = 'async_context_freertos_init') AS from_addr,
    f.addr AS to_addr,
    'async_context_vtable' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.name LIKE 'async!_context!_freertos!_%' ESCAPE '!'
  AND f.name != 'async_context_freertos_init'

UNION ALL

-- B5: __aeabi_*_init -> corresponding math shim functions
SELECT
    init_fn.addr AS from_addr,
    shim_fn.addr AS to_addr,
    'aeabi_shim_dispatch' AS edge_type,
    shim_fn.name AS to_name
FROM functions init_fn, functions shim_fn
WHERE init_fn.source = 'pico_freertos_hello'
  AND shim_fn.source = 'pico_freertos_hello'
  AND (
      (init_fn.name = '__aeabi_double_init' AND shim_fn.name IN (
          'dadd_shim', 'dsub_shim', 'dmul_shim', 'ddiv_shim', 'drsub_shim',
          'dunpacks', 'double_table_shim_on_use_helper',
          'double2ufix_shim', 'double2ufix64_shim',
          'double2uint_shim', 'double2uint64_shim',
          'd2fix', 'd2fix_a'))
      OR (init_fn.name = '__aeabi_float_init' AND shim_fn.name IN (
          'float_table_shim_on_use_helper'))
      OR (init_fn.name = '__aeabi_mem_init' AND shim_fn.name IN (
          '__wrap_memcpy'))
      OR (init_fn.name = '__aeabi_bits_init' AND shim_fn.name IN (
          'rom_funcs_lookup', 'rom_func_lookup', 'rom_data_lookup'))
  )

UNION ALL

-- B6: stdio_put_string -> stdio callback functions
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = 'stdio_put_string') AS from_addr,
    f.addr AS to_addr,
    'stdio_callback' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.name IN ('stdio_uart_out_chars', 'stdio_uart_out_flush',
                 'stdio_uart_in_chars', 'stdio_uart_set_chars_available_callback',
                 'stdio_out_chars_no_crlf', 'stdio_buffered_printer')

UNION ALL

-- B7: _vsnprintf -> output function callbacks
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = '_vsnprintf') AS from_addr,
    f.addr AS to_addr,
    'printf_callback' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.name IN ('_out_char', '_out_fct')

UNION ALL

-- B8: alarm_pool / timer implied edges
SELECT
    caller.addr AS from_addr,
    handler.addr AS to_addr,
    'alarm_callback' AS edge_type,
    handler.name AS to_name
FROM functions caller, functions handler
WHERE caller.source = 'pico_freertos_hello'
  AND handler.source = 'pico_freertos_hello'
  AND (
      (caller.name = 'async_context_freertos_add_at_time_worker'
       AND handler.name IN ('timer_handler', 'alarm_pool_irq_handler',
                            'sleep_until_callback'))
      OR (caller.name = 'runtime_init_default_alarm_pool'
          AND handler.name IN ('alarm_pool_irq_handler',
                               'timer_hardware_alarm_claim'))
  )

UNION ALL

-- B9: prvTimerTask -> timer callback dispatch
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = 'prvTimerTask') AS from_addr,
    f.addr AS to_addr,
    'timer_task_callback' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.name IN ('vEventGroupSetBitsCallback', 'xTimerGenericCommandFromTask')

UNION ALL

-- B10: irq_handler_chain -> ISR dispatched handlers
SELECT
    (SELECT addr FROM functions WHERE source = 'pico_freertos_hello'
     AND name = 'irq_handler_chain_first_slot') AS from_addr,
    f.addr AS to_addr,
    'irq_chain_dispatch' AS edge_type,
    f.name AS to_name
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.name IN ('prvFIFOInterruptHandler', 'on_uart_rx',
                 'alarm_pool_irq_handler')

UNION ALL

-- B11: Veneer trampolines -> their targets
SELECT
    x.function_addr AS from_addr,
    x.to_addr AS to_addr,
    'veneer_jump' AS edge_type,
    f_to.name AS to_name
FROM xrefs x
JOIN functions f_from ON f_from.source = x.source AND f_from.addr = x.function_addr
JOIN functions f_to ON f_to.source = x.source AND f_to.addr = x.to_addr
WHERE x.source = 'pico_freertos_hello'
  AND x.ref_type = 'COMPUTED_JUMP'
  AND f_from.name LIKE '%veneer%'

UNION ALL

-- C: Data xrefs pointing to function entry points
SELECT
    x.function_addr AS from_addr,
    x.to_addr AS to_addr,
    'data_xref_to_function' AS edge_type,
    f_to.name AS to_name
FROM xrefs x
JOIN functions f_to ON f_to.source = x.source AND f_to.addr = x.to_addr
WHERE x.source = 'pico_freertos_hello'
  AND x.ref_type IN ('DATA', 'PARAM', 'WRITE')
;

-- Show the implied edges by category
SELECT edge_type, COUNT(*) AS edges, COUNT(DISTINCT to_addr) AS distinct_targets
FROM implied_edges
WHERE from_addr IS NOT NULL
GROUP BY edge_type
ORDER BY edges DESC;

-- ================================================================
-- Section 3: Hardware entry-point roots
-- ================================================================

CREATE OR REPLACE TEMP TABLE hardware_roots AS
SELECT addr, name FROM functions
WHERE source = 'pico_freertos_hello'
  AND (
      -- Cortex-M exception handlers
      name LIKE 'isr!_%' ESCAPE '!'
      OR name IN ('xPortPendSVHandler', 'xPortSysTickHandler',
                  'vPortSVCHandler',
                  'ulSetInterruptMaskFromISR', 'vClearInterruptMaskFromISR')
      -- Boot/startup sequence (runs before main)
      OR name IN ('_entry_point', '_reset_handler')
      -- C runtime init/fini
      OR name IN ('_init', '_fini', 'frame_dummy', 'register_tm_clones',
                  'data_cpy')
      -- IRQ handler chain (installed in RAM vector table at runtime)
      OR name = 'irq_handler_chain_first_slot'
  );

SELECT 'Hardware/boot roots:' AS label, COUNT(*) AS n FROM hardware_roots;

-- ================================================================
-- Section 4: Materialize unified edge set and compute reachability
-- ================================================================

CREATE OR REPLACE TEMP TABLE all_edges AS
SELECT caller_addr AS from_addr, callee_addr AS to_addr
FROM calls
WHERE source = 'pico_freertos_hello' AND callee_addr IS NOT NULL
UNION
SELECT from_addr, to_addr
FROM implied_edges
WHERE from_addr IS NOT NULL AND to_addr IS NOT NULL;

-- Note: DuckDB 1.5.1 has a bug where scalar subqueries in a SELECT
-- that reads from a recursive CTE corrupt the CTE evaluation.
-- Workaround: materialize the count first, then combine.

CREATE OR REPLACE TEMP TABLE total_fn_count AS
SELECT COUNT(*) AS n FROM functions WHERE source = 'pico_freertos_hello';

WITH RECURSIVE
enhanced_reach AS (
    SELECT addr AS fn FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
    UNION ALL
    SELECT addr FROM hardware_roots
    UNION
    SELECT e.to_addr
    FROM enhanced_reach r
    JOIN all_edges e ON e.from_addr = r.fn
)
SELECT
    t.n AS total_functions,
    COUNT(*) AS enhanced_reachable,
    t.n - COUNT(*) AS still_unreachable
FROM enhanced_reach, total_fn_count t
GROUP BY t.n;

-- ================================================================
-- Section 5: What became reachable that was not before?
-- ================================================================

WITH RECURSIVE
static_reach AS (
    SELECT addr AS fn FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
    UNION
    SELECT c.callee_addr
    FROM static_reach r
    JOIN calls c ON c.source = 'pico_freertos_hello'
        AND c.caller_addr = r.fn AND c.callee_addr IS NOT NULL
),
enhanced_reach AS (
    SELECT addr AS fn FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
    UNION ALL
    SELECT addr FROM hardware_roots
    UNION
    SELECT e.to_addr
    FROM enhanced_reach r
    JOIN all_edges e ON e.from_addr = r.fn
)
SELECT f.name,
    CASE
        WHEN f.addr IN (SELECT addr FROM hardware_roots)
            THEN 'hardware_root'
        ELSE 'implied_edge'
    END AS how_recovered
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.addr IN (SELECT fn FROM enhanced_reach)
  AND f.addr NOT IN (SELECT fn FROM static_reach)
ORDER BY how_recovered, f.name;

-- ================================================================
-- Section 6: Detailed gap — what is still unreachable?
-- ================================================================

WITH RECURSIVE
enhanced_reach AS (
    SELECT addr AS fn FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
    UNION ALL
    SELECT addr FROM hardware_roots
    UNION
    SELECT e.to_addr
    FROM enhanced_reach r
    JOIN all_edges e ON e.from_addr = r.fn
)
SELECT f.name, printf('0x%08x', f.addr) AS hex_addr,
    CASE
        WHEN f.name LIKE '%veneer%' THEN 'veneer_trampoline'
        WHEN f.name LIKE 'divmod%' OR f.name LIKE 'div!_%' ESCAPE '!'
            THEN 'math_library'
        WHEN f.name LIKE '%shim%' OR f.name LIKE '%wrap%'
            THEN 'shim_or_wrapper'
        WHEN f.name LIKE 'x%' AND f.name LIKE '%FromISR%'
            THEN 'freertos_isr_api'
        WHEN f.name LIKE 'v%' OR f.name LIKE 'x%'
            OR f.name LIKE 'prv%' OR f.name LIKE 'pv%'
            OR f.name LIKE 'ux%' THEN 'freertos_internal'
        WHEN f.name LIKE '%Port%' OR f.name LIKE '%port%'
            THEN 'freertos_port'
        WHEN f.name LIKE 'FUN_%' THEN 'unnamed_ghidra'
        ELSE 'other'
    END AS category
FROM functions f
WHERE f.source = 'pico_freertos_hello'
  AND f.addr NOT IN (SELECT fn FROM enhanced_reach)
ORDER BY category, f.name;

-- ================================================================
-- Section 7: Summary by category
-- ================================================================

WITH RECURSIVE
enhanced_reach AS (
    SELECT addr AS fn FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
    UNION ALL
    SELECT addr FROM hardware_roots
    UNION
    SELECT e.to_addr
    FROM enhanced_reach r
    JOIN all_edges e ON e.from_addr = r.fn
),
categorized AS (
    SELECT f.name,
        f.addr IN (SELECT fn FROM enhanced_reach) AS now_reachable,
        CASE
            WHEN f.name LIKE '%veneer%' THEN 'veneer_trampoline'
            WHEN f.name LIKE 'divmod%' OR f.name LIKE 'div!_%' ESCAPE '!'
                THEN 'math_library'
            WHEN f.name LIKE '%shim%' OR f.name LIKE '%wrap%'
                THEN 'shim_or_wrapper'
            WHEN f.name LIKE 'x%' AND f.name LIKE '%FromISR%'
                THEN 'freertos_isr_api'
            WHEN f.name LIKE 'isr!_%' ESCAPE '!'
                OR f.name LIKE '%Handler%' THEN 'isr_handler'
            WHEN f.name LIKE 'async!_%' ESCAPE '!' THEN 'async_context'
            WHEN f.name LIKE 'runtime!_%' ESCAPE '!' THEN 'runtime_init'
            WHEN f.name LIKE 'v%' OR f.name LIKE 'x%'
                OR f.name LIKE 'prv%' OR f.name LIKE 'pv%'
                OR f.name LIKE 'ux%' THEN 'freertos_internal'
            WHEN f.name LIKE '%Port%' OR f.name LIKE '%port%'
                THEN 'freertos_port'
            WHEN f.name LIKE 'FUN_%' THEN 'unnamed_ghidra'
            ELSE 'other'
        END AS category
    FROM functions f
    WHERE f.source = 'pico_freertos_hello'
)
SELECT
    category,
    COUNT(*) AS total,
    SUM(CASE WHEN now_reachable THEN 1 ELSE 0 END) AS reachable,
    SUM(CASE WHEN NOT now_reachable THEN 1 ELSE 0 END) AS unreachable
FROM categorized
GROUP BY category
ORDER BY unreachable DESC, category;
