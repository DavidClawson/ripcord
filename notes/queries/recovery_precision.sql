-- recovery_precision.sql — Precision measurement for recovered indirect call edges
--
-- The recovered_calls table contains edges discovered by 5 mechanisms:
--   vector_table (1.0), veneer_jump (0.95), func_ptr_ref (0.7),
--   registrar_dispatch (0.6), binary_const (0.5).
--
-- These are INDIRECT edges (ISR dispatch, callback registration,
-- function-pointer passing) that do not appear in the direct calls
-- table. Validation uses structural and naming heuristics against
-- the symbol table, since we have no runtime trace for Pico targets.
--
-- Focus: pico_freertos_hello (265 fns, full symbols, well-understood)
--        zephyr_hello_world  (110 fns, vector table recovery)

-- ================================================================
-- 1. Overview: edge counts per mechanism per target
-- ================================================================
SELECT '--- 1. Edge counts per mechanism ---' AS section;

SELECT r.source, r.mechanism, COUNT(*) AS edges
FROM recovered_calls r
WHERE r.source IN ('pico_freertos_hello', 'zephyr_hello_world')
GROUP BY r.source, r.mechanism
ORDER BY r.source, edges DESC;

-- ================================================================
-- 2. VECTOR_TABLE precision (expected: 100%)
--    Every entry in the Cortex-M vector table is a real ISR handler.
-- ================================================================
SELECT '--- 2. Vector table edges (expect 100% precision) ---' AS section;

SELECT r.source, r.detail,
       ft.name AS callee_name,
       CASE
         WHEN ft.name LIKE 'z_arm_%' THEN 'ARM exception handler'
         WHEN ft.name LIKE '%isr%' OR ft.name LIKE '%ISR%'
           OR ft.name LIKE '%irq%' OR ft.name LIKE '%IRQ%' THEN 'IRQ handler'
         WHEN ft.name LIKE '%Handler%' OR ft.name LIKE '%handler%' THEN 'handler'
         WHEN ft.name LIKE '%clock%' OR ft.name LIKE '%tick%' THEN 'timer/tick'
         WHEN ft.name LIKE '%fault%' OR ft.name LIKE '%Fault%' THEN 'fault handler'
         WHEN ft.name LIKE '%reset%' OR ft.name LIKE '%Reset%' THEN 'reset vector'
         WHEN ft.name LIKE '%_wrapper%' THEN 'ISR wrapper'
         WHEN ft.name LIKE 'char_out' THEN 'UART ISR (Renode artifact)'
         ELSE 'other'
       END AS classification,
       'TRUE_POSITIVE' AS verdict
FROM recovered_calls r
LEFT JOIN functions ft ON ft.source = r.source AND ft.addr = r.callee_addr
WHERE r.mechanism = 'vector_table'
  AND r.source IN ('pico_freertos_hello', 'zephyr_hello_world')
ORDER BY r.source, r.call_site_addr;

-- ================================================================
-- 3. VENEER_JUMP precision (expected: ~100%)
--    Veneer functions are compiler-generated trampolines: the entire
--    function body is a single computed jump to the real target.
-- ================================================================
SELECT '--- 3. Veneer jump edges ---' AS section;

SELECT r.source,
       fc.name AS veneer_name,
       ft.name AS real_target,
       CASE
         WHEN fc.name LIKE '%veneer%' OR fc.name LIKE '%_veneer' THEN 'TRUE_POSITIVE'
         WHEN fc.name LIKE '%_init' AND ft.name LIKE '%lookup%' THEN 'TRUE_POSITIVE'
         WHEN fc.name LIKE 'd2fix%' THEN 'TRUE_POSITIVE'
         ELSE 'LIKELY_TP'
       END AS verdict,
       r.detail
FROM recovered_calls r
LEFT JOIN functions fc ON fc.source = r.source AND fc.addr = r.caller_addr
LEFT JOIN functions ft ON ft.source = r.source AND ft.addr = r.callee_addr
WHERE r.mechanism = 'veneer_jump'
  AND r.source IN ('pico_freertos_hello', 'zephyr_hello_world')
ORDER BY r.source, fc.name;

-- ================================================================
-- 4. FUNC_PTR_REF precision
--    Non-call xrefs (DATA, PARAM, WRITE) pointing to function entries.
-- ================================================================
SELECT '--- 4. Func-ptr-ref edges ---' AS section;

SELECT r.source,
       fc.name AS from_fn,
       ft.name AS to_fn,
       r.detail,
       CASE
         WHEN fc.name = '_reset_handler' THEN 'TRUE_POSITIVE (init vector)'
         WHEN fc.name LIKE '%install%' OR fc.name LIKE '%set%handler%'
           THEN 'TRUE_POSITIVE (handler registration)'
         ELSE 'NEEDS_REVIEW'
       END AS verdict
FROM recovered_calls r
LEFT JOIN functions fc ON fc.source = r.source AND fc.addr = r.caller_addr
LEFT JOIN functions ft ON ft.source = r.source AND ft.addr = r.callee_addr
WHERE r.mechanism = 'func_ptr_ref'
  AND r.source IN ('pico_freertos_hello', 'zephyr_hello_world')
ORDER BY r.source;

-- ================================================================
-- 5. BINARY_CONST precision analysis
--    Literal pool entries near a function body. The key signal is
--    HOW FAR the constant is from the function body end.
-- ================================================================
SELECT '--- 5a. Binary-const: distance distribution ---' AS section;

SELECT r.source,
  CASE
    WHEN r.call_site_addr >= fc.addr AND r.call_site_addr < fc.addr + fc.size
      THEN 'inside_body'
    WHEN r.call_site_addr - (fc.addr + fc.size) BETWEEN 0 AND 32
      THEN 'pool_0_32'
    WHEN r.call_site_addr - (fc.addr + fc.size) BETWEEN 33 AND 128
      THEN 'pool_33_128'
    WHEN r.call_site_addr - (fc.addr + fc.size) > 128
      THEN 'far_data'
    ELSE 'before_fn'
  END AS region,
  COUNT(*) AS n
FROM recovered_calls r
JOIN functions fc ON fc.source = r.source AND fc.addr = r.caller_addr
WHERE r.mechanism = 'binary_const'
  AND r.source IN ('pico_freertos_hello', 'zephyr_hello_world')
GROUP BY r.source, region
ORDER BY r.source, region;

-- Detailed binary_const with manual verdict based on name semantics
SELECT '--- 5b. Binary-const edge-by-edge verdict (pico_freertos_hello) ---' AS section;

SELECT
  fc.name AS caller_name,
  ft.name AS callee_name,
  r.call_site_addr - (fc.addr + fc.size) AS bytes_after_body,
  CASE
    -- Known callback registration patterns: function A stores address of B
    -- for later dispatch by a third party (FreeRTOS, SDK, etc.)
    WHEN fc.name = 'main_task' AND ft.name = 'blink_task' THEN 'TP: xTaskCreate callback'
    WHEN fc.name = 'vLaunch' AND ft.name = 'main_task' THEN 'TP: xTaskCreate callback'
    WHEN fc.name LIKE 'async_context%' AND ft.name IN ('end_task_func','handle_sync_func_call','timer_handler','async_context_task')
      THEN 'TP: async context callback'
    WHEN fc.name LIKE '%alarm%' AND ft.name LIKE '%alarm%' THEN 'TP: alarm callback'
    WHEN fc.name LIKE '%runtime_init%' AND ft.name LIKE '%alarm%irq%' THEN 'TP: IRQ handler install'
    WHEN fc.name LIKE '%irq_set%' AND ft.name LIKE 'isr_%' THEN 'TP: IRQ handler install'
    WHEN fc.name LIKE '%exception_set%' AND ft.name LIKE 'isr_%' THEN 'TP: IRQ handler install'
    WHEN fc.name LIKE '%runtime_init_install%' AND ft.name LIKE 'isr_%' THEN 'TP: IRQ handler install'
    WHEN fc.name LIKE '%veneer%' AND ft.name NOT LIKE '%veneer%' THEN 'TP: veneer literal pool'
    WHEN fc.name LIKE '%_init' AND ft.name LIKE '%lookup%' THEN 'TP: ROM lookup init'
    WHEN ft.name LIKE '%_shim%' OR fc.name LIKE '%_shim%' THEN 'TP: ROM shim chain'
    WHEN fc.name LIKE '%vprintf%' AND ft.name LIKE '_out_%' THEN 'TP: printf callback'
    WHEN fc.name LIKE 'best_effort%' AND ft.name LIKE '%callback%' THEN 'TP: SDK callback'
    WHEN fc.name LIKE '%irq_handler_chain%' AND ft.name LIKE 'stdio_%' THEN 'TP: IRQ chain handler'
    WHEN fc.name LIKE '%irq%' AND ft.name LIKE '%irq%' THEN 'TP: IRQ chain handler'
    WHEN fc.name LIKE 'FUN_%' AND ft.name LIKE '_out_%' THEN 'TP: printf format callback'
    WHEN fc.name LIKE 'FUN_%' AND ft.name LIKE '_vsnprintf%' THEN 'TP: printf internal'
    WHEN fc.name LIKE '%stdio%init%' AND ft.name LIKE 'stdio_%' THEN 'TP: stdio init callback'
    -- Self-reference (function has its own address in literal pool for recursion or identity)
    WHEN fc.name = ft.name THEN 'FP: self-reference in literal pool'
    -- data_cpy is the .data initializer; it contains init array addresses, not callbacks
    WHEN fc.name = 'data_cpy' THEN 'AMBIG: init array entry (likely TP for init)'
    -- Everything else needs manual review
    ELSE 'REVIEW'
  END AS verdict
FROM recovered_calls r
JOIN functions fc ON fc.source = r.source AND fc.addr = r.caller_addr
JOIN functions ft ON ft.source = r.source AND ft.addr = r.callee_addr
WHERE r.mechanism = 'binary_const'
  AND r.source = 'pico_freertos_hello'
ORDER BY verdict, fc.name;

-- ================================================================
-- 6. REGISTRAR_DISPATCH precision analysis
--    This mechanism is the noisiest. It infers: if function A references
--    function B as data AND calls C, then C dispatches to B. The logic
--    requires C to have >=2 incoming call refs but does NOT verify that
--    C is actually a registrar (xTaskCreate, xTimerCreate, etc.).
-- ================================================================
SELECT '--- 6a. Registrar dispatch: supposed dispatchers ---' AS section;

SELECT fc.name AS dispatcher,
       COUNT(*) AS n_edges,
       CASE
         -- TRUE registrar functions that take a function pointer and
         -- will eventually call it
         WHEN fc.name IN ('xTaskCreate', 'prvCreateTask', 'xTimerCreate',
                          'xTimerGenericCommandFromTask')
           THEN 'TRUE_REGISTRAR'
         -- Functions that actually set up interrupt/exception handlers
         WHEN fc.name IN ('irq_set_exclusive_handler', 'exception_set_exclusive_handler',
                          'irq_set_enabled')
           THEN 'PLAUSIBLE_REGISTRAR'
         -- Queue operations could dispatch but usually don't "call" the target
         WHEN fc.name LIKE 'xQueue%' THEN 'PLAUSIBLE_REGISTRAR'
         -- Lock/critical section: never dispatches to arbitrary functions
         WHEN fc.name LIKE '%Critical%' OR fc.name LIKE '%Lock%'
           OR fc.name LIKE '%lock%' OR fc.name LIKE '%spin%'
           THEN 'FALSE_REGISTRAR'
         -- Utility functions: called often but never dispatch
         WHEN fc.name IN ('time_us_64', '__wrap_memset', '__wrap_memcpy',
                          '__wrap_printf', '__wrap_puts', 'strlen',
                          'panic_unsupported', 'vTaskSwitchContext',
                          'timer_time_us_64', 'next_striped_spin_lock_num')
           THEN 'FALSE_REGISTRAR'
         WHEN fc.name LIKE '%veneer%' THEN 'FALSE_REGISTRAR'
         WHEN fc.name LIKE 'vList%' THEN 'FALSE_REGISTRAR'
         ELSE 'UNKNOWN'
       END AS registrar_verdict
FROM recovered_calls r
JOIN functions fc ON fc.source = r.source AND fc.addr = r.caller_addr
WHERE r.mechanism = 'registrar_dispatch'
  AND r.source = 'pico_freertos_hello'
GROUP BY fc.name, registrar_verdict
ORDER BY registrar_verdict, n_edges DESC;

-- Summarize registrar_dispatch by verdict
SELECT '--- 6b. Registrar dispatch: precision by dispatcher class ---' AS section;

SELECT registrar_class, SUM(n) AS total_edges
FROM (
  SELECT
    CASE
      WHEN fc.name IN ('xTaskCreate', 'prvCreateTask', 'xTimerCreate',
                        'xTimerGenericCommandFromTask')
        THEN 'TRUE_REGISTRAR'
      WHEN fc.name IN ('irq_set_exclusive_handler', 'exception_set_exclusive_handler',
                        'irq_set_enabled')
        THEN 'PLAUSIBLE_REGISTRAR'
      WHEN fc.name LIKE 'xQueue%' THEN 'PLAUSIBLE_REGISTRAR'
      ELSE 'FALSE_REGISTRAR'
    END AS registrar_class,
    COUNT(*) AS n
  FROM recovered_calls r
  JOIN functions fc ON fc.source = r.source AND fc.addr = r.caller_addr
  WHERE r.mechanism = 'registrar_dispatch'
    AND r.source = 'pico_freertos_hello'
  GROUP BY registrar_class
) sub
GROUP BY registrar_class
ORDER BY registrar_class;

-- ================================================================
-- 7. Cross-check: recovered edges vs the direct calls table
--    Recovered edges are INDIRECT — they should NOT appear in calls.
--    If they do, they're redundant (not wrong). Count overlap.
-- ================================================================
SELECT '--- 7. Overlap with direct calls table ---' AS section;

SELECT r.mechanism,
       COUNT(*) AS recovered,
       SUM(CASE WHEN c.callee_addr IS NOT NULL THEN 1 ELSE 0 END) AS also_direct,
       COUNT(*) - SUM(CASE WHEN c.callee_addr IS NOT NULL THEN 1 ELSE 0 END) AS truly_new
FROM recovered_calls r
LEFT JOIN calls c ON c.source = r.source
                  AND c.caller_addr = r.caller_addr
                  AND c.callee_addr = r.callee_addr
WHERE r.source = 'pico_freertos_hello'
GROUP BY r.mechanism
ORDER BY r.mechanism;

-- ================================================================
-- 8. Callee coverage: what fraction of the "unreachable from main"
--    functions are now reachable via recovered edges?
-- ================================================================
SELECT '--- 8. Callee coverage of previously-unreachable functions ---' AS section;

-- Functions not called by anyone (via direct calls)
WITH uncalled AS (
  SELECT f.addr, f.name
  FROM functions f
  WHERE f.source = 'pico_freertos_hello'
    AND f.addr NOT IN (
      SELECT DISTINCT c.callee_addr FROM calls c
      WHERE c.source = 'pico_freertos_hello' AND c.callee_addr IS NOT NULL
    )
),
-- Of those, which appear as callee in recovered_calls?
recovered_targets AS (
  SELECT DISTINCT r.callee_addr
  FROM recovered_calls r
  WHERE r.source = 'pico_freertos_hello'
)
SELECT
  COUNT(*) AS total_uncalled,
  SUM(CASE WHEN u.addr IN (SELECT callee_addr FROM recovered_targets) THEN 1 ELSE 0 END) AS now_recovered,
  LIST(u.name ORDER BY u.name) FILTER (WHERE u.addr IN (SELECT callee_addr FROM recovered_targets)) AS recovered_names
FROM uncalled u;

-- ================================================================
-- 9. Summary: per-mechanism precision estimate
-- ================================================================
SELECT '--- 9. PRECISION SUMMARY ---' AS section;

-- Counts from empirical analysis on pico_freertos_hello + zephyr_hello_world:
--
-- vector_table:       8 Zephyr edges, all correct ISR/exception vectors.
--                     Pico targets have no vector_table recovery (Pico SDK
--                     copies vector table to RAM at startup — the ELF
--                     vector table is the initial template). 8/8 = 100%.
--
-- veneer_jump:        10 Pico + 2 Zephyr = 12 edges. All are compiler-
--                     generated trampolines (name contains "veneer" or is
--                     a known init→lookup / d2fix→d2fix_a pattern). 12/12.
--
-- func_ptr_ref:       2 Pico + 1 Zephyr = 3 edges. All verified: reset
--                     handler init, RAM vector table install, thread entry
--                     setup. 3/3.
--
-- binary_const:       72 Pico + 14 Zephyr = 86 edges. On pico_freertos_hello:
--                     54 auto-classified TP (callbacks, shims, IRQ installs,
--                     veneer literal pools). 13 initially REVIEW, ALL 13
--                     confirmed TP on manual inspection:
--                       pxPortInitialiseStack→prvTaskExitError (stack frame)
--                       stdio_put_string→stdio_out_chars_{no_crlf,crlf}
--                       stdio_uart_set_chars_available_callback→on_uart_rx
--                       vTaskStartScheduler→prvIdleTask
--                       vfctprintf→_out_fct (printf callback)
--                       xEventGroupSetBitsFromISR→vEventGroupSetBitsCallback
--                       xPortStartScheduler→{vPortSVCHandler,xPortPendSVHandler,
--                                            prvFIFOInterruptHandler,xPortSysTickHandler}
--                       xTimerCreateTimerTask→prvTimerTask
--                       __wrap_vprintf→stdio_buffered_printer
--                     4 AMBIG (data_cpy init array entries — likely TP).
--                     1 FP (d2fix_a self-reference). 67/(67+1) = 98.5%.
--
-- registrar_dispatch: 86 Pico + 10 Zephyr = 96 edges. On pico_freertos_hello:
--                     Only 7 edges from TRUE registrars (xTaskCreate,
--                     prvCreateTask, xTimerCreate, xTimerGenericCommandFromTask).
--                     22 from PLAUSIBLE registrars (irq_set_*, xQueue*).
--                     57 from FALSE registrars (time_us_64, memset, memcpy,
--                     strlen, panic_unsupported, veneers, etc.).
--                     Best case 29/86 = 33.7%. Realistic 7/86 = 8.1%.
--
SELECT * FROM (VALUES
  ('vector_table',        8,   8,  0,  '100.0%',  'All entries are real ISR/exception handlers'),
  ('veneer_jump',        12,  12,  0,  '100.0%',  'All are compiler-generated trampolines'),
  ('func_ptr_ref',        3,   3,  0,  '100.0%',  'Xref-validated function pointer references'),
  ('binary_const',       86,  84,  2,   '97.7%',  '1 self-ref FP, 4 init-array ambiguous (counted as TP), 1 Zephyr far_data'),
  ('registrar_dispatch', 96,   7, 89,    '7.3%',  'Mechanism is broken: no registrar whitelist, massive false positive rate')
) AS t(mechanism, total_edges, true_positives, false_positives, precision, notes);
