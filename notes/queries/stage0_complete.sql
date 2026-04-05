-- Stage 0 exit criterion: demonstrate all five extracted tables
-- working together in cross-table joins that were impossible before
-- the widening push.
--
-- Usage:
--   scripts/query < notes/queries/stage0_complete.sql
--
-- If every query returns sensible rows, Stage 0 is complete and
-- Phase 1 (library identification, trace capture, register map)
-- has its foundation.

-- 1. Warehouse summary: row counts per table per target.
SELECT 'functions'   AS table_name, source, COUNT(*) AS rows FROM functions    GROUP BY source
UNION ALL
SELECT 'calls',              source, COUNT(*) FROM calls        GROUP BY source
UNION ALL
SELECT 'basic_blocks',       source, COUNT(*) FROM basic_blocks GROUP BY source
UNION ALL
SELECT 'xrefs',              source, COUNT(*) FROM xrefs        GROUP BY source
UNION ALL
SELECT 'strings',            source, COUNT(*) FROM strings      GROUP BY source
ORDER BY source, table_name;

-- 2. Basic block consistency: every functions.basic_block_count
-- value should equal the number of basic_blocks rows with that
-- function's addr. If this returns any rows, one of the extractors
-- is miscounting.
SELECT
    f.source,
    f.name,
    f.basic_block_count                              AS fn_table_count,
    COUNT(bb.block_addr)                             AS bb_table_count,
    f.basic_block_count - COUNT(bb.block_addr)       AS diff
FROM functions f
LEFT JOIN basic_blocks bb
    ON bb.source = f.source AND bb.function_addr = f.addr
GROUP BY f.source, f.name, f.basic_block_count
HAVING f.basic_block_count != COUNT(bb.block_addr)
ORDER BY ABS(diff) DESC
LIMIT 20;

-- 3. Functions ranked by basic-block count (proxy for control-flow
-- complexity). These are the juiciest targets for eventual agent
-- work because they're the most structurally complex.
SELECT
    f.source,
    f.name,
    f.size                            AS bytes,
    COUNT(bb.block_addr)              AS blocks,
    SUM(bb.instruction_count)         AS instructions
FROM functions f
JOIN basic_blocks bb
    ON bb.source = f.source AND bb.function_addr = f.addr
GROUP BY f.source, f.name, f.size
ORDER BY blocks DESC, instructions DESC
LIMIT 10;

-- 4. Xref type distribution. Tells us what kinds of non-call
-- references Ghidra recognized on this target and whether any
-- important category is unexpectedly small.
SELECT source, ref_type, COUNT(*) AS n
FROM xrefs
GROUP BY source, ref_type
ORDER BY source, n DESC;

-- 5. STAGE 0 EXIT CRITERION: every function that references a
-- runtime string. Joins strings ⨝ xrefs ⨝ functions across three
-- tables that did not exist in the same warehouse before Step 3.
-- The result is the crudest form of library/purpose identification
-- and the first primitive of Phase 1 fingerprinting — any function
-- that touches a string constant is partially self-documenting.
--
-- For targets with debug logging (most real firmware), this query
-- becomes the first "what does this function actually do" source
-- of truth. On Pico blinky it only surfaces the error-message
-- consumers (panic, hard_assertion_failure, timer_hardware_alarm_claim)
-- because the blinky code path is too trivial to log anything; on a
-- FreeRTOS or Zephyr target the same query will cover dozens of
-- functions.
SELECT
    f.source,
    f.name                                           AS function_name,
    MIN(printf('0x%x', f.addr))                      AS function_addr,
    COUNT(DISTINCT s.addr)                           AS distinct_strings,
    COUNT(*)                                         AS total_refs,
    LIST(DISTINCT s.value ORDER BY s.value)[:3]      AS sample_strings
FROM strings s
JOIN xrefs x
    ON x.source = s.source AND x.to_addr = s.addr
JOIN functions f
    ON f.source = x.source AND f.addr = x.function_addr
GROUP BY f.source, f.name
ORDER BY distinct_strings DESC, total_refs DESC, function_name
LIMIT 20;

-- 6. Unreferenced strings — strings in the binary that no function
-- body xrefs. Could be dead data the linker didn't garbage-collect,
-- data reached via computed (indirect) addressing Ghidra couldn't
-- resolve, or strings referenced from outside any function (data
-- section pointers, vector tables). Useful as a sanity check and as
-- a future hint for where computed-ref recovery would pay off.
SELECT source, COUNT(*) AS n
FROM strings s
WHERE NOT EXISTS (
    SELECT 1 FROM xrefs x
    WHERE x.source = s.source AND x.to_addr = s.addr
)
GROUP BY source
ORDER BY source;
