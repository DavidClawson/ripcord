-- constant_fingerprint.sql — Cross-target function matching by referenced constants
--
-- Hypothesis: functions that reference the same set of constants
-- (peripheral registers, SRAM globals, string literals, immediate
-- values) are likely the same function, even across different
-- compilers or optimization levels. Unlike structural fingerprinting
-- (which depends on identical code generation) or P-Code matching
-- (which depends on identical ISA lowering), constant references
-- come from the source code and hardware, not the compiler.
--
-- This is particularly interesting for:
--   - Cross-compiler matching (arm-gcc vs Keil)
--   - Cross-optimization matching (-O2 vs -O3)
--   - Peripheral driver identification (functions touching UART, SPI, etc.)
--
-- We test three constant signals:
--   1. Peripheral register addresses (0x40000000+) — most compiler-invariant
--   2. Full xref target set (all DATA/READ/WRITE addresses) — richer but noisier
--   3. String references — sparse but very distinctive when available
--
-- Usage: scripts/query < notes/queries/constant_fingerprint.sql

-- =====================================================================
-- 1. Per-function constant set: which addresses does each function reference?
-- =====================================================================

CREATE OR REPLACE TEMP TABLE func_constants AS
SELECT
    x.source,
    x.function_addr,
    f.name AS func_name,
    f.size AS func_size,
    x.to_addr,
    CASE
        WHEN x.to_addr BETWEEN 1073741824 AND 1610612735 THEN 'peripheral'
        WHEN x.to_addr >= 3758096384 THEN 'system'
        WHEN x.to_addr BETWEEN 536870912 AND 805306367 THEN 'sram'
        ELSE 'other'
    END AS addr_class
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.ref_type IN ('DATA', 'READ', 'WRITE', 'PARAM')
  AND x.to_addr IS NOT NULL
  AND f.is_thunk = false
  AND f.size >= 16;

-- =====================================================================
-- 2. Peripheral-only constant set per function (most hardware-invariant)
-- =====================================================================

CREATE OR REPLACE TEMP TABLE periph_sets AS
SELECT
    source, function_addr, func_name, func_size,
    LIST(DISTINCT to_addr ORDER BY to_addr) AS periph_addrs,
    COUNT(DISTINCT to_addr) AS periph_count
FROM func_constants
WHERE addr_class IN ('peripheral', 'system')
GROUP BY source, function_addr, func_name, func_size
HAVING COUNT(DISTINCT to_addr) >= 2;

-- How many functions have peripheral constant sets?
SELECT 'functions_with_periph_sets' AS metric,
       source, COUNT(*) AS cnt
FROM periph_sets
GROUP BY source
ORDER BY source;

-- =====================================================================
-- 3. Within-ISA: match functions by identical peripheral sets
--    (Pico vs Pico, or Zephyr vs Zephyr — same hardware)
-- =====================================================================

SELECT '--- WITHIN-ISA PERIPHERAL SET MATCHES ---' AS section;

SELECT
    a.source AS source_a, a.func_name AS name_a,
    b.source AS source_b, b.func_name AS name_b,
    a.periph_count,
    a.periph_addrs,
    CASE WHEN a.func_name = b.func_name THEN 'MATCH' ELSE 'MISMATCH' END AS name_match
FROM periph_sets a
JOIN periph_sets b
  ON a.periph_addrs = b.periph_addrs
  AND a.source < b.source
-- Same ISA group
WHERE (a.source LIKE 'pico%' AND b.source LIKE 'pico%')
   OR (a.source LIKE 'zephyr%' AND b.source LIKE 'zephyr%')
ORDER BY a.periph_count DESC, a.func_name
LIMIT 40;

-- =====================================================================
-- 4. Full constant set matching (all xref targets, not just peripherals)
-- =====================================================================

CREATE OR REPLACE TEMP TABLE full_const_sets AS
SELECT
    source, function_addr, func_name, func_size,
    LIST(DISTINCT to_addr ORDER BY to_addr) AS const_addrs,
    COUNT(DISTINCT to_addr) AS const_count
FROM func_constants
GROUP BY source, function_addr, func_name, func_size
HAVING COUNT(DISTINCT to_addr) >= 3;

SELECT '--- FULL CONSTANT SET MATCHES (within-ISA) ---' AS section;

SELECT
    a.source AS source_a, a.func_name AS name_a,
    b.source AS source_b, b.func_name AS name_b,
    a.const_count,
    CASE WHEN a.func_name = b.func_name THEN 'MATCH' ELSE 'MISMATCH' END AS name_match
FROM full_const_sets a
JOIN full_const_sets b
  ON a.const_addrs = b.const_addrs
  AND a.source < b.source
WHERE (a.source LIKE 'pico%' AND b.source LIKE 'pico%')
   OR (a.source LIKE 'zephyr%' AND b.source LIKE 'zephyr%')
ORDER BY a.const_count DESC, a.func_name
LIMIT 40;

-- =====================================================================
-- 5. Precision measurement: of matches, how many share the same name?
-- =====================================================================

SELECT '--- PRECISION: FULL CONSTANT SET ---' AS section;

WITH matches AS (
    SELECT
        a.func_name AS name_a, b.func_name AS name_b,
        a.const_count,
        CASE WHEN a.func_name = b.func_name THEN 1 ELSE 0 END AS is_correct
    FROM full_const_sets a
    JOIN full_const_sets b
      ON a.const_addrs = b.const_addrs
      AND a.source < b.source
    WHERE (a.source LIKE 'pico%' AND b.source LIKE 'pico%')
       OR (a.source LIKE 'zephyr%' AND b.source LIKE 'zephyr%')
)
SELECT
    COUNT(*) AS total_matches,
    SUM(is_correct) AS correct,
    COUNT(*) - SUM(is_correct) AS incorrect,
    ROUND(100.0 * SUM(is_correct) / COUNT(*), 1) AS precision_pct,
    ROUND(AVG(const_count), 1) AS avg_consts
FROM matches;

-- Break down by constant count threshold
SELECT '--- PRECISION BY MIN CONSTANTS ---' AS section;

WITH matches AS (
    SELECT
        a.func_name AS name_a, b.func_name AS name_b,
        a.const_count,
        CASE WHEN a.func_name = b.func_name THEN 1 ELSE 0 END AS is_correct
    FROM full_const_sets a
    JOIN full_const_sets b
      ON a.const_addrs = b.const_addrs
      AND a.source < b.source
    WHERE (a.source LIKE 'pico%' AND b.source LIKE 'pico%')
       OR (a.source LIKE 'zephyr%' AND b.source LIKE 'zephyr%')
)
SELECT
    CASE
        WHEN const_count >= 10 THEN '10+'
        WHEN const_count >= 5 THEN '5-9'
        WHEN const_count >= 3 THEN '3-4'
    END AS const_bucket,
    COUNT(*) AS matches,
    SUM(is_correct) AS correct,
    ROUND(100.0 * SUM(is_correct) / COUNT(*), 1) AS precision_pct
FROM matches
GROUP BY const_bucket
ORDER BY const_bucket DESC;

-- =====================================================================
-- 6. Cross-ISA test: Pico (M0+) vs Zephyr (M3)
--    These share no hardware, so peripheral matches are impossible.
--    But SRAM layout patterns or code constants might still match
--    for library functions (FreeRTOS internals, libc, etc.)
-- =====================================================================

SELECT '--- CROSS-ISA: Pico vs Zephyr (full constant set) ---' AS section;

-- Use relative offsets from function start instead of absolute addresses
-- This tests whether the PATTERN of constant references is similar
CREATE OR REPLACE TEMP TABLE relative_const_sets AS
SELECT
    source, function_addr, func_name,
    LIST(DISTINCT (to_addr - function_addr) ORDER BY (to_addr - function_addr)) AS relative_offsets,
    COUNT(DISTINCT to_addr) AS const_count
FROM func_constants
GROUP BY source, function_addr, func_name
HAVING COUNT(DISTINCT to_addr) >= 3;

SELECT
    a.source AS source_a, a.func_name AS name_a,
    b.source AS source_b, b.func_name AS name_b,
    a.const_count,
    CASE WHEN a.func_name = b.func_name THEN 'MATCH' ELSE 'MISMATCH' END AS name_match
FROM relative_const_sets a
JOIN relative_const_sets b
  ON a.relative_offsets = b.relative_offsets
  AND a.source < b.source
WHERE a.source LIKE 'pico%' AND b.source LIKE 'zephyr%'
ORDER BY a.const_count DESC
LIMIT 20;

-- =====================================================================
-- 7. String-based matching: functions referencing the same strings
-- =====================================================================

SELECT '--- STRING-BASED MATCHES ---' AS section;

CREATE OR REPLACE TEMP TABLE func_strings AS
SELECT
    x.source, x.function_addr, f.name AS func_name,
    LIST(s.value ORDER BY s.value) AS string_set,
    COUNT(*) AS string_count
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
WHERE x.ref_type IN ('DATA', 'READ', 'PARAM')
GROUP BY x.source, x.function_addr, f.name
HAVING COUNT(*) >= 1;

SELECT
    a.source AS source_a, a.func_name AS name_a,
    b.source AS source_b, b.func_name AS name_b,
    a.string_count,
    a.string_set,
    CASE WHEN a.func_name = b.func_name THEN 'MATCH' ELSE 'MISMATCH' END AS name_match
FROM func_strings a
JOIN func_strings b
  ON a.string_set = b.string_set
  AND a.source < b.source
ORDER BY a.string_count DESC, a.func_name
LIMIT 30;

-- =====================================================================
-- 8. Combined signal: structural + constant matching
--    Does adding constants to the structural fingerprint improve precision?
-- =====================================================================

SELECT '--- COMBINED: STRUCTURAL + CONSTANTS ---' AS section;

CREATE OR REPLACE TEMP TABLE combined_fp AS
WITH
    bb_agg AS (
        SELECT source, function_addr,
               SUM(instruction_count) AS instructions
        FROM basic_blocks
        WHERE function_addr IS NOT NULL
        GROUP BY source, function_addr
    ),
    xref_agg AS (
        SELECT source, function_addr,
               COUNT(DISTINCT CASE WHEN ref_type IN ('READ','DATA') THEN to_addr END) AS reads,
               COUNT(DISTINCT CASE WHEN ref_type = 'WRITE' THEN to_addr END) AS writes
        FROM xrefs
        GROUP BY source, function_addr
    ),
    call_agg AS (
        SELECT source, caller_addr AS function_addr,
               COUNT(*) AS outgoing_calls,
               COUNT(DISTINCT callee_addr) AS distinct_callees
        FROM calls
        GROUP BY source, caller_addr
    )
SELECT
    f.source, f.addr, f.name, f.size,
    f.basic_block_count,
    COALESCE(bb.instructions, 0) AS instructions,
    COALESCE(ca.outgoing_calls, 0) AS outgoing_calls,
    COALESCE(ca.distinct_callees, 0) AS distinct_callees,
    COALESCE(xa.reads, 0) AS reads,
    COALESCE(xa.writes, 0) AS writes,
    fc.const_count,
    fc.const_addrs
FROM functions f
LEFT JOIN bb_agg bb ON bb.source = f.source AND bb.function_addr = f.addr
LEFT JOIN call_agg ca ON ca.source = f.source AND ca.function_addr = f.addr
LEFT JOIN xref_agg xa ON xa.source = f.source AND xa.function_addr = f.addr
LEFT JOIN full_const_sets fc ON fc.source = f.source AND fc.function_addr = f.addr
WHERE f.is_thunk = false AND f.size >= 16;

-- Structural-only matches vs structural+constant matches
WITH struct_matches AS (
    SELECT a.name AS name_a, b.name AS name_b,
           CASE WHEN a.name = b.name THEN 1 ELSE 0 END AS correct,
           'structural_only' AS method
    FROM combined_fp a
    JOIN combined_fp b
      ON a.size = b.size
      AND a.basic_block_count = b.basic_block_count
      AND a.instructions = b.instructions
      AND a.outgoing_calls = b.outgoing_calls
      AND a.distinct_callees = b.distinct_callees
      AND a.reads = b.reads AND a.writes = b.writes
      AND a.source < b.source
    WHERE a.source LIKE 'pico%' AND b.source LIKE 'pico%'

    UNION ALL

    SELECT a.name, b.name,
           CASE WHEN a.name = b.name THEN 1 ELSE 0 END,
           'structural+constants'
    FROM combined_fp a
    JOIN combined_fp b
      ON a.size = b.size
      AND a.basic_block_count = b.basic_block_count
      AND a.instructions = b.instructions
      AND a.outgoing_calls = b.outgoing_calls
      AND a.distinct_callees = b.distinct_callees
      AND a.reads = b.reads AND a.writes = b.writes
      AND a.const_addrs IS NOT NULL AND b.const_addrs IS NOT NULL
      AND a.const_addrs = b.const_addrs
      AND a.source < b.source
    WHERE a.source LIKE 'pico%' AND b.source LIKE 'pico%'
)
SELECT
    method,
    COUNT(*) AS total_matches,
    SUM(correct) AS correct,
    ROUND(100.0 * SUM(correct) / COUNT(*), 1) AS precision_pct
FROM struct_matches
GROUP BY method
ORDER BY method;
