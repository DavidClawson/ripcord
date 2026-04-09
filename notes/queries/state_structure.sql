-- State structure access analysis for FNIRSI 2C53T stock firmware (V1.2.0)
--
-- The firmware revolves around a ~4KB global state structure at 0x200000F8.
-- Register r9/sl holds the base address; decompiled code references offsets
-- like *(byte *)(unaff_r9 + 0x2D) for timebase_index.
--
-- This query file maps every READ and WRITE xref that falls within the
-- structure's address range (0x200000F8 .. 0x20001088) and groups them
-- by function, offset, and direction. The output reveals:
--   - which functions are the primary writers of scope-critical state
--   - which functions read those values
--   - the writer->reader data flow chains through the structure
--
-- The osc project's STATE_STRUCTURE.md provides the offset->name map.
-- Key offsets for scope mode experiments:
--   +0xF68 (0x20001060): system_mode / command-bank selector
--   +0xF69 (0x20001061): mode_transition_flags (packed)
--   +0xF6A (0x20001062): scope_ui_state_flags
--   +0xF6B (0x20001063): mode_flags (packed display/marker)
--   +0xE1B (0x20000F13): panel_entry_count
--   +0xE1C (0x20000F14): panel_subview_state
--
-- Key empirical findings (2026-04-08):
--
--   1. FUN_08027a50 (15346 bytes) is the dominant state writer: 171 distinct
--      offsets written, 252 total write refs. It also directly accesses
--      USART2 registers (0x40004408-0x40004410), making it the central
--      "state-commit + FPGA-command" function. It is the sole writer of
--      +0xF69, +0xF6A, and +0xF6B, and one of two writers of +0xF68.
--
--   2. FUN_08006c78 (840 bytes) is the other writer of +0xF68 (system_mode).
--      It manipulates DAT_20001060 with bitmask operations (| 0x80, & 0x7f)
--      suggesting bit 7 is a flag while bits 0-6 carry mode state. It also
--      reads USART peripheral status registers and calls FUN_080263bc(0x55).
--
--   3. The +0xF68 byte (system_mode) has 8 distinct readers spanning scope
--      UI draw helpers (FUN_0800d014, FUN_0800d314, FUN_0800d6e8,
--      FUN_0800da94), scope FSM (FUN_0801de98), and FUN_08027a50 itself.
--      The data flow is: FUN_08006c78/FUN_08027a50 write -> multiple scope
--      draw/FSM functions read -> UI rendering branches.
--
--   4. No xrefs found at offset +0x355 (0x2000044D). This address may be
--      accessed through computed offsets (r9 + register) that Ghidra's
--      static xref analysis does not resolve. Nearby +0x354 (0x2000044C)
--      is accessed by FUN_080263bc (READ+WRITE) and FUN_08027a50 (READ+WRITE).
--
--   5. The +0xE1A..+0xE1D panel staging range is sparsely referenced:
--      only +0xE1B (WRITE by FUN_08027a50) and +0xE1C (READ by FUN_0801c19c).
--      This suggests either indirect access patterns or that these bytes
--      are not as hot as the scope experiment priorities note implied.
--
-- Run: scripts/query < notes/queries/state_structure.sql

-- ========================================================================
-- Q1: Per-offset access summary (who reads/writes each state byte)
-- ========================================================================

SELECT
    printf('0x%03X', x.to_addr - 536871160) AS state_offset,
    printf('0x%08X', x.to_addr) AS abs_addr,
    x.ref_type,
    COUNT(DISTINCT x.function_addr) AS num_functions,
    COUNT(*) AS total_refs
FROM xrefs x
WHERE x.source = 'stock_v120'
  AND x.to_addr BETWEEN 536871160 AND 536875144
  AND x.ref_type IN ('READ', 'WRITE')
GROUP BY x.to_addr, x.ref_type
ORDER BY x.to_addr, x.ref_type;

-- ========================================================================
-- Q2: Top state structure accessor functions (reads + writes)
-- ========================================================================

SELECT
    f.name AS function_name,
    printf('0x%08X', f.addr) AS fn_addr,
    f.size AS fn_size,
    SUM(CASE WHEN x.ref_type = 'READ' THEN 1 ELSE 0 END) AS reads,
    SUM(CASE WHEN x.ref_type = 'WRITE' THEN 1 ELSE 0 END) AS writes,
    COUNT(*) AS total_refs,
    COUNT(DISTINCT x.to_addr) AS distinct_offsets
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.to_addr BETWEEN 536871160 AND 536875144
  AND x.ref_type IN ('READ', 'WRITE')
GROUP BY f.name, f.addr, f.size
ORDER BY total_refs DESC
LIMIT 30;

-- ========================================================================
-- Q3: Scope-critical preset bytes (+0xF68..+0xF6B = 0x20001060..0x20001063)
-- ========================================================================

SELECT
    printf('0x%03X', x.to_addr - 536871160) AS state_offset,
    printf('0x%08X', x.to_addr) AS abs_addr,
    f.name AS function_name,
    x.ref_type,
    COUNT(*) AS access_count
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.to_addr BETWEEN 536875104 AND 536875107
  AND x.ref_type IN ('READ', 'WRITE')
GROUP BY x.to_addr, f.name, x.ref_type
ORDER BY x.to_addr, x.ref_type, f.name;

-- ========================================================================
-- Q4: Panel staging bytes (+0xE1A..+0xE1D = 0x20000F12..0x20000F15)
-- ========================================================================

SELECT
    printf('0x%03X', x.to_addr - 536871160) AS state_offset,
    printf('0x%08X', x.to_addr) AS abs_addr,
    f.name AS function_name,
    x.ref_type,
    COUNT(*) AS access_count
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.to_addr BETWEEN 536874770 AND 536874773
  AND x.ref_type IN ('READ', 'WRITE')
GROUP BY x.to_addr, f.name, x.ref_type
ORDER BY x.to_addr, x.ref_type, f.name;

-- ========================================================================
-- Q5: Channel state / flag region (+0x350..+0x355 = 0x20000448..0x2000044D)
-- ========================================================================

SELECT
    printf('0x%03X', x.to_addr - 536871160) AS state_offset,
    printf('0x%08X', x.to_addr) AS abs_addr,
    f.name AS function_name,
    x.ref_type,
    COUNT(*) AS access_count
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.to_addr BETWEEN 536871880 AND 536872013
  AND x.ref_type IN ('READ', 'WRITE')
GROUP BY x.to_addr, f.name, x.ref_type
ORDER BY x.to_addr, x.ref_type, f.name;

-- ========================================================================
-- Q6: Writer -> Reader data flow for preset bytes (+0xF68..+0xF6B)
-- ========================================================================

WITH writers AS (
    SELECT DISTINCT x.to_addr, f.addr AS fn_addr, f.name AS fn_name
    FROM xrefs x
    JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
    WHERE x.source = 'stock_v120'
      AND x.to_addr BETWEEN 536875104 AND 536875107
      AND x.ref_type = 'WRITE'
),
readers AS (
    SELECT DISTINCT x.to_addr, f.addr AS fn_addr, f.name AS fn_name
    FROM xrefs x
    JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
    WHERE x.source = 'stock_v120'
      AND x.to_addr BETWEEN 536875104 AND 536875107
      AND x.ref_type = 'READ'
)
SELECT
    printf('0x%03X', w.to_addr - 536871160) AS state_offset,
    w.fn_name AS writer,
    STRING_AGG(DISTINCT r.fn_name, ', ' ORDER BY r.fn_name) AS readers,
    COUNT(DISTINCT r.fn_addr) AS reader_count
FROM writers w
JOIN readers r ON w.to_addr = r.to_addr AND w.fn_addr != r.fn_addr
GROUP BY w.to_addr, w.fn_name
ORDER BY state_offset, writer;

-- ========================================================================
-- Q7: Full state structure writer -> reader flow (all offsets, top pairs)
-- ========================================================================

WITH writers AS (
    SELECT DISTINCT x.to_addr, f.addr AS fn_addr, f.name AS fn_name
    FROM xrefs x
    JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
    WHERE x.source = 'stock_v120'
      AND x.to_addr BETWEEN 536871160 AND 536875144
      AND x.ref_type = 'WRITE'
),
readers AS (
    SELECT DISTINCT x.to_addr, f.addr AS fn_addr, f.name AS fn_name
    FROM xrefs x
    JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
    WHERE x.source = 'stock_v120'
      AND x.to_addr BETWEEN 536871160 AND 536875144
      AND x.ref_type = 'READ'
)
SELECT
    w.fn_name AS writer,
    r.fn_name AS reader,
    COUNT(DISTINCT w.to_addr) AS shared_offsets
FROM writers w
JOIN readers r ON w.to_addr = r.to_addr AND w.fn_addr != r.fn_addr
GROUP BY w.fn_name, r.fn_name
HAVING shared_offsets >= 3
ORDER BY shared_offsets DESC
LIMIT 30;

-- ========================================================================
-- Q8: USART2 peripheral access (0x40004400-0x40004410)
-- Who touches the FPGA communication registers?
-- ========================================================================

SELECT
    printf('0x%08X', x.to_addr) AS periph_addr,
    f.name AS function_name,
    x.ref_type,
    COUNT(*) AS access_count
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.to_addr BETWEEN 1073759232 AND 1073760255
  AND x.ref_type IN ('READ', 'WRITE')
GROUP BY x.to_addr, f.name, x.ref_type
ORDER BY x.to_addr, f.name;
