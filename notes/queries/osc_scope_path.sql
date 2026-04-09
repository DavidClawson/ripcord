-- Scope acquisition path analysis for FNIRSI 2C53T stock firmware.
--
-- Traces the call graph backward from functions that access the FPGA
-- communication peripherals (USART2 for FPGA serial, SPI3 for FPGA
-- SPI, DMA channels for bulk transfer, FSMC/LCD for display output).
-- This finds the full acquisition-to-display pipeline.
--
-- Usage:
--   scripts/query < notes/queries/osc_scope_path.sql

-- 1. Identify leaf functions that directly access FPGA-facing peripherals.
CREATE OR REPLACE VIEW fpga_accessors AS
SELECT DISTINCT
    x.function_addr AS addr,
    CASE
        WHEN x.to_addr BETWEEN 1073759232 AND 1073760255 THEN 'USART2'     -- 0x40004400
        WHEN x.to_addr BETWEEN 1073757184 AND 1073758207 THEN 'SPI3'       -- 0x40003C00
        WHEN x.to_addr BETWEEN 1073872896 AND 1073873919 THEN 'DMA1'       -- 0x40020000
        WHEN x.to_addr BETWEEN 1073873920 AND 1073874943 THEN 'DMA2'       -- 0x40020400
        WHEN x.to_addr BETWEEN 1610612736 AND 1879048191 THEN 'FSMC/LCD'   -- 0x60000000
    END AS peripheral
FROM xrefs x
WHERE x.source = 'stock_v120'
  AND (
    x.to_addr BETWEEN 1073759232 AND 1073760255     -- USART2 (0x40004400)
    OR x.to_addr BETWEEN 1073757184 AND 1073758207  -- SPI3 (0x40003C00)
    OR x.to_addr BETWEEN 1073872896 AND 1073873919  -- DMA1 (0x40020000)
    OR x.to_addr BETWEEN 1073873920 AND 1073874943  -- DMA2 (0x40020400)
    OR x.to_addr BETWEEN 1610612736 AND 1879048191  -- FSMC/LCD (0x60000000)
  );

-- 2. Direct FPGA peripheral accessors with their function names.
SELECT f.name,
       printf('0x%08x', f.addr) AS hex,
       f.size,
       LIST(DISTINCT fa.peripheral ORDER BY fa.peripheral) AS peripherals,
       COUNT(DISTINCT fa.peripheral) AS periph_count
FROM fpga_accessors fa
JOIN functions f ON f.source = 'stock_v120' AND f.addr = fa.addr
GROUP BY f.name, f.addr, f.size
ORDER BY periph_count DESC, f.size DESC;

-- 3. Reverse call tree: who calls the FPGA accessor functions?
--    Walks up to 8 levels of callers.
WITH RECURSIVE
reaches_fpga(addr, depth) AS (
    SELECT DISTINCT addr, 0 FROM fpga_accessors
    UNION
    SELECT c.caller_addr, r.depth + 1
    FROM reaches_fpga r
    JOIN calls c ON c.source = 'stock_v120' AND c.callee_addr = r.addr
    WHERE r.depth < 8
)
SELECT f.name,
       printf('0x%08x', f.addr) AS hex,
       f.size,
       MIN(r.depth) AS fpga_depth
FROM reaches_fpga r
JOIN functions f ON f.source = 'stock_v120' AND f.addr = r.addr
GROUP BY f.name, f.addr, f.size
ORDER BY fpga_depth, f.size DESC;

-- 4. The acquisition hot path: functions at depth 0-2 with their
--    direct peripheral accesses and who calls them.
WITH RECURSIVE
reaches_fpga(addr, depth) AS (
    SELECT DISTINCT addr, 0 FROM fpga_accessors
    UNION
    SELECT c.caller_addr, r.depth + 1
    FROM reaches_fpga r
    JOIN calls c ON c.source = 'stock_v120' AND c.callee_addr = r.addr
    WHERE r.depth < 2
),
hot_path AS (
    SELECT f.name, f.addr, f.size, MIN(r.depth) AS depth
    FROM reaches_fpga r
    JOIN functions f ON f.source = 'stock_v120' AND f.addr = r.addr
    GROUP BY f.name, f.addr, f.size
)
SELECT hp.name,
       printf('0x%08x', hp.addr) AS hex,
       hp.size,
       hp.depth,
       COALESCE(LIST(DISTINCT fa.peripheral ORDER BY fa.peripheral)
                FILTER (WHERE fa.peripheral IS NOT NULL), []) AS direct_peripherals,
       COALESCE(LIST(DISTINCT caller_f.name ORDER BY caller_f.name)
                FILTER (WHERE caller_f.name IS NOT NULL), []) AS called_by
FROM hot_path hp
LEFT JOIN fpga_accessors fa ON fa.addr = hp.addr
LEFT JOIN calls c ON c.source = 'stock_v120' AND c.callee_addr = hp.addr
LEFT JOIN functions caller_f ON caller_f.source = 'stock_v120' AND caller_f.addr = c.caller_addr
GROUP BY hp.name, hp.addr, hp.size, hp.depth
ORDER BY hp.depth, hp.size DESC;

-- 5. ADC acquisition path: functions accessing ADC registers.
--    The AT32F403A ADC drives the analog front end.
SELECT f.name,
       printf('0x%08x', f.addr) AS hex,
       f.size,
       LIST(DISTINCT printf('0x%08x', x.to_addr)) AS adc_regs
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND (x.to_addr BETWEEN 1073816576 AND 1073817599     -- ADC1: 0x40012400
       OR x.to_addr BETWEEN 1073817600 AND 1073818623) -- ADC2: 0x40012800
GROUP BY f.name, f.addr, f.size
ORDER BY f.size DESC;
