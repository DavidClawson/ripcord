-- Decompiled code search for FNIRSI 2C53T stock firmware (V1.2.0).
--
-- Pattern-based queries against the pseudo-C decompilation. Useful for
-- finding where specific register addresses, constants, RAM addresses,
-- or API names appear in the decompiled output.
--
-- NOTE: Ghidra's decompiler renders MMIO addresses as DAT_XXXXXXXX
-- labels (e.g. DAT_40004404 for USART2_DR), not as 0x-prefixed hex.
-- Search patterns must match accordingly.
--
-- Only stock_v120 has decompiled data in the warehouse.
--
-- Usage:
--   scripts/query < notes/queries/osc_decompiled_search.sql
--   Or: copy individual queries and modify the LIKE pattern.

-- 1. Functions referencing USART2 registers (FPGA serial link).
--    DAT_4000440x covers SR, DR, BRR, CR registers.
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND d.decompile_success
  AND d.decompiled_c LIKE '%DAT_400044%'
ORDER BY f.size DESC;

-- 2. Functions referencing SPI3 registers (FPGA SPI link).
--    DAT_40003c0x covers CR1, CR2, SR, DR.
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND d.decompile_success
  AND d.decompiled_c LIKE '%DAT_40003c%'
ORDER BY f.size DESC;

-- 3. Functions referencing the FSMC/LCD data address (display writes).
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND d.decompile_success
  AND d.decompiled_c LIKE '%DAT_6001%'
ORDER BY f.size DESC;

-- 4. Functions referencing RAM globals in the 0x20000000 region
--    (likely oscilloscope state structures).
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size,
       LENGTH(d.decompiled_c) AS c_length
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND d.decompile_success
  AND d.decompiled_c LIKE '%DAT_2000%'
ORDER BY f.size DESC
LIMIT 30;

-- 5. Largest decompiled functions (likely main loop, init, or complex drivers).
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size AS fn_bytes,
       LENGTH(d.decompiled_c) AS c_chars,
       f.basic_block_count AS blocks
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND d.decompile_success
ORDER BY LENGTH(d.decompiled_c) DESC
LIMIT 20;

-- 6. Functions that failed to decompile (timeout, error).
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND NOT d.decompile_success
ORDER BY f.size DESC;

-- 7. Search for DMA register references in decompiled code.
--    DMA is key to bulk data transfer from FPGA.
SELECT printf('0x%08x', d.addr) AS hex,
       d.name,
       f.size
FROM decompiled d
JOIN functions f ON f.source = d.source AND f.addr = d.addr
WHERE d.source = 'stock_v120'
  AND d.decompile_success
  AND (d.decompiled_c LIKE '%DAT_40020%' OR d.decompiled_c LIKE '%DAT_40021%')
ORDER BY f.size DESC;
