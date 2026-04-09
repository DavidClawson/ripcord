-- fpga_interaction.sql
-- Traces every function that touches FPGA interface peripherals
-- (SPI3, USART2, DMA1/2, GPIOB PB11, GPIOC PC6) and builds
-- the transitive call tree from hardware registers up to task-level.
--
-- Target: stock_v120 (FNIRSI 2C53T, AT32F403A + Gowin FPGA)
-- Peripheral addresses: AT32F403A = STM32F103 compatible register map

-- Step 1: Direct HW access functions with peripheral breakdown
SELECT f.name, printf('0x%08x', f.addr) AS addr, f.size, f.basic_block_count,
    STRING_AGG(DISTINCT
        CASE
            WHEN x.to_addr BETWEEN 1073759232 AND 1073759263 THEN 'USART2'
            WHEN x.to_addr BETWEEN 1073757184 AND 1073757215 THEN 'SPI3'
            WHEN x.to_addr BETWEEN 1073873920 AND 1073874175 THEN 'DMA2'
            WHEN x.to_addr BETWEEN 1073872896 AND 1073873919 THEN 'DMA1'
            WHEN x.to_addr IN (1073810448, 1073810452) THEN 'PB11'
            WHEN x.to_addr IN (1073811464, 1073811472, 1073811476) THEN 'PC6'
        END, ', '
    ) AS peripherals
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.ref_type IN ('READ', 'WRITE', 'PARAM')
  AND (
    x.to_addr BETWEEN 1073759232 AND 1073759263   -- USART2 0x40004400-0x4000441F
    OR x.to_addr BETWEEN 1073757184 AND 1073757215 -- SPI3   0x40003C00-0x40003C1F
    OR x.to_addr BETWEEN 1073873920 AND 1073874175 -- DMA2   0x40020400-0x400204FF
    OR x.to_addr BETWEEN 1073872896 AND 1073873919 -- DMA1   0x40020000-0x400203FF
    OR x.to_addr IN (1073810448, 1073810452)        -- GPIOB BSRR/BRR (PB11)
    OR x.to_addr IN (1073811464, 1073811472, 1073811476) -- GPIOC IDR/BSRR/BRR (PC6)
  )
GROUP BY f.name, f.addr, f.size, f.basic_block_count
ORDER BY f.size DESC;

-- Step 2: Full transitive reachability
WITH RECURSIVE
fpga_leaf AS (
    SELECT DISTINCT x.function_addr AS addr
    FROM xrefs x
    WHERE x.source = 'stock_v120'
      AND x.ref_type IN ('READ', 'WRITE', 'PARAM')
      AND (
        x.to_addr BETWEEN 1073759232 AND 1073759263
        OR x.to_addr BETWEEN 1073757184 AND 1073757215
        OR x.to_addr BETWEEN 1073873920 AND 1073874175
        OR x.to_addr BETWEEN 1073872896 AND 1073873919
        OR x.to_addr IN (1073810448, 1073810452)
        OR x.to_addr IN (1073811464, 1073811472, 1073811476)
      )
),
reaches_fpga(addr, depth) AS (
    SELECT addr, 0 FROM fpga_leaf
    UNION
    SELECT c.caller_addr, r.depth + 1
    FROM reaches_fpga r
    JOIN calls c ON c.source = 'stock_v120' AND c.callee_addr = r.addr
    WHERE r.depth < 8
)
SELECT f.name, printf('0x%08x', f.addr) AS addr, f.size, f.basic_block_count,
    MIN(r.depth) AS min_depth_to_hw,
    CASE WHEN MIN(r.depth) = 0 THEN 'DIRECT_HW_ACCESS'
         WHEN MIN(r.depth) = 1 THEN 'FPGA_DRIVER'
         WHEN MIN(r.depth) = 2 THEN 'ORCHESTRATOR'
         WHEN MIN(r.depth) = 3 THEN 'TASK_LEVEL'
         ELSE 'INDIRECT'
    END AS role
FROM reaches_fpga r
JOIN functions f ON f.source = 'stock_v120' AND f.addr = r.addr
GROUP BY f.name, f.addr, f.size, f.basic_block_count
ORDER BY MIN(r.depth), f.size DESC;
