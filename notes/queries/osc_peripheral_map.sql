-- Peripheral register access map for FNIRSI 2C53T stock firmware.
--
-- Groups all MMIO accesses by peripheral block and shows which
-- functions touch them. The AT32F403A is register-compatible with
-- STM32F103 for most peripherals; address ranges below are from the
-- AT32F403A reference manual.
--
-- Usage:
--   scripts/query < notes/queries/osc_peripheral_map.sql

-- 1. Classify every xref into the peripheral address space.
CREATE OR REPLACE VIEW peripheral_access AS
SELECT
    f.name,
    f.addr AS fn_addr,
    f.size,
    CASE
        -- APB1 peripherals (0x40000000 - 0x4000FFFF)
        WHEN x.to_addr BETWEEN 1073741824 AND 1073742847   THEN 'TMR2'         -- 0x40000000
        WHEN x.to_addr BETWEEN 1073742848 AND 1073743871   THEN 'TMR3'         -- 0x40000400
        WHEN x.to_addr BETWEEN 1073743872 AND 1073744895   THEN 'TMR4'         -- 0x40000800
        WHEN x.to_addr BETWEEN 1073744896 AND 1073745919   THEN 'TMR5'         -- 0x40000C00
        WHEN x.to_addr BETWEEN 1073747968 AND 1073748991   THEN 'TMR6'         -- 0x40001800
        WHEN x.to_addr BETWEEN 1073748992 AND 1073750015   THEN 'TMR7'         -- 0x40001C00
        WHEN x.to_addr BETWEEN 1073754112 AND 1073755135   THEN 'USART6/7/8'   -- 0x40003000
        WHEN x.to_addr BETWEEN 1073756160 AND 1073757183   THEN 'SPI2'         -- 0x40003800
        WHEN x.to_addr BETWEEN 1073757184 AND 1073758207   THEN 'SPI3'         -- 0x40003C00
        WHEN x.to_addr BETWEEN 1073759232 AND 1073760255   THEN 'USART2'       -- 0x40004400
        WHEN x.to_addr BETWEEN 1073760256 AND 1073761279   THEN 'USART3'       -- 0x40004800
        WHEN x.to_addr BETWEEN 1073761280 AND 1073762303   THEN 'UART4'        -- 0x40004C00
        WHEN x.to_addr BETWEEN 1073763328 AND 1073764351   THEN 'I2C1'         -- 0x40005400
        WHEN x.to_addr BETWEEN 1073764352 AND 1073765375   THEN 'I2C2'         -- 0x40005800
        WHEN x.to_addr BETWEEN 1073765376 AND 1073766399   THEN 'I2C3'         -- 0x40005C00
        WHEN x.to_addr BETWEEN 1073770496 AND 1073771519   THEN 'DAC'          -- 0x40007000
        WHEN x.to_addr BETWEEN 1073771520 AND 1073772543   THEN 'PWR'          -- 0x40007400
        -- APB2 peripherals (0x40010000 - 0x4001FFFF)
        WHEN x.to_addr BETWEEN 1073807360 AND 1073808383   THEN 'AFIO/IOMUX'  -- 0x40010000
        WHEN x.to_addr BETWEEN 1073808384 AND 1073809407   THEN 'EXTI'         -- 0x40010400
        WHEN x.to_addr BETWEEN 1073809408 AND 1073810431   THEN 'GPIOA'        -- 0x40010800
        WHEN x.to_addr BETWEEN 1073810432 AND 1073811455   THEN 'GPIOB'        -- 0x40010C00
        WHEN x.to_addr BETWEEN 1073811456 AND 1073812479   THEN 'GPIOC'        -- 0x40011000
        WHEN x.to_addr BETWEEN 1073812480 AND 1073813503   THEN 'GPIOD'        -- 0x40011400
        WHEN x.to_addr BETWEEN 1073813504 AND 1073814527   THEN 'GPIOE'        -- 0x40011800
        WHEN x.to_addr BETWEEN 1073816576 AND 1073817599   THEN 'ADC1'         -- 0x40012400
        WHEN x.to_addr BETWEEN 1073817600 AND 1073818623   THEN 'ADC2'         -- 0x40012800
        WHEN x.to_addr BETWEEN 1073820672 AND 1073821695   THEN 'TMR1'         -- 0x40013400
        WHEN x.to_addr BETWEEN 1073821696 AND 1073822719   THEN 'SPI1'         -- 0x40013800
        WHEN x.to_addr BETWEEN 1073822720 AND 1073823743   THEN 'TMR8'         -- 0x40013C00
        WHEN x.to_addr BETWEEN 1073823744 AND 1073824767   THEN 'USART1'       -- 0x40014000
        WHEN x.to_addr BETWEEN 1073826816 AND 1073827839   THEN 'TMR9'         -- 0x40014C00
        WHEN x.to_addr BETWEEN 1073827840 AND 1073828863   THEN 'TMR10'        -- 0x40015000
        WHEN x.to_addr BETWEEN 1073828864 AND 1073829887   THEN 'TMR11'        -- 0x40015400
        WHEN x.to_addr BETWEEN 1073829888 AND 1073830911   THEN 'TMR11_EXT'    -- 0x40015800
        -- AHB peripherals (0x40020000+)
        WHEN x.to_addr BETWEEN 1073872896 AND 1073873919   THEN 'DMA1'         -- 0x40020000
        WHEN x.to_addr BETWEEN 1073873920 AND 1073874943   THEN 'DMA2'         -- 0x40020400
        WHEN x.to_addr BETWEEN 1073876992 AND 1073877247   THEN 'RCC'          -- 0x40021000
        WHEN x.to_addr BETWEEN 1073881088 AND 1073881343   THEN 'FLASH_CTRL'   -- 0x40022000
        -- SDIO (AT32-specific)
        WHEN x.to_addr BETWEEN 2684354560 AND 2684355583   THEN 'SDIO'         -- 0xA0000000
        -- FSMC / external LCD
        WHEN x.to_addr BETWEEN 1610612736 AND 1879048191   THEN 'FSMC/LCD'     -- 0x60000000
        -- Cortex-M4 system peripherals
        WHEN x.to_addr BETWEEN 3758153744 AND 3758153759   THEN 'SYSTICK'      -- 0xE000E010
        WHEN x.to_addr BETWEEN 3758153984 AND 3758157311   THEN 'NVIC'         -- 0xE000E100
        WHEN x.to_addr BETWEEN 3758157312 AND 3758157567   THEN 'SCB'          -- 0xE000ED00
        WHEN x.to_addr BETWEEN 3758161920 AND 3758162175   THEN 'FPU'          -- 0xE000EF00
        ELSE 'UNKNOWN_' || printf('0x%08x', x.to_addr)
    END AS peripheral,
    printf('0x%08x', x.to_addr) AS reg_hex,
    x.to_addr AS reg_addr,
    x.ref_type
FROM xrefs x
JOIN functions f ON f.source = x.source AND f.addr = x.function_addr
WHERE x.source = 'stock_v120'
  AND x.to_addr >= 1073741824;   -- 0x40000000

-- 2. Summary: peripherals ranked by access count and function count.
SELECT peripheral,
       COUNT(DISTINCT fn_addr) AS functions,
       COUNT(*) AS accesses,
       COUNT(DISTINCT reg_addr) AS distinct_regs
FROM peripheral_access
GROUP BY peripheral
ORDER BY accesses DESC;

-- 3. Which functions touch which peripherals (filtered to significant accessors).
SELECT name, peripheral,
       COUNT(*) AS accesses,
       LIST(DISTINCT reg_hex ORDER BY reg_hex)[:5] AS sample_regs
FROM peripheral_access
GROUP BY name, peripheral
HAVING accesses >= 3
ORDER BY peripheral, accesses DESC;

-- 4. Multi-peripheral functions: functions that touch 3+ different peripherals.
--    These are likely init routines or complex drivers.
SELECT name,
       printf('0x%08x', fn_addr) AS hex,
       size,
       COUNT(DISTINCT peripheral) AS periph_count,
       LIST(DISTINCT peripheral ORDER BY peripheral) AS peripherals
FROM peripheral_access
GROUP BY name, fn_addr, size
HAVING COUNT(DISTINCT peripheral) >= 3
ORDER BY periph_count DESC, size DESC;
