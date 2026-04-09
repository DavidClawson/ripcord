-- peripheral_summary.sql — Per-function peripheral access classification
--
-- Uses the peripheral_xrefs table (derived from xrefs + SVD register maps)
-- to answer: "what hardware does each function touch?"
--
-- Three views at increasing granularity:
--   1. Per-target peripheral usage overview
--   2. Per-function peripheral profile (which peripherals, which registers)
--   3. Multi-peripheral functions (hardware integration points)

-- ============================================================
-- 1. Target-level peripheral overview
-- ============================================================
-- How many functions touch each peripheral group?
-- Useful for understanding a binary's hardware surface at a glance.

SELECT
    p.source,
    p.peripheral_group,
    LIST(DISTINCT p.peripheral ORDER BY p.peripheral) AS peripherals,
    COUNT(DISTINCT p.function_addr) AS functions,
    COUNT(DISTINCT p.access_addr) AS distinct_registers,
    COUNT(*) AS total_accesses
FROM peripheral_xrefs p
GROUP BY p.source, p.peripheral_group
ORDER BY p.source, total_accesses DESC;

-- ============================================================
-- 2. Per-function peripheral profile
-- ============================================================
-- For each function, list every peripheral it accesses and the
-- specific registers it touches. This is the core classification:
-- "this function is an SPI driver", "this function configures DMA".

SELECT
    p.source,
    f.name AS function_name,
    printf('0x%08X', p.function_addr) AS addr,
    f.size,
    p.peripheral,
    p.peripheral_group,
    LIST(DISTINCT p.register_name ORDER BY p.register_name)
        FILTER (WHERE p.register_name != '') AS registers,
    SUM(CASE WHEN p.ref_type IN ('READ', 'DATA') THEN 1 ELSE 0 END) AS reads,
    SUM(CASE WHEN p.ref_type = 'WRITE' THEN 1 ELSE 0 END) AS writes,
    COUNT(*) AS total
FROM peripheral_xrefs p
JOIN functions f ON p.source = f.source AND p.function_addr = f.addr
GROUP BY p.source, f.name, p.function_addr, f.size, p.peripheral, p.peripheral_group
ORDER BY p.source, f.name, total DESC;

-- ============================================================
-- 3. Multi-peripheral functions (hardware integration points)
-- ============================================================
-- Functions that access 2+ distinct peripheral groups are hardware
-- integration points: init routines, DMA-driven transfers, ISR
-- handlers coordinating multiple subsystems. These are the most
-- architecturally significant functions in any firmware.

SELECT
    p.source,
    f.name AS function_name,
    printf('0x%08X', p.function_addr) AS addr,
    f.size,
    COUNT(DISTINCT p.peripheral_group) AS groups_touched,
    LIST(DISTINCT p.peripheral_group ORDER BY p.peripheral_group) AS groups,
    LIST(DISTINCT p.peripheral ORDER BY p.peripheral) AS peripherals,
    COUNT(DISTINCT p.access_addr) AS distinct_registers,
    COUNT(*) AS total_accesses
FROM peripheral_xrefs p
JOIN functions f ON p.source = f.source AND p.function_addr = f.addr
GROUP BY p.source, f.name, p.function_addr, f.size
HAVING COUNT(DISTINCT p.peripheral_group) >= 2
ORDER BY p.source, groups_touched DESC, total_accesses DESC;
