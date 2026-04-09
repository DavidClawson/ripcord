-- recovered_calls.sql — Analyze recovered call edges by mechanism
--
-- Shows what the computed call recovery extractor found per target:
-- vector table ISR handlers, function-pointer references, veneer
-- jumps, and registrar dispatch inferences. Useful for validating
-- the recovery quality and understanding call-graph completeness.
--
-- Run: scripts/query < notes/queries/recovered_calls.sql

-- 1. Per-target, per-mechanism summary
SELECT
    rc.source,
    rc.mechanism,
    COUNT(*) AS edges,
    ROUND(AVG(rc.confidence), 2) AS avg_confidence,
    ROUND(MIN(rc.confidence), 2) AS min_confidence
FROM recovered_calls rc
GROUP BY rc.source, rc.mechanism
ORDER BY rc.source, rc.mechanism;

-- 2. Vector table entries with function names
SELECT
    rc.source,
    rc.callee_addr,
    f.name AS handler_name,
    rc.detail
FROM recovered_calls rc
JOIN functions f ON f.source = rc.source AND f.addr = rc.callee_addr
WHERE rc.mechanism = 'vector_table'
ORDER BY rc.source, rc.call_site_addr;

-- 3. Reachability improvement: compare static-only vs static+recovered
--    (Uses DuckDB recursive CTE — same approach as reachability.sql)
WITH RECURSIVE
    -- Static edges only
    static_reach(addr) AS (
        SELECT addr FROM functions WHERE name = 'main'
        UNION
        SELECT c.callee_addr
        FROM static_reach sr
        JOIN calls c ON c.source = (SELECT DISTINCT source FROM functions LIMIT 1)
            AND c.caller_addr = sr.addr
            AND c.callee_addr IS NOT NULL
    ),
    -- Static + recovered edges
    full_edges AS (
        SELECT source, caller_addr, callee_addr FROM calls
        WHERE callee_addr IS NOT NULL
        UNION
        SELECT source, caller_addr, callee_addr FROM recovered_calls
        WHERE caller_addr IS NOT NULL AND callee_addr IS NOT NULL
    ),
    full_reach(addr) AS (
        SELECT addr FROM functions WHERE name = 'main'
        UNION
        SELECT fe.callee_addr
        FROM full_reach fr
        JOIN full_edges fe ON fe.source = (SELECT DISTINCT source FROM functions LIMIT 1)
            AND fe.caller_addr = fr.addr
    )
SELECT
    f.source,
    COUNT(DISTINCT f.addr) AS total_functions,
    COUNT(DISTINCT sr.addr) AS static_reachable,
    COUNT(DISTINCT fr.addr) AS full_reachable,
    COUNT(DISTINCT fr.addr) - COUNT(DISTINCT sr.addr) AS newly_reachable,
    ROUND(100.0 * COUNT(DISTINCT sr.addr) / COUNT(DISTINCT f.addr), 1) AS static_pct,
    ROUND(100.0 * COUNT(DISTINCT fr.addr) / COUNT(DISTINCT f.addr), 1) AS full_pct
FROM functions f
LEFT JOIN static_reach sr ON sr.addr = f.addr
LEFT JOIN full_reach fr ON fr.addr = f.addr
GROUP BY f.source;
