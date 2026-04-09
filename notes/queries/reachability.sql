-- reachability.sql — DuckDB recursive CTE equivalent of Stage 4 derivations
--
-- Demonstrates transitive call reachability, orchestrator detection,
-- and subsystem clustering using DuckDB recursive CTEs over the
-- warehouse tables. This is the inline alternative to the Souffle
-- derivation layer (scripts/datalog/reachability.dl) — useful for
-- ad-hoc queries and targets where running Souffle is overkill.
--
-- Usage: scripts/query < notes/queries/reachability.sql
--
-- Change the target name below to analyze a different target.

-- ----------------------------------------------------------------
-- 1. Transitive reachability from main
-- ----------------------------------------------------------------

WITH RECURSIVE
main_addr AS (
    SELECT addr FROM functions
    WHERE source = 'pico_freertos_hello' AND name = 'main'
),
reachable AS (
    SELECT DISTINCT callee_addr AS addr, 1 AS depth
    FROM calls, main_addr
    WHERE source = 'pico_freertos_hello'
      AND caller_addr = main_addr.addr
      AND callee_addr IS NOT NULL
    UNION
    SELECT DISTINCT c.callee_addr, r.depth + 1
    FROM reachable r
    JOIN calls c ON c.caller_addr = r.addr
        AND c.source = 'pico_freertos_hello'
        AND c.callee_addr IS NOT NULL
    WHERE r.depth < 30
)
SELECT
    f.name,
    MIN(r.depth) AS min_depth,
    r.addr
FROM reachable r
JOIN functions f ON f.source = 'pico_freertos_hello' AND f.addr = r.addr
GROUP BY f.name, r.addr
ORDER BY min_depth, f.name;

-- ----------------------------------------------------------------
-- 2. Orchestrator detection: top functions by transitive reach
-- ----------------------------------------------------------------

WITH RECURSIVE
reachable AS (
    SELECT caller_addr AS src, callee_addr AS addr
    FROM calls
    WHERE source = 'pico_freertos_hello'
      AND callee_addr IS NOT NULL
    UNION
    SELECT r.src, c.callee_addr
    FROM reachable r
    JOIN calls c ON c.caller_addr = r.addr
        AND c.source = 'pico_freertos_hello'
        AND c.callee_addr IS NOT NULL
),
reach_counts AS (
    SELECT src, COUNT(DISTINCT addr) AS transitive_reach
    FROM reachable
    GROUP BY src
),
direct_counts AS (
    SELECT caller_addr AS src, COUNT(DISTINCT callee_addr) AS direct_callees
    FROM calls
    WHERE source = 'pico_freertos_hello' AND callee_addr IS NOT NULL
    GROUP BY caller_addr
)
SELECT
    f.name,
    dc.direct_callees,
    rc.transitive_reach
FROM reach_counts rc
JOIN direct_counts dc ON dc.src = rc.src
JOIN functions f ON f.source = 'pico_freertos_hello' AND f.addr = rc.src
WHERE dc.direct_callees >= 5 AND rc.transitive_reach >= 20
ORDER BY rc.transitive_reach DESC;

-- ----------------------------------------------------------------
-- 3. Subsystem clustering: function pairs sharing 3+ call targets
-- ----------------------------------------------------------------

WITH shared AS (
    SELECT
        a.caller_addr AS fn_a,
        b.caller_addr AS fn_b,
        COUNT(DISTINCT a.callee_addr) AS shared_callees
    FROM calls a
    JOIN calls b
        ON a.callee_addr = b.callee_addr
        AND a.source = b.source
        AND a.caller_addr < b.caller_addr
    WHERE a.source = 'pico_freertos_hello'
      AND a.callee_addr IS NOT NULL
    GROUP BY a.caller_addr, b.caller_addr
    HAVING COUNT(DISTINCT a.callee_addr) >= 3
)
SELECT
    fa.name AS function_a,
    fb.name AS function_b,
    s.shared_callees
FROM shared s
JOIN functions fa ON fa.source = 'pico_freertos_hello' AND fa.addr = s.fn_a
JOIN functions fb ON fb.source = 'pico_freertos_hello' AND fb.addr = s.fn_b
ORDER BY s.shared_callees DESC, fa.name
LIMIT 25;
