-- Sanity queries and exit criterion for the `calls` table.
--
-- These queries test that the Step 2 extraction produced something
-- structurally plausible. Run as:
--   scripts/query < notes/queries/calls_sanity.sql
--
-- The recursive CTE at the bottom is the Step 2 exit criterion from
-- the roadmap: reachability from `main` up to depth 3. If it returns
-- a sensible Pico SDK boot path (main, sleep_ms, gpio_put, ...), the
-- call-graph extraction is working.

-- 1. Row count and ref_type distribution per target.
SELECT source,
       ref_type,
       COUNT(*)                                      AS n,
       SUM(CASE WHEN is_computed THEN 1 ELSE 0 END)  AS computed,
       SUM(CASE WHEN callee_addr IS NULL THEN 1 ELSE 0 END) AS unresolved
FROM calls
GROUP BY source, ref_type
ORDER BY source, n DESC;

-- 2. Invariant: every non-computed call should either resolve to a
-- function row or be an external reference. A non-computed call with
-- a non-null callee_addr that does NOT match a functions row is a
-- potential extraction bug.
SELECT c.source,
       COUNT(*) AS orphan_direct_calls,
       MIN(printf('0x%x', c.call_site_addr)) AS example_site,
       MIN(printf('0x%x', c.callee_addr))    AS example_target
FROM calls c
LEFT JOIN functions f
    ON f.source = c.source AND f.addr = c.callee_addr
WHERE NOT c.is_computed
  AND c.callee_addr IS NOT NULL
  AND f.addr IS NULL
GROUP BY c.source
ORDER BY c.source;

-- 3. Top 10 functions by outgoing call sites (call fan-out).
SELECT f.source, f.name, COUNT(*) AS outgoing_calls, COUNT(DISTINCT c.callee_addr) AS distinct_callees
FROM calls c
JOIN functions f ON f.source = c.source AND f.addr = c.caller_addr
GROUP BY f.source, f.name
ORDER BY outgoing_calls DESC
LIMIT 10;

-- 4. Top 10 functions by incoming call sites (call fan-in).
-- Only counts resolved direct calls; computed calls can't be
-- attributed to a specific callee.
SELECT f.source, f.name, COUNT(*) AS incoming_calls, COUNT(DISTINCT c.caller_addr) AS distinct_callers
FROM calls c
JOIN functions f ON f.source = c.source AND f.addr = c.callee_addr
WHERE c.callee_addr IS NOT NULL
GROUP BY f.source, f.name
ORDER BY incoming_calls DESC
LIMIT 10;

-- 5. STEP 2 EXIT CRITERION: functions reachable from `main` up to
-- depth 3, via the call graph. For Pico blinky this should surface
-- the boot-to-blink path: main -> gpio_init / sleep_ms / ... and
-- their transitive callees. Depth is the minimum number of calls
-- from main to reach the function.
WITH RECURSIVE reachable(source, addr, name, depth) AS (
    SELECT f.source, f.addr, f.name, 0
    FROM functions f
    WHERE f.name = 'main'
    UNION
    SELECT f.source, f.addr, f.name, r.depth + 1
    FROM reachable r
    JOIN calls c
        ON c.source = r.source AND c.caller_addr = r.addr
    JOIN functions f
        ON f.source = c.source AND f.addr = c.callee_addr
    WHERE r.depth < 3
)
SELECT source, name, MIN(depth) AS min_depth
FROM reachable
GROUP BY source, name
ORDER BY source, min_depth, name;
