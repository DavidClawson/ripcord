-- pcode_cosine.sql — P-Code histogram cosine similarity for cross-ISA matching
--
-- Tests whether P-Code opcode histogram cosine similarity can
-- discriminate functions across ISAs (Cortex-M0+ vs Cortex-M3),
-- given that exact pcode_sequence_hash matching produces zero
-- true positives cross-ISA (see cross_isa_pcode.sql).
--
-- The histogram captures the distribution of P-Code operations
-- (COPY, INT_ADD, LOAD, STORE, CBRANCH, ...) without caring about
-- order or register allocation. Cosine similarity measures the
-- angle between two such count vectors — identical distributions
-- score 1.0, orthogonal ones score 0.0.
--
-- Evaluation challenge: Pico (SDK + newlib) and Zephyr (Zephyr RTOS
-- + picolibc) share almost no source-level function names (only
-- `main`). So we cannot do name-based precision evaluation cross-ISA
-- the way we did within-ISA. Instead we:
--   1. Characterize the cosine similarity distribution cross-ISA
--   2. Compare it to within-ISA similarity (where names match)
--   3. Look at top cross-ISA matches qualitatively
--   4. Test within-ISA cosine as a matching signal (precision eval)
--
-- EMPIRICAL RESULT (2026-04-08):
--
-- Cosine similarity on raw P-Code opcode histograms does NOT
-- discriminate cross-ISA. The distribution is heavily concentrated
-- in the 0.80-1.00 range (92% of all cross-ISA pairs), meaning
-- nearly every function looks "similar" to nearly every other
-- function. This is because the histogram is dominated by a few
-- common opcodes (COPY, INT_ADD, LOAD, STORE, CBRANCH) that appear
-- in almost every function regardless of its purpose.
--
-- Within-ISA (Pico-to-Pico, freertos_hello vs freertos_static):
--   - Best-match precision at cosine = 1.0: 94.3% (159 matches, 150 correct)
--   - Best-match precision at cosine >= 0.99: 80.1% (211 matches, 169 correct)
--   - This is NO BETTER than exact pcode_sequence_hash (93-94%)
--
-- Cross-ISA (Pico vs Zephyr):
--   - 92% of all pairs have cosine >= 0.80
--   - 46% have cosine >= 0.90
--   - The signal is too coarse to rank candidates meaningfully
--
-- Conclusion: raw opcode histogram cosine similarity is NOT the path
-- to cross-ISA matching. The histogram needs normalization (e.g.,
-- by function size), weighting (e.g., TF-IDF on opcodes), or
-- augmentation with structural features (call count, basic block
-- count, xref patterns) before it can discriminate.
--
-- Usage: scripts/query < notes/queries/pcode_cosine.sql

-- ================================================================
-- Helper: explode JSON histograms into (source, addr, opcode, count)
-- ================================================================

-- 1. First, let's see the full opcode vocabulary across all targets
SELECT '=== 1. P-Code opcode vocabulary ===' AS section;

WITH all_opcodes AS (
    SELECT DISTINCT unnest(json_keys(pcode_histogram::JSON)) AS opcode
    FROM pcode_features
    WHERE source NOT LIKE '%stripped%'
)
SELECT opcode FROM all_opcodes ORDER BY opcode;

-- ================================================================
-- 2. Cross-ISA cosine similarity: Pico vs Zephyr
--    For each (pico_fn, zephyr_fn) pair, compute cosine similarity
--    of their P-Code opcode histograms.
--
--    Strategy: explode both histograms to (opcode, count), full outer
--    join on opcode, compute dot product and magnitudes.
-- ================================================================

SELECT '=== 2. Top 30 cross-ISA cosine matches (ops >= 20) ===' AS section;

WITH pico_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'pico_%'
      AND p.source != 'pico_freertos_hello_stripped'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
),
zephyr_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'zephyr_%'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
),
-- Explode pico histograms
pico_exploded AS (
    SELECT source, addr, name, pcode_ops_total,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM pico_fns
),
-- Explode zephyr histograms
zephyr_exploded AS (
    SELECT source, addr, name, pcode_ops_total,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM zephyr_fns
),
-- For each (pico, zephyr) pair, join on opcode and compute cosine components
-- To keep this tractable, we pick one representative per function name per ecosystem
pico_dedup AS (
    SELECT * FROM pico_exploded
    WHERE (source, addr) IN (
        SELECT source, addr FROM pico_fns
        WHERE (name, source) IN (
            SELECT name, MIN(source) FROM pico_fns GROUP BY name
        )
    )
),
zephyr_dedup AS (
    SELECT * FROM zephyr_exploded
),
-- Compute dot product and magnitudes per pair
pair_components AS (
    SELECT
        p.source AS pico_source, p.addr AS pico_addr, p.name AS pico_name,
        z.source AS zephyr_source, z.addr AS zephyr_addr, z.name AS zephyr_name,
        SUM(COALESCE(p.cnt, 0) * COALESCE(z.cnt, 0)) AS dot_product
    FROM pico_dedup p
    INNER JOIN zephyr_dedup z ON p.opcode = z.opcode
    GROUP BY p.source, p.addr, p.name, z.source, z.addr, z.name
),
pico_magnitudes AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM pico_dedup
    GROUP BY source, addr
),
zephyr_magnitudes AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM zephyr_dedup
    GROUP BY source, addr
),
cosine_scores AS (
    SELECT
        pc.pico_name, pc.zephyr_name,
        pc.pico_source, pc.zephyr_source,
        ROUND(pc.dot_product / (pm.mag * zm.mag), 4) AS cosine_sim,
        pc.dot_product,
        ROUND(pm.mag, 2) AS pico_mag,
        ROUND(zm.mag, 2) AS zephyr_mag
    FROM pair_components pc
    JOIN pico_magnitudes pm ON pm.source = pc.pico_source AND pm.addr = pc.pico_addr
    JOIN zephyr_magnitudes zm ON zm.source = pc.zephyr_source AND zm.addr = pc.zephyr_addr
)
SELECT pico_name, zephyr_name, pico_source, zephyr_source,
       cosine_sim, pico_mag, zephyr_mag
FROM cosine_scores
ORDER BY cosine_sim DESC
LIMIT 30;

-- ================================================================
-- 3. Cross-ISA cosine similarity distribution
-- ================================================================

SELECT '=== 3. Cross-ISA cosine similarity distribution (ops >= 20) ===' AS section;

WITH pico_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'pico_%'
      AND p.source != 'pico_freertos_hello_stripped'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
      -- Dedup: one per name
      AND (f.name, p.source) IN (
          SELECT ff.name, MIN(pp.source)
          FROM pcode_features pp
          JOIN functions ff ON ff.source = pp.source AND ff.addr = pp.addr
          WHERE pp.source LIKE 'pico_%' AND pp.source != 'pico_freertos_hello_stripped'
            AND ff.name NOT LIKE 'FUN_%' AND pp.pcode_ops_total >= 20
          GROUP BY ff.name
      )
),
zephyr_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'zephyr_%'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
      AND (f.name, p.source) IN (
          SELECT ff.name, MIN(pp.source)
          FROM pcode_features pp
          JOIN functions ff ON ff.source = pp.source AND ff.addr = pp.addr
          WHERE pp.source LIKE 'zephyr_%'
            AND ff.name NOT LIKE 'FUN_%' AND pp.pcode_ops_total >= 20
          GROUP BY ff.name
      )
),
pico_exploded AS (
    SELECT source, addr, name,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM pico_fns
),
zephyr_exploded AS (
    SELECT source, addr, name,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM zephyr_fns
),
pair_dots AS (
    SELECT p.source AS ps, p.addr AS pa, z.source AS zs, z.addr AS za,
           SUM(p.cnt * z.cnt * 1.0) AS dot_product
    FROM pico_exploded p
    JOIN zephyr_exploded z ON p.opcode = z.opcode
    GROUP BY p.source, p.addr, z.source, z.addr
),
pico_mags AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM pico_exploded GROUP BY source, addr
),
zephyr_mags AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM zephyr_exploded GROUP BY source, addr
),
all_cosines AS (
    SELECT ROUND(pd.dot_product / (pm.mag * zm.mag), 4) AS cosine_sim
    FROM pair_dots pd
    JOIN pico_mags pm ON pm.source = pd.ps AND pm.addr = pd.pa
    JOIN zephyr_mags zm ON zm.source = pd.zs AND zm.addr = pd.za
)
SELECT
    CASE
        WHEN cosine_sim >= 0.99 THEN '0.99-1.00'
        WHEN cosine_sim >= 0.95 THEN '0.95-0.99'
        WHEN cosine_sim >= 0.90 THEN '0.90-0.95'
        WHEN cosine_sim >= 0.80 THEN '0.80-0.90'
        WHEN cosine_sim >= 0.70 THEN '0.70-0.80'
        WHEN cosine_sim >= 0.50 THEN '0.50-0.70'
        ELSE '< 0.50'
    END AS bucket,
    COUNT(*) AS pair_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct
FROM all_cosines
GROUP BY bucket
ORDER BY bucket DESC;

-- ================================================================
-- 4. Within-ISA cosine similarity precision (Pico-to-Pico, ops >= 20)
--    Calibration: for pairs where both functions have names,
--    what fraction of top cosine matches share the same name?
-- ================================================================

SELECT '=== 4. Within-ISA (Pico-to-Pico) cosine precision at various thresholds ===' AS section;

WITH pico_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'pico_%'
      AND p.source != 'pico_freertos_hello_stripped'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
),
pico_exploded AS (
    SELECT source, addr, name,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM pico_fns
),
-- Cross-source pairs only
pair_dots AS (
    SELECT p1.source AS s1, p1.addr AS a1, p1.name AS n1,
           p2.source AS s2, p2.addr AS a2, p2.name AS n2,
           SUM(p1.cnt * p2.cnt * 1.0) AS dot_product
    FROM pico_exploded p1
    JOIN pico_exploded p2 ON p1.opcode = p2.opcode AND p1.source < p2.source
    GROUP BY p1.source, p1.addr, p1.name, p2.source, p2.addr, p2.name
),
mags AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM pico_exploded GROUP BY source, addr
),
within_cosines AS (
    SELECT pd.n1, pd.n2,
           ROUND(pd.dot_product / (m1.mag * m2.mag), 4) AS cosine_sim
    FROM pair_dots pd
    JOIN mags m1 ON m1.source = pd.s1 AND m1.addr = pd.a1
    JOIN mags m2 ON m2.source = pd.s2 AND m2.addr = pd.a2
)
SELECT threshold,
       total_pairs,
       same_name,
       ROUND(100.0 * same_name / GREATEST(total_pairs, 1), 1) AS precision_pct
FROM (
    SELECT 0.99 AS threshold,
           COUNT(*) AS total_pairs,
           SUM(CASE WHEN n1 = n2 THEN 1 ELSE 0 END) AS same_name
    FROM within_cosines WHERE cosine_sim >= 0.99
    UNION ALL
    SELECT 0.95, COUNT(*), SUM(CASE WHEN n1 = n2 THEN 1 ELSE 0 END)
    FROM within_cosines WHERE cosine_sim >= 0.95
    UNION ALL
    SELECT 0.90, COUNT(*), SUM(CASE WHEN n1 = n2 THEN 1 ELSE 0 END)
    FROM within_cosines WHERE cosine_sim >= 0.90
    UNION ALL
    SELECT 0.80, COUNT(*), SUM(CASE WHEN n1 = n2 THEN 1 ELSE 0 END)
    FROM within_cosines WHERE cosine_sim >= 0.80
) t
ORDER BY threshold DESC;

-- ================================================================
-- 5. Within-ISA: top cosine=1.0 pairs that are FALSE positives
--    (same cosine, different name) — shows the collision rate
-- ================================================================

SELECT '=== 5. Within-ISA cosine=1.0 false positives (different name, ops>=20) ===' AS section;

WITH pico_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'pico_%'
      AND p.source != 'pico_freertos_hello_stripped'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
),
pico_exploded AS (
    SELECT source, addr, name, pcode_ops_total,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM pico_fns
),
pair_dots AS (
    SELECT p1.source AS s1, p1.addr AS a1, p1.name AS n1, MAX(p1.pcode_ops_total) AS ops1,
           p2.source AS s2, p2.addr AS a2, p2.name AS n2, MAX(p2.pcode_ops_total) AS ops2,
           SUM(p1.cnt * p2.cnt * 1.0) AS dot_product
    FROM pico_exploded p1
    JOIN pico_exploded p2 ON p1.opcode = p2.opcode AND p1.source < p2.source
    GROUP BY p1.source, p1.addr, p1.name, p2.source, p2.addr, p2.name
),
mags AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM pico_exploded GROUP BY source, addr
),
within_cosines AS (
    SELECT pd.n1, pd.n2, pd.ops1, pd.ops2, pd.s1, pd.s2,
           ROUND(pd.dot_product / (m1.mag * m2.mag), 4) AS cosine_sim
    FROM pair_dots pd
    JOIN mags m1 ON m1.source = pd.s1 AND m1.addr = pd.a1
    JOIN mags m2 ON m2.source = pd.s2 AND m2.addr = pd.a2
)
SELECT n1, n2, ops1, ops2, s1, s2
FROM within_cosines
WHERE cosine_sim >= 0.9999 AND n1 != n2
ORDER BY ops1 DESC
LIMIT 20;

-- ================================================================
-- 6. What does "main" look like cross-ISA? (the one shared name)
-- ================================================================

SELECT '=== 6. main() cosine similarity across ecosystems ===' AS section;

WITH main_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE f.name = 'main'
      AND p.source != 'pico_freertos_hello_stripped'
),
main_exploded AS (
    SELECT source, addr,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM main_fns
),
pair_dots AS (
    SELECT m1.source AS s1, m1.addr AS a1, m2.source AS s2, m2.addr AS a2,
           SUM(m1.cnt * m2.cnt * 1.0) AS dot_product
    FROM main_exploded m1
    JOIN main_exploded m2 ON m1.opcode = m2.opcode AND m1.source < m2.source
    GROUP BY m1.source, m1.addr, m2.source, m2.addr
),
mags AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM main_exploded GROUP BY source, addr
)
SELECT pd.s1, pd.s2,
       ROUND(pd.dot_product / (m1.mag * m2.mag), 4) AS cosine_sim
FROM pair_dots pd
JOIN mags m1 ON m1.source = pd.s1 AND m1.addr = pd.a1
JOIN mags m2 ON m2.source = pd.s2 AND m2.addr = pd.a2
ORDER BY pd.s1, pd.s2;

-- ================================================================
-- 7. Best-match precision: for each function in source A, take the
--    single best cosine match in source B. What fraction are correct?
--    This is the metric that matters for matching, not all-pairs.
--    (Within-ISA: pico_freertos_hello vs pico_freertos_static)
-- ================================================================

SELECT '=== 7. Best-match precision (freertos_hello vs freertos_static) ===' AS section;

WITH pico_fns AS (
    SELECT p.source, p.addr, f.name, p.pcode_ops_total, p.pcode_histogram
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source IN ('pico_freertos_hello', 'pico_freertos_static')
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 20
),
pico_exploded AS (
    SELECT source, addr, name,
           unnest(json_keys(pcode_histogram::JSON)) AS opcode,
           CAST(json_extract(pcode_histogram::JSON,
                '$.' || unnest(json_keys(pcode_histogram::JSON))) AS INTEGER) AS cnt
    FROM pico_fns
),
pair_dots AS (
    SELECT p1.source AS s1, p1.addr AS a1, p1.name AS n1,
           p2.source AS s2, p2.addr AS a2, p2.name AS n2,
           SUM(p1.cnt * p2.cnt * 1.0) AS dot_product
    FROM pico_exploded p1
    JOIN pico_exploded p2 ON p1.opcode = p2.opcode
    WHERE p1.source = 'pico_freertos_hello' AND p2.source = 'pico_freertos_static'
    GROUP BY p1.source, p1.addr, p1.name, p2.source, p2.addr, p2.name
),
mags AS (
    SELECT source, addr, SQRT(SUM(cnt * cnt * 1.0)) AS mag
    FROM pico_exploded GROUP BY source, addr
),
cosines AS (
    SELECT pd.n1, pd.n2,
           ROUND(pd.dot_product / (m1.mag * m2.mag), 6) AS cosine_sim
    FROM pair_dots pd
    JOIN mags m1 ON m1.source = pd.s1 AND m1.addr = pd.a1
    JOIN mags m2 ON m2.source = pd.s2 AND m2.addr = pd.a2
),
best_matches AS (
    SELECT n1, FIRST(n2 ORDER BY cosine_sim DESC) AS best_n2,
           MAX(cosine_sim) AS best_sim
    FROM cosines
    GROUP BY n1
)
SELECT
    threshold,
    COUNT(*) AS total,
    SUM(CASE WHEN n1 = best_n2 THEN 1 ELSE 0 END) AS correct,
    ROUND(100.0 * SUM(CASE WHEN n1 = best_n2 THEN 1 ELSE 0 END) / GREATEST(COUNT(*),1), 1) AS precision_pct
FROM best_matches
CROSS JOIN (VALUES (1.0), (0.999), (0.99), (0.95), (0.90)) AS t(threshold)
WHERE best_sim >= threshold
GROUP BY threshold
ORDER BY threshold DESC;
