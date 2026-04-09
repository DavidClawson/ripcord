-- multi_signal_score.sql — Cross-compiler function matching via weighted
-- multi-signal similarity scoring
--
-- The core problem: exact matching (body hash, structural fingerprint)
-- fails across compilers. GCC, LLVM, and Keil produce different code
-- for the same source. But a COMBINATION of partial matches across
-- multiple signals can identify functions with high confidence.
--
-- Signals used (each normalized to 0.0-1.0):
--   1. Size similarity     — how close are the byte sizes?
--   2. Block count match   — same number of basic blocks?
--   3. Call fan-out match  — same outgoing call pattern?
--   4. Constant overlap    — shared peripheral/data address references?
--   5. String overlap      — shared string literal references?
--   6. Body hash           — exact byte match (bonus)
--
-- The weighted score produces a ranked candidate list, not exact matches.
-- This is the key insight: "top 3 candidates at 0.85 confidence" is far
-- more useful than "0 exact matches" when compilers differ.
--
-- Usage: scripts/query < notes/queries/multi_signal_score.sql
--
-- To change the reference/target pair, edit the WHERE clauses at the bottom.

-- =====================================================================
-- 1. Build per-function feature vectors with all signals
-- =====================================================================

CREATE OR REPLACE TEMP TABLE func_features AS
WITH
    bb_agg AS (
        SELECT source, function_addr,
               SUM(instruction_count) AS instructions
        FROM basic_blocks
        WHERE function_addr IS NOT NULL
        GROUP BY source, function_addr
    ),
    call_agg AS (
        SELECT source, caller_addr AS function_addr,
               COUNT(*) AS outgoing_calls,
               COUNT(DISTINCT callee_addr) AS distinct_callees
        FROM calls
        GROUP BY source, caller_addr
    ),
    xref_agg AS (
        SELECT source, function_addr,
               COUNT(DISTINCT CASE WHEN ref_type IN ('READ','DATA') THEN to_addr END) AS reads,
               COUNT(DISTINCT CASE WHEN ref_type = 'WRITE' THEN to_addr END) AS writes
        FROM xrefs
        GROUP BY source, function_addr
    ),
    -- Peripheral register references (0x40000000-0x5FFFFFFF, 0xE0000000+)
    periph_agg AS (
        SELECT source, function_addr,
               LIST(DISTINCT to_addr ORDER BY to_addr) AS periph_addrs,
               COUNT(DISTINCT to_addr) AS periph_count
        FROM xrefs
        WHERE ref_type IN ('DATA', 'READ', 'WRITE', 'PARAM')
          AND to_addr IS NOT NULL
          AND (to_addr BETWEEN 1073741824 AND 1610612735
               OR to_addr >= 3758096384)
        GROUP BY source, function_addr
    ),
    -- All constant references (for Jaccard similarity)
    const_agg AS (
        SELECT source, function_addr,
               LIST(DISTINCT to_addr ORDER BY to_addr) AS const_addrs,
               COUNT(DISTINCT to_addr) AS const_count
        FROM xrefs
        WHERE ref_type IN ('DATA', 'READ', 'WRITE', 'PARAM')
          AND to_addr IS NOT NULL
        GROUP BY source, function_addr
    ),
    -- String references
    string_agg AS (
        SELECT x.source, x.function_addr,
               LIST(DISTINCT s.value ORDER BY s.value) AS string_set,
               COUNT(DISTINCT s.value) AS string_count
        FROM xrefs x
        JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
        WHERE x.ref_type IN ('DATA', 'READ', 'PARAM')
        GROUP BY x.source, x.function_addr
    )
SELECT
    f.source, f.addr, f.name, f.size, f.body_hash,
    f.basic_block_count,
    COALESCE(bb.instructions, 0) AS instructions,
    COALESCE(ca.outgoing_calls, 0) AS outgoing_calls,
    COALESCE(ca.distinct_callees, 0) AS distinct_callees,
    COALESCE(xa.reads, 0) AS reads,
    COALESCE(xa.writes, 0) AS writes,
    COALESCE(pa.periph_addrs, []) AS periph_addrs,
    COALESCE(pa.periph_count, 0) AS periph_count,
    COALESCE(coa.const_addrs, []) AS const_addrs,
    COALESCE(coa.const_count, 0) AS const_count,
    COALESCE(sa.string_set, []) AS string_set,
    COALESCE(sa.string_count, 0) AS string_count
FROM functions f
LEFT JOIN bb_agg bb ON bb.source = f.source AND bb.function_addr = f.addr
LEFT JOIN call_agg ca ON ca.source = f.source AND ca.function_addr = f.addr
LEFT JOIN xref_agg xa ON xa.source = f.source AND xa.function_addr = f.addr
LEFT JOIN periph_agg pa ON pa.source = f.source AND pa.function_addr = f.addr
LEFT JOIN const_agg coa ON coa.source = f.source AND coa.function_addr = f.addr
LEFT JOIN string_agg sa ON sa.source = f.source AND sa.function_addr = f.addr
WHERE f.is_thunk = false AND f.size >= 16;

-- =====================================================================
-- 2. Compute pairwise multi-signal similarity scores
-- =====================================================================
-- Reference: at32_freertos_hello (GCC)  →  Target: stock_v120
-- Change these to match any reference→target pair.

CREATE OR REPLACE TEMP TABLE scored_matches AS
SELECT
    ref.name AS ref_name,
    ref.addr AS ref_addr,
    ref.size AS ref_size,
    tgt.name AS tgt_name,
    tgt.addr AS tgt_addr,
    printf('0x%08x', tgt.addr) AS tgt_hex,
    tgt.size AS tgt_size,

    -- Signal 1: Size similarity (gaussian-ish: 1.0 at exact, decays)
    -- Allow 30% size difference for cross-compiler
    CASE WHEN ref.size = 0 OR tgt.size = 0 THEN 0.0
         ELSE EXP(-3.0 * POWER(
             (CAST(ref.size AS DOUBLE) - tgt.size) / GREATEST(ref.size, tgt.size), 2))
    END AS size_sim,

    -- Signal 2: Block count similarity
    CASE WHEN ref.basic_block_count = tgt.basic_block_count THEN 1.0
         WHEN ABS(ref.basic_block_count - tgt.basic_block_count) = 1 THEN 0.7
         WHEN ABS(ref.basic_block_count - tgt.basic_block_count) <= 3 THEN 0.3
         ELSE 0.0
    END AS block_sim,

    -- Signal 3: Call pattern similarity
    CASE WHEN ref.outgoing_calls = tgt.outgoing_calls
              AND ref.distinct_callees = tgt.distinct_callees THEN 1.0
         WHEN ref.distinct_callees = tgt.distinct_callees THEN 0.8
         WHEN ABS(ref.distinct_callees - tgt.distinct_callees) <= 1 THEN 0.5
         WHEN ABS(ref.distinct_callees - tgt.distinct_callees) <= 2 THEN 0.2
         ELSE 0.0
    END AS call_sim,

    -- Signal 4: Peripheral address overlap (Jaccard on sets)
    CASE WHEN ref.periph_count = 0 AND tgt.periph_count = 0 THEN 0.0
         WHEN ref.periph_count = 0 OR tgt.periph_count = 0 THEN 0.0
         ELSE CAST(list_intersect(ref.periph_addrs, tgt.periph_addrs).len() AS DOUBLE)
              / list_distinct(list_concat(ref.periph_addrs, tgt.periph_addrs)).len()
    END AS periph_sim,

    -- Signal 5: String overlap (Jaccard on string sets)
    CASE WHEN ref.string_count = 0 AND tgt.string_count = 0 THEN 0.0
         WHEN ref.string_count = 0 OR tgt.string_count = 0 THEN 0.0
         ELSE CAST(list_intersect(ref.string_set, tgt.string_set).len() AS DOUBLE)
              / list_distinct(list_concat(ref.string_set, tgt.string_set)).len()
    END AS string_sim,

    -- Signal 6: Body hash exact match (bonus)
    CASE WHEN ref.body_hash IS NOT NULL AND ref.body_hash != ''
              AND ref.body_hash = tgt.body_hash THEN 1.0
         ELSE 0.0
    END AS hash_match,

    -- Read/write pattern similarity
    CASE WHEN ref.reads = tgt.reads AND ref.writes = tgt.writes THEN 1.0
         WHEN ABS(ref.reads - tgt.reads) <= 2
              AND ABS(ref.writes - tgt.writes) <= 2 THEN 0.5
         ELSE 0.0
    END AS rw_sim

FROM func_features ref
CROSS JOIN func_features tgt
WHERE ref.source IN ('at32_hal_blinky', 'at32_freertos_hello')
  AND tgt.source = 'stock_v120'
  -- Pre-filter: size within 50% to avoid N^2 blowup
  AND tgt.size BETWEEN ref.size * 0.5 AND ref.size * 2.0;

-- =====================================================================
-- 3. Compute weighted composite score and rank
-- =====================================================================

-- Weights: peripheral overlap and strings are most compiler-invariant,
-- so they get the highest weights. Size and blocks are informative
-- but compiler-dependent. Body hash is a bonus (all-or-nothing).
CREATE OR REPLACE TEMP TABLE ranked_matches AS
SELECT *,
    -- Weighted composite score
    (0.15 * size_sim
   + 0.15 * block_sim
   + 0.10 * call_sim
   + 0.25 * periph_sim
   + 0.20 * string_sim
   + 0.05 * hash_match
   + 0.10 * rw_sim
    ) AS composite_score,
    -- Count how many signals are "active" (non-zero)
    (CASE WHEN size_sim > 0.5 THEN 1 ELSE 0 END
   + CASE WHEN block_sim > 0.5 THEN 1 ELSE 0 END
   + CASE WHEN call_sim > 0.5 THEN 1 ELSE 0 END
   + CASE WHEN periph_sim > 0 THEN 1 ELSE 0 END
   + CASE WHEN string_sim > 0 THEN 1 ELSE 0 END
   + CASE WHEN hash_match > 0 THEN 1 ELSE 0 END
   + CASE WHEN rw_sim > 0.5 THEN 1 ELSE 0 END
    ) AS signals_active
FROM scored_matches;

-- =====================================================================
-- 4. Results: top candidates per reference function
-- =====================================================================

SELECT '--- TOP CANDIDATES (best match per reference function) ---' AS section;

WITH best_per_ref AS (
    SELECT *,
           ROW_NUMBER() OVER (PARTITION BY ref_name ORDER BY composite_score DESC) AS rank
    FROM ranked_matches
    WHERE composite_score > 0.3
)
SELECT
    ref_name, ref_size,
    tgt_name, tgt_hex, tgt_size,
    ROUND(composite_score, 3) AS score,
    signals_active AS signals,
    ROUND(size_sim, 2) AS sz,
    ROUND(block_sim, 2) AS bb,
    ROUND(call_sim, 2) AS call,
    ROUND(periph_sim, 2) AS periph,
    ROUND(string_sim, 2) AS str,
    ROUND(hash_match, 2) AS hash
FROM best_per_ref
WHERE rank <= 3
ORDER BY composite_score DESC, ref_name, rank;

-- =====================================================================
-- 5. High-confidence matches (score > 0.5 AND >= 3 signals)
-- =====================================================================

SELECT '--- HIGH-CONFIDENCE MATCHES (score > 0.5, >= 3 signals) ---' AS section;

WITH best_per_ref AS (
    SELECT *,
           ROW_NUMBER() OVER (PARTITION BY ref_name ORDER BY composite_score DESC) AS rank
    FROM ranked_matches
    WHERE composite_score > 0.5 AND signals_active >= 3
)
SELECT
    ref_name, ref_size,
    tgt_name, tgt_hex, tgt_size,
    ROUND(composite_score, 3) AS score,
    signals_active AS signals
FROM best_per_ref
WHERE rank = 1
ORDER BY composite_score DESC;

-- =====================================================================
-- 6. Score distribution: how many candidates at each confidence level?
-- =====================================================================

SELECT '--- SCORE DISTRIBUTION ---' AS section;

WITH best_per_ref AS (
    SELECT ref_name,
           MAX(composite_score) AS best_score,
           MAX(signals_active) AS best_signals
    FROM ranked_matches
    GROUP BY ref_name
)
SELECT
    CASE
        WHEN best_score >= 0.7 THEN '0.7+ (high)'
        WHEN best_score >= 0.5 THEN '0.5-0.7 (medium)'
        WHEN best_score >= 0.3 THEN '0.3-0.5 (low)'
        ELSE '< 0.3 (noise)'
    END AS confidence_tier,
    COUNT(*) AS ref_functions,
    ROUND(AVG(best_score), 3) AS avg_score,
    ROUND(AVG(best_signals), 1) AS avg_signals
FROM best_per_ref
GROUP BY confidence_tier
ORDER BY confidence_tier DESC;
