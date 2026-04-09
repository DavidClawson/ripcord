-- Composite multi-signal fingerprinting: Phase 2 baseline.
--
-- Combines four independent signals into a single similarity score:
--   1. Structural features (size-normalized 8-tuple from structural_signatures.sql)
--   2. P-Code opcode frequency (cosine similarity on histogram vectors)
--   3. Call-graph neighborhood (Jaccard on callee name sets)
--   4. String references (Jaccard on referenced string sets)
--
-- The hypothesis: each signal captures a different aspect of function
-- identity. Structural features encode code shape; P-Code frequencies
-- encode semantic operation mix; callee names encode behavioral context;
-- strings encode data dependencies. Combining them should discriminate
-- where any single signal fails — particularly cross-ISA where
-- individual signals are weak.
--
-- Composite score = 0.25 * structural_sim + 0.25 * pcode_sim
--                 + 0.25 * callee_sim   + 0.25 * string_sim
--
-- Equal weights are the uninformed baseline. The empirical results
-- from this query will inform weight tuning in a later iteration.
--
-- Usage:
--   scripts/query < notes/queries/composite_fingerprint.sql

-- ================================================================
-- 0. Inventory
-- ================================================================
SELECT source,
       COUNT(*) AS total_fns,
       SUM(CASE WHEN COALESCE(is_thunk, FALSE) = FALSE AND size >= 8 THEN 1 ELSE 0 END) AS eligible_fns
FROM functions
GROUP BY source
ORDER BY source;

-- ================================================================
-- 1. Per-function feature views
-- ================================================================

-- 1a. Structural features: size-normalized so cosine similarity is
-- scale-invariant. A 200-byte function with 10 blocks and a 400-byte
-- function with 20 blocks should look similar.
CREATE OR REPLACE VIEW struct_features AS
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
               COUNT(*)                     AS out_calls,
               COUNT(DISTINCT callee_addr)  AS distinct_callees
        FROM calls
        GROUP BY source, caller_addr
    ),
    xref_agg AS (
        SELECT source, function_addr,
               SUM(CASE WHEN ref_type = 'READ'  THEN 1 ELSE 0 END) AS reads,
               SUM(CASE WHEN ref_type = 'WRITE' THEN 1 ELSE 0 END) AS writes,
               SUM(CASE WHEN ref_type IN ('CONDITIONAL_JUMP', 'UNCONDITIONAL_JUMP')
                        THEN 1 ELSE 0 END) AS jumps
        FROM xrefs
        GROUP BY source, function_addr
    )
SELECT
    f.source,
    f.addr,
    f.name,
    f.size,
    -- Raw counts (for reference)
    f.basic_block_count AS blocks,
    COALESCE(bb_agg.instructions, 0)       AS instructions,
    COALESCE(call_agg.out_calls, 0)        AS out_calls,
    COALESCE(call_agg.distinct_callees, 0) AS distinct_callees,
    COALESCE(xref_agg.reads, 0)            AS reads,
    COALESCE(xref_agg.writes, 0)           AS writes,
    COALESCE(xref_agg.jumps, 0)            AS jumps,
    -- Size-normalized (divide by size; these are the cosine vector components)
    f.basic_block_count * 1.0 / f.size              AS n_blocks,
    COALESCE(bb_agg.instructions, 0) * 1.0 / f.size AS n_instructions,
    COALESCE(call_agg.out_calls, 0) * 1.0 / f.size  AS n_out_calls,
    COALESCE(call_agg.distinct_callees, 0) * 1.0 / f.size AS n_distinct_callees,
    COALESCE(xref_agg.reads, 0) * 1.0 / f.size      AS n_reads,
    COALESCE(xref_agg.writes, 0) * 1.0 / f.size     AS n_writes,
    COALESCE(xref_agg.jumps, 0) * 1.0 / f.size      AS n_jumps
FROM functions f
LEFT JOIN bb_agg ON bb_agg.source = f.source AND bb_agg.function_addr = f.addr
LEFT JOIN call_agg ON call_agg.source = f.source AND call_agg.function_addr = f.addr
LEFT JOIN xref_agg ON xref_agg.source = f.source AND xref_agg.function_addr = f.addr
WHERE COALESCE(f.is_thunk, FALSE) = FALSE
  AND f.size IS NOT NULL
  AND f.size >= 8;

-- 1b. P-Code frequency vector: top 30 opcodes as fractions of total ops.
-- Reuses the same opcode set from pcode_similarity.sql.
CREATE OR REPLACE VIEW pcode_freq AS
SELECT
    pf.source, pf.addr,
    f.name,
    pf.pcode_ops_total,
    pf.pcode_unique_opcodes,
    -- Frequency fractions (each opcode count / total)
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.COPY')          AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_copy,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_ADD')       AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_add,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SUB')       AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_sub,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_EQUAL')     AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_equal,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_NOTEQUAL')  AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_notequal,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SLESS')     AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_sless,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_LESS')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_less,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_AND')       AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_and,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_OR')        AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_or,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_XOR')       AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_xor,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_LEFT')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_left,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_RIGHT')     AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_right,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SRIGHT')    AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_sright,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_ZEXT')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_zext,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SEXT')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_sext,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.LOAD')          AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_load,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.STORE')         AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_store,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BRANCH')        AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_branch,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.CBRANCH')       AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_cbranch,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.CALL')          AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_call,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.RETURN')        AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_return,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BOOL_AND')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_bool_and,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BOOL_OR')       AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_bool_or,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BOOL_NEGATE')   AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_bool_negate,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.PIECE')         AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_piece,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.SUBPIECE')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_subpiece,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_MULT')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_int_mult,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INDIRECT')      AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_indirect,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.MULTIEQUAL')    AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_multiequal,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.CAST')          AS DOUBLE), 0) / NULLIF(pf.pcode_ops_total, 0) AS f_cast
FROM pcode_features pf
JOIN functions f ON pf.source = f.source AND pf.addr = f.addr
WHERE pf.pcode_ops_total >= 5
  AND COALESCE(f.is_thunk, FALSE) = FALSE
  AND f.size IS NOT NULL
  AND f.size >= 8;

-- 1c. Callee name sets: for each function, the list of distinct
-- non-auto callee names. Two functions calling the same named functions
-- are likely doing similar things even if their internal structure differs.
CREATE OR REPLACE VIEW callee_sets AS
SELECT
    c.source,
    c.caller_addr AS addr,
    LIST(DISTINCT f_callee.name ORDER BY f_callee.name) AS callee_names
FROM calls c
JOIN functions f_callee
    ON c.source = f_callee.source AND c.callee_addr = f_callee.addr
WHERE f_callee.name NOT LIKE 'FUN_%'  -- exclude Ghidra auto-names
  AND c.callee_addr IS NOT NULL
GROUP BY c.source, c.caller_addr;

-- 1d. String reference sets: for each function, the list of distinct
-- string values referenced via any xref to a string address.
-- Sparse signal (~5-12 functions per target) but very high-precision
-- when it fires: two functions referencing "Hello World!" are almost
-- certainly related.
CREATE OR REPLACE VIEW string_sets AS
SELECT
    x.source,
    x.function_addr AS addr,
    LIST(DISTINCT s.value ORDER BY s.value) AS ref_strings
FROM xrefs x
JOIN strings s ON x.source = s.source AND x.to_addr = s.addr
GROUP BY x.source, x.function_addr;

-- Quick counts: how many functions have each signal?
SELECT
    sf.source,
    COUNT(*) AS struct_fns,
    SUM(CASE WHEN pf.addr IS NOT NULL THEN 1 ELSE 0 END) AS pcode_fns,
    SUM(CASE WHEN cs.addr IS NOT NULL THEN 1 ELSE 0 END) AS callee_fns,
    SUM(CASE WHEN ss.addr IS NOT NULL THEN 1 ELSE 0 END) AS string_fns
FROM struct_features sf
LEFT JOIN pcode_freq pf ON sf.source = pf.source AND sf.addr = pf.addr
LEFT JOIN callee_sets cs ON sf.source = cs.source AND sf.addr = cs.addr
LEFT JOIN string_sets ss ON sf.source = ss.source AND sf.addr = ss.addr
GROUP BY sf.source
ORDER BY sf.source;

-- ================================================================
-- 2. WITHIN-BUILD TEST: pico_blinky vs pico_freertos_hello
-- ================================================================
-- Same build tuple (m0plus-O3-newlib). Ground truth: matching names.
-- These share Pico SDK runtime functions (gpio_init, sleep_ms, etc.)
-- and newlib (memcpy, memset, vfprintf, etc.).

-- 2a. Composite similarity for all candidate pairs.
-- Pre-filter: at least one of (callee overlap, pcode >= 20 ops) to
-- keep the cross-join manageable.

CREATE OR REPLACE VIEW pico_composite AS
WITH pairs AS (
    SELECT
        a.source AS src_a, a.addr AS addr_a, a.name AS name_a,
        b.source AS src_b, b.addr AS addr_b, b.name AS name_b,
        -- Structural cosine similarity (7-component normalized vector)
        (a.n_blocks*b.n_blocks + a.n_instructions*b.n_instructions
         + a.n_out_calls*b.n_out_calls + a.n_distinct_callees*b.n_distinct_callees
         + a.n_reads*b.n_reads + a.n_writes*b.n_writes + a.n_jumps*b.n_jumps
        ) / NULLIF(
            SQRT(a.n_blocks*a.n_blocks + a.n_instructions*a.n_instructions
                 + a.n_out_calls*a.n_out_calls + a.n_distinct_callees*a.n_distinct_callees
                 + a.n_reads*a.n_reads + a.n_writes*a.n_writes + a.n_jumps*a.n_jumps)
            * SQRT(b.n_blocks*b.n_blocks + b.n_instructions*b.n_instructions
                   + b.n_out_calls*b.n_out_calls + b.n_distinct_callees*b.n_distinct_callees
                   + b.n_reads*b.n_reads + b.n_writes*b.n_writes + b.n_jumps*b.n_jumps),
            0
        ) AS structural_sim,
        -- Callee Jaccard
        CASE
            WHEN cs_a.callee_names IS NOT NULL AND cs_b.callee_names IS NOT NULL
            THEN len(list_intersect(cs_a.callee_names, cs_b.callee_names)) * 1.0
                 / NULLIF(len(list_distinct(list_concat(cs_a.callee_names, cs_b.callee_names))), 0)
            ELSE 0
        END AS callee_sim,
        -- String Jaccard
        CASE
            WHEN ss_a.ref_strings IS NOT NULL AND ss_b.ref_strings IS NOT NULL
            THEN len(list_intersect(ss_a.ref_strings, ss_b.ref_strings)) * 1.0
                 / NULLIF(len(list_distinct(list_concat(ss_a.ref_strings, ss_b.ref_strings))), 0)
            ELSE 0
        END AS string_sim,
        -- P-Code frequency cosine
        CASE
            WHEN pf_a.addr IS NOT NULL AND pf_b.addr IS NOT NULL
            THEN (pf_a.f_copy*pf_b.f_copy + pf_a.f_int_add*pf_b.f_int_add
                  + pf_a.f_int_sub*pf_b.f_int_sub + pf_a.f_int_equal*pf_b.f_int_equal
                  + pf_a.f_int_notequal*pf_b.f_int_notequal
                  + pf_a.f_int_sless*pf_b.f_int_sless + pf_a.f_int_less*pf_b.f_int_less
                  + pf_a.f_int_and*pf_b.f_int_and + pf_a.f_int_or*pf_b.f_int_or
                  + pf_a.f_int_xor*pf_b.f_int_xor + pf_a.f_int_left*pf_b.f_int_left
                  + pf_a.f_int_right*pf_b.f_int_right + pf_a.f_int_sright*pf_b.f_int_sright
                  + pf_a.f_int_zext*pf_b.f_int_zext + pf_a.f_int_sext*pf_b.f_int_sext
                  + pf_a.f_load*pf_b.f_load + pf_a.f_store*pf_b.f_store
                  + pf_a.f_branch*pf_b.f_branch + pf_a.f_cbranch*pf_b.f_cbranch
                  + pf_a.f_call*pf_b.f_call + pf_a.f_return*pf_b.f_return
                  + pf_a.f_bool_and*pf_b.f_bool_and + pf_a.f_bool_or*pf_b.f_bool_or
                  + pf_a.f_bool_negate*pf_b.f_bool_negate + pf_a.f_piece*pf_b.f_piece
                  + pf_a.f_subpiece*pf_b.f_subpiece + pf_a.f_int_mult*pf_b.f_int_mult
                  + pf_a.f_indirect*pf_b.f_indirect + pf_a.f_multiequal*pf_b.f_multiequal
                  + pf_a.f_cast*pf_b.f_cast
                 ) / NULLIF(
                    SQRT(pf_a.f_copy*pf_a.f_copy + pf_a.f_int_add*pf_a.f_int_add
                         + pf_a.f_int_sub*pf_a.f_int_sub + pf_a.f_int_equal*pf_a.f_int_equal
                         + pf_a.f_int_notequal*pf_a.f_int_notequal
                         + pf_a.f_int_sless*pf_a.f_int_sless + pf_a.f_int_less*pf_a.f_int_less
                         + pf_a.f_int_and*pf_a.f_int_and + pf_a.f_int_or*pf_a.f_int_or
                         + pf_a.f_int_xor*pf_a.f_int_xor + pf_a.f_int_left*pf_a.f_int_left
                         + pf_a.f_int_right*pf_a.f_int_right + pf_a.f_int_sright*pf_a.f_int_sright
                         + pf_a.f_int_zext*pf_a.f_int_zext + pf_a.f_int_sext*pf_a.f_int_sext
                         + pf_a.f_load*pf_a.f_load + pf_a.f_store*pf_a.f_store
                         + pf_a.f_branch*pf_a.f_branch + pf_a.f_cbranch*pf_a.f_cbranch
                         + pf_a.f_call*pf_a.f_call + pf_a.f_return*pf_a.f_return
                         + pf_a.f_bool_and*pf_a.f_bool_and + pf_a.f_bool_or*pf_a.f_bool_or
                         + pf_a.f_bool_negate*pf_a.f_bool_negate + pf_a.f_piece*pf_a.f_piece
                         + pf_a.f_subpiece*pf_a.f_subpiece + pf_a.f_int_mult*pf_a.f_int_mult
                         + pf_a.f_indirect*pf_a.f_indirect + pf_a.f_multiequal*pf_a.f_multiequal
                         + pf_a.f_cast*pf_a.f_cast)
                    * SQRT(pf_b.f_copy*pf_b.f_copy + pf_b.f_int_add*pf_b.f_int_add
                           + pf_b.f_int_sub*pf_b.f_int_sub + pf_b.f_int_equal*pf_b.f_int_equal
                           + pf_b.f_int_notequal*pf_b.f_int_notequal
                           + pf_b.f_int_sless*pf_b.f_int_sless + pf_b.f_int_less*pf_b.f_int_less
                           + pf_b.f_int_and*pf_b.f_int_and + pf_b.f_int_or*pf_b.f_int_or
                           + pf_b.f_int_xor*pf_b.f_int_xor + pf_b.f_int_left*pf_b.f_int_left
                           + pf_b.f_int_right*pf_b.f_int_right + pf_b.f_int_sright*pf_b.f_int_sright
                           + pf_b.f_int_zext*pf_b.f_int_zext + pf_b.f_int_sext*pf_b.f_int_sext
                           + pf_b.f_load*pf_b.f_load + pf_b.f_store*pf_b.f_store
                           + pf_b.f_branch*pf_b.f_branch + pf_b.f_cbranch*pf_b.f_cbranch
                           + pf_b.f_call*pf_b.f_call + pf_b.f_return*pf_b.f_return
                           + pf_b.f_bool_and*pf_b.f_bool_and + pf_b.f_bool_or*pf_b.f_bool_or
                           + pf_b.f_bool_negate*pf_b.f_bool_negate + pf_b.f_piece*pf_b.f_piece
                           + pf_b.f_subpiece*pf_b.f_subpiece + pf_b.f_int_mult*pf_b.f_int_mult
                           + pf_b.f_indirect*pf_b.f_indirect + pf_b.f_multiequal*pf_b.f_multiequal
                           + pf_b.f_cast*pf_b.f_cast),
                    0
                 )
            ELSE NULL
        END AS pcode_sim
    FROM struct_features a
    JOIN struct_features b ON a.source < b.source
    LEFT JOIN pcode_freq pf_a ON a.source = pf_a.source AND a.addr = pf_a.addr
    LEFT JOIN pcode_freq pf_b ON b.source = pf_b.source AND b.addr = pf_b.addr
    LEFT JOIN callee_sets cs_a ON a.source = cs_a.source AND a.addr = cs_a.addr
    LEFT JOIN callee_sets cs_b ON b.source = cs_b.source AND b.addr = cs_b.addr
    LEFT JOIN string_sets ss_a ON a.source = ss_a.source AND a.addr = ss_a.addr
    LEFT JOIN string_sets ss_b ON b.source = ss_b.source AND b.addr = ss_b.addr
    WHERE a.source = 'pico_blinky'
      AND b.source = 'pico_freertos_hello'
)
SELECT *,
    -- Composite: equal-weight average of available signals.
    -- Missing pcode gets 0 contribution (score out of available weight).
    -- This penalizes pairs where pcode is unavailable, which is correct:
    -- less evidence = lower confidence.
    0.25 * COALESCE(structural_sim, 0)
    + 0.25 * COALESCE(pcode_sim, 0)
    + 0.25 * callee_sim
    + 0.25 * string_sim AS composite_score,
    CASE WHEN name_a = name_b AND name_a NOT LIKE 'FUN_%' THEN 'TRUE_POS'
         WHEN name_a = name_b AND name_a LIKE 'FUN_%' THEN 'AUTO_MATCH'
         ELSE 'UNKNOWN' END AS match_type
FROM pairs;

-- 2b. Top 30 pico-to-pico composite matches
SELECT name_a, name_b,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string,
       match_type
FROM pico_composite
ORDER BY composite_score DESC
LIMIT 30;

-- 2c. Precision at thresholds: composite vs individual signals
-- For each threshold, count pairs above it and measure what fraction
-- are true positives (same non-auto name).
SELECT * FROM (
    SELECT 'composite' AS signal, threshold,
           total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1) AS precision_pct
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM pico_composite WHERE composite_score >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE composite_score >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE composite_score >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE composite_score >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE composite_score >= 0.50
    ) t

    UNION ALL

    SELECT 'structural' AS signal, threshold,
           total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1)
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM pico_composite WHERE structural_sim >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE structural_sim >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE structural_sim >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE structural_sim >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE structural_sim >= 0.50
    ) t

    UNION ALL

    SELECT 'pcode' AS signal, threshold,
           total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1)
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM pico_composite WHERE pcode_sim >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE pcode_sim >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE pcode_sim >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE pcode_sim >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE pcode_sim >= 0.50
    ) t

    UNION ALL

    SELECT 'callee' AS signal, threshold,
           total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1)
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM pico_composite WHERE callee_sim >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE callee_sim >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE callee_sim >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE callee_sim >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM pico_composite WHERE callee_sim >= 0.50
    ) t
)
ORDER BY signal, threshold DESC;

-- 2d. Best match per function: for each pico_blinky function, what is
-- its highest-scoring match in pico_freertos_hello?
SELECT name_a,
       name_b AS best_match,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string,
       match_type
FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY addr_a ORDER BY composite_score DESC) AS rn
    FROM pico_composite
)
WHERE rn = 1
  AND name_a NOT LIKE 'FUN_%'
ORDER BY composite_score DESC
LIMIT 30;

-- ================================================================
-- 3. SAME-BUILD CONTROL: Zephyr-to-Zephyr (m3-Os-picolibc)
-- ================================================================
-- Known 96% precision on structural alone. Does composite maintain
-- that precision while adding recall?

CREATE OR REPLACE VIEW zephyr_composite AS
WITH pairs AS (
    SELECT
        a.source AS src_a, a.addr AS addr_a, a.name AS name_a,
        b.source AS src_b, b.addr AS addr_b, b.name AS name_b,
        (a.n_blocks*b.n_blocks + a.n_instructions*b.n_instructions
         + a.n_out_calls*b.n_out_calls + a.n_distinct_callees*b.n_distinct_callees
         + a.n_reads*b.n_reads + a.n_writes*b.n_writes + a.n_jumps*b.n_jumps
        ) / NULLIF(
            SQRT(a.n_blocks*a.n_blocks + a.n_instructions*a.n_instructions
                 + a.n_out_calls*a.n_out_calls + a.n_distinct_callees*a.n_distinct_callees
                 + a.n_reads*a.n_reads + a.n_writes*a.n_writes + a.n_jumps*a.n_jumps)
            * SQRT(b.n_blocks*b.n_blocks + b.n_instructions*b.n_instructions
                   + b.n_out_calls*b.n_out_calls + b.n_distinct_callees*b.n_distinct_callees
                   + b.n_reads*b.n_reads + b.n_writes*b.n_writes + b.n_jumps*b.n_jumps),
            0
        ) AS structural_sim,
        CASE
            WHEN cs_a.callee_names IS NOT NULL AND cs_b.callee_names IS NOT NULL
            THEN len(list_intersect(cs_a.callee_names, cs_b.callee_names)) * 1.0
                 / NULLIF(len(list_distinct(list_concat(cs_a.callee_names, cs_b.callee_names))), 0)
            ELSE 0
        END AS callee_sim,
        CASE
            WHEN ss_a.ref_strings IS NOT NULL AND ss_b.ref_strings IS NOT NULL
            THEN len(list_intersect(ss_a.ref_strings, ss_b.ref_strings)) * 1.0
                 / NULLIF(len(list_distinct(list_concat(ss_a.ref_strings, ss_b.ref_strings))), 0)
            ELSE 0
        END AS string_sim,
        CASE
            WHEN pf_a.addr IS NOT NULL AND pf_b.addr IS NOT NULL
            THEN (pf_a.f_copy*pf_b.f_copy + pf_a.f_int_add*pf_b.f_int_add
                  + pf_a.f_int_sub*pf_b.f_int_sub + pf_a.f_int_equal*pf_b.f_int_equal
                  + pf_a.f_int_notequal*pf_b.f_int_notequal
                  + pf_a.f_int_sless*pf_b.f_int_sless + pf_a.f_int_less*pf_b.f_int_less
                  + pf_a.f_int_and*pf_b.f_int_and + pf_a.f_int_or*pf_b.f_int_or
                  + pf_a.f_int_xor*pf_b.f_int_xor + pf_a.f_int_left*pf_b.f_int_left
                  + pf_a.f_int_right*pf_b.f_int_right + pf_a.f_int_sright*pf_b.f_int_sright
                  + pf_a.f_int_zext*pf_b.f_int_zext + pf_a.f_int_sext*pf_b.f_int_sext
                  + pf_a.f_load*pf_b.f_load + pf_a.f_store*pf_b.f_store
                  + pf_a.f_branch*pf_b.f_branch + pf_a.f_cbranch*pf_b.f_cbranch
                  + pf_a.f_call*pf_b.f_call + pf_a.f_return*pf_b.f_return
                  + pf_a.f_bool_and*pf_b.f_bool_and + pf_a.f_bool_or*pf_b.f_bool_or
                  + pf_a.f_bool_negate*pf_b.f_bool_negate + pf_a.f_piece*pf_b.f_piece
                  + pf_a.f_subpiece*pf_b.f_subpiece + pf_a.f_int_mult*pf_b.f_int_mult
                  + pf_a.f_indirect*pf_b.f_indirect + pf_a.f_multiequal*pf_b.f_multiequal
                  + pf_a.f_cast*pf_b.f_cast
                 ) / NULLIF(
                    SQRT(pf_a.f_copy*pf_a.f_copy + pf_a.f_int_add*pf_a.f_int_add
                         + pf_a.f_int_sub*pf_a.f_int_sub + pf_a.f_int_equal*pf_a.f_int_equal
                         + pf_a.f_int_notequal*pf_a.f_int_notequal
                         + pf_a.f_int_sless*pf_a.f_int_sless + pf_a.f_int_less*pf_a.f_int_less
                         + pf_a.f_int_and*pf_a.f_int_and + pf_a.f_int_or*pf_a.f_int_or
                         + pf_a.f_int_xor*pf_a.f_int_xor + pf_a.f_int_left*pf_a.f_int_left
                         + pf_a.f_int_right*pf_a.f_int_right + pf_a.f_int_sright*pf_a.f_int_sright
                         + pf_a.f_int_zext*pf_a.f_int_zext + pf_a.f_int_sext*pf_a.f_int_sext
                         + pf_a.f_load*pf_a.f_load + pf_a.f_store*pf_a.f_store
                         + pf_a.f_branch*pf_a.f_branch + pf_a.f_cbranch*pf_a.f_cbranch
                         + pf_a.f_call*pf_a.f_call + pf_a.f_return*pf_a.f_return
                         + pf_a.f_bool_and*pf_a.f_bool_and + pf_a.f_bool_or*pf_a.f_bool_or
                         + pf_a.f_bool_negate*pf_a.f_bool_negate + pf_a.f_piece*pf_a.f_piece
                         + pf_a.f_subpiece*pf_a.f_subpiece + pf_a.f_int_mult*pf_a.f_int_mult
                         + pf_a.f_indirect*pf_a.f_indirect + pf_a.f_multiequal*pf_a.f_multiequal
                         + pf_a.f_cast*pf_a.f_cast)
                    * SQRT(pf_b.f_copy*pf_b.f_copy + pf_b.f_int_add*pf_b.f_int_add
                           + pf_b.f_int_sub*pf_b.f_int_sub + pf_b.f_int_equal*pf_b.f_int_equal
                           + pf_b.f_int_notequal*pf_b.f_int_notequal
                           + pf_b.f_int_sless*pf_b.f_int_sless + pf_b.f_int_less*pf_b.f_int_less
                           + pf_b.f_int_and*pf_b.f_int_and + pf_b.f_int_or*pf_b.f_int_or
                           + pf_b.f_int_xor*pf_b.f_int_xor + pf_b.f_int_left*pf_b.f_int_left
                           + pf_b.f_int_right*pf_b.f_int_right + pf_b.f_int_sright*pf_b.f_int_sright
                           + pf_b.f_int_zext*pf_b.f_int_zext + pf_b.f_int_sext*pf_b.f_int_sext
                           + pf_b.f_load*pf_b.f_load + pf_b.f_store*pf_b.f_store
                           + pf_b.f_branch*pf_b.f_branch + pf_b.f_cbranch*pf_b.f_cbranch
                           + pf_b.f_call*pf_b.f_call + pf_b.f_return*pf_b.f_return
                           + pf_b.f_bool_and*pf_b.f_bool_and + pf_b.f_bool_or*pf_b.f_bool_or
                           + pf_b.f_bool_negate*pf_b.f_bool_negate + pf_b.f_piece*pf_b.f_piece
                           + pf_b.f_subpiece*pf_b.f_subpiece + pf_b.f_int_mult*pf_b.f_int_mult
                           + pf_b.f_indirect*pf_b.f_indirect + pf_b.f_multiequal*pf_b.f_multiequal
                           + pf_b.f_cast*pf_b.f_cast),
                    0
                 )
            ELSE NULL
        END AS pcode_sim
    FROM struct_features a
    JOIN struct_features b ON a.source < b.source
    LEFT JOIN pcode_freq pf_a ON a.source = pf_a.source AND a.addr = pf_a.addr
    LEFT JOIN pcode_freq pf_b ON b.source = pf_b.source AND b.addr = pf_b.addr
    LEFT JOIN callee_sets cs_a ON a.source = cs_a.source AND a.addr = cs_a.addr
    LEFT JOIN callee_sets cs_b ON b.source = cs_b.source AND b.addr = cs_b.addr
    LEFT JOIN string_sets ss_a ON a.source = ss_a.source AND a.addr = ss_a.addr
    LEFT JOIN string_sets ss_b ON b.source = ss_b.source AND b.addr = ss_b.addr
    WHERE a.source = 'zephyr_hello_world'
      AND b.source = 'zephyr_synchronization'
)
SELECT *,
    0.25 * COALESCE(structural_sim, 0)
    + 0.25 * COALESCE(pcode_sim, 0)
    + 0.25 * callee_sim
    + 0.25 * string_sim AS composite_score,
    CASE WHEN name_a = name_b AND name_a NOT LIKE 'FUN_%' THEN 'TRUE_POS'
         WHEN name_a = name_b AND name_a LIKE 'FUN_%' THEN 'AUTO_MATCH'
         ELSE 'UNKNOWN' END AS match_type
FROM pairs;

-- 3b. Top 30 Zephyr-to-Zephyr composite matches
SELECT name_a, name_b,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string,
       match_type
FROM zephyr_composite
ORDER BY composite_score DESC
LIMIT 30;

-- 3c. Zephyr precision at thresholds
SELECT * FROM (
    SELECT 'composite' AS signal, threshold,
           total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1) AS precision_pct
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM zephyr_composite WHERE composite_score >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE composite_score >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE composite_score >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE composite_score >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE composite_score >= 0.50
    ) t

    UNION ALL

    SELECT 'structural', threshold, total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1)
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM zephyr_composite WHERE structural_sim >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE structural_sim >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE structural_sim >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE structural_sim >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE structural_sim >= 0.50
    ) t

    UNION ALL

    SELECT 'pcode', threshold, total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1)
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM zephyr_composite WHERE pcode_sim >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE pcode_sim >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE pcode_sim >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE pcode_sim >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE pcode_sim >= 0.50
    ) t

    UNION ALL

    SELECT 'callee', threshold, total_pairs, name_matches,
           ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1)
    FROM (
        SELECT 0.90 AS threshold,
               COUNT(*) AS total_pairs,
               SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END) AS name_matches
        FROM zephyr_composite WHERE callee_sim >= 0.90
        UNION ALL
        SELECT 0.80, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE callee_sim >= 0.80
        UNION ALL
        SELECT 0.70, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE callee_sim >= 0.70
        UNION ALL
        SELECT 0.60, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE callee_sim >= 0.60
        UNION ALL
        SELECT 0.50, COUNT(*), SUM(CASE WHEN match_type = 'TRUE_POS' THEN 1 ELSE 0 END)
        FROM zephyr_composite WHERE callee_sim >= 0.50
    ) t
)
ORDER BY signal, threshold DESC;

-- ================================================================
-- 4. CROSS-ISA TEST: Pico (M0+) vs Zephyr (M3)
-- ================================================================
-- Different ISA, optimization, libc. Individual signals are weak here.
-- Question: does composite find ANY true cross-ISA matches?
-- True positives are rare (different link surfaces), but `main` and
-- a few libc primitives may overlap.

CREATE OR REPLACE VIEW cross_isa_composite AS
WITH pairs AS (
    SELECT
        a.source AS src_a, a.addr AS addr_a, a.name AS name_a,
        b.source AS src_b, b.addr AS addr_b, b.name AS name_b,
        (a.n_blocks*b.n_blocks + a.n_instructions*b.n_instructions
         + a.n_out_calls*b.n_out_calls + a.n_distinct_callees*b.n_distinct_callees
         + a.n_reads*b.n_reads + a.n_writes*b.n_writes + a.n_jumps*b.n_jumps
        ) / NULLIF(
            SQRT(a.n_blocks*a.n_blocks + a.n_instructions*a.n_instructions
                 + a.n_out_calls*a.n_out_calls + a.n_distinct_callees*a.n_distinct_callees
                 + a.n_reads*a.n_reads + a.n_writes*a.n_writes + a.n_jumps*a.n_jumps)
            * SQRT(b.n_blocks*b.n_blocks + b.n_instructions*b.n_instructions
                   + b.n_out_calls*b.n_out_calls + b.n_distinct_callees*b.n_distinct_callees
                   + b.n_reads*b.n_reads + b.n_writes*b.n_writes + b.n_jumps*b.n_jumps),
            0
        ) AS structural_sim,
        CASE
            WHEN cs_a.callee_names IS NOT NULL AND cs_b.callee_names IS NOT NULL
            THEN len(list_intersect(cs_a.callee_names, cs_b.callee_names)) * 1.0
                 / NULLIF(len(list_distinct(list_concat(cs_a.callee_names, cs_b.callee_names))), 0)
            ELSE 0
        END AS callee_sim,
        CASE
            WHEN ss_a.ref_strings IS NOT NULL AND ss_b.ref_strings IS NOT NULL
            THEN len(list_intersect(ss_a.ref_strings, ss_b.ref_strings)) * 1.0
                 / NULLIF(len(list_distinct(list_concat(ss_a.ref_strings, ss_b.ref_strings))), 0)
            ELSE 0
        END AS string_sim,
        CASE
            WHEN pf_a.addr IS NOT NULL AND pf_b.addr IS NOT NULL
            THEN (pf_a.f_copy*pf_b.f_copy + pf_a.f_int_add*pf_b.f_int_add
                  + pf_a.f_int_sub*pf_b.f_int_sub + pf_a.f_int_equal*pf_b.f_int_equal
                  + pf_a.f_int_notequal*pf_b.f_int_notequal
                  + pf_a.f_int_sless*pf_b.f_int_sless + pf_a.f_int_less*pf_b.f_int_less
                  + pf_a.f_int_and*pf_b.f_int_and + pf_a.f_int_or*pf_b.f_int_or
                  + pf_a.f_int_xor*pf_b.f_int_xor + pf_a.f_int_left*pf_b.f_int_left
                  + pf_a.f_int_right*pf_b.f_int_right + pf_a.f_int_sright*pf_b.f_int_sright
                  + pf_a.f_int_zext*pf_b.f_int_zext + pf_a.f_int_sext*pf_b.f_int_sext
                  + pf_a.f_load*pf_b.f_load + pf_a.f_store*pf_b.f_store
                  + pf_a.f_branch*pf_b.f_branch + pf_a.f_cbranch*pf_b.f_cbranch
                  + pf_a.f_call*pf_b.f_call + pf_a.f_return*pf_b.f_return
                  + pf_a.f_bool_and*pf_b.f_bool_and + pf_a.f_bool_or*pf_b.f_bool_or
                  + pf_a.f_bool_negate*pf_b.f_bool_negate + pf_a.f_piece*pf_b.f_piece
                  + pf_a.f_subpiece*pf_b.f_subpiece + pf_a.f_int_mult*pf_b.f_int_mult
                  + pf_a.f_indirect*pf_b.f_indirect + pf_a.f_multiequal*pf_b.f_multiequal
                  + pf_a.f_cast*pf_b.f_cast
                 ) / NULLIF(
                    SQRT(pf_a.f_copy*pf_a.f_copy + pf_a.f_int_add*pf_a.f_int_add
                         + pf_a.f_int_sub*pf_a.f_int_sub + pf_a.f_int_equal*pf_a.f_int_equal
                         + pf_a.f_int_notequal*pf_a.f_int_notequal
                         + pf_a.f_int_sless*pf_a.f_int_sless + pf_a.f_int_less*pf_a.f_int_less
                         + pf_a.f_int_and*pf_a.f_int_and + pf_a.f_int_or*pf_a.f_int_or
                         + pf_a.f_int_xor*pf_a.f_int_xor + pf_a.f_int_left*pf_a.f_int_left
                         + pf_a.f_int_right*pf_a.f_int_right + pf_a.f_int_sright*pf_a.f_int_sright
                         + pf_a.f_int_zext*pf_a.f_int_zext + pf_a.f_int_sext*pf_a.f_int_sext
                         + pf_a.f_load*pf_a.f_load + pf_a.f_store*pf_a.f_store
                         + pf_a.f_branch*pf_a.f_branch + pf_a.f_cbranch*pf_a.f_cbranch
                         + pf_a.f_call*pf_a.f_call + pf_a.f_return*pf_a.f_return
                         + pf_a.f_bool_and*pf_a.f_bool_and + pf_a.f_bool_or*pf_a.f_bool_or
                         + pf_a.f_bool_negate*pf_a.f_bool_negate + pf_a.f_piece*pf_a.f_piece
                         + pf_a.f_subpiece*pf_a.f_subpiece + pf_a.f_int_mult*pf_a.f_int_mult
                         + pf_a.f_indirect*pf_a.f_indirect + pf_a.f_multiequal*pf_a.f_multiequal
                         + pf_a.f_cast*pf_a.f_cast)
                    * SQRT(pf_b.f_copy*pf_b.f_copy + pf_b.f_int_add*pf_b.f_int_add
                           + pf_b.f_int_sub*pf_b.f_int_sub + pf_b.f_int_equal*pf_b.f_int_equal
                           + pf_b.f_int_notequal*pf_b.f_int_notequal
                           + pf_b.f_int_sless*pf_b.f_int_sless + pf_b.f_int_less*pf_b.f_int_less
                           + pf_b.f_int_and*pf_b.f_int_and + pf_b.f_int_or*pf_b.f_int_or
                           + pf_b.f_int_xor*pf_b.f_int_xor + pf_b.f_int_left*pf_b.f_int_left
                           + pf_b.f_int_right*pf_b.f_int_right + pf_b.f_int_sright*pf_b.f_int_sright
                           + pf_b.f_int_zext*pf_b.f_int_zext + pf_b.f_int_sext*pf_b.f_int_sext
                           + pf_b.f_load*pf_b.f_load + pf_b.f_store*pf_b.f_store
                           + pf_b.f_branch*pf_b.f_branch + pf_b.f_cbranch*pf_b.f_cbranch
                           + pf_b.f_call*pf_b.f_call + pf_b.f_return*pf_b.f_return
                           + pf_b.f_bool_and*pf_b.f_bool_and + pf_b.f_bool_or*pf_b.f_bool_or
                           + pf_b.f_bool_negate*pf_b.f_bool_negate + pf_b.f_piece*pf_b.f_piece
                           + pf_b.f_subpiece*pf_b.f_subpiece + pf_b.f_int_mult*pf_b.f_int_mult
                           + pf_b.f_indirect*pf_b.f_indirect + pf_b.f_multiequal*pf_b.f_multiequal
                           + pf_b.f_cast*pf_b.f_cast),
                    0
                 )
            ELSE NULL
        END AS pcode_sim
    FROM struct_features a
    JOIN struct_features b ON a.source < b.source
    LEFT JOIN pcode_freq pf_a ON a.source = pf_a.source AND a.addr = pf_a.addr
    LEFT JOIN pcode_freq pf_b ON b.source = pf_b.source AND b.addr = pf_b.addr
    LEFT JOIN callee_sets cs_a ON a.source = cs_a.source AND a.addr = cs_a.addr
    LEFT JOIN callee_sets cs_b ON b.source = cs_b.source AND b.addr = cs_b.addr
    LEFT JOIN string_sets ss_a ON a.source = ss_a.source AND a.addr = ss_a.addr
    LEFT JOIN string_sets ss_b ON b.source = ss_b.source AND b.addr = ss_b.addr
    WHERE a.source = 'pico_blinky'
      AND b.source = 'zephyr_hello_world'
)
SELECT *,
    0.25 * COALESCE(structural_sim, 0)
    + 0.25 * COALESCE(pcode_sim, 0)
    + 0.25 * callee_sim
    + 0.25 * string_sim AS composite_score,
    CASE WHEN name_a = name_b AND name_a NOT LIKE 'FUN_%' THEN 'TRUE_POS'
         WHEN name_a = name_b AND name_a LIKE 'FUN_%' THEN 'AUTO_MATCH'
         ELSE 'UNKNOWN' END AS match_type
FROM pairs;

-- 4b. Top 30 cross-ISA composite matches
SELECT name_a, name_b,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string,
       match_type
FROM cross_isa_composite
ORDER BY composite_score DESC
LIMIT 30;

-- 4c. Cross-ISA: do any name-matching pairs exist, and where do they rank?
SELECT name_a,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string
FROM cross_isa_composite
WHERE match_type = 'TRUE_POS'
ORDER BY composite_score DESC;

-- 4d. Cross-ISA similarity distribution: how does composite compare
-- to individual signals in separating signal from noise?
SELECT
    'composite' AS signal,
    ROUND(AVG(composite_score), 4) AS mean_sim,
    ROUND(MEDIAN(composite_score), 4) AS median_sim,
    ROUND(STDDEV(composite_score), 4) AS stddev_sim,
    ROUND(MAX(composite_score), 4) AS max_sim
FROM cross_isa_composite
UNION ALL
SELECT 'structural',
    ROUND(AVG(structural_sim), 4),
    ROUND(MEDIAN(structural_sim), 4),
    ROUND(STDDEV(structural_sim), 4),
    ROUND(MAX(structural_sim), 4)
FROM cross_isa_composite
UNION ALL
SELECT 'pcode',
    ROUND(AVG(pcode_sim), 4),
    ROUND(MEDIAN(pcode_sim), 4),
    ROUND(STDDEV(pcode_sim), 4),
    ROUND(MAX(pcode_sim), 4)
FROM cross_isa_composite WHERE pcode_sim IS NOT NULL
UNION ALL
SELECT 'callee',
    ROUND(AVG(callee_sim), 4),
    ROUND(MEDIAN(callee_sim), 4),
    ROUND(STDDEV(callee_sim), 4),
    ROUND(MAX(callee_sim), 4)
FROM cross_isa_composite
UNION ALL
SELECT 'string',
    ROUND(AVG(string_sim), 4),
    ROUND(MEDIAN(string_sim), 4),
    ROUND(STDDEV(string_sim), 4),
    ROUND(MAX(string_sim), 4)
FROM cross_isa_composite;

-- ================================================================
-- 5. SIGNAL CONTRIBUTION ANALYSIS
-- ================================================================
-- For true-positive pairs in the pico and zephyr within-build tests,
-- which signal contributes most to the composite score? This informs
-- weight tuning.

-- 5a. Pico true positives: signal breakdown
SELECT name_a,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string
FROM pico_composite
WHERE match_type = 'TRUE_POS'
ORDER BY composite_score DESC
LIMIT 20;

-- 5b. Zephyr true positives: signal breakdown
SELECT name_a,
       ROUND(composite_score, 4) AS composite,
       ROUND(structural_sim, 4) AS struct,
       ROUND(COALESCE(pcode_sim, 0), 4) AS pcode,
       ROUND(callee_sim, 4) AS callee,
       ROUND(string_sim, 4) AS string
FROM zephyr_composite
WHERE match_type = 'TRUE_POS'
ORDER BY composite_score DESC
LIMIT 20;

-- 5c. Signal correlation: for true positives, how correlated are
-- the individual signals? High correlation means redundancy; low
-- correlation means each signal adds independent information.
SELECT
    'pico' AS pair,
    ROUND(CORR(structural_sim, COALESCE(pcode_sim, 0)), 3) AS struct_pcode_r,
    ROUND(CORR(structural_sim, callee_sim), 3) AS struct_callee_r,
    ROUND(CORR(structural_sim, string_sim), 3) AS struct_string_r,
    ROUND(CORR(COALESCE(pcode_sim, 0), callee_sim), 3) AS pcode_callee_r,
    ROUND(CORR(COALESCE(pcode_sim, 0), string_sim), 3) AS pcode_string_r,
    ROUND(CORR(callee_sim, string_sim), 3) AS callee_string_r
FROM pico_composite
WHERE match_type = 'TRUE_POS'
UNION ALL
SELECT
    'zephyr',
    ROUND(CORR(structural_sim, COALESCE(pcode_sim, 0)), 3),
    ROUND(CORR(structural_sim, callee_sim), 3),
    ROUND(CORR(structural_sim, string_sim), 3),
    ROUND(CORR(COALESCE(pcode_sim, 0), callee_sim), 3),
    ROUND(CORR(COALESCE(pcode_sim, 0), string_sim), 3),
    ROUND(CORR(callee_sim, string_sim), 3)
FROM zephyr_composite
WHERE match_type = 'TRUE_POS';
