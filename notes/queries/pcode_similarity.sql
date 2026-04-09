-- P-Code histogram cosine similarity: cross-ISA function matching.
--
-- The structural 8-tuple fingerprint (structural_signatures.sql) finds
-- essentially zero cross-ISA matches because Cortex-M0+ and M3 differ
-- in byte size, instruction count, and block layout for the same C
-- source.  Exact P-Code sequence hashes also fail because Ghidra's
-- lowering produces different opcode orderings per ISA.
--
-- Hypothesis: the *frequency distribution* of P-Code opcodes is
-- order-invariant and should tolerate register allocation and ISA
-- encoding differences.  Functions compiled from the same C source
-- for different ISAs will have similar opcode frequency profiles.
--
-- This query:
--   (a) Unpacks pcode_histogram JSON into a fixed-width opcode vector
--   (b) Computes cosine similarity between function pairs across targets
--   (c) Validates high-similarity pairs against ground-truth names
--   (d) Tries both raw counts and normalized (frequency) vectors
--
-- Usage:
--   scripts/query < notes/queries/pcode_similarity.sql

-- ================================================================
-- 0. Inventory: what do we have?
-- ================================================================
SELECT source,
       COUNT(*) AS total_fns,
       SUM(CASE WHEN pcode_ops_total >= 20 THEN 1 ELSE 0 END) AS fns_ge20,
       SUM(CASE WHEN pcode_ops_total >= 50 THEN 1 ELSE 0 END) AS fns_ge50
FROM pcode_features
GROUP BY source
ORDER BY source;

-- ================================================================
-- 1. Raw-count opcode vector view
-- ================================================================
-- 30 opcodes covering ~95% of all P-Code operations.
-- Skip functions with < 20 total ops (too small to fingerprint).

CREATE OR REPLACE VIEW pcode_vec AS
SELECT
    pf.source, pf.addr,
    f.name,
    pf.pcode_ops_total,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.COPY')          AS INT), 0) AS v_copy,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_ADD')       AS INT), 0) AS v_int_add,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SUB')       AS INT), 0) AS v_int_sub,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_EQUAL')     AS INT), 0) AS v_int_equal,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_NOTEQUAL')  AS INT), 0) AS v_int_notequal,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SLESS')     AS INT), 0) AS v_int_sless,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_LESS')      AS INT), 0) AS v_int_less,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_AND')       AS INT), 0) AS v_int_and,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_OR')        AS INT), 0) AS v_int_or,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_XOR')       AS INT), 0) AS v_int_xor,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_LEFT')      AS INT), 0) AS v_int_left,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_RIGHT')     AS INT), 0) AS v_int_right,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SRIGHT')    AS INT), 0) AS v_int_sright,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_ZEXT')      AS INT), 0) AS v_int_zext,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_SEXT')      AS INT), 0) AS v_int_sext,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.LOAD')          AS INT), 0) AS v_load,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.STORE')         AS INT), 0) AS v_store,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BRANCH')        AS INT), 0) AS v_branch,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.CBRANCH')       AS INT), 0) AS v_cbranch,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.CALL')          AS INT), 0) AS v_call,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.RETURN')        AS INT), 0) AS v_return,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BOOL_AND')      AS INT), 0) AS v_bool_and,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BOOL_OR')       AS INT), 0) AS v_bool_or,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.BOOL_NEGATE')   AS INT), 0) AS v_bool_negate,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.PIECE')         AS INT), 0) AS v_piece,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.SUBPIECE')      AS INT), 0) AS v_subpiece,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INT_MULT')      AS INT), 0) AS v_int_mult,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.INDIRECT')      AS INT), 0) AS v_indirect,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.MULTIEQUAL')    AS INT), 0) AS v_multiequal,
    COALESCE(CAST(json_extract(pf.pcode_histogram, '$.CAST')          AS INT), 0) AS v_cast
FROM pcode_features pf
JOIN functions f ON pf.source = f.source AND pf.addr = f.addr
WHERE pf.pcode_ops_total >= 20;

-- Quick sanity: how many functions per target in the vector view?
SELECT source, COUNT(*) AS n FROM pcode_vec GROUP BY source ORDER BY source;

-- ================================================================
-- 2. Same-ISA control: Zephyr-to-Zephyr cosine similarity (raw)
-- ================================================================
-- This pair shares ISA, compiler, optimization, and libc.
-- Structural signatures already hit 96% here. Histogram similarity
-- should be at least as good.

CREATE OR REPLACE VIEW zz_cosine_raw AS
SELECT
    a.name AS name_a,
    b.name AS name_b,
    a.pcode_ops_total AS ops_a,
    b.pcode_ops_total AS ops_b,
    -- dot product
    (a.v_copy*b.v_copy + a.v_int_add*b.v_int_add + a.v_int_sub*b.v_int_sub
     + a.v_int_equal*b.v_int_equal + a.v_int_notequal*b.v_int_notequal
     + a.v_int_sless*b.v_int_sless + a.v_int_less*b.v_int_less
     + a.v_int_and*b.v_int_and + a.v_int_or*b.v_int_or
     + a.v_int_xor*b.v_int_xor + a.v_int_left*b.v_int_left
     + a.v_int_right*b.v_int_right + a.v_int_sright*b.v_int_sright
     + a.v_int_zext*b.v_int_zext + a.v_int_sext*b.v_int_sext
     + a.v_load*b.v_load + a.v_store*b.v_store
     + a.v_branch*b.v_branch + a.v_cbranch*b.v_cbranch
     + a.v_call*b.v_call + a.v_return*b.v_return
     + a.v_bool_and*b.v_bool_and + a.v_bool_or*b.v_bool_or
     + a.v_bool_negate*b.v_bool_negate + a.v_piece*b.v_piece
     + a.v_subpiece*b.v_subpiece + a.v_int_mult*b.v_int_mult
     + a.v_indirect*b.v_indirect + a.v_multiequal*b.v_multiequal
     + a.v_cast*b.v_cast
    ) * 1.0 / NULLIF(
        SQRT(a.v_copy*a.v_copy + a.v_int_add*a.v_int_add + a.v_int_sub*a.v_int_sub
             + a.v_int_equal*a.v_int_equal + a.v_int_notequal*a.v_int_notequal
             + a.v_int_sless*a.v_int_sless + a.v_int_less*a.v_int_less
             + a.v_int_and*a.v_int_and + a.v_int_or*a.v_int_or
             + a.v_int_xor*a.v_int_xor + a.v_int_left*a.v_int_left
             + a.v_int_right*a.v_int_right + a.v_int_sright*a.v_int_sright
             + a.v_int_zext*a.v_int_zext + a.v_int_sext*a.v_int_sext
             + a.v_load*a.v_load + a.v_store*a.v_store
             + a.v_branch*a.v_branch + a.v_cbranch*a.v_cbranch
             + a.v_call*a.v_call + a.v_return*a.v_return
             + a.v_bool_and*a.v_bool_and + a.v_bool_or*a.v_bool_or
             + a.v_bool_negate*a.v_bool_negate + a.v_piece*a.v_piece
             + a.v_subpiece*a.v_subpiece + a.v_int_mult*a.v_int_mult
             + a.v_indirect*a.v_indirect + a.v_multiequal*a.v_multiequal
             + a.v_cast*a.v_cast)
        * SQRT(b.v_copy*b.v_copy + b.v_int_add*b.v_int_add + b.v_int_sub*b.v_int_sub
               + b.v_int_equal*b.v_int_equal + b.v_int_notequal*b.v_int_notequal
               + b.v_int_sless*b.v_int_sless + b.v_int_less*b.v_int_less
               + b.v_int_and*b.v_int_and + b.v_int_or*b.v_int_or
               + b.v_int_xor*b.v_int_xor + b.v_int_left*b.v_int_left
               + b.v_int_right*b.v_int_right + b.v_int_sright*b.v_int_sright
               + b.v_int_zext*b.v_int_zext + b.v_int_sext*b.v_int_sext
               + b.v_load*b.v_load + b.v_store*b.v_store
               + b.v_branch*b.v_branch + b.v_cbranch*b.v_cbranch
               + b.v_call*b.v_call + b.v_return*b.v_return
               + b.v_bool_and*b.v_bool_and + b.v_bool_or*b.v_bool_or
               + b.v_bool_negate*b.v_bool_negate + b.v_piece*b.v_piece
               + b.v_subpiece*b.v_subpiece + b.v_int_mult*b.v_int_mult
               + b.v_indirect*b.v_indirect + b.v_multiequal*b.v_multiequal
               + b.v_cast*b.v_cast),
        0
    ) AS cosine_sim
FROM pcode_vec a
JOIN pcode_vec b ON a.source < b.source
WHERE a.source = 'zephyr_hello_world'
  AND b.source = 'zephyr_synchronization';

-- Top 25 Zephyr-to-Zephyr matches by raw cosine similarity
SELECT name_a, name_b,
       ROUND(cosine_sim, 4) AS sim,
       ops_a, ops_b,
       CASE WHEN name_a = name_b THEN 'MATCH' ELSE 'MISMATCH' END AS name_check
FROM zz_cosine_raw
ORDER BY cosine_sim DESC
LIMIT 25;

-- Precision at thresholds (Zephyr-to-Zephyr, raw)
SELECT
    threshold,
    total_pairs,
    name_matches,
    ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1) AS precision_pct
FROM (
    SELECT 0.99 AS threshold,
           COUNT(*) AS total_pairs,
           SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END) AS name_matches
    FROM zz_cosine_raw WHERE cosine_sim >= 0.99
    UNION ALL
    SELECT 0.95, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_raw WHERE cosine_sim >= 0.95
    UNION ALL
    SELECT 0.90, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_raw WHERE cosine_sim >= 0.90
    UNION ALL
    SELECT 0.85, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_raw WHERE cosine_sim >= 0.85
    UNION ALL
    SELECT 0.80, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_raw WHERE cosine_sim >= 0.80
) t
ORDER BY threshold DESC;

-- ================================================================
-- 3. Cross-ISA experiment: Pico (M0+) vs Zephyr (M3) raw cosine
-- ================================================================
-- These targets share almost no function names (different libc,
-- different SDK), so "name match" validation is limited.  But we
-- can still look at the similarity distribution and manually
-- inspect the top matches.

CREATE OR REPLACE VIEW pz_cosine_raw AS
SELECT
    a.name AS name_a,
    b.name AS name_b,
    a.source AS source_a,
    b.source AS source_b,
    a.pcode_ops_total AS ops_a,
    b.pcode_ops_total AS ops_b,
    (a.v_copy*b.v_copy + a.v_int_add*b.v_int_add + a.v_int_sub*b.v_int_sub
     + a.v_int_equal*b.v_int_equal + a.v_int_notequal*b.v_int_notequal
     + a.v_int_sless*b.v_int_sless + a.v_int_less*b.v_int_less
     + a.v_int_and*b.v_int_and + a.v_int_or*b.v_int_or
     + a.v_int_xor*b.v_int_xor + a.v_int_left*b.v_int_left
     + a.v_int_right*b.v_int_right + a.v_int_sright*b.v_int_sright
     + a.v_int_zext*b.v_int_zext + a.v_int_sext*b.v_int_sext
     + a.v_load*b.v_load + a.v_store*b.v_store
     + a.v_branch*b.v_branch + a.v_cbranch*b.v_cbranch
     + a.v_call*b.v_call + a.v_return*b.v_return
     + a.v_bool_and*b.v_bool_and + a.v_bool_or*b.v_bool_or
     + a.v_bool_negate*b.v_bool_negate + a.v_piece*b.v_piece
     + a.v_subpiece*b.v_subpiece + a.v_int_mult*b.v_int_mult
     + a.v_indirect*b.v_indirect + a.v_multiequal*b.v_multiequal
     + a.v_cast*b.v_cast
    ) * 1.0 / NULLIF(
        SQRT(a.v_copy*a.v_copy + a.v_int_add*a.v_int_add + a.v_int_sub*a.v_int_sub
             + a.v_int_equal*a.v_int_equal + a.v_int_notequal*a.v_int_notequal
             + a.v_int_sless*a.v_int_sless + a.v_int_less*a.v_int_less
             + a.v_int_and*a.v_int_and + a.v_int_or*a.v_int_or
             + a.v_int_xor*a.v_int_xor + a.v_int_left*a.v_int_left
             + a.v_int_right*a.v_int_right + a.v_int_sright*a.v_int_sright
             + a.v_int_zext*a.v_int_zext + a.v_int_sext*a.v_int_sext
             + a.v_load*a.v_load + a.v_store*a.v_store
             + a.v_branch*a.v_branch + a.v_cbranch*a.v_cbranch
             + a.v_call*a.v_call + a.v_return*a.v_return
             + a.v_bool_and*a.v_bool_and + a.v_bool_or*a.v_bool_or
             + a.v_bool_negate*a.v_bool_negate + a.v_piece*a.v_piece
             + a.v_subpiece*a.v_subpiece + a.v_int_mult*a.v_int_mult
             + a.v_indirect*a.v_indirect + a.v_multiequal*a.v_multiequal
             + a.v_cast*a.v_cast)
        * SQRT(b.v_copy*b.v_copy + b.v_int_add*b.v_int_add + b.v_int_sub*b.v_int_sub
               + b.v_int_equal*b.v_int_equal + b.v_int_notequal*b.v_int_notequal
               + b.v_int_sless*b.v_int_sless + b.v_int_less*b.v_int_less
               + b.v_int_and*b.v_int_and + b.v_int_or*b.v_int_or
               + b.v_int_xor*b.v_int_xor + b.v_int_left*b.v_int_left
               + b.v_int_right*b.v_int_right + b.v_int_sright*b.v_int_sright
               + b.v_int_zext*b.v_int_zext + b.v_int_sext*b.v_int_sext
               + b.v_load*b.v_load + b.v_store*b.v_store
               + b.v_branch*b.v_branch + b.v_cbranch*b.v_cbranch
               + b.v_call*b.v_call + b.v_return*b.v_return
               + b.v_bool_and*b.v_bool_and + b.v_bool_or*b.v_bool_or
               + b.v_bool_negate*b.v_bool_negate + b.v_piece*b.v_piece
               + b.v_subpiece*b.v_subpiece + b.v_int_mult*b.v_int_mult
               + b.v_indirect*b.v_indirect + b.v_multiequal*b.v_multiequal
               + b.v_cast*b.v_cast),
        0
    ) AS cosine_sim
FROM pcode_vec a
JOIN pcode_vec b ON a.source != b.source
WHERE a.source = 'pico_blinky'
  AND b.source = 'zephyr_hello_world';

-- Top 25 Pico-vs-Zephyr matches (raw cosine)
SELECT name_a, name_b,
       ROUND(cosine_sim, 4) AS sim,
       ops_a, ops_b
FROM pz_cosine_raw
ORDER BY cosine_sim DESC
LIMIT 25;

-- Distribution of cross-ISA similarities
SELECT
    CASE
        WHEN cosine_sim >= 0.99 THEN '>=0.99'
        WHEN cosine_sim >= 0.95 THEN '0.95-0.99'
        WHEN cosine_sim >= 0.90 THEN '0.90-0.95'
        WHEN cosine_sim >= 0.85 THEN '0.85-0.90'
        WHEN cosine_sim >= 0.80 THEN '0.80-0.85'
        WHEN cosine_sim >= 0.70 THEN '0.70-0.80'
        ELSE '<0.70'
    END AS sim_bucket,
    COUNT(*) AS pairs
FROM pz_cosine_raw
GROUP BY 1
ORDER BY sim_bucket DESC;

-- ================================================================
-- 4. Normalized (frequency) vectors — divide by total ops
-- ================================================================
-- Raw counts are dominated by function size: a 1000-op function has
-- larger counts than a 100-op function doing the same thing.
-- Normalizing to frequencies (count / total) should improve
-- matching for semantically similar functions that differ in size
-- due to ISA differences.

-- 4a. Zephyr-to-Zephyr normalized cosine (control)
CREATE OR REPLACE VIEW zz_cosine_norm AS
SELECT
    a.name AS name_a,
    b.name AS name_b,
    a.pcode_ops_total AS ops_a,
    b.pcode_ops_total AS ops_b,
    -- Normalized vectors: each component divided by pcode_ops_total
    -- dot(a_norm, b_norm) / (|a_norm| * |b_norm|)
    (
      (a.v_copy*1.0/a.pcode_ops_total)*(b.v_copy*1.0/b.pcode_ops_total)
      + (a.v_int_add*1.0/a.pcode_ops_total)*(b.v_int_add*1.0/b.pcode_ops_total)
      + (a.v_int_sub*1.0/a.pcode_ops_total)*(b.v_int_sub*1.0/b.pcode_ops_total)
      + (a.v_int_equal*1.0/a.pcode_ops_total)*(b.v_int_equal*1.0/b.pcode_ops_total)
      + (a.v_int_notequal*1.0/a.pcode_ops_total)*(b.v_int_notequal*1.0/b.pcode_ops_total)
      + (a.v_int_sless*1.0/a.pcode_ops_total)*(b.v_int_sless*1.0/b.pcode_ops_total)
      + (a.v_int_less*1.0/a.pcode_ops_total)*(b.v_int_less*1.0/b.pcode_ops_total)
      + (a.v_int_and*1.0/a.pcode_ops_total)*(b.v_int_and*1.0/b.pcode_ops_total)
      + (a.v_int_or*1.0/a.pcode_ops_total)*(b.v_int_or*1.0/b.pcode_ops_total)
      + (a.v_int_xor*1.0/a.pcode_ops_total)*(b.v_int_xor*1.0/b.pcode_ops_total)
      + (a.v_int_left*1.0/a.pcode_ops_total)*(b.v_int_left*1.0/b.pcode_ops_total)
      + (a.v_int_right*1.0/a.pcode_ops_total)*(b.v_int_right*1.0/b.pcode_ops_total)
      + (a.v_int_sright*1.0/a.pcode_ops_total)*(b.v_int_sright*1.0/b.pcode_ops_total)
      + (a.v_int_zext*1.0/a.pcode_ops_total)*(b.v_int_zext*1.0/b.pcode_ops_total)
      + (a.v_int_sext*1.0/a.pcode_ops_total)*(b.v_int_sext*1.0/b.pcode_ops_total)
      + (a.v_load*1.0/a.pcode_ops_total)*(b.v_load*1.0/b.pcode_ops_total)
      + (a.v_store*1.0/a.pcode_ops_total)*(b.v_store*1.0/b.pcode_ops_total)
      + (a.v_branch*1.0/a.pcode_ops_total)*(b.v_branch*1.0/b.pcode_ops_total)
      + (a.v_cbranch*1.0/a.pcode_ops_total)*(b.v_cbranch*1.0/b.pcode_ops_total)
      + (a.v_call*1.0/a.pcode_ops_total)*(b.v_call*1.0/b.pcode_ops_total)
      + (a.v_return*1.0/a.pcode_ops_total)*(b.v_return*1.0/b.pcode_ops_total)
      + (a.v_bool_and*1.0/a.pcode_ops_total)*(b.v_bool_and*1.0/b.pcode_ops_total)
      + (a.v_bool_or*1.0/a.pcode_ops_total)*(b.v_bool_or*1.0/b.pcode_ops_total)
      + (a.v_bool_negate*1.0/a.pcode_ops_total)*(b.v_bool_negate*1.0/b.pcode_ops_total)
      + (a.v_piece*1.0/a.pcode_ops_total)*(b.v_piece*1.0/b.pcode_ops_total)
      + (a.v_subpiece*1.0/a.pcode_ops_total)*(b.v_subpiece*1.0/b.pcode_ops_total)
      + (a.v_int_mult*1.0/a.pcode_ops_total)*(b.v_int_mult*1.0/b.pcode_ops_total)
      + (a.v_indirect*1.0/a.pcode_ops_total)*(b.v_indirect*1.0/b.pcode_ops_total)
      + (a.v_multiequal*1.0/a.pcode_ops_total)*(b.v_multiequal*1.0/b.pcode_ops_total)
      + (a.v_cast*1.0/a.pcode_ops_total)*(b.v_cast*1.0/b.pcode_ops_total)
    ) / NULLIF(
      SQRT(
        POWER(a.v_copy*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_add*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_sub*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_equal*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_notequal*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_sless*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_less*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_and*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_or*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_xor*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_left*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_right*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_sright*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_zext*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_sext*1.0/a.pcode_ops_total, 2) + POWER(a.v_load*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_store*1.0/a.pcode_ops_total, 2) + POWER(a.v_branch*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_cbranch*1.0/a.pcode_ops_total, 2) + POWER(a.v_call*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_return*1.0/a.pcode_ops_total, 2) + POWER(a.v_bool_and*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_bool_or*1.0/a.pcode_ops_total, 2) + POWER(a.v_bool_negate*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_piece*1.0/a.pcode_ops_total, 2) + POWER(a.v_subpiece*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_mult*1.0/a.pcode_ops_total, 2) + POWER(a.v_indirect*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_multiequal*1.0/a.pcode_ops_total, 2) + POWER(a.v_cast*1.0/a.pcode_ops_total, 2)
      ) * SQRT(
        POWER(b.v_copy*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_add*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_sub*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_equal*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_notequal*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_sless*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_less*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_and*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_or*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_xor*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_left*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_right*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_sright*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_zext*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_sext*1.0/b.pcode_ops_total, 2) + POWER(b.v_load*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_store*1.0/b.pcode_ops_total, 2) + POWER(b.v_branch*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_cbranch*1.0/b.pcode_ops_total, 2) + POWER(b.v_call*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_return*1.0/b.pcode_ops_total, 2) + POWER(b.v_bool_and*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_bool_or*1.0/b.pcode_ops_total, 2) + POWER(b.v_bool_negate*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_piece*1.0/b.pcode_ops_total, 2) + POWER(b.v_subpiece*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_mult*1.0/b.pcode_ops_total, 2) + POWER(b.v_indirect*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_multiequal*1.0/b.pcode_ops_total, 2) + POWER(b.v_cast*1.0/b.pcode_ops_total, 2)
      ), 0
    ) AS cosine_sim
FROM pcode_vec a
JOIN pcode_vec b ON a.source < b.source
WHERE a.source = 'zephyr_hello_world'
  AND b.source = 'zephyr_synchronization';

-- Top 25 Zephyr-to-Zephyr normalized matches
SELECT name_a, name_b,
       ROUND(cosine_sim, 4) AS sim,
       ops_a, ops_b,
       CASE WHEN name_a = name_b THEN 'MATCH' ELSE 'MISMATCH' END AS name_check
FROM zz_cosine_norm
ORDER BY cosine_sim DESC
LIMIT 25;

-- Precision at thresholds (Zephyr-to-Zephyr, normalized)
SELECT
    threshold,
    total_pairs,
    name_matches,
    ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1) AS precision_pct
FROM (
    SELECT 0.99 AS threshold,
           COUNT(*) AS total_pairs,
           SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END) AS name_matches
    FROM zz_cosine_norm WHERE cosine_sim >= 0.99
    UNION ALL
    SELECT 0.95, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_norm WHERE cosine_sim >= 0.95
    UNION ALL
    SELECT 0.90, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_norm WHERE cosine_sim >= 0.90
    UNION ALL
    SELECT 0.85, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_norm WHERE cosine_sim >= 0.85
    UNION ALL
    SELECT 0.80, COUNT(*), SUM(CASE WHEN name_a = name_b THEN 1 ELSE 0 END)
    FROM zz_cosine_norm WHERE cosine_sim >= 0.80
) t
ORDER BY threshold DESC;

-- 4b. Pico-vs-Zephyr normalized cosine (the cross-ISA experiment)
CREATE OR REPLACE VIEW pz_cosine_norm AS
SELECT
    a.name AS name_a,
    b.name AS name_b,
    a.source AS source_a,
    b.source AS source_b,
    a.pcode_ops_total AS ops_a,
    b.pcode_ops_total AS ops_b,
    (
      (a.v_copy*1.0/a.pcode_ops_total)*(b.v_copy*1.0/b.pcode_ops_total)
      + (a.v_int_add*1.0/a.pcode_ops_total)*(b.v_int_add*1.0/b.pcode_ops_total)
      + (a.v_int_sub*1.0/a.pcode_ops_total)*(b.v_int_sub*1.0/b.pcode_ops_total)
      + (a.v_int_equal*1.0/a.pcode_ops_total)*(b.v_int_equal*1.0/b.pcode_ops_total)
      + (a.v_int_notequal*1.0/a.pcode_ops_total)*(b.v_int_notequal*1.0/b.pcode_ops_total)
      + (a.v_int_sless*1.0/a.pcode_ops_total)*(b.v_int_sless*1.0/b.pcode_ops_total)
      + (a.v_int_less*1.0/a.pcode_ops_total)*(b.v_int_less*1.0/b.pcode_ops_total)
      + (a.v_int_and*1.0/a.pcode_ops_total)*(b.v_int_and*1.0/b.pcode_ops_total)
      + (a.v_int_or*1.0/a.pcode_ops_total)*(b.v_int_or*1.0/b.pcode_ops_total)
      + (a.v_int_xor*1.0/a.pcode_ops_total)*(b.v_int_xor*1.0/b.pcode_ops_total)
      + (a.v_int_left*1.0/a.pcode_ops_total)*(b.v_int_left*1.0/b.pcode_ops_total)
      + (a.v_int_right*1.0/a.pcode_ops_total)*(b.v_int_right*1.0/b.pcode_ops_total)
      + (a.v_int_sright*1.0/a.pcode_ops_total)*(b.v_int_sright*1.0/b.pcode_ops_total)
      + (a.v_int_zext*1.0/a.pcode_ops_total)*(b.v_int_zext*1.0/b.pcode_ops_total)
      + (a.v_int_sext*1.0/a.pcode_ops_total)*(b.v_int_sext*1.0/b.pcode_ops_total)
      + (a.v_load*1.0/a.pcode_ops_total)*(b.v_load*1.0/b.pcode_ops_total)
      + (a.v_store*1.0/a.pcode_ops_total)*(b.v_store*1.0/b.pcode_ops_total)
      + (a.v_branch*1.0/a.pcode_ops_total)*(b.v_branch*1.0/b.pcode_ops_total)
      + (a.v_cbranch*1.0/a.pcode_ops_total)*(b.v_cbranch*1.0/b.pcode_ops_total)
      + (a.v_call*1.0/a.pcode_ops_total)*(b.v_call*1.0/b.pcode_ops_total)
      + (a.v_return*1.0/a.pcode_ops_total)*(b.v_return*1.0/b.pcode_ops_total)
      + (a.v_bool_and*1.0/a.pcode_ops_total)*(b.v_bool_and*1.0/b.pcode_ops_total)
      + (a.v_bool_or*1.0/a.pcode_ops_total)*(b.v_bool_or*1.0/b.pcode_ops_total)
      + (a.v_bool_negate*1.0/a.pcode_ops_total)*(b.v_bool_negate*1.0/b.pcode_ops_total)
      + (a.v_piece*1.0/a.pcode_ops_total)*(b.v_piece*1.0/b.pcode_ops_total)
      + (a.v_subpiece*1.0/a.pcode_ops_total)*(b.v_subpiece*1.0/b.pcode_ops_total)
      + (a.v_int_mult*1.0/a.pcode_ops_total)*(b.v_int_mult*1.0/b.pcode_ops_total)
      + (a.v_indirect*1.0/a.pcode_ops_total)*(b.v_indirect*1.0/b.pcode_ops_total)
      + (a.v_multiequal*1.0/a.pcode_ops_total)*(b.v_multiequal*1.0/b.pcode_ops_total)
      + (a.v_cast*1.0/a.pcode_ops_total)*(b.v_cast*1.0/b.pcode_ops_total)
    ) / NULLIF(
      SQRT(
        POWER(a.v_copy*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_add*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_sub*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_equal*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_notequal*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_sless*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_less*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_and*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_or*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_xor*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_left*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_right*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_sright*1.0/a.pcode_ops_total, 2) + POWER(a.v_int_zext*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_sext*1.0/a.pcode_ops_total, 2) + POWER(a.v_load*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_store*1.0/a.pcode_ops_total, 2) + POWER(a.v_branch*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_cbranch*1.0/a.pcode_ops_total, 2) + POWER(a.v_call*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_return*1.0/a.pcode_ops_total, 2) + POWER(a.v_bool_and*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_bool_or*1.0/a.pcode_ops_total, 2) + POWER(a.v_bool_negate*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_piece*1.0/a.pcode_ops_total, 2) + POWER(a.v_subpiece*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_int_mult*1.0/a.pcode_ops_total, 2) + POWER(a.v_indirect*1.0/a.pcode_ops_total, 2)
        + POWER(a.v_multiequal*1.0/a.pcode_ops_total, 2) + POWER(a.v_cast*1.0/a.pcode_ops_total, 2)
      ) * SQRT(
        POWER(b.v_copy*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_add*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_sub*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_equal*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_notequal*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_sless*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_less*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_and*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_or*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_xor*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_left*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_right*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_sright*1.0/b.pcode_ops_total, 2) + POWER(b.v_int_zext*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_sext*1.0/b.pcode_ops_total, 2) + POWER(b.v_load*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_store*1.0/b.pcode_ops_total, 2) + POWER(b.v_branch*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_cbranch*1.0/b.pcode_ops_total, 2) + POWER(b.v_call*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_return*1.0/b.pcode_ops_total, 2) + POWER(b.v_bool_and*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_bool_or*1.0/b.pcode_ops_total, 2) + POWER(b.v_bool_negate*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_piece*1.0/b.pcode_ops_total, 2) + POWER(b.v_subpiece*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_int_mult*1.0/b.pcode_ops_total, 2) + POWER(b.v_indirect*1.0/b.pcode_ops_total, 2)
        + POWER(b.v_multiequal*1.0/b.pcode_ops_total, 2) + POWER(b.v_cast*1.0/b.pcode_ops_total, 2)
      ), 0
    ) AS cosine_sim
FROM pcode_vec a
JOIN pcode_vec b ON a.source != b.source
WHERE a.source = 'pico_blinky'
  AND b.source = 'zephyr_hello_world';

-- Top 25 Pico-vs-Zephyr normalized matches
SELECT name_a, name_b,
       ROUND(cosine_sim, 4) AS sim,
       ops_a, ops_b
FROM pz_cosine_norm
ORDER BY cosine_sim DESC
LIMIT 25;

-- Distribution of cross-ISA normalized similarities
SELECT
    CASE
        WHEN cosine_sim >= 0.99 THEN '>=0.99'
        WHEN cosine_sim >= 0.95 THEN '0.95-0.99'
        WHEN cosine_sim >= 0.90 THEN '0.90-0.95'
        WHEN cosine_sim >= 0.85 THEN '0.85-0.90'
        WHEN cosine_sim >= 0.80 THEN '0.80-0.85'
        WHEN cosine_sim >= 0.70 THEN '0.70-0.80'
        ELSE '<0.70'
    END AS sim_bucket,
    COUNT(*) AS pairs
FROM pz_cosine_norm
GROUP BY 1
ORDER BY sim_bucket DESC;

-- ================================================================
-- 5. Best-match analysis: for each Pico function, which Zephyr
--    function is most similar? (normalized cosine, best-1)
-- ================================================================
-- Uses QUALIFY to pick the top match per Pico function.

SELECT name_a AS pico_fn,
       name_b AS best_zephyr_match,
       ROUND(cosine_sim, 4) AS sim,
       ops_a, ops_b
FROM pz_cosine_norm
QUALIFY ROW_NUMBER() OVER (PARTITION BY name_a ORDER BY cosine_sim DESC) = 1
ORDER BY cosine_sim DESC
LIMIT 30;

-- ================================================================
-- 6. Pico-to-Pico same-ISA control (different SDK targets)
-- ================================================================
-- pico_blinky vs pico_hello_timer: same ISA, same compiler, same -O3.
-- Many shared library functions. This is the "easy" baseline.

SELECT
    threshold,
    total_pairs,
    name_matches,
    ROUND(100.0 * name_matches / NULLIF(total_pairs, 0), 1) AS precision_pct
FROM (
    SELECT 0.99 AS threshold, COUNT(*) AS total_pairs,
           SUM(CASE WHEN a.name = b.name THEN 1 ELSE 0 END) AS name_matches
    FROM pcode_vec a JOIN pcode_vec b ON a.source < b.source
    WHERE a.source = 'pico_blinky' AND b.source = 'pico_hello_timer'
      AND (a.v_copy*b.v_copy + a.v_int_add*b.v_int_add + a.v_int_sub*b.v_int_sub
           + a.v_int_equal*b.v_int_equal + a.v_int_notequal*b.v_int_notequal
           + a.v_int_sless*b.v_int_sless + a.v_int_less*b.v_int_less
           + a.v_int_and*b.v_int_and + a.v_int_or*b.v_int_or
           + a.v_int_xor*b.v_int_xor + a.v_int_left*b.v_int_left
           + a.v_int_right*b.v_int_right + a.v_int_sright*b.v_int_sright
           + a.v_int_zext*b.v_int_zext + a.v_int_sext*b.v_int_sext
           + a.v_load*b.v_load + a.v_store*b.v_store
           + a.v_branch*b.v_branch + a.v_cbranch*b.v_cbranch
           + a.v_call*b.v_call + a.v_return*b.v_return
           + a.v_bool_and*b.v_bool_and + a.v_bool_or*b.v_bool_or
           + a.v_bool_negate*b.v_bool_negate + a.v_piece*b.v_piece
           + a.v_subpiece*b.v_subpiece + a.v_int_mult*b.v_int_mult
           + a.v_indirect*b.v_indirect + a.v_multiequal*b.v_multiequal
           + a.v_cast*b.v_cast
          ) * 1.0 / NULLIF(
            SQRT(a.v_copy*a.v_copy + a.v_int_add*a.v_int_add + a.v_int_sub*a.v_int_sub
                 + a.v_int_equal*a.v_int_equal + a.v_int_notequal*a.v_int_notequal
                 + a.v_int_sless*a.v_int_sless + a.v_int_less*a.v_int_less
                 + a.v_int_and*a.v_int_and + a.v_int_or*a.v_int_or
                 + a.v_int_xor*a.v_int_xor + a.v_int_left*a.v_int_left
                 + a.v_int_right*a.v_int_right + a.v_int_sright*a.v_int_sright
                 + a.v_int_zext*a.v_int_zext + a.v_int_sext*a.v_int_sext
                 + a.v_load*a.v_load + a.v_store*a.v_store
                 + a.v_branch*a.v_branch + a.v_cbranch*a.v_cbranch
                 + a.v_call*a.v_call + a.v_return*a.v_return
                 + a.v_bool_and*a.v_bool_and + a.v_bool_or*a.v_bool_or
                 + a.v_bool_negate*a.v_bool_negate + a.v_piece*a.v_piece
                 + a.v_subpiece*a.v_subpiece + a.v_int_mult*a.v_int_mult
                 + a.v_indirect*a.v_indirect + a.v_multiequal*a.v_multiequal
                 + a.v_cast*a.v_cast)
            * SQRT(b.v_copy*b.v_copy + b.v_int_add*b.v_int_add + b.v_int_sub*b.v_int_sub
                   + b.v_int_equal*b.v_int_equal + b.v_int_notequal*b.v_int_notequal
                   + b.v_int_sless*b.v_int_sless + b.v_int_less*b.v_int_less
                   + b.v_int_and*b.v_int_and + b.v_int_or*b.v_int_or
                   + b.v_int_xor*b.v_int_xor + b.v_int_left*b.v_int_left
                   + b.v_int_right*b.v_int_right + b.v_int_sright*b.v_int_sright
                   + b.v_int_zext*b.v_int_zext + b.v_int_sext*b.v_int_sext
                   + b.v_load*b.v_load + b.v_store*b.v_store
                   + b.v_branch*b.v_branch + b.v_cbranch*b.v_cbranch
                   + b.v_call*b.v_call + b.v_return*b.v_return
                   + b.v_bool_and*b.v_bool_and + b.v_bool_or*b.v_bool_or
                   + b.v_bool_negate*b.v_bool_negate + b.v_piece*b.v_piece
                   + b.v_subpiece*b.v_subpiece + b.v_int_mult*b.v_int_mult
                   + b.v_indirect*b.v_indirect + b.v_multiequal*b.v_multiequal
                   + b.v_cast*b.v_cast), 0
          ) >= 0.99
    UNION ALL
    SELECT 0.95 AS threshold, COUNT(*) AS total_pairs,
           SUM(CASE WHEN a.name = b.name THEN 1 ELSE 0 END) AS name_matches
    FROM pcode_vec a JOIN pcode_vec b ON a.source < b.source
    WHERE a.source = 'pico_blinky' AND b.source = 'pico_hello_timer'
      AND (a.v_copy*b.v_copy + a.v_int_add*b.v_int_add + a.v_int_sub*b.v_int_sub
           + a.v_int_equal*b.v_int_equal + a.v_int_notequal*b.v_int_notequal
           + a.v_int_sless*b.v_int_sless + a.v_int_less*b.v_int_less
           + a.v_int_and*b.v_int_and + a.v_int_or*b.v_int_or
           + a.v_int_xor*b.v_int_xor + a.v_int_left*b.v_int_left
           + a.v_int_right*b.v_int_right + a.v_int_sright*b.v_int_sright
           + a.v_int_zext*b.v_int_zext + a.v_int_sext*b.v_int_sext
           + a.v_load*b.v_load + a.v_store*b.v_store
           + a.v_branch*b.v_branch + a.v_cbranch*b.v_cbranch
           + a.v_call*b.v_call + a.v_return*b.v_return
           + a.v_bool_and*b.v_bool_and + a.v_bool_or*b.v_bool_or
           + a.v_bool_negate*b.v_bool_negate + a.v_piece*b.v_piece
           + a.v_subpiece*b.v_subpiece + a.v_int_mult*b.v_int_mult
           + a.v_indirect*b.v_indirect + a.v_multiequal*b.v_multiequal
           + a.v_cast*b.v_cast
          ) * 1.0 / NULLIF(
            SQRT(a.v_copy*a.v_copy + a.v_int_add*a.v_int_add + a.v_int_sub*a.v_int_sub
                 + a.v_int_equal*a.v_int_equal + a.v_int_notequal*a.v_int_notequal
                 + a.v_int_sless*a.v_int_sless + a.v_int_less*a.v_int_less
                 + a.v_int_and*a.v_int_and + a.v_int_or*a.v_int_or
                 + a.v_int_xor*a.v_int_xor + a.v_int_left*a.v_int_left
                 + a.v_int_right*a.v_int_right + a.v_int_sright*a.v_int_sright
                 + a.v_int_zext*a.v_int_zext + a.v_int_sext*a.v_int_sext
                 + a.v_load*a.v_load + a.v_store*a.v_store
                 + a.v_branch*a.v_branch + a.v_cbranch*a.v_cbranch
                 + a.v_call*a.v_call + a.v_return*a.v_return
                 + a.v_bool_and*a.v_bool_and + a.v_bool_or*a.v_bool_or
                 + a.v_bool_negate*a.v_bool_negate + a.v_piece*a.v_piece
                 + a.v_subpiece*a.v_subpiece + a.v_int_mult*a.v_int_mult
                 + a.v_indirect*a.v_indirect + a.v_multiequal*a.v_multiequal
                 + a.v_cast*a.v_cast)
            * SQRT(b.v_copy*b.v_copy + b.v_int_add*b.v_int_add + b.v_int_sub*b.v_int_sub
                   + b.v_int_equal*b.v_int_equal + b.v_int_notequal*b.v_int_notequal
                   + b.v_int_sless*b.v_int_sless + b.v_int_less*b.v_int_less
                   + b.v_int_and*b.v_int_and + b.v_int_or*b.v_int_or
                   + b.v_int_xor*b.v_int_xor + b.v_int_left*b.v_int_left
                   + b.v_int_right*b.v_int_right + b.v_int_sright*b.v_int_sright
                   + b.v_int_zext*b.v_int_zext + b.v_int_sext*b.v_int_sext
                   + b.v_load*b.v_load + b.v_store*b.v_store
                   + b.v_branch*b.v_branch + b.v_cbranch*b.v_cbranch
                   + b.v_call*b.v_call + b.v_return*b.v_return
                   + b.v_bool_and*b.v_bool_and + b.v_bool_or*b.v_bool_or
                   + b.v_bool_negate*b.v_bool_negate + b.v_piece*b.v_piece
                   + b.v_subpiece*b.v_subpiece + b.v_int_mult*b.v_int_mult
                   + b.v_indirect*b.v_indirect + b.v_multiequal*b.v_multiequal
                   + b.v_cast*b.v_cast), 0
          ) >= 0.95
) t
ORDER BY threshold DESC;
