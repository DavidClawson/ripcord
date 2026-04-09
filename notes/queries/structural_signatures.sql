-- Structural fingerprinting, v0: exact-match on a hand-crafted
-- per-function feature vector, joined across targets.
--
-- This is the first Phase 1 primitive the warehouse can answer
-- without any new extractor, pipeline stage, or ML model. The
-- hypothesis: two targets built with the *same* toolchain
-- (arm-none-eabi-gcc 15.2.1) link identical libgcc compiler-runtime
-- helpers (__aeabi_uidiv, __aeabi_lmul, memcpy-family inlines,
-- etc.). Pico SDK renames them via `-Wl,--wrap` so name matching
-- fails, but the *structure* should match exactly: same byte count,
-- same basic block layout, same instruction count, same outgoing
-- calls. If the structural match finds these functions, the
-- warehouse has enough signal to drive library identification
-- without byte-level pattern work — at least for the obvious cases.
--
-- What this doesn't do: byte-pattern matching, fuzzy match,
-- learned embeddings. Those are Phase 1 proper. This query is the
-- no-ML, no-corpus baseline — whatever it catches for free is the
-- floor every later technique has to beat.
--
-- Usage:
--   scripts/query < notes/queries/structural_signatures.sql

-- 1. Materialize the feature vector as a view for reuse below.
--
-- Filters: is_thunk=false because thunks all collapse to the same
-- tiny signature; size >= 8 because sub-8-byte functions are
-- typically compiler stubs (bx lr, infinite loop) that also all
-- collapse. Neither is useful fingerprinting signal.
CREATE OR REPLACE VIEW feature_vector AS
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
    f.basic_block_count                       AS blocks,
    COALESCE(bb_agg.instructions,        0)   AS instructions,
    COALESCE(call_agg.out_calls,         0)   AS out_calls,
    COALESCE(call_agg.distinct_callees,  0)   AS distinct_callees,
    COALESCE(xref_agg.reads,             0)   AS reads,
    COALESCE(xref_agg.writes,            0)   AS writes,
    COALESCE(xref_agg.jumps,             0)   AS jumps
FROM functions f
LEFT JOIN bb_agg
    ON bb_agg.source = f.source AND bb_agg.function_addr = f.addr
LEFT JOIN call_agg
    ON call_agg.source = f.source AND call_agg.function_addr = f.addr
LEFT JOIN xref_agg
    ON xref_agg.source = f.source AND xref_agg.function_addr = f.addr
WHERE COALESCE(f.is_thunk, FALSE) = FALSE
  AND f.size IS NOT NULL
  AND f.size >= 8;

-- 2. Feature-vector discrimination summary. If the vector is too
-- loose, most functions share a signature with others in the same
-- target, so cross-target matches will be dominated by noise. If
-- it's too tight, very few cross-target matches exist. Both
-- failure modes show up here.
SELECT
    source,
    COUNT(*)                                          AS functions,
    COUNT(DISTINCT (size, blocks, instructions, out_calls,
                    distinct_callees, reads, writes, jumps))
                                                      AS distinct_signatures,
    ROUND(
        1.0 * COUNT(*)
        / NULLIF(COUNT(DISTINCT (size, blocks, instructions, out_calls,
                                 distinct_callees, reads, writes, jumps)), 0),
        2
    )                                                 AS avg_functions_per_signature
FROM feature_vector
GROUP BY source
ORDER BY source;

-- 3. Within-target signature collisions. Pairs of functions in
-- the same binary that share a signature. A low count here means
-- the vector is discriminative enough to distinguish most
-- functions from their peers; a high count means it's too coarse.
SELECT
    source,
    size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps,
    COUNT(*) AS n_functions,
    LIST(name ORDER BY name)[:4] AS sample_names
FROM feature_vector
GROUP BY source, size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps
HAVING COUNT(*) > 1
ORDER BY n_functions DESC, source
LIMIT 15;

-- 4. STRICT CROSS-TARGET MATCH: signature tuples that appear in
-- both targets. The 8-tuple is exact: byte-for-byte match on size,
-- block structure, instruction count, call shape, and xref
-- distribution. For libgcc helpers linked identically, this
-- should land.
SELECT
    size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps,
    COUNT(DISTINCT source)                    AS target_count,
    COUNT(*)                                  AS total_functions,
    LIST({'source': source, 'name': name, 'addr': printf('0x%x', addr)}
         ORDER BY source, name)               AS members
FROM feature_vector
GROUP BY size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps
HAVING COUNT(DISTINCT source) > 1
ORDER BY total_functions DESC, size DESC
LIMIT 20;

-- 5. RELAXED CROSS-TARGET MATCH: drop the xref features, keep
-- only the structural skeleton (size, blocks, instructions,
-- out_calls, distinct_callees). Xref counts can vary between
-- targets for the same logical function because different linked
-- code may cause different data references to get resolved; the
-- skeleton should be more stable.
SELECT
    size, blocks, instructions, out_calls, distinct_callees,
    COUNT(DISTINCT source)                    AS target_count,
    COUNT(*)                                  AS total_functions,
    LIST({'source': source, 'name': name, 'addr': printf('0x%x', addr)}
         ORDER BY source, name)               AS members
FROM feature_vector
GROUP BY size, blocks, instructions, out_calls, distinct_callees
HAVING COUNT(DISTINCT source) > 1
ORDER BY total_functions DESC, size DESC
LIMIT 20;

-- 6. SKELETON MATCH: just size + blocks + instructions. The
-- crudest possible match. High false-positive rate expected but
-- gives an upper bound on how many functions are even plausibly
-- similar across targets.
SELECT
    size, blocks, instructions,
    COUNT(DISTINCT source)                    AS target_count,
    COUNT(*)                                  AS total_functions,
    LIST({'source': source, 'name': name}
         ORDER BY source, name)[:6]           AS sample_members
FROM feature_vector
GROUP BY size, blocks, instructions
HAVING COUNT(DISTINCT source) > 1
ORDER BY total_functions DESC, size DESC
LIMIT 15;

-- 7. NAME-AWARE PRECISION: decompose cross-target clusters by name.
--
-- Sections 4-6 group by the feature tuple only. When two different
-- functions in the same binary share a signature (within-target
-- twins), the cluster inflates and the name list shows multiple
-- distinct names — but the cross-target match on each name
-- individually may still be correct. This query resolves that
-- ambiguity by sub-grouping: for each (signature, name) pair that
-- appears in more than one target, that's a confirmed cross-target
-- name match. Clusters where names disagree across targets are
-- separated out as collisions.
--
-- The summary at the end reports precision = confirmed / (confirmed
-- + collision), which should be ~100% on the Zephyr pair where the
-- raw cluster-level metric was ~96%.

-- 7a. Per-name cross-target matches (confirmed)
CREATE OR REPLACE VIEW name_matches AS
SELECT
    name,
    size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps,
    COUNT(DISTINCT source) AS target_count,
    COUNT(*)               AS total_functions,
    LIST(DISTINCT source ORDER BY source) AS sources
FROM feature_vector
WHERE name NOT LIKE 'FUN_%'   -- exclude Ghidra auto-names (no ground truth)
GROUP BY name, size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps
HAVING COUNT(DISTINCT source) > 1;

-- Show the confirmed matches, largest first
SELECT name, size, blocks, instructions, target_count, sources
FROM name_matches
ORDER BY size DESC
LIMIT 30;

-- 7b. Within-target collisions: signature tuples that appear in
-- multiple targets but carry more than one distinct (non-auto) name
-- across the full cluster. These are the cases the raw §4 query
-- mis-counts.
CREATE OR REPLACE VIEW signature_collisions AS
WITH cross_target_clusters AS (
    SELECT
        size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps,
        COUNT(DISTINCT source) AS target_count
    FROM feature_vector
    GROUP BY size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps
    HAVING COUNT(DISTINCT source) > 1
),
cluster_names AS (
    SELECT
        fv.size, fv.blocks, fv.instructions, fv.out_calls,
        fv.distinct_callees, fv.reads, fv.writes, fv.jumps,
        COUNT(DISTINCT CASE WHEN fv.name NOT LIKE 'FUN_%' THEN fv.name END) AS distinct_real_names,
        LIST(DISTINCT fv.name ORDER BY fv.name)[:6] AS sample_names
    FROM feature_vector fv
    INNER JOIN cross_target_clusters c USING (size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps)
    GROUP BY fv.size, fv.blocks, fv.instructions, fv.out_calls,
             fv.distinct_callees, fv.reads, fv.writes, fv.jumps
)
SELECT * FROM cluster_names WHERE distinct_real_names > 1;

SELECT * FROM signature_collisions ORDER BY distinct_real_names DESC;

-- 7c. Summary: name-aware precision
--
-- confirmed_matches: (signature, name) pairs present in >1 target.
--   Every one of these is a true positive by construction (same name,
--   same structural fingerprint, different targets).
-- collisions: signature tuples that appear in >1 target but carry
--   multiple distinct real names. These are ambiguous, not wrong —
--   they need a richer discriminator (byte hash, P-Code) to resolve.
-- unambiguous_pct: fraction of cross-target signature clusters that
--   are collision-free (single name across all targets). This is the
--   "how often can you trust a structural match without further
--   disambiguation" metric.
SELECT
    (SELECT COUNT(*) FROM name_matches)   AS confirmed_matches,
    (SELECT COUNT(*) FROM signature_collisions) AS collisions,
    ROUND(
        100.0 * (SELECT COUNT(*) FROM name_matches)
        / NULLIF((SELECT COUNT(*) FROM name_matches)
                 + (SELECT COUNT(*) FROM signature_collisions), 0),
        1
    ) AS unambiguous_pct;

-- 8. BODY-HASH DISAMBIGUATION: resolve structural collisions using
-- the byte-level hash (requires body_hash column in functions table).
--
-- For each collision cluster from §7b, check whether the body_hash
-- can split the ambiguous members into distinct groups. If two
-- functions share a structural signature but have different hashes,
-- they are definitively different. If they share both structure and
-- hash, they are byte-identical (true duplicates or copy-pasted code).
--
-- This section is a no-op if body_hash is NULL (pre-hash pipeline run).

-- 8a. Cross-target matches using structure + hash (the gold standard)
CREATE OR REPLACE VIEW hash_matches AS
SELECT
    fv.name,
    f.body_hash,
    fv.size, fv.blocks, fv.instructions,
    COUNT(DISTINCT fv.source) AS target_count,
    LIST(DISTINCT fv.source ORDER BY fv.source) AS sources
FROM feature_vector fv
JOIN functions f ON f.source = fv.source AND f.addr = fv.addr
WHERE fv.name NOT LIKE 'FUN_%'
  AND f.body_hash IS NOT NULL
GROUP BY fv.name, f.body_hash, fv.size, fv.blocks, fv.instructions
HAVING COUNT(DISTINCT fv.source) > 1;

SELECT name, body_hash[:16] AS hash_prefix, size, blocks, target_count, sources
FROM hash_matches
ORDER BY size DESC
LIMIT 30;

-- 8b. Collision resolution: do any §7b collisions survive when we
-- add body_hash as a discriminator?
SELECT
    sc.size, sc.blocks, sc.instructions,
    sc.sample_names,
    COUNT(DISTINCT f.body_hash) AS distinct_hashes
FROM signature_collisions sc
JOIN feature_vector fv USING (size, blocks, instructions, out_calls, distinct_callees, reads, writes, jumps)
JOIN functions f ON f.source = fv.source AND f.addr = fv.addr
WHERE f.body_hash IS NOT NULL
GROUP BY sc.size, sc.blocks, sc.instructions, sc.sample_names;
