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
