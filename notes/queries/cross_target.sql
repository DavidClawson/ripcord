-- Cross-target queries: the first joins that exercise the warehouse
-- across multiple targets at once. These become more interesting
-- every time a new target is added to config.yaml.
--
-- Usage:
--   scripts/query < notes/queries/cross_target.sql

-- 1. Per-target row-count matrix. A quick vertical read of how much
-- surface each target exposes to the pipeline. Big asymmetries
-- (e.g., 10x more strings on one target than another) are usually
-- interesting — either the target has more debug logging or the
-- extractor is behaving differently.
SELECT
    source,
    (SELECT COUNT(*) FROM functions    WHERE source = t.source) AS functions,
    (SELECT COUNT(*) FROM calls        WHERE source = t.source) AS calls,
    (SELECT COUNT(*) FROM basic_blocks WHERE source = t.source) AS basic_blocks,
    (SELECT COUNT(*) FROM xrefs        WHERE source = t.source) AS xrefs,
    (SELECT COUNT(*) FROM strings      WHERE source = t.source) AS strings,
    (SELECT COUNT(*) FROM ground_truth_functions WHERE source = t.source) AS nm_symbols
FROM (SELECT DISTINCT source FROM functions) t
ORDER BY source;

-- 2. Functions that exist by name in every target. Shared runtime
-- (libc, compiler helpers, __aeabi_*, memcpy, strlen, etc.) is the
-- most common reason a name appears on two targets built with the
-- same toolchain family. This is the crudest structural signal
-- that Phase 1 library identification will refine — if Zephyr and
-- the Pico SDK both contain a function named `memcpy` at different
-- addresses with similar byte counts, that's a 2-sample fingerprint
-- candidate.
SELECT
    f.name,
    COUNT(DISTINCT f.source)            AS targets,
    LIST(DISTINCT f.source ORDER BY f.source)                   AS present_in,
    LIST({'source': f.source, 'size': f.size, 'blocks': f.basic_block_count}
         ORDER BY f.source)             AS per_target_stats
FROM functions f
WHERE f.name NOT LIKE 'FUN\_%' ESCAPE '\'
GROUP BY f.name
HAVING COUNT(DISTINCT f.source) > 1
ORDER BY targets DESC, f.name
LIMIT 30;

-- 3. Functions by complexity (block count) per target, side by
-- side. Top 5 from each target. Gives an at-a-glance comparison
-- of where the complexity lives in each binary.
WITH ranked AS (
    SELECT
        source,
        name,
        basic_block_count AS blocks,
        size,
        ROW_NUMBER() OVER (PARTITION BY source ORDER BY basic_block_count DESC, size DESC) AS rn
    FROM functions
    WHERE basic_block_count IS NOT NULL
)
SELECT source, name, blocks, size
FROM ranked
WHERE rn <= 5
ORDER BY source, rn;

-- 4. Ground-truth coverage side-by-side. How well does the Ghidra
-- extractor handle each target? The two numbers to watch are
-- pct_nm_addrs_in_ghidra (Ghidra's recall against nm symbols) and
-- ghidra_only (functions Ghidra finds that nm doesn't know about —
-- usually DWARF-recovered weak symbols). Large asymmetry between
-- targets suggests the extractor is behaving differently on one of
-- them and warrants a look.
SELECT
    COALESCE(gt.source, f.source)       AS source,
    COUNT(DISTINCT gt.addr)             AS nm_unique_addrs,
    COUNT(DISTINCT f.addr)              AS ghidra_functions,
    COUNT(DISTINCT CASE WHEN f.addr IS NOT NULL AND gt.addr IS NOT NULL
                        THEN gt.addr END) AS both,
    COUNT(DISTINCT CASE WHEN f.addr IS NULL AND gt.addr IS NOT NULL
                        THEN gt.addr END) AS only_in_nm,
    COUNT(DISTINCT CASE WHEN f.addr IS NOT NULL AND gt.addr IS NULL
                        THEN f.addr END)  AS only_in_ghidra,
    ROUND(
        100.0 * COUNT(DISTINCT CASE WHEN f.addr IS NOT NULL AND gt.addr IS NOT NULL
                                    THEN gt.addr END)
        / NULLIF(COUNT(DISTINCT gt.addr), 0),
        1
    ) AS pct_nm_addrs_in_ghidra
FROM ground_truth_functions gt
FULL OUTER JOIN functions f
    ON f.source = gt.source AND f.addr = gt.addr
GROUP BY COALESCE(gt.source, f.source)
ORDER BY source;

-- 5. Strings referenced by functions in each target. Combined with
-- the list of shared function names from query 2, this starts to
-- answer "does this target log debug information I can use to name
-- functions." Targets with lots of string references per function
-- are where Phase 1 fingerprinting will get the most value.
SELECT
    f.source,
    COUNT(DISTINCT f.addr)              AS functions_with_string_refs,
    COUNT(DISTINCT s.addr)              AS distinct_strings_referenced,
    COUNT(*)                             AS total_string_xrefs
FROM functions f
JOIN xrefs x ON x.source = f.source AND x.function_addr = f.addr
JOIN strings s ON s.source = x.source AND s.addr = x.to_addr
GROUP BY f.source
ORDER BY f.source;
