-- Extractor coverage against ELF symbol-table ground truth.
--
-- Joins the Ghidra-derived `functions` table against `ground_truth_functions`
-- (populated from `nm -S <elf>`) to report how many text symbols in the
-- unstripped ELF are present in the Ghidra extraction, how many are missing,
-- and how many Ghidra-discovered functions have no corresponding nm symbol.
--
-- Matches are by (source, addr). Name matching is reported as a side channel
-- but is not load-bearing — Ghidra applies DWARF-derived names that may not
-- match nm's symbol names verbatim.
--
-- Usage:
--   scripts/query < notes/queries/coverage.sql

-- 1. Coverage summary per target.
SELECT
    COALESCE(gt.source, f.source)              AS source,
    COUNT(DISTINCT gt.addr)                     AS nm_text_symbols,
    COUNT(DISTINCT f.addr)                      AS ghidra_functions,
    COUNT(DISTINCT CASE WHEN gt.addr IS NOT NULL AND f.addr IS NOT NULL
                        THEN gt.addr END)        AS both,
    COUNT(DISTINCT CASE WHEN gt.addr IS NOT NULL AND f.addr IS NULL
                        THEN gt.addr END)        AS only_in_nm,
    COUNT(DISTINCT CASE WHEN gt.addr IS NULL AND f.addr IS NOT NULL
                        THEN f.addr END)         AS only_in_ghidra,
    ROUND(
        100.0 * COUNT(DISTINCT CASE WHEN gt.addr IS NOT NULL AND f.addr IS NOT NULL
                                    THEN gt.addr END)
        / NULLIF(COUNT(DISTINCT gt.addr), 0),
        1
    )                                            AS pct_nm_covered
FROM ground_truth_functions gt
FULL OUTER JOIN functions f
    ON f.source = gt.source AND f.addr = gt.addr
GROUP BY COALESCE(gt.source, f.source)
ORDER BY source;

-- 2. Symbols nm sees but Ghidra does not (the extraction gap).
-- Grouped by a crude categorization of the name pattern so the gap is
-- explained rather than just counted.
SELECT
    gt.source,
    CASE
        WHEN gt.name LIKE '%_veneer'                       THEN 'linker veneer'
        WHEN gt.name LIKE '\_\_aeabi\_%' ESCAPE '\'        THEN 'aeabi helper'
        WHEN gt.name LIKE '\_\_wrap\_%'  ESCAPE '\'        THEN 'linker --wrap shim'
        WHEN gt.name LIKE '\_\_%'        ESCAPE '\'        THEN 'toolchain internal (__ prefix)'
        WHEN gt.bind = 'local'                              THEN 'local symbol'
        ELSE 'other'
    END                                          AS category,
    COUNT(*)                                     AS n,
    MIN(gt.name)                                 AS example_name,
    printf('0x%x', MIN(gt.addr))                 AS example_addr
FROM ground_truth_functions gt
LEFT JOIN functions f
    ON f.source = gt.source AND f.addr = gt.addr
WHERE f.addr IS NULL
GROUP BY gt.source, category
ORDER BY gt.source, n DESC;

-- 3. Ghidra-discovered functions with no corresponding nm symbol.
-- These are almost always Ghidra's auto-generated FUN_xxxxxxxx functions
-- created by the disassembler when it finds a code path that the symbol
-- table doesn't cover (e.g., function bodies the linker merged, inline
-- assembly, or residue from scratch sections).
SELECT
    f.source,
    COUNT(*)                                     AS n,
    MIN(f.name)                                  AS example_name,
    printf('0x%x', MIN(f.addr))                  AS example_addr
FROM functions f
LEFT JOIN ground_truth_functions gt
    ON gt.source = f.source AND gt.addr = f.addr
WHERE gt.addr IS NULL
GROUP BY f.source
ORDER BY f.source;
