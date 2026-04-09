-- cross_isa_pcode.sql — Cross-ISA P-Code sequence hash matching
--
-- Tests design decision D9: "Train function embeddings on P-Code,
-- not disassembly." P-Code is Ghidra's ISA-invariant intermediate
-- representation. If two functions compiled from the same C source
-- for different ISAs produce the same P-Code opcode sequence, then
-- pcode_sequence_hash will match even when their machine code is
-- completely different.
--
-- Empirical result (2026-04-08): Exact pcode_sequence_hash matching
-- across ISAs (Cortex-M0+ vs Cortex-M3) produces essentially ZERO
-- true positives. The 4 matches found are all false positives —
-- small (14-23 op) functions with generic patterns (simple loops,
-- call sequences) that collide by coincidence.
--
-- This is expected and informative: P-Code sequence hashes work as
-- an exact-match signal within the same (ISA, -O, libc) build tuple
-- (93-94% precision at ops >= 50 within Pico), but fail cross-ISA
-- because register allocation, calling conventions, and instruction
-- semantics produce different P-Code lowerings even for the same
-- source function. The path to cross-ISA matching must go through
-- learned embeddings (histograms, graph structure, normalized
-- features), not exact sequence hashes.
--
-- Usage: scripts/query < notes/queries/cross_isa_pcode.sql

-- 1. Cross-ISA matches (Pico M0+ vs Zephyr M3)
WITH pico AS (
    SELECT p.source, p.addr, f.name, p.pcode_sequence_hash, p.pcode_ops_total
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'pico_%'
      AND p.source != 'pico_freertos_hello_stripped'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 10
),
zephyr AS (
    SELECT p.source, p.addr, f.name, p.pcode_sequence_hash, p.pcode_ops_total
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'zephyr_%'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 10
)
SELECT
    pi.name AS pico_name,
    z.name AS zephyr_name,
    pi.pcode_ops_total AS pico_ops,
    z.pcode_ops_total AS zephyr_ops,
    pi.source AS pico_source,
    z.source AS zephyr_source,
    CASE WHEN pi.name = z.name THEN 'MATCH' ELSE 'DIFFERENT' END AS name_status
FROM pico pi
JOIN zephyr z ON pi.pcode_sequence_hash = z.pcode_sequence_hash
ORDER BY pi.pcode_ops_total DESC;

-- 2. Summary
WITH pico AS (
    SELECT DISTINCT p.pcode_sequence_hash, f.name
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'pico_%'
      AND p.source != 'pico_freertos_hello_stripped'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 10
),
zephyr AS (
    SELECT DISTINCT p.pcode_sequence_hash, f.name
    FROM pcode_features p
    JOIN functions f ON f.source = p.source AND f.addr = p.addr
    WHERE p.source LIKE 'zephyr_%'
      AND f.name NOT LIKE 'FUN_%'
      AND p.pcode_ops_total >= 10
)
SELECT
    COUNT(*) AS total_cross_isa_matches,
    SUM(CASE WHEN pi.name = z.name THEN 1 ELSE 0 END) AS same_name,
    SUM(CASE WHEN pi.name != z.name THEN 1 ELSE 0 END) AS different_name,
    ROUND(100.0 * SUM(CASE WHEN pi.name = z.name THEN 1 ELSE 0 END) / GREATEST(COUNT(*), 1), 1) AS precision_pct
FROM pico pi
JOIN zephyr z ON pi.pcode_sequence_hash = z.pcode_sequence_hash;

-- 3. Within-ISA comparison: Pico-to-Pico at various op thresholds
SELECT 'within-pico ops>=50' AS context,
    COUNT(*) AS total,
    SUM(CASE WHEN f1.name = f2.name THEN 1 ELSE 0 END) AS same_name,
    ROUND(100.0 * SUM(CASE WHEN f1.name = f2.name THEN 1 ELSE 0 END) / COUNT(*), 1) AS precision_pct
FROM pcode_features p1
JOIN pcode_features p2 ON p1.pcode_sequence_hash = p2.pcode_sequence_hash AND p1.source < p2.source
JOIN functions f1 ON f1.source = p1.source AND f1.addr = p1.addr
JOIN functions f2 ON f2.source = p2.source AND f2.addr = p2.addr
WHERE p1.source LIKE 'pico_%' AND p2.source LIKE 'pico_%'
  AND p1.source != 'pico_freertos_hello_stripped' AND p2.source != 'pico_freertos_hello_stripped'
  AND f1.name NOT LIKE 'FUN_%' AND f2.name NOT LIKE 'FUN_%'
  AND p1.pcode_ops_total >= 50
UNION ALL
SELECT 'within-zephyr ops>=10',
    COUNT(*),
    SUM(CASE WHEN f1.name = f2.name THEN 1 ELSE 0 END),
    ROUND(100.0 * SUM(CASE WHEN f1.name = f2.name THEN 1 ELSE 0 END) / COUNT(*), 1)
FROM pcode_features p1
JOIN pcode_features p2 ON p1.pcode_sequence_hash = p2.pcode_sequence_hash AND p1.source < p2.source
JOIN functions f1 ON f1.source = p1.source AND f1.addr = p1.addr
JOIN functions f2 ON f2.source = p2.source AND f2.addr = p2.addr
WHERE p1.source LIKE 'zephyr_%' AND p2.source LIKE 'zephyr_%'
  AND f1.name NOT LIKE 'FUN_%' AND f2.name NOT LIKE 'FUN_%'
  AND p1.pcode_ops_total >= 10;
