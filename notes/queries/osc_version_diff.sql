-- Cross-version comparison for FNIRSI 2C53T stock firmware.
--
-- Compares all four stock versions (V1.0.3, V1.0.7, V1.1.2, V1.2.0)
-- at function granularity using body_hash for byte-exact identity.
-- Useful for tracking what changed between releases and identifying
-- the stable core vs. actively-developed functions.
--
-- Usage:
--   scripts/query < notes/queries/osc_version_diff.sql

-- 1. Size evolution across versions.
SELECT source,
       COUNT(*) AS functions,
       SUM(size) AS total_bytes,
       COUNT(*) FILTER (WHERE is_thunk) AS thunks
FROM functions
WHERE source LIKE 'stock_%'
GROUP BY source
ORDER BY source;

-- 2. Byte-identical functions across ALL four versions.
--    These are the completely untouched core — same address, same bytes.
SELECT printf('0x%08x', f1.addr) AS addr,
       f1.name,
       f1.body_hash[:16] AS hash_prefix,
       f1.size
FROM functions f1
WHERE f1.source = 'stock_v103'
  AND f1.body_hash IS NOT NULL
  AND EXISTS (
      SELECT 1 FROM functions f2
      WHERE f2.source = 'stock_v107'
        AND f2.addr = f1.addr AND f2.body_hash = f1.body_hash
  )
  AND EXISTS (
      SELECT 1 FROM functions f3
      WHERE f3.source = 'stock_v112'
        AND f3.addr = f1.addr AND f3.body_hash = f1.body_hash
  )
  AND EXISTS (
      SELECT 1 FROM functions f4
      WHERE f4.source = 'stock_v120'
        AND f4.addr = f1.addr AND f4.body_hash = f1.body_hash
  )
ORDER BY f1.size DESC;

-- 3. Functions that changed between V1.1.2 and V1.2.0 (latest delta).
--    Matched by address; shows size delta for functions whose bytes differ.
SELECT
    printf('0x%08x', v120.addr) AS addr,
    v120.name AS name_v120,
    v112.size AS size_v112,
    v120.size AS size_v120,
    v120.size - v112.size AS delta
FROM functions v120
JOIN functions v112 ON v112.addr = v120.addr AND v112.source = 'stock_v112'
WHERE v120.source = 'stock_v120'
  AND v120.body_hash IS NOT NULL
  AND v112.body_hash IS NOT NULL
  AND v120.body_hash != v112.body_hash
ORDER BY ABS(v120.size - v112.size) DESC;

-- 4. Functions added in V1.2.0 (present in v120, absent from v112 by address).
SELECT printf('0x%08x', v120.addr) AS addr,
       v120.name,
       v120.size
FROM functions v120
WHERE v120.source = 'stock_v120'
  AND NOT EXISTS (
      SELECT 1 FROM functions v112
      WHERE v112.source = 'stock_v112' AND v112.addr = v120.addr
  )
ORDER BY v120.addr;

-- 5. Functions removed in V1.2.0 (present in v112, absent from v120 by address).
SELECT printf('0x%08x', v112.addr) AS addr,
       v112.name,
       v112.size
FROM functions v112
WHERE v112.source = 'stock_v112'
  AND NOT EXISTS (
      SELECT 1 FROM functions v120
      WHERE v120.source = 'stock_v120' AND v120.addr = v112.addr
  )
ORDER BY v112.addr;

-- 6. Version-to-version stability matrix.
--    For each pair of adjacent versions, count: identical, changed, added, removed.
WITH pairs(ver_old, ver_new) AS (
    VALUES ('stock_v103','stock_v107'),
           ('stock_v107','stock_v112'),
           ('stock_v112','stock_v120')
),
stats AS (
    SELECT p.ver_old, p.ver_new,
        (SELECT COUNT(*) FROM functions a JOIN functions b
         ON a.addr = b.addr AND a.body_hash = b.body_hash
         WHERE a.source = p.ver_old AND b.source = p.ver_new
           AND a.body_hash IS NOT NULL) AS identical,
        (SELECT COUNT(*) FROM functions a JOIN functions b
         ON a.addr = b.addr AND a.body_hash != b.body_hash
         WHERE a.source = p.ver_old AND b.source = p.ver_new
           AND a.body_hash IS NOT NULL AND b.body_hash IS NOT NULL) AS changed,
        (SELECT COUNT(*) FROM functions b
         WHERE b.source = p.ver_new
           AND NOT EXISTS (SELECT 1 FROM functions a
                           WHERE a.source = p.ver_old AND a.addr = b.addr)) AS added,
        (SELECT COUNT(*) FROM functions a
         WHERE a.source = p.ver_old
           AND NOT EXISTS (SELECT 1 FROM functions b
                           WHERE b.source = p.ver_new AND b.addr = a.addr)) AS removed
    FROM pairs p
)
SELECT ver_old, ver_new, identical, changed, added, removed
FROM stats
ORDER BY ver_old;
