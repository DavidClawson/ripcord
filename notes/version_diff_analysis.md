# FNIRSI 2C53T Stock Firmware Version Diff Analysis

Generated 2026-04-08 from ripcord warehouse cross-version queries.

## Firmware versions analyzed

| Version | Binary size | Functions | Unique body hashes | Total code bytes | Calls | Strings |
|---------|------------|-----------|-------------------|-----------------|-------|---------|
| V1.0.3 (2024-08-14) | 462,400 | 269 | 267 | 104,226 | 1,057 | 272 |
| V1.0.7 (2024-12-05) | 486,720 | 287 | 285 | 139,874 | 1,499 | 271 |
| V1.1.2 (2025-09-29) | 751,040 | 306 | 304 | 161,176 | 1,695 | 293 |
| V1.2.0 (2025-10-15) | 751,232 | 305 | 303 | 161,310 | 1,694 | 293 |

The firmware grew 62% in binary size and 55% in code bytes from V1.0.3
to V1.1.2, then plateaued. V1.1.2 and V1.2.0 are nearly identical in
structure.

## Cross-version body-hash matching

Functions matched by identical SHA-256 of raw instruction bytes (position-independent matching -- ignores address relocation):

| Transition | From count | To count | Hash-identical | New/changed in target | Removed/changed from source |
|-----------|-----------|---------|---------------|----------------------|---------------------------|
| V1.0.3 -> V1.0.7 | 269 | 287 | 116 | 175 | 157 |
| V1.0.7 -> V1.1.2 | 287 | 306 | 93 | 217 | 198 |
| V1.1.2 -> V1.2.0 | 306 | 305 | 182 | 127 | 128 |

### Stable core across all four versions

**83 functions** have byte-identical body hashes across all four
versions. These are the firmware's immutable foundation -- library
routines, peripheral drivers, and data-structure operations that
FNIRSI never touched across 14 months of development. The largest
stable functions are 908, 696, 580, 518, and 482 bytes.

### Version-unique functions

| Version | Functions unique to this version (hash not in any other) |
|---------|--------------------------------------------------------|
| V1.0.3 | 157 |
| V1.0.7 | 171 |
| V1.1.2 | 128 |
| V1.2.0 | 127 |

## Address relocation patterns

Matching by body hash reveals that most functions were relinked
(different address, same code) rather than rewritten:

| Pair | Hash matches | Same address | Relocated | Median shift (bytes) |
|------|-------------|-------------|-----------|---------------------|
| V1.0.3 <-> V1.0.7 | 116 | 25 | 91 | 14,008 |
| V1.0.3 <-> V1.1.2 | 89 | 0 | 89 | 24,520 |
| V1.0.3 <-> V1.2.0 | 89 | 0 | 89 | 24,716 |
| V1.0.7 <-> V1.1.2 | 93 | 0 | 93 | 10,512 |
| V1.0.7 <-> V1.2.0 | 93 | 0 | 93 | 10,708 |
| V1.1.2 <-> V1.2.0 | 182 | 33 | 149 | 196 |

Key finding: **V1.1.2 and V1.2.0 differ by a uniform ~196-256 byte
shift for most functions**, meaning only a few functions at the
beginning of the image changed size, pushing everything else down.
The actual code changes between V1.1.2 and V1.2.0 are minimal.

The V1.0.3 -> V1.0.7 transition has a 14 KB median shift, indicating
~14 KB of new code was inserted early in the image. The V1.0.7 ->
V1.1.2 transition has a 10.5 KB median shift -- another significant
code insertion.

## What changed between versions

### V1.0.3 -> V1.0.7 (the big feature add)

The largest function jumped from 6,632 bytes to 14,650 bytes. The
function at 0x0802c014 grew from 112 bytes (5 basic blocks) to 3,138
bytes (205 basic blocks) -- a 28x increase, likely a simple stub
replaced with full implementation.

Code byte growth: +35,648 bytes (34% increase). Call count growth:
+442 calls (42% increase). This was the most disruptive update -- only
116 of 287 V1.0.7 functions match anything in V1.0.3.

### V1.0.7 -> V1.1.2 (internationalization and measurement modes)

Binary size jumped from 487 KB to 751 KB (54% increase). Strings new
in V1.1.2+ include:

- **Spanish**: "Voltaje de Corriente Continua", "Gran Corriente Alterna"
- **Portuguese**: "Pequeno Corrente Alternada", "Continuidade"
- **German**: "Kleiner Wechselstrom", "Oszilloskop-Einstellungen"
- **Measurement modes**: "Exceeded Limit", "Capacitancia", "Resistencia", "Temperatura"

A debug source path `../../../project/bsp_sys.c` appeared in V1.1.2
(not present in V1.0.3 or V1.0.7), suggesting the build system or
assert macros changed.

Only 93 of 306 V1.1.2 functions match V1.0.7 by hash -- extensive
rework.

### V1.1.2 -> V1.2.0 (minor patch)

The most conservative update. 182 of 305 V1.2.0 functions are
byte-identical to V1.1.2 counterparts. Function count dropped by 1
(306 -> 305). Total code bytes increased by only 134.

The 13 functions at stable addresses with different hashes include:

| Address | Size V1.1.2 | Size V1.2.0 | Delta | Notes |
|---------|------------|------------|-------|-------|
| 0x080062dc | 128 | 910 | +782 | Largest growth -- stub -> implementation |
| 0x0803fb4c | 376 | 194 | -182 | Shrunk significantly |
| 0x08032f48 | 112 | 256 | +144 | |
| 0x0801de18 | 22 | 82 | +60 | |
| 0x08004238 | 2,116 | 2,116 | 0 | Same size, different code |
| 0x080042c8 | 36 | 36 | 0 | Same size, different code |
| 0x08005448 | 224 | 224 | 0 | Same size, different code |

Function at 0x08004238 (2,116 bytes, 262 basic blocks) is the
second function in the image -- likely the main dispatch loop or
early initialization. It changed in every version transition,
suggesting it's the primary integration point for new features.

## Function size distribution

| Version | <50B | 50-200B | 200B-1KB | 1KB-5KB | >5KB |
|---------|------|---------|----------|---------|------|
| V1.0.3 | 65 | 82 | 100 | 20 | 2 |
| V1.0.7 | 66 | 82 | 111 | 24 | 4 |
| V1.1.2 | 71 | 91 | 112 | 28 | 4 |
| V1.2.0 | 71 | 90 | 112 | 28 | 4 |

Growth is primarily in the medium (200B-1KB) and large (1KB-5KB)
categories. The enormous functions (>5KB) jumped from 2 to 4 between
V1.0.3 and V1.0.7 and stayed at 4.

## Call graph evolution

| Version | Total calls | Unique callers | Unique callees |
|---------|------------|----------------|----------------|
| V1.0.3 | 1,057 | 169 | 214 |
| V1.0.7 | 1,499 | 180 | 242 |
| V1.1.2 | 1,695 | 194 | 262 |
| V1.2.0 | 1,694 | 194 | 261 |

V1.1.2 and V1.2.0 are call-graph-identical in structure (within 1
call).

## Interpretation: what was FNIRSI doing?

1. **V1.0.3 -> V1.0.7** was a major feature release. The 14,650-byte
   function (not present in V1.0.3's top functions) and the 28x growth
   of 0x0802c014 suggest a new subsystem was implemented -- possibly
   the multimeter measurement mode or a major UI overhaul.

2. **V1.0.7 -> V1.1.2** was the internationalization release. Spanish,
   Portuguese, and German translations were added. The binary grew
   54% (most of which is likely string tables and font/image data for
   the UI, not new code -- code grew only 15%). New measurement
   mode strings ("Capacitancia", "Temperatura") suggest the DMM
   functionality was also expanded.

3. **V1.1.2 -> V1.2.0** was a bugfix/polish release. Nearly identical
   code, with a handful of functions tweaked (the 0x080062dc stub
   getting fleshed out, one function shrinking). The function at
   0x08004238 (likely main loop/init) changed but stayed the same
   size, suggesting a logic fix, not a feature addition.

4. **The FPGA interaction code**: Without symbol names, we can't
   definitively identify FPGA-specific functions. However, the stable
   core of 83 unchanged functions across all versions likely includes
   the SPI/FPGA communication primitives (these would be low-level
   and unlikely to change). The functions that changed every version
   (like 0x08004238) are more likely application-level integration
   points that orchestrate when and how the FPGA is talked to, not
   the communication protocol itself.

## Methodology notes

- All comparisons use SHA-256 body hashes of raw function bytes
  (position-independent, computed by the Ghidra extractor)
- "Hash-identical" means the compiled machine code is byte-for-byte
  the same; it does not mean the source was identical (the compiler
  could produce identical output from slightly different source)
- Address-based matching only works within the same link layout;
  hash-based matching works across relinks
- All four binaries were loaded at base address 0x08004000 using
  Ghidra's BinaryLoader with ARM:LE:32:Cortex processor
