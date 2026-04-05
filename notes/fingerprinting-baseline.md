# Fingerprinting baseline (2026-04-05)

First attempt at structural fingerprinting against the live
warehouse: `notes/queries/structural_signatures.sql`. This is the
no-ML, no-corpus, no-byte-pattern baseline — whatever it catches
for free is the floor every Phase 1 technique has to beat. The
results surfaced a finding about the current target pair that's
worth pinning before we invest in richer features.

## The feature vector

Per function, excluding thunks and functions smaller than 8 bytes:

```
(size, basic_block_count, instruction_count,
 outgoing_calls, distinct_callees,
 read_refs, write_refs, jump_refs)
```

Eight scalar features, all integer, all aggregable from existing
warehouse tables via single-pass GROUP BY.

## Within-target discrimination: works

```
pico_blinky:         71 functions, 64 distinct signatures  (1.11 avg)
zephyr_hello_world:  90 functions, 87 distinct signatures  (1.03 avg)
```

The feature vector is highly discriminative *within a single
binary*. Nearly every function has a unique signature. The small
number of within-target collisions are legitimate: tiny `__aeabi_*`
init stubs that all genuinely do nothing (single-instruction
`bx lr` returns), dispatch veneers that share structure because
they exist to share structure, and a handful of `runtime_init_*`
helpers with the same shape.

**Implication:** on a single target, this vector is strong enough
to act as an index key for "find me functions shaped like this
known library function." Phase 1 library identification *within*
a binary — matching a target against a reference corpus compiled
with the same ISA and flags — will work with features this
simple.

## Cross-target match: essentially nothing, and here's why

The 8-tuple strict match found exactly **one** cluster across
pico_blinky and zephyr_hello_world: a group of 3 tiny
`(size=8, blocks=1, instructions=3, out_calls=1)` stub functions
that are trivially interchangeable and not usefully identifiable
as "the same function."

The relaxed 5-tuple and the 3-tuple skeleton found a handful more,
all at sizes ≤ 14 bytes, all tiny wrappers where the structural
match is genuine but the functions are not the same thing — e.g.,
pico's `_out_char` matches zephyr's `elapsed` on
`(size=14, blocks=3, instructions=6, out_calls=1)`, but one is a
stdio character writer and the other is a tick counter read.
Structural similarity without semantic equivalence.

**None of the real libgcc helpers match across targets.** The
libgcc `__aeabi_*` functions I hypothesized would be byte-identical
(based on "same toolchain") are not in both binaries at all: Pico
has `__wrap___aeabi_lmul` (50 bytes), `divmod_u32u32` and friends
(Pico SDK's own math code); Zephyr hello_world has only `memcpy`,
`memset`, and two tiny arch_early_ wrappers, no aeabi helpers
whatsoever. Zephyr's hello_world does no 64-bit math, no floating
point, no division, so libgcc's aeabi helpers are simply not
linked.

Even where the two targets share a name, the code is different:

| function | pico_blinky          | zephyr_hello_world    |
|----------|---------------------:|----------------------:|
| `main`   | 36 bytes, 2 blocks   | 14 bytes, 1 block     |
| `memcpy` | 6 bytes, 1 block (`__wrap_memcpy`, a thunk) | 28 bytes, 5 blocks (direct impl) |

## Why the cross-target match fails on these specific targets

Four compounding differences:

1. **Different ISA.** Pico is Cortex-M0+ (armv6s-m, Thumb only,
   16-bit instructions, no conditional execution). Zephyr is
   Cortex-M3 (armv7-m, Thumb-2, 32-bit instructions available,
   richer addressing modes). The same C source compiles to
   structurally different code: Cortex-M3 can express operations
   in fewer instructions, and the basic block graph can collapse
   because it has true conditional execution where Cortex-M0+
   requires explicit branches.

2. **Different optimization level.** Pico builds with `-O3`
   (the Pico SDK default); Zephyr hello_world defaults to `-Os`
   or similar size-optimized flags. Different `-O` produces
   different inlining decisions, different loop unrolling,
   different register allocation. Same source, different binary.

3. **Different libc.** Pico SDK uses newlib (or newlib-nano).
   Zephyr uses picolibc. These implement the same API with
   different code. `memcpy`, `printf`, `strlen` are *not* the
   same function across these targets even though they share a
   name.

4. **Almost no shared link surface.** Pico blinky pulls in
   runtime init, alarm pool, boot2, clocks, GPIO, pico-specific
   divmod helpers. Zephyr hello_world pulls in the Zephyr kernel,
   picolibc printf machinery, ARM fault handlers, thread
   scheduling. The overlap in "what code is actually present" is
   `main()` and a couple of tiny wrappers. Even if the targets
   were byte-compatible, there's not much shared code to match.

## Takeaways for Phase 1 library identification

This is the load-bearing part.

1. **The "same toolchain" hypothesis is too weak.** I had assumed
   that two targets built with `arm-none-eabi-gcc 15.2.1` would
   share compiler-runtime code. They don't, because "same
   toolchain" does not mean "same ISA + same flags + same libc
   + overlapping link surface." Library fingerprinting needs the
   stronger condition — or, equivalently, features that are
   invariant to these differences.

2. **Cross-ISA fingerprinting requires ISA-invariant features.**
   This validates design-decision D9 (train function embeddings
   on Ghidra P-Code, not raw disassembly). P-Code is
   architecture-independent by construction: the same C source
   compiled for armv6s-m and armv7-m produces similar P-Code,
   even when the machine instructions and byte counts differ
   dramatically. A P-Code–level feature extractor is the right
   target for the learned phase of fingerprinting.

3. **A useful reference corpus has to be homogeneous.** For
   Phase 1 rule-based fingerprinting to work, the reference
   builds need to span the same `(ISA, -O level, libc)` tuples
   the targets will be matched against. Compiling FreeRTOS once
   is not enough; we need FreeRTOS × {armv6s-m, armv7-m,
   armv7e-m, armv8-m} × {-O0, -Os, -O2, -O3} × {newlib, picolibc}.
   This is the corpus-build effort `notes/PLAN.md` §1.1 referenced
   in vague terms; today's finding gives it concrete dimensions.

4. **Within-target library ID is the right first milestone.**
   Matching one target's functions against a ground-truth library
   reference compiled with *matching* flags is tractable with the
   feature vector we have today. Matching *across* targets with
   different ISAs is the learned-model problem.

5. **The current baseline is still useful.** The feature vector
   plus its signature grouping is the right scaffolding for Phase
   1 rule-based fingerprinting. The fix is not to abandon the
   vector; it's to aim it at a reference corpus that shares flags
   with the target being matched. When we build that corpus and
   add it as a "target" in ripcord, the same query file will
   start producing meaningful matches.

## Concrete next steps this unblocks

In rough order of cost vs. value:

- **Add a second Zephyr sample on the same qemu_cortex_m3 board.**
  Same ISA, same flags, same libc, overlapping link surface
  (both pull in the Zephyr kernel). The structural signature
  query should start producing real cross-target matches on
  kernel functions (`k_sleep`, `z_swap`, `printk` stack, etc.).
  One ELF, one config entry, half an hour of work.

- **Build Pico blinky and another Pico SDK example (hello_usb,
  hello_timer).** Same ISA, same flags, same SDK. Should match on
  all the pico_runtime_* and clock_configure_* infrastructure.

- **Start the reference corpus with one library and one flag set.**
  FreeRTOS built for Cortex-M0+ with `-O3 -mcpu=cortex-m0plus` to
  match Pico's build, dropped in as `targets/freertos_v11_m0plus/`.
  The structural query should then identify FreeRTOS functions in
  a Pico-FreeRTOS build.

- **Write an export_pcode.py extractor.** This is the Phase 1
  invariant-features path. P-Code basic-block sequences hashed
  into a per-function fingerprint, ISA-invariant by construction.
  Bigger lift than the above but the highest leverage for
  eventual cross-ISA work.

## What not to conclude from this

- The structural signature query is *not* broken. It does what it
  should: group functions by a hand-crafted feature vector.
- The warehouse is *not* missing the features it would need for
  this to work on these targets. It's that these two targets
  genuinely don't share code.
- Phase 1 fingerprinting is *not* blocked. It is better-scoped:
  we now know the corpus requirement (homogeneous flags) and the
  invariant-features requirement (P-Code for cross-ISA) are
  non-negotiable, not optional.
