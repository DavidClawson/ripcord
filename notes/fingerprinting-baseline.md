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

## Second Zephyr target confirms the hypothesis (2026-04-05, same day)

Added `zephyr_synchronization` — Zephyr's canonical two-threads-
two-semaphores sample, built for the same `qemu_cortex_m3` board
with the same flags and the same picolibc, as a strict superset of
`zephyr_hello_world`'s kernel surface. Ran the same
`structural_signatures.sql` without modification. The results flip
from "essentially nothing" to "near-perfect library identification."

**Strict 8-tuple match results (zephyr_hello_world ⨝ zephyr_synchronization):**

| metric                                          |   n |
|-------------------------------------------------|----:|
| distinct signatures in zephyr_hello_world       |  87 |
| distinct signatures in zephyr_synchronization   | 103 |
| signatures matched between the two (strict 8-tuple) | **75** |
| clusters with identical names across targets    |  **72** |

**72 of 75 cross-target clusters have matching names — 96% cluster-
level precision.** The 3 "mismatches" are not cross-target false
positives: they are *within-target* collisions where two or more
functions inside the same binary share the same signature
(`z_arm_interrupt_init` and `init_ready_q` both appear in both
targets with identical signatures, creating a four-member cluster
with two distinct names). The cross-target pairing on each name
individually is still correct.

86% of zephyr_hello_world's distinct-signature functions (75/87)
have an identical structural twin in zephyr_synchronization. 73%
in the other direction (75/103), because synchronization adds
functions hello_world doesn't have (thread scheduler entry
points, the two per-thread locals, semaphore primitives). The
asymmetry is exactly the shape we expected from a
subset/superset relationship.

**Representative matches (top-25 by size):**

    vfprintf                           1278 bytes, 158 blocks
    z_thread_abort                      394          35
    skip_to_arg                         298          53
    z_add_timeout                       278          19
    sys_clock_set_timeout               200          14
    __ultoa_invert                      192          12
    sys_clock_announce                  186           6
    bg_thread_main                      166          11
    z_cstart                            160           1
    ready_thread                        140          13
    ... (15 more)
    k_sched_unlock                       94          11
    move_current_to_end_of_prio_q        86           7
    z_time_slice                         80           8
    z_arm_fatal_error                    76           5
    free_list_add                        68           4
    sys_clock_isr                        64           1
    z_impl_k_wakeup                      64           3
    elapsed                              58           4
    z_time_slice_size                    52           8
    z_reset_time_slice                   52           3

Every entry is a real Zephyr kernel or picolibc function. The
coverage spans every subsystem both targets touch: printf
machinery (`vfprintf`, `skip_to_arg`, `__ultoa_invert`), thread
scheduler (`z_thread_abort`, `ready_thread`, `k_sched_unlock`,
`move_current_to_end_of_prio_q`, `z_time_slice*`), timer subsystem
(`z_add_timeout`, `sys_clock_*`, `elapsed`), kernel init
(`z_cstart`, `bg_thread_main`), ARM fault handling
(`z_arm_fatal_error`), memory management (`free_list_add`).

The 12 functions from synchronization that do NOT match hello_world
are exactly what you'd predict: thread entry points (`thread_a_entry_point`,
`thread_b_entry_point`), the `hello_loop` function synchronization
defines, `k_sem_*` primitives that hello_world never pulls in, and
a few of synchronization's own static helpers. Clean superset
structure.

**Takeaway — this is the Phase 1 primitive working end-to-end:**

1. The structural signature query is the right primitive. It was
   not broken; it was aimed at incompatible targets last session.
2. Rule-based library identification under same-build conditions
   works *today*, at ~96% cluster-level precision, with no ML, no
   learned corpus, and no byte-pattern hashing. The Stage 0
   warehouse is sufficient.
3. The feature vector's limitation is within-target structural
   twins (functions with identical `(size, blocks, instructions,
   calls, xrefs)` counts that are genuinely different functions).
   On Zephyr this affected 3 of 75 clusters. The fix is richer
   per-function features: a byte-pattern hash, a P-Code opcode
   histogram, or a call-neighborhood signature — all deferred to
   Phase 1 proper.
4. The cross-target failure from the first session (pico ↔ zephyr)
   was entirely explained by build matrix mismatch, not feature
   vector weakness. Same session, same query, different targets,
   dramatic change in result quality.
5. **Phase 1 library identification can be driven by a reference
   corpus that is built with matching flags, at ~96% precision,
   using only the SQL we have.** Every step beyond that — byte
   patterns, P-Code embeddings, fuzzy match — is a precision
   improvement, not a prerequisite. The floor is already usable.

## Updated next steps

Downgrade in importance:

- ~~Build a second Zephyr sample to confirm the same-build
  hypothesis.~~ Done.

Upgrade in importance:

- **Start the Phase 1 reference corpus with one target-matched
  library build.** FreeRTOS compiled for `cortex-m0plus -O3`
  dropped in as a ripcord target, so the structural signature
  query can identify FreeRTOS functions in a future Pico-FreeRTOS
  build. This is the first real library-ID result we could
  demonstrate against an unknown binary.

- **Add a byte-pattern feature** to the extractor (a hash of the
  instruction bytes per function, normalized for relocations) to
  close the 3-of-75 within-target collision gap. Small extractor
  change, single new column, no ML.

- **Add name-aware matching post-processing** to the structural
  query. When a cluster has multiple distinct names, split it by
  name pair — that's the 100%-precision version of the current
  query and it's a pure SQL change with no new data needed.
