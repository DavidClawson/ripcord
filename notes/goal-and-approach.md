# Goal and Approach

## The reframe

The natural first framing of firmware reverse engineering is
"reverse-engineer the binary into a clean readable codebase." That
framing is usually wrong, and realizing it is wrong unlocks a better
pipeline.

For most real-world reverse engineering goals — writing replacement
firmware, verifying hardware behavior, extracting a protocol
specification, characterizing an opaque peripheral — **understanding
every function's "purpose" is nice but not necessary**. What's
necessary is a structured, queryable specification of the binary's
observable behavior: its call graph, its data flow, its hardware
interactions, and the semantic contract of each function.

If you have that specification, you can answer every question a human
could answer by reading the binary, without ever asking a human to
read the binary. And critically, most of that specification can be
*extracted mechanically* by existing tools — Ghidra for static
analysis, Renode for dynamic traces, angr for symbolic facts — without
requiring any LLM involvement at all.

## The hardware-boundary case — an illustrative extreme

The most demanding version of this problem is firmware that drives an
opaque hardware peripheral (FPGA, ASIC, external coprocessor) whose
internal behavior cannot be recovered by any means. In that case, the
only observable surface of the peripheral is the sequence of MMIO
reads and writes the MCU performs against it, plus any timing
assumptions baked into the MCU code.

For that case, the observation that shapes the whole pipeline is: **the
firmware, by construction, already contains a complete executable
specification of the peripheral's interface**. The MCU cannot drive
the peripheral without encoding the full protocol. Everything needed
is in there; the problem is bounded.

This is the most hopeful framing available: we are not trying to
discover hidden information, we are trying to *extract* information
that provably exists in the binary. And the pipeline design is shaped
by the demands of this extreme — if it handles the opaque-peripheral
case, it handles everything simpler.

This hardware-boundary framing was sharpened on a specific project
(the "cord" target — an AT32F403A driving an opaque FPGA over the
EXMC/FSMC bus) but applies to any firmware with external hardware
dependencies whose documentation is missing or incomplete.

## What the output artifact should be

Given the reframe, the output artifact is **not source code**. It is a
**queryable database** of:

- Functions (addresses, sizes, signatures, inferred roles, library
  identifications)
- Basic blocks and control flow graphs
- Call graph edges
- Memory access patterns, including the MMIO register map and access
  histories for any peripheral regions
- Per-feature execution traces (the observable behavior when the
  device does specific things, captured via emulation)
- Boundary APIs where the binary calls into known libraries
  (FreeRTOS, vendor HALs, crypto libraries, protocol stacks),
  identified by structural fingerprinting
- Semantic contracts for application-specific functions, produced
  jointly by static analysis, symbolic execution, and verified
  LLM-agent proposals

Source code — in C, Rust, or whatever — is a *render* of that database
that happens later, after you have the database, and gets verified by
differential testing against the original.

## Why Rust was the wrong lift target

The original intuition was: "if it compiles in Rust, it's logically sound."
This is a common misconception. Rust's compiler catches memory safety and
data-race bugs. It does not catch logical bugs. A Rust program can be fully
type-safe, borrow-check clean, and write `0x5B` where the original wrote
`0x5A`, and nothing in the toolchain will flag it.

The thing Rust *does* offer that is real: whole-program type propagation via
rust-analyzer. That is a tooling benefit, not a correctness benefit — and
clangd + C gives you most of the same benefit with none of the impedance
mismatch against firmware patterns (volatile, MMIO, bit twiddling, ISR
globals, union punning).

What actually catches logic bugs:

1. **Differential emulation.** Run original vs. replacement on the same
   inputs in Unicorn; compare register and memory deltas. This is the only
   check that catches "I wrote 0x5B instead of 0x5A."
2. **Symbolic execution via angr.** Derive formal facts like "this function
   writes a specific value to a specific register iff some precondition
   holds."
3. **Per-feature MMIO trace equivalence.** Compare Renode traces of the
   original against traces of the replacement running the same scenarios.

None of these are language features. They are execution-based verification.

## Three lift-target options

### Option A — No target language; the database is the artifact

The deliverable is the DuckDB warehouse (plus SQLite coordination
layer) itself, enriched over time with facts, traces, and derived
queries. You never produce a clean codebase as an intermediate.
Instead:

- Each function has a row with its contract (signature, reads/writes,
  side effects, confidence).
- Each peripheral register (for targets with external hardware) has
  a row with its inferred role and access history.
- Each high-level observable behavior has a row pointing at the trace
  that realizes it.
- Replacement firmware, if it is ever written, is written fresh
  against the database in whatever language makes sense for the
  target.

**Strongest fit for most goals.** The database answers comprehension
and replication questions directly. Source code, if desired, comes
later.

### Option B — C as the lift target

Not because C is safer (it obviously isn't) but because it is the native
dialect of firmware. Bit twiddling, volatile MMIO, packed structs, inline
asm — all ergonomic. clangd provides cross-references and refactoring.
UBSan/ASan catch a lot under emulation. Vendor SDKs are almost always
C, so integration is free. Reasonable secondary option if you want
source code to exist alongside the database.

### Option C — Datalog DSL as the derivation layer

Not a language to ship, but a language to *query and derive facts in.*
Datalog (via Soufflé) expresses recursive relationships compactly:
"every function that can transitively cause a write to register X,"
"every function that reads X before writing Y in the same basic block,"
"every register whose value depends on an interrupt handler's globals."

These queries are miserable in SQL and natural in Datalog. Not an
alternative to Option A — a *layer on top of it*.

## Ranking

**A → C (on top of A) → B → Rust.**

The structured database is the deliverable; Datalog is the derivation
engine on top; C is useful if you want a rendered source tree
alongside the database; Rust is the weakest fit because its safety
guarantees don't catch the bugs you actually care about, and its type
system fights firmware idioms.

## The key verification loop

Whatever the artifact shape, the core correctness loop is:

1. Exercise a feature on the original firmware in Renode; record the MMIO
   trace.
2. Write (or have an agent write) a replacement implementation of that
   feature against the spec DB.
3. Run the replacement in Renode under the same scenario; record its MMIO
   trace.
4. Diff the traces. Differences are bugs, full stop.

At the function level, the same loop runs in Unicorn with randomized
inputs for speed. Either way, **execution is the oracle, not the compiler.**
