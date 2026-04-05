# Goal and Approach

## The reframe

The natural first framing of this project is "reverse-engineer the firmware
into a clean readable codebase." That framing is wrong for the actual goal,
and realizing it is wrong unlocks a better pipeline.

The actual goal is: **write replacement firmware that drives the existing
hardware faithfully.** The hardware is an MCU (AT32F403A) plus an opaque
FPGA. The FPGA's internal logic is permanently unknowable — it isn't going
to be decompiled. The only observable surface of the FPGA is the sequence of
MMIO reads and writes the MCU performs against it, plus any timing
assumptions baked into the MCU code.

This means: understanding every function's "purpose" is nice but not
necessary. **What's necessary is a complete specification of the MCU↔FPGA
boundary** — every register, every access pattern, every sequence, every
timing constraint. If we can reproduce that boundary behavior exactly,
replacement firmware works, regardless of how much of the rest of the MCU
code we've truly "understood."

## The optimistic corollary

The firmware, by construction, already contains a complete executable
specification of the FPGA's interface. The MCU cannot drive the FPGA without
encoding the full protocol. Everything needed is in there; it's bounded.
This is the most hopeful framing of the whole project: we are not trying to
discover hidden information, we are trying to *extract* information that
provably exists in the binary.

## What the output artifact should be

Given the reframe, the output artifact is **not source code**. It is a
**queryable specification** of:

- The FPGA register map (addresses, widths, inferred roles)
- Access patterns per register (read-only, write-only, command/status pairs,
  polling loops, FIFO-like regions)
- Per-feature MMIO traces (the register sequence observed when the user
  presses a button, refreshes the LCD, sends a USB packet, etc.)
- Timing constraints observed in the original firmware
- Boundary APIs where the MCU calls into FreeRTOS or the AT32 SDK (these
  should be identified as known code and used as typed interfaces)

Source code — in C, Rust, or whatever — is a *render* of that spec that
happens later, after you have the spec, and gets verified by differential
testing.

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
   writes 0x5A to reg 0x14 iff arg0 > 0 and g_mode == 2."
3. **Per-feature MMIO trace equivalence.** Compare Renode traces of the
   original against traces of the replacement running the same scenarios.

None of these are language features. They are execution-based verification.

## Three lift-target options (ranked for this project)

### Option A — No target language; the spec database is the artifact

The deliverable is the SQLite/DuckDB database itself, enriched over time
with facts, traces, and derived queries. You never produce a clean codebase
as an intermediate. Instead:

- Each function has a row with its contract (signature, reads/writes,
  side effects, confidence).
- Each FPGA register has a row with its inferred role and access history.
- Each high-level feature has a row pointing at the MMIO trace that
  realizes it.
- Replacement firmware is written fresh against the database, in whatever
  language makes sense for the target (probably C because of the vendor
  SDK).

**Strongest fit for the stated goal.** The database answers replication
questions directly. Comprehension happens as a side effect.

### Option B — C as the lift target

Not because C is safer (it obviously isn't) but because it is the native
dialect of firmware. Bit twiddling, volatile MMIO, packed structs, inline
asm — all ergonomic. clangd provides cross-references and refactoring.
UBSan/ASan catch a lot under emulation. The AT32 SDK is already C, so
integration is free. Reasonable secondary option if you want source code to
exist alongside the spec DB.

### Option C — Datalog DSL as the derivation layer

Not a language to ship, but a language to *query and derive facts in.*
Datalog (via Soufflé) expresses recursive relationships compactly:
"every function that can transitively cause a write to register X,"
"every function that reads X before writing Y in the same basic block,"
"every register whose value depends on an interrupt handler's globals."

These queries are miserable in SQL and natural in Datalog. Not an
alternative to Option A — a *layer on top of it*.

## Ranking for this project

**A → C (on top of A) → B → Rust.**

The structured spec is the deliverable; Datalog is the derivation engine on
top; C is useful if you want a rendered source tree alongside the spec;
Rust is the weakest fit because its safety guarantees don't catch the
bugs you actually care about, and its type system fights firmware idioms.

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
