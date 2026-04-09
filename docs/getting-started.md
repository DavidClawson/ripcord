# Getting Started with ripcord

A plain-language guide to what ripcord does, how it works, and where
it's going. This assumes you know the basics of programming and have a
rough idea of what a CPU does, but you don't need to be a reverse
engineering expert or have used any of the specific tools before.

---

## Table of Contents

- [1. What Is ripcord?](#1-what-is-ripcord)
  - [1.1. The Problem](#11-the-problem)
  - [1.2. The Idea](#12-the-idea)
  - [1.3. The Name](#13-the-name)
- [2. Core Concepts](#2-core-concepts)
  - [2.1. What Is Firmware?](#21-what-is-firmware)
  - [2.2. What Is Reverse Engineering?](#22-what-is-reverse-engineering)
  - [2.3. What Is a "Fact Database"?](#23-what-is-a-fact-database)
  - [2.4. Functions, Basic Blocks, and Call Graphs](#24-functions-basic-blocks-and-call-graphs)
  - [2.5. MMIO and Hardware Boundaries](#25-mmio-and-hardware-boundaries)
  - [2.6. P-Code: The Rosetta Stone](#26-p-code-the-rosetta-stone)
- [3. The Tools We Use](#3-the-tools-we-use)
  - [3.1. Ghidra — The Disassembler and Decompiler](#31-ghidra--the-disassembler-and-decompiler)
  - [3.2. DuckDB and Apache Parquet — The Data Layer](#32-duckdb-and-apache-parquet--the-data-layer)
  - [3.3. Snakemake — The Pipeline Orchestrator](#33-snakemake--the-pipeline-orchestrator)
  - [3.4. Renode — The Hardware Emulator](#34-renode--the-hardware-emulator)
  - [3.5. Souffl&eacute; — The Logic Engine](#35-souffl--the-logic-engine)
  - [3.6. Python — The Glue](#36-python--the-glue)
  - [3.7. Future Tools](#37-future-tools)
- [4. The Theory Behind It All](#4-the-theory-behind-it-all)
  - [4.1. Why a Database, Not Source Code?](#41-why-a-database-not-source-code)
  - [4.2. The "Minutes, Not Days" Constraint](#42-the-minutes-not-days-constraint)
  - [4.3. Function Fingerprinting: Identifying Known Code](#43-function-fingerprinting-identifying-known-code)
  - [4.4. Cross-ISA Matching and Why It's Hard](#44-cross-isa-matching-and-why-its-hard)
  - [4.5. Execution-Based Verification](#45-execution-based-verification)
  - [4.6. The Blackboard Architecture](#46-the-blackboard-architecture)
  - [4.7. Confidence and Evidence Tracking](#47-confidence-and-evidence-tracking)
- [5. How the Pipeline Works](#5-how-the-pipeline-works)
  - [5.1. Overview of the Stages](#51-overview-of-the-stages)
  - [5.2. Stage 0: Extraction (Ghidra)](#52-stage-0-extraction-ghidra)
  - [5.3. Stage 1: Library Identification](#53-stage-1-library-identification)
  - [5.4. Stage 2: Dynamic Traces (Renode)](#54-stage-2-dynamic-traces-renode)
  - [5.5. Stage 4: Datalog Derivation](#55-stage-4-datalog-derivation)
  - [5.6. Later Stages: Agents and Verification](#56-later-stages-agents-and-verification)
- [6. The Warehouse: What's in the Database](#6-the-warehouse-whats-in-the-database)
  - [6.1. Table Overview](#61-table-overview)
  - [6.2. Querying the Warehouse](#62-querying-the-warehouse)
  - [6.3. Example Queries](#63-example-queries)
- [7. Where We Are Now](#7-where-we-are-now)
  - [7.1. What's Been Proven](#71-whats-been-proven)
  - [7.2. Current Targets](#72-current-targets)
  - [7.3. Key Empirical Results](#73-key-empirical-results)
- [8. Where We're Going](#8-where-were-going)
  - [8.1. Near Term: Cross-ISA Matching](#81-near-term-cross-isa-matching)
  - [8.2. Medium Term: Agent Swarms](#82-medium-term-agent-swarms)
  - [8.3. Long Term: Learned Embeddings and Public Corpus](#83-long-term-learned-embeddings-and-public-corpus)
  - [8.4. The Endgame](#84-the-endgame)
- [9. Setting Up and Running It Yourself](#9-setting-up-and-running-it-yourself)
  - [9.1. Prerequisites](#91-prerequisites)
  - [9.2. Install the Tools](#92-install-the-tools)
  - [9.3. Build a Test Target](#93-build-a-test-target)
  - [9.4. Run the Pipeline](#94-run-the-pipeline)
  - [9.5. Explore the Results](#95-explore-the-results)
- [10. Repository Layout](#10-repository-layout)
- [11. Glossary](#11-glossary)

---

## 1. What Is ripcord?

### 1.1. The Problem

Imagine you bought a piece of electronics — maybe an oscilloscope, a
drone controller, or a smart thermostat. Inside is a microcontroller
(a tiny computer on a chip) running software called **firmware**. That
firmware is the only thing that knows how to talk to the hardware:
how to read a sensor, drive a display, or communicate over a serial
bus.

Now imagine the manufacturer goes out of business, or the firmware has
a bug, or you want to add a feature, or you just want to understand
what you own. The firmware is a blob of raw machine code — ones and
zeros — with no source code, no documentation, and no comments. To a
human, it's opaque.

Traditionally, reverse engineering that blob is a slow, manual,
expert-intensive process. A skilled analyst might spend weeks or
months in a tool like Ghidra or IDA Pro, clicking through functions
one at a time, renaming things, writing notes, building up a mental
model. It works, but it doesn't scale, and it's hard to share or
reproduce.

### 1.2. The Idea

ripcord flips the problem. Instead of a human manually reading the
binary, ripcord runs a **pipeline of automated tools** that extract
every fact they can find from the binary and store those facts in a
**queryable database**. The database becomes the deliverable — not
source code, not a report, but a structured collection of facts that
any tool or person can query.

The core thesis:

> Most of the work in firmware reverse engineering is deterministic
> automation that should take minutes, not days. Invest heavily in
> that fast deterministic path so that expensive resources (human
> experts, LLM agents) only need to look at the genuinely hard parts.

A typical firmware binary might contain 300 functions. Of those, maybe
200 are well-known open-source library code (FreeRTOS, a USB stack,
a standard C library). Another 50 are vendor-provided hardware
abstraction layer (HAL) code. Only 50 are truly application-specific
— the novel logic that makes this particular device do its thing.

ripcord's job is to automatically identify the 250 known functions,
build a complete map of how everything connects, capture hardware
interaction traces, and present the whole thing as a database. Then
the human (or an AI agent) only needs to focus on the 50 genuinely
unknown functions, with the full context of everything around them
already mapped out.

### 1.3. The Name

Pull a ripcord on a parachute, and a carefully packed structure
tumbles out and inflates into something functional. Same idea: one
command, binary in, structured knowledge out.

---

## 2. Core Concepts

### 2.1. What Is Firmware?

Firmware is software that runs directly on a microcontroller or
embedded processor. Unlike your laptop's operating system, firmware
typically:

- Runs on **very constrained hardware** — think 256 KB of flash
  memory and 64 KB of RAM, with a CPU clock of 48-168 MHz.
- Has **no operating system** (or a tiny one like FreeRTOS or
  Zephyr).
- Talks directly to **hardware peripherals** — GPIO pins, serial
  buses (UART, SPI, I2C), timers, ADCs, DMA controllers — through
  special memory addresses.
- Is compiled from C (occasionally C++ or Rust) using a
  cross-compiler (one that runs on your laptop but produces code for
  the target chip).

When you compile firmware, you get an **ELF file** (Executable and
Linkable Format) — a structured binary that contains the machine code,
data sections, and optionally debug information. If the manufacturer
ships only a `.bin` (raw flash image), that debug information is
stripped, and recovery is harder.

### 2.2. What Is Reverse Engineering?

Reverse engineering (RE) is figuring out how something works by
examining its output rather than its source. For firmware, this means:

1. **Disassembly** — converting raw machine code bytes back into
   human-readable assembly instructions. A byte sequence like
   `0x4B 0x08 0x68 0x1B` becomes `ldr r3, [pc, #32]; ldr r3, [r3]`
   (an ARM Thumb instruction to load a value from memory).

2. **Decompilation** — going one step further and converting assembly
   into something resembling C code. The `ldr` instructions above
   might become `x = *some_global;`.

3. **Analysis** — understanding what the code actually *does*: which
   functions call which, what hardware registers they touch, what
   protocols they implement, what data structures they use.

ripcord automates all three of these steps and stores the results
in a structured database rather than in a human's head.

### 2.3. What Is a "Fact Database"?

The central idea of ripcord is that the output of reverse engineering
should be a **database of facts**, not rendered source code. A fact
might be:

- "There is a function at address 0x10000340 that is 128 bytes long
  and calls 3 other functions."
- "Address 0x40004400 is a UART data register, and it's written to
  by functions at 0x10000340 and 0x10000580."
- "This function has the same structure and byte-for-byte content as
  `vTaskDelete` in FreeRTOS 11.1.0 compiled with GCC 13 at -O3."

Each fact is a row in a table. Tables can be joined, filtered, and
aggregated using SQL — the same language used for regular databases.
This makes the analysis **reproducible** (run the same query, get the
same answer), **composable** (join facts from different sources), and
**machine-readable** (downstream tools can consume the database
directly).

### 2.4. Functions, Basic Blocks, and Call Graphs

Three structures you'll see constantly in ripcord's output:

**Functions** are the primary unit of analysis. A function is a
contiguous region of code with a single entry point that performs
some operation and returns. In C, this maps 1:1 to a function
definition. In machine code, it's a block of instructions bounded
by a prologue (entry) and one or more epilogues (returns).

**Basic blocks** are the building blocks of functions. A basic block
is a sequence of instructions with no branches in the middle — once
you start executing a basic block, you execute every instruction in
it. A function is a graph of basic blocks connected by jumps and
branches. This graph is called the **control flow graph (CFG)**.

**Call graphs** describe which functions call which other functions.
If `main()` calls `init_uart()`, and `init_uart()` calls
`write_register()`, that's a call chain three levels deep. The
complete set of these relationships forms the call graph. It tells
you how the firmware is organized — which functions are
orchestrators (calling many others) and which are leaf functions
(called by many, calling nothing).

### 2.5. MMIO and Hardware Boundaries

This is where firmware RE gets interesting and different from
reversing desktop software.

Microcontrollers talk to their peripherals through **Memory-Mapped
I/O (MMIO)**. Instead of special I/O instructions, the hardware
designer assigns specific memory addresses to peripheral registers.
When firmware writes a value to address `0x40004400`, it's not
storing data in RAM — it's sending a byte out a UART serial port.
When it reads from `0x40021000`, it's checking the status of a
clock controller.

These MMIO addresses are documented in the chip's **reference
manual** (a 1,000+ page PDF from the manufacturer). But if you're
reversing firmware for a chip you don't have the manual for, or if
the firmware drives an **opaque peripheral** (like an FPGA that the
firmware talks to via SPI but whose internal logic is unknown), then
the MMIO access patterns *in the firmware itself* become the only
documentation of the hardware interface.

ripcord captures these patterns in two ways:

1. **Static xrefs** — by analyzing which addresses the code
   references, we can see which peripheral registers each function
   touches, even without running the code.
2. **Dynamic traces** — by actually running the firmware in an
   emulator (Renode) and logging every MMIO access, we get a
   time-ordered sequence of exactly what the firmware did to the
   hardware during a specific scenario (boot, idle, active use).

### 2.6. P-Code: The Rosetta Stone

Different processor architectures use different instruction sets.
ARM Cortex-M0+ (the Raspberry Pi Pico's CPU) uses one set of
instructions; ARM Cortex-M3 uses a superset of those; RISC-V uses
something completely different. The same C function compiled for
different architectures produces different assembly code.

This is a problem for function matching. If you want to ask "is this
function in a Cortex-M0+ binary the same as that function in a
Cortex-M3 binary?", you can't just compare the assembly —
it's different by construction.

**P-Code** is Ghidra's solution. It's an intermediate representation
(IR) — a simplified, architecture-independent "language" that Ghidra
translates every architecture's instructions into. In P-Code:

- Physical registers become abstract **varnodes** (named slots).
- Complex addressing modes are broken into simple arithmetic.
- Calling conventions are abstracted away.
- The same P-Code opcodes work across ARM, x86, MIPS, RISC-V, etc.

This means that the same C function compiled for two different
architectures should produce *similar* (not identical, but similar)
P-Code. ripcord extracts P-Code features from every function and
stores them in the warehouse, enabling cross-architecture matching
that would be impossible at the assembly level.

---

## 3. The Tools We Use

### 3.1. Ghidra — The Disassembler and Decompiler

**What it is:** An open-source reverse engineering framework created
by the NSA and released publicly in 2019. It's the Swiss Army knife
of binary analysis — it disassembles, decompiles, analyzes, and
lets you script against all of it.

**What we use it for:** Everything in Stage 0 of the pipeline.
Ghidra runs in **headless mode** (no GUI, just command-line) and
processes each target binary. Our Python scripts run inside Ghidra's
environment and extract:

- Every function (address, size, name if available, parameters,
  calling convention)
- Every call relationship (who calls whom, from what address)
- Every basic block (address, size, instruction count, containing
  function)
- Every cross-reference (data reads, writes, jumps)
- Every string embedded in the binary
- P-Code features (opcode histograms and sequence hashes) for every
  function
- SHA-256 hashes of each function's raw bytes

**Why Ghidra and not IDA Pro?** IDA Pro is the commercial industry
standard and arguably more polished, but it costs thousands of
dollars and isn't open source. Ghidra is free, open-source,
scriptable in Python (via PyGhidra), and has excellent ARM Cortex-M
support. For an automated pipeline that needs to run unattended,
Ghidra's headless mode and Python API are exactly right.

**How we drive it:** Modern Ghidra (11.2+) ships with **PyGhidra**
built in. We invoke it via `pyghidraRun -H`, which launches Ghidra's
headless analyzer with a Python 3 runtime. Our extraction scripts
(one per table) run as "post-scripts" after Ghidra finishes its
auto-analysis, accessing Ghidra's full Program API from Python.

### 3.2. DuckDB and Apache Parquet — The Data Layer

**What Parquet is:** A columnar file format designed for analytics.
Think of it as a very efficient way to store tables on disk —
much more compact and faster to query than CSV or JSON, with strong
typing (integers are stored as integers, not strings).

**What DuckDB is:** An embedded analytical database engine. Think
"SQLite, but optimized for analytics instead of transactions." It
can read Parquet files directly, run SQL queries over them, and
return results — all in-process, with no server to manage.

**How we use them together:** Each pipeline run produces Parquet
files organized as `build/<target>/tables/<table_name>.parquet`.
The `scripts/query` tool auto-discovers all these files, creates
DuckDB views that union them across targets, and lets you run SQL
queries over the entire warehouse. There's no persistent database
file — the Parquet files *are* the database.

This design means:
- Adding a new target is just adding Parquet files to a new
  directory.
- Adding a new table type is just writing a new Parquet file with
  the right name.
- Every query is reproducible — same files in, same results out.
- You can use any Parquet-compatible tool (Python pandas, Polars,
  Apache Spark, even Excel) to explore the data.

### 3.3. Snakemake — The Pipeline Orchestrator

**What it is:** A workflow management system written in Python, widely
used in bioinformatics. Think of it as a smarter version of `make`:
you declare rules that say "to produce output X, run command Y on
input Z," and Snakemake figures out what needs to run, in what order,
and what can run in parallel.

**What we use it for:** Orchestrating the entire pipeline. The
`Snakefile` declares rules for:
- Running Ghidra extraction on each target
- Ingesting each JSONL output into Parquet
- Extracting ground-truth symbols (for validation)
- Running Renode scenarios and parsing traces
- Running Datalog derivations
- Computing cross-target fingerprint matches

Snakemake handles dependency tracking (don't re-extract if the
Parquet already exists), parallelism (run independent targets
simultaneously), and resource management (only one Ghidra instance
at a time, since it's memory-hungry).

**Why Snakemake and not Make/Airflow/etc.?** Snakemake's rules are
Python-native, so the configuration is a real programming language
rather than tab-sensitive makefile syntax. It handles the
multi-target, multi-table fan-out naturally, and it's proven in
scientific pipelines that care about reproducibility.

### 3.4. Renode — The Hardware Emulator

**What it is:** An open-source full-system emulator developed by
Antmicro. Unlike CPU-only emulators, Renode emulates entire
systems: CPU, memory, peripherals, buses. You give it a platform
description file (what peripherals exist at what addresses) and a
firmware binary, and it boots the firmware as if it were running on
real hardware.

**What we use it for:** Capturing **MMIO traces** — the complete
sequence of hardware register reads and writes that happen when
firmware executes a specific scenario (booting up, handling an
interrupt, processing a command). These traces are ground truth for
what the firmware actually *does* to the hardware, not just what
static analysis *thinks* it does.

**How it works in the pipeline:** A Renode "scenario" is a `.resc`
script that loads a platform definition, loads the firmware ELF,
enables execution tracing, runs for a specified duration, and saves
the trace log. The `parse_trace.py` script then extracts every
`MemoryIORead` and `MemoryIOWrite` event, identifies which
peripheral each address belongs to, and writes the results as MMIO
event rows in the warehouse.

**Example output:** A 2-second boot trace of a Zephyr hello_world
firmware produces 394 MMIO events: 214 UART writes (the "Hello
World" string being transmitted one character at a time), 154 NVIC
(interrupt controller) accesses, and a handful of GPIO and system
control register touches.

### 3.5. Souffl&eacute; — The Logic Engine

**What it is:** A high-performance Datalog engine. Datalog is a
logic programming language — you state facts and rules, and the
engine computes everything that can be derived from them. Think of
it as "SQL for recursive queries, but much more natural."

**What we use it for:** Deriving higher-level facts from the raw
warehouse data. The flagship example is **transitive call
reachability**: "Which functions can be reached from `main()` through
any chain of calls?" In SQL, this requires a recursive CTE (doable
but awkward). In Datalog, it's two lines:

```prolog
reaches(X, Y) :- calls(X, Y).
reaches(X, Z) :- reaches(X, Y), calls(Y, Z).
```

From this, we derive:
- **Reachable functions** — the 30% of functions reachable from
  `main` through direct calls.
- **Unreachable functions** — the 70% that are ISR handlers,
  callback functions, and task entry points. These are invoked by
  hardware or by function pointer, not by direct call, so they don't
  appear in the static call graph.
- **Orchestrator functions** — functions with high fan-out and deep
  transitive reach. These are the "main loops" and "task schedulers"
  that organize the firmware's behavior.
- **Subsystem clusters** — groups of functions that share many
  callees, suggesting they belong to the same logical subsystem.

### 3.6. Python — The Glue

Python 3.11+ is the scripting language for everything outside of
Ghidra's JVM. The pipeline uses it for:

- **Ghidra extraction scripts** — run inside Ghidra via PyGhidra,
  access the Ghidra API, write JSONL output.
- **Ingest scripts** — read JSONL, apply schemas, write Parquet via
  PyArrow.
- **Renode trace parsing** — read raw text traces, extract MMIO
  events.
- **Datalog fact export** — read Parquet tables, write TSV files for
  Souffl&eacute;.
- **The query tool** — set up DuckDB views and run SQL.

Dependencies are managed via `uv` (a fast Python package manager)
and declared in `pyproject.toml`. Key packages: `duckdb`, `pyarrow`,
`snakemake`, `pyghidra`.

### 3.7. Future Tools

These aren't in the pipeline yet but are planned for later phases:

- **Unicorn Engine** — a lightweight CPU emulator for per-function
  differential testing. Run a function with known inputs on the
  original binary and on a proposed replacement; diff the outputs.
  This is how we'll verify that our understanding of a function is
  correct.
- **angr** — a programmable binary analysis framework with symbolic
  execution. For the hardest functions (complex state machines,
  crypto), angr can explore all possible execution paths and
  determine what a function does mathematically.
- **LLM agents** — AI models that read function context from the
  database, propose names and contracts, and have their proposals
  verified by execution. The database is pre-enriched enough that
  agents get high-quality context without reading raw assembly.

---

## 4. The Theory Behind It All

### 4.1. Why a Database, Not Source Code?

Traditional RE aims to produce "decompiled source code" — C that
looks like what the original developer might have written. ripcord
argues this is the wrong goal for several reasons:

1. **You can't verify source code.** If a decompiler produces C that
   looks plausible, how do you know it's correct? The only way is to
   recompile it and compare — but the recompiled binary will almost
   never be byte-identical to the original due to compiler
   differences. A database of facts can be verified piecewise:
   "does this function really call these three others?" is a
   checkable claim.

2. **Source code is a lossy view.** It discards information you care
   about: exact addresses, register assignments, alignment, linking
   decisions. A database preserves everything.

3. **Source code doesn't compose.** If two analysts work on the same
   binary, merging their C files is a nightmare. Merging their
   database rows (especially with confidence scores and provenance)
   is straightforward.

4. **Machines read databases, not source.** Downstream tools —
   whether they're SQL queries, Datalog rules, or LLM agents —
   work better with structured data than with free-form text.

The database can still *render* source code as a late-stage view,
for humans who want to read C. But the source code is generated
from the database, not the other way around.

### 4.2. The "Minutes, Not Days" Constraint

A key design constraint: the deterministic pipeline (everything
before human/LLM involvement) must run end-to-end in **minutes on a
modern laptop**, not hours or days.

This matters because:
- Fast iteration means you can tweak the pipeline and see results
  immediately.
- Cheap processing means you can run it on many targets without
  worrying about cost.
- Quick onboarding means adding a new binary to the warehouse is
  trivial — no multi-day batch job.

Currently, a full pipeline run on all 8 test targets takes a few
minutes, dominated by Ghidra's auto-analysis (~30-60 seconds per
target). Everything after Ghidra (ingest, Renode traces, Datalog
derivations) runs in seconds.

### 4.3. Function Fingerprinting: Identifying Known Code

Most firmware is not novel. A typical binary contains:

- **C runtime** (newlib, picolibc) — `memcpy`, `printf`, etc.
- **RTOS kernel** (FreeRTOS, Zephyr) — task scheduling, queues,
  semaphores.
- **Vendor HAL** — hardware abstraction wrappers for the specific
  chip.
- **Third-party libraries** — USB stacks, crypto, filesystems.
- **Application code** — the actual novel logic.

If you can automatically identify the first four categories, the
analyst only needs to look at the last one. This is **function
fingerprinting**: matching functions in an unknown binary against a
library of known functions.

ripcord uses a **multi-signal approach**, cheapest signals first:

1. **Byte hash** — SHA-256 of the function's raw bytes. If two
   functions are byte-for-byte identical, they're the same function.
   This works perfectly within the same build configuration
   (same compiler, same flags, same architecture) and costs nothing.

2. **Structural signature** — an 8-tuple of (size,
   basic_block_count, instruction_count, outgoing_calls,
   distinct_callees, read_refs, write_refs, jump_refs). Functions
   with identical structural signatures are likely the same function.
   This is cheap to compute and works at ~96% precision on
   same-build pairs.

3. **P-Code histogram** — the distribution of P-Code opcodes in a
   function. Two functions with similar P-Code histograms are doing
   similar operations, even across different architectures. This is
   the path to cross-ISA matching.

4. **Constants and strings** — crypto code references magic numbers
   (`0x67452301` for MD5), protocol implementations reference string
   constants. These are highly distinctive and compiler-invariant.

5. **Call graph context** — if you know a function's neighbors, you
   can infer its identity. A function called by `main` that calls
   `xTaskCreate` is probably a FreeRTOS initialization routine.

Later phases will add **learned embeddings** (small neural networks
trained on P-Code sequences) and **LLM-based classification** for
the hardest cases.

### 4.4. Cross-ISA Matching and Why It's Hard

One of ripcord's research goals is matching functions **across
different processor architectures**. This is hard because:

- The same C function compiled for Cortex-M0+ and Cortex-M3
  produces different assembly (different instructions, different
  register usage, different code size).
- Even simple structural features (instruction count, basic block
  count) differ because the architectures encode operations
  differently.
- Exact byte hashing produces zero matches by construction.

The current empirical results confirm this: structural matching
between Pico targets (Cortex-M0+) and Zephyr targets (Cortex-M3)
finds essentially nothing useful, even for functions compiled from
the same source code.

The solution is **P-Code histogram similarity**. Because P-Code
normalizes away architectural differences, the distribution of
P-Code operations in a function should be similar across ISAs.
Computing cosine similarity between P-Code histograms is the
current research frontier.

### 4.5. Execution-Based Verification

ripcord's verification philosophy: **don't trust the compiler, trust
the execution**.

If you decompile a function, re-write it in C, and it compiles
cleanly — that tells you nothing about correctness. The compiler
checks types, not logic. A function that returns the wrong value
from a sensor register will compile just fine.

Instead, ripcord plans to verify understanding through execution:

1. **Unicorn differential testing** — run the original function and
   a proposed replacement with the same inputs; compare every
   register value, memory write, and MMIO access. If they differ,
   the proposal is wrong.

2. **Renode trace comparison** — run a complete scenario on the
   original binary and on a patched binary; compare the full MMIO
   trace. This catches integration errors that single-function
   testing misses.

3. **angr symbolic execution** — for functions where you can't
   easily generate test inputs, angr can explore all possible paths
   mathematically and verify equivalence.

This isn't implemented yet (it's Phase 7 in the roadmap), but the
MMIO traces captured in Phase 2 are the ground truth that
verification will compare against.

### 4.6. The Blackboard Architecture

When ripcord eventually adds AI agents (Phase 3+), they'll operate
on a **blackboard architecture**:

- The **warehouse** (the Parquet database) is the shared blackboard.
- **Agents** are small, focused workers that read context from the
  warehouse, propose a claim (e.g., "this function is
  `uart_send_byte`"), and write the claim back with a confidence
  score.
- **Tools** verify claims — e.g., run the function in Unicorn and
  check that it actually writes to the UART register.
- **No claim enters canonical state without verification.**

This design means agents can work in parallel on different
functions, can't corrupt each other's work (because proposals are
versioned and verified independently), and their output is auditable
(every claim has a confidence score and evidence trail).

### 4.7. Confidence and Evidence Tracking

Every claim in the warehouse carries two companion columns:

- **`confidence`** — a float from 0.0 to 1.0 indicating how
  certain the claim is.
- **`evidence_method`** — a tag describing how the claim was derived.

Calibration anchors:

| Confidence | Meaning |
|-----------|---------|
| 1.0 | Byte-identical match with name confirmation |
| 0.96 | Full structural match, names agree |
| 0.85 | Structural match, no name available |
| 0.70 | Partial structural match |
| 0.50 | Weak match, plausible but unconfirmed |
| 0.0 | Claim exists but has no evidence |

When multiple independent signals agree, confidence takes the
maximum (not the product — these aren't independent probabilities).
When signals conflict, a conflict flag is set and the evidence log
preserves both claims for human review.

---

## 5. How the Pipeline Works

### 5.1. Overview of the Stages

The pipeline is designed as a series of stages, each building on the
previous one:

```
Stage 0: Ghidra extraction → raw facts (functions, calls, blocks, xrefs, strings, P-Code)
Stage 1: Library identification → match known functions, enrich the database
Stage 2: Renode dynamic traces → MMIO event captures per scenario
Stage 3: Static trace analysis → peripheral register maps, access patterns
Stage 4: Datalog derivation → reachability, orchestrators, subsystem clusters
Stage 5: angr symbolic analysis → deep analysis of hard functions
Stage 6: Agent swarm → AI-assisted naming, contracts, understanding
Stage 7: Unicorn verification → differential testing of all claims
Stage 8: Rendered views → human-readable output (register maps, call graphs, specs)
```

Currently implemented and working: Stages 0, 1, 2, and 4.

### 5.2. Stage 0: Extraction (Ghidra)

This is the foundation. For each target binary listed in
`config.yaml`, Snakemake:

1. Runs Ghidra headless with all six extraction scripts as
   post-scripts.
2. Ghidra auto-analyzes the binary (discovers functions, resolves
   calls, identifies strings, etc.).
3. Each extraction script iterates over Ghidra's analysis results
   and writes one JSONL file (one JSON object per line).
4. The ingest step reads each JSONL file, applies a typed schema
   (from `scripts/ingest/schemas.py`), and writes a Parquet file.

The JSONL intermediate format is deliberate — it's human-readable
for debugging, trivial to parse, and keeps the extraction scripts
free of Parquet/Arrow dependencies (which can't run inside Ghidra's
JVM).

After Stage 0, the warehouse contains six tables per target:
`functions`, `calls`, `basic_blocks`, `xrefs`, `strings`, and
`pcode_features`. A seventh table, `ground_truth_functions`, is
produced by running `nm -S` on the ELF (extracting the symbol table
that the compiler left behind). This ground truth is used to validate
that Ghidra's extraction is correct, not as part of the analysis.

### 5.3. Stage 1: Library Identification

Once the raw facts are in the warehouse, Stage 1 matches functions
across targets:

1. Targets are grouped by **build tuple** — a tag like
   `m0plus-O3-newlib` that captures (ISA, optimization level, C
   library). Functions from targets with the same build tuple are
   comparable.

2. Within each build-tuple group, functions are matched by their
   structural signature and byte hash. If function A in target X
   has the same 8-tuple and the same body hash as function B in
   target Y, they're the same compiled function.

3. Matches are written back to `functions_enriched.parquet` with
   inferred names, library tags, and confidence scores.

The blind recovery test demonstrates this working: a
stripped binary (all symbol names removed) was matched against the
same binary with symbols. Result: 86.6% of functions recovered,
94.9% precision on recovered names.

### 5.4. Stage 2: Dynamic Traces (Renode)

For targets with configured scenarios, the pipeline:

1. Generates a Renode scenario script that loads the platform
   description, loads the firmware, enables execution tracing, runs
   for a specified duration, and exits.
2. Renode emulates the full system and logs every instruction
   execution and memory access.
3. `parse_trace.py` extracts `MemoryIORead` and `MemoryIOWrite`
   events, identifies peripherals by address range, and writes
   `mmio_events` rows.

The resulting table is joinable to `functions` by PC (program
counter) — you can ask "which functions wrote to UART0?" or "what's
the sequence of peripheral accesses during boot?" using SQL.

### 5.5. Stage 4: Datalog Derivation

`export_facts.py` reads the `calls` and `functions` tables and
writes them as tab-separated fact files for Souffl&eacute;.
`reachability.dl` defines the derivation rules. Souffl&eacute;
computes:

- `reaches.csv` — all (function, function) pairs connected by any
  chain of calls
- `reach_count.csv` — how many functions each function can
  transitively reach
- `orchestrators.csv` — functions with both high fan-out and deep
  transitive reach
- `unreachable_from_main.csv` — functions not reachable from `main`
  (ISR handlers, callbacks)
- `subsystem_pairs.csv` — pairs of functions that share many callees

### 5.6. Later Stages: Agents and Verification

Stages 3, 5, 6, 7, and 8 are designed but not yet implemented. They
build on the foundation of Stages 0-4:

- **Stage 3** clusters MMIO events into peripheral interactions and
  infers register maps.
- **Stage 5** uses angr for surgical symbolic analysis of specific
  hard functions.
- **Stage 6** introduces AI agent workers that read enriched context
  from the warehouse and propose function names, types, and
  behavioral contracts.
- **Stage 7** verifies agent proposals by running functions in
  Unicorn and comparing against the original.
- **Stage 8** renders human-readable output: register maps, annotated
  call graphs, feature specifications.

---

## 6. The Warehouse: What's in the Database

### 6.1. Table Overview

| Table | Grain | What it captures |
|-------|-------|------------------|
| `functions` | One row per function | Address, name, size, parameters, calling convention, basic block count, body hash |
| `calls` | One row per call site | Caller, callee, call site address, ref type, computed/conditional flags |
| `basic_blocks` | One row per code block | Address, size, instruction count, containing function |
| `xrefs` | One row per non-call reference | Source, target, ref type (data read, write, jump, etc.) |
| `strings` | One row per defined string | Address, value, length, data type |
| `pcode_features` | One row per function | P-Code opcode histogram, sequence hash, total ops, unique opcodes |
| `mmio_events` | One row per MMIO access | PC, peripheral address, value, direction (read/write), peripheral name |
| `ground_truth_functions` | One row per nm symbol | Address, name, size, type — used for validation only |
| `functions_enriched` | One row per function | Same as functions plus inferred name, library, confidence, evidence |
| `recovered_calls` | One row per recovered edge | Caller, callee, mechanism (vector table, func pointer, veneer), confidence |

Every table has a `source` column identifying which target the row
belongs to, so cross-target queries are natural joins.

### 6.2. Querying the Warehouse

The `scripts/query` tool is the primary interface:

```bash
# Run a SQL query
scripts/query "SELECT source, COUNT(*) FROM functions GROUP BY source"

# List all available tables
scripts/query

# Run a query from a file
scripts/query < notes/queries/coverage.sql

# Drop into an interactive REPL
scripts/query --repl
```

Under the hood, `scripts/query` discovers all Parquet files under
`build/*/tables/`, creates a DuckDB view per table name (unioning
across targets), and runs your SQL against those views.

### 6.3. Example Queries

**How many functions does each target have?**
```sql
SELECT source, COUNT(*) AS num_functions
FROM functions
GROUP BY source
ORDER BY num_functions DESC;
```

**What are the largest functions in a specific target?**
```sql
SELECT name, size, basic_block_count
FROM functions
WHERE source = 'pico_freertos_hello'
ORDER BY size DESC
LIMIT 10;
```

**Which functions write to UART registers?**
```sql
SELECT DISTINCT f.name, f.source
FROM mmio_events m
JOIN functions f
  ON m.source = f.source
  AND m.pc BETWEEN f.addr AND f.addr + f.size
WHERE m.peripheral = 'UART0'
  AND m.direction = 'write';
```

**Which functions are unreachable from main?** (using the Datalog
derivation output — or you can use a recursive CTE directly)
```sql
SELECT f.name, f.size
FROM functions f
LEFT JOIN calls c ON f.source = c.source AND f.addr = c.callee_addr
WHERE f.source = 'pico_freertos_hello'
  AND f.name NOT IN (
    SELECT DISTINCT callee FROM reaches
    WHERE caller = 'main'
  );
```

The `notes/queries/` directory contains many more examples that
serve as both documentation and regression tests.

---

## 7. Where We Are Now

### 7.1. What's Been Proven

As of April 2026, the following pipeline stages work end-to-end:

- **Stage 0 (Ghidra extraction)** is complete and validated against
  ground truth on both ISAs. Ghidra's function recovery is more
  accurate than `nm` symbols (it finds functions the linker strips).

- **Stage 1 (Library ID)** is validated with blind recovery on a
  stripped binary: 86.6% recall, 94.9% precision. Cross-target
  matching works at 96% precision within the same build
  configuration.

- **Stage 2 (Renode traces)** is proven standalone. A Zephyr
  hello_world boot trace produces 394 MMIO events in 2 seconds.
  The traces are in the warehouse and joinable to functions.

- **Stage 4 (Datalog derivation)** is proven standalone. Transitive
  reachability, orchestrator detection, and subsystem clustering
  all produce meaningful results. Key finding: 70% of functions
  are unreachable from `main`, which tells us exactly where
  function-pointer and ISR recovery needs to focus.

### 7.2. Current Targets

The warehouse contains 12 targets across two processor architectures
and two build ecosystems:

| Target | Architecture | Description |
|--------|-------------|-------------|
| `pico_blinky` | Cortex-M0+ | Simplest possible Pico SDK example |
| `pico_hello_timer` | Cortex-M0+ | Timer example |
| `pico_hello_usb` | Cortex-M0+ | USB CDC example with TinyUSB |
| `pico_freertos_hello` | Cortex-M0+ | FreeRTOS task example |
| `pico_freertos_static` | Cortex-M0+ | FreeRTOS with static allocation |
| `pico_freertos_hello_stripped` | Cortex-M0+ | Stripped (no symbols) — blind recovery test |
| `zephyr_hello_world` | Cortex-M3 | Minimal Zephyr application |
| `zephyr_synchronization` | Cortex-M3 | Zephyr threading/semaphores |
| `stock_v103` through `stock_v120` | Cortex-M4 | FNIRSI 2C53T oscilloscope firmware (4 versions) |

The Pico and Zephyr targets are open-source with full ground truth
(we can check our work against the source code). The stock firmware
targets are real-world proprietary firmware — no source code, no
symbols.

### 7.3. Key Empirical Results

1. **Same-build matching works at 96% precision.** Structural
   fingerprinting between Zephyr targets (same build configuration)
   correctly identifies 72 of 75 cross-target function clusters.

2. **Blind recovery works at 86.6% recall, 94.9% precision.** A
   stripped binary matched against its non-stripped counterpart
   recovers function names for 171 of 197 functions, with only 9
   false positives (all structural twins — functions that look
   identical but have different names).

3. **Cross-ISA matching fails with simple features, but P-Code is
   the path forward.** Exact P-Code sequence hashing fails across
   architectures (Cortex-M0+ vs M3) but works within ISA at 93-94%
   precision. P-Code histogram cosine similarity is the next test.

4. **70% of functions are unreachable from main.** This is normal
   for RTOS firmware — the unreachable set is ISR handlers, task
   entry points, and callbacks invoked through function pointers.
   Recovering these edges is a high-value next step.

5. **Byte hashing resolves all structural twins.** Functions with
   identical structural signatures but different byte content (the
   only source of false positives) are disambiguated perfectly by
   SHA-256 body hashes.

---

## 8. Where We're Going

### 8.1. Near Term: Cross-ISA Matching

The highest-leverage next step is **P-Code histogram cosine
similarity** for cross-ISA function matching. We already extract
P-Code opcode histograms for every function. The experiment:
compute cosine similarity between histograms of Pico functions
(Cortex-M0+) and Zephyr functions (Cortex-M3) that we know are
compiled from the same source code. If cosine similarity
discriminates well, we have a cross-ISA matching signal. If it
doesn't, we'll need learned embeddings (Phase 3).

Also near term:
- **Snakemake integration** for Renode and Datalog (done — both are
  now pipeline stages).
- **Function-pointer recovery** — recovering the call edges that
  Ghidra's standard analysis misses (ISR vector tables, `xTaskCreate`
  arguments, callback registrations).

### 8.2. Medium Term: Agent Swarms

Once the warehouse is rich enough (all deterministic stages running),
Phase 3 introduces **LLM agent workers**:

- A **task queue** defines units of work: "name function at
  0x10001234", "propose a contract for this function", "classify
  this function's purpose."
- **Context assembly** pulls relevant facts from the warehouse for
  each task: the function's code, its callers and callees, MMIO
  accesses, P-Code features, any existing matches.
- **Worker agents** (small, focused LLM calls) read the context and
  produce structured proposals.
- **Validation** checks proposals against execution (Unicorn) or
  consistency (does the proposed name match the call graph context?).

The blackboard architecture means agents don't need to understand
the whole binary — they work on one function at a time with curated
context, and their proposals are verified independently.

### 8.3. Long Term: Learned Embeddings and Public Corpus

The long-term research direction is training a **P-Code embedding
model** — a small neural network that converts a function's P-Code
sequence into a vector, such that similar functions (same source
code, different compilers/architectures) produce similar vectors.

What makes this unusually tractable: **labels are free**. Every
open-source firmware binary compiled from known source code provides
ground-truth labels for every function. The same CI infrastructure
that builds test targets also generates training data. ripcord's
labeled corpus of embedded firmware functions would be a novel
public contribution — no such dataset exists today.

The model progression:
1. Rules (current — working)
2. Hand-crafted features + gradient-boosted decision trees
3. Small P-Code embedding model on Apple Silicon
4. Multi-modal model (P-Code + CFG + constants + MMIO profiles)

Each phase is independently useful. You can stop at any phase and
still have a working pipeline.

### 8.4. The Endgame

The fully realized pipeline takes a bare firmware binary and, in
minutes to hours, produces:

1. A complete function-level map with 80-95% of functions identified
   by name and library.
2. A peripheral register map derived from MMIO traces.
3. Behavioral contracts for every function (what it reads, writes,
   calls, and under what conditions).
4. Human-readable rendered views: annotated call graphs, register
   interaction diagrams, feature specifications.
5. Optionally, replacement source code verified by differential
   testing against the original.

The goal is that a developer looking at an unknown firmware binary
gets, in one pipeline run, roughly the same understanding that
would take an expert analyst weeks of manual work. The
deterministic pipeline handles the 80% that's automatable; agents
handle the 15% that's hard but tractable; and the human focuses on
the 5% that's genuinely novel.

---

## 9. Setting Up and Running It Yourself

### 9.1. Prerequisites

You need:
- **macOS or Linux** (macOS is the primary development platform)
- **Java 21+** (for Ghidra)
- **Python 3.11+**
- About **4 GB of disk space** for Ghidra and dependencies
- An **ARM cross-compiler** if you want to build test targets from
  source (otherwise you can supply any ELF binary)

### 9.2. Install the Tools

```bash
# 1. Install Ghidra (includes JDK 21 as a dependency)
brew install ghidra

# 2. Install uv (fast Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Clone the repo and install Python dependencies
git clone <repo-url> ripcord
cd ripcord
uv sync    # creates .venv/ with all dependencies

# 4. Set environment variables (add to ~/.zshrc for persistence)
export GHIDRA_PYGHIDRA=/opt/homebrew/opt/ghidra/libexec/support/pyghidraRun
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home

# 5. Verify
$GHIDRA_PYGHIDRA -H 2>&1 | tail -3    # should print Ghidra version info
uv run python -c "import duckdb, pyarrow; print('ok')"
snakemake --version
```

### 9.3. Build a Test Target

The simplest target to start with is the Raspberry Pi Pico blinky
example. See `targets/README.md` for detailed build instructions.
The short version:

```bash
# Install ARM cross-compiler
brew install --cask gcc-arm-embedded

# Get the Pico SDK
git clone https://github.com/raspberrypi/pico-sdk ~/pico-sdk
cd ~/pico-sdk && git submodule update --init && cd -
export PICO_SDK_PATH=~/pico-sdk

# Build blinky
mkdir -p targets/pico_blinky/build && cd targets/pico_blinky/build
cmake -DPICO_BOARD=pico .. && make -j4
cp blink.elf ../
cd ../../..
```

Or, if you have any ELF binary you want to analyze, just drop it
under `targets/<name>/` and add an entry to `config.yaml`:

```yaml
targets:
  my_target:
    elf: targets/my_target/firmware.elf
    description: "My firmware binary"
    arch: arm
    build_tuple: m4-gcc-O2   # or whatever matches your build
```

### 9.4. Run the Pipeline

```bash
# Full pipeline run
snakemake --cores 4 --resources ghidra=1

# Dry run (show what would execute without running anything)
snakemake --cores 4 --resources ghidra=1 -n

# Run only for a specific target
snakemake --cores 4 --resources ghidra=1 build/pico_blinky/tables/functions.parquet
```

The `--resources ghidra=1` flag limits Ghidra to one instance at a
time (it's memory-hungry). Other stages run in parallel.

### 9.5. Explore the Results

```bash
# List all tables in the warehouse
scripts/query

# Count functions per target
scripts/query "SELECT source, COUNT(*) AS n FROM functions GROUP BY source ORDER BY n DESC"

# Look at the biggest functions
scripts/query "SELECT source, name, size FROM functions ORDER BY size DESC LIMIT 20"

# Interactive REPL (requires duckdb CLI)
scripts/query --repl

# Run a committed query file
scripts/query < notes/queries/coverage.sql
```

---

## 10. Repository Layout

```
ripcord/
├── CLAUDE.md              # Project orientation (for Claude Code sessions)
├── README.md              # Human-facing project overview
├── SETUP.md               # Detailed installation instructions
├── Snakefile              # Pipeline definition (all the rules)
├── config.yaml            # Target binary list and configuration
├── docs/
│   └── getting-started.md # This file
├── notes/                 # Design notes (authoritative documentation)
│   ├── PLAN.md            # Phased roadmap with status markers
│   ├── design-decisions.md # Why we chose what we chose
│   ├── fingerprinting-baseline.md  # Empirical matching results
│   ├── datalog-baseline.md         # Call graph analysis results
│   ├── renode-setup.md             # Hardware emulation setup
│   ├── ghidra-extraction-notes.md  # Extraction accuracy analysis
│   ├── goal-and-approach.md        # Why a database, not source code
│   ├── pipeline-architecture.md    # Full pipeline design
│   ├── tooling.md                  # Tool reference sheet
│   └── queries/           # Committed SQL files (executable docs)
│       ├── coverage.sql
│       ├── cross_target.sql
│       ├── reachability.sql
│       └── ...
├── scripts/
│   ├── query              # SQL query tool over the Parquet warehouse
│   ├── ghidra/            # Extraction scripts (run inside Ghidra)
│   │   ├── export_functions.py
│   │   ├── export_calls.py
│   │   ├── export_basic_blocks.py
│   │   ├── export_xrefs.py
│   │   ├── export_strings.py
│   │   └── export_pcode.py
│   ├── ingest/            # JSONL-to-Parquet loaders and schemas
│   │   ├── schemas.py     # Single source of truth for table schemas
│   │   ├── load_table.py  # Generic JSONL → Parquet loader
│   │   └── load_ground_truth.py
│   ├── renode/            # Renode platform files and trace parsers
│   └── datalog/           # Soufflé rules and fact exporters
├── targets/               # Test binaries (gitignored, not in repo)
└── build/                 # Pipeline outputs (gitignored)
    └── <target>/
        ├── tables/        # Parquet files (the warehouse)
        ├── traces/        # Renode execution traces
        ├── datalog/       # Soufflé derived facts
        └── ghidra_project/ # Ghidra's analysis database
```

---

## 11. Glossary

| Term | Definition |
|------|-----------|
| **Basic block** | A sequence of instructions with no branches in the middle. The smallest unit of control flow. |
| **Blackboard architecture** | A design pattern where multiple agents share a common data store (the "blackboard") and operate on it independently. |
| **Body hash** | SHA-256 hash of a function's raw bytes. Two functions with the same body hash are byte-for-byte identical. |
| **Build tuple** | A tag like `m0plus-O3-newlib` that captures the ISA, optimization level, and C library. Functions are only comparable within the same build tuple (for structural matching). |
| **Call graph** | A directed graph where nodes are functions and edges are call relationships. |
| **CFG (Control Flow Graph)** | A directed graph where nodes are basic blocks and edges are jumps/branches within a single function. |
| **Confidence** | A 0.0–1.0 float attached to every claim in the warehouse, calibrated against known anchors. |
| **Cortex-M** | ARM's family of microcontroller CPUs. M0/M0+ are the simplest (ARMv6-M), M3/M4/M7 are progressively more capable (ARMv7-M). |
| **Cross-ISA** | Across different instruction set architectures (e.g., comparing Cortex-M0+ code against Cortex-M3 code). |
| **Datalog** | A logic programming language for expressing recursive queries over facts. Used via Soufflé. |
| **DuckDB** | An embedded analytical SQL database engine. Reads Parquet files directly. |
| **ELF** | Executable and Linkable Format — the standard binary format for compiled programs on Linux/embedded. |
| **Evidence method** | A tag describing how a claim was derived (e.g., `body_hash_exact`, `structural_8tuple`, `agent_proposal_verified`). |
| **Fingerprinting** | Identifying a function by matching its features against a library of known functions. |
| **FreeRTOS** | A popular real-time operating system for microcontrollers. Provides task scheduling, queues, semaphores, etc. |
| **Ghidra** | NSA's open-source reverse engineering framework. Disassembles, decompiles, and provides a scriptable analysis API. |
| **HAL** | Hardware Abstraction Layer — vendor-provided wrapper functions for chip peripherals. |
| **ISA** | Instruction Set Architecture — the set of machine instructions a CPU understands. |
| **ISR** | Interrupt Service Routine — a function invoked by hardware when an interrupt fires. Not called by normal code. |
| **JSONL** | JSON Lines — one JSON object per line. Used as the intermediate format between Ghidra extraction and Parquet ingest. |
| **MMIO** | Memory-Mapped I/O — hardware peripheral registers accessed as memory addresses. |
| **nm** | A command-line tool that lists symbols from an ELF file. Used for ground-truth validation. |
| **Orchestrator** | A function with high fan-out that calls many other functions, organizing a subsystem's behavior. |
| **P-Code** | Ghidra's intermediate representation. Architecture-independent, uses abstract varnodes instead of physical registers. |
| **Parquet** | Apache Parquet — a columnar storage format optimized for analytics. |
| **Pipeline** | The sequence of automated stages that transforms a raw binary into a populated warehouse. |
| **PyGhidra** | Python 3 bridge into Ghidra's JVM. Lets Python scripts access the full Ghidra API. |
| **Renode** | An open-source full-system hardware emulator by Antmicro. |
| **RTOS** | Real-Time Operating System — a lightweight OS for embedded systems (FreeRTOS, Zephyr, etc.). |
| **Snakemake** | A Python-based workflow management system for reproducible pipelines. |
| **Soufflé** | A high-performance Datalog engine used for the derivation layer. |
| **Structural signature** | An 8-tuple of function features (size, block count, instruction count, etc.) used for matching. |
| **Unicorn** | A lightweight CPU emulator for differential testing. |
| **Varnode** | P-Code's abstraction for a data location (register, memory, temporary). |
| **Warehouse** | The tree of Parquet files under `build/` — ripcord's primary output. |
| **Xref** | Cross-reference — a reference from one address to another (data read, write, jump, call). |
| **Zephyr** | An open-source RTOS from the Linux Foundation, used as a test target. |
