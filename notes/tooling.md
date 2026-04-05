# Tooling Reference

Every tool discussed in design, what it does, and when to reach for it.

## Static analysis

### Ghidra

NSA's open-source reverse engineering framework. The backbone of the
pipeline's static extraction.

- **Headless mode** is how you run it from a script or CI. No GUI,
  no clicking, deterministic. This project uses `pyghidraRun -H`
  (which is `analyzeHeadless` launched under Ghidra's native
  PyGhidra Python 3 runtime) rather than plain `analyzeHeadless`,
  so `.py` postScripts can import the venv's packages. See
  `design-decisions.md` §D17 and `SETUP.md` for the full launcher
  setup including the `JAVA_HOME` requirement.
- **P-Code** is Ghidra's intermediate representation — a normalized,
  architecture-independent form lower-level than decompiled C but more
  structured than raw assembly. The natural unit for agent tasks.
- **HighFunction IR** is the refined post-decompilation form, with recovered
  types and variable scopes. Probably more useful to export than raw
  P-Code for agent consumption.
- **Program API** gives access to functions, basic blocks, call graph,
  xrefs, strings — everything you'd want for extraction.

### PyGhidra (ships with Ghidra 11.2+)

Ghidra's native CPython 3 scripting bridge. In 11.2+ it replaces
both the ancient bundled Jython 2 and the older third-party
Ghidrathon extension — Ghidra's built-in `PyGhidraScriptProvider`
claims `.py` files at the JVM level, so any Python script run via
`pyghidraRun -H` (analyzeHeadless under PyGhidra) gets a real
Python 3 runtime with access to the project venv. Install with
`pip install pyghidra`; no Ghidra extension to manage. See
`design-decisions.md` §D17 for the migration away from Ghidrathon.

### BinExport

A protobuf format for binary analysis data, originally from Zynamics (now
Google), used by BinDiff. If you ever want interoperability with other
analyzers (IDA, BinDiff, Binary Ninja), exporting to BinExport alongside
your own format is cheap insurance. Not required for v1.

### FLIRT signatures / Lumina / BinDiff

Techniques for identifying library functions in a binary by matching
byte/structure patterns against known libraries. Critical for Stage 1
(library identification). FLIRT is IDA's format; Ghidra has its own
equivalent (function ID databases). BinDiff compares two binaries
structurally — useful when you have the AT32 SDK compiled separately and
want to find matches in the firmware.

## Dynamic analysis / emulation

### Renode

Full-system emulator from Antmicro. Models whole boards — CPU, memory,
peripherals, interrupts, timers, DMA — not just the CPU. The right tool
for whole-firmware execution and trace capture.

- **Platform file (`.repl`)** describes the board: CPU, memory map,
  peripherals. You'll port an STM32F4 platform file to AT32F403A and
  patch for the known divergences.
- **Bus logging** can be enabled on any memory region — one line to turn
  on full MMIO trace capture for the FPGA address range.
- **Scenario scripting** via Monitor commands, Python, or Robot Framework.
  Drive the firmware through specific sequences to generate per-feature
  traces.
- **Custom peripherals** can be written in C# or Python. For the FPGA,
  write a peripheral model that logs every access and optionally replays
  recorded values in response to reads — a "ghost FPGA."
- **Deterministic replay** — runs are reproducible, which matters for
  differential testing.
- **Co-simulation with Verilator** — if you ever get HDL for the FPGA,
  Renode can simulate it alongside. Probably not relevant here.

Use for: Stage 2 (whole-firmware trace capture), integration testing of
replacement firmware.

### Unicorn Engine

Just the CPU instruction emulator ripped out of QEMU, with no peripherals.
You provide the memory map and hooks in Python.

- **Fast** — boots in milliseconds, per-function tests take microseconds.
- **Hermetic** — no peripherals, no interrupts, no clocks. Exactly what
  you want for per-function isolation testing.
- **Trivially parallel** — each test is self-contained, spin up thousands
  across CPU cores.
- **Used under the hood by angr** for concrete execution.

Use for: Stage 7 (per-function differential testing of agent-proposed
lifts). Not for whole-firmware work — too much ceremony and no peripherals.

### Renode vs Unicorn

They are different tools for different jobs. Renode is a house; Unicorn is
a lathe. You want both, eventually. Renode for realistic whole-firmware
scenarios; Unicorn for microscopic per-function verification at scale.

## Formal analysis

### angr

Python framework for binary analysis. Three main capabilities:

1. **Programmable CFG recovery and disassembly** — like Ghidra but
   scriptable from Python.
2. **Symbolic execution** — the headline feature. Run code with *symbolic*
   variables instead of concrete values; track constraints as execution
   proceeds; ask questions like "what input causes this write?" or "is
   this branch ever taken?" and get answers from a constraint solver (Z3).
3. **Programmatic access to analysis results** — everything is a Python
   object you can query and extend.

Pain points for bare-metal ARM firmware: angr was built primarily for
Linux binaries, so you need to set up the memory map, load address, and
stub out hardware registers manually. 50-150 lines of Python of harness
code.

Use for: Stage 5 (surgical precondition extraction on specific functions
where static analysis is ambiguous). Not a first-pass tool.

### Triton, BAP, Manticore

Alternatives to angr in the same space. Triton (Quarkslab) is narrower but
excellent for specific queries. BAP (CMU, OCaml-based) is the academic
reference with a Datalog-like query interface. Manticore (Trail of Bits)
is another Python symbolic execution framework. Pick angr first unless you
hit a wall it can't handle.

### Soufflé (Datalog engine)

Production-grade Datalog implementation, used by academic static analyzers
(Doop for Java, parts of the Rust/Scala analysis ecosystems).

- Declare base facts and rules; the engine computes derived facts to
  fixpoint.
- Extremely fast on millions of facts.
- Natural fit for recursive queries over call graphs and data-flow
  relationships.
- Output back into SQL tables, Parquet, or text.

Use for: Stage 4 (derivation layer). Recursive queries that are painful in
SQL become one-liners in Datalog.

## Data layer

### SQLite

The coordination layer's database. Use for: tasks, leases, contracts,
evidence log, type proposals. Small writes, high-frequency transactions,
strong ACID guarantees. The right tool for coordination.

### DuckDB

Analytical embedded database in the same "single-file, no server" spirit
as SQLite, but columnar and optimized for read-heavy analytical queries.

- **10-100x faster than SQLite** for analytical workloads (joins, group
  bys, recursive CTEs).
- **Reads Parquet directly** — you can query a Parquet file without
  importing it first.
- **Excellent recursive CTEs** — supports some of the Datalog-style
  queries without needing Soufflé for simple cases.
- **Arrow-native** — interoperates with Python/Polars/Pandas efficiently.

Use for: the analytical layer. P-Code instructions, MMIO events, register
accesses, derived facts. Anything with millions of rows that you query
analytically.

### Parquet

Columnar, compressed, typed file format. Lingua franca of modern data
tooling.

Use for: intermediate artifacts between pipeline stages. Ghidra exports,
Renode traces, angr output. Inspectable, versionable, and much faster to
process than JSON.

## Orchestration

### Snakemake

Python-embedded workflow engine from the bioinformatics world.

- Rules declare `input → output` relationships.
- Figures out the DAG automatically.
- Parallelizes independent steps.
- Skips up-to-date outputs (content-hash based).
- Integrates cleanly with Python for conditional logic.

Use for: Layer 1 orchestration — the static extraction pipeline (Ghidra
export → DB ingest → library identification → trace capture → fact
derivation). File-based DAGs are its native habitat.

### Blackboard loop (homegrown, ~200 lines Python)

Not a library — a pattern. A long-running worker script that polls
SQLite for pending tasks, claims them with leases, runs them, posts
results. Use for Layer 2: the iterative agent-swarm analysis stages,
which are not file-based DAGs but message-passing loops.

### Make / Dagster / Prefect / Nextflow

Alternatives to Snakemake. Make is simpler but bad at dynamic DAGs.
Dagster and Prefect are heavier modern data orchestrators with web UIs;
overkill for v1 but worth knowing for later if you want observability
across hundreds of parallel tasks. Nextflow is similar to Snakemake,
larger in the bio world.

## LLM integration

Not a specific tool — a pattern. The agent swarm calls an LLM API (via
the Claude API, OpenAI API, a local model, or whatever) with structured
context pulled from the DB. Design principles:

- **Small context per call** — one function, its neighbor contracts,
  relevant trace evidence. Never the whole binary.
- **Structured output** — agents return JSON matching a schema, not
  free-form text. Parse-fail = reject.
- **Confidence scores required** — every claim carries a number.
- **Verification is separate** — LLM output is a proposal, not a fact,
  until a tool verifies it.
- **Traceable** — every claim in the DB points at the specific agent
  invocation, the prompt used, and the model that produced it.

## Visualization / inspection

Not strictly needed for v1, but worth knowing about:

- **Binary Ninja** — commercial decompiler with good scripting. Some
  folks prefer it to Ghidra. Not open source but has free tiers.
- **Cutter** — free GUI over Radare2.
- **objdiff / asm-differ** — tools from the decomp community for
  comparing assembly outputs. Useful for the Unicorn differential
  verification step when you want a human-readable diff of what
  changed.
- **Graphviz / D3** for call graph and data flow visualization from the
  DB.

## What to install first

For bootstrapping Stage 0 + Stage 2:

1. Ghidra (includes PyGhidra natively in 11.2+) + `pip install pyghidra`
2. Renode (you already have it from the other project)
3. Python 3.11+ with: `duckdb`, `sqlite3` (stdlib), `pyarrow`, `polars`,
   `snakemake`, `unicorn`, eventually `angr`
4. Soufflé for the Datalog derivation layer (later, not day 1)
5. `arm-none-eabi-gcc` toolchain for compiling FreeRTOS and the AT32 SDK
   for library identification
