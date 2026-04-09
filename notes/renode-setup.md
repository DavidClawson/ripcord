# Renode Setup and First Trace Capture

## Status: Working (2026-04-08)

Renode boots the `zephyr_hello_world` target successfully and produces
usable MMIO traces via execution tracing with memory access tracking.

## Installation

Renode v1.16.1 is installed at `/Applications/Renode.app`.

The binary is at `/Applications/Renode.app/Contents/MacOS/renode`.
It is not in `$PATH`; invoke it with the full path or add a symlink.

## Platform file

Renode does not ship an LM3S6965 platform file. A custom one lives at
`scripts/renode/lm3s6965.repl` with:

- Cortex-M3 CPU
- 256KB flash at 0x00000000
- 64KB SRAM at 0x20000000
- NVIC at 0xE000E000 (systick at 50 MHz)
- UART0 (PL011) at 0x4000C000 -> IRQ 5
- UART1 (PL011) at 0x4000D000 -> IRQ 6
- UART2 (PL011) at 0x4001C000 -> IRQ 33

This is sufficient for the Zephyr hello_world target. The Stellaris
GPIO port (0x4000E000) and System Control (0x400FE000) are not
modeled — firmware accesses to them produce warnings but execution
proceeds correctly.

## Running the scenario

```bash
# From repo root:
/Applications/Renode.app/Contents/MacOS/renode --disable-xwt --console \
    scripts/renode/zephyr_hello_boot.resc
```

This:
1. Creates the LM3S6965 machine
2. Loads `targets/zephyr_hello_world/zephyr.elf`
3. Enables execution tracing with memory access tracking
4. Runs for 2 virtual seconds
5. Produces two output files and quits

Output on UART0:
```
*** Booting Zephyr OS build v4.4.0-rc2-41-g149c8b1758a8 ***
Hello World! qemu_cortex_m3/ti_lm3s6965
```

## Output files

### `build/renode_hello_boot.log` — Session log

Renode's own log output. Contains:
- Machine setup info
- Warnings for accesses to unmapped peripherals (with PC and value)
- UART output lines with host/virtual timestamps

### `build/renode_exec_trace.log` — Execution trace (primary data source)

Per-instruction trace with interleaved memory access events.

**Format** (text, one event per line):

```
0x5A4: 0x480A                                          ← instruction at PC 0x5A4
MemoryRead with address 0x5D0, value 0x20001000        ← memory read issued by preceding instruction
0x5A6: 0xF3808808                                      ← next instruction
...
MemoryIORead with address 0x4000C018, value 0x90       ← MMIO read (peripheral register)
0x1B96: 0x0612
0x1B98: 0xD5FC
0x1B9A: 0x6019
MemoryIOWrite with address 0x4000C000, value 0x2A      ← MMIO write (UART TX data register)
```

**Event types:**

| Type             | Meaning                                     | Count (2s boot) |
|------------------|---------------------------------------------|-----------------|
| `0xNNN: 0xOPCODE` | Instruction executed at PC                | 10,562          |
| `MemoryRead`     | Load from RAM/flash                         | 2,332           |
| `MemoryWrite`    | Store to RAM/flash                          | 1,741           |
| `MemoryIORead`   | Read from peripheral register               | 192             |
| `MemoryIOWrite`  | Write to peripheral register                | 202             |

**Total MMIO events: 394 in 2 seconds of execution.**

**Peripheral breakdown (MMIO only):**

| Address range   | Peripheral        | Events |
|-----------------|-------------------|--------|
| 0x4000C000-FFF  | UART0 (PL011)     | 214    |
| 0xE000E000-FFF  | NVIC              | 154    |
| 0x4000E000-FFF  | GPIO (unmapped)   | 10     |
| 0x4000D000-FFF  | UART1 (PL011)     | 10     |
| 0x400FE000-FFF  | SysCtl (unmapped) | 6      |

**Key observation:** MMIO events can be correlated to the issuing
instruction because the `MemoryIORead/Write` line always immediately
follows the instruction line that caused it. The preceding `0xNNN:`
line gives you the PC.

## Trace format → Renode execution trace is also available in binary

The text format used here (`PCAndOpcode`) is human-readable but
would need parsing for ingest. Renode also supports binary trace
output formats. For the pipeline, the text format is fine for
prototyping; binary format is worth exploring if trace volume grows
past millions of events.

## Proposed mmio_events table schema

Based on the actual trace output, the MMIO event table should be:

```
mmio_events(
    source          TEXT,      -- target name, e.g. 'zephyr_hello_world'
    scenario_id     TEXT,      -- scenario name, e.g. 'boot'
    sequence_idx    INT64,     -- global ordering within trace
    pc              INT64,     -- program counter of issuing instruction (hex address)
    address         INT64,     -- peripheral register address
    value           INT64,     -- value read or written
    direction       TEXT,      -- 'read' or 'write'
    width           INT32,     -- access width in bytes (4 for DoubleWord, 2, 1)
    peripheral      TEXT       -- inferred peripheral name (e.g. 'uart0', 'nvic', or NULL)
)
```

**Grain:** one row per MemoryIORead or MemoryIOWrite event.

**Derivable columns (not stored, computed at query time):**
- `function_name` — join on `functions` table where `pc BETWEEN addr AND addr+size`
- `register_offset` — `address - peripheral_base`

**Volume estimate:** ~200 MMIO events per second of idle Zephyr boot.
A complex scenario with active I/O might produce 1K-10K events/second.
Even at 10K events/sec for 60 seconds, that's 600K rows — trivially
small for Parquet/DuckDB.

## What's needed to turn this into a pipeline stage

1. **Parse script** (`scripts/renode/parse_trace.py`): Read the
   execution trace log, extract MemoryIO events with their preceding
   PC, emit JSONL in the standard ingest format.

2. **Schema entry** in `scripts/ingest/schemas.py`: Add `mmio_events`
   schema matching the table above.

3. **Snakefile rule**: `ingest_mmio_events` that depends on the trace
   log file and produces `build/<target>/tables/mmio_events.parquet`.

4. **Scenario management**: The `.resc` file is per-(target, scenario).
   Need a convention for naming and a config entry for scenarios per
   target.

5. **Unmapped peripheral coverage**: Adding stub `MappedMemory` regions
   for GPIO (0x4000E000) and SysCtl (0x400FE000) would capture those
   accesses as MemoryIORead/Write instead of just warnings in the log.
   Low priority but worth doing for completeness.

## Tracing API notes

- `cpu.EnableExecutionTracing` does **not** exist in Renode v1.16.1.
- `cpu.CreateExecutionTracing "name" path PCAndOpcode` works. It
  creates a named tracer object.
- `tracer.TrackMemoryAccesses` enables MemoryRead/Write/MemoryIORead/
  MemoryIOWrite interleaved with instruction trace.
- `--disable-xwt` runs headless (no GUI). Required for automation.
- `--console` keeps output on the terminal instead of a separate
  console window.
- `emulation RunFor "H:M:S"` runs for virtual time, not wall time.
  Do **not** call `start` before `emulation RunFor` — it will error
  with "emulation is already started."
