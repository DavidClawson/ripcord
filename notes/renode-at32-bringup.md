# Renode AT32F403A bring-up: the FNIRSI FPGA emulation oracle

**Status:** scaffolded 2026-05-29. First boot not yet run. This is the
execution oracle for the MCU↔FPGA boundary — the #1 next move in
`CLAUDE.md`.

## Why this exists

`notes/scope_acquisition_spec.md` is a *static* reconstruction of the
MCU↔FPGA protocol (xref analysis + decompiled C, seeded from the
OpenScope `fpga.c`). It is a hypothesis with no execution oracle.
ripcord's thesis is that no claim is canonical until execution-verified,
and the opaque Gowin FPGA is only knowable through how the AT32F403A
firmware talks to it. So: boot the real firmware against an instrumented
software FPGA and capture the transcript.

**Deliverable.** Not the FPGA's internal logic — the *boundary contract*,
complete enough that the firmware runs to full acquisition against the
model with no divergence from a real-hardware trace. That is a
falsifiable definition of done. When `fpga_protocol.py` is complete, it
**is** the reverse-engineered FPGA interface spec, expressed as runnable
code.

## The pieces

| file | role |
|------|------|
| `scripts/renode/at32f403a.repl` | platform: Cortex-M4F + STM32F1-compatible memory map; RCC/Flash ready-stubs; SPI3/USART2 instrumented stubs |
| `scripts/renode/fpga_protocol.py` | the executable FPGA model (the growing spec). Standalone-testable: `uv run python scripts/renode/fpga_protocol.py` |
| `scripts/renode/stock_v120_boot.resc` | boot scenario: loads the raw image at 0x08004000, boots from its vector table, traces, runs 5s |
| `scripts/renode/parse_trace.py` | trace → `mmio_events` JSONL (`--platform at32f403a`) |

Key platform facts (from `scope_acquisition_spec.md`, V1.2.0):
- **Cortex-M4F** — FPU on; the FreeRTOS port calls `vPortEnableVFP`,
  which faults on a plain M4.
- App base **0x08004000** (a bootloader occupies 0x08000000–0x08003FFF;
  we skip it and boot the app vector table directly).
- SPI3 @ 0x40003C00 is the FPGA data/command channel; USART2 @ 0x40004400
  is the early command channel. CS=PB6 (active LOW), enable=PC6 (HIGH),
  gate=PB11 (HIGH). **MISO is idle-HIGH (0xFF) until the 115638-byte bulk
  cal table is uploaded (opcode 0x3B…0x3A).**

## Run it

```bash
# from repo root (so $CWD and the scripts/renode path resolve)
/Applications/Renode.app/Contents/MacOS/renode --disable-xwt --console \
    scripts/renode/stock_v120_boot.resc

# transcript -> warehouse
uv run python scripts/renode/parse_trace.py \
    --trace build/stock_v120_exec_trace.log \
    --platform at32f403a --scenario boot \
    --output build/stock_v120/mmio_events.jsonl
# then ingest mmio_events.jsonl as a Parquet table the usual way
```

## The poll-satisfaction loop (the actual work)

**Expect the first boot to stall.** The stub returns placeholder FPGA
replies, so the firmware spins (or branches to an error path) at the
first poll whose expected value we have not modeled. *That stall is the
data.* The loop:

1. Run the scenario. Note where execution stops advancing (watch the
   `build/stock_v120_exec_trace.log` tail and `renode_stock_v120_boot.log`
   unmapped-access warnings).
2. Map the stall PC to a function via the warehouse
   (`SELECT name FROM functions WHERE source='stock_v120' AND <addr> BETWEEN entry AND entry+size`)
   and read its decompiled C (`decompiled` table).
3. Identify what value the poll loop wants from which register, and
   encode that response into `fpga_protocol.py` (or, for a non-FPGA
   peripheral, model it in the `.repl`).
4. Re-run. The firmware advances to the next interaction. Each iteration
   adds one **execution-verified** fact to the boundary contract.

Convergence: the firmware reaches full acquisition (cal upload completes,
PB11 goes HIGH, the SPI data interface streams) with no stall.

## Reconcile against the static spec

Every captured transaction either confirms `scope_acquisition_spec.md`
(upgrade that fact `static-inferred → execution-verified` per
`confidence-scheme.md`) or diverges from it (a correction — most likely
in indirect-dispatch or DMA paths, where static analysis is weakest).
Keep `fpga_protocol.py`'s `access_log` honest: every reply value we have
not seen on silicon is tagged `unverified=True`. Do not promote a
placeholder to "known" without a hardware trace.

## Bring-up run log

### Run 1 (2026-05-29) — boots cleanly, hangs on a bootloader-handoff assert

The scaffold works end to end: Renode 1.16.1 builds the AT32F403A machine,
the Cortex-M4F disassembler comes up, the image loads at 0x08004000, and
the CPU boots from the real reset vector. SP/PC are correct (SP=0x20036F90,
reset=0x08007310). 32 instructions executed, **zero MMIO**, no faults.

The vector table validates the load address beyond doubt: SP + reset + 6
fault handlers + the 4 reserved words at slots 7–10 and 13 + SVCall/
PendSV/SysTick, all pointing into 0x0800xxxx. Not a base-address problem.

**Where it stops:** reset (`0x08007310`) — whose literal first instruction
is `BL FUN_0803ecf0` (bytes `37 f0 ee fc`), with real code after it that
expects the call to return — calls `FUN_0803ecf0` with **r0 = 0**.
`FUN_0803ecf0` is a `configASSERT`-style trap:

```c
FUN_0803ecf0(param_1, param_2, param_3):   // param_1 = r0, stored to [sp+0x20]
  if (param_1 == 0) {
    if (isCurrentModePrivileged()) setBasePriority(0x10);  // = configMAX_SYSCALL_INTERRUPT_PRIORITY
    ISB; DSB;
    for (;;) {}                                            // hang @ 0x0803ED1E (b .)
  }
  ... // real work: walks a descriptor at param_1+0x38/+0x3c/+0x40, calls FUN_0803f730/FUN_0803e168/FUN_08038cc4
```

**Root cause:** the reset handler passes **r0** straight into a non-null
assert as its first act. A cold reset leaves r0 = 0, so it traps. On real
hardware r0 must be non-zero here — i.e. **the FNIRSI bootloader (0x08000000–
0x08003FFF, not in this image) hands off to the app with a pointer in r0**
(a boot-info / descriptor struct the app validates and then walks). This is
a bootloader↔app register contract, not uninitialized RAM (param_1 is r0,
not a global — no scatter-load is involved in the trap).

### Run 1 analysis (2026-05-29) — the descriptor theory was wrong; cold-boot is the wrong model

Identified `FUN_0803ecf0` = **`xQueueGenericSend`** (81 call sites, 7 callers;
textbook FreeRTOS asserts: `configASSERT(pxQueue)`, the `pvItemToQueue==NULL
&& uxItemSize!=0` assert at +0x40, the `cRxLock/cTxLock` queue-lock bytes at
+0x44/+0x45, and the `0xE000ED04 = 0x10000000` PendSV `portYIELD`). So
`param_1` is a `Queue_t *` — feeding it a synthetic descriptor would just move
the crash. The real problem is the **entry point**, not a missing argument.

Findings that change the approach:
- `vector[1] = 0x08007310` is tagged "undiscovered entry point" by the
  pipeline's `vector_table` recovery, sits in a 12.5 KB gap with no Ghidra
  functions, and disassembles as **application code that dereferences `r5`
  as a pointer to the ~4 KB scope state struct** (offsets 0xe1c/0xf60/0xf69,
  the `0x200000F8` struct from `state_structure_analysis.md`) and `BL`s
  straight into `xQueueGenericSend`. A cold reset cannot have set up `r5` or
  a queue handle.
- The `.bin` is app-only at `0x08004000` (verified: no second vector table
  anywhere in the image; base is correct). The bootloader lives at
  `0x08000000–0x08003FFF` and is **not in our image**.

**Conclusion: the FNIRSI firmware is two-stage and the app is not
independently cold-bootable.** The bootloader does the C-runtime / clock /
RAM / FreeRTOS init (creating queues, setting a fixed `r5` = state-struct
base), then hands off to the app with full context. The app's own
`vector[1]` is never used as a cold-reset entry — it is leftover/re-entry
application code. Booting from `vector[1]` is fundamentally wrong.

**Revised approach — function-level emulation, not full boot.** The FPGA
driver (206 SPI3 + 28 USART2 accesses) lives entirely inside `FUN_08027a50`,
a ~12 KB Ghidra-merged blob that also contains the FreeRTOS port handlers
(SVCall/PendSV/SysTick resolve "mid-body" into it). Plan:
1. Split `FUN_08027a50` into its real sub-functions (the SPI3 byte-transfer
   primitive, the 0x05/0x12/0x15 handshake sequencer, the 0x3B/0x3A cal-upload
   loop). Use `scripts/analysis/decompose.py` and the opcode constants from
   `scope_acquisition_spec.md` to find boundaries.
2. Emulate those functions directly (Renode `cpu PC <addr>` start, or Unicorn
   like `scripts/validation/unicorn_validate.py`) with a synthetic context:
   valid SP, `r5` → a scratch state struct, args set to the call's expectation.
3. Trace SPI3/USART2/GPIO/DMA against the FPGA stub into `mmio_events`, and
   reconcile against the static handshake in `scope_acquisition_spec.md`.

This matches how ripcord already does per-function execution validation and
sidesteps the missing bootloader entirely. The full-boot scaffold
(`at32f403a.repl`, `fpga_protocol.py`, `parse_trace.py`) is still the
substrate — only the entry point changes from the reset vector to the FPGA
function.

### Run 2 (2026-05-29) — SPI3 FPGA handshake isolated inside FUN_08027a50

`decompose.py` split `FUN_08027a50` (15346 B, 452 BB) into 26 phases — it is
the whole board-init sequence (LCD/FSMC, timers, ADC, EXTI, USART2, DMA, …).
The FPGA handshake is **Phase 20: SPI3 + Handshake, `0x0802A5F6 – 0x0802AED8`**
(204 SPI3 + 58 SysTick + 13 GPIOB + 3 GPIOC accesses). The SPI byte transfer
is fully **inlined** (no `spi3_xfer` helper — the call table has 0 calls in the
region).

Decoded from the binary (independently confirms `scope_acquisition_spec.md`
§1.4–1.7):

| element | location / value |
|---|---|
| SPI3 STS poll | `r6 = 0x40003C08`; `ldr [r6]` (TXE/RXNE via `ldrpl/ldreq`) |
| SPI3 DT (data) | `[r6, #4]` = `0x40003C0C`; write then read each xfer |
| CS = PB6 (active LOW) | `str #0x40,[r4,lr]` → GPIOB SCR `0x40010C10` / CLR `0x40010C14` |
| inter-step delays | SysTick `r5 = 0xE000E010` (the ~20 ms) |
| cmd 0x05 (ID query) | `movs r0,#5; str [r6,#4]` @ `0x802A7D2` |
| cmd 0x12 | @ `0x802A90A` |
| cmd 0x15 | @ `0x802AA42` |
| cmd 0x3B (bulk begin) | @ `0x802AB06` |
| cal table src + len | `r1=0x08051D19`, `r2=0x0001C3B6` (115638) @ `0x802AB28` — byte-exact match to spec |
| cmd 0x3A (bulk end) | @ `0x802AC96` |
| post-upload | `xQueueGenericSend` item=1,2,6,7,8 (queue handle @ global `0x20002D78`) |

**Emulation entry context** (for the function-level oracle — start ~`0x802A774`,
the first transfer, after SPI3 config + initial delays):
- `r6 = 0x40003C08` (SPI3 STS; DT at +4) → route to the FPGA stub
- `r4 = 0x40011000` (GPIOC base; CS/PB6 reached via the negative `lr/ip` offsets)
- `r5 = 0xE000E010` (SysTick) — or stub the delay calls
- flash `0x08051D19` is in the loaded image, so the cal-upload loop runs as-is
- stub/skip the trailing calls: `FUN_080342fc` (delay), `FUN_0803ecf0`
  (xQueueGenericSend), `FUN_0802e430`
- the FPGA stub should still return MISO idle-HIGH (0xFF) until the `0x3A`
  bulk-end, per `fpga_protocol.py` — this run will verify exactly when the
  firmware first depends on a real reply.

### Run 3 (2026-05-29) — handshake captured in emulation ✅

`scripts/renode/stock_v120_handshake.resc` enters Phase 20 at `0x802A774`
with the recovered register context (r6/r4/r5/ip/lr) and traces against the
FPGA stub. (Two API fixes were needed first: Renode's Python-peripheral
request API is **PascalCase** — `request.IsRead/IsWrite/IsInit/Value/Offset`,
not lowercase.) Result — the captured SPI3 `DT` write sequence:

```
00  05 00 00  12 00 00  15 00 00  3B
```

i.e. `0x05` ID-query, `0x12`, `0x15`, `0x3B` bulk-begin, each framed by
flush/param `0x00` bytes — byte-exact to `scope_acquisition_spec.md` §1.6,
now **execution-verified** (confidence: static-inferred → observed). The
stub returned `0xFF` (idle-HIGH) on all 11 `DT` reads, matching "MISO idle
until cal upload." SysTick delays completed as bounded loops (~93 iters),
not infinite spins. Run hooks-paused cleanly at the `0x3B` bulk-begin
(`0x802AB28`) before the 38546-iteration upload.

Reproducible in one command (~6.5 s) via the generic runner:

```
scripts/renode/emulate_function.py --target stock_v120 \
    --entry 0x0802A774 --stop 0x0802AB28 \
    --reg sp=0x20036F90 --reg r6=0x40003C08 --reg r4=0x40011000 \
    --reg r5=0xE000E010 --reg ip=0xFFFFFC14 --reg lr=0xFFFFFC10 \
    --mem 0x20002B1C=0x40 --mem 0x20002B20=0x40 --run
# -> writes[spi3]: 00 05 00 00 12 00 00 15 00 00 3B
#    writes[gpiob]: 40 40 40 40 40 40 40   (7 CS toggles, PB6)
```

Next: move `--stop` past the upload loop to capture the cal-table stream and
the `0x3A` close, then drive the GPIO stub (PB6/PC6/PB11) so the data
interface gates on the real handshake rather than the scaffold shortcut.

## Scaffold simplifications to revisit

- **GPIO is storage-only.** `at32f403a.repl` maps GPIOA–E as plain
  memory, and the SPI3 stub pretends PC6/PB11 are already HIGH so the
  data interface gates only on the cal upload. To model the real
  handshake, upgrade GPIOB/GPIOC to stubs that call `model.set_cs()` /
  `set_pc6()` / `set_pb11()`.
- **RCC/Flash return blanket ready values.** Fine for boot; if any
  clock-dependent timing matters, model the specific bits.
- **DMA is storage-only.** Sample transfer is normally IRQ-driven; if a
  poll on DMA transfer-complete stalls, model it.
- **Python-peripheral state persistence** (the `model` created at
  `isInit` surviving across requests) is assumed. If Renode resets the
  script scope per access, move the singleton into a module-level global
  in `fpga_protocol.py` and import it. The standalone self-test is the
  guaranteed-correct part regardless.
- **Not yet wired into Snakemake.** Runs standalone like the Zephyr
  scenarios. Wiring `stock_v120` into the `renode_trace` rule needs the
  rule to handle raw-binary (non-ELF) targets first.
