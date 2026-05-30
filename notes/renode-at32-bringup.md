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

### Static trace-back (2026-05-29) — separating control / display / acquisition

Before extending the emulation, a full warehouse trace-back of every SPI3,
DMA, and XMC access answered the question the handshake capture raised: *the
firmware read `0xFF` on every SPI3 `DT` read and never complained — does it
check the replies?* It does not, and chasing that opened up the board's three
distinct data paths. **All of the following is static (disasm + decompile) —
not execution-verified.**

**A self-correction is recorded here on purpose.** An intermediate conclusion
held that the XMC window (`0x6001FFFE`/`0x60020000`) was the FPGA acquisition
interface. Decoding the register indices written to `0x6001FFFE` refuted
that: they are the **ILI9341/ST7789 LCD command set**, so XMC NE1 is the
**display**, not the FPGA. Lesson (confidence discipline): a memory-mapped
register strobe is not self-labeling — decode the actual register IDs before
naming the device.

**1. SPI3 = control/cal only; handshake is fire-and-forget.** All 206 SPI3
accesses are inside `FUN_08027a50`; no SPI3 programmed-IO data read anywhere
else. Over `0x0802A774–0x0802AED8`, every `ldr r0,[r6,#4]` (DT read) is
overwritten on the next instruction — no `cmp`, no branch, no store. **The
FPGA's handshake reply values are therefore unknowable from MCU-side
execution; only hardware/bitstream can fill them. That is the honest ceiling
of the oracle on the control plane.** SPI3's payload is the 115,638-byte cal
upload (`0x3B…0x3A`).

**2. XMC NE1 (`0x60000000`) = LCD controller (ILI9341/ST7789-family).**
`0x6001FFFE` = command/index register, `0x60020000` = data register (FSMC A16
= RS). Decoded command immediates (written once at init in `FUN_08027a50`):

| index | LCD command | index | LCD command |
|---|---|---|---|
| `0x11` | Sleep Out | `0x36` | MADCTL (mem access ctrl) |
| `0x29` | Display ON | `0x3A` | pixel format (COLMOD) |
| `0x2A` | Column Address Set | `0x2E` | Memory Read |
| `0x2B` | Page Address Set | `0xB2–0xE1` | frame/power/gamma config |
| `0x2C` | Memory Write | | |

Panel = `0x140 × 0xF0` (320×240). The dominant runtime idiom is a
3-register burst whose indices live in an SRAM descriptor at `0x20008340`:
`+0xa`=`0x2A` (Column), `+0xc`=`0x2B` (Page), `+8`=`0x2C` (Mem-Write) — i.e. a
windowed framebuffer write (`FUN_080067E8` sets the column/page window, then
streams pixels). Values are initialised in `FUN_08027a50`
(`_DAT_20008348=0x2c`, `_DAT_2000834a=0x2a`, `_DAT_2000834c=0x2b`,
`_DAT_20008340=0x140`, `_DAT_20008342=0xf0`).

**3. DMA1-Channel2 = framebuffer blit.** `C2CMAR = 0x60020000` (LCD data
port); ~150 KB. It is the only DMA channel with a non-default ISR
(`0x08009670`, Ghidra-missed; all others share trap `0x08007345`). The ISR
and its software twin `FUN_08022aac` manage a linked list of dirty/framebuffer
regions (head `0x20000138`), clear a 16-bit marker table (`0x2000107c`,
indexed `(pos−base)>>5`, bounded `< 0xAF` 1 KB-blocks ≈ 174 KB) via `memset`
(`FUN_080052bc` = `memset`), and fire a wrap callback `(*0x20001070)(0)`.
`FUN_080263bc` (mode `0x55`, 320×240, floats) is waveform **rasterization**.

| structure | addr | role |
|---|---|---|
| LCD descriptor | `0x20008340` | `+0`=w(0x140) `+2`=h(0xf0) `+8`=`0x2c` `+0xa`=`0x2a` `+0xc`=`0x2b` |
| control block | `0x20001070` | `+0` wrap-cb, `+8` fb base, `+0xc` marker table, `+0x10` enable |
| dirty-list head | `0x20000138` | linked list of framebuffer regions |
| enable byte | `0x20001080` | display live — set `=1` by `FUN_08027a50` |

**4. DMA2-Channel4 is the DAC signal generator — also an output, not
acquisition.** (This corrects an intermediate claim that DMA2-Ch4 was the
acquisition path.) `C4PADDR = &DAT_40007414` = `DAC_DHR12R2`,
`C4MADDR = &DAT_20000f5a` (SRAM waveform LUT, `0x6xx` 12-bit codes),
circular, `C4DTCNT = 100`, request-mux source `6`. The 2C53T's built-in
signal/cal output. Armed in `FUN_08027a50` at `0x08029A66`.

**5. The bulk scope-sample acquisition path is NOT located.** Only two DMA
streams exist (DMA1-Ch2 = LCD blit, DMA2-Ch4 = DAC siggen) and **both are
outputs**. XMC configures only NE1 (the LCD bank), so the FPGA is not on a
second parallel-bus bank. SPI3 has no DMA and no reads outside init. So the
sample path is either **polled SPI3 in undiscovered/merged code**, or an
**FPGA-driven ISR** (EXTI / TMR3 / etc.) Ghidra did not surface as a
function. The disciplined way to find it without another mislabel: **trace
the input buffer of the rasterizer `FUN_080263bc` (320×240, mode `0x55`)
backward to whoever fills it** — that producer is the acquisition path.

**What this means for the oracle.** Three of the board's data channels are
now positively identified (SPI3 control, XMC/DMA1-Ch2 LCD, DMA2-Ch4 DAC) and
**none is the scope-sample path**. Do **not** build a `0x6001FFFE` stub (LCD)
or a DMA2-Ch4 source stub (DAC) for the acquisition oracle — both would model
an output. The next move is identification, not modeling: find the sample
producer (rasterizer-input trace, or audit the undiscovered ISR/handler code
for a peripheral read that feeds a large SRAM buffer). Only once the real
source peripheral is known does an execution stub make sense.

**Methodological note.** Two labels in this analysis were wrong before being
corrected (XMC→"FPGA data", then DMA2-Ch4→"acquisition"). Both came from
naming a transport by its *existence* rather than by decoding its register
IDs / endpoints. The corrected facts above are decode-backed; the open item
(#5) is deliberately left unlabeled until its endpoint is decoded.

### Run 4 (2026-05-30) — bitstream upload EXECUTION-VERIFIED; sample path located

Two things changed since Run 3, both from the `fnirsi-scope-decode` workflow
rounds (see `notes/scope_architecture_v120.md`, `notes/scope_decode_round2.md`):

1. **Open item #5 ("bulk sample path NOT located") is resolved.** The runtime
   acquisition engine is a 7092-byte FreeRTOS task at **`0x0803B454`** (was in
   the undecoded gap; now seeded + decoded — 56916-char decompile, 233 SPI3
   accesses). It is *polled SPI3*, not a DMA/ISR path. So the earlier "sample
   path is either polled SPI3 in merged code or an FPGA-driven ISR" is settled:
   polled SPI3, in code Ghidra never reached.

2. **The bitstream upload runs to completion in emulation — byte-exact.**
   Extending Run 3's entry to `--stop 0x0802ACB0` (past the `0x3A` close):

   ```
   scripts/renode/emulate_function.py --target stock_v120 \
       --entry 0x0802A774 --stop 0x0802ACB0 \
       --reg sp=0x20036F90 --reg r6=0x40003C08 --reg r4=0x40011000 \
       --reg r5=0xE000E010 --reg ip=0xFFFFFC14 --reg lr=0xFFFFFC10 \
       --mem 0x20002B1C=0x40 --mem 0x20002B20=0x40 --run
   # -> spi3 write 115655 ; reads 346965 ; gpiob write 12
   #    writes[spi3]: 00 05 00 00 12 00 00 15 00 00 3B 00 2A 65 24 06 30 01 8C 47 ...
   ```

   The 115,655 SPI3 DT writes = preamble (`05/12/15/3B`) + the 115,638-byte
   flash blob `0x08051D19` **byte-exact** (`2A 65 24 06 30 01 8C 47 AF 9E 44 63
   …` matches the raw flash dump) through the `0x3A` close, no stall.
   **Contract #18 (`fpga_bitstream_upload`) promoted `decompile-derived →
   execution-verified` (0.97).** The upload *mechanism* (transport + payload +
   framing) is now silicon-independent fact; the payload's *identity* as a
   Gowin bitstream stays `inferred` (0.75) — only a Gowin parser / hardware
   confirms that.

### Run 5 (2026-05-30) — runtime BURST sample path EXECUTION-VERIFIED ✅

`acq_engine_task` (`0x0803B454`) emulated against the stub; the burst read
writes samples to `state+0x5B0` — confirmed byte-for-byte.

```
RIPCORD_FPGA_SAMPLE_PATTERN=1 scripts/renode/emulate_function.py --target stock_v120 \
    --entry 0x0803B4C2 --stop 0x0803B49A \
    --reg sp=0x20036F90 --reg r7=0x40003C08 --reg r4=0x20002D78 \
    --reg r5=0x20036FC6 --reg sb=0x200000F8 --mem 0x20036FC6=0x04 --run
# -> spi3 write 1026 (04 cmd echo + 1024 0xFF sample dummies), read 3078
#    (1024 DT reads = 512 CH1/CH2 pairs); gpiob write 40 (PB6 CS)
#    trace: 1024 byte-contiguous MemoryWrites 0x200006A8..0x20000AA7
#           = exactly state+0x5B0; in pattern mode values = 02 03 04 ...
```

The entry trick: **enter post-receive at `0x0803B4C2`** with the command byte
staged at `[sp+0x36]` (`--mem 0x20036FC6=0x04`) and the integer context the
prologue would set (`r7`=SPI3_STS, `r9/sb`=state, `r5`=&local_2). This
sidesteps the blocking `xQueueReceive` entirely — no stub-return hook needed.
Command `0x04` selects TBH case 3 = **mode 4 (burst)**; the dispatch asserts
PB6, polls TDBE/RDBF, and the burst loop does 512 paired DT reads into
`state+0x5B0..0x9AF`. The FPGA stub gained an env-gated
`RIPCORD_FPGA_SAMPLE_PATTERN` mode (returns an incrementing byte instead of
`0xFF` idle) purely to make the read→buffer flow distinguishable — the buffer
filled `02 03 04 …`, proving each clocked-in byte lands in the next slot.

**Contract #19 (`acq_engine_runtime`) promoted `decompile-derived →
execution-verified` (0.90).** Verified: dispatch, read count, buffer address
(state+0x5B0), and the data path. Still decompile-derived/inferred: roll +
the other modes, the full 9-mode command map, and real sample *values* (the
stub supplies placeholders — true values need a hardware trace).

With #18 (config bitstream upload) and #19 (runtime burst) both execution-
verified, **the SPI3 boundary — config link and runtime sample link — is now
silicon-independent fact.** The honest open frontier is the USART2 control
plane (command→FPGA-effect still terminates in state-struct writes) and the
real sample/handshake reply *values*, which remain the oracle's ceiling
without hardware.

### Run 6 (2026-05-30) — full 9-mode dispatch map EXECUTION-VERIFIED

Swept command bytes 1–9 through the same post-receive entry (`0x0803B4C2`,
command staged at `[sp+0x36]`), per-mode state-byte setup via `--mem` so gated
handlers exercise their real path, `RIPCORD_FPGA_SAMPLE_PATTERN=1`. The
`cmd → case N-1` dispatch is confirmed for all nine; per-handler behavior:

| cmd | mode | SPI3 DT stream | SRAM (state) writes | status |
|----:|------|----------------|---------------------|--------|
| 1 | range/settling gate | (not run) | — | decompile-derived (flash LUT 0x0804D833 logic) |
| 2 | write FPGA mode byte | `02 55` | — | ✅ writes `state+0x14` |
| 3 | **roll** | `03 FF FF FF FF` | `+0x482`, `+0x5AF`, `+0xDB6` | ✅ CH2/CH1 raw + fill-count |
| 4 | **burst** (1st half) | `04` + 1024×`FF` | 1024 contig → `+0x5B0` | ✅ (Run 5) |
| 5 | **burst** (2nd half) | `05` + 1024×`FF` | 1024 contig → `+0x9B0` | ✅ 2048-B two-half buffer |
| 6 | write channel mode | `06 66` | — | ✅ writes `state+0x16` |
| 7 | write trigger mode | `07 77` | — | ✅ writes `state+0x18` |
| 8 | write computed trim | `08 08` | — | ✅ **WRITE** (0x88→0x08), confirms round-2 direction fix |
| 9 | 16-bit ADC-ref read | `09 FF FF` | `+0x46` | ✅ partial: `state+0x46` + PB6 pulse (2 GPIOB); the conditional `0x0A` 5-transaction path was NOT hit with default state |

So `state+0x5B0`/`+0x9B0` (burst), `+0x356/+0x483` rings + `+0xDB6` (roll),
`+0x14/0x16/0x18` (mode/channel/trigger writes), the computed-trim write
direction, and `+0x46` (ADC ref) are all execution-verified. **Contract #19
(`acq_engine_runtime`) evidence broadened from the burst path to the full
mode map.** Honest gaps: mode 1 (range-gate) untested; mode 9's `0x0A`
candidate FPGA opcode is on a conditional branch not reached here — still
`inferred`.

### Run 7 (2026-05-30) — mode 1 + mode 9 `0x0A` EXECUTION-VERIFIED

Same post-receive entry as Run 6 (`0x0803B4C2`, command staged at `[sp+0x36]`,
`sb=0x200000F8`), with per-mode state setup via `--mem`.

**Mode 1 — auto-range settle-then-step (case `0x0803B54C`), all three branches
verified.** The handler reads `range_index` = `state+0x2D`, indexes the flash
LUT at `0x0804D833`, and compares `LUT[idx]+0x32` against the debounce counter
`state+0xDB8`. Driving the LUT gate both ways:

| `state+0x2D` (idx) | `state+0xDB8` (counter) | branch | SPI3 writes |
|--------------------|--------------------------|--------|-------------|
| `0x05` | `0x0000` | HOLD (counter < thr) | `01 05` — re-send `range_index` |
| `0x05` | `0xFFFF` | ADVANCE (idx ≤ 0x12) | `01 06` — `range_index+1` |
| `0x20` | `0xFFFF` | CLAMP (idx > 0x12)   | `01 12` — clamp to `0x12` |

So mode 1 is a closed-loop auto-ranger: hold the current range until the
per-range LUT debounce expires, then step up one (or clamp at `0x12`). The
`01` prefix is the command byte the dispatcher sends to the FPGA before the
handler's value (same `cmd value` framing as all other modes).

**Mode 9 — 16-bit ADC-ref read (case `0x0803B79C`), full sequence verified.**
SPI3 writes `09 FF FF 0A FF FF`: cmd `09`, then five transfers assembling a
16-bit value into `state+0x46`, with a PB6/CS pulse mid-sequence. **The `0x0A`
(`0x0803B848: movs r0,#0xa; str r0,[r7,#4]`) is UNCONDITIONAL straight-line
code, not a state-gated branch — this corrects the Run-6 note** ("conditional
`0x0A` path not reached"): Run 6's sweep simply truncated mode 9 before it got
there. The `0x0A` sits just past a **FreeRTOS yield** (`FUN_0803e390` =
`vTaskDelay`/yield — its delay-0 path writes `0x10000000` PENDSVSET to ICSR
`0xE000ED04`), which a no-scheduler function-level entry cannot satisfy: it
spins forever walking the uninitialised scheduler list (`0x0803E0AC`). The
robust fix is a **flash NOP-patch of the yield call site** — `--mem
0x0803B824=0xBF00BF00` rewrites the `bl` to `nop; nop`, so the SPI3 sequence
runs to completion without the yield. (A PC←LR skip *hook* was tried first and
abandoned: Renode does not cleanly redirect PC from inside a block-begin hook;
the `--mem` flash patch is deterministic and needs no new tool.) `0x0A` is now
wire-level fact; its FPGA-register *semantics* remain inferred.

**All nine capture-mode handlers are now execution-verified at the transaction
level.** Contract #19 (`acq_engine_runtime`) → confidence 0.95. Residual
unverified: real FPGA sample/reply *values* (hardware-bound — the oracle
supplies placeholder bytes), and the GPIO handshake gating (Run 8).

### Run 8 (next) — GPIO handshake + real reply values

- **GPIO handshake lines** (PB6/PC6/PB11): upgrade `at32f403a.repl` from
  storage-only GPIO to stubs that call `model.set_cs()/set_pc6()/set_pb11()`,
  so the data interface gates on the real handshake, not the scaffold
  shortcut — and feed real FPGA reply *values* (the hardware-bound ceiling).

#### Original Run-5 plan (kept for context)

The blocker was the entry: the task opens by *blocking* on `xQueueReceive` —
`bl 0x803f1d8(*0x20002D78, &local_2, portMAX_DELAY)` at `0x0803B4BA`, loop
`bne 0x0803B4B2` until a command byte arrives. In emulation the queue is empty,
so a full-entry run spins. Two ways past it:
- **Enter post-receive at `0x0803B4C2`** (right after `bne`), staging the
  command byte at `[sp+0x36]` (`local_2`) via `--mem`, and setting the integer
  context the prologue would have (`r7=0x40003C08` SPI3_STS, `r4=0x20002D78`,
  `r9/sb=0x200000F8` state, `r5=sp+0x36`). The VFP calib constants (`s16..s28`,
  loaded `0x0803B462–0x0803B48C`) won't be set — fine: garbage calibration
  changes sample *values*, not the SPI3 read count or the buffer *address*,
  which is what we're verifying structurally.
- **Or add a `--stub-return ADDR=VAL` option to `emulate_function.py`** that
  hooks the `xQueueReceive` BL and forces `r0=1` — cleaner, reusable, lets the
  real prologue run.

Then the FPGA stub (`fpga_protocol.py`) must return *sample* bytes (not `0xFF`
idle) during the runtime read phase so the burst loop fills a real buffer. The
state-struct mode-gating bytes the dispatch reads (`+0x352`, `+0x1c`,
`DAT_2000044a/b`, `DAT_2000010e`) must be set to select burst mode — read from
the decompile (`acq_engine_task`, `decompiled` table) per the poll-satisfaction
loop. Convergence: a captured SPI3 read burst followed by a `state+0x5B0`
write run promotes contract #19 (`acq_engine_runtime`) to execution-verified.

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
