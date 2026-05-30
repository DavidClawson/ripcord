# FNIRSI 2C53T (stock_v120) — Whole-Scope Architecture

**Target:** FNIRSI 2C53T digital oscilloscope, stock firmware V1.2.0
(`stock_v120`). MCU: AT32F403A (Cortex-M4F @ 240 MHz). Co-processor:
opaque Gowin FPGA (GW1N-2/GW1NS-2 family, inferred). Load base
0x08004000 (this image is the **application stage** of a two-stage boot;
the bootloader at 0x08000000–0x08003FFF that does scatter-load/VTOR
relocation is **not in this binary**).

This document synthesizes eight independently-verified subsystem reports.
Every claim carries a provenance tag (`direct-xref` | `decompile-derived`
| `inferred`) and confidence. Findings the verifier **refuted** are kept
but explicitly demoted and corrected, because the demotion is itself
load-bearing knowledge. Internal selector/index/command codes are kept
separate from wire-level register transactions throughout.

---

## 1. Executive summary

The 2C53T is a FreeRTOS application on an AT32F403A driving a Gowin FPGA
that does the actual analog-front-end timing and ADC sampling. At boot
the MCU clocks itself to 240 MHz, then **uploads a ~115 KB Gowin
bitstream to the FPGA over SPI3** (one-time configuration). After config,
the FPGA samples both channels and hands 8-bit samples back to the MCU
**over the same SPI3 bus, polled (no DMA on the inbound sample path)**.
A second link, **USART2, is the runtime control/status bus**: magic-framed
12-byte packets carry FPGA acquisition-complete signals and host commands
in, short numeric responses out.

The control loop is: FPGA samples → SPI3 polled read into the global
state struct at `0x200000F8` (raw buffers at +0x5B0/+0x9B0, or roll-mode
rings at +0x356/+0x483) → per-sample VFP calibration → measurement math
(Vpp/DC/AC-mean/frequency/period/duty, all on the state struct) →
per-viewport SRAM framebuffer rendered by drawing primitives → **DMA1-Ch2
blits the framebuffer to an ILI9341 LCD over the XMC/FSMC bus** (the LCD,
not the FPGA, is what FSMC NE1 talks to). A FreeRTOS queue + semaphore
handshake sequences acquire→process→display each frame.

Two independent **DAC output paths** exist: DAC ch2 is the DMA-driven AWG
/ signal generator (TMR7-triggered, 100-sample circular LUT); DAC ch1 is
a software-triggered single-shot used for the **trigger-level analog
reference** to the AFE comparator and for calibration. A GPIO key matrix +
TMR11 encoder feed a FreeRTOS key queue that drives the UI/menu state
machine.

The single biggest unknown remains the **MCU↔FPGA boundary contract**:
the SPI3 config preamble opcodes and the USART2 12-byte frame semantics
are statically inferred and have never been execution-verified.

---

## 2. System / RTOS / clock / boot

**Confidence: high on clock + FreeRTOS port; boot-chain framing corrected.**

### Clock tree (240 MHz)
- `SystemInit` = **FUN_080374EC**. HSI enable → HSE (8 MHz) enable+wait →
  PLL: PLLSRC = HSE/2 = 4 MHz, PLLMULT[5:0] = 59 → **×60 = 240 MHz
  SYSCLK**. AHB = 240 MHz; APB1 = APB2 = /2 = 120 MHz.
- **CORRECTION (verifier-refuted register attribution):** the extended PLL
  high bits are **CRM_CFG[30:29]** (PLLMULT5_4), *not* CRM_MISC3[9:8].
  MISC3[9:8] = HICK_TO_SCLK/HICK_TO_USB. The 240 MHz result is unchanged
  and is independently confirmed by SysTick LOAD=239999 (240e6/1000−1 ⇒
  1 kHz tick). `direct-xref`, 0.92 (result) / register fix verified.
- `SystemCoreClock` cached at **0x20002B20**, used everywhere as the
  SysTick-delay multiplier.

### FreeRTOS ARM_CM4F port (confirmed, 0.97)
- `vTaskStartScheduler` port layer = **FUN_0803E9D4**: validates CPUID,
  `configMAX_SYSCALL_INTERRUPT_PRIORITY=0x10` (@0x200022C0), SHPR3 |=
  0xF0F00000 (PendSV+SysTick lowest), SysTick LOAD=239999 / CTRL=7,
  `vPortEnableVFP` = **FUN_0803E154** (CPACR |= 0xF00000), FPCCR |=
  0xC0000000 (lazy FP stacking). Tick = 1000 Hz.
- Six tasks (entry / pri / stack / handle), **confirmed verbatim from
  string literals**, `decompile-derived` 0.98:

  | task     | entry      | pri | stack | handle     |
  |----------|------------|-----|-------|------------|
  | display  | 0x0803DA50 | 1   | 384 W | 0x20002D90 |
  | osc      | 0x0804009C | 2   | 256 W | 0x20002D98 |
  | dvom_TX  | 0x0803E3F4 | 2   | 64 W  | 0x20002DA0 |
  | fpga     | 0x0803E454 | 3   | 128 W | 0x20002D9C |
  | dvom_RX  | 0x0803DAC0 | 3   | 128 W | 0x20002DA4 |
  | key      | 0x08040008 | 4   | 128 W | 0x20002D94 |

- Two software timers: Timer1 (10 ms, cb 0x080400B8), Timer2 (1000 ms,
  cb 0x080406C8). **CORRECTION:** Timer1's callback is 0x080400B8 (inside
  FUN_08040046), *not* 0x0802AB3C — that address is the `"Timer1"` name
  string. (UI report independently caught the same trap.)
- All `xTaskCreate`/`xQueueCreate`/`xTimerCreate` calls live inside the
  mis-bounded **SVC_Handler (0x08028DC0)** body (verified: the call table
  attributes them to 0x08028DC0). **DEMOTED:** the claim that
  FUN_08028CE0 is an 18531-byte task-create function is refuted —
  FUN_08028CE0 is a 38-byte Ghidra fragment.

### Boot chain (framing corrected)
`bootloader (not in image: scatter-load + VTOR reloc)` →
**Reset_Handler 0x08007310** (single BL) → **FUN_0803ECF0** →
**FUN_080042F0** (2nd-stage init, sets SP, calls SystemInit, then
function-pointer table @0x08004354–0x0800435C) → **FUN_080374EC**
(SystemInit) → **FUN_08027A50** (board/GPIO/XMC init) → **FUN_0802A9C4**
(app: WDT arm, USB-FS init, then `vTaskStartScheduler` wrapper
FUN_0803E6D8).
- **CRITICAL CORRECTION (verifier-refuted):** FUN_0803ECF0 is **not** Keil
  `__main`/scatter-load — it is **xQueueSend/Receive** (3 params, queue
  field access, critical-section + ICSR PENDSVSET, 126 call sites). The
  scatter-load is in the absent bootloader. This is consistent with a
  two-stage image where RAM is already initialized when 0x08007310 runs.

### IRQ vectors (non-default), `direct-xref` 0.97
EXINT3=0x08009C10, DMA1_CH2=0x08009670, USBFS_L/CAN1_RX0(IRQ20)=0x0802E8E4
(**not "USBHD_LP"** — AT32F403A has no HS USB), TMR3=0x0802E71C,
USART2=0x0802E7B4, TMR8_BRK_TMR12=0x0802E78C. Default stub 0x08007344.

### Watchdog + flash update
WDT armed once in FUN_0802A9C4 (CMD 0x5555/0xAAAA/0xCCCC, DIV, RLD). Flash
firmware-update subsystem = ≥5 functions (FUN_080263BC bank1,
FUN_08030F7C unlock, FUN_08032AFC multi-bank, FUN_080333E4/FUN_080335EC
option-byte/USD).

---

## 3. FPGA configuration / bitstream load (one-time, startup)

**Confidence: high (verifier overall 0.93). This is the most thoroughly
disassembled subsystem.**

The FreeRTOS `fpga` task (FUN_080042F0 dispatch path) calls three
sub-functions via the flash table at 0x08004354–0x0800435C: pre-check
(0x08033F7C), **bitstream pump (0x0802A9C4)**, post-handler (0x08007184).
The pump is one continuous execution block 0x0802A540–0x0802ADDE that
Ghidra mis-cut into SysTick_Handler (0x0802A994) + FUN_0802A9C4 +
SVC_Handler fragments. **DEMOTED:** the "SysTick fires harmlessly during
RDBF polling" narrative is refuted — the SysTick fragment ends in
`b #0x0802A9C2`, not an EXC_RETURN, so it is pure Ghidra mis-segmentation,
not a real re-entrant ISR.

### SPI3 config setup (`direct-xref`, confirmed)
- SPI3 @0x40003C00 configured via **FUN_0803A848**: mode 0 (CPOL=0/CPHA=0),
  master, MSB-first, SSM, BR=0 (PCLK1/2 ≈ 30 MHz). SPE asserted
  @0x0802A608. (Runtime ADC SPI3 mode differs — see §4.)
- **CS = GPIOB bit 6 (PB6)**: assert low via GPIOB.CLR (0x40010C14),
  deassert high via GPIOB.SCR (0x40010C10), mask 0x40. **Contract #18's
  "GPIOC bit 6 as CS" is refuted.** `direct-xref` 0.97.
- GPIOC.PC6 set HIGH once @0x0802A63C (GPIOC.SCR 0x40011010, 0x40) — a
  secondary FPGA control pin, **likely nCONFIG** (`inferred`, 0.82).

### Wire-level config sequence (`direct-xref`, confirmed)
Five preamble transactions, each CS-framed: `0x05+0x00`, `0x12+0x00`,
`0x15+0x00` (SysTick inter-command delays), then **`0x3B` OPEN (CS stays
LOW)** → stream **115,638 bytes** from flash **0x08051D19–0x0806E0CE**,
3 bytes/iteration (38,546 iters exactly), per-byte TDBE poll (STS bit1)
before write + RDBF poll (STS bit0) after, **all received bytes
discarded** → CS HIGH → **`0x3A` CLOSE** + flush cycles. No DMA despite
CTRL2 DMAREN/DMATEN being set.

### The blob is a Gowin bitstream (`inferred`, 0.75)
Entropy 2.86 bits/byte, 69.4% zero, longest zero run 512 B — consistent
with an uncompressed Gowin GW1N-2/GW1NS-2 frame bitstream, **not** a
calibration/LUT table (refutes contract #2's "cal upload"). No sync word
found, but Gowin format varies by family.

**Phantom-xref warning (verified 0.99):** GPIOC.CLR / IDT accesses
attributed to FUN_0802A9C4 in `peripheral_xrefs` are artifacts of the
FreeRTOS task-name string literals (`Timer1`,`Timer2`,`display`,`key`,
`osc`,`fpga`,`dvom_TX`,`dvom_RX`) at 0x0802AB3C+ being decoded as code
after a branch-over-data. Do **not** trust those peripheral hits.

---

## 4. Acquisition sample path (FPGA → MCU)

**Confidence: medium-high. SPI3 polled path solid; several
state-buffer/range details corrected by verifier.**

The runtime acquisition engine is at **0x0803B456**, in the **undecoded
binary tail** (Ghidra covers ~21% of the image; this address is absent
from the functions table — confirmed). It builds r7=SPI3_STS (0x40003C08),
`[r7+4]`=SPI3_DT (0x40003C0C), and runs the same TDBE/RDBF polled
handshake as config. **Nine capture modes** dispatch from a TBH at
0x08037F0E; only two are traced:

- **Burst mode:** 1024 bytes = 512 interleaved CH1/CH2 8-bit pairs per
  trigger → `state+0x5B0`. Post-acquisition VFP pass @0x0803BD9C:
  `s16=−28.0` offset, `vdiv` by vertical scale, **clamp [0.0..255.0]**,
  write back in place. **CORRECTION:** clamp is [0.0..255.0]
  (s24=255.0/s26=0.0), **not [0x1B..0xE4]** as originally claimed.
- **Roll mode:** 301-byte rings — CH1 `state+0x356`, CH2 `state+0x483`
  (0x483 = 0x356+0x12D) — one sample/exchange, ring shifted left each
  trigger; later copied to display buffers +0x5B0/+0x9B0.

**USART2 = runtime FPGA control/status bus** (see §9 for full protocol):
ISR FUN_0802B7B4 receives magic-framed 12-byte packets and gives the
binary semaphore at **0x20002D7C** to wake acquisition. **CORRECTION:** the
TX response buffer is at **0x20000005** (a standalone 10-byte SRAM
buffer), **not** state+5; and the 12-byte completion has extra guards
(`DAT_2000000f==10 && DAT_20001034==0`), not byte-count alone.

**Acquisition state machine** = 0x08008D60 (undecoded; PUSH prologue
confirmed): 10-state TBH on `state+0xF68`; state 2 copies ring→display
(+0x356→+0x5B0, +0x483→+0x9B0) and signals queue 0x20002D6C.
**CORRECTION:** the DMA1_CH2 ISR vector (0x08009671) falls *inside this
state machine* (0x08008D60–0x08009B44), **not** inside FUN_08006670.

ADC1 (FUN_08006C78) is an **auxiliary** voltage-measure/battery channel,
not the waveform path. **CORRECTION:** its trigger is a software poll of
**GPIOC.IDT bit 7** (`_DAT_40011008<<0x18<0`), **not IOMUX.EXINTC1**; the
result register is ADC1.ODT (0x4001244C), ADC1.STS is 0x40012400.

---

## 5. Measurement / math (FPU on state struct)

**Confidence: medium-high; one critical data-flow inversion corrected.**

Two cooperating mega-functions:
- **FUN_080212EC** — per-frame ADC calibration. Two phases: (1) non-VFP
  trigger-aligned copy reads raw CH1 `state+0x5B0`(0x200006A8) / CH2
  `state+0x9B0`(0x20000AA8) → writes display buffers +0x356/+0x483;
  (2) VFP pass reads back +0x356/+0x483 and applies the linear
  calibration `(volt_div_ref/ref_scale)*(raw+adc_off−probe)+ch_off+...`
  in place, using hardware VCVT/VDIV/VMUL/VADD/VSUB. Volt/div refs from
  flash LUT DAT_080465CC. **CORRECTION:** the VFP pass input is the
  display buffer +0x356, not raw +0x5B0 directly (the report conflated
  the two phases).
- **FUN_0801DE98** (13274 B, mis-bounded, zero direct callers) — top-level
  measurement orchestrator. Drives: **Vpp** (FUN_08005C60 byte min/max
  over 300 calibrated samples → +0x260..+0x33C arrays, *and* writes the
  trigger-level DAC value — see §7); **DC voltage** (500-sample FPU mean
  of +0x6AA/+0xAAA ÷500.0 → int16 @+0x288); **AC voltage** (same mean,
  −28.0 substituted).

**Verified key finding (0.88):** there is **NO true RMS** — no
sum-of-squares, no VSQRT anywhere in flash. The "Vrms/AC" UI value is a
500-sample mean estimate. Hardware VFP is used *only* in the per-sample
calibration of FUN_080212EC and the SVC_Handler sample-rate block; all
frequency/period/duty math is the **software IEEE-754 double library at
0x08040000–0x08043200** (FUN_0804277C is the most-called primitive).

- **Period** = FUN_0802DA70: reads int64 timebase tables, soft-double
  chain → `state+0xE08`. **CORRECTION:** uses **two** tables (0x080466C8
  primary + 0x080465E0), not one.
- **Duty** = FUN_08038078: UMULL/3 integer math on period + trigger pos →
  +0xDC8/+0xDF8. (Also called from FUN_080212EC, not solely the
  orchestrator.)

### CRITICAL CORRECTION (verifier-refuted)
The measurement report claimed `state+0xE62` (0x20000F5A) is a **100-sample
ADC *input* staging buffer fed by DMA2-Ch4 from SPI3.DT**. **This is
fully refuted and inverted.** DMA2-Ch4 C4CTRL bit4 (DTD) = 1 →
**Memory→Peripheral**; C4PADDR = **0x40007414 = DAC_DHR12R2**. `state+0xE62`
is the **AWG waveform output LUT feeding DAC ch2** (§7), not an ADC input.
The raw ADC path is SPI3 polling (§4), not DMA. Carry this correction
everywhere — the open question "where is the +0xE62→+0x5B0 copy path"
is moot; there is no such copy.

---

## 6. Display (LCD framebuffer + blit)

**Confidence: high (verifier 0.88). Execution-verified blit (contract #13).**

The panel is a **320×240 RGB565 ILI9341** (or compatible) on the AT32 **XMC
(FSMC) bank-1 NE1** as a 16-bit async SRAM bus: **command port 0x6001FFFE**
(A16=0), **data port 0x60020000** (A16=1). XMC configured in FUN_08027A50:
BK1CTRL1=0x5011 (MBKEN|MWID16|EXTMOD|**WREN**), BK1TMG1=0x2020424,
BK1TMGWR1=0x202. **The FSMC NE1 interface is entirely display-side; no FPGA
data passes through FSMC** (refutes the old "FSMC = FPGA" idea; 0 CPU
reads in the FSMC range).

Display config struct @**0x20008340**: +0 full_w(320), +2 full_h(240),
+8 RAMWR(0x2C), +0xA CASET(0x2A), +0xC RASET(0x2B), +0x10..+0x16 viewport
x/y/w/h, +0x18 framebuffer_ptr. (Struct is ≥28 B; "20 bytes" was wrong.)

**Render → blit → pend loop:** each UI path allocates a per-viewport SRAM
framebuffer from the bitmap heap (FUN_08037CFC, 8.5–46.7 KB) → drawing
primitives write RGB565 via `fb + ((y−y_off)*w + (x−x_off))*2` (verified
verbatim across all primitives) → **FUN_0803FEE0** (execution-verified,
contract #13) writes CASET/RASET/RAMWR then arms **DMA1-Ch2** M2P:
C2PADDR=framebuffer (source, increments), C2MADDR=0x60020000 (dest,
fixed), CCR=0x4543, TCIE→IRQ12 → caller pends on **FUN_0803F3A8**
(semaphore _DAT_20002D84) until **IRQ12_Handler 0x08009670** walks the
dirty-region list @0x20000138, frees retired buffers, unblocks the task.
Startup uses a fixed 153600-B buffer @0x2000835C (FUN_08006670; note its
DMA setup is *not* identical — PINC=0, half DTCNT).

**Note (AT32 quirk):** DMA C2PADDR = source, C2MADDR = dest (PINC/MINC
naming per AT32 TRM, not PINCOS/MINCOS).

The scope waveform composite renderer is split across mis-bounded
mega-functions **FUN_080135A8** (grid + waveform) and **FUN_0801DE98**
(also the measurement orchestrator — same function), reached only via
FreeRTOS function-pointer dispatch (zero call edges). Colors:
grid=0x3A29, trace=0x18C3, cursor/trigger marker=0xFB43. Text =
FUN_0800C154 layout → FUN_0800CB90 alpha-blend glyph. RAMRD readback =
FUN_080067E8 (contract #12): cmd 0x2E then 3×16-bit reads per **2 pixels**
(ILI9341 18-bit readback; **not** 3×8-bit per pixel).

**Screen state byte `state+0xF68` (0x20001060)** selects the active
viewport/render path: 0=normal scope, 5=measurement, 9=settings, 11=alt
UI. (This same byte is the acquisition-SM state, UI mode gate, and AWG
mode selector across subsystems — it is heavily multiplexed.)

---

## 7. Signal generator / DAC output

**Confidence: medium-high (verifier 0.89). Two independent DAC paths.**

DAC peripheral @0x40007400. **The two paths are functionally distinct.**

### AWG path — DAC ch2, DMA-driven (confirmed 0.97)
- SVC_Handler configures **DMA2-Ch4**: C4CTRL = circular + M2P + MINC +
  16-bit, **C4DTCNT=100**, **C4PADDR=0x40007414 (DAC_D2DTH12R)**,
  **C4MADDR=0x20000F5A** (= state+0xE62, the AWG LUT). DAC_CTRL: TEN2=1,
  **TSEL2=2 (TMR7 TRGO)**, DEN2=1.
- **TMR7** (FUN_08026D40) sets the sample rate: DIV/PR from freq param
  `state+0xE5C`, SWEVT, CEN. (Also a DAC ch2 reset/idle path in its
  else-branch.)
- LUT generator **FUN_08026E14**: 13-case TBH on waveform type
  `state+0xE59`, scaled by amplitude `state+0xE61`, fills **100 contiguous
  uint16** at +0xE62..+0xF28 (10 groups ×10, adjacent — single flat
  200-byte buffer; the "+0xE62..+0xE74" extent was a 10× undercount).
- **Flash waveform template LUT @0x0804D848 is all zeros in this image.**
  **CORRECTION:** this is *not* a truncation artifact (0x0804D848 is at
  file offset 0x49848, well within the binary). The templates are simply
  blank/unprogrammed in this dump. Shapes (sine/square/triangle/...) are
  inferred from code structure only.

### Calibration / trigger-level path — DAC ch1, software-triggered (0.95)
- Single-shot writes to **DAC_D1DTH12R (0x40007408)** then **SWTRG
  (0x40007404) |= 1**. Formula `(span/200.0)*(position+100)+baseline`.
  **CORRECTION:** position source is **state+0x4 (0x200000FC)**, *not*
  state+0xF2D (which is a waveform_index byte the ISR zeros on exit).
- Writers: FUN_080058A4, FUN_08005C60 (the Vpp path — this is where the
  **trigger-level analog reference to the AFE comparator** is produced),
  FUN_0800AF58, FUN_080087CC, FUN_0801DE98, and the EXTI3 ISR.
- **EXTI3 ISR** real body = **0x08009B50** (push prologue); the
  Ghidra-named IRQ9_Handler 0x08009C10 is just the 16-byte epilogue.
  Mode dispatcher on `state+0xF68`: mode 2 = inline interpolated ch1 DAC
  write + SWTRG; mode 1 = post FreeRTOS msgs 0x1D/0x1B/0x1A; tail-calls
  freq-measurement math FUN_080068E0. **What physically drives EXTI3 is
  unknown** (comparator? FPGA? GPIO feedback?).
- **CORRECTION:** FUN_0800AF58 writes **GPIOD.CLR (0x40011414)**, not
  "EXTI14"; FUN_080087CC is a 10-mode TBH dispatcher, not "AWG mode-2".

---

## 8. UI / input (keys, menus, encoder)

**Confidence: medium (verifier 0.72 — several bit/peripheral corrections).**

Key scanner/debouncer = **FUN_0803D0B8** (no direct callers; invoked via
an unresolved periodic mechanism — likely a timer callback, but the two
registered callbacks land mid-function, so unresolved statically).

- **4×4 GPIO matrix:** rows driven via **GPIOx.CLR + pin-mode switching
  (FUN_080342FC to INPUT_FLOATING)** — **CORRECTION:** FUN_0803D0B8 issues
  **zero direct SCR writes**; row deselect is by mode-switch, not
  SCR-drive-high. Column reads (all active-low) — **CORRECTION:** correct
  bits are **GPIOA[7], GPIOB[0], GPIOC[5], GPIOE[2]** (the originally
  reported [7]/[3]/[4]/[14] were wrong).
- 15 keys, per-key debounce counters @0x20002D58, thresholds 0x46
  (long-press) / 0x48 (repeat). Result halfword @0x20002D56 (uint16, not
  "4-bit mask"). Key codes posted (non-blocking, multi-key-guarded) to
  **queue 0x20002D70** via xQueueSend FUN_0803ECF0.
- **Encoder:** TMR11.C1DT (0x40015434) polled for capture; 11-period
  debounce @0x20002D67. **Direction (CW/CCW) not resolved.**
- **Frequency counters:** TMR2.CVAL (0x40000024, CH1) + **TMR5.CVAL
  (0x40000C24, CH2 — NOT TMR3)** gated every 51 scan periods → freq/period
  into state+0x50/0x54/0x80/0x84 (stored value is 2×count).
- **Battery monitor** = FUN_08006C78 (also the §4 aux ADC): GPIOC.IDT
  bit7 power-detect, ADC1 SWSTART, 10 thresholds, posts battery codes to
  queue 0x20002D6C.

UI dispatcher task = **0x0803D008** (Ghidra gap): blocks on
xQueueReceive(0x20002D70), checks mode guards, dispatches via a BLX table
@0x08046544 (r8=0x08046548). **The dispatch-table encoding is unverified**
(`unverifiable` 0.65) — entries have bit0=0 under a direct-jump reading;
likely r8-relative offsets, but unconfirmed. The same task waits on
semaphore 0x20002D80 then calls the UI state machine FUN_0801DE98.

---

## 9. Command protocol (USART2 + code classifier)

**Confidence: medium-high (verifier 0.88). Two ISR-path claims refuted.**

USART2 (@0x40004400) is a **bidirectional, magic-framed, RTOS-mediated
command/response bus** — *not* a waveform channel. It carries user-facing
control (timebase/trigger/coupling/probe/range) and the FPGA
acquisition-complete doorbell.

### Receive (ISR FUN_0802B7B4, confirmed 0.95)
Builds a 12-byte frame at RX_buf 0x20004E11 (counter 0x20004E10). Frame
sync: buf[0]∈{0x5A,0xAA}; for 0x5A, buf[1]≠0xA5; for 0xAA, buf[1]≠0x55.
On a complete 0x5A frame → posts to **queue 0x20002D7C** (FUN_0803F09C) →
**PendSV (ICSR ← 0x10000000)**.
- **CORRECTION (refuted):** the 0xAA/0x55 "sync" path does **NOT** call
  FUN_0802FDD4 — on match it simply resets the counter and returns (drops
  the frame). The "in-band bootloader switch" claim is unsupported.
- **CORRECTION:** before checking cmd_lock the ISR also gates on TX
  counter `[0x2000000F]==0xA` (TX idle).

### Command dispatcher (task @0x0803AAC0, confirmed)
Waits on queue 0x20002D7C, reads buf[2..6], forms 4 command bytes by a
**sliding nibble-interleave** `(buf[k+2]&0xF0)|(buf[k+3]&0x0F)`, classifies
each via **FUN_08037EF8**, dispatches on index 4-tuples to write state
fields (+0xF35 action, +0xF30 float, +0xF2D scan_param, +0xF36 coupling,
+0xF37 probe ratio). Second-stage TBB @0x0803B1C4 on scan_param 0–7.

### Code classifier FUN_08037EF8 (confirmed 0.95) — **selector codes, not wire transactions**
`AND #0xEF` then TBH/TBB → 21 known wire codes map to indices 0–20, else
0xFF. Live map: 0x8A→7, 0x8F→3, 0xAD→2, 0xC7→5, 0xCF→9, 0xE1→17, 0xE5→19,
0xE7→6, 0xEB→0, 0xEC→18, 0xEE→10, 0xEF→8, 0x4E→4, 0x61→14, 0x65→12, plus
0x00→16, 0x04→15, 0x0A→1, 0x23→11, 0x24→20, 0x27→13. **Refutes contract
#18:** the TBH @0x08037F0E is this classifier's *internal* table, not a
102-case SPI3 router. (These are internal dispatch codes — the
*semantics* of each command class remain un-decoded; see open questions.)

### Transmit (task @0x0803B3F4, confirmed)
Waits on queue 0x20002D74, encodes a 16-bit value into 10-byte TX buffer
@**0x20000005** (TX[2]=hi, TX[3]=lo, TX[9]=hi+lo checksum), enables TXEIE
(CTRL1|=0x80); ISR drains 10 bytes.

- **CORRECTION (refuted):** SVC_Handler (0x08028DC0) is the **SVCall**
  vector target (slot 11 = 0x08028DC1), **not DebugMon** (slot 12 =
  0x080097E5). It is still mis-bounded; only the exception identity was
  wrong.
- USART2 RX is gated off (CTRL1 &= ~0x2000) during the FPGA bitstream
  upload in FUN_0802A9C4. TMR3 is **not** a USART2 protocol timer.

---

## 10. End-to-end acquisition → process → display loop

```
                         ┌──────────────────────────────────────────────┐
   (one-time at boot)    │  FPGA CONFIG: SPI3 mode0, CS=PB6              │
   FUN_0802A9C4 ────────▶│  preamble 05/12/15, OPEN 3B, 115638 B blob,  │
   (flash 0x08051D19)    │  CLOSE 3A  → Gowin FPGA configured            │
                         └──────────────────────────────────────────────┘
                                          │
   ┌──────────────────────────────────────┼───────────── runtime loop ──┐
   │                                       ▼                             │
   │  FPGA samples both channels                                         │
   │     │                                                               │
   │     ├── USART2 12-byte frame "acq complete" ─▶ ISR FUN_0802B7B4     │
   │     │       └─ give semaphore 0x20002D7C ─▶ wakes acquisition       │
   │     │                                                               │
   │     ▼ SPI3 polled read (engine 0x0803B456, TDBE/RDBF)              │
   │  raw samples → state+0x5B0 / +0x9B0  (burst)                        │
   │                or rings +0x356 / +0x483 (roll)                      │
   │     │                                                               │
   │     ▼ acquisition SM 0x08008D60 (state+0xF68), ring→display copy    │
   │     ▼ VFP calibration  FUN_080212EC  (offset −28, ÷scale,           │
   │       clamp 0..255)  → display buffers +0x356 / +0x483             │
   │     │                                                               │
   │     ▼ measurement math FUN_0801DE98:                                │
   │        Vpp (FUN_08005C60) ─▶ also writes DAC ch1 trigger level      │
   │        DC/AC mean (500-sample FPU), freq/period/duty (soft-double)  │
   │        results → state +0x260.. / +0x288 / +0xE08 / +0xDC8/+0xDF8   │
   │        TX measurement ─▶ queue 0x20002D74 ─▶ USART2 TX task         │
   │     │                                                               │
   │     ▼ render: per-viewport SRAM framebuffer (FUN_08037CFC heap),    │
   │       primitives (line/glyph/fill) write RGB565 @0x20008358         │
   │       waveform composite FUN_080135A8 / FUN_0801DE98                │
   │     │                                                               │
   │     ▼ FUN_0803FEE0: CASET/RASET/RAMWR + arm DMA1-Ch2 M2P            │
   │       framebuffer ─▶ 0x60020000 (ILI9341 data, XMC NE1)            │
   │     │                                                               │
   │     ▼ IRQ12 0x08009670: free buffers, unblock display task         │
   │       (task pended on semaphore 0x20002D84 via FUN_0803F3A8)        │
   └────────────────────────────────────────────────────────────────────┘

   Independent: DAC ch2 AWG  (TMR7 TRGO ─▶ DMA2-Ch4 ─▶ DAC_D2DTH12R,
                100-sample LUT @0x20000F5A);  GPIO key matrix + TMR11
                encoder ─▶ key queue 0x20002D70 ─▶ UI dispatcher 0x0803D008.
```

**Sequencing primitives:** queue 0x20002D7C (USART2 RX→cmd/acq doorbell),
0x20002D74 (measurement→TX), 0x20002D70 (keys), 0x20002D6C (mode/battery
events), semaphores 0x20002D7C/0x20002D80/0x20002D84 (acq + display
handshake). PendSV-driven context switches via ICSR writes.

---

## 11. MCU ↔ FPGA boundary contract

This is the crux and the weakest-verified region. Tag every row.

### Configuration link (SPI3) — `direct-xref`, high confidence on transport
| element | value | provenance |
|---|---|---|
| Bus | SPI3 @0x40003C00, mode 0, master, MSB, ~30 MHz | direct-xref 0.87 |
| CS | GPIOB.PB6 (CLR=0x40010C14 low / SCR=0x40010C10 high) | direct-xref 0.97 |
| Secondary ctrl | GPIOC.PC6 HIGH once (likely nCONFIG) | inferred 0.82 |
| Preamble cmds | 0x05, 0x12, 0x15 (each +0x00, CS-framed) | direct-xref 0.93 |
| Stream framing | 0x3B OPEN … 115638 B … 0x3A CLOSE | direct-xref 0.93/0.96 |
| Payload | Gowin GW1N-2/GW1NS-2 bitstream | inferred 0.75 |
| **Command *meaning*** | 0x05/0x12/0x15 semantics | **UNKNOWN** — not exec-verified |

### Runtime sample link (SPI3) — `direct-xref` on transport
SPI3 polled TDBE/RDBF, 8-bit samples, interleaved CH1/CH2 → state+0x5B0
(burst) / rings (roll). Runtime SPI3 mode/divider differs from config and
was **not** cleanly extracted (open). No DMA on the inbound path.

### Runtime control/status link (USART2) — `decompile-derived`
12-byte RX frames (magic 0x5A/0xAA), nibble-interleaved command encoding,
10-byte TX responses. The classifier wire-codes (§9) are confirmed as
*internal selector indices*; the **mapping from a command tuple to an
actual FPGA-facing effect (timebase/trigger written to the FPGA) is not
traced to a wire transaction** — it currently terminates in state-struct
writes only. **Do not present any FPGA behavior as established fact.**

### Falsifiable definition of done (per CLAUDE.md north star)
Boot stock_v120 in Renode with the logging FPGA stub; the firmware must
run to full acquisition against the software FPGA model with no
divergence. Until then, everything above the SPI3/USART2 transport layer
is inferred.

---

## 12. Annotated state-struct map (base 0x200000F8)

Aggregated across subsystems. Offset = byte from base; abs = 0x200000F8+off.
Provenance per row inherited from owning subsystem; `(C)` = verifier-confirmed,
`(corr)` = corrected from original report.

| off | abs | field | owner |
|---|---|---|---|
| +0x00 | 0x200000F8 | ch0 select / ch1 DAC counter (zeroed by FUN_0800AF58) | sys/siggen |
| +0x02 | 0x200000FA | ch1/ch2 select; CH1 volt-div idx; FUN_080087CC channel index `(corr: +0x2 not +0xFA)` | meas/siggen |
| +0x03 | 0x200000FB | CH2 volt/div index | meas |
| +0x04 | 0x200000FC | **DAC ch1 voltage position** `(corr: not +0xF2D)`; probe factor | siggen/meas |
| +0x05 | 0x200000FD | CH2 probe factor / DC coeff | meas |
| +0x14 | 0x2000010C | CH1 coupling (1=DC,2=AC,3=math) | meas |
| +0x17 | 0x2000010F | channel-mode selector (1=CH1,2=dual) | acq/display |
| +0x1A | 0x20000112 | trigger position (int16) | meas |
| +0x1C | — | trigger level (signed) | acq |
| +0x2D | 0x20000125 | timebase index 0–19 | meas/acq |
| +0x2E | 0x20000126 | channel-enable / auto-cal flag | meas |
| +0x260 | 0x20000358 | CH1 Vmin per volt/div (int16[10]) | meas |
| +0x288 | 0x20000380 | CH1 DC-mean result (int16) | meas |
| +0x29C | 0x20000394 | CH1 Vmax per volt/div (int16[10]) | meas |
| +0x2D8 | 0x200003D0 | CH2 Vmin[10] | meas |
| +0x314 | 0x2000040C | CH2 Vmax[10] | meas |
| +0x352/+0x353 | — | CH1/CH2 calibration offsets | acq |
| +0x356 | 0x2000044E | **CH1 calibrated display samples (301 B)** / roll ring | acq/meas/display |
| +0x483 | 0x2000057B | **CH2 calibrated display samples (301 B)** / roll ring | acq/meas |
| +0x5B0 | 0x200006A8 | **CH1 raw ADC (1024 burst / 302 B)** | acq/meas |
| +0x6AA | 0x200007A2 | CH1 DC-mean window (500 B) | meas |
| +0x9B0 | 0x20000AA8 | **CH2 raw ADC** | acq/meas |
| +0xAAA | 0x20000BA2 | CH2 DC-mean window (500 B) | meas |
| +0xDB0 | 0x20000EA8 | acquisition sub-state (0=idle,2=done,3=roll) | acq/meas |
| +0xDB4 | 0x20000EAC | raw period / display width | acq/meas |
| +0xDC8 | 0x20000EC0 | computed trigger level (FUN_08038078) | meas |
| +0xDF8 | 0x20000EF0 | duty-cycle phase offset | meas |
| +0xE08 | 0x20000F00 | period result (int64, FUN_0802DA70) | meas |
| +0xE59 | 0x20000F51 | AWG waveform type (0–12) | siggen |
| +0xE5C | 0x20000F54 | AWG frequency param (TMR7 DIV) | siggen |
| +0xE61 | 0x20000F59 | AWG amplitude | siggen |
| +0xE62 | 0x20000F5A | **AWG output LUT (100 uint16, 200 B) → DMA2-Ch4 → DAC ch2** `(corr: OUTPUT, not ADC input)` | siggen |
| +0xF2C | 0x20001028 | scan_param_prev / coupling/trigger fields | cmd |
| +0xF2D | 0x20001025 | scan_param_idx (cmd 2nd-stage) **and** waveform_index (zeroed by EXTI3) | cmd/siggen |
| +0xF35 | 0x2000102D | command action code (1–9) | cmd |
| +0xF36/+0xF37 | — | coupling / probe ratio | cmd |
| +0xF3C | 0x2000102C | cmd_lock (ISR gate) | cmd |
| +0xF68 | 0x20001060 | **multiplexed mode byte**: screen mode (0/5/9/11), acq-SM state (0–9), AWG mode (0/1/2), cmd dispatch | display/acq/siggen/cmd |
| +0xF69 | 0x20001061 | channel-active flag | acq/display |
| +0xF6A | 0x20001062 | active-channel nibble | display |
| +0xF6B | 0x20001063 | acquisition-running flag | display/acq |

**Out-of-struct globals of note:** 0x20002B20 (SystemCoreClock),
0x20000138 (dirty-region list head), 0x20008340 (display config struct),
0x20008358 (live framebuffer ptr), 0x20000005 (USART2 TX buffer),
0x20004E10/11 (USART2 RX frame), 0x20002D6C–0x20002DA4 (queues/timers/task
handles), 0x20000000 (FreeRTOS nesting counter), 0x200022C0
(configMAX_SYSCALL_INTERRUPT_PRIORITY).

---

## 13. Prioritized open questions

1. **FPGA boundary contract (the north star).** Three sub-unknowns, all
   un-execution-verified: (a) the meaning of SPI3 config preamble opcodes
   0x05/0x12/0x15 (Gowin SSPI register reads? proprietary?); (b) the
   **runtime SPI3 mode/divider/bit-order** for sample acquisition (never
   extracted from the FUN_08027A50 init); (c) the semantics of the USART2
   12-byte frame fields and whether a host command actually propagates to
   a wire-level FPGA transaction (today it dead-ends in state-struct
   writes). **Resolution: boot stock_v120 in Renode with the logging FPGA
   stub and reconcile against §11.** This is the falsifiable DoD.

2. **The undecoded acquisition tail (≈79% of the image).** The real
   acquisition engine (0x0803B456), the 10-state acq SM (0x08008D60), 7
   of 9 capture modes (TBH @0x08037F0E), and the +0x6AA/+0xAAA DC-window
   writers are all outside Ghidra's coverage. Extend extraction over the
   binary tail; without it, deep-mem/single-shot/averaging/X-Y modes and
   the raw→DC-window fill remain unmapped.

3. **What physically drives EXTI3, and the encoder direction.** EXTI3
   (FUN_08009B50) does inline DAC-trigger-level writes and freq math but
   its source signal (comparator vs FPGA vs GPIO) is unknown; TMR11
   captures encoder presence but phase-B / direction is unresolved. Both
   are hardware-pin questions needing a trace or schematic.

4. **The key-event BLX dispatch table @0x08046544.** Encoding is
   unverified (`unverifiable` 0.65) — direct-jump reading yields invalid
   bit0=0 targets; r8-relative-offset reading is plausible but
   unconfirmed. Resolve by emulating one keypress through the dispatcher.
   The "two 15-entry key-code byte tables @0x08046528/0x08046537" overlap
   the 32-bit dispatch entries (values 0xFF/0xFE appear as "key codes") —
   treat as suspect until traced.

5. **Calibration constants and trigger/timebase tables.** The flash AWG
   waveform templates @0x0804D848 are **blank in this image** (so shapes
   are inferred, not verified); the VFP per-volt/div scale constants
   (s18..s28 in FUN_080212EC) and the two int64 timebase tables
   (0x080466C8 + 0x080465E0, unit = ns? ps? fixed-point?) are not
   ground-truthed. Verify by running FUN_0802DA70 / the calibration loop
   against a known waveform in emulation.

---

## 14. Cross-cutting corrections ledger (demotions the verifier forced)

These overturn earlier subsystem claims; do not re-introduce the originals.

- **DMA2-Ch4 / state+0xE62 is a DAC *output* (AWG), not an ADC input
  staging buffer.** (measurement report inversion — the single most
  important correction; refutes contract #6, confirms #7.)
- **FUN_0803ECF0 = xQueueSend/Receive, not Keil __main/scatter-load.**
  Scatter-load is in the absent bootloader (two-stage image).
- **SVC_Handler (0x08028DC0) is the SVCall vector, not DebugMon.** Still
  mis-bounded (6882 B); FUN_08028CE0 is 38 B, not 18531 B.
- **VFP clamp range is [0.0..255.0], not [0x1B..0xE4].**
- **No true RMS** — AC value is a 500-sample mean; no VSQRT in flash.
- **Config-SPI CS is GPIOB.PB6, not GPIOC bit6** (refutes contract #18).
- **PLL high bits at CRM_CFG[30:29], not MISC3[9:8]** (240 MHz unchanged).
- **CH2 frequency counter is TMR5.CVAL, not TMR3.CVAL.**
- **Key matrix column bits: GPIOA[7],GPIOB[0],GPIOC[5],GPIOE[2]**; scanner
  does zero direct SCR writes (deselect via mode-switch).
- **DAC ch1 voltage position = state+0x4, not state+0xF2D.**
- **USART2 0xAA sync path drops the frame; does not call FUN_0802FDD4.**
- **USART2 TX buffer = 0x20000005, not state+5.**
- **DMA1_CH2 ISR (0x08009670) lives inside acq SM 0x08008D60, not
  FUN_08006670.**
- **ADC1 aux trigger = poll of GPIOC.IDT bit7, not IOMUX.EXINTC1.**
- **Timer1 callback = 0x080400B8** (0x0802AB3C is the "Timer1" string);
  **classifier TBH @0x08037F0E is internal, not a 102-case SPI3 router.**
- **Phantom peripheral_xrefs** on FUN_0802A9C4 from task-name strings —
  ignore GPIOC/IDT hits there.
