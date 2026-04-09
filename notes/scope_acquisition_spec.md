# Scope Acquisition: MCU-to-FPGA Protocol Specification

Synthesized from ripcord xref analysis of stock V1.2.0, decompiled
`fpga_task_annotated.c`, `FPGA_BOOT_SEQUENCE.md`, `FPGA_TASK_ANALYSIS.md`,
`FPGA_PROTOCOL_COMPLETE.md`, `spi3_bulk_cal_resolved.md`, and the osc
project's current `fpga.c` implementation.

**Purpose:** Unblock scope acquisition in the osc project's custom firmware
by specifying the best current staged model of register values, command
sequences, and timing that transition the FNIRSI 2C53T from boot to
receiving live oscilloscope ADC data via SPI3.

---

## Confidence and Provenance

Every major claim in this document carries one of these evidence levels:

- **[hardware-confirmed]** — verified by bench measurement in the osc project
- **[direct-xref]** — observed directly in ripcord warehouse xref queries
- **[decompile-derived]** — from Ghidra pseudo-C decompilation
- **[synthesized-model]** — cross-referenced from multiple sources; plausible but not independently confirmed
- **[low-confidence-hypothesis]** — speculative, needs further evidence

**Important distinction — internal selectors vs wire-level commands:**
The stock firmware has a multi-layer command dispatch. Some command codes
(notably 0x0B-0x11) are internal display-queue selectors that are
translated by a dispatch handler before the final 16-bit TX words reach
USART2_DR. Other command codes (notably 0x16-0x19, 0x1A-0x1E, 0x20/0x21,
0x26-0x28) are believed to be closer to wire-level based on direct
USART2_DR xref tracing, but a translation layer may still exist between
the command source and the hardware register write. Each command group
below is labeled with its evidence level.

---

## Prerequisites

Before any scope acquisition can occur, the following must be true:

| Condition | How to set | Verified by |
|-----------|-----------|-------------|
| PB11 = HIGH | `GPIOB->scr = 0x800` | Stock step 52 (just before scheduler) |
| PC6 = HIGH | `GPIOC->scr = (1 << 6)` | Stock step 19 |
| PB6 = HIGH (CS idle) | `GPIOB->scr = 0x40` | Stock step 27 |
| USART2 configured: 9600 8N1, TX+RX | See Phase 2 | Stock step 9 |
| SPI3 configured: Mode 3, /2, Master | See Phase 3 | Stock step 21 |
| SPI3 bulk cal table uploaded | 115,638 bytes via 0x3B/0x3A | Stock Phase 8 |
| FreeRTOS scheduler running | `vTaskStartScheduler()` | Stock step 53 |
| TMR3 ISR enabled (drives USART exchange) | NVIC IRQ 29 | Stock step 50 |

**Critical:** Both PB11 and PC6 must be HIGH before SPI3 returns real
data. Missing either causes 0xFF on every read.

---

## Phase 1: Boot Initialization (pre-scheduler, one-time)

This is the `fpga_init()` path. It runs before FreeRTOS starts.

### 1.1 AFIO Remap (free PB3/PB4/PB5 for SPI3)

```c
// Disable JTAG-DP, keep SW-DP
// Stock: AFIO_PCF0 = (AFIO_PCF0 & ~0xF000) | 0x2000
// AT32: write IOMUX->remap bits [26:24] = 010
uint32_t remap = IOMUX->remap;
remap &= ~(0x7u << 24);
remap |= (0x2u << 24);
IOMUX->remap = remap;
gpio_pin_remap_config(SWJTAG_GMUX_010, TRUE);
// Do NOT call SPI3_GMUX_0010 — stock never writes it
```

### 1.2 USART2 Init

```
Register          Value       Meaning
─────────────────────────────────────────────────
USART2_BRR        APB1/9600   9600 baud (APB1 = HCLK/2 = 120 MHz)
USART2_CR1        RE+TE+UEN   Receiver enable, Transmitter enable, USART enable
                  +RDBFIEN    RX interrupt enable
USART2_CR2        0           (no extra config needed)
```

Ripcord warehouse confirms: `FUN_08027a50` writes USART2_BRR (1 R+W),
USART2_CR1 (8 R+W pairs), USART2_CR2 (1 R+W) starting at instruction
address `0x080298d2`.

### 1.3 USART2 Boot Commands (inline, NOT via task queues)

Stock firmware sends five commands before SPI3 is even configured.
Each is a 10-byte frame sent byte-by-byte with TX polling:

```
Command  cmd_hi  cmd_lo  Checksum    Purpose
────────────────────────────────────────────────
  1      0x00    0x01    0x01        Channel init
  2      0x00    0x02    0x02        Signal gen setup
  3      0x00    0x06    0x06        Signal gen setup
  4      0x00    0x07    0x07        Meter probe detect
  5      0x00    0x08    0x08        Meter configure
```

**TX frame format** (10 bytes, bytes [4]-[8] are all zero):
```
[0]=0x00 [1]=0x00 [2]=cmd_hi [3]=cmd_lo [4..8]=0x00 [9]=(cmd_hi+cmd_lo)&0xFF
```

**Note:** The osc firmware currently sends 0x01 through 0x08 (all eight).
Stock only sends 0x01, 0x02, 0x06, 0x07, 0x08 at boot. The extra
commands (0x03, 0x04, 0x05) are harmless but unnecessary.

**Inter-command delay:** Stock uses inline SysTick delays between commands.
The osc firmware uses 50ms per command. This is conservative but safe.

### 1.4 SPI3 Peripheral Configuration

```
Register          Value       Meaning
─────────────────────────────────────────────────
SPI3_CTL0/CTRL1   0x0307      CPHA=1, CPOL=1 (Mode 3), MSTEN=1,
                              BR=000 (/2 = 60MHz), SSI=1, SSM=1
SPI3_CTL1/CTRL2   0x03        bit 0 = RXDMAEN, bit 1 = TXDMAEN
                              (DMA enable bits set but no DMA channels configured
                               — transfers are polled. The bits may be required
                               for the FPGA SPI slave handshake.)
SPI3_CTL0 |= 0x40             SPE = SPI Enable
```

**GPIO for SPI3:**
```
PB3 = SCK   (AF push-pull, 50MHz)
PB4 = MISO  (Input floating)
PB5 = MOSI  (AF push-pull, 50MHz)
PB6 = CS    (GPIO output push-pull, active LOW)
PC6 = Enable (GPIO output push-pull, set HIGH)
```

### 1.5 SysTick Delays

Stock firmware has ~20ms of multi-phase SysTick delays between SPI3
enable and the handshake. The osc firmware does 10+5+5 = 20ms total.
This appears sufficient.

### 1.6 SPI3 FPGA Handshake

Exact sequence from stock (confirmed by Unicorn trace):

```
1. CS HIGH (deassert)
2. spi3_xfer(0x00)          → discard (bus flush)

3. CS LOW  (assert)
4. spi3_xfer(0x05)          → FPGA status/ID query
5. spi3_xfer(0x00)          → parameter byte
6. CS HIGH (deassert)

7. spi3_xfer(0x00)          → flush

8. [delay ~10ms]

9. CS LOW  (assert)
10. spi3_xfer(0x12)         → post-handshake command
11. spi3_xfer(0x00)         → parameter
12. CS HIGH (deassert)

13. spi3_xfer(0x00)         → flush
14. [delay ~5ms]

15. CS LOW  (assert)
16. spi3_xfer(0x15)         → post-handshake command
17. spi3_xfer(0x00)         → parameter
18. CS HIGH (deassert)

19. spi3_xfer(0x00)         → flush
20. [delay ~5ms]
```

**Important:** Each CS transaction is exactly 2 bytes. Earlier analyses
said 4 bytes per transaction — that was wrong. Extra bytes within a CS
assertion may confuse the FPGA's SPI slave state machine.

### 1.7 Bulk Calibration Table Upload (115,638 bytes)

This is the H2 table that programs the FPGA's internal register/memory
state. **Without this upload, the FPGA's SPI data interface appears to
remain inactive** (MISO stays idle-HIGH).

```
1. CS LOW  (assert)
2. spi3_xfer(0x3B)          → "begin bulk register write" opcode
3. spi3_xfer(0x00)          → flush byte after opcode
4. For i = 0 to 115637:
     spi3_xfer(table[i])    → 3-byte records, 38546 iterations
5. spi3_xfer(0x3A)          → "end bulk register write" opcode
6. spi3_xfer(0x00)          → flush byte after close
7. CS HIGH (deassert)
8. [delay ~50ms]            → let FPGA process the table
```

The table data lives in the stock binary at flash offset `0x08051D19`
(115,638 bytes). The osc firmware has this extracted as
`fpga_h2_cal_table[]` in `fpga_cal_table.h`.

### 1.8 Analog Frontend + Meter Activation

Stock firmware configures the analog MUX relays and sends meter
activation commands before PB11 goes HIGH. The osc firmware mirrors
this with relay GPIO writes and commands `0x0508`, `0x0509`,
`0x0507`/`0x050A`, `0x0514`, then `0x1A`-`0x1E`.

### 1.9 PB11 HIGH (FPGA Active Mode)

```c
GPIOB->scr = 0x800;   // PB11 HIGH — FPGA active mode
```

Stock firmware sets this in step 52, just before `vTaskStartScheduler()`.
It must come AFTER all peripheral config, boot commands, SPI3 handshake,
bulk cal upload, analog frontend config, and meter activation.

### 1.10 Start FreeRTOS Scheduler

```c
vTaskStartScheduler();   // Never returns
```

---

## Phase 2: Scope Mode Entry (runtime, from FreeRTOS context)

When the user switches to oscilloscope mode, the firmware must send
a sequence of USART2 commands to configure the FPGA for scope operation.
This happens via the FreeRTOS task infrastructure (dvom_TX task).

### 2.1 Exit Previous Mode

```c
GPIOC->clr = (1U << 11);  // PC11 LOW — meter MUX off
GPIOB->scr = PB11_MASK;   // PB11 HIGH — ensure FPGA active
```

### 2.2 Analog Frontend Relay Configuration

The analog MUX relays must be set for the scope input path. The relay
configuration depends on the voltage range:

| V/div range | PC12 | PE4 | PE5 | PE6 | PA15 | PA10 | PB10 |
|-------------|------|-----|-----|-----|------|------|------|
| 10mV-20mV  | LOW  | HIGH| LOW | LOW | LOW  | LOW  | LOW  |
| 50mV-200mV | LOW  | HIGH| var | LOW | HIGH | HIGH | LOW  |
| 500mV-2V   | LOW  | LOW | var | HIGH| LOW  | LOW  | LOW  |
| 5V         | HIGH | LOW | HIGH| HIGH| LOW  | LOW  | LOW  |
| 10V        | LOW  | HIGH| LOW | HIGH| LOW  | LOW  | HIGH |
| 20V-50V    | LOW  | HIGH| HIGH| HIGH| LOW  | LOW  | LOW  |

### 2.3 USART2 Scope Command Sequence

The stock firmware's scope mode entry (mode 0 in `FUN_0800735C`) sends
these commands through the USART command dispatch pipeline. **This is
the best current staged model, not a confirmed wire-level capture.**

```
Step  cmd_hi              cmd_lo  Purpose                              Evidence
───────────────────────────────────────────────────────────────────────────────
 1    0x00                0x00    Reset/Init                           [decompile-derived]
 2    channel_mask        0x01    Configure channel (01=CH1, 02=CH2)   [decompile-derived]
 3    param               0x0B    Scope config selector 0              [decompile-derived] *
 4    param               0x0C    Scope config selector 1              [decompile-derived] *
 5    param               0x0D    Scope config selector 2              [decompile-derived] *
 6    param               0x0E    Scope config selector 3              [decompile-derived] *
 7    param               0x0F    Scope config selector 4              [decompile-derived] *
 8    param               0x10    Scope config selector 5              [decompile-derived] *
 9    param               0x11    Scope config selector 6              [decompile-derived] *
```

**\* Commands 0x0B-0x11 are internal display-queue selectors, NOT final
wire-level cmd_lo values.** These are translated by the dispatch handler
(`usart_tx_config_writer` at `0x08039734`) into different 16-bit TX words
before reaching USART2_DR. The osc firmware must use the translated
wire-level words, not these internal selector codes.

**Then the channel range/coupling block** (from `FUN_0800ba06`):
Believed to be wire-level based on direct USART2_DR xref tracing,
but a translation layer may exist. **[synthesized-model]**
```
10   0x00                0x07/0x0A  Channel prefix (0x07 if probe, 0x0A if no probe)
11   ch1_gain_param      0x1A    CH1 gain (vdiv_idx | probe_flag | disable_flag)
12   ch1_offset_param    0x1B    CH1 offset (128 - position, clamped 0-255)
13   ch2_gain_param      0x1C    CH2 gain
14   ch2_offset_param    0x1D    CH2 offset
15   coupling_param      0x1E    Coupling/BW limit (blocks until accepted)
```

**Then acquisition/timing** (from `FUN_0800bba6` and `FUN_0800bc00`):
Believed to be wire-level based on direct USART2_DR xref tracing,
but a translation layer may exist. **[synthesized-model]**
```
16   run_mode            0x20    Acquisition run mode (0=stop, 1=single, 2=normal, 3=auto)
17   sample_depth        0x21    Sample depth (blocks until accepted)
18   tb_prescaler        0x26    Timebase prescaler
19   tb_period           0x27    Timebase period
20   tb_mode             0x28    Timebase mode (blocks until accepted)
```

**Then the trigger block** (from `FUN_0800bb10`):
Believed to be wire-level based on direct USART2_DR xref tracing,
but a translation layer may exist. **[synthesized-model]**
```
21   0x00                0x07/0x0A  Trigger prefix
22   trigger_lsb         0x16    Trigger threshold LSB
23   0x00                0x17    Trigger threshold MSB
24   trigger_mode_byte   0x18    Trigger mode/edge select
25   0x00                0x19    Trigger holdoff (blocks until accepted)
```

**Timing between commands:** The osc firmware uses 10-20ms delays between
commands via `fpga_timed_send_cmd()`. Stock firmware uses the FreeRTOS
queue mechanism with `portMAX_DELAY` blocking on the final command of each
group, which provides natural inter-command spacing through task scheduling.

### 2.4 Parameter Encoding Reference

**Trigger mode byte** (cmd 0x18):
```
bit 0:   source (0=CH1, 1=CH2)
bit 4:   normal trigger mode
bit 5:   single trigger mode
bit 7:   falling edge (0=rising)
```

**Channel gain param** (cmds 0x1A, 0x1C):
```
bits [3:0]:  vdiv_idx (voltage range index)
bit 4:       10x probe attenuation
bit 7:       channel disabled
```

**Coupling param** (cmd 0x1E):
```
bits [1:0]:  CH1 coupling (00=DC, 01=AC)
bits [3:2]:  CH2 coupling
bit 4:       CH1 bandwidth limit
bit 5:       CH2 bandwidth limit
```

---

## Phase 3: Continuous Acquisition Loop (runtime)

Once scope mode is entered and the FPGA is configured, the acquisition
loop runs continuously in the `fpga_acquisition_task` FreeRTOS task.

### 3.1 Trigger Mechanism

The `input_and_housekeeping` function (called from the TMR3 ISR) monitors
the acquisition timer. When the timebase threshold is reached, it sends
**two** trigger items to `spi3_data_queue` back-to-back (ping-pong
double-buffering to prevent display tearing).

The acquisition task blocks on `xQueueReceive(spi3_data_queue, ...)`.

### 3.2 Pre-Acquisition Command (Transaction 1)

Before each bulk read, the stock firmware sends a command byte to arm
the FPGA's sample buffer:

```
CS_ASSERT  (PB6 LOW)
spi3_xfer(command_code)     // command_code = ~0x7F ^ voltage_range
                            // i.e., voltage_range with bits inverted
CS_DEASSERT (PB6 HIGH)
```

The `command_code` transform is: `int16_t command_code = ~0x7F ^ voltage_range;`
where `voltage_range` is from `meter_state[0x1C]`. For scope mode, this
reduces to roughly `0x80 | (range_index & 0x7F)`.

**The osc firmware currently does this** as `spi3_xfer(0x80 | voltage_range)`.
This appears correct.

### 3.3 Bulk Data Read (Transaction 2)

**Case 2 — Normal Scope Acquisition (1024 bytes):**
```
CS_ASSERT  (PB6 LOW)
spi3_xfer(0xFF)              → discard (command echo / arm read)
for i = 0 to 511:
    spi3_xfer(0xFF)          → CH1 sample [i]  (unsigned 8-bit)
    spi3_xfer(0xFF)          → CH2 sample [i]  (unsigned 8-bit)
CS_DEASSERT (PB6 HIGH)
```

Total: 1 + 1024 = 1025 SPI bytes per acquisition frame.
Data is interleaved: CH1[0], CH2[0], CH1[1], CH2[1], ...

**Case 3 — Dual Channel Acquisition (2048 bytes):**
```
CS_ASSERT  (PB6 LOW)
spi3_xfer(0xFF)              → discard
for i = 0 to 1023:
    spi3_xfer(0xFF)          → sample byte → stored interleaved
CS_DEASSERT (PB6 HIGH)
```

**Case 1 — Roll Mode (5 bytes per trigger):**
```
CS_ASSERT  (PB6 LOW)
spi3_xfer(0xFF) → CH1 ref
spi3_xfer(0xFF) → CH1 data
spi3_xfer(0xFF) → CH2 data
spi3_xfer(0xFF) → CH2 extra
spi3_xfer(0xFF) → last byte (stored at ms+0x5AF)
CS_DEASSERT (PB6 HIGH)
```

### 3.4 ADC Calibration

Raw 8-bit samples have a hardware DC offset of **-28 LSBs**:

```c
float raw_f  = (float)(uint8_t)raw_sample;
float norm   = (raw_f - 28.0f) / divisor;
float result = norm * display_range + dc_offset + bias;
// Clamp to [0, 255]
```

The osc firmware currently applies `FPGA_ADC_OFFSET = -28` as an integer
add. This is correct for basic operation.

### 3.5 Post-Acquisition

After each acquisition frame:
1. Apply VFP calibration (per-sample float math in stock firmware)
2. Store calibrated data in CH1/CH2 buffers
3. Increment frame counter at `ms[0xDB0]`
4. Signal display task to render

---

## Phase 4: Scope Heartbeat / Re-arm

The stock firmware re-arms acquisition by:

1. TMR3 ISR fires → calls `input_and_housekeeping`
2. Housekeeping increments acquisition timer
3. When timer reaches timebase threshold → sends trigger to SPI3 queue
4. Acquisition task reads data and returns to wait

The osc firmware drives this from the display task via
`fpga_trigger_scope_read()` which queues trigger events. This differs
from stock (which uses the TMR3 timer ISR) but achieves the same result.

The `fpga_scope_heartbeat()` function re-sends timebase commands:
```
fpga_timed_send_cmd(tb_prescaler, 0x26, 15);
fpga_timed_send_cmd(tb_period, 0x27, 15);
fpga_timed_send_cmd(tb_mode, 0x28, 20);
fpga_trigger_scope_read();
```

---

## Timing Constraints

| Constraint | Value | Source |
|-----------|-------|--------|
| SPI3 clock | 60 MHz (APB1/2) | Stock `spi_init` prescaler = /2 |
| USART2 baud | 9600 | Stock step 9 |
| SysTick delay after SPI3 enable | ~20ms | Stock phases 24-26 |
| Delay between handshake and post-handshake | ~10ms | Stock step 40 |
| Delay after bulk cal upload | ~50ms | Empirical (osc firmware) |
| Inter-command delay (boot) | 50ms conservative | Stock uses SysTick, varies |
| Inter-command delay (runtime) | 10-20ms | osc firmware `fpga_timed_send_cmd` |
| Watchdog timeout | ~2-5 seconds | IWDG prescaler /64, reload 1249 |
| Watchdog feed rate | every ~50ms | Every 11 calls to `input_and_housekeeping` |
| TMR3 ISR period | ~1ms (typical) | Drives USART exchange + button scan |

---

## Discrepancies Found Between osc Implementation and Stock

### 1. USART Boot Commands — Minor Difference (HARMLESS)

Stock sends: `0x01, 0x02, 0x06, 0x07, 0x08` (five commands).
osc sends:   `0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08` (eight commands).

The extra commands (0x03, 0x04, 0x05) are siggen-related setup. They
should not harm scope operation but are unnecessary at boot.

### 2. Scope Mode Entry — 0x0B-0x11 Are Internal Selectors, Not Wire Commands (LIKELY ISSUE)

The osc firmware sends commands like:
```c
fpga_timed_send_cmd(0x01, 0x0B, 15);   // cmd_hi = 0x01
fpga_timed_send_cmd(0x03, 0x0D, 15);   // cmd_hi = 0x03
fpga_timed_send_cmd(0x80, 0x0E, 15);   // cmd_hi = 0x80
```

The deeper issue is not just wrong `cmd_hi` values -- **0x0B through
0x11 are internal display-queue selector codes**, not final wire-level
USART2 command bytes. The stock `usart_tx_config_writer` at
`0x08039734` translates these internal selectors into different 16-bit
TX words before they reach USART2_DR. The osc firmware needs to use the
translated wire-level words, not pass these internal codes directly to
the UART frame builder.

The `cmd_hi` values labeled "empirically least-bad bank-2 defaults" in
the code comments compound this: even if the `cmd_hi` guesses were
correct, the `cmd_lo` values themselves are wrong for wire-level use.

**Recommendation:** Either:
- Capture stock USART2 TX with a logic analyzer during scope entry to
  see the actual wire-level words, OR
- Decompile the `usart_tx_config_writer` dispatch path to extract the
  selector-to-wire translation for each of 0x0B-0x11.

### 3. Acquisition Trigger Source — Different Architecture (POTENTIAL ISSUE)

Stock: TMR3 ISR → `input_and_housekeeping` → `spi3_data_queue` (driven by
hardware timer at ~1ms interval, sends TWO items for double-buffering).

osc: Display task → `fpga_trigger_scope_read()` → `spi3_acq_queue` (driven
by software from the rendering loop).

The display-driven approach means acquisition rate is limited by frame
rendering time, not by the FPGA's readiness. Stock's timer-driven approach
gives the FPGA a consistent, predictable trigger cadence. If the FPGA
expects periodic polling, the display-driven approach may cause stalls.

**Recommendation:** Consider adding a dedicated timer ISR or a simple
periodic task that triggers acquisition at a fixed rate independent of
the display.

### 4. Dual-Channel Read Order — Different From Stock (BUG)

osc firmware `case 4` (dual channel) reads 1024 bytes into CH1, then 1024
bytes into CH2. But stock firmware reads 2048 bytes **interleaved** (even
bytes = CH1, odd bytes = CH2) — same as case 2 but double the count.

```c
// Stock (correct):
for (int i = 0; i < 0x800; i += 2) {
    ms[0x5B0 + i]     = spi3_xfer(0xFF);  // CH1
    ms[0x5B0 + i + 1] = spi3_xfer(0xFF);  // CH2
}

// osc (wrong — reads sequentially, not interleaved):
for (int i = 0; i < 512; i++) ch1[i] = spi3_xfer(0xFF);
for (int i = 0; i < 512; i++) ch2[i] = spi3_xfer(0xFF);
```

This will produce garbled data in dual-channel mode because the FPGA sends
interleaved data regardless of how the MCU reads it.

### 5. Missing Watchdog Feed (POTENTIAL RESET)

The osc firmware does not implement watchdog feeding during scope mode. The
stock firmware's `input_and_housekeeping` feeds the IWDG every 11 calls
(~50ms). If the osc firmware's FPGA init enables the watchdog (stock step
49), the device will reset after ~2-5 seconds if the watchdog is not fed.

**Recommendation:** Either disable the watchdog at boot or implement
periodic feeding (`IWDG_KR = 0xAAAA`).

### 6. SPI3 DMA Register Accesses — Warehouse Finding

Ripcord warehouse shows `FUN_08027a50` configures DMA2 Channel 1 for SPI3:

```
Instruction       Register         Type    Name
──────────────────────────────────────────────────
0x08029a5a        0x40020444       READ    DMA2_CH1_CCR
0x08029a60        0x40020444       WRITE   DMA2_CH1_CCR  (disable channel)
0x08029a62        0x40020444       WRITE   DMA2_CH1_CCR  (clear config)
0x08029a66        0x40020448       WRITE   DMA2_CH1_CNDTR (transfer count)
0x08029a6a        0x4002044c       WRITE   DMA2_CH1_CPAR  (peripheral addr)
0x08029a6e        0x40020450       WRITE   DMA2_CH1_CMAR  (memory addr)
... [29 total DMA2 register accesses]
```

The stock firmware configures DMA2 for SPI3 bulk transfers. The osc
firmware uses polled SPI3 transfers only. This may explain why the
`SPI3_CTL1 |= 0x03` (DMA enable bits) was initially thought to interfere
— the stock firmware actually uses DMA for some transfer modes. However,
the `spi3_acquisition_task` in the decompilation shows polled transfers for
all 9 acquisition modes, so DMA may only be used during the bulk cal
upload or for a mode not yet identified.

### 7. GPIOC Accesses — Warehouse Finding

Ripcord warehouse shows 45 GPIOC register accesses in `FUN_08027a50`:
- 4 reads of GPIOC_IDR (0x40011008) early in the function (PC6 state polling?)
- Multiple writes to GPIOC_BOP and GPIOC_BCR throughout

The first access at instruction `0x08027ab6` is a WRITE to GPIOC_BCR
(clear). This occurs very early in the init function — before the SPI3
setup. It may clear PC6 LOW initially, with PC6 being set HIGH later in
step 19. The osc firmware does not explicitly clear PC6 before setting it
HIGH.

---

## What the osc Firmware Should Implement Next

### Immediate (unblock scope acquisition):

1. **Resolve the 0x0B-0x11 selector-to-wire translation.** These are
   internal selectors, not wire-level commands. Either:
   - Capture stock USART2 TX with a logic analyzer during scope entry, OR
   - Decompile the `usart_tx_config_writer` dispatch path at `0x08039734`
     to extract the translation for each selector code.

2. **Fix dual-channel interleaving** in `fpga_acquisition_task` case 4.
   Read interleaved, then de-interleave into separate CH1/CH2 buffers.

3. **Implement watchdog feeding** or confirm it is not enabled. Add
   `IWDG->kr = 0xAAAA;` in the TMR3 ISR or a periodic task.

### Medium-term (stable acquisition):

4. **Add a timer-driven acquisition trigger** instead of display-driven.
   Create a simple periodic task or use a hardware timer to send trigger
   events to `spi3_acq_queue` at a rate matching the current timebase.

5. **Implement the fast-timebase path** (Case 0). For timebase indices
   0-3 (fastest sweep), the FPGA needs a timebase configuration command
   instead of a bulk data read. The current firmware does not handle this.

6. **Implement roll mode** (Case 1) with the 300-sample circular buffer.

### Long-term (full parity with stock):

7. **Extract the timebase lookup table** at flash address `0x0804D833`.
   This maps timebase index (0x00-0x13) to sample count thresholds.

8. **Implement the full VFP calibration pipeline** using the stock's
   per-sample float math with the -28.0 offset constant and per-channel
   gain/offset coefficients loaded from the cal table.

9. **Add the probe compensation path** for roll mode when probe type
   value exceeds 0xDC.

---

## Quick Reference: SPI3 Transfer Cookbook

```c
/* Single byte exchange (all modes) */
static uint8_t spi3_xfer(uint8_t tx) {
    while (!(SPI3->sts & SPI_TDBE_FLAG)) {}
    SPI3->dt = tx;
    while (!(SPI3->sts & SPI_RDBF_FLAG)) {}
    return (uint8_t)SPI3->dt;
}

/* Normal scope read (Case 2, trigger_byte == 3) */
SPI3_CS_ASSERT();
spi3_xfer(0x80 | voltage_range);   // Transaction 1: arm FPGA
SPI3_CS_DEASSERT();

SPI3_CS_ASSERT();
spi3_xfer(0xFF);                    // Transaction 2: initial echo (discard)
for (int i = 0; i < 512; i++) {
    ch1_buf[i] = spi3_xfer(0xFF);  // CH1 sample
    ch2_buf[i] = spi3_xfer(0xFF);  // CH2 sample
}
SPI3_CS_DEASSERT();
```

---

## Files Referenced

| File | Location | Content |
|------|----------|---------|
| FPGA interaction analysis | `ripcord/notes/fpga_interaction_analysis.md` | xref-based peripheral access map |
| FPGA protocol spec | `osc/reverse_engineering/FPGA_PROTOCOL_COMPLETE.md` | Full command table |
| FPGA boot sequence | `osc/reverse_engineering/analysis_v120/FPGA_BOOT_SEQUENCE.md` | 53-step boot timeline |
| FPGA task analysis | `osc/reverse_engineering/analysis_v120/FPGA_TASK_ANALYSIS.md` | 9 SPI3 modes |
| Annotated FPGA task | `osc/reverse_engineering/analysis_v120/fpga_task_annotated.c` | Decompiled C |
| Bulk cal resolution | `osc/reverse_engineering/analysis_v120/spi3_bulk_cal_resolved.md` | H2 table analysis |
| Remaining unknowns | `osc/reverse_engineering/analysis_v120/remaining_unknowns.md` | Clock tree, DMA, ADC |
| osc firmware FPGA driver | `osc/firmware/src/drivers/fpga.c` | Current implementation |
| Next session plan | `osc/firmware/NEXT_SESSION_PLAN.md` | Phase 4 scope acquisition |
