# FPGA Interaction Analysis: stock V1.2.0 Firmware

Generated 2026-04-08 from warehouse queries against `build/stock_v120/tables/`.

## Provenance key

Every major claim in this document is tagged with one of:

- **[hardware-confirmed]** — verified by bench measurement in the osc project
- **[direct-xref]** — observed directly in ripcord warehouse xref queries
- **[decompile-derived]** — from Ghidra pseudo-C decompilation
- **[synthesized-model]** — cross-referenced from multiple sources; plausible but not independently confirmed
- **[low-confidence-hypothesis]** — speculative, needs further evidence

## Summary

The stock V1.2.0 firmware (305 functions, 18183 xrefs) contains **67 functions**
that can transitively reach FPGA interface hardware, organized in a clear
four-layer architecture. The FPGA interaction is dominated by **one monster
function** (`FUN_08027a50`, 15346 bytes) that directly touches all five
FPGA-relevant peripherals and has no callers in the call graph -- it is
likely a monolithic master-init / BSP owner with runtime-adjacent behavior. **[direct-xref]**

## Peripheral surface

The MCU-FPGA interface uses these peripherals:

| Peripheral | Base addr    | Registers accessed         | Functions |
|------------|-------------|----------------------------|-----------|
| SPI3       | 0x40003C00  | CR1, CR2, SR, DR           | 1 (FUN_08027a50 only, 206 accesses) |
| USART2     | 0x40004400  | SR, DR, BRR, CR1, CR2      | 2         |
| GPIOB BSRR/BRR | 0x40010C10/14 | PB11 set/reset       | 10        |
| GPIOC IDR/BSRR/BRR | 0x40011008/10/14 | PC6 read/set/reset | 6   |
| DMA1       | 0x40020000  | ISR, IFCR, CCR/CNDTR/CPAR/CMAR | 2    |
| DMA2       | 0x40020400  | IFCR                       | 1         |

`FUN_08027a50` also configures: TIM2, TIM3, TIM8, RCC (clock enables),
and accesses GPIOD, GPIOG registers -- this is the system BSP
initialization path (confirmed by string reference `"../../../project/bsp_sys.c"`).

## Layered architecture

### Depth 0: Direct hardware access (17 functions)

| Function       | Size  | BB  | Peripherals touched            | Likely role |
|----------------|-------|-----|-------------------------------|-------------|
| FUN_08027a50   | 15346 | 452 | SPI3, USART2, DMA2, PB11, PC6 | **Monolithic master-init / BSP owner** (refs `bsp_sys.c`, `dvom_TX/RX`, `Timer1/2`, `display`) **[direct-xref]** |
| FUN_0801de98   | 13276 | 648 | PC6 (+ I2C2, DAC, GPIOD)      | **Large secondary owner touching scope-adjacent state** (no callers, ISR or task entry; task role not confirmed) **[direct-xref]** |
| FUN_080263bc   |  2436 |  94 | PC6                            | Scope-related helper |
| FUN_0800f908   |   950 |  16 | PC6 (reads GPIOC_IDR)          | PC6 state polling **[direct-xref]** |
| FUN_08006c78   |   840 |  71 | PC6 (reads GPIOC_IDR + GPIOG_IDR) | GPIO state reader |
| FUN_08005a58   |   506 |  25 | PB11                           | GPIO pin setup |
| FUN_080058a4   |   422 |  26 | PC6 (GPIOC BSRR+BRR)          | **PC6 toggle driver** (called by 08027a50, 0801de98, 08005c60) **[direct-xref]** |
| FUN_08006670   |   370 |   6 | DMA1                           | **DMA1 transfer setup** (no callers = ISR) |
| FUN_0803fee0   |   358 |   1 | DMA1                           | **DMA1 channel config** (1 basic block = inline setup, called by FUN_0800d014 et al.) |
| FUN_0802b7b4   |   304 |  25 | USART2 (SR, DR, CR1)           | **USART2 send/receive** (reads SR, reads/writes DR, no callers = ISR or polled) |
| FUN_08032f48   |   256 |   1 | PB11                           | PB11 bit-bang (called by FUN_08027a50) |
| FUN_0803336c   |   118 |   5 | PB11                           | PB11 bit-bang step |
| FUN_08033048   |   112 |   5 | PB11                           | **GPIOB PB11 control** (called by 14 functions) **[direct-xref]** |
| FUN_08032ee8   |    96 |   1 | PB11                           | PB11 bit-bang step |
| FUN_0803311c   |    78 |   5 | PB11                           | PB11 bit-bang step |
| FUN_08032e9c   |    76 |   1 | PB11                           | PB11 bit-bang step |
| FUN_08033344   |    38 |   1 | PB11                           | PB11 bit-bang step |

### Depth 1: FPGA driver layer (21 functions)

These call depth-0 functions but don't touch FPGA registers directly.
Key members:

- **FUN_08005c60** (1634 bytes, 116 BB) -- calls FUN_080058a4 (SPI CS).
  Called by FUN_0801de98. Likely SPI3 transaction wrapper.
- **FUN_0800d014** (322 bytes) -- calls FUN_0803fee0 (DMA1 config).
  No callers = DMA completion handler or initialization.
- **FUN_0800d314**, **FUN_0800d6e8**, **FUN_0800da94** (222-234 bytes each)
  -- all call FUN_0803fee0 (DMA1 config). Probably DMA channel
  configuration variants for different transfer types.

### Depth 2: Orchestrator layer (19 functions)

Call driver-layer functions. These include display update routines,
measurement processing, and data formatting functions.

### Depth 3: Task level (10 functions)

Outermost application code that indirectly depends on FPGA data.

## The two entry points

The firmware has **two mega-functions with zero callers** that directly
access FPGA hardware:

1. **FUN_08027a50** (0x08027a50, 15346 bytes, 452 basic blocks)
   - Touches ALL FPGA peripherals: SPI3, USART2, DMA2, PB11, PC6 **[direct-xref]**
   - Also configures: TIM2, TIM3, TIM8, RCC, GPIOD, GPIOG **[direct-xref]**
   - String refs: `bsp_sys.c`, `dvom_TX`, `dvom_RX`, `Timer1`, `Timer2`, `display` **[direct-xref]**
   - Calls 43 functions **[direct-xref]**
   - **This is a monolithic master-init / BSP owner with runtime-adjacent
     behavior.** The `bsp_sys.c` source file reference and the combination
     of clock setup (RCC), peripheral init (SPI3, USART2, timers), and
     runtime-adjacent references (dvom_TX/RX, display) all in one function
     indicate a monolithic BSP pattern. Whether it also contains the main
     processing loop or only initialization is not confirmed from xrefs
     alone. **[synthesized-model]**

2. **FUN_0801de98** (0x0801de98, 13276 bytes, 648 basic blocks)
   - Touches: PC6 (GPIOC), GPIOD, I2C2, DAC **[direct-xref]**
   - Calls 27 functions including FUN_080058a4 (PC6 toggle) and FUN_08005c60 **[direct-xref]**
   - No callers = separate task entry or interrupt handler **[direct-xref]**
   - **Large secondary owner touching scope-adjacent state.** It accesses
     PC6, I2C2, and the DAC, but there is not enough evidence from xrefs
     alone to confirm it is the acquisition task. **[synthesized-model]**

## USART2 (FPGA command interface) path

Only two functions touch USART2 registers:

1. **FUN_08027a50** -- configures USART2 (writes CR1, CR2, BRR) and
   does inline command I/O. 20 USART2 register accesses.
2. **FUN_0802b7b4** (0x0802b7b4, 304 bytes) -- the USART2 send/receive
   primitive. Reads SR (status), reads/writes DR (data), reads/writes CR1.
   Has zero callers in the call graph, so it is either:
   - A USART2 interrupt handler (most likely: reads SR then DR is
     the classic UART ISR pattern)
   - Called via function pointer
   - Calls FUN_0803f09c (316 bytes) which may be the command parser

## SPI3 (bulk ADC data) path

**Only FUN_08027a50 directly accesses SPI3 registers in the xref data**
(206 accesses: 183 reads, 23 writes across CR1, CR2, SR, DR). **[direct-xref]**
This is an xref observation, not a semantic conclusion -- it means no
other function contains hard-coded SPI3 register addresses, but does not
rule out indirect access via function pointers, DMA, or runtime-computed
addresses. Observable implications:

- SPI3 configuration and inline polled transfers are contained within
  this function based on the xref surface
- The 183 reads of SPI3 registers suggest polled SPI transfers
  (repeatedly reading SR for TXE/RXNE flags, reading DR for data)
- DMA2 is also configured in this function, so some transfers may
  be DMA-based while others are polled

## PB11 (GPIOB control) cluster

10 functions touch GPIOB_BSRR/BRR. **[direct-xref]** The small functions
(38-256 bytes) form a coordinated PB11 control cluster:

```
FUN_080332ac (152B) -> FUN_0803336c (118B) -> FUN_0803311c (78B)
                                            -> FUN_08033344 (38B)
FUN_08032e9c (76B) -> FUN_0803311c
                    -> FUN_08033344
FUN_08032f48 (256B) -> FUN_08032ee8 (96B)     [called by FUN_08027a50]
FUN_08033048 (112B)                            [called by 14 functions]
```

`FUN_08033048` is the most-called GPIOB function (14 callers including
display and data processing functions). **[direct-xref]** PB11 is
hardware-confirmed as an FPGA active-mode control line. **[hardware-confirmed]**
The high fan-in from display-adjacent functions may indicate PB11 is
toggled as part of FPGA mode transitions, not necessarily as a bit-banged
SPI data line. The earlier "bit-bang SPI for display" hypothesis is
withdrawn pending further evidence.

## PC6 (enable/gate line) analysis

6 functions read or write GPIOC for PC6. **[direct-xref]** PC6's role
is an enable/gate line; it is not the primary SPI3 chip-select (PB6
serves that role). **[hardware-confirmed]**

- **FUN_080058a4** (422B): PC6 toggle driver. Writes both BSRR (set)
  and BRR (reset). Called by the two main FPGA-touching functions and
  the SPI transaction wrapper. **[direct-xref]**
- **FUN_08006c78** (840B): Reads GPIOC_IDR -- polling PC6 state or
  reading other GPIOC pins.
- **FUN_0800f908** (950B): Also reads GPIOC_IDR.
- **FUN_08027a50**, **FUN_0801de98**, **FUN_080263bc**: Direct GPIOC
  manipulation within the main task functions.

## Scope acquisition path (reconstructed)

Based on the call graph and peripheral access patterns, the scope
acquisition path from entry point to SPI3 DMA receive is:

```
FUN_08027a50 (bsp_sys.c master-init / BSP owner, 15346B)
  |
  +-- Configures RCC clocks for all peripherals
  +-- Configures SPI3 (CR1, CR2), USART2 (CR1, CR2, BRR)
  +-- Configures TIM2, TIM3, TIM8 for ADC timing
  +-- Configures DMA2 for SPI3 transfers
  +-- Calls FUN_080058a4 to assert/deassert SPI3 CS (PC6)
  +-- Calls FUN_08006c78 to read GPIO state
  +-- Calls FUN_08032f48 for bit-bang SPI (PB11) to display
  +-- Polls SPI3_SR / reads SPI3_DR for data (183 reads)
  +-- Sends FPGA commands via USART2_DR

FUN_0801de98 (large secondary owner, 13276B, separate entry point)
  |
  +-- Calls FUN_08005c60 (SPI transaction wrapper, 1634B)
  |     +-- Calls FUN_080058a4 (SPI CS toggle)
  +-- Calls FUN_080058a4 directly (additional CS operations)
  +-- Reads GPIOC_IDR (PC6 state)
  +-- Writes GPIOC_BSRR/BRR (PC6 control)
  +-- Accesses I2C2 (DAC/offset control?)
  +-- Accesses DAC (0x40001C34)

FUN_0802b7b4 (USART2 ISR, 304B, separate entry point)
  |
  +-- Reads USART2_SR (check flags)
  +-- Reads/writes USART2_DR (receive/transmit byte)
  +-- Calls FUN_0803f09c (command parser?, 316B)
```

## Key findings

1. **The firmware is monolithic.** A single 15KB function (`FUN_08027a50` =
   `bsp_sys.c`) handles BSP init and peripheral configuration for all FPGA
   communication. Whether it also contains runtime processing or only
   initialization cannot be determined from xrefs alone. This is the
   function to decompile first. **[direct-xref]**

2. **SPI3 xrefs appear in only one function.** All 206 SPI3 register
   accesses in the xref data are in `FUN_08027a50`. This is an xref
   observation -- it does not rule out indirect access paths. There is
   no SPI3 HAL abstraction visible in the xref surface. **[direct-xref]**

3. **USART2 has a clear ISR pattern.** `FUN_0802b7b4` (304B) is the USART2
   interrupt handler: it reads SR, reads/writes DR, and calls a downstream
   parser. The baud rate and mode are configured in `FUN_08027a50`.

4. **PB11 is an FPGA active-mode control line** **[hardware-confirmed]**
   touched by 10 functions in a coordinated control cluster. The earlier
   "bit-bang SPI for display" hypothesis is withdrawn. **[direct-xref]**

5. **Two independent entry points.** `FUN_08027a50` and `FUN_0801de98`
   are both zero-caller mega-functions that touch FPGA hardware.
   **[direct-xref]** Their exact runtime roles (main loop vs task vs ISR)
   are not confirmed from xrefs alone. **[synthesized-model]**

6. **67 functions (22% of the firmware) are in the FPGA interaction
   cone.** The call tree fans out: 17 direct HW -> 21 drivers ->
   19 orchestrators -> 10 task-level.

## Priority decompilation targets

For understanding the MCU-FPGA protocol:

| Priority | Function     | Size  | Why |
|----------|-------------|-------|-----|
| 1        | FUN_08027a50 | 15346 | Master-init / BSP owner: all FPGA init + SPI3 xref surface |
| 2        | FUN_0802b7b4 |   304 | USART2 ISR: FPGA command protocol |
| 3        | FUN_0803f09c |   316 | Called by USART2 ISR: command parser |
| 4        | FUN_0801de98 | 13276 | Large secondary owner: PC6 + I2C/DAC (task role unconfirmed) |
| 5        | FUN_080058a4 |   422 | PC6 toggle driver |
| 6        | FUN_08006670 |   370 | DMA1 ISR |
