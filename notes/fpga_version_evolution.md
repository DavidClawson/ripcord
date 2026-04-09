# FPGA Interaction Evolution Across Firmware Versions

Generated 2026-04-08 from warehouse queries against all four stock firmware builds.

## Executive summary

The V1.0.3-to-V1.0.7 transition was a **complete architectural rewrite of the
FPGA acquisition path**. V1.0.3 used USART2-only communication with the FPGA
(8 register accesses, 1 function, zero SPI3/DMA2 usage). V1.0.7 introduced the
monolithic master-init function with SPI3-based high-speed data transfer (206
SPI3 accesses, 29 DMA2 accesses, 20 USART2 accesses). From V1.0.7 onward, the FPGA-facing
peripheral surface is **frozen** -- identical SPI3, USART2, DMA2, GPIOB, and
GPIOC register access counts in every subsequent version. The changes between
V1.0.7/V1.1.2/V1.2.0 are in non-peripheral code paths (UI, string handling,
display rendering); there is no evidence of peripheral-surface changes.

**Caveat:** Identical register access counts are evidence of a stable hardware
surface. They do not prove that higher-level state choreography, selector
translation, or queue usage is semantically identical across versions.

## Peripheral access totals per version

| Version    | SPI3 | USART2 | DMA2 | DMA1 | GPIOB | GPIOC |
|------------|------|--------|------|------|-------|-------|
| stock_v103 |    0 |      8 |    0 |   32 |    13 |     0 |
| stock_v107 |  206 |     28 |   29 |   32 |    43 |    60 |
| stock_v112 |  206 |     28 |   29 |   66 |    41 |    72 |
| stock_v120 |  206 |     28 |   29 |   66 |    41 |    71 |

Key observations:
- **SPI3, DMA2**: Zero in V1.0.3, introduced in V1.0.7, unchanged after.
- **USART2**: Present in V1.0.3 (8 refs in one function), expanded to 28 in V1.0.7+.
  The extra 20 refs are all in the master init; the original 8-ref USART2 helper persists.
- **GPIOC**: Zero in V1.0.3, introduced in V1.0.7 (PC6 for scope chip-select or
  data-ready signaling). Slight variation between V1.0.7 (60) and V1.1.2+ (71-72)
  comes from the 13276-byte display/rendering function added in V1.1.2.
- **DMA1**: 32 in V1.0.3 and V1.0.7; doubles to 66 in V1.1.2+. DMA1 is not on
  the FPGA path (it handles other transfers), but its increase suggests the i18n
  or display code added DMA-backed memory operations.

## FPGA-touching function count per version

| Version    | Functions touching SPI3/USART2/DMA2/GPIOC |
|------------|-------------------------------------------|
| stock_v103 | 1 (USART2 only)                           |
| stock_v107 | 8                                         |
| stock_v112 | 8                                         |
| stock_v120 | 7                                         |

V1.0.3 has a single 304-byte function that accesses 8 USART2 registers. This
is likely a simple command/response interface -- send a byte, poll for response.
No high-speed bulk transfer capability.

## The master init function: evolution

This is the monolithic function that contains the SPI3 protocol engine, DMA2
setup, GPIO control, and USART2 command sequences -- the entire FPGA interaction
in a single function.

| Version | Address    | Size   | BBs  | Total xrefs | Calls out | Peripheral xrefs |
|---------|------------|--------|------|-------------|-----------|-------------------|
| V1.0.3  | (none)     | --     | --   | --          | --        | --                |
| V1.0.7  | 0x0802447C | 14,650 | 442  | 2,098       | 114       | SPI3:206 USART2:20 DMA2:29 GPIOB:14 GPIOC:31 |
| V1.1.2  | 0x08027A30 | 15,128 | 453  | 2,126       | 129       | SPI3:206 USART2:20 DMA2:29 GPIOB:14 GPIOC:31 |
| V1.2.0  | 0x08027A50 | 15,346 | 452  | 2,207       | 129       | SPI3:206 USART2:20 DMA2:29 GPIOB:14 GPIOC:31 |

Every peripheral register access count is **identical** across V1.0.7, V1.1.2,
and V1.2.0. There is no evidence of peripheral-surface changes. What changed:

- **V1.0.7 to V1.1.2**: +478 bytes, +11 basic blocks, +15 callsites. The master
  init grew to call more helper functions (likely new UI/display code for i18n).
  Body hash changed.
- **V1.1.2 to V1.2.0**: +218 bytes, -1 basic block, same 129 callsites. The
  +81 non-peripheral xrefs indicate small logic changes (conditionals, state
  transitions) but zero peripheral changes. Body hash changed.

## SPI3 register access pattern (frozen since V1.0.7)

All three post-V1.0.3 versions show identical SPI3 register access from the
master init:

| Register   | Offset | Access           | Count |
|------------|--------|------------------|-------|
| SPI3_CR1   | +0x00  | 1 READ, 1 WRITE  |     2 |
| SPI3_CR2   | +0x04  | 2 READ, 2 WRITE  |     4 |
| SPI3_SR    | +0x08  | 160 READ         |   160 |
| SPI3_DR    | +0x0C  | 20 READ, 20 WRITE|    40 |

The 160 SR reads are status polling loops (busy-wait on SPI transfer complete).
The 20 DR read/write pairs are individual byte-level SPI transactions embedded
in the master init (not DMA-driven -- the DMA2 setup is separate and handles
bulk waveform data). This means the master init contains roughly 20 discrete
SPI command sequences that poll-wait on the status register ~8 times each.

## The second large function (display/UI, added V1.1.2)

| Version | Address    | Size   | BBs | body_hash changed? |
|---------|------------|--------|-----|--------------------|
| V1.0.7  | (none >13k)|  --   | --  | --                 |
| V1.1.2  | 0x0801DEB0 | 13,276 | 648 | --                 |
| V1.2.0  | 0x0801DE98 | 13,276 | 648 | YES (different hash)|

Same size, same basic block count, but different body hash. This function
touches GPIOC (19 refs in V1.1.2, 19 in V1.2.0) and timer/I2C peripherals
(0x40007404, 0x40007408, 0x40001C34) but **not** SPI3, USART2, or DMA2.
It is not part of the FPGA data path. Its GPIOC access is likely display
chip-select or backlight control via PC6. The body hash change between
V1.1.2 and V1.2.0 with identical size/structure suggests constant or
address changes (e.g., string pointer relocation from i18n), not logic changes.

## Stable structural functions (UI/rendering layer)

Two functions have identical size and basic block count across all four versions
but different body hashes in every version:

| Function   | Size  | BBs | Present in |
|------------|-------|-----|------------|
| 5748-byte  | 5,748 | 536 | All 4 versions |
| 6632-byte  | 6,632 | 276 | All 4 versions |

These are structurally frozen (same control flow graph) but their body bytes
change each version, consistent with string/constant pointer updates as the
firmware grows. They are likely the core rendering/menu functions.

## What FNIRSI was iterating on

### V1.0.3 to V1.0.7: The big rewrite

This was the fundamental architecture change. V1.0.3 talked to the FPGA over
USART2 only -- a serial command interface at baud rate, no bulk transfer. V1.0.7
introduced:

1. **SPI3 as the primary data bus** -- high-speed clocked transfer replacing
   USART2 for waveform data
2. **DMA2 for bulk waveform reads** -- 29 DMA2 register accesses for
   autonomous memory-to-peripheral and peripheral-to-memory transfers
3. **GPIOC (PC6) as a control/handshake line** -- not present in V1.0.3
4. **The monolithic master init** -- 14,650 bytes of initialization and
   acquisition state machine that did not exist in V1.0.3

The 18 new functions (269 to 287) are almost entirely new FPGA-interaction and
UI code. The function count increase (+18) with the size increase (one 14.6kB
function alone) shows this was not incremental -- it was a rewrite.

### V1.0.7 to V1.1.2: UI expansion, FPGA protocol untouched

+19 functions (287 to 306). The master init grew +478 bytes. The 13,276-byte
display function appeared. DMA1 usage doubled (32 to 66). GPIOC references
increased. None of this touched SPI3/USART2/DMA2 access patterns. This was
the internationalization release.

### V1.1.2 to V1.2.0: Minor patch, FPGA protocol untouched

-1 function (306 to 305). Master init grew +218 bytes (non-peripheral xrefs
only). The 13,276-byte display function changed body hash but not size/structure.
GPIOC dropped by 1 reference. This was a bugfix/polish release.

## Implications for the osc project

1. **The FPGA-facing peripheral surface has been stable since V1.0.7.** If you
   are implementing scope acquisition, the V1.0.7 master init is a strong
   reference for the hardware access pattern. Later versions show no evidence
   of peripheral-surface changes. However, higher-level state choreography,
   selector translation, or queue usage may differ in ways not visible in
   register access counts.

2. **The SPI3 access pattern is the protocol specification.** 20 discrete
   SPI command sequences with status polling, plus DMA2-based bulk transfer.
   These 20 commands are likely the scope's configuration registers (timebase,
   trigger level, coupling, etc.) and acquisition start/stop commands.

3. **V1.0.3's USART2-only interface may still be useful** as a diagnostic/debug
   path. The 304-byte USART2 function persists in all versions (with body hash
   changes), suggesting FNIRSI kept the serial command channel even after adding
   SPI3.

4. **The timing/sequencing that matters is in the master init's state machine.**
   The 442-453 basic blocks with 206 SPI3 accesses encode the ordering of
   SPI transactions, GPIO assertions, and DMA setup. Extracting this sequence
   from the Ghidra decompilation of V1.2.0's FUN_08027a50 gives the
   peripheral-level interaction pattern, though higher-level dispatch semantics
   require separate analysis.

5. **If you're hitting timing issues, look at the poll loops.** The 160 SPI3_SR
   reads (8 per command) are busy-wait poll sequences. If your implementation
   is missing these or timing them differently, that's the most likely divergence
   point.
