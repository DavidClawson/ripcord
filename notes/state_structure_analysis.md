# State Structure Access Analysis — FNIRSI 2C53T V1.2.0

Date: 2026-04-08
Source: `scripts/query < notes/queries/state_structure.sql`

## Summary

The ~4KB global state structure at `0x200000F8` is accessed by ~40
functions across 710 distinct (offset, ref_type) pairs. Three
functions dominate the write side, and the writer-reader data flow
reveals a clear architecture.

## Key Functions

### Writers (by distinct offsets written)

| Function | Addr | Size | Offsets Written | Write Refs | Role |
|----------|------|------|-----------------|------------|------|
| FUN_08027a50 | 0x08027A50 | 15346 | 171 | 252 | **State-commit + FPGA command dispatcher.** Sole USART2 TX writer (registers 0x40004408-0x40004410). Also reads 48 state offsets. Only caller is itself (recursive or main-loop entry). |
| FUN_080236f8 | 0x080236F8 | — | 97 | 168 | Bulk state initializer / config restore. |
| FUN_080263bc | 0x080263BC | — | 24 | 24 | Calibration / probe detect writer. Also reads 164 offsets (second-heaviest reader). |
| FUN_08026e14 | 0x08026E14 | — | 23 | 93 | Concentrated writer (93 writes to 23 offsets — likely array/struct init). |
| FUN_0801de98 | 0x0801DE98 | 13276 | 18 | 45 | **scope_main_fsm** analog. Reads 274 state offsets, writes 45. |

### Readers (by total refs)

| Function | Total Reads | Distinct Offsets | Role |
|----------|-------------|------------------|------|
| FUN_0801de98 | 274 | 62 | Primary scope FSM — reads nearly every runtime field. |
| FUN_080236f8 | 177 | 125 | Reads widely (likely for save/restore). |
| FUN_080263bc | 162 | 164 | Calibration reader — touches the most distinct offsets of any function. |
| FUN_08024930 | 143 | 15 | Concentrated reader (143 reads from 15 offsets — display/waveform render). |
| FUN_08027a50 | 48 | 178 | Reads state before committing to USART2 TX. |

## Scope-Critical Offset Analysis

### +0xF68 (0x20001060) — system_mode

**Writers:** FUN_08006c78, FUN_08027a50
**Readers:** FUN_0800d014, FUN_0800d314, FUN_0800d6e8, FUN_0800da94, FUN_0800f908, FUN_0801de98, FUN_08027a50

FUN_08006c78 manipulates this byte with bitmask operations:
- `DAT_20001060 | 0x80` — sets bit 7 as a flag
- `DAT_20001060 & 0x7f` — clears bit 7, preserving mode in bits 0-6
- Checks `(DAT_20001060 - 1 < 5) || (DAT_20001060 == 9)` — mode values 1-5 and 9 are scope-related
- On mode match, sends byte `0x22` and `0x23` via FUN_0803ecf0 (likely RTOS queue send)
- Calls `FUN_080263bc(0x55)` during a "powered" state transition

FUN_08027a50 writes this byte as part of its massive state-commit
operation, which also touches USART2 directly.

### +0xF69 (0x20001061) — mode_transition_flags

**Writer:** FUN_08027a50 (sole writer)
**Readers:** FUN_0800d014, FUN_08012988

### +0xF6A (0x20001062) — scope_ui_state_flags

**Writer:** FUN_08027a50 (sole writer)
**Readers:** FUN_0800fde0 (6 reads), FUN_0801279c, FUN_08019d58

### +0xF6B (0x20001063) — mode_flags

**No writers detected in xrefs.** 6 reads by FUN_08012988.
This byte may be written through a wider (16/32-bit) store that
Ghidra attributes to a different address, or through a computed
register-indirect store that static xref analysis misses.

### +0xE1A..+0xE1D (0x20000F12..0x20000F15) — panel staging

Sparse xref coverage:
- +0xE1B: WRITE by FUN_08027a50 only
- +0xE1C: READ by FUN_0801c19c only (2 reads)
- +0xE1A, +0xE1D: **No xrefs.** Likely accessed through computed offsets.

### +0x355 (0x2000044D) — flag

**No xrefs at this address.** The nearest xrefs are:
- +0x354 (0x2000044C): READ+WRITE by FUN_080263bc and FUN_08027a50
- +0x352 (0x2000044A): READ by FUN_080263bc, WRITE by FUN_0801de98 and FUN_08027a50
- +0x353 (0x2000044B): READ by FUN_080263bc, WRITE by FUN_0801de98

This flag is likely accessed through register-indirect addressing
(e.g., `r9 + r_offset` where `r_offset` is computed at runtime)
rather than a literal address that Ghidra can resolve statically.

## Writer -> Reader Data Flow (Top Pairs)

The strongest data flow channels through the state structure:

| Writer | Reader | Shared Offsets |
|--------|--------|----------------|
| FUN_08027a50 | FUN_080263bc | 154 |
| FUN_08027a50 | FUN_0801de98 | 24 |
| FUN_08038078 | FUN_0801de98 | 12 |
| FUN_08027a50 | FUN_080212ec | 11 |
| FUN_08038078 | FUN_080382f8 | 10 |
| FUN_080263bc | FUN_08027a50 | 9 |

The dominant pattern is **FUN_08027a50 writes -> FUN_080263bc reads**
across 154 shared offsets. This is the state-commit -> calibration
pipeline.

## USART2 TX Path

Only two functions access USART2 peripheral registers (0x40004400-0x40004410):

| Register | Function | Direction |
|----------|----------|-----------|
| 0x40004400 (USART2_STS) | FUN_0802b7b4 | READ (status polling) |
| 0x40004404 (USART2_DT) | FUN_0802b7b4 | READ + WRITE (data register) |
| 0x40004408 (USART2_BAUDR) | FUN_08027a50 | READ + WRITE (baud rate) |
| 0x4000440C (USART2_CTRL1) | FUN_08027a50, FUN_0802b7b4 | READ + WRITE (control) |
| 0x40004410 (USART2_CTRL2) | FUN_08027a50 | READ + WRITE |

**FUN_08027a50 is the USART2 control plane** (baud, control registers).
**FUN_0802b7b4 is the USART2 data plane** (status polling + byte TX/RX).

The scope data flow for preset bytes is:
```
FUN_08006c78 / FUN_08027a50
    |-- write state[0xF68] (system_mode)
    v
FUN_0800d014, FUN_0800d314, FUN_0800d6e8, FUN_0800da94
    |-- read state[0xF68], branch on mode
    v
    (scope UI draw helpers -- rendering decisions)

FUN_08027a50
    |-- write state[0xF69, 0xF6A, 0xF6B]
    |-- read state for FPGA config
    |-- write USART2 registers (FPGA command TX)
    v
FUN_0802b7b4
    |-- USART2 data register byte TX/RX
```

FUN_08027a50 is both the state writer AND the USART2 command sender.
The state write and FPGA command happen in the same function, not
through a writer->reader->TX chain. The "readers" of the preset bytes
are UI draw functions, not FPGA command senders.
