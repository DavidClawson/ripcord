# Feedback Query Results (2026-04-08)

Executed against the ripcord warehouse and cross-referenced with osc project
analysis files. See `osc_project_feedback_2026_04_08.md` for the motivating
questions.

---

## 1. Final TX Word Trace: Complete Wire-Level Commands for Scope Entry

### Data flow confirmed

The three-layer dispatch is confirmed by `gap_functions_annotated.c` and
`SCOPE_CMD_PARAMETERS.md`:

```
Layer 1: Internal selectors (1-byte) → usart_cmd_queue (0x20002D6C)
Layer 2: Dispatch handlers translate → 16-bit TX words
Layer 3: dvom_TX task → usart_tx_queue (0x20002D74) → USART2 frame
```

The dvom_TX task (`fpga_usart_tx_task` at 0x08037400) dequeues a 2-byte
item from `usart_tx_queue`, places:
- Low byte → TX frame position [3] (command code)
- High byte → TX frame position [2] (parameter)
- Checksum = buf[2] + buf[3] → position [9]

The TX frame on the wire is: `[55][AA][param][cmd][00][00][00][00][00][cksum]`

Therefore: the 16-bit words enqueued to `usart_tx_queue` ARE the final
wire-level (cmd_hi, cmd_lo) pairs. Anything that reaches this queue goes
directly to USART2_DR with no further translation.

### Complete table of confirmed final TX words

#### Static raw TX words (direct `strh` writes to staging variable)

| TX word  | cmd_hi | cmd_lo | Source address | Context                     | Evidence |
|----------|--------|--------|---------------|-----------------------------|----------|
| `0x02A0` | 0x02   | 0xA0   | 0x0800679A    | Mode entry / scope arm      | [decompile-derived] |
| `0x0501` | 0x05   | 0x01   | 0x080060DA    | Scope selector seed         | [decompile-derived] |
| `0x0503` | 0x05   | 0x03   | 0x080067CE    | Scope steady-state/activate | [decompile-derived] |
| `0x0508` | 0x05   | 0x08   | 0x080033DC    | Scope/meter config          | [decompile-derived] |
| `0x0509` | 0x05   | 0x09   | 0x08003BB6    | Meter start                 | [decompile-derived] |
| `0x0514` | 0x05   | 0x14   | 0x08005B8A    | Meter variant               | [decompile-derived] |

#### Dynamic scope words (FUN_08006120, cmd_hi always = 0x05)

Built at runtime when `DAT_20001060 == 1` (meter active). Selector is
`DAT_20001025` (meter_mode), side is `DAT_2000102E` (meter_overload).

| meter_mode | side=0 (CH1) | side=1 (CH2) | Valid selector mask: `(1<<mode) & 0xC6` |
|------------|-------------|-------------|------------------------------------------|
| 1          | `0x050C`    | `0x050D`    | Config pair A                            |
| 2          | `0x050E`    | `0x0517`    | Config pair B                            |
| 6          | `0x0511`    | `0x0516`    | Config pair D                            |
| 7          | `0x0510`    | `0x0515`    | Config pair C                            |

#### Gap function wire-level cmd_lo values (cmd_hi from config_writer)

These are queued to `usart_tx_queue` by the gap functions. The cmd_hi byte
is computed by `usart_tx_config_writer` (0x08039734) from current scope
state before the gap function writes cmd_lo. These cmd_lo values are
final wire-level -- they go directly to the TX frame.

| Group           | Function      | Size | cmd_lo values                    | Prefix cmd_lo |
|-----------------|---------------|------|----------------------------------|---------------|
| Channel ranges  | FUN_0800BA06  | 102B | 0x1A, 0x1B, 0x1C, 0x1D, 0x1E   | 0x07 (CH1) or 0x0A (CH2) |
| Trigger         | FUN_0800BB10  |  84B | 0x16, 0x17, 0x18, 0x19          | 0x07 or 0x0A |
| Acquisition     | FUN_0800BBA6  |  24B | 0x20, 0x21                       | (none) |
| Timebase        | FUN_0800BC00  |  42B | 0x26, 0x27, 0x28                 | (none) |

### Full scope entry sequence (best current model)

For a default boot into scope mode (CH1, 1V/div, 1ms/div, auto trigger):

| Step | TX word  | cmd_hi | cmd_lo | Source          | Meaning                |
|------|----------|--------|--------|-----------------|------------------------|
| 1    | `0x02A0` | 0x02   | 0xA0   | Static write    | Mode entry / scope arm |
| 2    | `0x0501` | 0x05   | 0x01   | Static write    | Scope selector seed    |
| 3    | `0x050C` | 0x05   | 0x0C   | Dynamic builder | CH1 config pair A      |
| 4    | `0x050E` | 0x05   | 0x0E   | Dynamic builder | CH1 config pair B      |
| 5    | `0x0510` | 0x05   | 0x10   | Dynamic builder | CH1 config pair C      |
| 6    | `0x0511` | 0x05   | 0x11   | Dynamic builder | CH1 config pair D      |
| 7    | `0x0503` | 0x05   | 0x03   | Static write    | Scope commit/activate  |

Then the runtime config commands (cmd_hi = state-derived):

| Step | cmd_lo group    | Meaning               |
|------|----------------|-----------------------|
| 8    | 0x07 or 0x0A   | Channel bank prefix   |
| 9-13 | 0x1A-0x1E     | Channel range config  |
| 14   | 0x07 or 0x0A   | Trigger source prefix |
| 15-18| 0x16-0x19     | Trigger config        |
| 19-20| 0x20, 0x21    | Acquisition mode      |
| 21-23| 0x26-0x28     | Timebase config       |

### Blocking gap: dispatch table at 0x08044E74

The mapping from internal selectors 0x0B-0x11 to wire-level TX words passes
through the dispatch table at 0x08044E74 (normalized address). The warehouse
has no functions at that address range -- it is data, not code. The dispatch
handlers are called via function pointer.

Additionally, the stock binary references addresses above 0x080B7680 (63
distinct flash references past the end of the downloaded app image). Some
scope configuration data may only be recoverable from a live on-device
flash dump.

---

## 2. Layer Classification Per Command Group

### Classification table

| Group                | cmd_lo range | Layer          | Evidence                                    |
|----------------------|-------------|----------------|---------------------------------------------|
| Mode entry           | 0xA0        | **Wire-level** | Static `strh` to staging variable, direct queue to usart_tx_queue | [decompile-derived] |
| Scope seed/activate  | 0x01, 0x03  | **Wire-level** | Static `strh` writes | [decompile-derived] |
| Dynamic scope config | 0x0C-0x11, 0x15-0x17 | **Wire-level** | Dynamic builder, `0x0500 | low_byte`, direct to usart_tx_queue | [decompile-derived] |
| Boot/runtime init    | 0x00, 0x01, 0x0B-0x11 | **Internal selectors** | Queued to usart_cmd_queue (0x20002D6C), translated by dispatch handlers | [decompile-derived] |
| Channel ranges       | 0x1A-0x1E   | **Wire-level** | Gap function FUN_0800BA06 queues directly to usart_tx_queue | [decompile-derived] |
| Trigger              | 0x16-0x19   | **Wire-level** | Gap function FUN_0800BB10 queues directly to usart_tx_queue | [decompile-derived] |
| Acquisition          | 0x20, 0x21  | **Wire-level** | Gap function FUN_0800BBA6 queues directly to usart_tx_queue | [decompile-derived] |
| Timebase             | 0x26-0x28   | **Wire-level** | Gap function FUN_0800BC00 queues directly to usart_tx_queue | [decompile-derived] |
| Meter config         | 0x08, 0x09  | **Wire-level** | Static writes | [decompile-derived] |

### Key distinction

The **same cmd_lo values** can appear in different layers:

- `0x0B-0x11` as **internal selectors** when queued to `usart_cmd_queue`
  (0x20002D6C) -- these get translated by the dispatch table
- `0x0C, 0x0D, 0x0E, 0x10, 0x11, 0x15, 0x16, 0x17` as **wire-level
  cmd_lo** when produced by the dynamic builder with cmd_hi=0x05, queued
  directly to `usart_tx_queue` (0x20002D74)

The critical error in the original osc firmware was sending internal
selector values (0x0B-0x11) directly as wire-level cmd_lo bytes. The FPGA
does not understand those codes -- it expects the translated 16-bit words.

### How to tell which layer you are looking at

| Queue destination | Item size | Layer |
|-------------------|-----------|-------|
| `0x20002D6C` (usart_cmd_queue) | 1 byte | Internal selector -- gets translated |
| `0x20002D74` (usart_tx_queue)  | 2 bytes | Wire-level -- goes straight to USART2 frame |

If code writes to `0x20002D74`, the bytes are final. If it writes to
`0x20002D6C`, there is a translation layer in between.

---

## 3. Pin Role Reconciliation

### Reconciliation table

| Pin  | ripcord claim (fpga_interaction_analysis.md)           | osc hardware-confirmed                          | Status       |
|------|-------------------------------------------------------|------------------------------------------------|--------------|
| PB6  | Not explicitly named; FUN_080058a4 called "PC6 toggle driver" / "SPI CS" | SPI3 chip select (software-controlled, active LOW) | **Corrected in current notes.** fpga_interaction_analysis.md incorrectly attributed CS to PC6. PB6 is the real SPI3 CS. |
| PC6  | Called "chip-select" in GPIOC analysis; 6 functions read/write GPIOC for PC6 | FPGA SPI enable/gate line (must be HIGH for SPI3 to work) | **Needs correction.** PC6 is an enable/gate, not chip-select. fpga_interaction_analysis.md's "SPI CS" label for FUN_080058a4 is wrong -- that function toggles PC6 as an enable line, not as chip-select. |
| PB11 | Correctly labeled as "FPGA active-mode control" in latest version; "bit-bang SPI for display" hypothesis withdrawn | FPGA active mode control (HIGH = active measurement mode) | **Correct.** ripcord's latest note already withdrew the bit-bang hypothesis and correctly identifies PB11 as active-mode control. |

### What ripcord got right

- PB11 role: correctly identified after initial over-attribution, now
  labeled as FPGA active-mode control with [hardware-confirmed] tag
- The xref counts (10 functions touching PB11, 6 touching PC6) are
  accurate and useful for identifying the control cluster

### What ripcord got wrong or overstated

- PC6 was called "SPI chip-select" in the peripheral surface section
  and in FUN_080058a4's description. It is actually an enable/gate line.
  The real SPI3 chip-select is PB6 (software GPIO, not hardware NSS).
- The "SPI CS toggle" label on FUN_080058a4 should be "PC6 enable toggle"

### Recommended corrections to fpga_interaction_analysis.md

1. Line 33: Change `PC6 read/set/reset` column to note "enable/gate, not CS"
2. Line 53: Change FUN_080058a4 from "PC6 toggle driver" / "SPI CS" to
   "PC6 enable/gate toggle"
3. Line 129: Remove "SPI3 CS (PC6)" framing; replace with "PC6 enable
   line (separate from SPI3 CS on PB6)"
4. Add PB6 to the peripheral surface table (currently missing)

---

## 4. Version Stability: What Is Proven vs What Is Not

### What IS proven (strong evidence)

1. **Peripheral register access counts are identical V1.0.7-V1.2.0.**
   SPI3 (206), USART2 (20 in master init), DMA2 (29), GPIOB (14 in
   master init), GPIOC (31 in master init) -- all frozen.
   Evidence: [direct-xref], warehouse query.

2. **101 functions are byte-identical across all three post-rewrite versions
   (V1.0.7, V1.1.2, V1.2.0).** This includes FreeRTOS primitives, queue
   operations, and several application-level functions up to 928 bytes.
   Evidence: body_hash comparison, warehouse query.

3. **182 functions are byte-identical between V1.1.2 and V1.2.0.**
   The V1.1.2→V1.2.0 transition was a minor patch.
   Evidence: body_hash comparison.

4. **The FreeRTOS queue primitive (FUN_0803f09c / 316 bytes) is
   byte-identical across V1.0.7/V1.1.2/V1.2.0.** Hash:
   `7038b281ebec96458ecc50eb17b2bee81a8253dddde20ff1957186405629291c`.
   This is the `xQueueGenericSend` or similar core primitive.
   Evidence: body_hash match.

### What is NOT proven (despite looking stable)

1. **The master init functions are NOT byte-identical across any version pair.**

   | Version pair    | Size change  | body_hash match? |
   |-----------------|-------------|------------------|
   | V1.0.7→V1.1.2  | 14650→15128 | No               |
   | V1.1.2→V1.2.0  | 15128→15346 | No               |
   | V1.0.7→V1.2.0  | 14650→15346 | No               |

   The master init grew in every release. Identical peripheral access
   counts prove the hardware surface is stable, but the function's logic,
   state machine, and non-peripheral code changed.

2. **The second large function (13276 bytes) also differs between V1.1.2
   and V1.2.0** despite identical size and basic block count. The body
   hash changed, consistent with constant/pointer updates.

3. **Runtime semantics, state machine behavior, and queue usage patterns
   cannot be proven from xref counts alone.** Identical SPI3 access
   counts mean the same registers are read/written the same number of
   times. They do not prove the ordering, timing, conditional paths,
   or higher-level choreography is identical.

4. **The USART2 ISR (304 bytes) does NOT appear byte-identical across
   versions.** The V1.2.0 hash `c3928c28...` was not found in V1.0.7
   or V1.1.2 at the same size. The ISR likely changed slightly between
   versions.

### What would prove more

1. **Decompiled C diff of the master init across versions.** The warehouse
   has decompiled C for all four stock versions. A structured diff would
   show whether the peripheral-touching code paths are identical even if
   surrounding logic changed.

2. **P-code feature comparison.** If `pcode_features` is populated for
   the stock targets, comparing feature vectors for the master init across
   versions would give a finer-grained stability signal than body_hash.

3. **Focused body_hash on USART2-adjacent basic blocks only.** The master
   init is 450+ basic blocks. If the ~20 blocks that touch USART2 registers
   are byte-identical, that is stronger evidence for protocol stability
   than whole-function hash comparison.

### Recommended wording changes for fpga_version_evolution.md

| Current wording | Recommended wording |
|----------------|---------------------|
| "the FPGA protocol layer did not change" | "the FPGA-facing peripheral access surface is frozen" |
| "V1.0.7 is the canonical reference in full" | "V1.0.7 is the earliest version with the full SPI3/USART2/DMA2 surface; later versions may differ in non-peripheral logic" |
| "identical peripheral counts" (used as evidence of protocol stability) | "identical peripheral register access counts (xref-level evidence; does not prove runtime ordering or state machine identity)" |
