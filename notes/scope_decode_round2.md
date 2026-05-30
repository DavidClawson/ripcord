# FNIRSI 2C53T (stock_v120) — Decode Round 2 Addendum

**Addendum to `scope_architecture_v120.md`.** Round 2 attacks the parts
the whole-scope doc left thin or wrong: the undecoded tail's runtime
**acquisition engine** (0x0803B454), three subsystems the round-1 pass
never enumerated (USB/MSC, FAT/SPI-NOR filesystem, JPEG asset codec),
and the **re-segmentation** of the two Keil interrupt mega-functions that
Ghidra shredded into ~12 phantom fragments.

Same discipline as the parent doc. Every claim carries provenance
(`direct-xref` | `decompile-derived` | `inferred`) and a 0.0–1.0
confidence. Verifier-**refuted** claims are kept and explicitly demoted —
the demotion is load-bearing. Internal selector/index/command codes are
kept separate from wire-level register transactions. Each report was
written by an analyst and independently checked by a verifier against
stock_v120's own bytes; both passes are folded in below.

All addresses are stock_v120 @ load base 0x08004000. Nothing here is
imported from any other project.

---

## R2.1 Headline correction: the round-1 "9 capture modes" claim

**The number 9 held. The mechanism and location did not.** Round-1 (and
`scope_architecture_v120.md` §4) said nine acquisition modes dispatch
from a TBH at **0x08037F0E**. That is now corrected on two axes:

- **Location/mechanism (refuted):** 0x08037F0E is **not** the acquisition
  dispatcher. It is the internal TBH of **FUN_08037EF8**, a **102-case
  nibble-pair semantic classifier** for multi-byte scope *settings*
  packets (called 4× from the settings parser at 0x0803AB1C–0x0803AB60
  with `r0 = (raw_byte_n & 0xF0) | (raw_byte_{n+1} & 0x0F)`). This is the
  same FUN_08037EF8 the parent doc §9 already correctly identified as the
  command **selector-code** classifier — round 2 confirms it has zero
  involvement in the sample loop. *(direct-xref, 1.00 — verifier matched
  4 callers and the 0xCC-byte / 102-entry table at 0x08037F12.)*
- **The real dispatcher (confirmed):** a distinct **9-entry TBH at
  0x0803B536**, inside the acquisition task, keyed on `(USART2_cmd_byte −
  1)`, index 0–8 (`cmp r1,#8 / bhi / tbh [pc,r1,lsl#1]` at 0x0803B532).
  All 9 table targets resolved byte-for-byte from the image:

  | idx | cmd | target      | role                                   |
  |-----|-----|-------------|----------------------------------------|
  | 0   | 1   | 0x0803B54C  | range/timebase lookup + settling gate  |
  | 1   | 2   | 0x0803B970  | conditional FPGA-mode byte write       |
  | 2   | 3   | 0x0803B9F2  | roll-mode ring update (1 CH1 + 1 CH2)  |
  | 3   | 4   | 0x0803B5A4  | burst capture, first 512-pair block    |
  | 4   | 5   | 0x0803B68C  | burst capture, second 512-pair block   |
  | 5   | 6   | 0x0803BD1C  | channel-mode byte write                |
  | 6   | 7   | 0x0803BD5C  | trigger-mode byte write                |
  | 7   | 8   | 0x0803B75C  | **WRITE** computed ADC-trim to FPGA    |
  | 8   | 9   | 0x0803B79C  | 16-bit ADC-reference read (PB6 pulse)  |

  *(direct-xref, 0.99 — analyst and verifier independently decoded the
  identical 9 halfwords; I re-decoded them a third time from
  `stock_v120.bin` file offset 0x3753A and they match.)*

So §4's sentence "Nine capture modes dispatch from a TBH at 0x08037F0E"
is **superseded**: nine *commands* dispatch from the TBH at **0x0803B536**;
0x08037F0E belongs to the settings classifier. The mode *count* of 9 was
correct by coincidence of two unrelated dispatchers both being plausible.

---

## R2.2 Runtime acquisition engine (THE PRIZE)

**Confidence: high on transport + dispatch structure; medium on
calibration arithmetic and a couple of mode semantics.**

The acquisition engine is a **single 7092-byte FreeRTOS task at
0x0803B454** (true extent 0x0803B454–0x0803D007; undecoded tail, no Ghidra
decode exists — work is from raw disasm). Prologue is `sub sp, #0x38`
(B08E) with **no register push** — the canonical never-returns FreeRTOS
task entry; all control paths loop back to 0x0803B498/0x0803B49A, no
`bx lr`/`pop {pc}` anywhere in the body. *(direct-xref, 0.98.)*

### The loop (corrected/expanded data-flow)

Per iteration:

1. **Blocking dequeue** one command byte from the USART2-RX FreeRTOS
   queue at `state+0x2D78` via FUN_0803F1D8 (`r0=queue, r1=&outbyte,
   r2=−1` infinite timeout; returns 1). The dequeued byte (value 1–9) is
   the FPGA→MCU command. *(direct-xref, 0.97.)*
2. **Calibration gate:** if `state+0x352` (CH1 gain-cal byte) is 0x00 or
   0xFF, **or** `state+0x353` (CH2) is 0x00 or 0xFF → skip the VFP path
   and use a raw ADC trim from `state+0x1C` (`ldrsh`). VFP path is taken
   only when **both** cal bytes are valid. *(direct-xref, 0.96.)*
3. **Assert SPI3 software-NSS:** `GPIOB_BRR (0x40010C14) ← 0x40` drives
   **PB6 LOW** before the echo write.
4. **Echo-ACK:** write the command byte to **SPI3_DT (0x40003C0C)** with
   TDBE/RDBF polling on **SPI3_STS (0x40003C08)** (TDBE = bit1 via
   `lsls #0x1E`; RDBF = bit0 via `lsls #0x1F`; 4-instruction ITTTT-PL
   unroll). The FPGA echo read-back is discarded.
5. **Dispatch** the 9-way TBH (R2.1); on return, **deassert PB6 HIGH**
   (`GPIOB_BSRR 0x40010C10 ← 0x40`) and loop.

**CORRECTION (verifier, resolves analyst open-Q #2):** PB6 is
**transaction-scoped, not continuously asserted**. It deasserts HIGH at
the end of *every* dispatch (0x0803B4A8) and reasserts LOW at the start
of the next command (0x0803B4F4). The round-1 doc never characterized
PB6; record it here as GPIOB.PB6 = software SPI3 chip-select to the FPGA.
*(direct-xref, 0.92.)*

### Note on the two USART2 queues

The acquisition task reads the **command** queue at `state+0x2D78`. The
parent doc §9 RX path posts the 12-byte completion frame to queue
**0x20002D7C** and the *settings* dispatcher (§9, task @0x0803AAC0) reads
**0x20002D6C**. These are distinct queues; 0x2D78 (acq commands), 0x2D7C
(acq doorbell semaphore), 0x2D74 (TX), 0x2D70 (sibling task B), 0x2D6C
(settings). Do not conflate. *(direct-xref, 0.9.)*

### Mode semantics (per TBH index)

- **Mode 1 (cmd 1) — range/settling gate.** Reads `state+0x2D`
  (range/timebase index), indexes a sparse flash LUT at **0x0804D833**
  (verified bytes: idx3→0x80, idx4→0x08, else 0; thresholds 0x80+0x32=178,
  0x08+0x32=58). Compares `state+0xDB8` (debounce/settle counter) to the
  threshold.
  **CORRECTION (verifier, refutes analyst):** the retry/"send 0x12"
  branch is two-way, not one. When `threshold ≤ debounce`: if
  `range_index > 0x12` → SPI3 write constant **0x12**; if `range_index ≤
  0x12` → SPI3 write **`range_index + 1`**. Normal path (`threshold >
  debounce`) writes `range_index` directly. The round-1-style "always
  sends 0x12" is incomplete. *(direct-xref, 0.95.)*
- **Mode 2 (cmd 2):** if `state+0x14` (FPGA mode byte) nonzero, SPI3-write
  it. *(direct-xref, 0.9.)*
- **Mode 3 (cmd 3) — roll.** Updates ring head `state+0xDB4` and fill
  count `state+0xDB6` (capped 0x12C = 300). Shifts the two 301-slot rings
  (CH1 `state+0x356`, CH2 `state+0x483` = 0x356+0x12D) left by one. SPI3
  reads (0xFF dummies): CH2 raw → `state+0x482`, CH1 raw → `state+0x5AF`,
  then a per-sample VFP calibration. **Roll uses a different gain divisor
  than burst — see calibration note.** *(direct-xref, 0.93.)*
- **Modes 4 & 5 (cmd 4, 5) — burst.** Each reads **512 interleaved
  CH1/CH2 8-bit pairs** by polled SPI3 (TDBE→write 0xFF→RDBF→read, twice
  per iteration; even index = CH1, odd = CH2). Mode 4 fills
  `state+0x5B0..0x9AF` (r0 = 0..0x3FE); mode 5 continues `r0 =
  0x400..0x7FE` into `state+0x9B0..0xDAF`. Together = a 2048-byte
  interleaved buffer. Each is followed by in-place VFP calibration.
  *(direct-xref, 0.98.)*

  **Open (analyst Q #5, unresolved):** mode-5's calibration loop reads
  `state+0x353` (CH2 cal) and `state+0x5` (CH2 zero), which would suggest
  the *entire* second 1024-byte block is CH2 — contradicting the
  interleaved layout the same mode just wrote. Not reconciled; treat the
  second-half calibration channel-selection as **inferred, 0.6** pending
  a full re-trace or Renode run.

- **Mode 6 (cmd 6):** SPI3-write `state+0x16` (channel mode). *(0.9)*
- **Mode 7 (cmd 7):** SPI3-write `state+0x18` (trigger mode). *(0.9)*
- **Mode 8 (cmd 8) — direction INVERTED from round-1 wording.**
  **CORRECTION (verifier, refutes analyst's "calibration read-back"):**
  TBH[7] at 0x0803B75C **WRITES** `uxtb(r2)` to SPI3_DT, where r2 holds
  the bypass-path ADC trim derived from `state+0x1C`. There is **no read
  of a calibration byte from the FPGA** here. It is an MCU→FPGA write of a
  computed trim. *(direct-xref, 0.97.)*
- **Mode 9 (cmd 9) — 16-bit ADC reference read.** Assembles a 16-bit value
  into `state+0x46` from two SPI3 reads, with a PB6 HIGH→delay→LOW pulse
  between them (`FUN_0803E390(1)`), then `state+0xDB0++`.
  **CORRECTION (verifier):** the sequence is **5 SPI transactions, not 3**.
  Between byte_hi and byte_lo there is an undescribed `TDBE → write
  **0x0A** → RDBF` cycle (0x0803B846: `movs r0,#0xA; str r0,[r7,#4]`).
  **0x0A is a non-dummy command byte to the FPGA**, not a 0xFF filler —
  flag it as a candidate FPGA control opcode. Wire-level identity of 0x0A
  is **inferred, 0.5**; its presence in the stream is direct-xref. *(0.91.)*

### Post-burst VFP calibration (formula CORRECTED)

VFP constants loaded at task entry: `s16 = −28.0` (via `vmov.f32`
immediate at 0x0803B48C — **not** a literal-pool `vldr` as the analyst
worded it), `s18 = 192.0`, `s20 = −128.0`, `s22 = 128.0`, `s24 = 255.0`,
`s26 = 0.0`, `s28 = 150.0` (six `vldr` at 0x0803B462–0x0803B476 from the
pool at 0x0803B674). *(direct-xref, 0.99.)*

**CORRECTION (verifier, refutes analyst formula):** the stored value is

```
out = clamp( (raw − 128 − zero_offset)/gain + 128 + zero_offset , 0..255 )
```

— the analyst dropped the trailing `+ zero_offset` (there is a
`vadd s6, s4, s2` re-adding `zero_offset` at 0x0803BE38 *before* the
clamp). Also: **burst** modes use `gain = (cal_ref − 28.0)/150.0`
(divisor s28=150.0), while **roll** mode uses divisor **s18 = 192.0**
(`vdiv s0, s2, s18` at 0x0803BB68). Two distinct gain denominators, not
one. *(direct-xref, 0.97.)*

### Sibling tasks in the tail (NEW, structural only)

- **0x0803B3F4** — adjacent task, `sub sp,#8` prologue, uses
  `state+0x2D74` + GPIOB. This is the parent doc §9 **TX task**
  (queue 0x20002D74). *(direct-xref, 0.85.)*
- **0x0803D008** — adjacent task, `sub sp,#8`, reads queue
  `state+0x2D70`. **CORRECTION (verifier):** the analyst read
  `movw r8,#0x6548; movt r8,#0x804` as an ASCII string "HeS4" — it is a
  **flash data address 0x08046548**, not a string; and the following
  `movw sb,#0x5434; movt sb,#0x4001` = peripheral 0x40015434, not a state
  base. Role (display/UI vs other) is **inferred, 0.55**; only the
  prologue + queue are direct-xref. *(0.8.)*

### State-struct fields added by this report (base 0x200000F8)

Merge into §12 of the parent doc:

| offset | access | meaning                                              |
|--------|--------|------------------------------------------------------|
| +0x04  | ldrsb  | CH1 ADC zero-offset (signed); VFP subtrahend         |
| +0x05  | ldrsb  | CH2 ADC zero-offset (signed); mode-5 calibration     |
| +0x14  | ldrb   | FPGA mode byte (mode 2 write)                         |
| +0x16  | ldrb   | channel mode (mode 6 write)                           |
| +0x18  | ldrb   | trigger mode (mode 7 write)                           |
| +0x1C  | ldrsh  | 16-bit ADC trim (cal-bypass + mode-8 write source)    |
| +0x2D  | ldrb   | range/timebase index (mode-1 LUT key)                 |
| +0x46  | strh   | 16-bit ADC reference assembled in mode 9              |
| +0x352 | ldrb   | CH1 gain-cal reference byte; `gain=(v−28)/150`        |
| +0x353 | ldrb   | CH2 gain-cal reference byte                           |
| +0x356 | buf    | CH1 roll ring, 301 slots → +0x482                     |
| +0x483 | buf    | CH2 roll ring, 301 slots → +0x5AF                     |
| +0x5B0 | buf    | burst block 1 (1024 B, mode 4); even=CH1 odd=CH2      |
| +0x9B0 | buf    | burst block 2 (1024 B, mode 5)                        |
| +0xDB0 | b      | acquisition counter (++ at burst end, mode-9 end)     |
| +0xDB4 | h      | roll ring write head                                  |
| +0xDB6 | h      | roll ring fill level (cap 0x12C)                      |
| +0xDB8 | h      | range settling/debounce counter (mode-1 threshold cmp)|

(`state+0x356`/`+0x483` here overlap the parent doc §4/§5 display-buffer
copies at the same offsets — confirming the ring buffers and the
post-calibration display buffers are the **same** contiguous region, as
§4 already hinted.)

---

## R2.3 USB device / Mass-Storage stack

**Confidence: high on MSC/BOT identity and SCSI vocabulary; one LUN-count
claim corrected.**

The V1.2.0 firmware is a **USB Mass-Storage Class device, Bulk-Only
Transport (BOT)**, single LUN, backed by the SPI2 NOR flash (R2.4) — not
CDC, not SD. *(decompile-derived, 1.00.)*

- **Class identity (confirmed 1.00):** `dCBWSignature = 0x43425355`
  ("USBC") checked in FUN_0802DE0C; `dCSWSignature = 0x53425355` ("USBS")
  emitted by FUN_0802DCC4; class requests `bRequest=0xFF` (BOT Mass-Storage
  Reset) and `0xFE` (Get-Max-LUN) in FUN_0802E078.
- **SCSI dispatcher FUN_0802D20C (1396 B):** 12 opcodes — 0x00 TEST UNIT
  READY, 0x03 REQUEST SENSE, 0x12 INQUIRY, 0x1A MODE SENSE(6), 0x1B
  START/STOP, 0x1E PREVENT/ALLOW REMOVAL, 0x23 READ FORMAT CAPACITIES,
  0x25 READ CAPACITY(10), 0x28 READ(10), 0x2A WRITE(10), 0x2F VERIFY(10),
  0x5A MODE SENSE(10). READ(10)/WRITE(10) call the SPI-NOR backends
  FUN_08033048 / FUN_0803316C; LUN 0 adds a **0x200000** byte offset for
  flash addressing. *(decompile-derived, verifier-confirmed.)*
- **INQUIRY template @0x0802D838 (confirmed, raw bytes read):**
  DeviceType 0x00 (direct-access), Removable=1, VendorID **"AT32"**,
  ProductID **"Disk0"**, Revision **"2.00"**.
- **Endpoints (confirmed 0.95):** EP0 control only; EP1 is the sole bulk
  pair — `0x01` OUT (CBW + write data), `0x81` IN (CSW + read data). No
  iso/interrupt EPs. PMA helpers FUN_0803DEB4 (WriteEP) / FUN_0803DB24
  (SetEPConfig) at base 0x40006000, 16-bit stride.
- **Init (confirmed 0.9):** inside SVC_Handler (0x08028DC0 — itself a
  mis-cut fragment of mega-function 1, see R2.6): stores USBFS base
  0x40005C00, calls USB_InitEP FUN_0803D990, writes `USBFS_CTRL ← 0x9E00`
  (the 0x9E00 value is **inferred, garbled decompile**; the access
  pattern is direct-xref).
- **Connect path:** FUN_0800D6AC clears `USBFS_CTRL[1]` (DISUSB) and
  `USBFS_CFG[1]` to attach the PHY. *(direct-xref, confirmed.)*
- **User-facing feature (inferred 0.8):** multilingual menu strings "USB
  Sharing" (0x080B935E) / "USB-Freigabe" / "Compartilhamento USB" /
  "Compartir USB" confirm a user-visible toggle. The string→handler link
  is MOVW/MOVT-encoded and absent from xrefs — connection is inferred.

### Corrections (verifier-forced)

- **Max-LUN = 0 (one LUN), corrected.** Get-Max-LUN sends 1 byte from
  `state+2`, which BOT Reset zeroes (`*(u32)(puVar2+2)=0`). The analyst
  misread `puVar2[1]=0x01` (the high byte of the BOT-IDLE encoding
  `*puVar2=0x0107`) as the MaxLUN field. **Value sent = 0.** The SCSI
  layer's `bCBWLUN < 2` check is a range guard, not evidence of a real
  LUN 1. *(direct-xref.)*
- **Register naming:** the SPI2 data register is **SPI2_DT** (0x4000380C)
  in the AT32 SVD, not STM32 "SPI2_DR". All "DR" mentions → "DT".
- **`FUN_0802CB80` is NOT USB** — it is a 64-point FFT butterfly (zero
  USBFS xrefs), pulled into the cluster only by call-graph proximity to
  the waveform task FUN_080221E4. Exclude. *(direct-xref, 1.00.)*
- **IRQ20 vector miscut (confirmed):** vector[36]@0x08004090 = 0x0802E8E5
  → 0x0802E8E4, which is **interior to IRQ38_Handler** (mega-function 2,
  R2.6); the bytes there (`2B 10 C9 07` = `lsls`) are not a prologue. USB
  LP interrupt servicing is delegated through the software callback table
  at `DAT_20002B28`, not a direct vector→FUN_0802B8E4 edge.
- **`SVC_Handler` does NOT absorb IRQ29/IRQ38** (a round-1-flavored
  over-claim): SVC_Handler ends at 0x0802A8A2; IRQ29_Handler (0x0802E71C)
  and IRQ38_Handler (0x0802E7B4) are >0x5000 bytes past it. The only real
  miscut is IRQ20-inside-IRQ38.

---

## R2.4 FAT / SPI-NOR filesystem

**Confidence: high on NOR transport + FAT layering; FAT-type label
semantics corrected.**

A FatFs-style filesystem over a **SPI NOR flash on SPI2**, NSS = GPIOB
pin 12. **Not an SD card** — the command set is canonical SPI-NOR:
0x03 READ, 0x02 PAGE PROGRAM, 0x20 4KB SECTOR ERASE, 0x06 WREN, 0x05 RDSR
(WIP poll). Sector granularity 4096 B = NOR erase unit. *(decompile +
disasm, 0.97.)*

> Note: this revises the parent doc's recurring "3:/System file = SD card,
> drive 3" shorthand. The medium is SPI-NOR, not SD; "SD" anywhere in
> §6/asset-load prose should read "SPI-NOR".

### Layers

- **Block I/O (all confirmed):** FUN_080330C4 = SPI2 byte transceiver
  (TDBE/RDBF poll on SPI2_STS 0x40003808, data SPI2_DT 0x4000380C).
  FUN_08033048 = READ (cmd 0x03 + 24-bit addr). FUN_0803336C = PAGE
  PROGRAM (cmd 0x02; **internally calls WREN FUN_08033344 first** —
  analyst omitted). FUN_08032E9C = SECTOR ERASE (cmd 0x20; **size 76 B,
  not 86**). FUN_08033344 = WREN (0x06). FUN_0803311C = RDSR WIP poll.
- **`FUN_0803316C` RMW write** (confirmed, with omission noted): reads the
  4KB sector into the cache at **0x200012C0**, patches, then ERASE+PROGRAM.
  **Optimization the analyst missed:** if every target byte in the cached
  sector is already 0xFF, it PROGRAMs directly from the source pointer and
  **skips the erase**. *(decompile-derived, 0.94.)*
- **Path/dir layer:** FUN_080377A0 (drive-prefix parser; drive table at
  **0x20005FCC**, `*(u32)(0x20005FCC + (digit−'0')*4)`), FUN_080336D8
  (path walker), FUN_08031F20 (readdir), FUN_080318B8 (f_open: mode byte
  0=read, 1=write, 2=create-trunc, 10=CREATE_ALWAYS|WRITE; FIL struct =
  0x102C bytes from FUN_08037CFC, 4KB sector cache at FIL+0xB),
  FUN_08031534 (mkdir), FUN_08030250 (dirent writer), FUN_0803986C (FAT
  chain entry writer; FAT32 4-byte entry base is `cluster*4 + 0x34`, not
  +0x35 — +0x35 is byte 1).
- **Partitioning (decompile-derived 0.88):** two FAT volumes — **drive 3
  "3:/System file"** (UI .jpg assets, base offset 0), **drive 2
  "2:/Screenshot file" / "2:/Screenshot simple file"** (.bmp/.bin
  captures, base offset **0x200000**). The +0x200000 split is gated on
  **drive number** (`vol[1]`), not FAT type directly.

### Corrections (verifier-forced)

- **`FUN_0802DB80` returns FatFs `check_fs()` status codes, NOT FAT type.**
  This is the parent doc's "FAT volume type detector" — demote it. It
  reads the boot sector, checks 0xAA55 at +0x232, compares +0x86 against
  "FAT32   " (0x0802DC94), and returns **0 = valid FAT found, 2 = 0x55AA
  present but not FAT (MBR/partition entry), 3 = no boot sig, 4 = disk
  error**. The actual FAT type (12/16/32 → 1/2/3) is stored in `vol[0]`
  and set by FUN_080377A0 via cluster-count thresholds (<0xFF6 / <0xFFF6 /
  <0xFFFFFF6). The "returns 3=FAT32, 2=FAT16" claim conflated three
  different fields. The FAT16-vs-FAT32 *labels* for drives 2/3 are
  **inferred (0.75)** — unverifiable without the flash contents.
- **`FUN_080333E4` is the AT32 internal-flash option-byte (USD)
  programmer, NOT a FAT/NOR function** — FLASH_USD_UNLOCK 0x40022008,
  FLASH_STS 0x4002200C, FLASH_CTRL 0x40022010, FLASH_USD 0x4002201C; zero
  SPI2/GPIOB. Exclude from the FS layer. *(direct-xref, 0.98.)*
- **Screenshot pipeline arrow is unsubstantiated.** The claim
  `FUN_0800EE84 → FUN_08039ED4` is **refuted**: FUN_0800EE84's full
  decompile calls FUN_0803212C directly (12+×) and FUN_08038878 — it is a
  UI state-save handler, not the screenshot trigger. FUN_08039ED4 (the
  real screenshot writer: f_open mode 10 to "2:/Screenshot file/%d.bmp"
  via DAT_20008360 + counter DAT_20000F09, write FUN_08032530, flush
  FUN_08031014, commit FUN_0803212C) has **zero warehouse callers** in
  calls/recovered_calls/xrefs. Trigger unknown. *(decompile-derived.)*
- **`0x0803AA50` (undecoded tail) is the storage-command dispatch task:**
  receives a byte from queue **0x20002D6C** (= the *settings* queue;
  FUN_0803F1D8), dispatches via a runtime-populated function-pointer table
  at **0x0804BE74** (`ldr.w r0,[r6,r0,lsl#2]; blx r0`), gates 0x0803ECF0
  on `state+0xF68==2`. Prologue is `sub sp,#8` (no `push{lr}`) → **not a
  seed candidate**. The 0x0804BE74 table is mostly zero in the image (28
  of 32 entries; the 4 nonzero are not valid Thumb pointers) — populated
  at runtime by an unidentified registrar. *(disasm-verified, 0.88.)*
- **No static USB→FAT bridge exists in the warehouse** (USB SCSI
  READ10/WRITE10 → SPI-NOR backends only). This is **absence in the call
  graph, not proof of architecture** — the MSC LUN likely exposes raw NOR
  LBAs to the host independent of the on-device FatFs. Tagged *direct-xref
  0.82 with explicit absence-of-evidence caveat.* Do not assert the
  negative as fact.

---

## R2.5 UI asset codec (JPEG)

**Confidence: high on codec identity + constant tables; several decompile
line-citations and two helper roles refuted.**

The "large unexplained functions" cluster is a complete, self-contained
**JFIF/JPEG baseline sequential-DCT decoder**, algorithmically equivalent
to IJG libjpeg-6b (`jidctfst.c`). It decodes the UI .jpg assets from
"3:/System file/N.jpg" (SPI-NOR drive 3, R2.4) to **RGB565** and blits
them tile-by-tile to the LCD.

- **FUN_08035F20 (4110 B)** = header parser (SOI 0xFFD8, SOF0 0xC0, DHT
  0xC4, DQT 0xDB, SOS 0xDA marker dispatch; pre-multiplies QT by AAN
  scale into 32-bit dequant entries). *(decompile-derived, confirmed.)*
- **FUN_08034524 (6632 B)** = MCU decode engine (Huffman bitstream →
  Loeffler 8-pt IDCT with AAN pre-scaling → YCbCr→RGB → RGB565 pack →
  tile blit callback). **No decompiled_c exists for this function — all
  behavioral evidence is disasm only** (see corrections). 0xFFD0 restart
  marker at 0x080345F2, RGB565 pack at 0x08035BF8. *(direct-xref, 0.97.)*
- **FUN_08036F6C (520 B)** = display worker: allocs 0x7C state + 0x102C
  Huffman/QT workspace + 0x5000 input buffer (= 0x60A8 = 24,744 B total)
  from the bitmap heap (FUN_08037CFC), opens the file (FUN_080318B8 mode
  1), chains parser+decoder. *(direct-xref, 0.97.)*
- **FUN_0801B784** = a UI compositor that loads "3:/System file/3.jpg" at
  (x=0, y=0xDD=221). *(direct-xref, 1.00.)*

### Constant tables (all byte-for-byte verified against published standards)

Keil **scatter-load**: tables live at load region **0x0806BE74** in the
binary, execution region **0x0806EE74** at runtime (code references the
exec address via `movw/movt`; the 0x3000 delta explains Ghidra's
DAT_ offset). Zigzag (64 B @0x0806BE74), AAN scale (128 B @0x0806BEB4),
IJG range-limit clip (1024 B @0x0806BF34) — all confirmed 1.00. YCbCr→RGB
JFIF coefficients within ~0.1% (0.045–0.113%). *(direct-xref.)*

- **LCD blit transport (confirmed 0.93):** the tile callback (interior to
  the undecoded tail, near 0x0803B828) sets/clears **GPIOB.PB6** via
  `GPIOB_SCR 0x40010C10 / GPIOB_CLR 0x40010C14` for LCD control lines and
  calls the pixel writer. **No FSMC or SPI in this specific blit path.**
  *(Reconcile with parent doc §6, which routes the framebuffer→LCD over
  XMC/FSMC + DMA1-Ch2: both can hold — §6 is the bulk framebuffer blit,
  this is the per-tile asset-decode write path. Flagged for cross-check.)*

### Corrections (verifier-forced)

- **FUN_08034524 has NO decompiled_c.** Every "decompile line NNN"
  citation for it is misattributed (lines 111-116 / 188-226 are actually
  FUN_08035F20's SOF0-subsampling and DHT-table-loading code; lines
  1306-1343 don't exist). All FUN_08034524 behavior must be sourced to
  disasm. The codec identity still stands on disasm evidence.
- **IDCT constant label fixed:** `0x1151/4096 = 1.0823 = FIX_1_082392200`
  (libjpeg-6b), **not** `2·sin(π/8)=0.7654` (the analyst's trig label was
  wrong by 31.7%; the value correctly fingerprints libjpeg-6b).
- **FUN_0803740C is a UTF-8 multibyte-char iterator** (0xC0/0xE0 lead-byte
  tests), used by FUN_0801B784 for **text rendering** interleaved with
  FUN_0800C154 — **NOT** a JPEG file accessor. *(direct-xref, 0.93.)*
- **FUN_080374EC is the clock/VTOR-init function, NOT an SD/JPEG read
  callback.** It sets `SCB_VTOR (0xE000ED08) ← 0x08007000` and spin-polls
  `RCC_CTRL (0x40021000)` HSI-ready — i.e. it is the parent doc §2
  `SystemInit`. The analyst mislabeled the registers (AIRCR/APB2EN) and
  the role. The real JPEG read-callback is **unidentified**; the pointer
  passed to FUN_08035F20 (0x080374F1) lands mid-instruction and is a
  misread. *(direct-xref, 0.96.)* **This corrects the parent doc, where
  §2 already names FUN_080374EC = SystemInit — round 2 independently
  confirms that and refutes the asset-codec analyst's contrary label.**

---

## R2.6 Re-segmentation of the mis-cut mega-fragments

**Confidence: high (0.93). Two Keil interrupt mega-functions account for
~12 phantom Ghidra "functions."**

The pattern: a single Keil function body is re-entered by **multiple ARM
exception/IRQ vector slots** pointing into its mid-body (hardware does the
register save on the exception path; the function's own `push` runs only
on the normal-call path). Ghidra cut a new "function" at each vector
target. Each mega-function has **exactly one** real `push.w` prologue,
confirmed by a full-body `E92D`-encoding scan.

### Mega-function 1 — USB-init / SVC / SysTick / SPI3 data-pump body

- **True entry 0x08027A50**, `push.w {r4-r8,sb,sl,fp,lr}` + `vpush {d8}`,
  true extent **0x08027A50–0x0802B6CA = 15,486 bytes**, tail-call `b.w
  0x0803E6D8`. Epilogue at 0x0802B6BE exactly reverses the prologue.
- **6 warehouse fragments collapse into it:** FUN_08027A50 (4738 B),
  FUN_08028CE0 (38 B), FUN_08028D08 (184 B), **SVC_Handler** (0x08028DC0,
  6882 B), **SysTick_Handler** (0x0802A994, 34 B), FUN_0802A9C4 (3262 B).
  Vector reads confirm SVCall=0x08028DC0, PendSV=0x08028D50,
  SysTick=0x0802A994 all fall inside the body. The backward branch
  0x08028CDA→0x08028780 crosses the FUN_08028CE0 boundary, proving one
  body. *(direct-xref, 0.98.)*
- **"SVC_Handler" is mislabeled:** it is the **SPI3 data-pump inner loop**
  (caller-set r8=SPI3 ptr, r10=write buffer, DAT_0804D767 LUT), not a
  conventional SVCall handler — the SVCall slot just re-enters the pump.
  *(decompile-derived, 0.92.)* This refines parent doc §9's note that
  SVC_Handler is the SVCall target but mis-bounded.

### Mega-function 2 — NAND/DMA packet processor

- **True entry 0x0802E664**, `push.w {r4-r8,sb,sl,fp,lr}`, true extent
  **0x0802E664–0x0802FDE0 = 6,016 bytes**, four `pop.w {r4-r8,sb,sl,fp,pc}`
  exits (0x0802FDC0/D0/D8/E0). FUN_0802FDE4 begins its own clean prologue
  immediately after.
- **6 fragments collapse into it:** FUN_0802E664 (184 B), IRQ29_Handler
  (0x0802E71C), IRQ43_Handler (0x0802E78C), IRQ38_Handler (0x0802E7B4),
  UsageFault_Handler (0x0802F310), FUN_0802FDD4 (8 B). Fragment sizes
  equal exact inter-vector distances (IRQ29→IRQ43 = 112, IRQ43→IRQ38 =
  40), confirming vector-boundary cuts. *(direct-xref, 0.97.)*
- **"UsageFault_Handler" is mislabeled** — no SCB_CFSR/BFAR/MMFAR access;
  it is mid-function NAND boundary-check code. The vector[6] slot reuses
  the NAND function as a fault stub. *(decompile-derived, 0.85.)*
- **Zero peripheral_xrefs is a phantom-absence artifact:** all MMIO is via
  struct-pointer dereference (`ldr.w r8,[r0]` then r8/r4 offsets), so the
  SVD classifier (which needs direct movw/movt MMIO encoding) sees nothing.
  Do not read "0 peripheral_xrefs" as "touches no hardware." *(0.9.)*

### Two functions Ghidra missed entirely (NEW, in the 0x0802B71C gap)

The ANSI-escape debug strings at **0x0802B6D0–0x0802B71B**
("\x1b[1;32m[DEBUG] file[%s] line[%d] …" + "../../../project/bsp_sys.c")
were Capstone-decoded as phantom Thumb in round 1; real code resumes after
them:

- **0x0802B71C** — `push {r4,lr}`, **true size 110 B** (analyst said 112;
  the extra 2 B is the inter-function NOP pad at 0x0802B78A). USB-disconnect
  + PendSV trigger: reads USB-OTG **GCCFG 0x40000410**, state `+0x2C`,
  calls FUN_0803EF08, then writes **NVIC ICSR 0xE000ED04 ← 0x10000000**
  (PendSV pending) to schedule a context switch. *(direct-xref, 0.95.)*
- **0x0802B78C** — leaf (no push; `bxeq lr`/`bx lr`), **38 B**.
  **PERIPHERAL CORRECTION (verifier):** the analyst labeled the polled
  register `TMR13_CTRL1 @0x40001810`, but the SVD puts TMR13 base at
  **0x40001C00**; **0x40001810 = TMR12 base (0x40001800) + 0x10 =
  TMR12.ISTS** (interrupt-status, bit0 = overflow OVFIF). The function
  tests TMR12's overflow flag and, if set, pets the watchdog
  (`WDT.CMD 0x40003000 ← 0xAAAA`) and clears the flag. Correct name:
  **`tmr12_ovf_wdt_pet`**, not `tmr13_wdt_pet`. *(direct-xref, 0.9.)*

### Re-extract impact

Seeding the two true entries + two gap functions (R2.7) replaces the 12
fragments with 2 correctly-bounded mega-functions and recovers 2 missing
functions — net warehouse function count is roughly unchanged but the
boundaries become correct, which is what unblocks call-graph and
peripheral-xref attribution for the IRQ/USB/NAND region.

---

## R2.7 Re-anchored seeds for the final re-extract

Selection rule: a seed is included **only if the analyst proposed it AND
the verifier marked `ok=true`**, re-anchored to stock_v120's own image
with a disasm-confirmed prologue.

**Included (6):** the two acquisition-tail entries (0x0803B454, 0x0803D008),
the two re-segmentation mega-function true-entries (0x08027A50, 0x0802E664;
these re-cut 12 phantom fragments), and the two missed gap functions
(0x0802B71C, 0x0802B78C).

**Deliberately excluded despite a proposal:**

- **0x0803E390** (`delay`/`lcd_pixel_write`): acquisition-engine verifier
  said ok=true, but it is **already correctly decoded** in the warehouse
  (FUN_0803e390, size 110) and the asset-codec verifier marked it
  ok=false as redundant. Re-seeding a correctly-bounded function is a
  no-op at best; excluded.
- **0x0802DB80, 0x0802E2D4** (USB/FAT helpers): verifier ok=false — already
  in the functions table, correctly bounded.
- **0x080374EC** (mislabeled "SD read callback"): verifier ok=false — it
  is SystemInit/VTOR-init, already in the warehouse (with a separate
  size=2 truncation bug to fix by other means, not via a mislabeled seed).
- **0x0803AA50, 0x0803B3F4** (tail tasks): `sub sp,#8` prologue, not a
  `push{lr}` entry; fail the prologue criterion.

The body to apply to `targets/stock_v120/seeds.txt`:

```
0x0803B454  acq_task_main                 7092
0x0803D008  acq_tail_task_b
0x08027A50  usb_init_svc_spi3_pump        15486
0x0802E664  nand_dma_packet_processor     6016
0x0802B71C  usb_disconnect_pendsv_trigger 110
0x0802B78C  tmr12_ovf_wdt_pet             38
```

(0x0803D008 size left unstated — the analyst gave 0; its true extent was
not measured. create_seed_functions.py will let Ghidra bound it from the
prologue.)
