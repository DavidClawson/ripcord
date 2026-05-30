# FNIRSI 2C53T — MCU↔FPGA boundary: hardware validation handoff

**Audience:** the Claude Code agent working in the custom-firmware repo (the
one that flashes the AT32F403A and can drive/probe the Gowin FPGA directly).

**Purpose:** ripcord (a static + emulation RE pipeline) has reconstructed the
MCU↔FPGA acquisition protocol of the FNIRSI 2C53T scope (stock firmware
`stock_v120`, V1.2.0) and verified it *in emulation*. This document hands you
that model as a set of **falsifiable, on-the-wire predictions** plus the two
experiments that promote them to silicon-confirmed fact — and an explicit list
of what we **do not** know, which only your hardware can answer.

---

## ⚠️ Read this first — what "verified" means here

Everything below tagged **`verified⊧model`** was confirmed by executing the
real firmware in Renode against a **software FPGA model we wrote**
(`fpga_protocol.py` in the ripcord repo). That proves the **MCU side**: which
command dispatches where, the transaction *structure*, buffer addresses, data
flow, and the CS handshake. It does **not** prove:

- the FPGA's actual **reply byte values** (our model returns documented
  placeholders),
- that our **framing is correct** (a systematic error — e.g. PB6 not really
  CS, wrong SPI idle level — would be internally self-consistent and wrong),
- the **semantics** of opaque opcodes (what `0x0A`, `0x12`, the mode bytes
  *mean* to the FPGA).

So treat `verified⊧model` as **"this is exactly what the firmware emits; please
confirm the wire and capture the replies."** Confidence tags used:

| tag | meaning |
|-----|---------|
| `verified⊧model` | confirmed by executing real firmware vs. our SW FPGA model (Renode) |
| `static` | derived from disassembly/decompile only; not run |
| `inferred` | a reasoned guess about *meaning*; weakest |
| `unknown` | we have no value/answer; hardware must supply it |

When you confirm or refute one of these on hardware, that is a **finding either
way** — please report it back in the format at the bottom so the ripcord
contract ledger can be updated.

---

## 1. The target and the boundary

- **MCU:** ArteryTek **AT32F403A**, Cortex-M4F @ 240 MHz, app image based at
  `0x08004000` (two-stage: a bootloader at `0x08000000–0x08003FFF` is *not* in
  the app image; the app is not independently cold-bootable — which is why
  ripcord verified it by function-level emulation, not full boot).
- **FPGA:** opaque Gowin part. Only observable through the MCU bus.
- **Primary channel — SPI3** @ `0x40003C00`, master, **Mode 3, /2,
  full-duplex** (`static`). Registers: `STS` (status) `0x40003C08`, `DT` (data)
  `0x40003C0C`. Each transfer writes `DT` and reads the byte clocked in.
- **Chip-select — PB6**, active **LOW** (`verified⊧model`, Run 8). Driven via
  GPIOB `SCR` `0x40010C10` (write `0x40` → PB6 HIGH = deassert) and `CLR`
  `0x40010C14` (write `0x40` → PB6 LOW = assert). The firmware asserts CS
  before each command's SPI3 activity and deasserts at the dispatch-loop
  bottom.
- **Enable/gate — PC6 (enable, HIGH) and PB11 (gate, HIGH)** (`static`/
  `inferred`; these are set during boot code our emulation skips — **please
  confirm on hardware**).
- **Command channel — USART2** @ `0x40004400` (early/control plane; its exact
  effect on the FPGA past the state struct is `inferred`).
- **Acquisition engine:** `acq_engine_task` @ `0x0803B454` (a ~7 KB FreeRTOS
  task). A 1-byte command wakes it; it dispatches via a `TBH` jump table at
  `0x0803B536` on `(command)`; **command N → handler case N**. The dispatcher
  **writes the command byte to SPI3 first**, then the handler streams its
  payload — so every command on the wire reads as `<cmd> <payload…>`.
- **Scope state struct** @ `0x200000F8` (offsets referenced below are relative
  to this base).

> SPI3 pins on AT32F403A default to SCK=PB3 / MISO=PB4 / MOSI=PB5, USART2 to
> TX=PA2 / RX=PA3 — but these are remappable. **Confirm the actual pin mapping
> from the board (GPIO `CFGLR`/`CFGHR` + AFIO remap, or the schematic) before
> probing.** Do not trust the defaults.

---

## 2. The prediction table (the heart of this handoff)

Each row is what we predict appears on **SPI3 MOSI** for that command, plus the
MCU-side effect. All command framing and structure is `verified⊧model` unless
noted; all **reply values and opcode meanings are `unknown`/`inferred`**.

| cmd | name | SPI3 MOSI (prediction) | MCU-side effect (state struct @ 0x200000F8) |
|----:|------|------------------------|---------------------------------------------|
| `01` | auto-range | `01 <idx>` hold · `01 <idx+1>` advance · `01 12` clamp | reads range idx `+0x2D`, flash LUT `0x0804D833`, debounce `+0xDB8`; settle-then-step |
| `02` | set FPGA mode | `02 <mode>` | writes `+0x14` |
| `03` | roll capture | `03` + readback stream | rings `+0x356`/`+0x483`, fill count `+0xDB6` |
| `04` | burst (half 1) | `04` + 512 paired reads | 1024 contiguous bytes → `+0x5B0` |
| `05` | burst (half 2) | `05` + 512 paired reads | 1024 contiguous bytes → `+0x9B0` |
| `06` | set channel | `06 <mode>` | writes `+0x16` |
| `07` | set trigger | `07 <mode>` | writes `+0x18` |
| `08` | write trim | `08 <computed>` | MCU→FPGA write of a value computed from `+0x1C` |
| `09` | ADC-ref read | `09 FF FF 0A FF FF` + PB6 pulse mid-seq | assembles 16-bit value → `+0x46` |

**The auto-range machine (cmd 01)** is a closed loop: hold the current range
(re-send `idx`) until a per-range debounce (`+0xDB8`) exceeds `LUT[idx]+0x32`
from the flash table at `0x0804D833`, then step `idx → idx+1` (or clamp at
`0x12`). Verified branches on the wire: `01 05`→`01 05` (hold), `01 05`→`01 06`
(advance), `01 20`→`01 12` (clamp).

**Burst (cmd 04/05)** is a 2048-byte two-half acquisition buffer
(`+0x5B0` then `+0x9B0`), filled from 512 paired full-duplex reads each. The
post-acquisition path applies VFP calibration (re-adds a zero offset, clamps
`[0.0..255.0]`, divides by 150.0 for burst / 192.0 for roll) — `static`.

**The `0x0A` in cmd 09** is an embedded sub-opcode sent mid-sequence
(`verified⊧model` that the byte `0x0A` goes on the wire; its **meaning** is
`inferred` — likely "read ADC-reference register"). The 16-bit result lands in
`+0x46`.

**Boot — FPGA configuration upload** (`verified⊧model`, Run 4): immediately
after reset the MCU streams a **115638-byte** blob (38546 × 3-byte records)
from flash `0x08051D19` over SPI3, framed by a `0x3B` "begin" and a `0x3A`
"end", with PB6 as CS. Until this completes the FPGA SPI data interface is
inactive.

**Handshake opcodes `0x05` (ID query), `0x12`, `0x15`** appear in the static
protocol spec (`notes/scope_acquisition_spec.md`) but were **not** reached in
our emulation — treat as `static`, lower confidence than the table above.

---

## 3. Experiment A — passive capture (do this FIRST; no custom firmware)

The cheapest, highest-leverage validation. Probe the **stock** device with a
logic analyzer; do not flash anything. This falsifies or confirms our entire
model in one session.

**Probe:** SPI3 SCK / MISO / MOSI, **PB6** (CS), **PC6**, **PB11**, and USART2
TX/RX. (Confirm pins per the note in §1.)

**Captures:**
1. **Power-on** → capture the boot **bitstream upload**. Check: a `3B` framing
   byte, ~115638 payload bytes, a `3A` terminator, CS=PB6 held through it.
2. **Trigger an acquisition** in each acquisition mode via the front panel
   (normal/burst, roll, different vertical ranges to exercise auto-range).
   Check each command's MOSI against the table in §2.

**Pass/fail is per-row in the table.** Specifically worth watching:
- Does mode 9 really emit `09 FF FF 0A FF FF`? (Confirms the `0x0A` sub-opcode
  on silicon.)
- Does changing the vertical range produce the `01 <idx>` / `01 <idx+1>` /
  `01 12` auto-range pattern?
- Is PB6 asserted (LOW) for the duration of each command? Are PC6/PB11 actually
  held HIGH? (Confirms or corrects the handshake assumption.)
- **And capture the MISO bytes** — those are the FPGA replies we have as
  `unknown` placeholders. Even passively, a triggered acquisition reveals real
  reply values for the read-bearing commands (03/04/05/09).

A clean match here promotes the whole static+emulation model to
silicon-confirmed. A divergence tells us exactly where the model is wrong —
which is just as valuable.

---

## 4. Experiment B — active characterization (custom firmware; AFTER A is green)

Once passive capture confirms the framing, use the custom firmware to capture
what Renode fundamentally cannot give us: the FPGA's **responses** and the
**meaning** of each opcode.

Your firmware needs to: drive SPI3 to the FPGA as bus master, assert/deassert
PB6/PC6/PB11, send arbitrary command sequences, and log the MISO bytes. (Adapt
to your repo's actual SPI/GPIO API — the point is the protocol, not a specific
call.)

**B1 — reply-value table.** For each command in §2, send the predicted MOSI
sequence and **record every MISO byte**. This replaces the placeholder reply
values in `fpga_protocol.py`. Of particular interest:
- the `0x05` ID-query reply (FPGA identity/status byte),
- the mode-9 16-bit ADC-reference value (the two readback bytes around `0x0A`),
- the burst sample encoding (are the 512 pairs interleaved CH1/CH2 8-bit, as we
  infer? what do they look like with a known input signal?).

**B2 — opcode semantics (bisection).** Send one command/parameter at a time and
observe a measurable effect (ADC output with a known input, display, a
measurable FPGA state). Resolve the `inferred` meanings: what does `0x0A`
select? what does the `02 <mode>` byte switch (timebase? sample rate?)? what
does the cmd-08 computed trim actually adjust?

**B3 — handshake reality.** Confirm PB6 is CS (does holding it HIGH block SPI
data?), and whether PC6/PB11 truly gate the data interface (our model assumes
so but never drove them — they're set in boot code we skipped).

---

## 5. What we explicitly DO NOT know

- **All FPGA reply values** — every MISO byte in our model is a placeholder.
- **Opcode semantics** — `0x0A`, `0x12`, the `02/06/07` mode bytes: we know the
  byte on the wire, not what the FPGA does with it.
- **PC6/PB11 gating** — assumed HIGH/enabling; their drive code wasn't in the
  emulated paths.
- **The cal/bitstream blob contents** — we know it's 115638 bytes from
  `0x08051D19` and the framing; we have not decoded what it configures.
- **USART2 control-plane effect on the FPGA** beyond writes to the state struct.
- **Timing** — our emulation has no real clock; settle/debounce timing (the
  flash LUT thresholds, the cmd-09 inter-byte delay) is structural, not
  metric.

---

## 6. How to report back (so ripcord can reconcile)

For each prediction you test, report a line ripcord can fold into its contract
ledger:

```
cmd <NN> / <name>:  CONFIRMED | DIVERGED | reply-captured
  observed MOSI:  <bytes>
  observed MISO:  <bytes>           # the values we didn't have
  effect:         <what changed / what it controls, if B2>
  notes:          <how it differed from the §2 prediction, if DIVERGED>
```

Confirmations promote ripcord contracts `verified⊧model → execution-verified
(hardware)`. Divergences are corrections — most likely in the handshake gating,
the burst sample encoding, or any opcode whose meaning we marked `inferred`.
The source-of-truth model you are reconciling against is `fpga_protocol.py`
(the executable FPGA spec) and `notes/scope_acquisition_spec.md` (the prose
spec) in the ripcord repo.

---

*Generated from the ripcord Renode oracle runs 4–8 (2026-05-30). Provenance for
every claim: ripcord `build/contracts.sqlite` contract #18 (bitstream upload)
and #19 (acquisition runtime), and `notes/renode-at32-bringup.md`.*
