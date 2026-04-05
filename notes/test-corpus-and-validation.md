# Test Corpus and Validation Strategy

A key insight: before pointing this pipeline at the AT32F403A firmware
where you don't know the ground truth, **run it against firmware where you
do know the ground truth.** Compile open-source firmware yourself, strip
it, and feed it to the pipeline. Then compare what the pipeline recovers
against the source you started from. Every discrepancy is either a
pipeline bug or a genuinely hard RE problem worth studying.

> **Status update (2026-04-05):** validation is live. The ground-
> truth comparison against `nm -S` is a committed pipeline rule
> (`ground_truth_functions.parquet`) with a committed regression
> query (`notes/queries/coverage.sql`). Three targets have been
> run through it: Pico blinky (68.8% raw coverage, 100% of real
> function bodies — the gap is non-function symbols documented in
> `notes/ghidra-extraction-notes.md`) and two Zephyr samples on
> qemu_cortex_m3 (97.0% raw coverage each). The test-difficulty
> ramp below was followed roughly in order: step 1 (Pico blinky)
> is done; the intermediate steps were partially skipped in favor
> of a Zephyr sample because the Zephyr pair was specifically
> needed to validate the structural fingerprinting primitive.

This also doubles as the foundation for a **fingerprint library** that
makes Stage 1 (library identification) dramatically more powerful — not
just for this project, but reusable across any future firmware RE work.

## Why this matters

1. **Ground truth you can verify against.** You know exactly what
   `xTaskCreate` looks like in the source, so when the pipeline lifts it
   from a compiled binary, you can score the result precisely. The
   cord firmware gives you no such luxury.
2. **Iteration speed.** You can rebuild the test binary in seconds with
   different optimization levels, different compilers, different
   configurations. The cord binary is fixed forever.
3. **Known error bars.** After running the pipeline on 20 well-understood
   test binaries, you have a realistic sense of its accuracy. Without
   this you're guessing.
4. **Regression testing.** Every time you change the pipeline, re-run
   against the corpus. Changes that improve one metric often silently
   regress another — a test suite catches this.
5. **Fingerprint library falls out for free.** Every compiled test binary
   is a source of library signatures. A corpus of a few hundred well-known
   firmwares gives you a library identification database that rivals
   commercial FLIRT sets.

## Test difficulty ramp — start even smaller than you think

The cleanest way to validate the pipeline is to start with something
that has almost no content at all and add one dimension of complexity
at a time. Each rung of the ramp has perfectly known ground truth and
isolates exactly one capability:

1. **Empty `main` with CMSIS startup only.** No RTOS, no peripherals,
   just the vector table, the C runtime init, and a `while(1);`. The
   pipeline should recover the vector table, identify `Reset_Handler`,
   find the C runtime initialization sequence, and correctly classify
   `main` as doing nothing. If it can't do this cleanly, there is no
   point running it against anything harder.
2. **FreeRTOS kernel only** (no application code). This is better than
   a FreeRTOS demo because there's no application logic to confuse the
   library identification. Every function in the binary has a name in
   the source, a stable structure, and a well-understood role. The
   pipeline should identify `xTaskCreate`, `vTaskDelay`,
   `xQueueReceive`, the scheduler, the tick handler, and the port
   layer against perfect ground truth.
3. **FreeRTOS + one demo task that blinks an LED.** Adds exactly one
   new dimension: peripheral access. The pipeline now needs to
   correctly distinguish application code from kernel code, and
   identify the single peripheral touched.
4. **FreeRTOS + STM32 HAL + an external peripheral over FSMC** (e.g.,
   SDRAM or an LCD on an STM32F4 Discovery board). This is the closest
   possible analog to the cord target — same RTOS, same peripheral
   bus, same general shape. If the pipeline handles this cleanly, it
   should handle the cord firmware.

Each rung adds exactly one new capability to exercise and tests it in
isolation. Climbing the ramp end to end is probably a few days of
pipeline work and at the end you have calibrated error bars for every
stage on known-good ground truth.

## Candidate test targets

Good test targets are: open source, well documented, compile cleanly with
common toolchains, target chips that are thoroughly documented, and cover
a range of complexity and styles.

### Cortex-M / ARM (most relevant — same family as the AT32)

- **Zephyr RTOS samples.** Dozens of sample apps, canonical board
  definitions, builds cleanly with `west`, widely used. `blinky`, `hello_world`,
  `button`, `shell`, `usb`, `bluetooth` samples span from trivial to
  complex. Zephyr targets STM32 dev boards natively so there's no chip
  porting work.
- **NuttX sample apps.** Similar to Zephyr, more POSIX-flavored, good
  coverage of filesystems and networking.
- **Mbed OS examples.** Arm's own RTOS with clean examples on STM32,
  NXP, Nordic boards.
- **Rust embedded / RTIC demos.** Same chip families, but built with
  `cargo-embed` / `probe-rs`. Useful for testing the pipeline on
  Rust-compiled binaries as a sanity check that the approach isn't
  C-specific.
- **FreeRTOS demos.** Since the cord firmware uses FreeRTOS, their
  canonical demos on STM32F4 are the closest possible analog to the
  real target. Compile one, strip it, run the pipeline, see whether it
  recovers the FreeRTOS calls and the demo-specific logic.
- **Arduino core + sample sketches on STM32duino or Arduino Giga.**
  Consumer-grade, heavily documented, everyone has seen the source.
- **TinyGo examples on STM32/Nordic.** Another language-variant sanity
  check.
- **libopencm3 examples.** Bare-metal Cortex-M without an RTOS. Useful
  for testing pipeline behavior on the simplest possible end of the
  spectrum.

### RISC-V (for diversification)

- **ESP32 / ESP-IDF sample apps** (Xtensa or RISC-V variants) —
  consumer-grade, ubiquitous, enormous sample library.
- **SiFive / BL602 demos** — open silicon, open toolchain, thoroughly
  documented.

### Bigger targets (for stress testing)

- **MicroPython** compiled for STM32F4 — a full language runtime is a
  great stress test for call graph recovery and library identification.
- **LVGL demo apps** on STM32 — real graphics stack, lots of callbacks,
  good test of data structure recovery.
- **Nerves / Elixir firmware** — BEAM runtime on embedded; unusual
  compilation patterns.

### Open-source hardware with real peripherals

If you want actual hardware to probe, model in Renode, or verify
against, these are the standouts:

- **ULX3S** — the single best match for the cord project's architecture.
  An open-hardware dev board with an ESP32 microcontroller connected to
  a Lattice ECP5 FPGA, where *everything* is open source: schematics,
  ESP32 firmware, FPGA gateware (Verilog/Amaranth), toolchain
  (Yosys + nextpnr, fully open). You can run the pipeline against
  ESP32 firmware talking to an FPGA and verify every inference
  against the actual HDL source. This is the perfect validation target
  for the MCU↔FPGA boundary extraction specifically. ~$155.
- **Raspberry Pi Pico (RP2040).** Open chip, open SDK, enormous sample
  base. Much cleaner than STM32 for a first test.
- **STM32 Discovery / Nucleo boards.** Closest architecture family to
  the cord target. STM32CubeMX generates reference projects you can
  compile from source. The STM32F4 Discovery with external SDRAM over
  FSMC is particularly on-point.
- **PineTime (InfiniTime firmware).** nRF52832 (Cortex-M4, same class),
  FreeRTOS-based, touch display over SPI, heart rate sensor over I²C,
  Bluetooth. Small enough to fully understand, big enough to be
  interesting. Real product, fully open, FreeRTOS just like cord.
- **Flipper Zero.** STM32WB55 (Cortex-M4), FreeRTOS, enormous peripheral
  variety (NFC, sub-GHz, IR, 1-Wire, LCD, SD). Huge community means
  every function has been discussed somewhere on the internet. Good
  stress test target once the pipeline works on simpler things.

### Other MCU+FPGA combinations

If the MCU+FPGA pairing is what you want to stress specifically, ULX3S
is the standout but there are others:

- **QMTech / cheap STM32+FPGA dev boards** from AliExpress. Sparse
  documentation but actual hardware to probe.
- **OrangeCrab** — RISC-V + ECP5, smaller sibling of ULX3S.
- **Precursor / Betrusted** — security-focused, iCE40 plus application
  MCU, fully open hardware.

### Closest analog to the cord target

If you want one test target that most resembles the actual project,
build a **FreeRTOS + STM32F4 HAL demo with a simple peripheral over
FSMC**. The STM32F4 discovery boards with external SDRAM or LCD over
FSMC give you a known-good example of "MCU driving an external device
over the same bus the FPGA uses." If the pipeline can recover that
structure from a stripped binary of a known demo, you have very high
confidence it will do the same on the cord firmware.

## Validation methodology

For each test target:

1. **Compile from source** with known toolchain flags. Record them.
2. **Strip symbols** to simulate the reverse engineering scenario.
   Keep the unstripped ELF as the ground-truth reference.
3. **Run the pipeline** end-to-end: Ghidra extraction → library
   identification → optional trace capture in Renode → derivation → any
   agent passes.
4. **Score the results** against ground truth:
   - Function identification rate: what percent of functions were
     correctly named by the library matcher?
   - Signature recovery accuracy: for functions the pipeline named, how
     many had correct parameter types?
   - Call graph completeness: does the recovered call graph match the
     ground truth call graph? (Easy to generate ground truth from the
     unstripped binary.)
   - Type recovery: if the pipeline proposes a struct layout, does it
     match the source?
   - Verification pass rate: for any lifted functions, do they pass
     differential testing against the original?
5. **Store results** as rows in a `validation_runs` table in the same
   DuckDB warehouse, tagged with pipeline version and target. You
   immediately have a regression-testable history.

### Round-trip tests specifically

The most useful single test: **compile → strip → run pipeline → render
lifted C → recompile → diff the lifted binary against the original**.
This is the N64 decomp community's "matching" criterion imported to
firmware. If the pipeline can produce C that recompiles to a
byte-identical binary, you know it recovered the full semantics. If it
produces something that doesn't match, the diff tells you exactly what
it got wrong.

This test won't pass end-to-end for complex targets any time soon —
matching decomp is extraordinarily hard. But partial matching (say, 60%
of functions produce byte-matching output) is a concrete, improvable
metric, and it's far more rigorous than "the agent's output looks
plausible."

## The fingerprint library corollary

Every compiled test binary is a source of library function signatures.
Scraping open-source embedded projects at scale gives you a library
identification corpus with huge coverage:

### Sources to scrape

- **Zephyr** — builds for dozens of boards, covers HAL code for most
  Cortex-M vendors. One Zephyr build gives you signatures for CMSIS,
  the vendor HAL, the Zephyr kernel, drivers for common peripherals,
  and sample applications.
- **PlatformIO registry** — curated index of embedded libraries with
  metadata. Scriptable downloads.
- **STM32CubeIDE / CubeMX examples** — thousands of reference projects
  published by ST. Compiling a sample of these gives you comprehensive
  STM32 HAL coverage.
- **Arduino library index** — enormous corpus of consumer libraries.
- **FreeRTOS demos** across all their supported ports.
- **ESP-IDF examples.**
- **Github search** for `freertos`, `platformio.ini`, `main.c`,
  `CMakeLists.txt` near known embedded keywords.

### Extraction pipeline

For each scraped project:

1. Compile with the project's declared toolchain (CI-style).
2. Produce multiple builds: `-O0`, `-O2`, `-Os`, with/without LTO,
   different compiler versions (GCC 10, 12, 13, clang). Compilation
   flags change signatures dramatically, so multi-config is essential.
3. Extract per-function signatures: byte patterns, basic-block hashes,
   structural features, CFG shape, string references.
4. Store in a dedicated DuckDB fingerprint database separate from any
   individual RE project's warehouse. Keyed by `(library, version,
   toolchain, flags, function_name)`.

### Matching strategy

When analyzing an unknown firmware:

1. Query the fingerprint DB with each function's features.
2. Rank candidate matches by confidence. Structural matches are weaker
   than exact byte matches but still useful.
3. Apply high-confidence matches to the warehouse directly.
4. Flag ambiguous matches as proposals for the agent swarm or manual
   review.
5. Record every match with provenance so you can audit false positives
   later.

### Why this is strategically valuable beyond the cord project

A good fingerprint library is **a reusable capability that outlives any
single target.** Every future firmware RE project starts with 60-80% of
the binary already identified. The cost of building it amortizes
across every project that uses it. And the corpus itself — open-source,
CI-buildable, hash-addressable — is the kind of thing that could be
published openly and benefit the broader community.

## Suggested validation sequence

Before the cord firmware work goes any deeper:

1. **Week 1:** Pick one simple target — probably a Zephyr `blinky` or
   FreeRTOS demo for STM32F4 — and run it through whatever slice of the
   pipeline you've built. Measure results against ground truth. Iterate
   on the pipeline until the results make sense.
2. **Week 2:** Scale to 5-10 targets of varying complexity. Establish
   baseline metrics. Fix systemic issues the first run revealed.
3. **Week 3:** Start the fingerprint corpus build — automate
   compilation of a few dozen open-source projects with multiple
   toolchain configs, populate the fingerprint DB.
4. **Week 4:** Now rerun library identification on the cord firmware
   with the richer fingerprint DB. You will almost certainly identify a
   substantially larger fraction of the binary.

This is a detour from the cord-specific work, but **the detour is
faster than the straight line** because it gives you a calibrated
pipeline, a known error profile, and a fingerprint database that
collapses the unknown surface on the real target.

## Caveats

- **Scraping and compiling public code at scale has practical costs:**
  storage, CI time, license review, build environment maintenance.
  Start small; grow when it proves valuable.
- **Toolchain drift is real.** Signatures compiled with GCC 11 often
  don't match GCC 13 output. The multi-config approach mitigates this
  but doesn't eliminate it.
- **Build-matrix mismatches are even more real, and were empirically
  verified on 2026-04-05.** Same toolchain alone is not sufficient
  for cross-target matching. The actual requirement is matching
  (ISA, -O level, libc, link surface). A reference corpus for
  rule-based Phase 1 fingerprinting must span the build tuples
  that target binaries use, not just the source libraries. See
  design-decision D18 and `notes/fingerprinting-baseline.md`.
- **The cord firmware's exact toolchain is unknown** and matters for
  signature matching. Worth investigating whether any vendor artifacts
  (e.g., compiler version strings embedded in the binary, ELF notes if
  there's an intermediate ELF floating around, or known Artery SDK
  toolchain defaults) can narrow it down. If you find a strong clue,
  generate fingerprints specifically for that toolchain first.
- **Matching doesn't solve everything.** Even with a perfect fingerprint
  library, the application code unique to this product still needs the
  full pipeline. The library corpus collapses the haystack; it doesn't
  find the needle.
