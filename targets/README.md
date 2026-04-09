# Test targets

This directory is where test binaries live. The contents (except this
README and `.gitkeep` files) are gitignored — binaries are built
locally, referenced by `config.yaml`, and not committed to the repo.

Each target is a subdirectory containing at least an ELF file. Naming
the ELF `blink.elf` or `<target>.elf` is conventional but not
required; the path is configured in `config.yaml`.

## Building the first target: Raspberry Pi Pico blinky

The default first test target. Cortex-M0+, bare metal, builds in
about a minute once the toolchain is installed.

### Prerequisites

```bash
# ARM toolchain
brew install --cask gcc-arm-embedded

# CMake and Ninja
brew install cmake ninja
```

### Build

In Pico SDK 2.x the example projects live in a separate repository
(`raspberrypi/pico-examples`), not inside the SDK itself.

```bash
# Clone the Pico SDK and the examples repo (outside ripcord)
git clone --depth 1 https://github.com/raspberrypi/pico-sdk ~/pico-sdk
cd ~/pico-sdk && git submodule update --init --depth 1

git clone --depth 1 https://github.com/raspberrypi/pico-examples ~/pico-examples

# Build the blink example
export PICO_SDK_PATH=~/pico-sdk
cd ~/pico-examples
mkdir -p build && cd build
cmake -G Ninja ..
ninja blink
```

The ELF lands at `~/pico-examples/build/blink/blink.elf`.

### Wire it into ripcord

```bash
cd ~/Desktop/ripcord
mkdir -p targets/pico_blinky
cp ~/pico-examples/build/blink/blink.elf targets/pico_blinky/blink.elf
```

The default `config.yaml` already references
`targets/pico_blinky/blink.elf`. Run the pipeline:

```bash
snakemake --cores 4
scripts/query \
    "SELECT name, size FROM functions WHERE source='pico_blinky' ORDER BY size DESC LIMIT 10"
```

## Building Zephyr sample targets (qemu_cortex_m3)

The currently-committed Zephyr targets are `zephyr_hello_world` and
`zephyr_synchronization`, both built for `qemu_cortex_m3` (an
emulated TI LM3S6965 board — Cortex-M3 with picolibc).

### Prerequisites

`west` and a full Zephyr workspace. Initialize once per machine:

```bash
# west goes in the pipeline venv
source ~/.venvs/ripcord/bin/activate
pip install west

# Initialize the workspace (~8 GB after update)
cd ~
west init -m https://github.com/zephyrproject-rtos/zephyr zephyrproject
cd ~/zephyrproject
west update                                             # ~5-10 min
pip install -r zephyr/scripts/requirements-base.txt
```

The build uses the existing `arm-none-eabi-gcc` Homebrew cask via
Zephyr's `gnuarmemb` toolchain variant — no Zephyr SDK download
required.

### Build

```bash
source ~/.venvs/ripcord/bin/activate
export ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb
export GNUARMEMB_TOOLCHAIN_PATH=/Applications/ArmGNUToolchain/15.2.rel1/arm-none-eabi
cd ~/zephyrproject

# hello_world
west build -b qemu_cortex_m3 zephyr/samples/hello_world
cp build/zephyr/zephyr.elf \
   ~/Desktop/ripcord/targets/zephyr_hello_world/zephyr.elf

# synchronization (rebuild after `west build` replaces the build dir)
rm -rf build
west build -b qemu_cortex_m3 zephyr/samples/synchronization
cp build/zephyr/zephyr.elf \
   ~/Desktop/ripcord/targets/zephyr_synchronization/zephyr.elf
```

Both entries are already in `config.yaml`. After copying the ELFs,
`snakemake --cores 4` picks them up automatically.

### Notes

- `qemu_cortex_m3` is the right starting board because it's pure
  software emulation — no hardware required, no peripheral quirks,
  and Zephyr ships a complete BSP for it.
- The two committed samples share a build config (`cortex-m3 -Os`
  picolibc), which is what makes the structural fingerprinting
  primitive in `notes/queries/structural_signatures.sql` produce
  ~96% precision when matching them against each other. Adding a
  third sample on the same board preserves that property and will
  add more shared kernel functions to the match set.
- Adding a Zephyr sample targeting a **different** board will
  change the build tuple and break cross-target matching against
  the qemu_cortex_m3 pair. That's expected (see design-decision
  D18) and is useful signal if you want to expand the target matrix
  intentionally.

## Building Pico + FreeRTOS targets

The FreeRTOS targets use `pico-examples` with FreeRTOS-Kernel.

### Prerequisites

```bash
# Clone FreeRTOS-Kernel (outside ripcord)
git clone --depth 1 https://github.com/FreeRTOS/FreeRTOS-Kernel ~/FreeRTOS-Kernel
```

### Build

```bash
export PICO_SDK_PATH=~/pico-sdk
export FREERTOS_KERNEL_PATH=~/FreeRTOS-Kernel
cd ~/pico-examples/build

# Reconfigure with FreeRTOS support
cmake -G Ninja -DFREERTOS_KERNEL_PATH=$FREERTOS_KERNEL_PATH ..

# hello_freertos (heap4 variant)
ninja freertos/hello_freertos/hello_freertos
mkdir -p ~/Desktop/ripcord/targets/pico_freertos_hello
cp freertos/hello_freertos/hello_freertos.elf \
   ~/Desktop/ripcord/targets/pico_freertos_hello/

# static allocation variant
ninja freertos/hello_freertos/hello_freertos_static
mkdir -p ~/Desktop/ripcord/targets/pico_freertos_static
cp freertos/hello_freertos/hello_freertos_static.elf \
   ~/Desktop/ripcord/targets/pico_freertos_static/

# Stripped blind-recovery test target
mkdir -p ~/Desktop/ripcord/targets/pico_freertos_hello_stripped
arm-none-eabi-strip -s \
   ~/Desktop/ripcord/targets/pico_freertos_hello/hello_freertos.elf \
   -o ~/Desktop/ripcord/targets/pico_freertos_hello_stripped/hello_freertos_stripped.elf
```

All entries are already in `config.yaml`. After copying the ELFs,
`snakemake --cores 4 --resources ghidra=1` picks them up.

## Adding more targets

Build an ELF somewhere, drop it under `targets/<your_target_name>/`,
and add an entry to `config.yaml`:

```yaml
targets:
  your_target_name:
    elf: targets/your_target_name/your.elf
    description: "brief description"
    arch: arm   # or avr, riscv, etc.
```

No Snakemake rules need to change — the pipeline iterates over every
target in the config. `arch` selects which `nm` binary the
`ground_truth_functions` rule invokes; the supported values are in
`scripts/ingest/load_ground_truth.py`.

## Target candidates for the early roadmap

Updated 2026-04-08 based on what's been built and what's most useful
next.

**Done:**

1. ✅ **Raspberry Pi Pico blinky** (Cortex-M0+, newlib, -O3) — 84 fn
2. ✅ **Zephyr hello_world on qemu_cortex_m3** (Cortex-M3, picolibc, -Os) — 110 fn
3. ✅ **Zephyr synchronization on qemu_cortex_m3** (same build tuple as #2) — 130 fn
4. ✅ **Pico + FreeRTOS hello (heap4)** (Cortex-M0+, newlib, -O3) — 265 fn
5. ✅ **Pico + FreeRTOS hello (static alloc)** (same build tuple as #4) — 284 fn
6. ✅ **Pico hello_usb** (Cortex-M0+, newlib, -O3, + TinyUSB) — 237 fn
7. ✅ **Pico hello_timer** (Cortex-M0+, newlib, -O3) — 155 fn
8. ✅ **Pico + FreeRTOS hello (stripped)** (same binary as #4, symbols removed) — 197 fn. Blind recovery test target: 86.6% recall, 94.9% precision when matched against the full-symbol corpus.

**Recommended next, in rough cost-value order:**

9. **FreeRTOS for `cortex-m3 -Os` with picolibc.** Matches the
   Zephyr build config for cross-ecosystem library-ID testing. This
   is the highest-value next target because it tests whether FreeRTOS
   functions can be identified across the Pico/Zephyr divide when
   compiled with matching flags.
10. **STM32 CubeMX blinky.** New build tuple (Cortex-M4, vendor HAL);
    expands the matrix. Exposes ST HAL for eventual vendor library
    identification.
11. **Arduino Uno blink.** AVR 8-bit, cross-architecture generality
    stress test. Validates that the pipeline handles non-ARM ISAs.
12. **ESP32-C3 blinky.** RISC-V, more architecture diversity.

Any combination is fine — the pipeline doesn't care what the targets
are, it just runs Ghidra on each ELF and populates the warehouse.
The build-matrix matters for Phase 1 fingerprinting, not for the
pipeline itself.
