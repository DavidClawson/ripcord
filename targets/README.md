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
duckdb build/warehouse.duckdb \
    "SELECT name, size FROM functions WHERE source='pico_blinky' ORDER BY size DESC LIMIT 10"
```

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
target in the config.

## Target candidates for the early roadmap

In roughly the order they should be added:

1. **Raspberry Pi Pico blinky** (Cortex-M0+, bare metal) — above.
2. **Pico with FreeRTOS.** Same toolchain, adds RTOS code.
3. **Zephyr `samples/hello_world`** on `qemu_cortex_m3`. QEMU-runnable,
   different RTOS, no hardware required for emulation tests.
4. **STM32 CubeMX blinky.** Exposes ST HAL for vendor library ID.
5. **Arduino Uno blink.** AVR 8-bit, cross-architecture generality.
6. **ESP32-C3 blinky.** RISC-V, more architecture diversity.

Any combination is fine — the pipeline doesn't care what the targets
are, it just runs Ghidra on each ELF and populates the warehouse.
