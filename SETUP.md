# Setup

Tooling and environment prerequisites for running the ripcord
pipeline. Nothing here is target-specific; ripcord works on any ELF
binary it is pointed at via `config.yaml`.

## Required tools

### Ghidra

Latest stable release, running on your local machine. Installed via
Homebrew (`brew install --cask ghidra`) or downloaded from
https://ghidra-sre.org/. The pipeline invokes `analyzeHeadless`, which
ships with every Ghidra install under `<ghidra_root>/support/`.

If `analyzeHeadless` is not on your `$PATH`, export its location
before running the pipeline:

```bash
export GHIDRA_HEADLESS=/Applications/ghidra_11.3_PUBLIC/support/analyzeHeadless
```

(Replace the path with whichever version you have installed.) The
Snakefile picks up this variable.

### Ghidrathon

[Mandiant's Ghidrathon extension](https://github.com/mandiant/Ghidrathon)
replaces Ghidra's bundled Jython 2 with modern CPython 3, which makes
extraction scripts sane to write and lets them share a Python
environment with the rest of the pipeline.

1. Check your Ghidra version (`Help → About Ghidra`).
2. Download the Ghidrathon release matching that Ghidra version from
   https://github.com/mandiant/Ghidrathon/releases.
3. In Ghidra, go to `File → Install Extensions` and install the
   downloaded `.zip`.
4. Restart Ghidra.
5. In Ghidra's Script Manager, configure the Python interpreter path
   to point at the same Python you use for the rest of the pipeline
   (see next section).

### Python 3.11+

Any modern Python will do. The pipeline uses the following packages:

```bash
pip install 'duckdb>=0.10' pyarrow polars snakemake
```

Those same packages need to be available to Ghidrathon (so extraction
scripts can write Parquet or JSON if they need to). The cleanest
setup is a single virtualenv used both by Ghidrathon and by Snakemake:

```bash
python3 -m venv ~/.venvs/ripcord
source ~/.venvs/ripcord/bin/activate
pip install 'duckdb>=0.10' pyarrow polars snakemake
```

Then point Ghidrathon at `~/.venvs/ripcord/bin/python` during its
configuration step.

### DuckDB CLI (optional but recommended)

For interactive queries against the warehouse outside of Python:

```bash
brew install duckdb
```

The Python bindings above are sufficient for the pipeline itself;
the CLI is just for exploration.

### Snakemake

Installed as part of the Python packages above. Verify:

```bash
snakemake --version
```

## Optional tools (added in later phases)

- **arm-none-eabi-gcc** — ARM toolchain for building test targets
  from source. Required for the Pico SDK, Zephyr, and FreeRTOS test
  targets. Install via `brew install --cask gcc-arm-embedded`.
- **Raspberry Pi Pico SDK** — the first test target builds against
  this. Clone from https://github.com/raspberrypi/pico-sdk to a
  convenient location and export `PICO_SDK_PATH`. See
  [`targets/README.md`](./targets/README.md).
- **Renode** — full-system emulator for hardware trace capture.
  Added in a later pipeline phase. Install from
  https://renode.io/.
- **Unicorn Engine** — per-function differential testing. Added in a
  later phase. `pip install unicorn`.
- **angr** — targeted symbolic execution for hard functions. Later
  phase. `pip install angr`.
- **Soufflé** — Datalog engine for the fact derivation layer. Later
  phase.

## Verifying the environment

Once Ghidra and the Python environment are set up:

```bash
# Ghidra headless
analyzeHeadless --help 2>&1 | head -3
#   (or: $GHIDRA_HEADLESS --help)

# Python environment
python -c "import duckdb, pyarrow, snakemake; print('python ok')"

# Snakemake
snakemake --version
```

All three should return without error. You are then ready to build a
test target and run the pipeline.

## Building a first test target

See [`targets/README.md`](./targets/README.md) for instructions on
building the Pico SDK blinky example and wiring it into the pipeline
via `config.yaml`.

## No firmware binary is required

ripcord has no built-in assumption about any specific target binary.
Targets are listed in `config.yaml` and built separately. The
repository ships with no firmware and requires none to run — point
the pipeline at any ELF you want to analyze.
