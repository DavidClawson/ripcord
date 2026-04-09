# Setup

Tooling and environment prerequisites for running the ripcord
pipeline. Nothing here is target-specific; ripcord works on any ELF
binary it is pointed at via `config.yaml`.

## Required tools

### Ghidra

Latest stable release, running on your local machine. On macOS,
install via Homebrew as a formula (the old cask no longer exists):

```bash
brew install ghidra
```

Or download from https://ghidra-sre.org/. The pipeline drives Ghidra
via `pyghidraRun -H`, which lives alongside `analyzeHeadless` under
`<ghidra_root>/support/`. The Homebrew formula puts it at
`/opt/homebrew/opt/ghidra/libexec/support/pyghidraRun`. See the
[Environment variables](#environment-variables) section below for the
`GHIDRA_PYGHIDRA` and `JAVA_HOME` variables the Snakefile expects.

### PyGhidra (Python 3 scripting inside Ghidra)

Historical note: ripcord originally used
[Mandiant's Ghidrathon extension](https://github.com/mandiant/Ghidrathon)
to get CPython 3 inside Ghidra. Ghidra 11.2+ ships **PyGhidra natively**
and its `PyGhidraScriptProvider` claims `.py` files at the JVM level,
so Ghidrathon is redundant on modern Ghidra. ripcord uses native
PyGhidra, invoked via `pyghidraRun -H` (which is `analyzeHeadless`
launched under a Python 3 runtime).

You do not install PyGhidra as a Ghidra extension — you install the
companion `pyghidra` Python package into the same venv the rest of
the pipeline uses. It brings `jpype1` along as a dependency, which
is what bridges Python to Ghidra's JVM. See the Python section below.

### Python 3.11+ (via uv)

Dependencies are declared in `pyproject.toml`. Install
[uv](https://docs.astral.sh/uv/) and sync:

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# From the repo root — creates .venv/ and installs all deps
uv sync
```

All pipeline scripts (`scripts/query`, Snakemake ingest rules) use
`uv run` to pick up the project venv automatically. No manual
activation needed.

`pyghidra` pulls in `jpype1`, which builds a native extension against
your Python version. On Python 3.14 there are no prebuilt wheels yet,
so pip will compile from source (~20 seconds). A C toolchain is
required (Xcode command line tools on macOS).

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
- **west + Zephyr workspace** — required if you want to build any
  Zephyr sample target (e.g. `zephyr_hello_world`,
  `zephyr_synchronization`). See `targets/README.md` for the full
  Zephyr build path. Short version:

  ```bash
  # Install west into the pipeline venv
  source ~/.venvs/ripcord/bin/activate
  pip install west

  # Initialize the Zephyr workspace (~8 GB after update)
  cd ~
  west init -m https://github.com/zephyrproject-rtos/zephyr zephyrproject
  cd ~/zephyrproject
  west update                                              # ~5-10 min
  pip install -r zephyr/scripts/requirements-base.txt

  # Use the existing arm-none-eabi-gcc via the gnuarmemb toolchain
  # variant — no Zephyr SDK download needed.
  export ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb
  export GNUARMEMB_TOOLCHAIN_PATH=/Applications/ArmGNUToolchain/15.2.rel1/arm-none-eabi
  ```

  The `GNUARMEMB_TOOLCHAIN_PATH` path will differ if you have a
  different `arm-none-eabi-gcc` version from Homebrew; the pattern
  is `/Applications/ArmGNUToolchain/<version>/arm-none-eabi`.

## Environment variables

The Snakefile reads three environment variables. Set them in your
shell (or put them in `~/.zshrc`) before running the pipeline:

```bash
# Ghidra's PyGhidra launcher (analyzeHeadless under a Python 3 runtime)
export GHIDRA_PYGHIDRA=/opt/homebrew/opt/ghidra/libexec/support/pyghidraRun

# JDK 21 for PyGhidra. Ghidra 12.x requires JDK 21+; PyGhidra reads
# JAVA_HOME (unlike analyzeHeadless, which auto-detects).
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home

# Pin the Python interpreter Snakemake uses for the DuckDB ingest rule
# to the pipeline venv, not whatever `python3` resolves to on $PATH.
export PYTHON=$HOME/.venvs/ripcord/bin/python
```

`openjdk@21` is installed automatically as a transitive dependency of
`brew install ghidra`.

## Verifying the environment

Once Ghidra and the Python environment are set up:

```bash
# PyGhidra launcher (prints version info and exits non-zero without args — expected)
$GHIDRA_PYGHIDRA -H 2>&1 | tail -3

# Python environment
source ~/.venvs/ripcord/bin/activate
python -c "import duckdb, pyarrow, snakemake, pyghidra; print('python ok')"

# Snakemake
snakemake --version
```

You are then ready to build a test target and run the pipeline.

## Building a first test target

See [`targets/README.md`](./targets/README.md) for instructions on
building the Pico SDK blinky example and wiring it into the pipeline
via `config.yaml`.

## No firmware binary is required

ripcord has no built-in assumption about any specific target binary.
Targets are listed in `config.yaml` and built separately. The
repository ships with no firmware and requires none to run — point
the pipeline at any ELF you want to analyze.
