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

### Python 3.11+

A single virtualenv is used for Snakemake, DuckDB/Polars ingest, and
PyGhidra:

```bash
python3 -m venv ~/.venvs/ripcord
source ~/.venvs/ripcord/bin/activate
pip install 'duckdb>=0.10' pyarrow polars snakemake pyghidra
```

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
