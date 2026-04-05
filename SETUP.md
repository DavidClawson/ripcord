# Setup

ripcord expects certain inputs to exist alongside the repository. None
of them are tracked in git — they are either vendor-owned, large
build outputs, or regeneratable artifacts.

## Expected layout

The repository is designed to live at `cord/ripcord/` with its inputs
in the parent `cord/` directory:

```
cord/
├── APP_2C53T_V1.2.0_251015.bin    # firmware under analysis
├── at32f403a_lib/                  # ArteryTek AT32F403A SDK
├── FreeRTOS/                       # FreeRTOS source tree (MIT)
├── Update Log.txt                  # vendor changelog
└── ripcord/                        # this repository
```

Nothing inside `ripcord/` references these paths with absolute paths —
pipeline scripts resolve them relative to the repo root (`../`). When
the pipeline code starts to exist, any required path configuration
will be declared in a single place (likely the Snakemake config or an
`.env`-style file that is itself gitignored).

## Fresh checkout instructions

If you are setting up a new machine or a new clone:

1. Clone this repository somewhere convenient.
2. Place the firmware binary at `../APP_2C53T_V1.2.0_251015.bin`
   relative to the repo root, or update your local config to point at
   its actual path.
3. Obtain the AT32F403A SDK from ArteryTek's developer portal and
   extract it to `../at32f403a_lib/`.
4. Clone FreeRTOS from https://github.com/FreeRTOS/FreeRTOS to
   `../FreeRTOS/`.

## Ownership note

The firmware binary is the original vendor's intellectual property and
is not included in this repository. All analysis work captured in this
repository is the repository author's own work product.

## Toolchain prerequisites

None installed yet — these will be documented here as they are added
during Phase 0 bootstrapping (see `notes/PLAN.md`). Expected list:

- **Python 3.11+** with `duckdb`, `pyarrow`, `polars`, `snakemake`,
  `unicorn`, eventually `angr`
- **Ghidra** (latest stable) with **Ghidrathon** for Python 3 scripting
- **Renode** (you already have it from another project)
- **Soufflé** (Datalog engine) — later, for the derivation layer
- **arm-none-eabi-gcc** toolchain — for compiling FreeRTOS and the
  AT32 SDK for library identification

When Phase 0 actually starts, this file will grow a versioned
dependency manifest and installation instructions.
