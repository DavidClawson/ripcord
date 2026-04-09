#!/usr/bin/env -S uv run python
"""ripcord — analyze a firmware binary end-to-end in one command.

Orchestrates the full pipeline: binary identification, Ghidra extraction,
Parquet ingest, call recovery, peripheral classification, and summary.

Usage:
    scripts/ripcord.py firmware.bin --chip AT32F403A --base-addr 0x08004000
    scripts/ripcord.py firmware.elf
    scripts/ripcord.py --report stock_v120
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = REPO_ROOT / "build"
SCRIPTS_DIR = REPO_ROOT / "scripts"
TARGETS_DIR = REPO_ROOT / "targets"

GHIDRA_PYGHIDRA = os.environ.get("GHIDRA_PYGHIDRA", "pyghidraRun")
PYTHON = os.environ.get("PYTHON", "uv run python")

ELF_MAGIC = b"\x7fELF"

# Chip → SVD filename mapping (files live in targets/_svd/)
SVD_MAP = {
    "AT32F403A": "AT32F403Axx_v2.svd",
    "AT32F407":  "AT32F403Axx_v2.svd",
    "RP2040":    "RP2040.svd",
    "LM3S6965":  "LM3S6965.svd",
}

# JSONL tables produced by Ghidra extraction, in postScript order
GHIDRA_TABLES = [
    "functions",
    "calls",
    "basic_blocks",
    "xrefs",
    "strings",
    "pcode",
]

# Parquet tables produced by ingest (table_name → jsonl_stem)
INGEST_MAP = {
    "functions":      "functions",
    "calls":          "calls",
    "basic_blocks":   "basic_blocks",
    "xrefs":          "xrefs",
    "strings":        "strings",
    "pcode_features": "pcode",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Analyze a firmware binary end-to-end.",
        epilog="examples:\n"
               "  %(prog)s firmware.bin --chip AT32F403A --base-addr 0x08004000\n"
               "  %(prog)s firmware.elf\n"
               "  %(prog)s --report stock_v120",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("binary", nargs="?", type=Path, help="firmware binary (ELF or raw .bin)")
    p.add_argument("--chip", help="chip family (e.g. AT32F403A, RP2040)")
    p.add_argument("--arch", default="arm", help="Ghidra arch string (default: arm)")
    p.add_argument("--base-addr", type=lambda x: int(x, 0), default=None,
                   help="load address for raw binaries (default: auto-detect or 0x08000000)")
    p.add_argument("--name", help="target name (default: derived from filename)")
    p.add_argument("--report", metavar="TARGET", help="skip analysis, print summary for existing target")
    p.add_argument("--no-open", action="store_true", help="don't open the report in a browser")
    return p.parse_args()


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def step(n: int, total: int, msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  Step {n}/{total}: {msg}")
    print(f"{'='*60}\n")


def run(cmd: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a shell command, printing it first."""
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=str(REPO_ROOT), **kwargs)
    if check and result.returncode != 0:
        die(f"command failed (exit {result.returncode}): {cmd}")
    return result


def is_elf(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(4) == ELF_MAGIC


def elf_arch(path: Path) -> str:
    """Read ISA from ELF headers. Returns 'arm' for ARM."""
    data = path.read_bytes()
    if len(data) < 20:
        return "unknown"
    e_machine = struct.unpack_from("<H", data, 18)[0]
    return {0x28: "arm", 0x08: "mips", 0xF3: "riscv", 0x03: "x86",
            0x3E: "x86-64", 0xB7: "aarch64"}.get(e_machine, "unknown")


def detect_base_addr(path: Path) -> int | None:
    """Try to detect base address from Cortex-M vector table."""
    data = path.read_bytes()
    if len(data) < 8:
        return None
    sp_init = struct.unpack_from("<I", data, 0)[0]
    if not (0x20000000 <= sp_init <= 0x20FFFFFF):
        return None
    vec_addrs = [struct.unpack_from("<I", data, i * 4)[0] & ~1
                 for i in range(1, min(16, len(data) // 4))
                 if struct.unpack_from("<I", data, i * 4)[0] not in (0, 0xFFFFFFFF)]
    return (min(vec_addrs) & ~0xFFF) if vec_addrs else 0x08000000


def resolve_svd(chip: str | None) -> Path | None:
    """Find SVD file for a chip, or None."""
    if not chip:
        return None
    chip_upper = chip.upper().strip()
    for key, filename in SVD_MAP.items():
        if chip_upper.startswith(key.upper()):
            p = TARGETS_DIR / "_svd" / filename
            if p.exists():
                return p
            print(f"  warning: SVD file {p} not found")
            return None
    print(f"  warning: no SVD mapping for chip '{chip}'")
    return None


def sanitize_name(filename: str) -> str:
    """Convert a filename to a valid target name."""
    stem = Path(filename).stem
    # Replace non-alphanumeric with underscore, collapse runs
    name = re.sub(r"[^a-zA-Z0-9]", "_", stem)
    name = re.sub(r"_+", "_", name).strip("_").lower()
    return name or "target"


def setup_target(binary: Path, name: str) -> Path:
    """Create target directory and copy binary in. Returns path to the binary copy."""
    target_dir = TARGETS_DIR / name
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / binary.name
    if not dest.exists() or not dest.samefile(binary):
        shutil.copy2(binary, dest)
        print(f"  copied {binary} -> {dest}")
    else:
        print(f"  binary already in place: {dest}")
    return dest


def check_ghidra() -> None:
    """Verify Ghidra is reachable."""
    r = subprocess.run(f"which {GHIDRA_PYGHIDRA.split()[0]}",
                       shell=True, capture_output=True)
    if r.returncode != 0:
        die(f"Ghidra not found. Set GHIDRA_PYGHIDRA to the path to pyghidraRun.\n"
            f"  Current value: {GHIDRA_PYGHIDRA}\n"
            f"  See SETUP.md for installation instructions.")


def run_ghidra(target_name: str, binary_path: Path) -> None:
    """Run Ghidra headless extraction, mirroring the Snakefile ghidra_extract rule."""
    bt = BUILD_DIR / target_name
    project_dir = bt / "ghidra_project"
    project_dir.mkdir(parents=True, exist_ok=True)

    out = {t: str((bt / f"{t}.jsonl").resolve()) for t in GHIDRA_TABLES}

    # Reuse cached results if all JSONL outputs exist and are non-empty
    if all(Path(p).exists() and Path(p).stat().st_size > 0 for p in out.values()):
        print(f"  Ghidra outputs cached. Delete build/{target_name}/ghidra_project/ to re-analyze.")
        return

    sp = SCRIPTS_DIR / "ghidra"
    cmd = (
        f"env -u VIRTUAL_ENV {GHIDRA_PYGHIDRA} -H {project_dir} {target_name} "
        f"-import {binary_path} -overwrite -scriptPath {sp} "
        f"-postScript create_vector_functions.py "
        f"-postScript export_functions.py {out['functions']} "
        f"-postScript export_calls.py {out['calls']} "
        f"-postScript export_basic_blocks.py {out['basic_blocks']} "
        f"-postScript export_xrefs.py {out['xrefs']} "
        f"-postScript export_strings.py {out['strings']} "
        f"-postScript export_pcode.py {out['pcode']}"
    )

    t0 = time.time()
    run(cmd)
    print(f"  Ghidra analysis completed in {time.time() - t0:.1f}s")

    for t in GHIDRA_TABLES:
        p = Path(out[t])
        if not p.exists() or p.stat().st_size == 0:
            die(f"Ghidra failed to produce {p}")


def _ingest(target_name: str, table: str, jsonl_stem: str) -> None:
    """Ingest one JSONL file to Parquet."""
    bt = BUILD_DIR / target_name
    jsonl = bt / f"{jsonl_stem}.jsonl"
    parquet = bt / "tables" / f"{table}.parquet"
    if parquet.exists() and jsonl.exists() and parquet.stat().st_mtime > jsonl.stat().st_mtime:
        print(f"  {table}: up-to-date, skipping")
        return
    if not jsonl.exists() or jsonl.stat().st_size == 0:
        print(f"  warning: {jsonl} missing or empty, skipping {table}")
        return
    run(f"{PYTHON} scripts/ingest/load_table.py --table {table} "
        f"--source {target_name} --output {parquet} {jsonl}")


def run_ingest(target_name: str) -> None:
    """Convert JSONL outputs to Parquet tables."""
    for table_name, jsonl_stem in INGEST_MAP.items():
        _ingest(target_name, table_name, jsonl_stem)


def run_recovery(target_name: str) -> None:
    """Run call recovery and ingest the result."""
    run(f"{PYTHON} scripts/recovery/recover_calls.py {target_name}")
    _ingest(target_name, "recovered_calls", "recovered_calls")


def run_peripheral_classification(target_name: str) -> None:
    """Run peripheral classification and ingest."""
    run(f"{PYTHON} scripts/peripheral/classify_peripherals.py {target_name}")
    _ingest(target_name, "peripheral_xrefs", "peripheral_xrefs")


def _query(sql: str) -> str | None:
    """Run a SQL query via scripts/query, return stdout or None on failure."""
    r = subprocess.run(
        f"{SCRIPTS_DIR / 'query'} \"{sql}\"",
        shell=True, cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def print_summary(target_name: str) -> None:
    """Print a warehouse summary for the target."""
    tables_dir = BUILD_DIR / target_name / "tables"
    if not tables_dir.exists():
        die(f"no warehouse tables found for '{target_name}' at {tables_dir}")

    parquets = sorted(tables_dir.glob("*.parquet"))
    if not parquets:
        die(f"no parquet files found in {tables_dir}")

    print(f"\n{'='*60}")
    print(f"  Analysis complete: {target_name}")
    print(f"{'='*60}\n")

    print(f"Warehouse: {tables_dir}")
    print(f"Tables:")
    for pq in parquets:
        print(f"  {pq.name:40s}  {pq.stat().st_size / 1024:6.1f} KB")

    td = tables_dir
    out = _query(
        f"SELECT "
        f"(SELECT COUNT(*) FROM read_parquet('{td}/functions.parquet')) AS functions, "
        f"(SELECT COUNT(*) FROM read_parquet('{td}/calls.parquet')) AS calls, "
        f"(SELECT COUNT(*) FROM read_parquet('{td}/basic_blocks.parquet')) AS basic_blocks, "
        f"(SELECT COUNT(*) FROM read_parquet('{td}/xrefs.parquet')) AS xrefs, "
        f"(SELECT COUNT(*) FROM read_parquet('{td}/strings.parquet')) AS strings"
    )
    if out:
        print(f"\nRow counts:\n{out}")

    periph = td / "peripheral_xrefs.parquet"
    if periph.exists():
        out = _query(
            f"SELECT peripheral, COUNT(*) AS accesses "
            f"FROM read_parquet('{periph}') "
            f"GROUP BY peripheral ORDER BY accesses DESC LIMIT 10"
        )
        if out:
            print(f"\nTop peripherals accessed:\n{out}")

    recovered = td / "recovered_calls.parquet"
    if recovered.exists():
        out = _query(
            f"SELECT mechanism, COUNT(*) AS edges, ROUND(AVG(confidence), 2) AS avg_conf "
            f"FROM read_parquet('{recovered}') "
            f"GROUP BY mechanism ORDER BY edges DESC"
        )
        if out:
            print(f"\nRecovered call edges:\n{out}")

    print(f"\nQuery the warehouse:")
    print(f"  scripts/query --repl")
    print(f"  scripts/query \"SELECT name, size FROM functions "
          f"WHERE source='{target_name}' ORDER BY size DESC LIMIT 20\"")


def main() -> None:
    args = parse_args()

    # --report mode: just print summary for an existing target
    if args.report:
        print_summary(args.report)
        return

    # Normal mode: need a binary
    if args.binary is None:
        die("provide a firmware binary path, or use --report TARGET for existing targets")

    binary = args.binary.resolve()
    if not binary.exists():
        die(f"file not found: {binary}")

    # Detect format
    elf = is_elf(binary)
    is_raw = not elf

    # Determine arch
    if elf:
        arch = elf_arch(binary)
        if arch == "unknown":
            print(f"  warning: could not detect ISA from ELF headers, using --arch={args.arch}")
            arch = args.arch
        else:
            print(f"  detected ELF, ISA: {arch}")
    else:
        arch = args.arch
        print(f"  raw binary detected, using arch: {arch}")

    # Base address for raw binaries
    base_addr = args.base_addr
    if is_raw and base_addr is None:
        detected = detect_base_addr(binary)
        if detected is not None:
            base_addr = detected
            print(f"  auto-detected base address: 0x{base_addr:08X}")
        else:
            base_addr = 0x08000000
            print(f"  using default base address: 0x{base_addr:08X}")

    # Target name
    target_name = args.name or sanitize_name(binary.name)
    print(f"  target name: {target_name}")

    # SVD
    svd = resolve_svd(args.chip)
    if svd:
        print(f"  SVD: {svd}")

    total_steps = 5

    # Step 1: Check prerequisites
    step(1, total_steps, "Checking prerequisites")
    check_ghidra()
    print("  Ghidra: OK")

    # Step 2: Set up target
    step(2, total_steps, "Setting up target")
    binary_dest = setup_target(binary, target_name)

    # Step 3: Run Ghidra extraction
    step(3, total_steps, "Running Ghidra analysis")
    run_ghidra(target_name, binary_dest)

    # Step 4: Ingest to Parquet
    step(4, total_steps, "Ingesting to warehouse")
    run_ingest(target_name)

    # Step 5: Derived stages (recovery + peripheral classification)
    step(5, total_steps, "Running derived analysis")
    run_recovery(target_name)
    run_peripheral_classification(target_name)

    # Summary
    print_summary(target_name)


if __name__ == "__main__":
    main()
