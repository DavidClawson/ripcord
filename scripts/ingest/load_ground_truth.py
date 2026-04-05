#!/usr/bin/env python3
"""Ground-truth function list extracted from an ELF symbol table.

Runs the arch-appropriate `nm` on the target ELF, filters to text-section
symbols (types T and t), parses each row, and writes a typed Parquet file
alongside the Ghidra-derived `functions` table. The `notes/queries/
coverage.sql` query joins the two tables to report extractor coverage.

This is the Phase 0.6 validation loop from PLAN.md, committed as a
first-class pipeline rule so every future snakemake run produces a
coverage signal automatically. The comparison is against addresses, not
names: Ghidra applies DWARF-derived names that may not exactly match
nm's symbol names, but the function entry point address is stable.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


# arch -> nm binary. Extend as new target architectures are added.
NM_BINARIES: dict[str, str] = {
    "arm": "arm-none-eabi-nm",
    "avr": "avr-nm",
    "riscv": "riscv64-elf-nm",
}


GROUND_TRUTH_FUNCTIONS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("addr", pa.int64()),
        ("size", pa.int64()),  # nullable — nm -S only prints size for some symbols
        ("name", pa.string()),
        ("bind", pa.string()),  # 'global' for T, 'local' for t
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path, help="path to target ELF")
    parser.add_argument(
        "--arch",
        required=True,
        choices=sorted(NM_BINARIES.keys()),
        help="target architecture (selects the nm binary)",
    )
    parser.add_argument(
        "--source",
        required=True,
        help="target name, stamped into every row",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="path to output .parquet",
    )
    return parser.parse_args()


def run_nm(nm_binary: str, elf_path: Path) -> str:
    """Run `nm -S` and return stdout. -S emits sizes when available."""
    try:
        result = subprocess.run(
            [nm_binary, "-S", str(elf_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(
            f"error: {nm_binary} not found on $PATH — install the target "
            f"toolchain or fix the arch mapping in load_ground_truth.py",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(
            f"error: {nm_binary} exited {exc.returncode} on {elf_path}:\n{exc.stderr}",
            file=sys.stderr,
        )
        sys.exit(1)
    return result.stdout


def parse_nm_text_symbols(
    nm_output: str, source: str, extracted_at: datetime
) -> list[dict]:
    """Extract (addr, size, type, name) rows for text-section symbols.

    `nm -S` prints either 3 fields `addr type name` or 4 fields
    `addr size type name`, depending on whether the symbol has a size.
    Text symbols have type 'T' (global) or 't' (local).
    """
    rows: list[dict] = []
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) == 4:
            addr_hex, size_hex, sym_type, name = parts
            size: int | None = int(size_hex, 16)
        elif len(parts) == 3:
            addr_hex, sym_type, name = parts
            size = None
        else:
            # Lines without an address (e.g. 'U undefined_symbol' with
            # only 2 fields, or blank lines) are not text symbols.
            continue

        if sym_type not in ("T", "t"):
            continue

        rows.append(
            {
                "source": source,
                "addr": int(addr_hex, 16),
                "size": size,
                "name": name,
                "bind": "global" if sym_type == "T" else "local",
                "extracted_at": extracted_at,
            }
        )
    return rows


def main() -> int:
    args = parse_args()

    if not args.elf.exists():
        print(f"error: {args.elf} does not exist", file=sys.stderr)
        return 1

    nm_binary = NM_BINARIES[args.arch]
    nm_output = run_nm(nm_binary, args.elf)

    extracted_at = datetime.now(timezone.utc)
    rows = parse_nm_text_symbols(nm_output, args.source, extracted_at)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=GROUND_TRUTH_FUNCTIONS_SCHEMA)
    pq.write_table(table, args.output, compression="zstd")

    print(
        f"wrote {len(rows)} ground-truth text symbols from {args.elf} "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
