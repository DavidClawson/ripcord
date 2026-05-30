#!/usr/bin/env -S uv run --with capstone python
"""Disassemble a region of a warehouse target's binary (Cortex-M Thumb).

Resolves the binary path, load base, and ISA from config.yaml, maps virtual
addresses to file offsets (raw-binary base or ELF LOAD segments), and prints a
capstone disassembly. Replaces the ad-hoc `uv run --with capstone` one-liners
used during firmware bring-up.

Usage:
    # by address range
    scripts/analysis/disasm.py --target stock_v120 --start 0x0802A774 --end 0x0802ACB8
    # by instruction count
    scripts/analysis/disasm.py --target stock_v120 --start 0x0802A774 --count 40
    # by warehouse function name (resolves addr+size)
    scripts/analysis/disasm.py --target stock_v120 --function FUN_08027a50

    # filtered views (the bring-up "skeleton" and call-graph views)
    scripts/analysis/disasm.py --target stock_v120 --function FUN_08027a50 --filter skeleton
    scripts/analysis/disasm.py --target stock_v120 --function FUN_08027a50 --filter calls
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Target resolution (config.yaml + warehouse)
# ---------------------------------------------------------------------------

def _coerce_int(v) -> int:
    if isinstance(v, int):
        return v
    return int(str(v), 0)


def load_target(name: str):
    """Return (binary_path, base_addr, arch, is_raw) for a config target."""
    import yaml

    cfg = yaml.safe_load((REPO / "config.yaml").read_text())
    try:
        t = cfg["targets"][name]
    except KeyError:
        sys.exit(f"error: target '{name}' not in config.yaml")
    binary = REPO / t["elf"]
    base = _coerce_int(t.get("base_addr", 0))
    arch = t.get("arch", "arm")
    is_raw = bool(t.get("raw_binary", False)) or not _looks_like_elf(binary)
    return binary, base, arch, is_raw


def _looks_like_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def resolve_function(target: str, name_or_addr: str):
    """Return (addr, size) for a function name or address via the warehouse."""
    import duckdb

    table = REPO / "build" / target / "tables" / "functions.parquet"
    if not table.exists():
        sys.exit(f"error: {table} not found (run the pipeline first)")
    con = duckdb.connect()
    rel = f"read_parquet('{table}')"
    try:  # allow an address as well as a name
        addr = int(name_or_addr, 0)
        row = con.execute(
            f"SELECT addr, size FROM {rel} WHERE addr = ? LIMIT 1", [addr]
        ).fetchone()
    except ValueError:
        row = con.execute(
            f"SELECT addr, size FROM {rel} WHERE name = ? LIMIT 1", [name_or_addr]
        ).fetchone()
    if not row:
        sys.exit(f"error: function '{name_or_addr}' not found in {target}")
    return int(row[0]), int(row[1])


# ---------------------------------------------------------------------------
# vaddr -> file offset
# ---------------------------------------------------------------------------

def vaddr_to_offset(vaddr: int, base: int, is_raw: bool, data: bytes) -> int:
    if is_raw:
        return vaddr - base
    # ELF32 LE: walk PT_LOAD program headers.
    if data[:4] != b"\x7fELF" or data[4] != 1:
        sys.exit("error: not an ELF32 image; pass --base for a raw mapping")
    e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    e_phnum = struct.unpack_from("<H", data, 0x2C)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIIII", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:  # PT_LOAD
            return p_offset + (vaddr - p_vaddr)
    sys.exit(f"error: vaddr 0x{vaddr:08X} not in any ELF LOAD segment")


# ---------------------------------------------------------------------------
# disassembly
# ---------------------------------------------------------------------------

def make_md(arch: str):
    from capstone import (
        CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB,
        CS_MODE_LITTLE_ENDIAN, Cs,
    )
    if arch in ("arm", "thumb", "cortex-m"):
        return Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    if arch in ("arm-a32",):
        return Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    if arch in ("aarch64", "arm64"):
        return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    sys.exit(f"error: unsupported arch '{arch}'")


SKELETON_PREFIXES = ("mov", "str", "ldr", "bl", "blx")
BRANCH_PREFIXES = ("b", "bl", "blx", "bx", "cbz", "cbnz")


def keep(ins, mode: str) -> bool:
    if mode == "all":
        return True
    if mode == "skeleton":
        return ins.mnemonic.startswith(SKELETON_PREFIXES)
    if mode == "calls":
        return ins.mnemonic in ("bl", "blx", "blx.w", "bl.w")
    if mode == "branches":
        return ins.mnemonic.split(".")[0] in BRANCH_PREFIXES
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="config.yaml target name")
    ap.add_argument("--start", help="start virtual address (0x...)")
    ap.add_argument("--end", help="end virtual address (exclusive)")
    ap.add_argument("--count", type=int, help="number of instructions (alt. to --end)")
    ap.add_argument("--function", help="warehouse function name or address to disassemble")
    ap.add_argument("--filter", default="all",
                    choices=["all", "skeleton", "calls", "branches"],
                    help="which instructions to print (default: all)")
    ap.add_argument("--base", help="override load base (hex), forces raw mapping")
    args = ap.parse_args()

    binary, base, arch, is_raw = load_target(args.target)
    if args.base is not None:
        base, is_raw = int(args.base, 0), True
    data = binary.read_bytes()

    if args.function:
        start, size = resolve_function(args.target, args.function)
        end = start + size
    elif args.start:
        start = int(args.start, 0)
        end = int(args.end, 0) if args.end else None
    else:
        sys.exit("error: pass --function or --start")

    off = vaddr_to_offset(start, base, is_raw, data)
    if end is not None:
        nbytes = end - start
    elif args.count:
        nbytes = args.count * 4 + 4  # upper bound; trimmed by --count below
    else:
        nbytes = 256
    chunk = data[off:off + nbytes]

    md = make_md(arch)
    print(f"# {args.target}: 0x{start:08X}"
          + (f"-0x{end:08X}" if end else f" (+{args.count} insns)")
          + f"  [base=0x{base:08X} {'raw' if is_raw else 'elf'} {arch}]")
    n = 0
    for ins in md.disasm(chunk, start):
        if args.count and n >= args.count:
            break
        if keep(ins, args.filter):
            print(f"0x{ins.address:08X}:  {ins.mnemonic:<9} {ins.op_str}")
        n += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
