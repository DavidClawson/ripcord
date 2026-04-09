#!/usr/bin/env -S uv run python
"""Parse the ARM Cortex-M vector table from a raw binary or ELF file.

Maps vector table entries to standard exception names (0-15) and
chip-specific IRQ names (16+). Cross-references against the warehouse
functions table to identify which Ghidra-discovered functions are ISR
handlers.

Standalone script + importable module.

Usage:
    scripts/analysis/vector_table.py \
        --binary targets/stock_v120/stock_v120.bin \
        --target stock_v120 \
        --build-dir build \
        --base-addr 0x08004000 \
        --chip at32f403a

    # ELF input (base address extracted from LOAD segment):
    scripts/analysis/vector_table.py \
        --binary targets/at32_hal_blinky/at32_hal_blinky.elf \
        --target at32_hal_blinky
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"

# ---------------------------------------------------------------------------
# Standard Cortex-M exception names (vector indices 0-15)
# ---------------------------------------------------------------------------

CORTEX_M_EXCEPTIONS = {
    0: "initial_sp",
    1: "Reset_Handler",
    2: "NMI_Handler",
    3: "HardFault_Handler",
    4: "MemManage_Handler",
    5: "BusFault_Handler",
    6: "UsageFault_Handler",
    # 7-10: Reserved
    11: "SVC_Handler",
    12: "DebugMon_Handler",
    # 13: Reserved
    14: "PendSV_Handler",
    15: "SysTick_Handler",
}

# ---------------------------------------------------------------------------
# Chip-specific IRQ name tables (entries 16+)
# ---------------------------------------------------------------------------

AT32F403A_IRQS = {
    16: "WWDT_IRQHandler",
    17: "PVM_IRQHandler",
    18: "TAMPER_IRQHandler",
    19: "ERTC_IRQHandler",
    20: "FLASH_IRQHandler",
    21: "CRM_IRQHandler",
    22: "EXINT0_IRQHandler",
    23: "EXINT1_IRQHandler",
    24: "EXINT2_IRQHandler",
    25: "EXINT3_IRQHandler",
    26: "EXINT4_IRQHandler",
    27: "DMA1_Channel1_IRQHandler",
    28: "DMA1_Channel2_IRQHandler",
    29: "DMA1_Channel3_IRQHandler",
    30: "DMA1_Channel4_IRQHandler",
    31: "DMA1_Channel5_IRQHandler",
    32: "DMA1_Channel6_IRQHandler",
    33: "DMA1_Channel7_IRQHandler",
    34: "ADC1_2_IRQHandler",
    35: "USB_HP_CAN1_TX_IRQHandler",
    36: "USB_LP_CAN1_RX0_IRQHandler",
    37: "CAN1_RX1_IRQHandler",
    38: "CAN1_SE_IRQHandler",
    39: "EXINT9_5_IRQHandler",
    40: "TMR1_BRK_TMR9_IRQHandler",
    41: "TMR1_OV_TMR10_IRQHandler",
    42: "TMR1_TRG_HALL_TMR11_IRQHandler",
    43: "TMR1_CH_IRQHandler",
    44: "TMR2_GLOBAL_IRQHandler",
    45: "TMR3_GLOBAL_IRQHandler",
    46: "TMR4_GLOBAL_IRQHandler",
    47: "I2C1_EV_IRQHandler",
    48: "I2C1_ER_IRQHandler",
    49: "I2C2_EV_IRQHandler",
    50: "I2C2_ER_IRQHandler",
    51: "SPI1_IRQHandler",
    52: "SPI2_IRQHandler",
    53: "USART1_IRQHandler",
    54: "USART2_IRQHandler",
    55: "USART3_IRQHandler",
    56: "EXINT15_10_IRQHandler",
    57: "ERTCAlarm_IRQHandler",
    58: "USBWakeUp_IRQHandler",
    59: "TMR8_BRK_TMR12_IRQHandler",
    60: "TMR8_OV_TMR13_IRQHandler",
    61: "TMR8_TRG_HALL_TMR14_IRQHandler",
    62: "TMR8_CH_IRQHandler",
    # 63: Reserved
    64: "SDIO1_IRQHandler",
    65: "TMR5_GLOBAL_IRQHandler",
    66: "SPI3_IRQHandler",
    67: "USART4_IRQHandler",
    68: "USART5_IRQHandler",
    69: "TMR6_GLOBAL_IRQHandler",
    70: "TMR7_GLOBAL_IRQHandler",
    71: "DMA2_Channel1_IRQHandler",
    72: "DMA2_Channel2_IRQHandler",
    73: "DMA2_Channel3_IRQHandler",
    74: "DMA2_Channel4_5_IRQHandler",
}

# Map from chip name to IRQ table
_CHIP_IRQS = {
    "at32f403a": AT32F403A_IRQS,
}

# ---------------------------------------------------------------------------
# Parquet schema
# ---------------------------------------------------------------------------

VECTOR_TABLE_SCHEMA = pa.schema([
    ("source", pa.string()),
    ("index", pa.int32()),
    ("addr", pa.int64()),
    ("handler_name", pa.string()),
    ("is_standard", pa.bool_()),
    ("matched_function", pa.bool_()),
    ("current_name", pa.string()),
])


# ---------------------------------------------------------------------------
# Core: parse vector table from raw binary bytes
# ---------------------------------------------------------------------------

def _is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def _load_binary(binary_path: str, base_addr: int | None) -> tuple[bytes, int]:
    """Load binary content and determine base address.

    For ELF files: extracts the first PT_LOAD segment and uses its
    virtual address as base_addr (ignoring any --base-addr override).
    For raw binaries: uses base_addr directly; the file IS the flash
    content starting at base_addr.

    Returns (flash_bytes, base_addr).
    """
    data = Path(binary_path).read_bytes()

    if _is_elf(data):
        if len(data) < 52:
            raise ValueError("ELF too short")
        ei_class = data[4]
        if ei_class != 1:
            raise ValueError("Only 32-bit ELF supported")
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_phentsize = struct.unpack_from("<H", data, 42)[0]
        e_phnum = struct.unpack_from("<H", data, 44)[0]

        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            p_type = struct.unpack_from("<I", data, ph)[0]
            if p_type == 1:  # PT_LOAD
                p_offset = struct.unpack_from("<I", data, ph + 4)[0]
                p_vaddr = struct.unpack_from("<I", data, ph + 8)[0]
                p_filesz = struct.unpack_from("<I", data, ph + 16)[0]
                return data[p_offset : p_offset + p_filesz], p_vaddr

        raise ValueError("No PT_LOAD segment in ELF")

    # Raw binary
    if base_addr is None:
        raise ValueError("--base-addr required for raw binary files")
    return data, base_addr


def parse_vector_table(
    binary_path: str,
    base_addr: int = 0x08000000,
    chip: str = "at32f403a",
    max_entries: int = 80,
) -> list[dict]:
    """Parse the vector table from a binary file.

    Returns list of dicts with keys:
        index, addr, name, is_standard, is_valid

    An entry is valid if:
    - The address is within flash range (base_addr .. base_addr + binary_size)
    - The address has the Thumb bit (bit 0) set — actual addr = value & ~1
    - The raw value is not 0x00000000 (unused / reserved)
    - Entry 0 (initial SP) is reported but flagged as not valid (not a handler)
    """
    flash, actual_base = _load_binary(binary_path, base_addr)
    flash_end = actual_base + len(flash)

    chip_irqs = _CHIP_IRQS.get(chip, {})
    entries: list[dict] = []

    n = min(max_entries, len(flash) // 4)
    for i in range(n):
        raw = struct.unpack_from("<I", flash, i * 4)[0]

        # Entry 0: initial stack pointer
        if i == 0:
            entries.append({
                "index": 0,
                "raw_value": raw,
                "addr": raw,
                "name": "initial_sp",
                "is_standard": True,
                "is_valid": False,  # not a handler
            })
            continue

        # Determine name
        if i in CORTEX_M_EXCEPTIONS:
            name = CORTEX_M_EXCEPTIONS[i]
            is_std = True
        elif i in chip_irqs:
            name = chip_irqs[i]
            is_std = False
        elif 7 <= i <= 10 or i == 13:
            name = f"Reserved_{i}"
            is_std = True
        elif i >= 16:
            name = f"IRQ{i - 16}"
            is_std = False
        else:
            name = f"Exception_{i}"
            is_std = True

        # Validity checks
        if raw == 0x00000000 or raw == 0xFFFFFFFF:
            entries.append({
                "index": i,
                "raw_value": raw,
                "addr": 0,
                "name": name,
                "is_standard": is_std,
                "is_valid": False,
            })
            continue

        thumb_set = bool(raw & 1)
        func_addr = raw & ~1

        in_flash = actual_base <= func_addr < flash_end
        valid = thumb_set and in_flash

        entries.append({
            "index": i,
            "raw_value": raw,
            "addr": func_addr,
            "name": name,
            "is_standard": is_std,
            "is_valid": valid,
        })

    return entries


# ---------------------------------------------------------------------------
# Cross-reference against warehouse functions table
# ---------------------------------------------------------------------------

def match_against_functions(
    vector_entries: list[dict],
    conn_duckdb,
    target: str,
) -> list[dict]:
    """Cross-reference vector table entries against the functions table.

    For each valid vector entry, check if the address matches a function
    in the warehouse. Returns entries enriched with 'matched_function'
    (bool) and 'current_name' (str or None) fields.
    """
    # Build addr->name map from warehouse
    try:
        rows = conn_duckdb.execute(
            "SELECT addr, name FROM functions WHERE source = ?",
            [target],
        ).fetchall()
        func_map = {int(r[0]): r[1] for r in rows}
    except Exception:
        func_map = {}

    enriched = []
    for e in vector_entries:
        entry = dict(e)
        if entry["is_valid"] and entry["addr"] in func_map:
            entry["matched_function"] = True
            entry["current_name"] = func_map[entry["addr"]]
        else:
            entry["matched_function"] = False
            entry["current_name"] = None
        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Default handler detection
# ---------------------------------------------------------------------------

def detect_default_handler(entries: list[dict]) -> int | None:
    """Find the most common handler address (the default/weak handler).

    Many IRQ entries point to a shared default handler that just loops.
    Returns the address if 3+ entries share it, else None.
    """
    from collections import Counter

    valid_addrs = [e["addr"] for e in entries if e["is_valid"] and e["index"] >= 1]
    if not valid_addrs:
        return None
    addr, count = Counter(valid_addrs).most_common(1)[0]
    return addr if count >= 3 else None


# ---------------------------------------------------------------------------
# Parquet output
# ---------------------------------------------------------------------------

def write_parquet(
    entries: list[dict],
    target: str,
    build_dir: str,
) -> Path:
    """Write vector table entries as vector_table.parquet.

    Only writes valid handler entries (skips initial_sp and invalid).
    Returns path to the written file.
    """
    rows = []
    for e in entries:
        if not e["is_valid"]:
            continue
        rows.append({
            "source": target,
            "index": e["index"],
            "addr": e["addr"],
            "handler_name": e["name"],
            "is_standard": e["is_standard"],
            "matched_function": e.get("matched_function", False),
            "current_name": e.get("current_name"),
        })

    table = pa.Table.from_pylist(rows, schema=VECTOR_TABLE_SCHEMA)
    out_dir = Path(build_dir) / target / "tables"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "vector_table.parquet"
    pq.write_table(table, out_path)
    return out_path


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def print_report(entries: list[dict], default_handler: int | None) -> None:
    """Print a formatted table of vector table entries."""
    print(f"\n{'Idx':>4}  {'Address':>10}  {'Handler Name':<40}  {'Match':>5}  {'Current Name'}")
    print("-" * 100)

    for e in entries:
        if e["index"] == 0:
            print(f"{0:>4}  0x{e['addr']:08X}  {'(initial stack pointer)':<40}  {'':>5}  —")
            continue

        if not e["is_valid"]:
            if e["raw_value"] == 0:
                label = "(unused)"
            elif e["raw_value"] == 0xFFFFFFFF:
                label = "(0xFFFFFFFF)"
            else:
                label = f"(invalid: 0x{e['raw_value']:08X})"
            print(f"{e['index']:>4}  {'—':>10}  {e['name']:<40}  {'':>5}  {label}")
            continue

        is_default = default_handler is not None and e["addr"] == default_handler
        matched = e.get("matched_function", False)
        current = e.get("current_name") or "—"

        addr_str = f"0x{e['addr']:08X}"
        match_str = "yes" if matched else "no"
        name_display = e["name"]
        if is_default:
            name_display += "  [DEFAULT]"

        print(f"{e['index']:>4}  {addr_str:>10}  {name_display:<40}  {match_str:>5}  {current}")

    # Summary
    valid = [e for e in entries if e["is_valid"]]
    matched = [e for e in entries if e.get("matched_function")]
    n_default = sum(1 for e in valid if default_handler and e["addr"] == default_handler)

    print()
    print(f"Valid handlers:   {len(valid)}")
    print(f"Matched to fn:    {len(matched)}")
    if default_handler:
        print(f"Default handler:  0x{default_handler:08X}  ({n_default} entries point here)")
    unique = len({e["addr"] for e in valid})
    print(f"Unique addresses: {unique}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse ARM Cortex-M vector table and cross-reference with warehouse"
    )
    parser.add_argument("--binary", required=True, help="Path to raw .bin or .elf file")
    parser.add_argument("--target", required=True, help="Target name in warehouse")
    parser.add_argument("--build-dir", default=str(BUILD_DIR), help="Build directory")
    parser.add_argument(
        "--base-addr",
        type=lambda x: int(x, 0),
        default=None,
        help="Base address for raw binaries (e.g. 0x08000000). Ignored for ELF.",
    )
    parser.add_argument("--chip", default="at32f403a", help="Chip for IRQ names")
    parser.add_argument("--max-entries", type=int, default=80, help="Max vector table entries")
    parser.add_argument("--no-parquet", action="store_true", help="Skip Parquet output")
    args = parser.parse_args()

    # Parse the vector table
    entries = parse_vector_table(
        binary_path=args.binary,
        base_addr=args.base_addr,
        chip=args.chip,
        max_entries=args.max_entries,
    )

    # Cross-reference with warehouse
    try:
        import duckdb

        sys.path.insert(
            0, str(Path(__file__).resolve().parent.parent / "agents")
        )
        from context import register_warehouse

        conn = duckdb.connect()
        register_warehouse(conn, args.build_dir)
        entries = match_against_functions(entries, conn, args.target)
    except Exception as exc:
        print(f"[warn] Could not cross-reference with warehouse: {exc}", file=sys.stderr)

    # Detect default handler pattern
    default_handler = detect_default_handler(entries)

    # Console report
    print_report(entries, default_handler)

    # Parquet output
    if not args.no_parquet:
        out = write_parquet(entries, args.target, args.build_dir)
        print(f"\nParquet written: {out}")


if __name__ == "__main__":
    main()
