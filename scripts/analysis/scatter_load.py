#!/usr/bin/env python3
"""Parse the Keil ARM scatter-load table from a raw firmware binary.

Keil ARM Compiler (AC5/AC6) embeds a scatter-load table used by the C
runtime startup (__scatterload) to initialize .data and .bss sections.
This script finds and parses that table to determine which flash regions
contain code vs. initialized data vs. padding.

The scatter-load table is an array of 16-byte entries:
    Word 0: source address in flash (where init data lives)
    Word 1: destination address in RAM
    Word 2: size in bytes (destination region size)
    Word 3: handler function address (copy, decompress, or zeroinit)

The table is referenced by the __scatterload routine, which Keil places
immediately after the vector table. The routine loads a descriptor
containing offsets to the table start and end.

Standalone script + importable module.

Usage:
    python scripts/analysis/scatter_load.py \\
        --binary targets/stock_v120/stock_v120.bin \\
        --base-addr 0x08004000

    python scripts/analysis/scatter_load.py \\
        --binary targets/stock_v103/stock_v103.bin \\
        --base-addr 0x08004000
"""

from __future__ import annotations

import argparse
import struct
import sys


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ARM Cortex-M flash and RAM address ranges (broad, covers most STM32/AT32)
FLASH_LO = 0x08000000
FLASH_HI = 0x08200000  # 2 MB max
RAM_LO = 0x20000000
RAM_HI = 0x20100000    # 1 MB max

# Maximum scatter-load entries we expect (usually 2-4)
MAX_ENTRIES = 16

# Maximum offset from binary start to search for __scatterload code.
# The code is placed right after the vector table, typically within the
# first 1 KB. We search up to 2 KB to be safe.
MAX_SCATTERLOAD_SEARCH = 0x800

# Keil __scatterload instruction signature (Thumb-2):
#   BL +4            ; call self+4 (falls through to __scatterload body)
#   BL __rt_entry    ; return address for after scatter-load completes
#   ADR R0, desc     ; load address of region table descriptor
#   LDMIA R0, {R10, R11}  ; load table start/end offsets
#
# The BL +4 encodes as F000 F802 in all observed Keil builds.
# The ADR and LDMIA follow with varying immediates.
SCATTERLOAD_BL_SELF = bytes([0x00, 0xF0, 0x02, 0xF8])

# Alternative: search for the LDMIA.W R10!, {R0-R3} pattern in the loop body
# Encoding: E8BA 000F
LDMIA_R10_R0R3 = bytes([0xBA, 0xE8, 0x0F, 0x00])


# ---------------------------------------------------------------------------
# Core: find and parse the scatter-load table
# ---------------------------------------------------------------------------

def _find_scatterload_code(binary: bytes) -> int | None:
    """Find the __scatterload entry point in the binary.

    Searches for the characteristic BL +4 instruction that marks
    the start of the Keil __scatterload routine, placed right after
    the vector table.

    Returns the binary offset of the __scatterload entry, or None.
    """
    limit = min(len(binary), MAX_SCATTERLOAD_SEARCH)

    # Strategy 1: search for the BL +4 (F000 F802) pattern
    # This is the two-instruction prologue: BL __scatterload; BL __rt_entry
    for off in range(0, limit - 4, 2):
        if binary[off : off + 4] == SCATTERLOAD_BL_SELF:
            # Verify: the next 4 bytes should also be a BL (F0xx Fxxx or F0xx Dxxx)
            if off + 8 <= len(binary):
                hw = struct.unpack_from("<H", binary, off + 4)[0]
                if (hw & 0xF800) == 0xF000:
                    return off

    # Strategy 2: search for the LDMIA.W R10!, {R0-R3} instruction
    # that appears in the scatter-load loop body
    for off in range(0, limit - 4, 2):
        if binary[off : off + 4] == LDMIA_R10_R0R3:
            # Walk backwards to find the function entry
            # The entry is: BL+4, BL, ADR, LDMIA R0 {R10,R11}, ...
            # Typically 0x22 bytes before the LDMIA R10 instruction
            for back in range(0x10, 0x40, 2):
                candidate = off - back
                if candidate >= 0 and binary[candidate : candidate + 4] == SCATTERLOAD_BL_SELF:
                    return candidate
            # Even without finding BL+4, we can work from the LDMIA
            # by finding the ADR before it
            break

    return None


def _decode_adr_offset(binary: bytes, off: int) -> int | None:
    """Decode a Thumb ADR Rd, <label> instruction at the given offset.

    Returns the offset from the ADR instruction's aligned PC to the label,
    or None if the instruction at off is not ADR.
    """
    if off + 2 > len(binary):
        return None

    hw = struct.unpack_from("<H", binary, off)[0]

    # T1 encoding: 1010 0 Rd(3) imm8 -> offset = imm8 * 4
    if (hw & 0xF800) == 0xA000:
        imm8 = hw & 0xFF
        return imm8 * 4

    # T2 (Thumb-2) ADR.W: F2AF 0xxx or F20F 0xxx
    if off + 4 > len(binary):
        return None
    hw2 = struct.unpack_from("<H", binary, off + 2)[0]
    if (hw & 0xFBFF) == 0xF20F and (hw2 & 0x8000) == 0:
        # ADDW encoding
        i = (hw >> 10) & 1
        imm3 = (hw2 >> 12) & 7
        imm8 = hw2 & 0xFF
        return (i << 11) | (imm3 << 8) | imm8

    return None


def _parse_table_descriptor(
    binary: bytes, scatterload_off: int, base_addr: int
) -> tuple[int, int] | None:
    """Parse the region table descriptor referenced by __scatterload.

    The __scatterload code at scatterload_off has the structure:
        BL +4                 ; +0
        BL __rt_entry         ; +4
        ADR R0, descriptor    ; +8 (the __scatterload body)
        LDMIA R0, {R10,R11}  ; +10 or +12
        ADD R10, R0           ; table_start = descriptor_addr + offset0
        ADD R11, R0           ; table_end = descriptor_addr + offset1

    The descriptor is two 32-bit words: offset to table start and table end,
    both relative to the descriptor's own address.

    Returns (table_start_binary_offset, table_end_binary_offset) or None.
    """
    # The ADR instruction is at scatterload_off + 8
    adr_off = scatterload_off + 8
    adr_imm = _decode_adr_offset(binary, adr_off)
    if adr_imm is None:
        return None

    # ADR loads: R0 = (align(PC, 4)) + imm
    # PC = base_addr + adr_off + 4 (Thumb pipeline)
    pc = base_addr + adr_off + 4
    descriptor_addr = (pc & ~3) + adr_imm
    descriptor_off = descriptor_addr - base_addr

    if descriptor_off < 0 or descriptor_off + 8 > len(binary):
        return None

    # Read the two offsets
    off_to_start = struct.unpack_from("<I", binary, descriptor_off)[0]
    off_to_end = struct.unpack_from("<I", binary, descriptor_off + 4)[0]

    table_start = descriptor_off + off_to_start
    table_end = descriptor_off + off_to_end

    if table_start >= table_end:
        return None
    if table_end > len(binary):
        return None
    if (table_end - table_start) % 16 != 0:
        return None
    if (table_end - table_start) // 16 > MAX_ENTRIES:
        return None

    return table_start, table_end


def _classify_entry_type(
    entries: list[dict], initial_sp: int | None
) -> None:
    """Infer whether each entry is 'copy' (data init) or 'zeroinit' (bss).

    Heuristics:
    1. If dest + size equals the initial SP, it is bss (zeroinit fills
       all remaining RAM up to the stack).
    2. If two entries have different handlers and one is identified as
       bss, the other is copy.
    3. If the entry has a very large size relative to the data init
       region, it is more likely bss.
    4. The first entry is usually .data (copy), subsequent are .bss.
    """
    if not entries:
        return

    # Collect unique handler addresses
    handlers = {e["handler"] for e in entries}

    # Check which entries' dest+size equals SP
    for entry in entries:
        end = entry["dest"] + entry["size"]
        if initial_sp is not None and end == initial_sp:
            entry["type"] = "zeroinit"
        elif entry["size"] > 0x10000:
            # Very large region is likely bss
            entry["type"] = "zeroinit"

    # If we identified at least one zeroinit and there are exactly 2
    # distinct handlers, the other handler's entries are copy.
    zeroinit_handlers = {e["handler"] for e in entries if e.get("type") == "zeroinit"}
    copy_handlers = handlers - zeroinit_handlers

    for entry in entries:
        if "type" not in entry:
            if entry["handler"] in copy_handlers and len(handlers) > 1:
                entry["type"] = "copy"
            elif entry["handler"] in zeroinit_handlers:
                entry["type"] = "zeroinit"

    # Fallback: first entry without a type is copy, rest are zeroinit
    for i, entry in enumerate(entries):
        if "type" not in entry:
            entry["type"] = "copy" if i == 0 else "zeroinit"


def find_scatter_load_table(
    binary: bytes,
    base_addr: int = 0x08000000,
) -> list[dict] | None:
    """Find and parse the Keil scatter-load table in a raw binary.

    Returns list of entries:
        [
            {
                "source": 0x0804XXXX,      # flash source address
                "dest": 0x2000XXXX,        # RAM destination
                "size": 1234,              # bytes (destination region size)
                "handler": 0x0800XXXX,     # copy or zeroinit function addr
                "type": "copy" | "zeroinit",
            },
            ...
        ]

    Returns None if no scatter-load table found with high confidence.
    """
    if len(binary) < 0x200:
        return None

    # Find __scatterload code
    sl_off = _find_scatterload_code(binary)
    if sl_off is None:
        return None

    # Parse the table descriptor
    result = _parse_table_descriptor(binary, sl_off, base_addr)
    if result is None:
        return None

    table_start, table_end = result
    n_entries = (table_end - table_start) // 16

    if n_entries == 0:
        return None

    # Read the initial SP from vector table entry 0 (for bss detection)
    initial_sp = struct.unpack_from("<I", binary, 0)[0] if len(binary) >= 4 else None

    # Read entries
    entries: list[dict] = []
    for i in range(n_entries):
        eoff = table_start + i * 16
        src, dest, size, handler = struct.unpack_from("<IIII", binary, eoff)

        # Validate: dest should be in RAM range
        if not (RAM_LO <= dest < RAM_HI):
            return None  # table is not valid scatter-load

        # Validate: source should be in flash range (may be past binary end)
        if not (FLASH_LO <= src < FLASH_HI):
            return None

        # Validate: handler should be in flash range
        if not (FLASH_LO <= handler < FLASH_HI):
            return None

        # Validate: size should be reasonable
        if size == 0 or size > 0x100000:
            return None

        entries.append({
            "source": src,
            "dest": dest,
            "size": size,
            "handler": handler,
        })

    # Validate: dest regions should be non-overlapping and ordered
    for i in range(1, len(entries)):
        prev_end = entries[i - 1]["dest"] + entries[i - 1]["size"]
        if entries[i]["dest"] < prev_end:
            return None  # overlapping regions

    # Classify entry types
    _classify_entry_type(entries, initial_sp)

    # Attach metadata
    for entry in entries:
        entry["table_addr"] = base_addr + table_start
        entry["scatterload_addr"] = base_addr + sl_off

    return entries


def get_data_regions(entries: list[dict]) -> dict:
    """Extract data region boundaries from scatter-load entries.

    Returns:
        {
            "data_init": [{"flash_src": ..., "ram_dest": ..., "size": ...}],
            "bss": [{"ram_start": ..., "size": ...}],
            "code_end": int,  # flash address where code ends (scatter table start)
        }
    """
    data_init = []
    bss = []

    for entry in entries:
        if entry["type"] == "copy":
            data_init.append({
                "flash_src": entry["source"],
                "ram_dest": entry["dest"],
                "size": entry["size"],
            })
        elif entry["type"] == "zeroinit":
            bss.append({
                "ram_start": entry["dest"],
                "size": entry["size"],
            })

    # Code ends where the scatter-load table starts
    code_end = entries[0]["table_addr"] if entries else 0

    return {
        "data_init": data_init,
        "bss": bss,
        "code_end": code_end,
    }


def classify_flash_regions(
    entries: list[dict],
    binary_size: int,
    base_addr: int = 0x08000000,
) -> list[dict]:
    """Classify flash address ranges as code vs data.

    Returns list of regions:
        [
            {"start": addr, "end": addr, "type": "code"},
            {"start": addr, "end": addr, "type": "scatter_table"},
            {"start": addr, "end": addr, "type": "data_init"},
            {"start": addr, "end": addr, "type": "padding"},
        ]

    Regions are sorted by start address and cover the full binary.
    """
    if not entries:
        return [{"start": base_addr, "end": base_addr + binary_size, "type": "unknown"}]

    regions: list[dict] = []
    table_addr = entries[0]["table_addr"]
    binary_end = base_addr + binary_size

    # Code region: from base to scatter table
    if table_addr > base_addr:
        regions.append({
            "start": base_addr,
            "end": table_addr,
            "type": "code",
        })

    # Scatter-load table itself (2 entries = 32 bytes, etc.)
    table_size = len(entries) * 16
    table_end = table_addr + table_size
    regions.append({
        "start": table_addr,
        "end": table_end,
        "type": "scatter_table",
    })

    # After the table: check if any data_init sources are within the binary
    copy_entries = [e for e in entries if e["type"] == "copy"]
    if copy_entries:
        first_data = min(e["source"] for e in copy_entries)
        if base_addr <= first_data < binary_end:
            # Padding between table end and data init
            if first_data > table_end:
                regions.append({
                    "start": table_end,
                    "end": first_data,
                    "type": "padding",
                })
            # Data init region(s) within the binary
            for entry in sorted(copy_entries, key=lambda e: e["source"]):
                src = entry["source"]
                # Source size in flash may differ from dest size (compression)
                # We don't know the compressed size, so just mark from src
                # to the next region or binary end
                if src < binary_end:
                    src_end = min(binary_end, src + entry["size"])
                    regions.append({
                        "start": src,
                        "end": src_end,
                        "type": "data_init",
                    })
        else:
            # Data init is past binary end (binary truncated before .data)
            if table_end < binary_end:
                regions.append({
                    "start": table_end,
                    "end": binary_end,
                    "type": "padding",
                })
    elif table_end < binary_end:
        regions.append({
            "start": table_end,
            "end": binary_end,
            "type": "padding",
        })

    # Sort and fill any gaps
    regions.sort(key=lambda r: r["start"])
    return regions


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def print_report(
    entries: list[dict],
    binary_size: int,
    base_addr: int,
) -> None:
    """Print a formatted report of the scatter-load analysis."""
    binary_end = base_addr + binary_size

    print(f"\nBinary: 0x{base_addr:08X} - 0x{binary_end:08X} ({binary_size:,} bytes)")
    print(f"__scatterload at: 0x{entries[0]['scatterload_addr']:08X}")
    print(f"Scatter table at: 0x{entries[0]['table_addr']:08X}")

    # Initial SP
    print()
    print("Scatter-load entries:")
    print(f"{'#':>3}  {'Type':<9}  {'Source':>10}  {'Dest':>10}  "
          f"{'Size':>10}  {'End':>10}  {'Handler':>10}")
    print("-" * 80)

    for i, entry in enumerate(entries):
        end = entry["dest"] + entry["size"]
        in_bin = "yes" if base_addr <= entry["source"] < binary_end else "NO"
        print(
            f"{i:>3}  {entry['type']:<9}  0x{entry['source']:08X}  "
            f"0x{entry['dest']:08X}  {entry['size']:>10,}  "
            f"0x{end:08X}  0x{entry['handler']:08X}"
        )

    # Data regions
    data_regions = get_data_regions(entries)
    print(f"\nCode region ends at: 0x{data_regions['code_end']:08X}")

    if data_regions["data_init"]:
        print("\n.data initialization:")
        for d in data_regions["data_init"]:
            in_bin = "in binary" if base_addr <= d["flash_src"] < binary_end else "past binary end"
            print(f"  Flash 0x{d['flash_src']:08X} -> RAM 0x{d['ram_dest']:08X} "
                  f"({d['size']:,} bytes) [{in_bin}]")

    if data_regions["bss"]:
        print("\n.bss (zero-initialized):")
        for b in data_regions["bss"]:
            end = b["ram_start"] + b["size"]
            print(f"  RAM 0x{b['ram_start']:08X} - 0x{end:08X} ({b['size']:,} bytes)")

    # Flash region classification
    regions = classify_flash_regions(entries, binary_size, base_addr)
    print("\nFlash region classification:")
    total_by_type: dict[str, int] = {}
    for r in regions:
        size = r["end"] - r["start"]
        total_by_type[r["type"]] = total_by_type.get(r["type"], 0) + size
        print(f"  0x{r['start']:08X} - 0x{r['end']:08X}  {size:>10,} bytes  {r['type']}")

    print("\nSummary:")
    for rtype, size in sorted(total_by_type.items()):
        pct = 100.0 * size / binary_size
        print(f"  {rtype:<16} {size:>10,} bytes  ({pct:.1f}%)")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Keil ARM scatter-load table from raw firmware binary"
    )
    parser.add_argument("--binary", required=True, help="Path to raw .bin file")
    parser.add_argument(
        "--base-addr",
        type=lambda x: int(x, 0),
        default=0x08000000,
        help="Flash base address (default: 0x08000000)",
    )
    args = parser.parse_args()

    try:
        with open(args.binary, "rb") as f:
            binary = f.read()
    except FileNotFoundError:
        print(f"Error: file not found: {args.binary}", file=sys.stderr)
        sys.exit(1)

    entries = find_scatter_load_table(binary, args.base_addr)

    if entries is None:
        print("No Keil scatter-load table found.", file=sys.stderr)
        sys.exit(1)

    print_report(entries, len(binary), args.base_addr)


if __name__ == "__main__":
    main()
