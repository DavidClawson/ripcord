#!/usr/bin/env -S uv run python
"""Identify ISA, load address, and chip family from a firmware binary.

Usage
-----
    scripts/identify.py firmware.bin          # raw binary
    scripts/identify.py firmware.elf          # ELF (reads headers directly)

Output is human-readable with suggested Ghidra flags for pipeline ingestion.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# ELF handling
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

# e_machine values we care about
ELF_MACHINES = {
    0x28: "ARM",
    0x08: "MIPS",
    0xF3: "RISC-V",
    0x03: "x86",
    0x3E: "x86-64",
    0xB7: "AArch64",
}

# ELF ISA → Ghidra processor string
ELF_GHIDRA_PROC = {
    "ARM": "ARM:LE:32:Cortex",
    "MIPS": "MIPS:BE:32:default",
    "RISC-V": "RISC-V:LE:32:default",
    "AArch64": "AARCH64:LE:64:v8A",
}


def identify_elf(path: Path, data: bytes) -> None:
    """Parse ELF headers and print identification."""
    if len(data) < 52:
        print("  File too small for ELF header")
        return

    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]  # 1=LE, 2=BE
    endian = "little" if ei_data == 1 else "big"
    fmt = "<" if ei_data == 1 else ">"
    bits = 32 if ei_class == 1 else 64

    e_machine = struct.unpack_from(f"{fmt}H", data, 18)[0]
    if bits == 32:
        e_entry = struct.unpack_from(f"{fmt}I", data, 24)[0]
    else:
        e_entry = struct.unpack_from(f"{fmt}Q", data, 24)[0]

    isa_name = ELF_MACHINES.get(e_machine, f"unknown (0x{e_machine:04X})")
    endian_str = "LE" if ei_data == 1 else "BE"

    print(f"\nELF Header:")
    print(f"  Class:       {bits}-bit")
    print(f"  Endianness:  {endian_str}")
    print(f"  ISA:         {isa_name} (e_machine=0x{e_machine:02X})")
    print(f"  Entry point: 0x{e_entry:08X}")

    # For ARM ELFs, check if entry has Thumb bit
    if e_machine == 0x28 and (e_entry & 1):
        print(f"               (Thumb mode, actual address 0x{e_entry & ~1:08X})")

    # Read ELF flags for ARM sub-architecture hints
    if bits == 32:
        e_flags = struct.unpack_from(f"{fmt}I", data, 36)[0]
        if e_machine == 0x28:
            eabi_ver = (e_flags >> 24) & 0xFF
            print(f"  ELF flags:   0x{e_flags:08X} (EABI{eabi_ver})")

    # Suggested Ghidra flags
    ghidra_proc = ELF_GHIDRA_PROC.get(isa_name)
    if ghidra_proc:
        print(f"\nSuggested Ghidra flags:")
        print(f'  -processor "{ghidra_proc}"')
        print(f"  (ELF loader will handle the rest automatically)")


# ---------------------------------------------------------------------------
# ISA detection for raw binaries
# ---------------------------------------------------------------------------


def count_thumb_patterns(data: bytes, sample_size: int = 4096) -> dict:
    """Score data as ARM Thumb / Thumb-2 instructions."""
    n = min(len(data), sample_size)
    if n < 16:
        return {"name": "ARM Thumb-2 (Cortex-M)", "confidence": 0.0, "detail": "too small"}

    # Sample at 2-byte aligned offsets
    matches = 0
    total = 0
    push_pop = 0
    bl_count = 0
    it_count = 0
    data_proc = 0
    thumb2_prefix = 0

    for off in range(0, n - 1, 2):
        hw = struct.unpack_from("<H", data, off)[0]
        total += 1

        # PUSH {regs, LR} — 0xB5xx
        if (hw & 0xFF00) == 0xB500:
            push_pop += 1
            matches += 1
        # POP {regs, PC} — 0xBDxx
        elif (hw & 0xFF00) == 0xBD00:
            push_pop += 1
            matches += 1
        # MOV Rd, Rs — 0x46xx
        elif (hw & 0xFF00) == 0x4600:
            data_proc += 1
            matches += 1
        # ADD/SUB/CMP/MOV immediate — 0x2xxx-0x3xxx
        elif (hw >> 13) == 1:
            data_proc += 1
            matches += 1
        # Data processing register — 0x4000-0x43FF
        elif (hw & 0xFC00) == 0x4000:
            data_proc += 1
            matches += 1
        # LDR/STR (various) — 0x5xxx-0x9xxx
        elif 0x5000 <= hw < 0xA000:
            matches += 1
        # BL/BLX first halfword — 0xF000-0xF7FF
        elif (hw & 0xF800) == 0xF000:
            bl_count += 1
            matches += 1
        # Thumb-2 32-bit prefix — 0xE800-0xEFFF, 0xF000-0xFFFF
        elif (hw & 0xE000) == 0xE000 and (hw & 0x1800) != 0x0000:
            thumb2_prefix += 1
            matches += 1
        # Branch — 0xDxxx (conditional), 0xE0xx (unconditional)
        elif (hw & 0xF000) == 0xD000 or (hw & 0xF800) == 0xE000:
            matches += 1
        # ADD SP / SUB SP — 0xB0xx
        elif (hw & 0xFF00) == 0xB000:
            matches += 1
        # IT block — 0xBFx0-0xBFxF (not BF00 = NOP)
        elif (hw & 0xFF00) == 0xBF00 and (hw & 0x000F) != 0:
            it_count += 1
            matches += 1
        # NOP — 0xBF00
        elif hw == 0xBF00:
            matches += 1
        # ADR, LDR literal — 0xA0xx, 0x48xx
        elif (hw & 0xF800) == 0xA000 or (hw & 0xF800) == 0x4800:
            matches += 1

    ratio = matches / total if total else 0.0

    # Confidence based on instruction match ratio and presence of function prologues
    confidence = 0.0
    if ratio > 0.3:
        confidence = min(ratio * 1.2, 0.99)
        # Boost if we see PUSH/POP pairs (real code has function prologues)
        if push_pop >= 4:
            confidence = min(confidence + 0.05, 0.99)

    detail_parts = [f"{bits(data)}, {ratio:.0%} instruction match"]
    if push_pop:
        detail_parts.append(f"{push_pop} PUSH/POP")
    if bl_count:
        detail_parts.append(f"{bl_count} BL/BLX")
    if it_count:
        detail_parts.append(f"{it_count} IT blocks")

    return {
        "name": "ARM Thumb-2 (Cortex-M)",
        "confidence": round(confidence, 2),
        "detail": ", ".join(detail_parts),
        "ghidra_processor": "ARM:LE:32:Cortex",
    }


def count_arm32_patterns(data: bytes, sample_size: int = 4096) -> dict:
    """Score data as ARM A32 (classic ARM) instructions."""
    n = min(len(data), sample_size)
    if n < 16:
        return {"name": "ARM A32", "confidence": 0.0, "detail": "too small"}

    matches = 0
    total = 0
    cond_always = 0

    for off in range(0, n - 3, 4):
        insn = struct.unpack_from("<I", data, off)[0]
        total += 1
        cond = (insn >> 28) & 0xF

        # Valid condition codes are 0x0-0xE (0xF is special/undefined for older ARM)
        if cond <= 0xE:
            matches += 1
            if cond == 0xE:
                cond_always += 1

    ratio = matches / total if total else 0.0
    cond_always_ratio = cond_always / total if total else 0.0

    # ARM code: most instructions have cond=0xE (always), ratio should be high
    confidence = 0.0
    if ratio > 0.8 and cond_always_ratio > 0.4:
        confidence = min(cond_always_ratio * 0.9, 0.95)

    return {
        "name": "ARM A32",
        "confidence": round(confidence, 2),
        "detail": f"{bits(data)}, {ratio:.0%} valid cond, {cond_always_ratio:.0%} AL",
        "ghidra_processor": "ARM:LE:32:v7",
    }


def count_mips_patterns(data: bytes, sample_size: int = 4096) -> dict:
    """Score data as MIPS32 instructions (big-endian or little-endian)."""
    n = min(len(data), sample_size)
    if n < 16:
        return {"name": "MIPS32", "confidence": 0.0, "detail": "too small"}

    best_conf = 0.0
    best_endian = "LE"

    for endian, fmt in [("LE", "<I"), ("BE", ">I")]:
        nop_count = 0
        jr_ra = 0
        valid = 0
        total = 0

        for off in range(0, n - 3, 4):
            insn = struct.unpack_from(fmt, data, off)[0]
            total += 1
            opcode = (insn >> 26) & 0x3F

            # Common MIPS opcodes
            if opcode in (0x00, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A,
                          0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x23, 0x2B):
                valid += 1
            if insn == 0x00000000:
                nop_count += 1
            if insn == 0x03E00008:  # JR $ra
                jr_ra += 1

        ratio = valid / total if total else 0.0
        conf = 0.0
        if ratio > 0.4 and jr_ra >= 2:
            conf = min(ratio * 0.8, 0.90)

        if conf > best_conf:
            best_conf = conf
            best_endian = endian

    return {
        "name": f"MIPS32 ({best_endian})",
        "confidence": round(best_conf, 2),
        "detail": f"{ratio:.0%} known opcodes",
        "ghidra_processor": f"MIPS:{best_endian}:32:default",
    }


def count_riscv_patterns(data: bytes, sample_size: int = 4096) -> dict:
    """Score data as RISC-V instructions.

    RISC-V compressed encoding (bits[1:0] != 0b11) matches ~75% of random
    data, so we only count 32-bit instructions with known opcodes *and*
    require structural indicators (JAL/JALR for function calls, AUIPC for
    PC-relative addressing).
    """
    n = min(len(data), sample_size)
    if n < 16:
        return {"name": "RISC-V", "confidence": 0.0, "detail": "too small"}

    rv32_match = 0
    rv32_total = 0
    jal_count = 0
    jalr_count = 0
    auipc_count = 0

    # Only scan at 4-byte alignment for 32-bit RV instructions
    for off in range(0, n - 3, 4):
        insn = struct.unpack_from("<I", data, off)[0]
        rv32_total += 1
        opcode = insn & 0x7F

        # bits [1:0] must be 0b11 for 32-bit RV instructions
        if (opcode & 0x03) != 0x03:
            continue

        if opcode in (0x03, 0x13, 0x17, 0x23, 0x33, 0x37, 0x63, 0x67, 0x6F, 0x73):
            rv32_match += 1
            if opcode == 0x6F:  # JAL
                jal_count += 1
            elif opcode == 0x67:  # JALR
                jalr_count += 1
            elif opcode == 0x17:  # AUIPC
                auipc_count += 1

    ratio = rv32_match / rv32_total if rv32_total else 0.0
    confidence = 0.0
    # Require both high opcode match rate AND structural function-call indicators
    if ratio > 0.5 and (jal_count + jalr_count) >= 4:
        confidence = min(ratio * 0.7, 0.90)
        if auipc_count >= 2:
            confidence = min(confidence + 0.05, 0.90)

    return {
        "name": "RISC-V",
        "confidence": round(confidence, 2),
        "detail": f"{bits(data)}, {ratio:.0%} known opcodes, {jal_count} JAL, {jalr_count} JALR",
        "ghidra_processor": "RISC-V:LE:32:default",
    }


def bits(data: bytes) -> str:
    """Return '32-bit LE' or similar based on simple heuristics."""
    # Check for zero bytes in positions suggesting endianness
    # This is a rough heuristic
    le_zeros = sum(1 for i in range(3, min(len(data), 256), 4) if data[i] == 0)
    be_zeros = sum(1 for i in range(0, min(len(data), 256), 4) if data[i] == 0)
    if le_zeros > be_zeros:
        return "32-bit LE"
    elif be_zeros > le_zeros:
        return "32-bit BE"
    return "32-bit"


def detect_isa(data: bytes) -> list[dict]:
    """Score each ISA and return candidates sorted by confidence."""
    candidates = [
        count_thumb_patterns(data),
        count_arm32_patterns(data),
        count_mips_patterns(data),
        count_riscv_patterns(data),
    ]
    return sorted(candidates, key=lambda x: x["confidence"], reverse=True)


# ---------------------------------------------------------------------------
# Cortex-M vector table detection
# ---------------------------------------------------------------------------


def detect_cortex_m_vector_table(data: bytes, offset: int = 0) -> dict | None:
    """Check if data at offset looks like a Cortex-M vector table.

    Returns dict with sp_init, reset_vector, load_address, sram_kb, confidence,
    or None if it doesn't look like a vector table.
    """
    if len(data) < offset + 8:
        return None

    sp_init = struct.unpack_from("<I", data, offset)[0]
    reset_vector = struct.unpack_from("<I", data, offset + 4)[0]

    # SP should point into SRAM (0x20000000-0x20FFFFFF for most Cortex-M)
    sp_is_ram = 0x20000000 <= sp_init <= 0x20FFFFFF
    if not sp_is_ram:
        return None

    # Reset vector should be in flash with Thumb bit set
    reset_addr = reset_vector & ~1
    reset_is_flash = 0x08000000 <= reset_addr <= 0x08FFFFFF
    reset_is_thumb = (reset_vector & 1) == 1

    if not (reset_is_flash and reset_is_thumb):
        return None

    # Check additional vectors for consistency
    vectors_valid = 0
    vectors_total = 0
    for i in range(2, min(16, (len(data) - offset) // 4)):
        vec = struct.unpack_from("<I", data, offset + i * 4)[0]
        vectors_total += 1
        if vec == 0:
            vectors_valid += 1  # Reserved/unused vectors are 0
        elif 0x08000000 <= (vec & ~1) <= 0x08FFFFFF and (vec & 1) == 1:
            vectors_valid += 1  # Valid flash address with Thumb bit

    vec_ratio = vectors_valid / vectors_total if vectors_total else 0

    # Infer SRAM size from SP init
    sram_size = sp_init - 0x20000000
    sram_kb = sram_size / 1024

    # Infer load address: the vector table is at the base of the image.
    # The reset vector points somewhere into the image.
    # For app images starting after a bootloader, load_address = base of flash region
    # containing the reset vector, aligned to the file's apparent base.
    #
    # Heuristic: if file offset is 0, the vector table is at load_address.
    # reset_vector points to load_address + some_offset.
    # We know the reset handler offset in the file; load_addr = reset_addr - file_offset_of_handler
    #
    # Simpler: the image base is typically page-aligned. Try common bases.
    reset_file_offset = None
    if offset == 0:
        # The load address is the flash address mapped to file offset 0.
        # For a raw .bin with vector table at offset 0, the load address
        # must be <= the lowest vector address. Without knowing the
        # bootloader size, we use the page-aligned address just below
        # the minimum vector as the best heuristic.
        #
        # Collect all non-zero vector addresses from the table
        vec_addrs = []
        for i in range(1, min(16, (len(data) - offset) // 4)):
            vec = struct.unpack_from("<I", data, offset + i * 4)[0]
            if vec != 0:
                vec_addrs.append(vec & ~1)  # strip Thumb bit

        if vec_addrs:
            min_vec = min(vec_addrs)
            # load_address must be <= min_vec and page-aligned
            # Use page below the minimum vector
            load_address = min_vec & ~0xFFF
            reset_file_offset = reset_addr - load_address
        else:
            load_address = reset_addr & ~0xFFF
            reset_file_offset = reset_addr - load_address
    else:
        load_address = None

    confidence = 0.5
    if sp_is_ram:
        confidence += 0.15
    if reset_is_thumb:
        confidence += 0.10
    if vec_ratio > 0.7:
        confidence += 0.15
    if reset_file_offset is not None:
        confidence += 0.05
    confidence = min(round(confidence, 2), 0.99)

    return {
        "sp_init": sp_init,
        "reset_vector": reset_vector,
        "reset_addr": reset_addr,
        "sram_bytes": sram_size,
        "sram_kb": sram_kb,
        "load_address": load_address,
        "vectors_valid_ratio": vec_ratio,
        "confidence": confidence,
        "file_offset": offset,
    }


def scan_for_vector_table(data: bytes, scan_limit: int = 0x10000) -> dict | None:
    """Scan data for a Cortex-M vector table, checking offset 0 first,
    then scanning at 0x1000-aligned offsets."""
    # Try offset 0 first
    result = detect_cortex_m_vector_table(data, 0)
    if result and result["confidence"] >= 0.7:
        return result

    # Scan at page-aligned offsets
    best = result
    for off in range(0x1000, min(len(data), scan_limit), 0x1000):
        r = detect_cortex_m_vector_table(data, off)
        if r and (best is None or r["confidence"] > best["confidence"]):
            best = r

    return best


# ---------------------------------------------------------------------------
# Chip family identification
# ---------------------------------------------------------------------------

# (sram_kb_range, isa_hint) → candidate chip families
# sram_kb_range is (min, max) inclusive
CHIP_FAMILIES: list[tuple[tuple[float, float], list[str]]] = [
    ((216, 232), ["AT32F403A", "AT32F407"]),
    ((188, 200), ["STM32F407", "STM32F405"]),
    ((124, 132), ["STM32F401", "STM32F411", "STM32F103RC/RD/RE"]),
    ((92, 100), ["STM32F103RB", "GD32F103"]),
    ((60, 68), ["STM32F103C8/CB"]),
    ((256, 272), ["RP2040"]),  # 264KB SRAM
    ((28, 36), ["STM32F030", "STM32F051"]),
    ((16, 20), ["STM32F030F4", "STM32F042"]),
    ((320, 384), ["STM32F429", "STM32F439", "AT32F435"]),
    ((508, 520), ["STM32H743", "STM32H750"]),
]


def identify_chip_family(sram_kb: float) -> list[str]:
    """Return candidate chip families based on SRAM size."""
    candidates = []
    for (lo, hi), chips in CHIP_FAMILIES:
        if lo <= sram_kb <= hi:
            candidates.extend(chips)
    return candidates


# ---------------------------------------------------------------------------
# Peripheral signature database (for post-Ghidra xref confirmation)
# ---------------------------------------------------------------------------

PERIPHERAL_SIGNATURES = {
    "STM32F1 / AT32F403A": {
        0x40021000: "RCC",
        0x40010000: "AFIO",
        0x40023000: "CRC",
        0x40010800: "GPIOA",
        0x40010C00: "GPIOB",
        0x40013800: "USART1",
        0x40004400: "USART2",
        0x40005400: "I2C1",
        0x40013000: "SPI1",
        0x40011000: "EXTI",
        0x40007000: "PWR",
    },
    "STM32F4": {
        0x40023800: "RCC",
        0x40023C00: "FLASH_IF",
        0x40020000: "GPIOA",
        0x40020400: "GPIOB",
        0x40011000: "SPI1",
        0x40013800: "USART1",
        0x40011400: "USART6",
        0x40007000: "PWR",
    },
    "Nordic nRF52": {
        0x40000000: "CLOCK",
        0x40001000: "POWER",
        0x40002000: "RADIO",
        0x40003000: "UART0",
        0x40006000: "GPIOTE",
    },
    "NXP LPC": {
        0x400FC000: "SC",
        0x40088000: "GPIO",
        0x40098000: "UART0",
        0x400A8000: "SSP0",
    },
}


def check_peripheral_xrefs(xref_addresses: set[int]) -> list[tuple[str, str, int]]:
    """Check a set of referenced addresses against known peripheral bases.

    Returns list of (chip_family, peripheral_name, address) matches.
    """
    hits = []
    for family, periphs in PERIPHERAL_SIGNATURES.items():
        for addr, name in periphs.items():
            # Check for references to the base address or nearby registers
            for ref in xref_addresses:
                if addr <= ref < addr + 0x400:  # typical peripheral register block
                    hits.append((family, name, addr))
                    break
    return hits


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware.bin|firmware.elf>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr)
        sys.exit(1)

    data = path.read_bytes()
    size = len(data)

    print(f"=== ripcord binary identification ===")
    print(f"File: {path.name} ({size:,} bytes)")

    # --- ELF? ---
    if data[:4] == ELF_MAGIC:
        identify_elf(path, data)
        return

    # --- Raw binary ---
    print(f"\nISA Detection:")
    candidates = detect_isa(data)
    for c in candidates:
        if c["confidence"] > 0.05:
            print(f"  {c['name']:30s}  confidence={c['confidence']:.2f}  [{c['detail']}]")

    best_isa = candidates[0] if candidates else None

    # --- Vector table ---
    print(f"\nVector Table Detection:")
    vt = scan_for_vector_table(data)
    if vt:
        sram_kb = vt["sram_kb"]
        print(f"  Initial SP:    0x{vt['sp_init']:08X}  ({sram_kb:.0f}KB SRAM)")
        print(f"  Reset Vector:  0x{vt['reset_vector']:08X}  (flash, {'Thumb bit set' if vt['reset_vector'] & 1 else 'ARM mode'})")
        if vt["load_address"] is not None:
            print(f"  Load Address:  0x{vt['load_address']:08X}  (page below lowest vector; adjust if bootloader offset is known)")
        else:
            print(f"  Load Address:  unknown (vector table at file offset 0x{vt['file_offset']:X})")
        print(f"  Vec validity:  {vt['vectors_valid_ratio']:.0%} of first 16 vectors valid")
        print(f"  Confidence:    {vt['confidence']:.2f}")

        # Chip family
        chips = identify_chip_family(sram_kb)
        if chips:
            print(f"\nChip Family (from SRAM size):")
            print(f"  Candidates:  {', '.join(chips)}")
            print(f"  (SRAM {sram_kb:.0f}KB is consistent with these parts)")
        else:
            print(f"\nChip Family: unknown (SRAM {sram_kb:.0f}KB doesn't match known families)")

        # Suggested Ghidra flags
        ghidra_proc = best_isa["ghidra_processor"] if best_isa and best_isa["confidence"] > 0.3 else "ARM:LE:32:Cortex"
        print(f"\nSuggested Ghidra flags:")
        print(f'  -processor "{ghidra_proc}"')
        if vt["load_address"] is not None:
            print(f'  -loader BinaryLoader -loader-baseAddr 0x{vt["load_address"]:08X}')
        print()
        print(f"Suggested config.yaml entry:")
        print(f"  - name: {path.stem}")
        print(f"    elf: targets/{path.stem}/{path.name}")
        print(f"    arch: {ghidra_proc}")
        if vt["load_address"] is not None:
            print(f"    loader: BinaryLoader")
            print(f"    base_addr: 0x{vt['load_address']:08X}")
    else:
        print("  No Cortex-M vector table detected at start or in first 64KB.")
        if best_isa and best_isa["confidence"] > 0.3:
            print(f"\nSuggested Ghidra flags:")
            print(f'  -processor "{best_isa["ghidra_processor"]}"')

    print()
    print("Peripheral confirmation (requires Ghidra xref extraction first):")
    print("  Run the pipeline, then:")
    print(f'  scripts/query "SELECT DISTINCT to_addr FROM xrefs WHERE source=\'<target>\' AND to_addr >= 0x40000000 AND to_addr < 0x50000000"')


if __name__ == "__main__":
    main()
