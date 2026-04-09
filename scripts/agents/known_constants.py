"""Known embedded constants database and decompiled-C scanner.

Provides a lookup table of magic numbers commonly found in embedded
firmware (flash unlock keys, FAT32 signatures, ARM Cortex-M system
addresses, USB descriptors, CRC polynomials, etc.) and a scanner
that finds them in Ghidra decompiled pseudo-C.

Usage as a library:
    from known_constants import scan_decompiled_c, format_constants_context

    matches = scan_decompiled_c(c_text)
    prompt_section = format_constants_context(matches)

Usage as CLI:
    python scripts/agents/known_constants.py --target stock_v120 --build-dir build
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_AGENTS_DIR = str(Path(__file__).resolve().parent)
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)


# ---------------------------------------------------------------------------
# Known constants database
# ---------------------------------------------------------------------------

# Minimum value to match.  Constants below this threshold generate too many
# false positives on small immediates (loop bounds, bit shifts, field widths).
MIN_MATCH_VALUE = 0x100

KNOWN_CONSTANTS: dict[int, str] = {
    # -----------------------------------------------------------------------
    # Flash programming (STM32 / AT32 family)
    # -----------------------------------------------------------------------
    0x45670123: "Flash unlock key 1 (FLASH_KEY1)",
    0xCDEF89AB: "Flash unlock key 2 (FLASH_KEY2)",
    0x08192A3B: "Option byte unlock key 1",
    0x4C5D6E7F: "Option byte unlock key 2",

    # -----------------------------------------------------------------------
    # FAT / filesystem
    # -----------------------------------------------------------------------
    0x55AA: "MBR/FAT32 boot signature",
    0xAA55: "MBR/FAT32 boot signature (byte-swapped)",
    0x41615252: "FSInfo signature 1 ('RRaA')",
    0x61417272: "FSInfo signature 2 ('rrAa')",
    0x0000FFF8: "FAT32 media descriptor (hard disk)",
    0x0FFFFFF8: "FAT32 EOC marker",
    0x0FFFFFFF: "FAT32 EOC marker (alt)",
    0xFFF8: "FAT16 EOC marker / FAT32 media descriptor (16-bit)",
    0xFFFF: "FAT16 EOC marker (alt)",
    0xFFF7: "FAT bad cluster marker",

    # -----------------------------------------------------------------------
    # ARM Cortex-M system addresses and magic values
    # -----------------------------------------------------------------------
    0x05FA0000: "SCB_AIRCR VECTKEY (write key, upper 16 bits)",
    0x05FA0004: "SCB_AIRCR system reset request",
    0xE000ED00: "SCB base address (CPUID)",
    0xE000ED04: "SCB_ICSR (Interrupt Control and State)",
    0xE000ED08: "SCB_VTOR (Vector Table Offset)",
    0xE000ED0C: "SCB_AIRCR (Application Interrupt and Reset Control)",
    0xE000ED10: "SCB_SCR (System Control Register)",
    0xE000ED14: "SCB_CCR (Configuration and Control)",
    0xE000E010: "SysTick_CTRL",
    0xE000E014: "SysTick_LOAD",
    0xE000E018: "SysTick_VAL",
    0xE000E01C: "SysTick_CALIB",
    0xE000E100: "NVIC_ISER0 (Interrupt Set-Enable)",
    0xE000E180: "NVIC_ICER0 (Interrupt Clear-Enable)",
    0xE000E200: "NVIC_ISPR0 (Interrupt Set-Pending)",
    0xE000E280: "NVIC_ICPR0 (Interrupt Clear-Pending)",
    0xE000E400: "NVIC_IPR0 (Interrupt Priority)",
    0xE000EF00: "Software Trigger Interrupt Register (STIR)",
    0xE0001000: "DWT_CTRL (Data Watchpoint and Trace)",
    0xE000EDF0: "CoreDebug_DHCSR (Debug Halting Control and Status)",
    0xDEADBEEF: "Debug/uninitialized memory marker",
    0xCAFEBABE: "Debug marker / Java class file magic",
    0xA5A5A5A5: "FreeRTOS stack fill pattern",
    0xFEEDFACE: "Mach-O magic / debug marker",

    # -----------------------------------------------------------------------
    # USB
    # -----------------------------------------------------------------------
    0x0483: "STMicroelectronics USB Vendor ID",
    0x5720: "Mass Storage USB Product ID (common STM32)",
    0x0200: "USB 2.0 version BCD",
    0x0110: "USB 1.1 version BCD",
    0x0100: "USB 1.0 version BCD",

    # -----------------------------------------------------------------------
    # CRC polynomials
    # -----------------------------------------------------------------------
    0xEDB88320: "CRC-32 polynomial (reflected, IEEE 802.3)",
    0x04C11DB7: "CRC-32 polynomial (normal, IEEE 802.3)",
    0x82F63B78: "CRC-32C polynomial (reflected, Castagnoli)",
    0x1EDC6F41: "CRC-32C polynomial (normal, Castagnoli)",
    0xA001: "CRC-16/Modbus polynomial (reflected)",
    0x8005: "CRC-16 polynomial (normal, IBM/ANSI)",
    0x1021: "CRC-16/CCITT polynomial (normal)",

    # -----------------------------------------------------------------------
    # Common protocol markers and sync bytes
    # -----------------------------------------------------------------------
    0x5A5A: "Common sync word (pair)",
    0xA5A5: "Common sync word (complement pair)",
    0x7F454C46: "ELF magic number",
    0x504B0304: "ZIP/JAR local file header",

    # -----------------------------------------------------------------------
    # I2C common device addresses (7-bit, left-shifted to 8-bit write addr)
    # -----------------------------------------------------------------------
    0xA0: "I2C EEPROM write address (24Cxx)",
    0xA1: "I2C EEPROM read address (24Cxx)",
    0xD0: "I2C RTC DS1307/DS3231 write address",
    0xD1: "I2C RTC DS1307/DS3231 read address",
    0x78: "I2C OLED SSD1306 write address (0x3C << 1)",
    0x7A: "I2C OLED SSD1306 write address (0x3D << 1)",

    # -----------------------------------------------------------------------
    # Baud rate divisors and timing constants
    # -----------------------------------------------------------------------
    0x00989680: "10,000,000 (10 MHz)",
    0x016E3600: "24,000,000 (24 MHz)",
    0x02DC6C00: "48,000,000 (48 MHz)",
    0x044AA200: "72,000,000 (72 MHz)",
    0x05F5E100: "100,000,000 (100 MHz)",
    0x07270E00: "120,000,000 (120 MHz)",
    0x08F0D180: "150,000,000 (150 MHz)",
    0x0BEBC200: "200,000,000 (200 MHz)",
    0x0EE6B280: "250,000,000 (250 MHz)",
    0x11E1A300: "300,000,000 (300 MHz)",
    0x1C9C3800: "480,000,000 (480 MHz, USB HS PHY)",
    # Common baud rates as raw values (not divisors)
    0x1C200: "115,200 (baud rate)",
    0x2580: "9,600 (baud rate)",
    0x4B00: "19,200 (baud rate)",
    0x9600: "38,400 (baud rate)",
    0xE100: "57,600 (baud rate)",
    0x1C200: "115,200 (baud rate)",
    0x38400: "230,400 (baud rate)",
    0x70800: "460,800 (baud rate)",
    0xE1000: "921,600 (baud rate)",

    # -----------------------------------------------------------------------
    # Display controller IDs
    # -----------------------------------------------------------------------
    0x7789: "ST7789V LCD controller ID",
    0x9341: "ILI9341 LCD controller ID",
    0x9488: "ILI9488 LCD controller ID",
    0x7735: "ST7735 LCD controller ID",
    0x1106: "SSD1306 OLED controller ID",

    # -----------------------------------------------------------------------
    # FPGA / FNIRSI-specific (from analysis)
    # -----------------------------------------------------------------------
    0x1C3B6: "115,638 bytes (H2 calibration data size)",

    # -----------------------------------------------------------------------
    # FreeRTOS internals
    # -----------------------------------------------------------------------
    0x5A5A5A5A: "FreeRTOS queue/mutex magic",

    # -----------------------------------------------------------------------
    # Common embedded math / DSP
    # -----------------------------------------------------------------------
    0x5F3759DF: "Fast inverse square root magic (Quake III)",
    0x7F800000: "IEEE 754 float +infinity",
    0xFF800000: "IEEE 754 float -infinity",
    0x7FC00000: "IEEE 754 float NaN (quiet)",
}

# Build a secondary index of 16-bit sub-values worth flagging when they
# appear as the upper or lower half of a 32-bit constant.
_KNOWN_16BIT: dict[int, str] = {
    k: v for k, v in KNOWN_CONSTANTS.items()
    if 0x100 <= k <= 0xFFFF
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

# Regex: hex literals (0x...), decimal literals, and Ghidra DAT_ references.
# DAT_ references encode an address — we don't match those as constants,
# but we DO match the hex/decimal literals that appear in expressions.
_HEX_RE = re.compile(r"\b0[xX]([0-9a-fA-F]+)\b")
_DEC_RE = re.compile(r"(?<![0-9a-fA-FxX])(?<!\w)\b([1-9][0-9]{2,})\b(?![0-9a-fA-FxX])")
# Negative numbers in casts, e.g. (int)-0x12345 or comparison == -12345
_NEG_HEX_RE = re.compile(r"-\s*0[xX]([0-9a-fA-F]+)\b")


def scan_decompiled_c(c_text: str) -> list[dict]:
    """Scan decompiled C text for known constants.

    Returns list of dicts with keys:
        value   (int)  — the matched constant
        meaning (str)  — human-readable description from KNOWN_CONSTANTS
        context (str)  — the source line where it appeared (stripped)

    Only returns matches for values >= MIN_MATCH_VALUE.  Unknown constants
    are silently ignored.
    """
    if not c_text:
        return []

    matches: list[dict] = []
    seen: set[tuple[int, int]] = set()  # (value, line_idx) dedup

    for line_idx, line in enumerate(c_text.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue

        # Collect all numeric values on this line
        values: list[int] = []

        for m in _HEX_RE.finditer(stripped):
            try:
                values.append(int(m.group(1), 16))
            except ValueError:
                continue

        for m in _NEG_HEX_RE.finditer(stripped):
            try:
                # Store as unsigned 32-bit
                v = int(m.group(1), 16)
                values.append(v)
            except ValueError:
                continue

        for m in _DEC_RE.finditer(stripped):
            try:
                values.append(int(m.group(1)))
            except ValueError:
                continue

        for val in values:
            if val < MIN_MATCH_VALUE:
                continue

            key = (val, line_idx)
            if key in seen:
                continue

            meaning = KNOWN_CONSTANTS.get(val)
            if meaning:
                seen.add(key)
                matches.append({
                    "value": val,
                    "meaning": meaning,
                    "context": stripped,
                })
                continue

            # Check if upper or lower 16 bits match a known 16-bit constant.
            # Only for 32-bit values where the sub-match is informative.
            if val > 0xFFFF:
                lo16 = val & 0xFFFF
                hi16 = (val >> 16) & 0xFFFF
                for sub, sub_meaning in ((lo16, None), (hi16, None)):
                    if sub < MIN_MATCH_VALUE:
                        continue
                    sub_meaning = _KNOWN_16BIT.get(sub)
                    if sub_meaning:
                        seen.add(key)
                        half = "lower" if sub == lo16 else "upper"
                        matches.append({
                            "value": val,
                            "meaning": f"Contains {sub_meaning} in {half} 16 bits",
                            "context": stripped,
                        })
                        break

    return matches


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------

def format_constants_context(matches: list[dict], max_matches: int = 8) -> str:
    """Format known constant matches for inclusion in LLM prompts.

    Returns an empty string if there are no matches, so callers can
    unconditionally append without checking.

    Output example::

        ## Known constants detected
        - 0x45670123: Flash unlock key 1 (FLASH_KEY1) -- line: "if (DAT_40023c04 != 0x45670123)"
        - 0x55AA: MBR/FAT32 boot signature -- line: "if (uVar3 == 0x55aa)"
    """
    if not matches:
        return ""

    # Deduplicate by value (keep first occurrence)
    seen_values: set[int] = set()
    unique: list[dict] = []
    for m in matches:
        if m["value"] not in seen_values:
            seen_values.add(m["value"])
            unique.append(m)

    # Truncate context lines to something readable
    lines: list[str] = []
    for m in unique[:max_matches]:
        ctx = m["context"]
        if len(ctx) > 120:
            ctx = ctx[:117] + "..."
        lines.append(
            f"- 0x{m['value']:X}: {m['meaning']} -- line: \"{ctx}\""
        )

    remainder = len(unique) - max_matches
    if remainder > 0:
        lines.append(f"- ... and {remainder} more known constants")

    return "## Known constants detected\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Scan decompiled C for known embedded constants.",
    )
    p.add_argument(
        "--target",
        required=True,
        help="Target name (e.g. stock_v120, pico_freertos_hello).",
    )
    p.add_argument(
        "--build-dir",
        default="build",
        help="Root build directory (default: build).",
    )
    p.add_argument(
        "--min-matches",
        type=int,
        default=0,
        help="Only show functions with at least this many matches.",
    )
    return p


def main() -> None:
    args = _build_arg_parser().parse_args()

    import duckdb
    from context import register_warehouse

    build_dir = Path(args.build_dir)
    if not build_dir.is_dir():
        print(f"error: build directory not found: {build_dir}", file=sys.stderr)
        sys.exit(1)

    conn = duckdb.connect(":memory:")
    register_warehouse(conn, str(build_dir))

    # Check that the decompiled table exists for this target
    try:
        rows = conn.execute(
            "SELECT addr, name, decompiled_c FROM decompiled "
            "WHERE source = ? AND decompile_success = true "
            "ORDER BY addr",
            [args.target],
        ).fetchall()
    except duckdb.CatalogException:
        print(
            f"error: no 'decompiled' table found for target '{args.target}'. "
            "Run the decompiler extraction first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not rows:
        print(f"No decompiled functions found for target '{args.target}'.")
        return

    # Scan each function
    total_matches = 0
    results: list[tuple[int, str, list[dict]]] = []

    for addr, name, c_text in rows:
        if not c_text:
            continue
        matches = scan_decompiled_c(c_text)
        if matches and len(matches) >= args.min_matches:
            results.append((addr, name, matches))
            total_matches += len(matches)

    # Sort by number of matches descending
    results.sort(key=lambda r: len(r[2]), reverse=True)

    # Print report
    print(f"Target: {args.target}")
    print(f"Functions scanned: {len(rows)}")
    print(f"Functions with matches: {len(results)}")
    print(f"Total constant matches: {total_matches}")
    print()

    for addr, name, matches in results:
        print(f"--- {name} (0x{addr:08X}) --- {len(matches)} match(es)")
        # Deduplicate by value for display
        seen: set[int] = set()
        for m in matches:
            if m["value"] in seen:
                continue
            seen.add(m["value"])
            ctx = m["context"]
            if len(ctx) > 100:
                ctx = ctx[:97] + "..."
            print(f"  0x{m['value']:08X}  {m['meaning']}")
            print(f"             {ctx}")
        print()


if __name__ == "__main__":
    main()
