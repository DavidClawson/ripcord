"""Shared AT32F403A / Cortex-M peripheral register name decoder.

Provides a single canonical REGISTER_NAMES dict and decode/annotate
helpers used by agent prompts and phase analysis.
"""

from __future__ import annotations

import re

REGISTER_NAMES: dict[int, str] = {
    # DMA1
    0x40020000: "DMA1_STS", 0x40020004: "DMA1_CLR",
    0x4002001C: "DMA1_C2CTRL", 0x40020020: "DMA1_C2DTCNT",
    0x40020024: "DMA1_C2MADDR", 0x40020028: "DMA1_C2PADDR",
    # DMA2
    0x40020400: "DMA2_STS", 0x40020404: "DMA2_CLR",
    0x40020440: "DMA2_C4CTRL", 0x40020444: "DMA2_C4CTRL",
    0x40020448: "DMA2_C4DTCNT", 0x4002044C: "DMA2_C4DTCNT",
    0x40020450: "DMA2_C4PADDR", 0x40020454: "DMA2_C4MADDR",
    0x40020458: "DMA1_CMAR3",
    0x4002046C: "DMA1_CMAR4",
    0x40020480: "DMA1_CMAR5",
    0x40020494: "DMA1_CMAR6",
    0x400204A0: "DMA2_DMA_SRC_SEL0", 0x400204A4: "DMA2_DMA_SRC_SEL1",
    0x400204A8: "DMA1_CMAR7",
    # SPI3
    0x40003C00: "SPI3_CTRL1", 0x40003C04: "SPI3_CTRL2",
    0x40003C08: "SPI3_STS", 0x40003C0C: "SPI3_DT",
    # SPI2
    0x40003800: "SPI2_CTRL1", 0x40003804: "SPI2_CTRL2",
    0x40003808: "SPI2_STS", 0x4000380C: "SPI2_DT",
    # SPI1
    0x40013400: "SPI1_CTRL1", 0x40013404: "SPI1_CTRL2",
    0x40013408: "SPI1_STS", 0x4001340C: "SPI1_DT",
    # USART2
    0x40004400: "USART2_STS", 0x40004404: "USART2_DT",
    0x40004408: "USART2_BAUDR", 0x4000440C: "USART2_CTRL1",
    0x40004410: "USART2_CTRL2", 0x40004414: "USART2_CTRL3",
    # USART3
    0x40004804: "USART3_DR",
    # USART1
    0x40013804: "USART1_DR",
    # CRM/RCC
    0x40021000: "CRM_CTRL", 0x40021004: "CRM_CFG",
    0x40021008: "CRM_CLKINT", 0x4002100C: "CRM_APB2RST",
    0x40021010: "CRM_APB1RST", 0x40021014: "CRM_AHBEN",
    0x40021018: "CRM_APB2EN", 0x4002101C: "CRM_APB1EN",
    0x40021028: "CRM_MISC1", 0x40021030: "CRM_MISC2",
    0x40021054: "CRM_MISC3",
    # FSMC
    0x6001FFFE: "FSMC_CMD (LCD/FPGA)", 0x60020000: "FSMC_DATA (LCD/FPGA)",
    # DAC
    0x40007408: "DAC_CTRL", 0x40007414: "DAC_D1DTH12R",
    # System
    0xE000E010: "SYSTICK_CTRL", 0xE000E014: "SYSTICK_LOAD",
    0xE000E018: "SYSTICK_VAL",
    0xE000E100: "NVIC_ISER0", 0xE000E104: "NVIC_ISER1",
    0xE000ED04: "SCB_ICSR", 0xE000ED08: "SCB_VTOR",
    0xE000ED0C: "SCB_AIRCR",
}


def decode_register(addr: int) -> str:
    """Decode a peripheral register address to a human-readable name."""
    if addr in REGISTER_NAMES:
        return REGISTER_NAMES[addr]

    # Generic peripheral family detection
    if 0x40020000 <= addr < 0x40020400:
        return f"DMA1+{addr - 0x40020000:#x}"
    if 0x40020400 <= addr < 0x40020800:
        return f"DMA2+{addr - 0x40020400:#x}"
    if 0x40003C00 <= addr < 0x40004000:
        return f"SPI3+{addr - 0x40003C00:#x}"
    if 0x40021000 <= addr < 0x40021100:
        return f"CRM+{addr - 0x40021000:#x}"
    if 0xE000E000 <= addr < 0xE000F000:
        return f"NVIC+{addr - 0xE000E000:#x}"

    return f"0x{addr:08x}"


# Pre-build a reverse lookup for annotation: hex string -> register name.
# Only includes addresses in the peripheral range (0x4000_0000+, 0x6000_0000+, 0xE000_0000+).
_HEX_LOOKUP: dict[str, str] = {
    f"{addr:08x}": name for addr, name in REGISTER_NAMES.items()
}

# Regex matching DAT_XXXXXXXX, *(type*)0xXXXXXXXX, or bare 0xXXXXXXXX in peripheral range.
# Captures the full token and the 8-char hex portion.  Uses a negative lookahead to
# skip already-annotated occurrences (followed by " /* ... */").
_ANNOTATE_RE = re.compile(
    r'(?:'
    r'DAT_([0-9a-fA-F]{8})'                      # DAT_40003c08
    r'|'
    r'\*\s*\([^)]*\)\s*0x([0-9a-fA-F]{8})'       # *(uint32_t*)0x40003c08
    r'|'
    r'(?<!\w)0x([0-9a-fA-F]{8})(?!\w)'            # bare 0x40003c08
    r')'
    r'(?!\s*/\*)'                                  # not already annotated
)


def annotate_decompiled_c(c_text: str) -> str:
    """Annotate hex addresses in decompiled C with register names.

    Idempotent: skips addresses already followed by /* ... */.
    Only annotates addresses present in REGISTER_NAMES.
    """
    def _replace(m: re.Match) -> str:
        hex_str = m.group(1) or m.group(2) or m.group(3)
        name = _HEX_LOOKUP.get(hex_str.lower())
        if name is None:
            return m.group(0)
        return f"{m.group(0)} /* {name} */"

    return _ANNOTATE_RE.sub(_replace, c_text)
