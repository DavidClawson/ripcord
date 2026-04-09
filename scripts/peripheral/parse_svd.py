"""Parse CMSIS-SVD files into a peripheral register lookup table.

Given an SVD file path, produces a mapping from absolute register
addresses to (peripheral_name, register_name, peripheral_group).
Handles the common SVD features:
  - derivedFrom (peripheral inherits registers from another)
  - addressBlock for peripheral size
  - register addressOffset relative to peripheral baseAddress

Does NOT handle: dim/dimIncrement register arrays, clusters, or
nested derivedFrom chains deeper than one level. These are rare in
vendor SVDs and can be added if a real SVD needs them.

Usage as a library:
    from parse_svd import parse_svd
    reg_map = parse_svd("path/to/chip.svd")
    info = reg_map.lookup(0x40004400)
    # -> RegisterInfo(peripheral='USART2', register='STS', group='communication')
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RegisterInfo:
    peripheral: str
    register: str  # empty string if address is in peripheral range but no exact register match
    group: str
    base_addr: int  # peripheral base address
    reg_addr: int  # absolute register address (0 if no exact match)
    alias: str = ""  # "", "xor", "set", "clr" — RP2040 atomic register aliases


@dataclass
class PeripheralDef:
    name: str
    base_addr: int
    size: int  # address block size in bytes
    group: str
    registers: dict[int, str] = field(default_factory=dict)  # offset -> register name


# ---------------------------------------------------------------------------
# Peripheral group classification
# ---------------------------------------------------------------------------

# Prefix -> semantic group. Checked in order; first match wins.
# Covers AT32, STM32, TI Stellaris, RP2040, Nordic, and generic Cortex-M names.
_GROUP_PREFIXES = [
    # Communication
    ("USART", "communication"),
    ("UART", "communication"),
    ("SPI", "communication"),
    ("I2C", "communication"),
    ("I2S", "communication"),
    ("CAN", "communication"),
    ("USB", "communication"),
    # GPIO
    ("GPIO", "gpio"),
    ("IO_BANK", "gpio"),
    ("PADS_BANK", "gpio"),
    ("SIO", "gpio"),
    # Timers
    ("TMR", "timer"),
    ("TIM", "timer"),
    ("TIMER", "timer"),
    ("GPTM", "timer"),  # TI General Purpose Timer
    # DMA
    ("DMA", "dma"),
    ("UDMA", "dma"),
    # Analog
    ("ADC", "analog"),
    ("DAC", "analog"),
    ("COMP", "analog"),
    # Clock / Reset
    ("CRM", "clock"),
    ("RCC", "clock"),
    ("CLOCKS", "clock"),
    ("SYSCTL", "clock"),  # TI system control
    ("RESETS", "clock"),
    # Power
    ("PWC", "power"),
    ("PWR", "power"),
    ("PSM", "power"),
    ("VREG", "power"),
    # Memory controller
    ("XMC", "memory"),
    ("FSMC", "memory"),
    ("FLASH", "memory"),
    ("FMC", "memory"),
    # Storage
    ("SDIO", "storage"),
    # Interrupt controller
    ("EXINT", "interrupt"),
    ("EXTI", "interrupt"),
    ("NVIC", "interrupt"),
    # RTC / backup
    ("RTC", "rtc"),
    ("BPR", "rtc"),
    # Watchdog
    ("WDT", "watchdog"),
    ("WWDT", "watchdog"),
    ("IWDG", "watchdog"),
    ("WWDG", "watchdog"),
    # Pin mux
    ("IOMUX", "pinmux"),
    ("AFIO", "pinmux"),
    ("IO_QSPI", "pinmux"),
    # Debug
    ("DEBUG", "debug"),
    # System misc
    ("CRC", "system"),
    ("ACC", "system"),
    ("SCB", "system"),
    ("FPU", "system"),
    ("SYSTICK", "system"),
    ("MPU", "system"),
    ("PLL", "clock"),
    ("ROSC", "clock"),
    ("XOSC", "clock"),
    ("WATCHDOG", "watchdog"),
]


def classify_group(name: str) -> str:
    """Classify a peripheral name into a semantic group by prefix match."""
    upper = name.upper()
    for prefix, group in _GROUP_PREFIXES:
        if upper.startswith(prefix):
            return group
    return "other"


# ---------------------------------------------------------------------------
# Cortex-M system peripherals (fixed addresses, no SVD needed)
# ---------------------------------------------------------------------------

_CORTEX_M_SYSTEM: list[PeripheralDef] = [
    PeripheralDef(
        name="SysTick",
        base_addr=0xE000E010,
        size=16,
        group="system",
        registers={
            0x00: "CTRL",
            0x04: "LOAD",
            0x08: "VAL",
            0x0C: "CALIB",
        },
    ),
    PeripheralDef(
        name="NVIC",
        base_addr=0xE000E100,
        size=0xD00,  # ISER0 through IABR7 + priority regs
        group="interrupt",
        registers={
            0x000: "ISER0", 0x004: "ISER1", 0x008: "ISER2", 0x00C: "ISER3",
            0x080: "ICER0", 0x084: "ICER1", 0x088: "ICER2", 0x08C: "ICER3",
            0x100: "ISPR0", 0x104: "ISPR1", 0x108: "ISPR2", 0x10C: "ISPR3",
            0x180: "ICPR0", 0x184: "ICPR1", 0x188: "ICPR2", 0x18C: "ICPR3",
            0x200: "IABR0", 0x204: "IABR1", 0x208: "IABR2", 0x20C: "IABR3",
            # IP0-IP239 at 0x300+
        },
    ),
    PeripheralDef(
        name="SCB",
        base_addr=0xE000ED00,
        size=0x90,
        group="system",
        registers={
            0x00: "CPUID",
            0x04: "ICSR",
            0x08: "VTOR",
            0x0C: "AIRCR",
            0x10: "SCR",
            0x14: "CCR",
            0x18: "SHPR1",
            0x1C: "SHPR2",
            0x20: "SHPR3",
            0x24: "SHCSR",
            0x28: "CFSR",
            0x2C: "HFSR",
            0x30: "DFSR",
            0x34: "MMFAR",
            0x38: "BFAR",
            0x3C: "AFSR",
        },
    ),
    PeripheralDef(
        name="FPU",
        base_addr=0xE000EF30,
        size=16,
        group="system",
        registers={
            0x00: "FPCCR",
            0x04: "FPCAR",
            0x08: "FPDSCR",
        },
    ),
    PeripheralDef(
        name="MPU",
        base_addr=0xE000ED90,
        size=0x20,
        group="system",
        registers={
            0x00: "TYPE",
            0x04: "CTRL",
            0x08: "RNR",
            0x0C: "RBAR",
            0x10: "RASR",
        },
    ),
    PeripheralDef(
        name="CoreDebug",
        base_addr=0xE000EDF0,
        size=16,
        group="debug",
        registers={
            0x00: "DHCSR",
            0x04: "DCRSR",
            0x08: "DCRDR",
            0x0C: "DEMCR",
        },
    ),
]


# ---------------------------------------------------------------------------
# RP2040 atomic register aliases
# ---------------------------------------------------------------------------

# The RP2040 maps every peripheral register at three additional offsets
# for atomic XOR/SET/CLR access.  The alias offset is always relative to
# the peripheral's base address (not the individual register).
_ALIAS_OFFSETS: dict[int, str] = {
    0x1000: "xor",
    0x2000: "set",
    0x3000: "clr",
}


# ---------------------------------------------------------------------------
# SVD parser
# ---------------------------------------------------------------------------

class RegisterMap:
    """Lookup table: absolute address -> RegisterInfo.

    Built from SVD peripherals + Cortex-M system peripherals.
    Uses sorted peripheral ranges for fast lookup.
    """

    def __init__(
        self,
        peripherals: list[PeripheralDef],
        *,
        atomic_aliases: bool = False,
    ):
        self._atomic_aliases = atomic_aliases

        # Build sorted list of (base_addr, end_addr, PeripheralDef)
        self._ranges: list[tuple[int, int, PeripheralDef]] = []
        for p in peripherals:
            end = p.base_addr + p.size
            self._ranges.append((p.base_addr, end, p))
        self._ranges.sort(key=lambda x: x[0])

        # Also build a flat dict for exact register address lookups
        self._exact: dict[int, tuple[PeripheralDef, str]] = {}
        for p in peripherals:
            for offset, reg_name in p.registers.items():
                addr = p.base_addr + offset
                self._exact[addr] = (p, reg_name)

    def _lookup_base(self, addr: int) -> RegisterInfo | None:
        """Core lookup against base addresses only (no alias resolution)."""
        # Fast path: exact register match
        if addr in self._exact:
            p, reg_name = self._exact[addr]
            return RegisterInfo(
                peripheral=p.name,
                register=reg_name,
                group=p.group,
                base_addr=p.base_addr,
                reg_addr=addr,
            )

        # Slow path: binary search for containing peripheral range
        lo, hi = 0, len(self._ranges) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            base, end, p = self._ranges[mid]
            if addr < base:
                hi = mid - 1
            elif addr >= end:
                lo = mid + 1
            else:
                # Address is within this peripheral's range
                return RegisterInfo(
                    peripheral=p.name,
                    register="",
                    group=p.group,
                    base_addr=p.base_addr,
                    reg_addr=addr,
                )
        return None

    def lookup(self, addr: int) -> RegisterInfo | None:
        """Look up a peripheral register by absolute address.

        Returns RegisterInfo if the address falls within any peripheral's
        address block, or None if it's not a peripheral address.

        When atomic_aliases is enabled (RP2040), addresses at +0x1000/
        +0x2000/+0x3000 from a known peripheral base are resolved back
        to the base peripheral with the alias field set.
        """
        result = self._lookup_base(addr)
        if result is not None:
            return result

        if not self._atomic_aliases:
            return None

        # Try each alias offset: subtract it and see if the base address resolves
        for offset, alias_name in _ALIAS_OFFSETS.items():
            base_addr = addr - offset
            if base_addr < 0:
                continue
            base_result = self._lookup_base(base_addr)
            if base_result is not None:
                return RegisterInfo(
                    peripheral=base_result.peripheral,
                    register=base_result.register,
                    group=base_result.group,
                    base_addr=base_result.base_addr,
                    reg_addr=base_addr + (addr - base_addr),  # original alias addr
                    alias=alias_name,
                )

        return None

    @property
    def peripherals(self) -> list[PeripheralDef]:
        return [r[2] for r in self._ranges]


def _detect_rp2040(root: ET.Element) -> bool:
    """Return True if the SVD describes an RP2040 (has atomic register aliases)."""
    device_name = (root.findtext("name") or "").upper()
    vendor = (root.findtext("vendor") or "").lower()
    return "RP2040" in device_name or "raspberry pi" in vendor


def parse_svd(path: str | Path, *, atomic_aliases: bool | None = None) -> RegisterMap:
    """Parse a CMSIS-SVD file and return a RegisterMap.

    Includes Cortex-M system peripherals (SysTick, NVIC, SCB, FPU, MPU)
    automatically — these are at fixed addresses on all Cortex-M parts.

    atomic_aliases: if True, enable RP2040-style atomic XOR/SET/CLR
    alias resolution at +0x1000/+0x2000/+0x3000 from each peripheral
    base. If None (default), auto-detect from the SVD device name.
    """
    path = Path(path)
    tree = ET.parse(path)
    root = tree.getroot()

    if atomic_aliases is None:
        atomic_aliases = _detect_rp2040(root)

    # First pass: collect all peripherals, resolving derivedFrom
    peripheral_defs: dict[str, PeripheralDef] = {}
    deferred: list[ET.Element] = []  # peripherals with derivedFrom

    for p_elem in root.findall(".//peripheral"):
        derived_from = p_elem.get("derivedFrom")
        if derived_from and derived_from not in peripheral_defs:
            deferred.append(p_elem)
            continue
        pdef = _parse_peripheral_element(p_elem, peripheral_defs)
        if pdef:
            peripheral_defs[pdef.name] = pdef

    # Second pass: resolve deferred derivedFrom references
    for p_elem in deferred:
        pdef = _parse_peripheral_element(p_elem, peripheral_defs)
        if pdef:
            peripheral_defs[pdef.name] = pdef

    # Combine with Cortex-M system peripherals
    all_peripherals = list(peripheral_defs.values()) + list(_CORTEX_M_SYSTEM)
    return RegisterMap(all_peripherals, atomic_aliases=atomic_aliases)


def cortex_m_system_map() -> RegisterMap:
    """Return a RegisterMap with only Cortex-M system peripherals.

    Use this for targets without an SVD file — still classifies
    NVIC, SysTick, SCB, FPU, MPU accesses.
    """
    return RegisterMap(list(_CORTEX_M_SYSTEM))


def _parse_peripheral_element(
    elem: ET.Element,
    known: dict[str, PeripheralDef],
) -> PeripheralDef | None:
    """Parse a single <peripheral> element, optionally inheriting from derivedFrom."""
    name = elem.findtext("name")
    if not name:
        return None

    base_text = elem.findtext("baseAddress")
    if not base_text:
        return None
    base_addr = int(base_text, 0)

    # Determine address block size
    size = 0x1000  # default 4KB if not specified
    addr_block = elem.find("addressBlock")
    if addr_block is not None:
        size_text = addr_block.findtext("size")
        if size_text:
            size = int(size_text, 0)

    # Group name from SVD or auto-classify
    group_name = elem.findtext("groupName") or name
    group = classify_group(group_name)

    # Parse registers (own or inherited)
    registers: dict[int, str] = {}

    derived_from = elem.get("derivedFrom")
    if derived_from and derived_from in known:
        # Inherit registers from the parent peripheral
        parent = known[derived_from]
        registers = dict(parent.registers)
        if size == 0x1000 and parent.size != 0x1000:
            size = parent.size
        if group == "other":
            group = parent.group

    # Override/add with own registers
    for reg_elem in elem.findall(".//register"):
        reg_name = reg_elem.findtext("name")
        offset_text = reg_elem.findtext("addressOffset")
        if reg_name and offset_text:
            offset = int(offset_text, 0)
            registers[offset] = reg_name

    return PeripheralDef(
        name=name,
        base_addr=base_addr,
        size=size,
        group=group,
        registers=registers,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: parse_svd.py <svd_file> [address_hex]")
        sys.exit(1)

    reg_map = parse_svd(sys.argv[1])
    print(f"Parsed {len(reg_map.peripherals)} peripherals:")
    for p in sorted(reg_map.peripherals, key=lambda p: p.base_addr):
        print(f"  {p.name:20s} 0x{p.base_addr:08X}-0x{p.base_addr + p.size - 1:08X}  "
              f"{len(p.registers):3d} regs  [{p.group}]")

    if len(sys.argv) >= 3:
        addr = int(sys.argv[2], 0)
        info = reg_map.lookup(addr)
        if info:
            alias_suffix = f" ({info.alias.upper()} alias)" if info.alias else ""
            print(f"\n0x{addr:08X} -> {info.peripheral}.{info.register} [{info.group}]{alias_suffix}")
        else:
            print(f"\n0x{addr:08X} -> (not a peripheral address)")
