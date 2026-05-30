#!/usr/bin/env python3
"""Parse a Renode execution trace and emit MMIO events as JSONL.

Reads the text-format execution trace produced by Renode's
PCAndOpcode tracer with TrackMemoryAccesses enabled. Extracts
MemoryIORead and MemoryIOWrite events, pairing each with the
most recent PC (instruction address) that caused it.

Trace format (one event per line):
    0x5A4: 0x480A                                   ← instruction at PC
    MemoryRead with address 0x5D0, value 0x20001000  ← RAM read (ignored)
    MemoryIOWrite with address 0x4000C000, value 0x48 ← MMIO write (captured)

Output JSONL record per MMIO event:
    {"sequence_idx": 0, "pc": 1444, "address": 1073741824,
     "value": 72, "direction": "write", "scenario": "boot",
     "peripheral": "uart0"}

Usage:
    python parse_trace.py --trace build/renode_exec_trace.log \\
        --scenario boot --output build/zephyr_hello_world/mmio_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# Peripheral address ranges per platform, mapping ranges to human-readable
# names. Selected by --platform (default: lm3s6965, the Zephyr target).
PERIPHERAL_MAPS = {
    # TI Stellaris LM3S6965 / Cortex-M3 (Zephyr qemu_cortex_m3).
    "lm3s6965": [
        (0x4000C000, 0x4000CFFF, "uart0"),
        (0x4000D000, 0x4000DFFF, "uart1"),
        (0x4001C000, 0x4001CFFF, "uart2"),
        (0x4000E000, 0x4000EFFF, "gpio"),
        (0x400FE000, 0x400FEFFF, "sysctl"),
        (0xE000E000, 0xE000EFFF, "nvic"),
    ],
    # ArteryTek AT32F403A / Cortex-M4F (FNIRSI 2C53T, STM32F1-compatible
    # map). FPGA-facing peripherals (spi3, usart2, dma1/2, gpiob/c) are the
    # interesting ones; see notes/renode-at32-bringup.md.
    "at32f403a": [
        (0x40003C00, 0x40003FFF, "spi3"),      # MCU<->FPGA data/command
        (0x40004400, 0x400047FF, "usart2"),    # MCU<->FPGA command channel
        (0x40010000, 0x400103FF, "afio"),
        (0x40010800, 0x40010BFF, "gpioa"),
        (0x40010C00, 0x40010FFF, "gpiob"),     # PB6 (CS), PB11 (gate)
        (0x40011000, 0x400113FF, "gpioc"),     # PC6 (enable)
        (0x40011400, 0x400117FF, "gpiod"),
        (0x40011800, 0x40011BFF, "gpioe"),
        (0x40012400, 0x400127FF, "adc1"),
        (0x40012800, 0x40012BFF, "adc2"),
        (0x40013000, 0x400133FF, "spi1"),
        (0x40013800, 0x40013BFF, "usart1"),
        (0x40020000, 0x400203FF, "dma1"),      # sample transfer
        (0x40020400, 0x400207FF, "dma2"),
        (0x40021000, 0x400213FF, "rcc"),
        (0x40022000, 0x400223FF, "flash"),
        (0xE000E000, 0xE000EFFF, "nvic"),      # incl. SysTick
    ],
}

# Regex patterns for the two line types we care about.
# Instruction line: "0xABC: 0xOPCODE"
RE_INSTRUCTION = re.compile(r"^(0x[0-9A-Fa-f]+):\s+0x[0-9A-Fa-f]+$")
# MMIO line: "MemoryIORead with address 0xADDR, value 0xVAL"
#        or: "MemoryIOWrite with address 0xADDR, value 0xVAL"
RE_MMIO = re.compile(
    r"^MemoryIO(Read|Write) with address (0x[0-9A-Fa-f]+), value (0x[0-9A-Fa-f]+)$"
)


def classify_peripheral(addr: int, peripheral_map) -> str | None:
    """Return peripheral name for an MMIO address, or None."""
    for lo, hi, name in peripheral_map:
        if lo <= addr <= hi:
            return name
    return None


def parse_trace(trace_path: Path, scenario: str, peripheral_map):
    """Yield MMIO event dicts from a Renode execution trace file."""
    current_pc: int | None = None
    sequence_idx = 0

    with trace_path.open() as fh:
        for line in fh:
            line = line.rstrip("\n")

            # Try instruction line first (most common line type).
            m = RE_INSTRUCTION.match(line)
            if m:
                current_pc = int(m.group(1), 16)
                continue

            # Try MMIO event line.
            m = RE_MMIO.match(line)
            if m:
                direction = "read" if m.group(1) == "Read" else "write"
                address = int(m.group(2), 16)
                value = int(m.group(3), 16)
                yield {
                    "sequence_idx": sequence_idx,
                    "pc": current_pc,
                    "address": address,
                    "value": value,
                    "direction": direction,
                    "scenario": scenario,
                    "peripheral": classify_peripheral(address, peripheral_map),
                }
                sequence_idx += 1
                continue

            # All other lines (MemoryRead, MemoryWrite, blank) are ignored.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trace", required=True, type=Path, help="Renode execution trace log"
    )
    parser.add_argument(
        "--scenario",
        required=True,
        help="scenario name stamped into every record (e.g. 'boot')",
    )
    parser.add_argument(
        "--platform",
        default="lm3s6965",
        choices=sorted(PERIPHERAL_MAPS),
        help="peripheral address map to classify against (default: lm3s6965)",
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="output JSONL file"
    )
    args = parser.parse_args()

    if not args.trace.exists():
        print(f"error: {args.trace} does not exist", file=sys.stderr)
        return 1

    peripheral_map = PERIPHERAL_MAPS[args.platform]
    args.output.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with args.output.open("w") as out:
        for event in parse_trace(args.trace, args.scenario, peripheral_map):
            out.write(json.dumps(event) + "\n")
            count += 1

    print(f"parsed {count} MMIO events from {args.trace} -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
