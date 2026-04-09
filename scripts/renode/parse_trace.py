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


# Peripheral address ranges for the LM3S6965 / Cortex-M3 platform.
# These map address ranges to human-readable peripheral names.
PERIPHERAL_MAP = [
    (0x4000C000, 0x4000CFFF, "uart0"),
    (0x4000D000, 0x4000DFFF, "uart1"),
    (0x4001C000, 0x4001CFFF, "uart2"),
    (0x4000E000, 0x4000EFFF, "gpio"),
    (0x400FE000, 0x400FEFFF, "sysctl"),
    (0xE000E000, 0xE000EFFF, "nvic"),
]

# Regex patterns for the two line types we care about.
# Instruction line: "0xABC: 0xOPCODE"
RE_INSTRUCTION = re.compile(r"^(0x[0-9A-Fa-f]+):\s+0x[0-9A-Fa-f]+$")
# MMIO line: "MemoryIORead with address 0xADDR, value 0xVAL"
#        or: "MemoryIOWrite with address 0xADDR, value 0xVAL"
RE_MMIO = re.compile(
    r"^MemoryIO(Read|Write) with address (0x[0-9A-Fa-f]+), value (0x[0-9A-Fa-f]+)$"
)


def classify_peripheral(addr: int) -> str | None:
    """Return peripheral name for an MMIO address, or None."""
    for lo, hi, name in PERIPHERAL_MAP:
        if lo <= addr <= hi:
            return name
    return None


def parse_trace(trace_path: Path, scenario: str):
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
                    "peripheral": classify_peripheral(address),
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
        "--output", required=True, type=Path, help="output JSONL file"
    )
    args = parser.parse_args()

    if not args.trace.exists():
        print(f"error: {args.trace} does not exist", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with args.output.open("w") as out:
        for event in parse_trace(args.trace, args.scenario):
            out.write(json.dumps(event) + "\n")
            count += 1

    print(f"parsed {count} MMIO events from {args.trace} -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
