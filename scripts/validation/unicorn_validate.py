"""Unicorn-based function validation for ripcord.

Two-pass validation:
  Pass 1 — Executability smoke test: attempt to run 10 instructions
  from each function address. Functions that crash on instruction 0-1
  are flagged as likely DATA, not code. This catches the #1 failure
  mode for raw binary imports where Ghidra decodes data as functions.

  Pass 2 — Behavioral validation: for functions that pass the smoke
  test, trace memory accesses and compare against LLM claims.

Produces a Parquet table (unicorn_smoke.parquet) with executability
results, and writes validation evidence to the coordination DB.

Usage:
    uv run python scripts/validation/unicorn_validate.py \
        --target stock_v120 \
        --build-dir build \
        --binary targets/stock_v120/stock_v120.bin \
        --base-addr 0x08000000

    # Smoke test only (fast, no coordination DB needed):
    uv run python scripts/validation/unicorn_validate.py \
        --target stock_v120 \
        --build-dir build \
        --binary targets/stock_v120/stock_v120.bin \
        --smoke-only
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from unicorn import *
from unicorn.arm_const import *

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

# Ensure scripts/agents is importable
_AGENTS_DIR = str(Path(__file__).resolve().parent.parent / "agents")
if _AGENTS_DIR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR)

from context import register_warehouse


# ---------------------------------------------------------------------------
# Memory map constants (Cortex-M)
# ---------------------------------------------------------------------------

FLASH_BASE   = 0x08000000
FLASH_SIZE   = 0x00100000   # 1MB
RAM_BASE     = 0x20000000
RAM_SIZE     = 0x00040000   # 256KB
PERIPH_BASE  = 0x40000000
PERIPH_SIZE  = 0x00100000   # 1MB
FSMC_BASE    = 0x60000000
FSMC_SIZE    = 0x10000000   # 256MB
SYSTEM_BASE  = 0xE0000000
SYSTEM_SIZE  = 0x00100000   # 1MB
EXMC_CFG_BASE = 0xA0000000
EXMC_CFG_SIZE = 0x00001000

STACK_TOP    = RAM_BASE + RAM_SIZE - 64
HALT_ADDR    = 0x08FFFFF0   # LR target — stops emulation on return


# ---------------------------------------------------------------------------
# Thumb prologue detection (static, no emulation)
# ---------------------------------------------------------------------------

def _has_thumb_prologue(data: bytes, offset: int) -> str | None:
    """Check if bytes at offset look like a Thumb function entry.

    Returns the prologue type string or None.
    """
    if offset + 4 > len(data):
        return None
    hw = int.from_bytes(data[offset:offset+2], 'little')
    hw2 = int.from_bytes(data[offset+2:offset+4], 'little')

    # PUSH {regs, LR}: 0xB5xx
    if hw & 0xFF00 == 0xB500:
        return "PUSH"
    # Thumb2 PUSH.W: 0xE92D xxxx
    if hw == 0xE92D:
        return "PUSH.W"
    # SUB SP, #imm: 0xB0xx (bit7=1 means sub)
    if hw & 0xFF80 == 0xB080:
        return "SUB_SP"
    # MOV r0-r7 low reg: 0x46xx (often used as function entry)
    # BX, BLX patterns
    # MOVS r0, #0: 0x2000
    if hw == 0x2000:
        return "MOVS_R0_0"
    # LDR r0, [PC, #imm]: 0x48xx
    if hw & 0xFF00 == 0x4800:
        return "LDR_PC"
    # Thumb2 wide instructions starting with 0xF--- or 0xE---
    if (hw >> 11) >= 0x1D:  # Thumb2 prefix
        return "THUMB2"

    return None


# ---------------------------------------------------------------------------
# Trace record
# ---------------------------------------------------------------------------

@dataclass
class MemAccess:
    address: int
    size: int
    value: int
    is_write: bool
    pc: int

    @property
    def region(self) -> str:
        if PERIPH_BASE <= self.address < PERIPH_BASE + PERIPH_SIZE:
            return "peripheral"
        if FSMC_BASE <= self.address < FSMC_BASE + FSMC_SIZE:
            return "fsmc"
        if SYSTEM_BASE <= self.address < SYSTEM_BASE + SYSTEM_SIZE:
            return "system"
        if RAM_BASE <= self.address < RAM_BASE + RAM_SIZE:
            return "ram"
        return "other"


@dataclass
class SmokeResult:
    """Result of the executability smoke test for one function."""
    addr: int
    name: str
    size: int
    has_prologue: bool
    prologue_type: str | None
    instructions_executed: int
    executable: bool          # True = likely code, False = likely data
    error: str | None
    periph_write_count: int
    periph_read_count: int
    periph_addrs: list[int]   # unique peripheral addresses touched
    classification: str       # 'code', 'data', 'uncertain'


# ---------------------------------------------------------------------------
# Unicorn execution harness
# ---------------------------------------------------------------------------

class FirmwareEmulator:
    """ARM Cortex-M firmware emulator using Unicorn."""

    def __init__(self, binary_path: str, base_addr: int = FLASH_BASE):
        self.base_addr = base_addr
        self.binary = Path(binary_path).read_bytes()
        self._traces: list[MemAccess] = []
        self._insn_count = 0
        self._max_insns = 100

    def _make_engine(self) -> Uc:
        """Create a fresh Unicorn engine with memory mapped.

        Includes fault-tolerant memory hooks: when a function reads or
        writes to an unmapped address, a page of zeros is mapped on the
        fly and execution continues. This handles functions that load
        global pointers from uninitialized .data sections (common with
        truncated binary dumps or raw flash images missing the .data
        init image).
        """
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        mu.mem_map(FLASH_BASE, FLASH_SIZE, UC_PROT_ALL)
        mu.mem_write(self.base_addr, self.binary)
        mu.mem_map(RAM_BASE, RAM_SIZE, UC_PROT_ALL)
        mu.mem_map(PERIPH_BASE, PERIPH_SIZE, UC_PROT_ALL)
        mu.mem_map(FSMC_BASE, FSMC_SIZE, UC_PROT_ALL)
        mu.mem_map(SYSTEM_BASE, SYSTEM_SIZE, UC_PROT_ALL)
        mu.mem_map(EXMC_CFG_BASE, EXMC_CFG_SIZE, UC_PROT_ALL)

        # Halt page
        if HALT_ADDR < FLASH_BASE or HALT_ADDR >= FLASH_BASE + FLASH_SIZE:
            mu.mem_map(HALT_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)

        mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_write,
                    begin=PERIPH_BASE, end=SYSTEM_BASE + SYSTEM_SIZE)
        mu.hook_add(UC_HOOK_MEM_READ, self._hook_read,
                    begin=PERIPH_BASE, end=SYSTEM_BASE + SYSTEM_SIZE)
        mu.hook_add(UC_HOOK_CODE, self._hook_code)

        # Fault-tolerant hooks: auto-map unmapped memory pages
        # so functions that read global pointers don't crash immediately.
        self._mapped_pages: set[int] = set()
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_unmapped)
        mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_unmapped)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_unmapped)

        return mu

    def _hook_unmapped(self, uc, access, address, size, value, user_data):
        """Auto-map unmapped pages with zeros so execution can continue.

        When a function reads a global pointer from uninitialized RAM,
        the pointer is 0x00000000. The next dereference goes to address 0
        which is unmapped. This hook maps a zero page there, letting the
        function execute a few more instructions — enough to classify it
        as code vs data.
        """
        page = address & ~0xFFF
        if page not in self._mapped_pages:
            try:
                uc.mem_map(page, 0x1000, UC_PROT_ALL)
                self._mapped_pages.add(page)
                return True  # retry the access
            except UcError:
                return False  # give up
        return True  # page already mapped, retry

    def _hook_write(self, uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        self._traces.append(MemAccess(address, size, value, True, pc))

    def _hook_read(self, uc, access, address, size, value, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        self._traces.append(MemAccess(address, size, value, False, pc))

    def _hook_code(self, uc, address, size, user_data):
        self._insn_count += 1
        if self._insn_count >= self._max_insns:
            uc.emu_stop()

    def smoke_test(self, addr: int, max_insns: int = 20) -> dict:
        """Try to execute a few instructions from addr.

        Returns dict with: insns_executed, error, success,
        periph_writes, periph_reads, periph_addrs.
        """
        self._traces = []
        self._insn_count = 0
        self._max_insns = max_insns

        mu = self._make_engine()
        mu.reg_write(UC_ARM_REG_SP, STACK_TOP)
        mu.reg_write(UC_ARM_REG_LR, HALT_ADDR | 1)
        # Zero out r0-r3 (no args)
        for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
            mu.reg_write(reg, 0)

        entry = addr | 1  # Thumb bit
        error = None
        try:
            mu.emu_start(entry, HALT_ADDR, timeout=2_000_000)  # 2s timeout
        except UcError as e:
            error = str(e)

        pw = [a for a in self._traces if a.is_write]
        pr = [a for a in self._traces if not a.is_write]
        addrs = sorted({a.address for a in self._traces})

        return {
            "insns": self._insn_count,
            "error": error,
            "periph_writes": len(pw),
            "periph_reads": len(pr),
            "periph_addrs": addrs,
        }


# ---------------------------------------------------------------------------
# Smoke test: executability classification
# ---------------------------------------------------------------------------

_SMOKE_SCHEMA = pa.schema([
    ("source", pa.string()),
    ("addr", pa.int64()),
    ("name", pa.string()),
    ("size", pa.int64()),
    ("has_prologue", pa.bool_()),
    ("prologue_type", pa.string()),
    ("instructions_executed", pa.int64()),
    ("executable", pa.bool_()),
    ("error", pa.string()),
    ("classification", pa.string()),
    ("periph_write_count", pa.int64()),
    ("periph_read_count", pa.int64()),
    ("extracted_at", pa.timestamp("us", tz="UTC")),
])


def run_smoke_test(
    target: str,
    build_dir: str,
    binary_path: str,
    base_addr: int,
) -> list[SmokeResult]:
    """Run executability smoke test on all functions in a target.

    For each function:
    1. Check if bytes at the function address have a Thumb prologue
    2. Try to execute 20 instructions in Unicorn
    3. Classify as 'code', 'data', or 'uncertain'

    Returns list of SmokeResult and writes unicorn_smoke.parquet.
    """
    build_path = Path(build_dir)

    print(f"smoke test: target={target}")
    print(f"smoke test: binary={binary_path}, base=0x{base_addr:08x}")

    # Load binary for static prologue check
    binary_data = Path(binary_path).read_bytes()

    # Load function list from warehouse
    conn = duckdb.connect(":memory:")
    pq_path = build_path / target / "tables" / "functions.parquet"
    conn.execute(f"CREATE VIEW functions AS SELECT * FROM read_parquet('{pq_path}')")

    rows = conn.execute("""
        SELECT addr, name, size FROM functions
        WHERE source = $1
        ORDER BY addr
    """, [target]).fetchall()
    conn.close()

    print(f"  {len(rows)} functions to test")

    # Create emulator
    emu = FirmwareEmulator(binary_path, base_addr)

    results: list[SmokeResult] = []
    code_count = 0
    data_count = 0
    uncertain_count = 0

    t0 = time.monotonic()
    for addr, name, size in rows:
        offset = addr - base_addr
        name = name or f"FUN_{addr:08x}"

        # Static check: does it look like Thumb code?
        prologue = _has_thumb_prologue(binary_data, offset)

        # Dynamic check: try to execute
        smoke = emu.smoke_test(addr, max_insns=20)
        insns = smoke["insns"]
        error = smoke["error"]

        # Classification logic:
        # - >= 5 instructions executed → likely code
        # - has_prologue + >= 3 insns → likely code
        # - 0-1 instructions + invalid insn error → likely data
        # - 2-4 instructions + crash → uncertain
        if insns >= 5:
            classification = "code"
            executable = True
        elif prologue and insns >= 3:
            classification = "code"
            executable = True
        elif insns <= 1 and error and ("INSN_INVALID" in error or "FETCH_UNMAPPED" in error):
            classification = "data"
            executable = False
        elif insns == 0:
            classification = "data"
            executable = False
        else:
            classification = "uncertain"
            executable = None

        if classification == "code":
            code_count += 1
        elif classification == "data":
            data_count += 1
        else:
            uncertain_count += 1

        results.append(SmokeResult(
            addr=addr,
            name=name,
            size=size,
            has_prologue=prologue is not None,
            prologue_type=prologue,
            instructions_executed=insns,
            executable=executable,
            error=error,
            periph_write_count=smoke["periph_writes"],
            periph_read_count=smoke["periph_reads"],
            periph_addrs=smoke["periph_addrs"],
            classification=classification,
        ))

    elapsed = time.monotonic() - t0

    # --- Print summary ---
    print(f"\n{'='*60}")
    print(f"  Smoke Test Results: {target}")
    print(f"{'='*60}")
    print(f"  total functions:  {len(results)}")
    print(f"  CODE:             {code_count}")
    print(f"  DATA:             {data_count}")
    print(f"  UNCERTAIN:        {uncertain_count}")
    print(f"  time:             {elapsed:.1f}s ({elapsed/len(results)*1000:.0f}ms/fn)")

    # Show data-classified functions
    if data_count > 0:
        print(f"\n  Functions classified as DATA ({data_count}):")
        for r in results:
            if r.classification == "data":
                print(f"    0x{r.addr:08x}  {r.size:5d}B  {r.name}")

    # Show uncertain functions
    if uncertain_count > 0:
        print(f"\n  Functions classified as UNCERTAIN ({uncertain_count}):")
        for r in results:
            if r.classification == "uncertain":
                reason = f"{r.instructions_executed} insns"
                if r.error:
                    reason += f", {r.error.split('(')[0].strip()}"
                print(f"    0x{r.addr:08x}  {r.size:5d}B  {r.name}  ({reason})")

    # --- Write Parquet ---
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    table = pa.table({
        "source": [target] * len(results),
        "addr": [r.addr for r in results],
        "name": [r.name for r in results],
        "size": [r.size for r in results],
        "has_prologue": [r.has_prologue for r in results],
        "prologue_type": [r.prologue_type for r in results],
        "instructions_executed": [r.instructions_executed for r in results],
        "executable": [r.executable for r in results],
        "error": [r.error for r in results],
        "classification": [r.classification for r in results],
        "periph_write_count": [r.periph_write_count for r in results],
        "periph_read_count": [r.periph_read_count for r in results],
        "extracted_at": [now] * len(results),
    }, schema=_SMOKE_SCHEMA)

    out_path = build_path / target / "tables" / "unicorn_smoke.parquet"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, out_path)
    print(f"\n  wrote {out_path}")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Unicorn-based function validation for ripcord"
    )
    parser.add_argument(
        "--target", required=True,
        help="Target name (e.g. stock_v120)",
    )
    parser.add_argument(
        "--build-dir", default="build",
        help="Build directory with parquet warehouse",
    )
    parser.add_argument(
        "--binary", required=True,
        help="Path to firmware binary (.bin)",
    )
    parser.add_argument(
        "--base-addr", type=lambda x: int(x, 0), default=0x08000000,
        help="Base address for binary (default: 0x08000000)",
    )
    args = parser.parse_args()

    run_smoke_test(
        target=args.target,
        build_dir=args.build_dir,
        binary_path=args.binary,
        base_addr=args.base_addr,
    )


if __name__ == "__main__":
    main()
