#!/usr/bin/env -S uv run python
"""Execution-verification harness for behavioral contracts.

A *contract* is a falsifiable claim about a region of the real firmware
binary — what it does to registers/memory/MMIO as a function of its
inputs. This module is the deterministic oracle that decides whether a
contract is true: it runs the actual function bytes in Unicorn with a
synthetic context and checks a postcondition. The emulator is the
compiler/test-harness equivalent; the contract's `spec` is the test.

This is the verification half of the ratchet described in
notes/renode-at32-bringup.md / the contract ledger (ledger.py): a claim
does not enter the database as "truth" (execution-verified) until it has
been *run*, not just read.

Memory map and Thumb conventions mirror scripts/validation/unicorn_validate.py.

Verification kinds (spec["kind"]):
  - "memory_fill": run f(ptr, len); assert [ptr..ptr+len) == fill_value
    with no over/underrun. The memset/region-clear contract.

Add new kinds here as new contract shapes need an oracle.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from unicorn import *
from unicorn.arm_const import *

REPO = Path(__file__).resolve().parent.parent.parent

# --- Cortex-M memory map (AT32F403A), matching unicorn_validate.py ----------
FLASH_BASE, FLASH_SIZE = 0x08000000, 0x00100000
RAM_BASE,   RAM_SIZE   = 0x20000000, 0x00040000
PERIPH_BASE, PERIPH_SIZE = 0x40000000, 0x00100000
FSMC_BASE,  FSMC_SIZE  = 0x60000000, 0x10000000
SYSTEM_BASE, SYSTEM_SIZE = 0xE0000000, 0x00100000
EXMC_CFG_BASE, EXMC_CFG_SIZE = 0xA0000000, 0x00001000
HALT_ADDR = 0x08FFFFF0          # LR sentinel — emu stops when PC reaches it

_REG = {f"r{i}": globals()[f"UC_ARM_REG_R{i}"] for i in range(13)}
_REG.update(sp=UC_ARM_REG_SP, lr=UC_ARM_REG_LR, pc=UC_ARM_REG_PC,
            ip=UC_ARM_REG_R12, fp=UC_ARM_REG_R11)


def load_target(source: str):
    cfg = yaml.safe_load((REPO / "config.yaml").read_text())
    t = cfg["targets"][source]
    binary = REPO / t["elf"]
    base = int(t.get("base_addr", FLASH_BASE))
    return binary.read_bytes(), base


class FunctionRunner:
    """Run a single firmware function in isolation with a synthetic context."""

    def __init__(self, binary: bytes, base_addr: int):
        self.binary = binary
        self.base_addr = base_addr

    def _engine(self) -> Uc:
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(FLASH_BASE, FLASH_SIZE, UC_PROT_ALL)
        mu.mem_write(self.base_addr, self.binary)
        mu.mem_map(RAM_BASE, RAM_SIZE, UC_PROT_ALL)
        mu.mem_map(PERIPH_BASE, PERIPH_SIZE, UC_PROT_ALL)
        mu.mem_map(FSMC_BASE, FSMC_SIZE, UC_PROT_ALL)
        mu.mem_map(SYSTEM_BASE, SYSTEM_SIZE, UC_PROT_ALL)
        mu.mem_map(EXMC_CFG_BASE, EXMC_CFG_SIZE, UC_PROT_ALL)
        mu.mem_map(HALT_ADDR & ~0xFFF, 0x1000, UC_PROT_ALL)
        return mu

    def run(self, entry: int, regs: dict | None = None,
            mem: dict | None = None, max_insns: int = 200_000,
            watch: tuple | None = None):
        """Execute from `entry` until the function returns (LR sentinel).

        regs: {name: value} initial registers.  mem: {addr: bytes} prewrites.
        watch: (lo, hi) — if set, every memory write into [lo,hi) is recorded
            in self.last_writes as (addr, size, value).  Used to capture an
            MMIO command/data stream (e.g. FSMC LCD writes) for a postcondition.
        Returns (mu, error) — read results via mu.mem_read / mu.reg_read.
        """
        mu = self._engine()
        mu.reg_write(UC_ARM_REG_SP, RAM_BASE + RAM_SIZE - 0x100)
        mu.reg_write(UC_ARM_REG_LR, HALT_ADDR | 1)
        for name, val in (regs or {}).items():
            mu.reg_write(_REG[name.lower()], val & 0xFFFFFFFF)
        for addr, data in (mem or {}).items():
            mu.mem_write(addr, bytes(data))
        self.last_writes = []
        if watch is not None:
            lo, hi = watch

            def _on_write(uc, access, address, size, value, ud):
                if lo <= address < hi:
                    self.last_writes.append(
                        (address, size, value & ((1 << (size * 8)) - 1)))

            mu.hook_add(UC_HOOK_MEM_WRITE, _on_write)
        err = None
        try:
            mu.emu_start(entry | 1, HALT_ADDR, count=max_insns)
        except UcError as e:
            err = str(e)
        return mu, err


# ---------------------------------------------------------------------------
# Verification kinds
# ---------------------------------------------------------------------------

def _verify_memory_fill(runner: FunctionRunner, spec: dict) -> dict:
    """f(ptr, len) clears [ptr..ptr+len) to fill_value, no over/underrun.

    Exercises the alignment branches by testing several lengths and an
    unaligned pointer.  Guard bytes around the buffer detect spill.
    """
    entry = int(spec["entry"])
    fill = spec.get("fill_value", 0) & 0xFF
    ptr_reg = spec.get("ptr_reg", "r0")
    len_reg = spec.get("len_reg", "r1")
    lengths = spec.get("lengths", [1, 3, 4, 7, 16, 100, 256])
    scratch = spec.get("scratch", 0x20020000)
    guard = 0xAA if fill != 0xAA else 0x55
    GUARD = 16

    cases, ok = [], True
    for length in lengths:
        for off in (0, 1):                       # aligned + unaligned ptr
            ptr = scratch + GUARD + off
            region = bytes([guard]) * (GUARD + off + length + GUARD)
            runner_mem = {scratch: region}
            mu, err = runner.run(entry,
                                 regs={ptr_reg: ptr, len_reg: length},
                                 mem=runner_mem)
            body = mu.mem_read(ptr, length)
            pre = mu.mem_read(ptr - GUARD, GUARD)
            post = mu.mem_read(ptr + length, GUARD)
            filled = all(b == fill for b in body)
            no_under = all(b == guard for b in pre)
            no_over = all(b == guard for b in post)
            passed = err is None and filled and no_under and no_over
            ok = ok and passed
            cases.append({
                "len": length, "ptr_off": off, "pass": passed,
                "filled": filled, "no_underrun": no_under,
                "no_overrun": no_over, "error": err,
            })
    fails = [c for c in cases if not c["pass"]]
    return {
        "verified": ok,
        "n_cases": len(cases),
        "n_pass": len(cases) - len(fails),
        "summary": ("all %d cases zero exactly [ptr..ptr+len), no spill"
                    % len(cases)) if ok
                   else "%d/%d cases FAILED: %s" % (len(fails), len(cases),
                                                    fails[:3]),
        "cases": cases,
    }


def _verify_lcd_command(runner: FunctionRunner, spec: dict) -> dict:
    """Run the function; assert it drives the FSMC LCD command port with the
    expected ILI9341/ST7789 opcode(s).

    The panel hangs off FSMC NE1 with A16 = the RS (register-select) line:
    writes with A16=0 (addr & 0x20000 == 0) are command/index writes; A16=1 are
    pixel/parameter data.  The contract is falsified unless every opcode in
    `expect_commands` actually appears on the command port at run time — proving
    by execution (not by reading) that this window speaks the LCD protocol.
    """
    entry = int(spec["entry"])
    expect = [c & 0xFF for c in spec.get("expect_commands", [])]
    regs = spec.get("regs")
    mem = {int(k): bytes(v) for k, v in spec.get("mem", {}).items()} or None
    rs_bit = int(spec.get("rs_bit", 0x20000))

    mu, err = runner.run(entry, regs=regs, mem=mem,
                         watch=(FSMC_BASE, FSMC_BASE + FSMC_SIZE))
    writes = runner.last_writes
    cmds = [v & 0xFF for (a, s, v) in writes if (a & rs_bit) == 0]
    data = [(a, v) for (a, s, v) in writes if (a & rs_bit) != 0]
    missing = [c for c in expect if c not in cmds]
    ok = err is None and bool(expect) and not missing
    return {
        "verified": ok,
        "commands": [hex(c) for c in cmds],
        "n_data_writes": len(data),
        "summary": (
            "no FSMC writes; LCD claim unsupported" if not writes else
            "cmd-port opcodes %s; expected %s; missing %s; %d data writes%s"
            % ([hex(c) for c in cmds], [hex(c) for c in expect],
               [hex(c) for c in missing], len(data),
               "" if err is None else f"; ERROR {err}")),
    }


def _verify_mmio_write(runner: FunctionRunner, spec: dict) -> dict:
    """Run the function; assert it writes given value(s) to given MMIO reg(s).

    spec["expect"] is a list of [addr, value] pairs. Each must appear among the
    function's writes into the watched window (default: the peripheral block).
    Proves by execution that a routine programs a specific register — e.g. that
    the DMA1-Ch2 blit sets CMAR = the LCD data port.
    """
    entry = int(spec["entry"])
    regs = spec.get("regs")
    mem = {int(k): bytes(v) for k, v in spec.get("mem", {}).items()} or None
    lo = int(spec.get("watch_lo", PERIPH_BASE))
    hi = int(spec.get("watch_hi", PERIPH_BASE + PERIPH_SIZE))
    expect = [(int(a), int(v)) for a, v in spec.get("expect", [])]

    mu, err = runner.run(entry, regs=regs, mem=mem, watch=(lo, hi))
    seen = {(a, v) for (a, s, v) in runner.last_writes}
    seen_addrs = {a: v for (a, s, v) in runner.last_writes}
    missing = [(a, v) for (a, v) in expect
               if (a, v) not in seen and seen_addrs.get(a) != v]
    ok = err is None and bool(expect) and not missing
    return {
        "verified": ok,
        "summary": (
            "no MMIO writes in window" if not runner.last_writes else
            "%d/%d expected reg writes present%s%s"
            % (len(expect) - len(missing), len(expect),
               "" if not missing else "; MISSING " +
               ", ".join(f"0x{a:08X}=0x{v:X}" for a, v in missing),
               "" if err is None else f"; ERROR {err}")),
        "writes": [f"0x{a:08X}=0x{v:X}" for (a, s, v) in runner.last_writes],
    }


_KINDS = {"memory_fill": _verify_memory_fill,
          "lcd_command": _verify_lcd_command,
          "mmio_write": _verify_mmio_write}


def verify_spec(source: str, spec: dict) -> dict:
    """Run the verification described by `spec` against `source`'s binary."""
    kind = spec.get("kind")
    if kind not in _KINDS:
        return {"verified": None,
                "summary": "no execution oracle for kind=%r (decode-only)" % kind}
    binary, base = load_target(source)
    runner = FunctionRunner(binary, base)
    return _KINDS[kind](runner, spec)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True)
    ap.add_argument("--spec", required=True, help="JSON verification spec (string or @file)")
    args = ap.parse_args()
    spec = json.loads(Path(args.spec[1:]).read_text() if args.spec.startswith("@")
                      else args.spec)
    result = verify_spec(args.source, spec)
    print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2))
    print("VERIFIED" if result.get("verified") else
          ("UNCHECKED" if result.get("verified") is None else "REFUTED"))
    return 0 if result.get("verified") is not False else 1


if __name__ == "__main__":
    sys.exit(main())
