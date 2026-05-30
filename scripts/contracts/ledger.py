#!/usr/bin/env -S uv run python
"""Contract ledger — the durable home for verified understanding.

The warehouse (Parquet) holds facts Ghidra *extracted*. This ledger holds
facts we *derived* — what a region of the firmware means — as falsifiable
contracts with provenance and confidence, so each analysis "bite" becomes
queryable truth for the next bite instead of evaporating into prose.

Why SQLite, not Parquet: contracts are mutable. A claim gets verified
(static→execution), or it gets *refuted* and superseded by a corrected
claim. The ledger records that history (a `supersedes` link), so a wrong
turn is a row with a pointer, not a silent edit. This is the structured
form of the blackboard/evidence-log in notes/agent-task-schema.md.

A contract enters as decode-derived (read, not run). Running its `spec`
through verify.py against the real binary is what promotes it to
`provenance='execution-verified'`. That promotion gate is the whole point.

Usage:
    scripts/contracts/ledger.py init
    scripts/contracts/ledger.py backfill          # this session's findings
    scripts/contracts/ledger.py verify <id>       # run the oracle, update row
    scripts/contracts/ledger.py list [--source stock_v120]
    scripts/contracts/ledger.py show <id>
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DB_PATH = REPO / "build" / "contracts.sqlite"

# Provenance levels, weakest→strongest (mirrors confidence-scheme.md intent).
PROVENANCE = ("hypothesis", "synthesized-model", "decompile-derived",
              "direct-xref", "execution-verified")

SCHEMA = """
CREATE TABLE IF NOT EXISTS contracts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    addr_start  INTEGER,
    addr_end    INTEGER,
    name        TEXT,
    kind        TEXT NOT NULL,        -- memory_effect|peripheral_id|isr_role|dataflow|structure
    claim       TEXT NOT NULL,        -- falsifiable, human-readable
    spec        TEXT,                 -- JSON: machine-checkable verification (or null = decode-only)
    provenance  TEXT NOT NULL,
    confidence  REAL NOT NULL,
    verified    INTEGER,              -- 1 verified, 0 refuted, NULL unchecked
    evidence    TEXT,
    supersedes  INTEGER REFERENCES contracts(id),
    created_at  TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add(con, *, source, kind, claim, name=None, addr_start=None, addr_end=None,
        spec=None, provenance="decompile-derived", confidence=0.7,
        verified=None, evidence=None, supersedes=None) -> int:
    assert provenance in PROVENANCE, provenance
    cur = con.execute(
        """INSERT INTO contracts (source, addr_start, addr_end, name, kind, claim,
              spec, provenance, confidence, verified, evidence, supersedes, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (source, addr_start, addr_end, name, kind, claim,
         json.dumps(spec) if spec else None, provenance, confidence,
         verified, evidence, supersedes, _now()))
    con.commit()
    return cur.lastrowid


def verify(con, cid: int) -> dict:
    """Run the contract's spec through the execution oracle; update the row."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import verify as oracle

    row = con.execute("SELECT * FROM contracts WHERE id=?", (cid,)).fetchone()
    if row is None:
        sys.exit(f"no contract id={cid}")
    if not row["spec"]:
        sys.exit(f"contract {cid} has no machine-checkable spec (decode-only)")
    spec = json.loads(row["spec"])
    result = oracle.verify_spec(row["source"], spec)
    v = result.get("verified")
    if v is True:
        prov, conf = "execution-verified", 1.0
    elif v is False:
        prov, conf = row["provenance"], min(row["confidence"], 0.2)
    else:
        prov, conf = row["provenance"], row["confidence"]
    con.execute(
        "UPDATE contracts SET verified=?, provenance=?, confidence=?, evidence=? WHERE id=?",
        (None if v is None else int(v), prov, conf, result.get("summary"), cid))
    con.commit()
    return result


def _fmt_addr(a):
    return "—" if a is None else f"0x{a:08X}"


def cmd_list(con, source=None):
    q = "SELECT * FROM contracts"
    args = []
    if source:
        q += " WHERE source=?"
        args.append(source)
    q += " ORDER BY id"
    rows = con.execute(q, args).fetchall()
    mark = {1: "✓", 0: "✗", None: "·"}
    print(f"{'id':>3}  {'ver':3} {'prov':18} {'conf':>4}  {'kind':14} {'addr':>10}  name / claim")
    print("-" * 100)
    for r in rows:
        sup = f"  (supersedes #{r['supersedes']})" if r["supersedes"] else ""
        print(f"{r['id']:>3}  {mark[r['verified']]:^3} {r['provenance']:18} "
              f"{r['confidence']:>4.2f}  {r['kind']:14} {_fmt_addr(r['addr_start']):>10}  "
              f"{(r['name'] or ''):<22}{sup}")
        print(f"          {r['claim'][:96]}")


def cmd_show(con, cid):
    r = con.execute("SELECT * FROM contracts WHERE id=?", (cid,)).fetchone()
    if not r:
        sys.exit(f"no contract id={cid}")
    for k in r.keys():
        print(f"  {k:12} {r[k]}")


# ---------------------------------------------------------------------------
# Backfill: this session's findings, as contracts with honest provenance.
# Corrections are recorded as refuted rows superseded by the corrected claim.
# ---------------------------------------------------------------------------

def backfill(con):
    S = "stock_v120"
    ids = {}

    ids["memset"] = add(con, source=S, kind="memory_effect", name="memset",
        addr_start=0x080052BC, addr_end=0x08005300,
        claim="FUN_080052bc(ptr,len) zero-fills [ptr..ptr+len); the ISR/buffer-manager "
              "block-clear primitive (callers ignore the return).",
        spec={"kind": "memory_fill", "entry": 0x080052BC, "fill_value": 0,
              "ptr_reg": "r0", "len_reg": "r1",
              "lengths": [1, 3, 4, 7, 16, 100, 256, 1024]},
        provenance="decompile-derived", confidence=0.7)

    add(con, source=S, kind="peripheral_id", name="spi3_fpga_control",
        addr_start=0x40003C00,
        claim="SPI3 @0x40003C00 is the FPGA control/cal channel only: 05/12/15 handshake "
              "(fire-and-forget — every DT read discarded) + 115638-byte cal upload (3B..3A). "
              "No SPI3 data read exists outside FUN_08027a50.",
        provenance="direct-xref", confidence=0.9, verified=None)

    # --- Correction #1: XMC window is the LCD, not the FPGA data plane. ---
    wrong_xmc = add(con, source=S, kind="peripheral_id", name="xmc_fpga_data_REFUTED",
        addr_start=0x60000000,
        claim="(REFUTED) XMC NE1 0x6001FFFE/0x60020000 is the FPGA acquisition data interface.",
        provenance="hypothesis", confidence=0.15, verified=0,
        evidence="Decoded register indices are the ILI9341/ST7789 LCD command set, not FPGA.")
    add(con, source=S, kind="peripheral_id", name="xmc_lcd_ili9341",
        addr_start=0x60000000,
        claim="XMC NE1 is an ILI9341/ST7789 LCD controller: 0x6001FFFE=cmd/index reg, "
              "0x60020000=data reg (FSMC A16=RS). Cmds 11/29/2A/2B/2C/2E/36/3A + B2..E1 "
              "power/gamma; panel 320x240. 0xA000xxxx = XMC bus timing.",
        provenance="direct-xref", confidence=0.95, verified=None, supersedes=wrong_xmc)

    add(con, source=S, kind="isr_role", name="dma1ch2_isr_lcd_blit",
        addr_start=0x08009670,
        claim="DMA1-Ch2 ISR 0x08009670 (only non-default DMA ISR) + software twin FUN_08022aac "
              "manage the framebuffer/dirty-region list (head 0x20000138, marker table 0x2000107c) "
              "and blit SRAM→LCD data port. Display, not acquisition.",
        provenance="decompile-derived", confidence=0.85, verified=None)

    # --- Correction #2: DMA2-Ch4 is the DAC siggen, not acquisition. ---
    wrong_dma2 = add(con, source=S, kind="dataflow", name="dma2ch4_acquisition_REFUTED",
        addr_start=0x40020400,
        claim="(REFUTED) DMA2-Ch4 is the FPGA→MCU sample-acquisition path.",
        provenance="hypothesis", confidence=0.15, verified=0,
        evidence="C4PADDR=&DAT_40007414=DAC_DHR12R2; SRAM LUT of 12-bit codes; an OUTPUT path.")
    add(con, source=S, kind="dataflow", name="dma2ch4_dac_siggen",
        addr_start=0x40020400,
        claim="DMA2-Ch4 drives DAC ch2 (C4PADDR=0x40007414=DHR12R2) from a circular SRAM "
              "waveform LUT (0x20000f5a). The built-in signal/cal generator; an output.",
        provenance="direct-xref", confidence=0.9, verified=None, supersedes=wrong_dma2)

    add(con, source=S, kind="isr_role", name="exti3_isr_dac_awg",
        addr_start=0x08009C10,
        claim="EXTI3 ISR 0x08009C10 interpolates state-struct waveform points and writes the DAC "
              "(0x40007404 + CR enable). AWG/siggen point update; an output.",
        provenance="decompile-derived", confidence=0.8, verified=None)

    add(con, source=S, kind="structure", name="active_irqs",
        claim="Active external IRQs (handler != default trap 0x08007345): EXTI3(DAC), "
              "DMA1_Ch2(LCD), USB_LP, TMR3, USART2, TMR8_BRK. FPGA runtime channel is the "
              "USART2+TMR3 cluster (0x0802Exxx).",
        provenance="direct-xref", confidence=0.95, verified=None)

    add(con, source=S, kind="dataflow", name="no_mcu_sample_path",
        claim="NEGATIVE SPACE: raw high-speed scope samples do not transit the MCU. Both DMA "
              "streams are outputs (LCD, DAC); XMC has only the LCD bank; SPI3 has no post-init "
              "reads. The FPGA samples/triggers/decimates and likely delivers reduced waveform "
              "data over USART2 (TMR3-driven). To confirm: trace the USART2 RX ring buffer.",
        provenance="synthesized-model", confidence=0.6, verified=None)

    con.commit()
    print(f"backfilled {con.execute('SELECT COUNT(*) FROM contracts').fetchone()[0]} contracts")
    return ids


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("backfill")
    p = sub.add_parser("verify"); p.add_argument("id", type=int)
    p = sub.add_parser("list"); p.add_argument("--source")
    p = sub.add_parser("show"); p.add_argument("id", type=int)
    args = ap.parse_args()

    con = connect()
    con.executescript(SCHEMA)

    if args.cmd == "init":
        print(f"initialized {DB_PATH}")
    elif args.cmd == "backfill":
        backfill(con)
    elif args.cmd == "verify":
        r = verify(con, args.id)
        print(json.dumps({k: v for k, v in r.items() if k != "cases"}, indent=2))
        print("VERIFIED" if r.get("verified") else
              ("UNCHECKED" if r.get("verified") is None else "REFUTED"))
    elif args.cmd == "list":
        cmd_list(con, args.source)
    elif args.cmd == "show":
        cmd_show(con, args.id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
