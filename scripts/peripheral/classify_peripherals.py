#!/usr/bin/env -S uv run python
"""Classify function peripheral accesses using xrefs + SVD register maps.

For each target, reads the xrefs table, filters to peripheral memory
regions (0x40000000-0x5FFFFFFF for vendor peripherals, 0xE0000000+
for Cortex-M system), and resolves each address against the chip's
SVD register map. Produces peripheral_xrefs.jsonl for ingest.

Works with or without an SVD file:
  - With SVD: register-level resolution (USART2.STS, GPIOA.ODR, etc.)
  - Without SVD: Cortex-M system peripherals only (NVIC, SysTick, SCB)
    plus raw addresses in vendor peripheral range tagged as "unknown"

Usage:
    scripts/peripheral/classify_peripherals.py at32_hal_blinky
    scripts/peripheral/classify_peripherals.py                # all targets
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"

sys.path.insert(0, str(REPO_ROOT / "scripts" / "peripheral"))
from parse_svd import RegisterMap, cortex_m_system_map, parse_svd


def _load_config() -> dict:
    """Load config.yaml and return the targets dict."""
    import yaml
    config_path = REPO_ROOT / "config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


def _get_register_map(target_cfg: dict) -> RegisterMap:
    """Build a RegisterMap for the target: SVD if available, else system-only."""
    svd_path = target_cfg.get("svd")
    if svd_path:
        full_path = REPO_ROOT / svd_path
        if full_path.exists():
            return parse_svd(full_path)
        else:
            print(f"  WARNING: SVD path {svd_path} not found, using system-only map")
    return cortex_m_system_map()


def _is_peripheral_addr(addr: int) -> bool:
    """Return True if address is in Cortex-M peripheral memory regions."""
    # Vendor peripherals: APB/AHB (0x40000000-0x5FFFFFFF)
    if 0x40000000 <= addr <= 0x5FFFFFFF:
        return True
    # External memory-mapped peripherals (0x60000000-0x9FFFFFFF)
    # e.g., FSMC/XMC LCD interface
    if 0x60000000 <= addr <= 0x9FFFFFFF:
        return True
    # XMC/FSMC (0xA0000000 region, used by AT32)
    if 0xA0000000 <= addr <= 0xAFFFFFFF:
        return True
    # Cortex-M system peripherals (0xE0000000+)
    if addr >= 0xE0000000:
        return True
    return False


def classify_target(target: str, target_cfg: dict) -> int:
    """Classify peripheral accesses for one target. Returns row count."""
    xrefs_path = BUILD_DIR / target / "tables" / "xrefs.parquet"
    if not xrefs_path.exists():
        print(f"  Skipping {target}: no xrefs.parquet")
        return 0

    reg_map = _get_register_map(target_cfg)
    has_svd = target_cfg.get("svd") is not None

    # Read peripheral xrefs via DuckDB
    import duckdb
    con = duckdb.connect()
    rows = con.execute(f"""
        SELECT function_addr, from_addr, to_addr, ref_type
        FROM read_parquet('{xrefs_path}')
        WHERE to_addr IS NOT NULL
          AND ref_type IN ('DATA', 'READ', 'WRITE', 'PARAM')
          AND (
              (to_addr BETWEEN 1073741824 AND 1610612735)   -- 0x40000000-0x5FFFFFFF
              OR (to_addr BETWEEN 1610612736 AND 2684354559) -- 0x60000000-0x9FFFFFFF
              OR (to_addr BETWEEN 2684354560 AND 2952790015) -- 0xA0000000-0xAFFFFFFF
              OR (to_addr >= 3758096384)                      -- 0xE0000000+
          )
        ORDER BY function_addr, to_addr
    """).fetchall()
    con.close()

    if not rows:
        print(f"  {target}: 0 peripheral xrefs found")
        # Write empty JSONL so downstream doesn't fail
        output_path = BUILD_DIR / target / "peripheral_xrefs.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("")
        return 0

    # Classify each xref
    now = datetime.now(timezone.utc).isoformat()
    output_path = BUILD_DIR / target / "peripheral_xrefs.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(output_path, "w") as f:
        for function_addr, from_addr, to_addr, ref_type in rows:
            info = reg_map.lookup(to_addr)
            if info:
                peripheral = info.peripheral
                register_name = info.register
                # Append alias suffix for RP2040 atomic aliases
                if info.alias and register_name:
                    register_name = f"{register_name}[{info.alias.upper()}]"
                elif info.alias:
                    register_name = f"[{info.alias.upper()}]"
                group = info.group
            elif has_svd:
                # Address is in peripheral range but not in any SVD peripheral
                peripheral = f"UNKNOWN_0x{to_addr:08X}"
                register_name = ""
                group = "unknown"
            else:
                # No SVD — skip vendor peripheral addresses (can't classify)
                if to_addr < 0xE0000000:
                    peripheral = f"UNMAPPED_0x{to_addr:08X}"
                    register_name = ""
                    group = "unknown"
                else:
                    continue

            rec = {
                "function_addr": function_addr,
                "from_addr": from_addr,
                "access_addr": to_addr,
                "ref_type": ref_type,
                "peripheral": peripheral,
                "register_name": register_name,
                "peripheral_group": group,
            }
            f.write(json.dumps(rec) + "\n")
            count += 1

    print(f"  {target}: {count} peripheral xrefs classified "
          f"({len(rows)} raw, {'SVD' if has_svd else 'system-only'})")
    return count


def main():
    config = _load_config()
    targets = config.get("targets", {})

    # Filter to specific target(s) if provided on command line
    if len(sys.argv) > 1:
        requested = sys.argv[1:]
        targets = {t: cfg for t, cfg in targets.items() if t in requested}
        if not targets:
            print(f"ERROR: target(s) {sys.argv[1:]} not found in config.yaml")
            sys.exit(1)

    total = 0
    for target, cfg in targets.items():
        print(f"Classifying peripherals: {target}")
        total += classify_target(target, cfg)

    print(f"\nTotal: {total} peripheral xrefs across {len(targets)} targets")


if __name__ == "__main__":
    main()
