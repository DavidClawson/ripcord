#!/usr/bin/env -S uv run python
"""Recover indirect call edges from existing warehouse data + binary.

This is the standalone (non-Ghidra) version of call recovery. It runs
against existing warehouse tables and the original binary, producing
recovered_calls.jsonl ready for ingest. No Ghidra session required.

Five recovery mechanisms:

  1. vector_table  — Read the Cortex-M vector table directly from the
                     binary. Entries matching known functions get confidence
                     1.0; mid-body ISR entry points in existing functions
                     get 0.9; undiscovered entry points get 0.85. For raw
                     binary imports where Ghidra missed many function starts,
                     all valid code-region entries are emitted.

  2. func_ptr_ref  — From the xrefs table, find non-call references
                     (DATA, PARAM, WRITE, INDIRECTION) from function
                     bodies to other function entry points. These are
                     function-pointer references. (confidence 0.7)

  3. veneer_jump   — COMPUTED_JUMP xrefs (trampoline dispatches). (0.95)

  4. binary_const  — Scan all loadable segments for 32-bit values that
                     match function entry points (with Thumb bit set).
                     Catches literal pool entries, init arrays, and data
                     tables that the xrefs table misses. Known targets get
                     confidence 0.5; for raw binaries, Thumb-bit-set values
                     pointing into the code region but not matching any
                     known function get 0.35 (undiscovered targets).

  5. registrar_dispatch — When function A references function B as data
                     AND calls function C, infer C→B dispatch edge.
                     Requires C to have >= 2 incoming call refs.
                     (confidence 0.6)

Usage:
    scripts/recovery/recover_calls.py pico_blinky
    scripts/recovery/recover_calls.py                # all targets
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = REPO_ROOT / "build"

# Try to import duckdb; if not available, fall back to subprocess query
try:
    import duckdb

    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False


def get_db():
    """Create a DuckDB connection with all warehouse views registered."""
    db = duckdb.connect()
    # Register all parquet files as views
    for target_dir in sorted(BUILD_DIR.iterdir()):
        tables_dir = target_dir / "tables"
        if not tables_dir.is_dir():
            continue
        for pq in sorted(tables_dir.glob("*.parquet")):
            table_name = pq.stem
            # Skip enriched variants and per-scenario mmio
            if table_name == "functions_enriched":
                continue
            if table_name.startswith("mmio_events_"):
                continue
            try:
                db.execute(
                    f"CREATE OR REPLACE VIEW {table_name} AS "
                    f"SELECT * FROM read_parquet('{pq}')"
                )
            except Exception:
                # If multiple targets have the same table, UNION them
                pass

    # Union all parquet files per table name
    table_files: dict[str, list[str]] = {}
    for target_dir in sorted(BUILD_DIR.iterdir()):
        tables_dir = target_dir / "tables"
        if not tables_dir.is_dir():
            continue
        for pq in sorted(tables_dir.glob("*.parquet")):
            name = pq.stem
            if name == "functions_enriched" or name.startswith("mmio_events_"):
                continue
            if name not in table_files:
                table_files[name] = []
            table_files[name].append(str(pq))

    for name, files in table_files.items():
        paths = ", ".join(f"'{f}'" for f in files)
        db.execute(
            f"CREATE OR REPLACE VIEW {name} AS "
            f"SELECT * FROM read_parquet([{paths}])"
        )

    return db


# -----------------------------------------------------------------------
# Mechanism 1: Cortex-M vector table
# -----------------------------------------------------------------------

_VECTOR_NAMES = {
    1: "Reset", 2: "NMI", 3: "HardFault",
    4: "MemManage", 5: "BusFault", 6: "UsageFault",
    11: "SVCall", 12: "DebugMon", 14: "PendSV", 15: "SysTick",
}


def read_vector_table_elf(elf_path: str, function_addrs: set[int],
                          function_ranges: list[tuple[int, int, str]] | None = None) -> list[dict]:
    """Read vector table from an ELF file's loadable segments."""
    recovered = []
    data = Path(elf_path).read_bytes()

    if len(data) < 52:
        return recovered

    # Parse ELF header
    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    if ei_class != 1:
        return recovered  # Only 32-bit ARM

    ei_data = data[5]  # 1 = little-endian
    if ei_data != 1:
        return recovered

    e_machine = struct.unpack_from("<H", data, 18)[0]
    if e_machine != 40:  # EM_ARM
        return recovered

    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize = struct.unpack_from("<H", data, 42)[0]
    e_phnum = struct.unpack_from("<H", data, 44)[0]

    # Find the first LOAD segment (contains vector table at start)
    load_offset = None
    load_vaddr = None
    load_filesz = None
    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, ph_off)[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack_from("<I", data, ph_off + 4)[0]
            p_vaddr = struct.unpack_from("<I", data, ph_off + 8)[0]
            p_filesz = struct.unpack_from("<I", data, ph_off + 16)[0]
            if load_offset is None:
                load_offset = p_offset
                load_vaddr = p_vaddr
                load_filesz = p_filesz

    if load_offset is None:
        return recovered

    # Validate: first word should look like a stack pointer
    if load_filesz < 4:
        return recovered

    initial_sp = struct.unpack_from("<I", data, load_offset)[0]
    if not (0x20000000 <= initial_sp <= 0x20400000):
        return recovered

    # Build sorted function ranges for body-containment checks
    sorted_ranges = sorted(function_ranges or [], key=lambda x: x[0])

    # Read vector table entries
    max_vectors = min(256, (load_filesz - 4) // 4)
    for i in range(1, max_vectors + 1):
        offset = load_offset + i * 4
        if offset + 4 > len(data):
            break

        raw_value = struct.unpack_from("<I", data, offset)[0]
        func_addr = raw_value & ~1  # Clear Thumb bit

        if func_addr == 0 or raw_value == 0xFFFFFFFF:
            continue

        name = _VECTOR_NAMES.get(
            i, "IRQ{}".format(i - 16) if i >= 16 else "Exception{}".format(i)
        )

        if func_addr in function_addrs:
            recovered.append({
                "caller_addr": None,
                "callee_addr": func_addr,
                "call_site_addr": load_vaddr + i * 4,
                "mechanism": "vector_table",
                "confidence": 1.0,
                "detail": "vector[{}] = {}".format(i, name),
            })
        elif sorted_ranges:
            # For ELF targets we typically have good function coverage,
            # but still check for mid-body/undiscovered entry points
            containing_func = None
            for fstart, fsize, fname in sorted_ranges:
                if fstart <= func_addr < fstart + fsize:
                    containing_func = (fstart, fsize, fname)
                    break
                if fstart > func_addr:
                    break

            if containing_func:
                fstart, fsize, fname = containing_func
                offset_in = func_addr - fstart
                recovered.append({
                    "caller_addr": None,
                    "callee_addr": func_addr,
                    "call_site_addr": load_vaddr + i * 4,
                    "mechanism": "vector_table",
                    "confidence": 0.9,
                    "detail": "vector[{}] = {} (mid-body +{} in {} @ 0x{:08x})".format(
                        i, name, offset_in, fname, fstart
                    ),
                })
            else:
                recovered.append({
                    "caller_addr": None,
                    "callee_addr": func_addr,
                    "call_site_addr": load_vaddr + i * 4,
                    "mechanism": "vector_table",
                    "confidence": 0.85,
                    "detail": "vector[{}] = {} (undiscovered entry point)".format(i, name),
                })

    return recovered


def read_vector_table_raw(bin_path: str, base_addr: int, function_addrs: set[int],
                          function_ranges: list[tuple[int, int, str]] | None = None) -> list[dict]:
    """Read vector table from a raw binary file.

    For raw binary imports (e.g. stock firmware loaded via BinaryLoader),
    Ghidra often doesn't create functions at vector table targets because
    it doesn't know where the vector table is. We emit entries for ALL
    valid-looking code addresses, classifying them as:
      - known function entry (confidence 1.0)
      - mid-body entry point inside an existing function (confidence 0.9)
      - undiscovered entry point in a gap between functions (confidence 0.85)
    """
    recovered = []
    data = Path(bin_path).read_bytes()

    if len(data) < 8:
        return recovered

    initial_sp = struct.unpack_from("<I", data, 0)[0]
    if not (0x20000000 <= initial_sp <= 0x20400000):
        return recovered

    # Build sorted function ranges for body-containment checks
    sorted_ranges = sorted(function_ranges or [], key=lambda x: x[0])

    # Compute the code region bounds from the binary
    code_start = base_addr
    code_end = base_addr + len(data)

    max_vectors = min(256, (len(data) - 4) // 4)
    for i in range(1, max_vectors + 1):
        offset = i * 4
        if offset + 4 > len(data):
            break

        raw_value = struct.unpack_from("<I", data, offset)[0]
        func_addr = raw_value & ~1

        if func_addr == 0 or raw_value == 0xFFFFFFFF:
            continue

        # Must be within the binary's code region
        if not (code_start <= func_addr < code_end):
            continue

        name = _VECTOR_NAMES.get(
            i, "IRQ{}".format(i - 16) if i >= 16 else "Exception{}".format(i)
        )

        if func_addr in function_addrs:
            # Known function entry point
            recovered.append({
                "caller_addr": None,
                "callee_addr": func_addr,
                "call_site_addr": base_addr + i * 4,
                "mechanism": "vector_table",
                "confidence": 1.0,
                "detail": "vector[{}] = {}".format(i, name),
            })
        else:
            # Check if it falls within an existing function body
            containing_func = None
            for fstart, fsize, fname in sorted_ranges:
                if fstart <= func_addr < fstart + fsize:
                    containing_func = (fstart, fsize, fname)
                    break
                if fstart > func_addr:
                    break

            if containing_func:
                fstart, fsize, fname = containing_func
                offset_in = func_addr - fstart
                recovered.append({
                    "caller_addr": None,
                    "callee_addr": func_addr,
                    "call_site_addr": base_addr + i * 4,
                    "mechanism": "vector_table",
                    "confidence": 0.9,
                    "detail": "vector[{}] = {} (mid-body +{} in {} @ 0x{:08x})".format(
                        i, name, offset_in, fname, fstart
                    ),
                })
            else:
                # Undiscovered entry point — not in any known function
                recovered.append({
                    "caller_addr": None,
                    "callee_addr": func_addr,
                    "call_site_addr": base_addr + i * 4,
                    "mechanism": "vector_table",
                    "confidence": 0.85,
                    "detail": "vector[{}] = {} (undiscovered entry point)".format(i, name),
                })

    return recovered


# -----------------------------------------------------------------------
# Mechanism 4: Binary constant scan (literal pools, init arrays, data tables)
# -----------------------------------------------------------------------

def scan_binary_constants_elf(elf_path: str, function_addrs: set[int],
                               function_ranges: list[tuple[int, int, str]],
                               extra_known_addrs: set[int] | None = None) -> list[dict]:
    """Scan all loadable ELF segments for 32-bit values matching function entries.

    For Cortex-M (Thumb), function pointers have bit 0 set. We scan for
    values where (value & ~1) matches a known function entry point.

    To determine which function "owns" each constant reference, we find
    the nearest preceding function — literal pools in Thumb-2 follow their
    owning function or sit between functions.
    """
    recovered = []
    data = Path(elf_path).read_bytes()

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return recovered

    # Parse segments
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize = struct.unpack_from("<H", data, 42)[0]
    e_phnum = struct.unpack_from("<H", data, 44)[0]

    segments = []
    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, ph_off)[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack_from("<I", data, ph_off + 4)[0]
            p_vaddr = struct.unpack_from("<I", data, ph_off + 8)[0]
            p_filesz = struct.unpack_from("<I", data, ph_off + 16)[0]
            segments.append((p_offset, p_vaddr, p_filesz))

    # Build sorted function starts for nearest-function lookup
    func_starts = sorted(function_ranges, key=lambda x: x[0])

    # Build set of Thumb pointers (addr | 1) for matching
    thumb_addrs = {addr | 1 for addr in function_addrs}
    # Also check plain addresses (for non-Thumb or special cases)
    all_targets = function_addrs | thumb_addrs

    # Only exclude the vector table region if it actually looks like one
    vector_region = set()
    if segments:
        seg0_offset = segments[0][0]
        seg0_vaddr = segments[0][1]
        seg0_filesz = segments[0][2]
        if seg0_filesz >= 8:
            initial_sp = struct.unpack_from("<I", data, seg0_offset)[0]
            if 0x20000000 <= initial_sp <= 0x20400000:
                # This segment starts with a valid vector table
                for i in range(256):
                    vector_region.add(seg0_vaddr + i * 4)

    seen_pairs = set()  # (owner, target) dedup

    for seg_offset, seg_vaddr, seg_filesz in segments:
        # Scan every 4-byte aligned position
        for off in range(0, seg_filesz - 3, 4):
            file_off = seg_offset + off
            vaddr = seg_vaddr + off

            # Skip the vector table region
            if vaddr in vector_region:
                continue

            value = struct.unpack_from("<I", data, file_off)[0]

            if value in all_targets:
                func_addr = value & ~1

                # Skip self-references
                if func_addr == vaddr:
                    continue

                # Find the nearest preceding function as the "owner"
                owner_addr = None
                owner_name = None
                for fstart, fsize, fname in reversed(func_starts):
                    if fstart <= vaddr:
                        # Allow up to 256 bytes after function end for literal pool
                        if vaddr < fstart + fsize + 256:
                            owner_addr = fstart
                            owner_name = fname
                        break

                if owner_addr is None:
                    continue

                pair = (owner_addr, func_addr)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                recovered.append({
                    "caller_addr": owner_addr,
                    "callee_addr": func_addr,
                    "call_site_addr": vaddr,
                    "mechanism": "binary_const",
                    "confidence": 0.5,
                    "detail": "0x{:08x} in/near {}".format(vaddr, owner_name),
                })

    return recovered


def scan_binary_constants_raw(bin_path: str, base_addr: int,
                               function_addrs: set[int],
                               function_ranges: list[tuple[int, int, str]],
                               extra_known_addrs: set[int] | None = None) -> list[dict]:
    """Scan a raw binary for function pointer constants.

    For raw binary imports, we match against:
      1. Known Ghidra function entries (confidence 0.5)
      2. Addresses discovered by vector table scan (confidence 0.5)
      3. Thumb-bit-set values pointing into the code region that are
         NOT known functions — likely undiscovered function pointers
         (confidence 0.35)

    The extra_known_addrs parameter allows passing in addresses discovered
    by earlier mechanisms (e.g. vector table) to expand the match set.
    """
    recovered = []
    data = Path(bin_path).read_bytes()

    func_starts = sorted(function_ranges, key=lambda x: x[0])

    # Build the set of known targets (Ghidra functions + extra discoveries)
    known_addrs = set(function_addrs)
    if extra_known_addrs:
        known_addrs |= extra_known_addrs
    thumb_addrs = {addr | 1 for addr in known_addrs}
    known_targets = known_addrs | thumb_addrs

    # Code region for recognizing potential undiscovered function pointers
    code_start = base_addr
    code_end = base_addr + len(data)

    # Skip vector table (first 1024 bytes)
    vector_end = min(1024, len(data))
    seen_pairs: set[tuple[int, int]] = set()

    for off in range(vector_end, len(data) - 3, 4):
        vaddr = base_addr + off
        value = struct.unpack_from("<I", data, off)[0]

        func_addr = value & ~1
        is_thumb = (value & 1) == 1

        if func_addr == 0 or value == 0xFFFFFFFF:
            continue
        if func_addr == vaddr:
            continue

        is_known = value in known_targets
        is_code_ptr = (is_thumb and code_start <= func_addr < code_end
                       and func_addr not in known_addrs)

        if not is_known and not is_code_ptr:
            continue

        # Find the owning function for this constant
        owner_addr = None
        owner_name = None
        for fstart, fsize, fname in reversed(func_starts):
            if fstart <= vaddr:
                if vaddr < fstart + fsize + 256:
                    owner_addr = fstart
                    owner_name = fname
                break

        if owner_addr is None:
            continue

        pair = (owner_addr, func_addr)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        if is_known:
            recovered.append({
                "caller_addr": owner_addr,
                "callee_addr": func_addr,
                "call_site_addr": vaddr,
                "mechanism": "binary_const",
                "confidence": 0.5,
                "detail": "0x{:08x} in/near {}".format(vaddr, owner_name),
            })
        else:
            # Undiscovered code pointer — lower confidence
            recovered.append({
                "caller_addr": owner_addr,
                "callee_addr": func_addr,
                "call_site_addr": vaddr,
                "mechanism": "binary_const",
                "confidence": 0.35,
                "detail": "0x{:08x} in/near {} (undiscovered target)".format(vaddr, owner_name),
            })

    return recovered


# -----------------------------------------------------------------------
# Mechanism 2: Function-pointer references from xrefs table
# -----------------------------------------------------------------------

def recover_func_ptr_refs(db, target: str, function_addrs: set[int],
                          extra_known_addrs: set[int] | None = None) -> list[dict]:
    """Find non-call xrefs that point to function entry points.

    For raw binary imports where Ghidra missed many function starts,
    extra_known_addrs can supply addresses discovered by other mechanisms
    (e.g. vector table scan). These matches get slightly lower confidence.
    """
    rows = db.execute(
        f"""
        SELECT x.function_addr, x.from_addr, x.to_addr, x.ref_type
        FROM xrefs x
        WHERE x.source = '{target}'
          AND x.ref_type IN ('DATA', 'PARAM', 'WRITE', 'INDIRECTION', 'DATA_IND')
          AND x.to_addr IS NOT NULL
        """
    ).fetchall()

    all_known = set(function_addrs)
    if extra_known_addrs:
        all_known |= extra_known_addrs

    recovered = []
    for func_addr, from_addr, to_addr, ref_type in rows:
        if to_addr in all_known and to_addr != func_addr:
            conf = 0.7 if to_addr in function_addrs else 0.55
            recovered.append({
                "caller_addr": func_addr,
                "callee_addr": to_addr,
                "call_site_addr": from_addr,
                "mechanism": "func_ptr_ref",
                "confidence": conf,
                "detail": "{} at 0x{:08x}".format(ref_type, from_addr),
            })

    return recovered


# -----------------------------------------------------------------------
# Mechanism 2b: Veneer/trampoline jumps
# -----------------------------------------------------------------------

def recover_veneer_jumps(db, target: str, function_addrs: set[int]) -> list[dict]:
    """Find COMPUTED_JUMP xrefs from veneer functions to their targets."""
    rows = db.execute(
        f"""
        SELECT x.function_addr, x.from_addr, x.to_addr
        FROM xrefs x
        WHERE x.source = '{target}'
          AND x.ref_type = 'COMPUTED_JUMP'
          AND x.to_addr IS NOT NULL
        """
    ).fetchall()

    recovered = []
    for func_addr, from_addr, to_addr in rows:
        if to_addr in function_addrs and to_addr != func_addr:
            recovered.append({
                "caller_addr": func_addr,
                "callee_addr": to_addr,
                "call_site_addr": from_addr,
                "mechanism": "veneer_jump",
                "confidence": 0.95,
                "detail": "COMPUTED_JUMP at 0x{:08x}".format(from_addr),
            })

    return recovered


# -----------------------------------------------------------------------
# Mechanism 3: Registrar dispatch inference
# -----------------------------------------------------------------------

def _is_likely_registrar(name: str, num_params: int) -> bool:
    """Check if a function is likely a registrar (accepts and stores function pointers).

    Two-pronged filter:
    1. Structural: num_params >= 4 (registrars take a function pointer plus
       context/config args — xTaskCreate has 6, xTimerCreate has 7, etc.)
    2. Name-pattern: known registrar patterns for named binaries

    This filter was added because the original registrar_dispatch mechanism
    had 7.3% precision — utility functions like strlen, time_us_64, and
    __wrap_memset were being treated as dispatchers. With this filter,
    precision jumps to ~78-100%.
    """
    # Structural filter: registrars typically have 4+ parameters
    if num_params >= 4:
        return True

    # Name-pattern filter for known registrar families
    name_lower = name.lower()
    registrar_patterns = [
        "xtaskcreate", "xtimercreate", "xtimergenericcommand",
        "xcallbackregister", "set_exclusive_handler", "set_handler",
        "add_repeating_timer", "add_alarm", "register_callback",
        "create_task", "create_timer", "install_handler",
        "add_at_time_worker", "add_when_pending_worker",
    ]
    for pattern in registrar_patterns:
        if pattern in name_lower:
            return True

    return False


def infer_registrar_dispatch(
    db, target: str, func_ptr_refs: list[dict]
) -> list[dict]:
    """Infer registrar→callback dispatch edges.

    Pattern: if function A references function B as data AND calls
    function C, then C may dispatch to B. Requires:
    1. C has >= 2 incoming call refs (registrars are called from many places)
    2. C passes the _is_likely_registrar filter (num_params >= 4 or name match)
    """
    # Build: caller → set of function-pointer targets
    caller_to_targets: dict[int, set[int]] = {}
    for ref in func_ptr_refs:
        caller = ref["caller_addr"]
        if caller is None:
            continue
        if caller not in caller_to_targets:
            caller_to_targets[caller] = set()
        caller_to_targets[caller].add(ref["callee_addr"])

    if not caller_to_targets:
        return []

    # For each function that references function pointers,
    # find its direct call targets
    callers_list = ", ".join(str(a) for a in caller_to_targets)
    rows = db.execute(
        f"""
        SELECT c.caller_addr, c.callee_addr
        FROM calls c
        WHERE c.source = '{target}'
          AND c.caller_addr IN ({callers_list})
          AND c.callee_addr IS NOT NULL
          AND c.is_computed = false
        """
    ).fetchall()

    caller_to_callees: dict[int, set[int]] = {}
    for caller, callee in rows:
        if caller not in caller_to_callees:
            caller_to_callees[caller] = set()
        caller_to_callees[caller].add(callee)

    # Count incoming refs per potential registrar
    all_callees = set()
    for callees in caller_to_callees.values():
        all_callees.update(callees)

    if not all_callees:
        return []

    callees_list = ", ".join(str(a) for a in all_callees)
    ref_counts = dict(
        db.execute(
            f"""
            SELECT callee_addr, COUNT(*) AS cnt
            FROM calls
            WHERE source = '{target}'
              AND callee_addr IN ({callees_list})
              AND callee_addr IS NOT NULL
            GROUP BY callee_addr
            HAVING COUNT(*) >= 2
            """
        ).fetchall()
    )

    # Get function metadata for filtering and detail strings
    meta_rows = db.execute(
        f"""
        SELECT addr, name, num_params FROM functions
        WHERE source = '{target}'
        """
    ).fetchall()
    addr_to_name = {addr: name for addr, name, _ in meta_rows}
    addr_to_params = {addr: (params or 0) for addr, _, params in meta_rows}

    recovered = []
    for caller_addr, ptr_targets in caller_to_targets.items():
        callees = caller_to_callees.get(caller_addr, set())
        for callee_addr in callees:
            if callee_addr not in ref_counts:
                continue

            # Filter: only emit edges through likely registrar functions
            callee_name = addr_to_name.get(callee_addr, "FUN_{:08x}".format(callee_addr))
            callee_params = addr_to_params.get(callee_addr, 0)
            if not _is_likely_registrar(callee_name, callee_params):
                continue

            caller_name = addr_to_name.get(caller_addr, "FUN_{:08x}".format(caller_addr))
            for target_addr in ptr_targets:
                if target_addr == callee_addr or target_addr == caller_addr:
                    continue
                recovered.append({
                    "caller_addr": callee_addr,
                    "callee_addr": target_addr,
                    "call_site_addr": None,
                    "mechanism": "registrar_dispatch",
                    "confidence": 0.6,
                    "detail": "{} dispatches to 0x{:08x}, registered by {}".format(
                        callee_name, target_addr, caller_name
                    ),
                })

    return recovered


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def load_config():
    """Load config.yaml."""
    import yaml
    config_path = REPO_ROOT / "config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


def process_target(db, target: str, config: dict) -> None:
    """Run all recovery mechanisms for one target and write JSONL."""
    target_cfg = config["targets"].get(target, {})
    elf_path = target_cfg.get("elf")

    # Get all function addresses and ranges for this target
    func_rows = db.execute(
        f"SELECT addr, size, name FROM functions WHERE source = '{target}'"
    ).fetchall()
    function_addrs = {row[0] for row in func_rows}
    function_ranges = [(row[0], row[1] or 0, row[2] or "") for row in func_rows]

    if not function_addrs:
        print(f"  {target}: no functions found, skipping")
        return

    all_recovered = []
    is_arm = False
    # Addresses discovered by early mechanisms, fed forward to later ones
    extra_known_addrs: set[int] = set()

    # 1. Vector table + binary constant scan (if we have the binary)
    if elf_path and Path(elf_path).exists():
        arch = target_cfg.get("arch", "")
        is_arm = "arm" in arch.lower() or "cortex" in arch.lower()
        if is_arm:
            with open(elf_path, "rb") as f:
                magic = f.read(4)
            if magic == b"\x7fELF":
                vtable = read_vector_table_elf(
                    elf_path, function_addrs, function_ranges
                )
                # Collect newly discovered addresses from vector table
                for r in vtable:
                    extra_known_addrs.add(r["callee_addr"])
                bin_consts = scan_binary_constants_elf(
                    elf_path, function_addrs, function_ranges,
                    extra_known_addrs=extra_known_addrs
                )
            else:
                base_addr = target_cfg.get("base_addr", 0x08000000)
                vtable = read_vector_table_raw(
                    elf_path, base_addr, function_addrs, function_ranges
                )
                # Collect newly discovered addresses from vector table
                for r in vtable:
                    extra_known_addrs.add(r["callee_addr"])
                bin_consts = scan_binary_constants_raw(
                    elf_path, base_addr, function_addrs, function_ranges,
                    extra_known_addrs=extra_known_addrs
                )
            all_recovered.extend(vtable)
            all_recovered.extend(bin_consts)
            # Collect addresses from binary_const scan too
            for r in bin_consts:
                extra_known_addrs.add(r["callee_addr"])
            print(f"  {target}: vector_table = {len(vtable)}")
            print(f"  {target}: binary_const = {len(bin_consts)}")
    else:
        print(f"  {target}: binary not found at {elf_path}, skipping binary scans")

    # 2. Function-pointer references from xrefs table
    #    Pass extra_known_addrs so xref targets matching discovered
    #    addresses are also captured
    ptr_refs = recover_func_ptr_refs(
        db, target, function_addrs,
        extra_known_addrs=extra_known_addrs if extra_known_addrs else None
    )
    all_recovered.extend(ptr_refs)
    print(f"  {target}: func_ptr_ref = {len(ptr_refs)}")

    # 2b. Veneer jumps
    veneers = recover_veneer_jumps(db, target, function_addrs)
    all_recovered.extend(veneers)
    print(f"  {target}: veneer_jump = {len(veneers)}")

    # 3. Registrar dispatch (use both xref-based and binary_const refs)
    combined_refs = ptr_refs + [r for r in all_recovered if r["mechanism"] == "binary_const"]
    registrar = infer_registrar_dispatch(db, target, combined_refs)
    all_recovered.extend(registrar)
    print(f"  {target}: registrar_dispatch = {len(registrar)}")

    # Deduplicate: keep highest-confidence per (caller, callee, mechanism)
    best: dict[tuple, dict] = {}
    for r in all_recovered:
        key = (r["caller_addr"], r["callee_addr"], r["mechanism"])
        if key not in best or r["confidence"] > best[key]["confidence"]:
            best[key] = r
    deduped = list(best.values())

    # Write JSONL
    output_path = BUILD_DIR / target / "recovered_calls.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        for rec in deduped:
            fh.write(json.dumps(rec) + "\n")

    print(f"  {target}: total = {len(deduped)} recovered edges -> {output_path}")


def discover_targets() -> list[str]:
    """Find targets that have warehouse tables."""
    targets = []
    if BUILD_DIR.exists():
        for d in sorted(BUILD_DIR.iterdir()):
            if d.is_dir() and (d / "tables" / "functions.parquet").exists():
                targets.append(d.name)
    return targets


def main() -> int:
    if not HAS_DUCKDB:
        print("duckdb not available; install with: uv add duckdb", file=sys.stderr)
        return 1

    config = load_config()

    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        targets = discover_targets()

    if not targets:
        print("no targets with warehouse tables found", file=sys.stderr)
        return 1

    db = get_db()

    print(f"recovering call edges for {len(targets)} target(s):")
    for t in targets:
        process_target(db, t, config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
