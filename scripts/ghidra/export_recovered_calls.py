# ripcord — Recovered call-edge extraction
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis.
# Recovers call edges that Ghidra's standard call-reference analysis
# misses: hardware interrupt vectors, function-pointer constants
# passed to registrar functions, veneer trampolines, etc.
#
# Unlike the hardcoded per-target SQL heuristics that previously lived
# in export_facts.py, this extractor works at the Ghidra level where
# it has access to instruction-level references, memory contents, and
# the full function model. It works on stripped binaries — no symbol
# names required.
#
# Each output row carries a `mechanism` tag and `confidence` float so
# downstream consumers can filter by reliability tier.
#
# Mechanisms emitted:
#   vector_table        — Cortex-M exception/IRQ vector (confidence 1.0)
#   func_ptr_ref        — non-call reference to a function entry (0.7)
#   veneer_jump         — COMPUTED_JUMP from a veneer/trampoline (0.95)
#   registrar_dispatch  — inferred registrar → callback edge (0.6)
#
# Usage (inside a Ghidra headless session):
#   -postScript export_recovered_calls.py <output.jsonl>

import json
import sys


def get_output_path():
    args = getScriptArgs()  # noqa: F821
    if len(args) < 1:
        printerr("usage: export_recovered_calls.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def build_function_entry_set(function_manager):
    """Build a set of all function entry-point offsets for fast lookup."""
    entries = set()
    for fn in function_manager.getFunctions(True):
        entries.add(int(fn.getEntryPoint().getOffset()))
    return entries


# -----------------------------------------------------------------------
# Mechanism 1: Cortex-M vector table
# -----------------------------------------------------------------------

# Standard Cortex-M exception names by vector index
_VECTOR_NAMES = {
    1: "Reset", 2: "NMI", 3: "HardFault",
    4: "MemManage", 5: "BusFault", 6: "UsageFault",
    11: "SVCall", 12: "DebugMon", 14: "PendSV", 15: "SysTick",
}


def scan_vector_table(program, function_entries):
    """Read the Cortex-M vector table and emit ISR entry edges.

    The vector table starts at the base of the loaded image. The first
    word is the initial stack pointer; subsequent words are exception
    handler addresses with Thumb bit set. We scan up to 256 entries
    (system exceptions + IRQs).
    """
    recovered = []
    memory = program.getMemory()
    min_addr = program.getMinAddress()
    lang_id = str(program.getLanguageID())

    # Only scan if this looks like a Cortex-M target
    if "ARM" not in lang_id and "Cortex" not in lang_id:
        return recovered

    # Validate: first word should look like a RAM address (stack pointer)
    # For Cortex-M, SRAM typically starts at 0x20000000
    try:
        initial_sp = memory.getInt(min_addr) & 0xFFFFFFFF
    except Exception:
        return recovered

    if not (0x20000000 <= initial_sp <= 0x20400000):
        return recovered

    for i in range(1, 256):
        entry_addr = min_addr.add(i * 4)
        try:
            raw_value = memory.getInt(entry_addr) & 0xFFFFFFFF
        except Exception:
            break

        # Cortex-M function pointers have Thumb bit (bit 0) set
        func_addr = raw_value & ~1

        if func_addr == 0 or raw_value == 0xFFFFFFFF:
            continue

        if func_addr in function_entries:
            name = _VECTOR_NAMES.get(i, "IRQ{}".format(i - 16) if i >= 16 else "Exception{}".format(i))
            recovered.append({
                "caller_addr": None,
                "callee_addr": func_addr,
                "call_site_addr": int(entry_addr.getOffset()),
                "mechanism": "vector_table",
                "confidence": 1.0,
                "detail": "vector[{}] = {}".format(i, name),
            })

    return recovered


# -----------------------------------------------------------------------
# Mechanism 2: Function-pointer references (non-call refs to func entries)
# -----------------------------------------------------------------------

def scan_func_ptr_references(program, function_entries):
    """Find non-call references from function bodies to other function entries.

    This catches:
      - ldr rN, =func_addr  (loading a function pointer before passing it)
      - str rN, [rM, #off]  (storing a function pointer into a struct/vtable)
      - .word func_addr      (literal pool entries referencing functions)
      - COMPUTED_JUMP from veneers/trampolines
    """
    recovered = []
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()

    for function in function_manager.getFunctions(True):
        body = function.getBody()
        if body is None:
            continue

        caller_addr = int(function.getEntryPoint().getOffset())

        src_iter = reference_manager.getReferenceSourceIterator(body, True)
        while src_iter.hasNext():
            src_addr = src_iter.next()
            for ref in reference_manager.getReferencesFrom(src_addr):
                ref_type = ref.getReferenceType()

                # Skip call references — already in the calls table
                if ref_type.isCall():
                    continue

                # Skip non-computed flow refs (normal jumps within function)
                if ref_type.isFlow() and not ref_type.isComputed():
                    continue

                to_addr = ref.getToAddress()
                if to_addr is None:
                    continue

                target = int(to_addr.getOffset())

                # Only interested in references to other functions' entries
                if target not in function_entries or target == caller_addr:
                    continue

                if ref_type.isComputed() and ref_type.isJump():
                    mechanism = "veneer_jump"
                    confidence = 0.95
                    detail = "COMPUTED_JUMP in {}".format(function.getName())
                else:
                    mechanism = "func_ptr_ref"
                    confidence = 0.7
                    detail = "{} in {}".format(ref_type.getName(), function.getName())

                recovered.append({
                    "caller_addr": caller_addr,
                    "callee_addr": target,
                    "call_site_addr": int(src_addr.getOffset()),
                    "mechanism": mechanism,
                    "confidence": confidence,
                    "detail": detail,
                })

    return recovered


# -----------------------------------------------------------------------
# Mechanism 3: Registrar dispatch inference
# -----------------------------------------------------------------------

def infer_registrar_dispatch(program, function_entries, ptr_refs):
    """Infer registrar → callback dispatch edges.

    Pattern: if function A references function B's address as data AND
    calls function C directly, then C may be a registrar that eventually
    dispatches to B (e.g., xTaskCreate, xTimerCreate, callback_register).

    We require C to have >= 2 incoming call references (registrars are
    typically called from multiple places) to reduce noise.

    This works on stripped binaries — it uses structural patterns, not
    function names.
    """
    recovered = []
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()
    addr_space = program.getAddressFactory().getDefaultAddressSpace()

    # Build map: caller_addr → set of function-pointer targets
    caller_to_targets = {}
    for ref in ptr_refs:
        caller = ref["caller_addr"]
        if caller is None:
            continue
        if caller not in caller_to_targets:
            caller_to_targets[caller] = set()
        caller_to_targets[caller].add(ref["callee_addr"])

    for caller_addr, ptr_targets in caller_to_targets.items():
        function = function_manager.getFunctionAt(
            addr_space.getAddress(caller_addr)
        )
        if function is None:
            continue

        body = function.getBody()
        if body is None:
            continue

        # Find this function's direct call targets
        direct_callees = set()
        src_iter = reference_manager.getReferenceSourceIterator(body, True)
        while src_iter.hasNext():
            src_addr = src_iter.next()
            for ref in reference_manager.getReferencesFrom(src_addr):
                rt = ref.getReferenceType()
                if rt.isCall() and not rt.isComputed():
                    to = ref.getToAddress()
                    if to is not None:
                        direct_callees.add(int(to.getOffset()))

        for callee_addr in direct_callees:
            callee_func = function_manager.getFunctionAt(
                addr_space.getAddress(callee_addr)
            )
            if callee_func is None:
                continue

            # Count incoming references to the potential registrar
            ref_count = 0
            for _ in reference_manager.getReferencesTo(callee_func.getEntryPoint()):
                ref_count += 1
                if ref_count >= 2:
                    break

            if ref_count < 2:
                continue

            for target in ptr_targets:
                # Don't create self-edges or duplicate the direct call
                if target == callee_addr or target == caller_addr:
                    continue
                recovered.append({
                    "caller_addr": callee_addr,
                    "callee_addr": target,
                    "call_site_addr": None,
                    "mechanism": "registrar_dispatch",
                    "confidence": 0.6,
                    "detail": "{} dispatches to 0x{:08x}, registered by {}".format(
                        callee_func.getName(), target, function.getName()
                    ),
                })

    return recovered


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821

    function_entries = build_function_entry_set(program.getFunctionManager())
    print("export_recovered_calls: {} function entries in program".format(len(function_entries)))

    all_recovered = []

    # 1. Vector table
    vtable = scan_vector_table(program, function_entries)
    all_recovered.extend(vtable)
    print("  vector_table: {} entries".format(len(vtable)))

    # 2. Function-pointer references
    ptr_refs = scan_func_ptr_references(program, function_entries)
    func_ptr_count = sum(1 for r in ptr_refs if r["mechanism"] == "func_ptr_ref")
    veneer_count = sum(1 for r in ptr_refs if r["mechanism"] == "veneer_jump")
    all_recovered.extend(ptr_refs)
    print("  func_ptr_ref: {} entries".format(func_ptr_count))
    print("  veneer_jump: {} entries".format(veneer_count))

    # 3. Registrar dispatch (only from func_ptr_ref, not veneers)
    data_refs_only = [r for r in ptr_refs if r["mechanism"] == "func_ptr_ref"]
    registrar = infer_registrar_dispatch(program, function_entries, data_refs_only)
    all_recovered.extend(registrar)
    print("  registrar_dispatch: {} entries".format(len(registrar)))

    # Deduplicate: keep highest-confidence edge per (caller, callee, mechanism)
    best = {}
    for r in all_recovered:
        key = (r["caller_addr"], r["callee_addr"], r["mechanism"])
        if key not in best or r["confidence"] > best[key]["confidence"]:
            best[key] = r

    deduped = list(best.values())

    with open(output_path, "w") as fh:
        for rec in deduped:
            fh.write(json.dumps(rec) + "\n")

    print("export_recovered_calls: wrote {} recovered edges to {}".format(
        len(deduped), output_path))


main()
