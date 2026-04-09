# ripcord — Create Ghidra functions from Cortex-M vector table entries
#
# PyGhidra postScript that reads the Cortex-M vector table from the
# loaded binary and creates functions at discovered ISR entry points.
# This is critical for raw binary imports where Ghidra misses many
# function starts that are only reachable via interrupt dispatch.
#
# For ELF imports with symbols, this is usually a no-op since Ghidra
# already discovers functions from the symbol table.
#
# Must run BEFORE the export scripts so that newly created functions
# are included in the extraction.
#
# Invoked by the Snakemake ghidra_extract rule as:
#   -postScript create_vector_functions.py
#
# No arguments needed — reads from currentProgram's memory model.

import sys


# Standard Cortex-M exception names (vector index -> name)
_VECTOR_NAMES = {
    1:  "Reset_Handler",
    2:  "NMI_Handler",
    3:  "HardFault_Handler",
    4:  "MemManage_Handler",
    5:  "BusFault_Handler",
    6:  "UsageFault_Handler",
    # 7-10: Reserved
    11: "SVC_Handler",
    12: "DebugMon_Handler",
    # 13: Reserved
    14: "PendSV_Handler",
    15: "SysTick_Handler",
}

# Reserved vector indices (should be zero or ignored)
_RESERVED_INDICES = {0, 7, 8, 9, 10, 13}


def is_arm_program(program):
    """Check if the loaded program is ARM (Cortex-M)."""
    lang_id = str(program.getLanguageID())
    return "ARM" in lang_id


def get_memory_range(program):
    """Return (min_addr_long, max_addr_long) of loaded memory."""
    memory = program.getMemory()
    blocks = memory.getBlocks()
    min_addr = None
    max_addr = None
    for block in blocks:
        start = block.getStart().getOffset()
        end = block.getEnd().getOffset()
        if min_addr is None or start < min_addr:
            min_addr = start
        if max_addr is None or end > max_addr:
            max_addr = end
    return (min_addr, max_addr)


def read_u32(program, addr_long):
    """Read a 32-bit little-endian value from Ghidra memory."""
    try:
        addr = toAddr(addr_long)  # noqa: F821 — Ghidra builtin
        memory = program.getMemory()
        # getInt reads in the program's endianness (little-endian for ARM)
        return memory.getInt(addr) & 0xFFFFFFFF
    except Exception:
        return None


def function_exists_at(program, addr_long):
    """Check if a function already exists at the given address."""
    addr = toAddr(addr_long)  # noqa: F821 — Ghidra builtin
    func = program.getFunctionManager().getFunctionAt(addr)
    return func is not None


def get_function_name_at(program, addr_long):
    """Get the name of an existing function, or None."""
    addr = toAddr(addr_long)  # noqa: F821 — Ghidra builtin
    func = program.getFunctionManager().getFunctionAt(addr)
    if func is not None:
        return str(func.getName())
    return None


def has_symbols(program):
    """Heuristic: does this program have meaningful symbol names?

    If most functions have auto-generated names (FUN_xxxxx), this is
    likely a stripped binary or raw import. If most have real names,
    Ghidra found symbols.
    """
    fm = program.getFunctionManager()
    total = 0
    auto_named = 0
    for func in fm.getFunctions(True):
        total += 1
        name = str(func.getName())
        if name.startswith("FUN_") or name.startswith("thunk_FUN_"):
            auto_named += 1
        if total >= 50:
            break
    if total == 0:
        return False
    # If fewer than half are auto-named, we likely have symbols
    return auto_named < (total / 2)


def main():
    program = currentProgram  # noqa: F821 — Ghidra builtin

    if not is_arm_program(program):
        print("create_vector_functions: not an ARM program, skipping")
        return

    mem_range = get_memory_range(program)
    if mem_range[0] is None:
        print("create_vector_functions: no memory blocks loaded, skipping")
        return

    min_addr, max_addr = mem_range

    # The vector table starts at the beginning of loaded memory
    base_addr = min_addr

    # Read and validate initial stack pointer (entry 0)
    initial_sp = read_u32(program, base_addr)
    if initial_sp is None:
        print("create_vector_functions: cannot read vector table at 0x{:08X}".format(base_addr))
        return

    if not (0x20000000 <= initial_sp <= 0x20FFFFFF):
        print("create_vector_functions: initial SP 0x{:08X} not in RAM range, skipping".format(initial_sp))
        return

    # Scan vector table entries (up to 256: 1 SP + 15 system + 240 IRQ)
    max_entries = 256
    created = 0
    already_existed = 0
    skipped_zero = 0
    skipped_invalid = 0
    total_valid = 0

    for i in range(1, max_entries):
        entry_addr = base_addr + i * 4
        raw_value = read_u32(program, entry_addr)

        if raw_value is None:
            # Past end of readable memory
            break

        if raw_value == 0x00000000:
            skipped_zero += 1
            continue

        if i in _RESERVED_INDICES:
            continue

        # Strip Thumb bit
        target = raw_value & ~1

        # Validate: must point into loaded memory
        if target < min_addr or target > max_addr:
            skipped_invalid += 1
            continue

        # Additional validation: Thumb bit should be set for Cortex-M code
        if (raw_value & 1) == 0:
            skipped_invalid += 1
            continue

        total_valid += 1

        if function_exists_at(program, target):
            already_existed += 1
            continue

        # Determine name
        if i in _VECTOR_NAMES:
            name = _VECTOR_NAMES[i]
        else:
            name = "IRQ{}_Handler".format(i - 16)

        # Create the function
        try:
            addr = toAddr(target)  # noqa: F821 — Ghidra builtin
            func = createFunction(addr, name)  # noqa: F821 — Ghidra builtin
            if func is not None:
                created += 1
            else:
                # createFunction returns None if it can't disassemble
                # Try disassembling first, then creating
                try:
                    disassemble(addr)  # noqa: F821 — Ghidra builtin
                    func = createFunction(addr, name)  # noqa: F821 — Ghidra builtin
                    if func is not None:
                        created += 1
                    else:
                        skipped_invalid += 1
                except Exception:
                    skipped_invalid += 1
        except Exception as exc:
            printerr(  # noqa: F821 — Ghidra builtin
                "create_vector_functions: failed to create function at 0x{:08X}: {}".format(target, exc)
            )
            skipped_invalid += 1

    print("create_vector_functions: created {} functions from vector table "
          "({} valid entries, {} already existed, {} unused, {} invalid)".format(
              created, total_valid, already_existed, skipped_zero, skipped_invalid))


main()
