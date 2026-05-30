# ripcord — Create Ghidra functions from a target-specific seed list.
#
# PyGhidra postScript. Reads a seed file (one "0xADDR [name]" per line) and
# forces a function at each address, even when Ghidra mis-decoded a truncated
# or overlapping function there. This recovers code that recursive descent
# never reached on a raw, symbol-less import — most importantly FreeRTOS task
# bodies, which are passed to xTaskCreate as *pointers* and therefore have no
# direct call site for Ghidra to follow. After seeding the roots it re-runs
# auto-analysis so the call tree *below* each seed gets decoded too (the
# cascade), turning a handful of seeds into the whole subsystem.
#
# Seeds are DATA (target-specific knowledge), kept out of the generic
# extractors per the project's "keep the tooling generic" rule.
#
# Invoked as:  -postScript create_seed_functions.py <seedfile>
# If <seedfile> is missing or empty, this is a no-op (so the same Snakemake
# rule works for every target whether or not it has a seed list).
#
# Must run AFTER create_vector_functions.py and BEFORE the export scripts so
# the newly created functions are included in every extraction.

import os
import sys


def parse_seeds(path):
    """Parse "0xADDR [name] [size]" lines; '#'-comments and blanks ignored.

    Optional size (decimal or 0x-hex) is the function's byte length. When
    given, the whole [addr, addr+size) range is force-disassembled so a large
    body gated by an unrecovered jump table is fully decoded rather than cut
    at the first undisassembled byte.
    """
    seeds = []
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            try:
                addr = int(parts[0], 16)
            except ValueError:
                printerr("create_seed_functions: bad seed line: %r" % raw)  # noqa: F821
                continue
            name = parts[1] if len(parts) > 1 else None
            size = None
            if len(parts) > 2:
                size = int(parts[2], 0)
            seeds.append((addr, name, size))
    return seeds


def force_disassemble_range(program, start_long, size):
    """Thumb-disassemble every instruction in [start, start+size)."""
    from ghidra.app.cmd.disassemble import ArmDisassembleCommand
    from ghidra.program.model.address import AddressSet
    start = toAddr(start_long)              # noqa: F821 — Ghidra builtin
    end = toAddr(start_long + size - 1)     # noqa: F821 — Ghidra builtin
    aset = AddressSet(start, end)
    cmd = ArmDisassembleCommand(aset, None, True)  # thumbMode=True (Cortex-M)
    cmd.applyTo(program, monitor)            # noqa: F821 — Ghidra builtin


def main():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        print("create_seed_functions: no seedfile arg, skipping")
        return
    seedfile = args[0]
    if not os.path.isfile(seedfile) or os.path.getsize(seedfile) == 0:
        print("create_seed_functions: seedfile %r missing/empty, skipping" % seedfile)
        return

    program = currentProgram  # noqa: F821 — Ghidra builtin
    fm = program.getFunctionManager()
    seeds = parse_seeds(seedfile)

    created = 0
    recut = 0
    existed = 0
    failed = 0

    for addr_long, name, size in seeds:
        # Strip the ARM Thumb bit (bit 0). FreeRTOS task pointers and other
        # code pointers are stored odd; instructions are halfword-aligned, so
        # createFunction at the odd address fails. Mask exactly as the
        # vector-table seeder does (target = raw & ~1).
        addr_long &= ~1
        addr = toAddr(addr_long)  # noqa: F821 — Ghidra builtin

        # Remove any function AT this address (so re-runs re-cut a fresh body
        # once the full range is disassembled) or a truncated function that
        # merely OVERLAPS it (mis-cut start elsewhere).
        at = fm.getFunctionAt(addr)
        if at is not None:
            try:
                fm.removeFunction(addr)
                existed += 1
            except Exception:
                pass
        else:
            containing = fm.getFunctionContaining(addr)
            if containing is not None and containing.getEntryPoint().getOffset() != addr_long:
                try:
                    fm.removeFunction(containing.getEntryPoint())
                    recut += 1
                except Exception as exc:
                    printerr("create_seed_functions: could not remove overlap at 0x%X: %s"  # noqa: F821
                             % (containing.getEntryPoint().getOffset(), exc))

        try:
            if size:
                # Force the WHOLE body to exist before cutting the function,
                # so a jump-table-gated tail isn't left undisassembled.
                force_disassemble_range(program, addr_long, size)
            else:
                disassemble(addr)  # noqa: F821 — Ghidra builtin
            func = createFunction(addr, name)  # noqa: F821 — Ghidra builtin
            if func is not None:
                created += 1
            else:
                failed += 1
                printerr("create_seed_functions: createFunction None at 0x%X" % addr_long)  # noqa: F821
        except Exception as exc:
            failed += 1
            printerr("create_seed_functions: seed 0x%X failed: %s" % (addr_long, exc))  # noqa: F821

    # Analyze ONLY the freshly disassembled/created seed regions so switch
    # recovery resolves jump tables (extending big bodies) and callees get
    # picked up. analyzeChanges() processes just the pending change set and
    # returns — unlike AutoAnalysisManager.reAnalyzeAll()+startAnalysis(),
    # which marks the whole program and deadlocks at 0% CPU under headless.
    try:
        analyzeChanges(program)  # noqa: F821 — Ghidra builtin
    except Exception as exc:
        printerr("create_seed_functions: analyzeChanges skipped: %s" % exc)  # noqa: F821

    print("create_seed_functions: created %d, re-cut %d overlapping, existed %d, failed %d"
          % (created, recut, existed, failed))


main()
