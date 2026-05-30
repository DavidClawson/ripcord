# ripcord — Harvest pointer-reached functions to a fixpoint (postScript).
#
# Ghidra's recursive descent follows direct calls and the vector table, so it
# misses every function that is reachable ONLY through a stored code pointer:
#   - FreeRTOS task bodies (passed to xTaskCreate as a pointer arg),
#   - callback / dispatch tables in .rodata,
#   - handlers loaded from a literal pool into a register and called indirect.
# create_vector_functions.py handles the vector table and create_seed_functions
# handles hand-known addresses; this is the GENERIC version of the same idea —
# it derives its candidates from the image itself, with no target knowledge.
#
# Algorithm (scan -> create -> cascade, repeated to a fixpoint):
#   1. Scan every initialized memory block as a stream of 32-bit LE words.
#   2. A word is a code-pointer candidate when bit0 is set (ARM Thumb bit) and
#      (word & ~1) lands, halfword-aligned, inside an executable block.
#   3. Accept the target only if it is not already a function and not interior
#      to one, AND it either (a) already holds a decoded instruction (orphan
#      code the aggressive instruction finder decoded but never made a function)
#      or (b) opens with a canonical non-leaf prologue: `push {...,lr}` (0xB5xx)
#      or `push.w {...,lr}` (0xE92D, LR bit set). This is deliberately
#      high-precision: a literal pool is full of 32-bit words that happen to
#      have bit0 set and point into the code range, so the prologue gate is what
#      separates real entry points from coincidence. The Unicorn smoke test
#      (scripts/validation/unicorn_validate.py) culls anything that still slips
#      through as data-decoded-as-code.
#   4. Create a function at each accepted target, then analyzeChanges() so the
#      call tree BELOW it is decoded too (and so the now-enabled switch analysis
#      resolves any jump tables the new bodies contain).
#   5. Re-scan. A freshly decoded body can expose a new literal pool with more
#      code pointers, so repeat until a round adds nothing (the fixpoint) or the
#      round cap is hit.
#
# This finds function ENTRIES reached by pointer. It does NOT decode the
# intra-function cases of a TBH/TBB jump table (those are pc-relative computed
# offsets, not stored absolute pointers, and belong to one enclosing function) —
# that is the job of Ghidra's Decompiler Switch Analysis, enabled in
# set_aggressive_analysis.py.
#
# Generic: keep target-specific addresses in seeds.txt, not here.
# Runs AFTER create_vector_functions.py + create_seed_functions.py and BEFORE
# the export scripts, so harvested functions are in every extracted table.
#
# Invoked as:  -postScript harvest_pointers.py

MAX_ROUNDS = 8
PLATE = "ripcord: pointer-harvested entry"


def executable_range(program):
    """(min, max_exclusive) offsets spanned by executable memory blocks."""
    lo = hi = None
    for block in program.getMemory().getBlocks():
        if not block.isExecute():
            continue
        s = block.getStart().getOffset()
        e = block.getEnd().getOffset() + 1
        lo = s if lo is None else min(lo, s)
        hi = e if hi is None else max(hi, e)
    return lo, hi


def initialized_blocks(program):
    return [b for b in program.getMemory().getBlocks() if b.isInitialized()]


def looks_like_prologue(memory, tgt):
    """True if the halfword(s) at tgt are a canonical LR-saving prologue."""
    try:
        hw0 = memory.getShort(toAddr(tgt)) & 0xFFFF  # noqa: F821 — Ghidra builtin
    except Exception:
        return False
    if (hw0 & 0xFF00) == 0xB500:                      # push {...,lr}
        return True
    if hw0 == 0xE92D:                                  # push.w {...}
        try:
            hw1 = memory.getShort(toAddr(tgt + 2)) & 0xFFFF  # noqa: F821
        except Exception:
            return False
        return (hw1 & 0x4000) != 0                      # LR present in reglist
    return False


def scan_round(program, exec_lo, exec_hi, failed):
    """Return the set of accepted, not-yet-created target offsets this round."""
    memory = program.getMemory()
    fm = program.getFunctionManager()
    listing = program.getListing()
    found = set()
    seen_words = set()  # don't re-test the same pointer value repeatedly

    # getInt reads a 32-bit LE word (program endianness); per-word JNI calls,
    # but only over initialized bytes so it never throws on a gap. Proven idiom
    # from create_vector_functions.read_u32 (PyGhidra is CPython+JPype, where
    # Jython's bulk-array helpers are unavailable).
    for block in initialized_blocks(program):
        a = block.getStart().getOffset()
        end = block.getEnd().getOffset()  # inclusive last byte of the block
        while a + 3 <= end:
            v = memory.getInt(toAddr(a)) & 0xFFFFFFFF  # noqa: F821 — Ghidra builtin
            a += 4
            if not (v & 1):
                continue
            tgt = v & ~1
            if tgt < exec_lo or tgt >= exec_hi:
                continue
            if tgt in failed or tgt in found or v in seen_words:
                continue
            seen_words.add(v)
            addr = toAddr(tgt)  # noqa: F821 — Ghidra builtin
            if fm.getFunctionAt(addr) is not None:
                continue                              # already an entry
            if fm.getFunctionContaining(addr) is not None:
                continue                              # interior to a function
            # Accept orphan decoded code outright; otherwise require a prologue.
            if listing.getInstructionAt(addr) is not None or looks_like_prologue(memory, tgt):
                found.add(tgt)
    return found


def main():
    program = currentProgram  # noqa: F821 — Ghidra builtin
    if "ARM" not in str(program.getLanguageID()):
        print("harvest_pointers: not an ARM program, skipping")
        return
    exec_lo, exec_hi = executable_range(program)
    if exec_lo is None:
        print("harvest_pointers: no executable blocks, skipping")
        return

    listing = program.getListing()
    failed = set()
    total = 0
    for rnd in range(1, MAX_ROUNDS + 1):
        cands = scan_round(program, exec_lo, exec_hi, failed)
        if not cands:
            print("harvest_pointers: round %d found no new candidates (fixpoint)" % rnd)
            break
        created = 0
        for tgt in sorted(cands):
            addr = toAddr(tgt)  # noqa: F821 — Ghidra builtin
            try:
                disassemble(addr)  # noqa: F821 — Ghidra builtin
                func = createFunction(addr, None)  # noqa: F821 — default FUN_ name
            except Exception as exc:
                printerr("harvest_pointers: create 0x%X failed: %s" % (tgt, exc))  # noqa: F821
                func = None
            if func is not None:
                created += 1
                try:
                    from ghidra.program.model.listing import CodeUnit
                    listing.setComment(addr, CodeUnit.PLATE_COMMENT, PLATE)
                except Exception:
                    pass
            else:
                failed.add(tgt)  # don't re-attempt a target that won't cut
        total += created
        print("harvest_pointers: round %d created %d (candidates %d, cumulative %d)"
              % (rnd, created, len(cands), total))
        if created == 0:
            break
        # Cascade: decode callees of the new entries and resolve their jump
        # tables. analyzeChanges processes only the pending change set (unlike
        # reAnalyzeAll, which deadlocks headless at 0% CPU).
        try:
            analyzeChanges(program)  # noqa: F821 — Ghidra builtin
        except Exception as exc:
            printerr("harvest_pointers: analyzeChanges skipped: %s" % exc)  # noqa: F821
    else:
        print("harvest_pointers: hit round cap %d without converging" % MAX_ROUNDS)

    print("harvest_pointers: created %d pointer-reached functions total" % total)


main()
