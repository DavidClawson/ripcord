# ripcord — Ghidra basic block export
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis
# completes. Iterates every code block in the program via
# BasicBlockModel.getCodeBlocks(), looks up the containing function
# for each block, counts instructions inside the block, and writes
# one JSON Lines row per block.
#
# Iterating program-wide and looking up containment (rather than
# iterating per-function and asking for "blocks in this function's
# body") guarantees each block is emitted exactly once, even if two
# functions happen to share a block. Blocks that fall outside any
# function body get function_addr=null — typically rare, but it
# happens when the disassembler finds code the function analyzer
# doesn't claim.
#
# Invoked as a postScript alongside the other extractors:
#   -postScript export_basic_blocks.py <basic_blocks.jsonl>

import json
import sys

from ghidra.program.model.block import BasicBlockModel  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_basic_blocks.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def count_instructions(listing, block):
    instr_iter = listing.getInstructions(block, True)
    count = 0
    while instr_iter.hasNext():
        instr_iter.next()
        count += 1
    return count


def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    block_model = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()

    total = 0
    with open(output_path, "w") as fh:
        cb_iter = block_model.getCodeBlocks(monitor)
        while cb_iter.hasNext():
            block = cb_iter.next()
            block_start = block.getFirstStartAddress()

            containing = function_manager.getFunctionContaining(block_start)
            function_addr = (
                int(containing.getEntryPoint().getOffset())
                if containing is not None
                else None
            )

            try:
                instr_count = count_instructions(listing, block)
            except Exception as exc:
                printerr(  # noqa: F821 — Ghidra builtin
                    "export_basic_blocks: instr count failed at {}: {}".format(
                        block_start, exc
                    )
                )
                instr_count = None

            record = {
                "function_addr": function_addr,
                "block_addr": int(block_start.getOffset()),
                "block_size": int(block.getNumAddresses()),
                "instruction_count": instr_count,
            }
            fh.write(json.dumps(record) + "\n")
            total += 1

    print("export_basic_blocks: wrote {} blocks to {}".format(total, output_path))


main()
