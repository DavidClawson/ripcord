# ripcord — Ghidra function metadata export
#
# Ghidrathon script (Python 3) run by analyzeHeadless after auto-analysis.
# Writes per-function metadata as JSON Lines to a path passed on the
# command line.
#
# Invoked by the Snakemake ghidra_export rule as:
#   analyzeHeadless <project_dir> <project_name> \
#       -import <elf> \
#       -overwrite \
#       -scriptPath scripts/ghidra \
#       -postScript export_functions.py <output_jsonl_path>
#
# The current Ghidra program is available via `currentProgram`.
# The script arguments are available via `getScriptArgs()`.
#
# Requires Ghidrathon to be installed and the Python environment it
# points at to be usable (standard library is sufficient for this
# script — no pyarrow/duckdb needed inside Ghidra).

import json
import sys

# Ghidra API imports. These only resolve when the script is run inside
# Ghidra (via analyzeHeadless or the Ghidra GUI with Ghidrathon).
from ghidra.program.model.block import BasicBlockModel  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_functions.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def count_basic_blocks(function, block_model, monitor):
    body = function.getBody()
    blocks = block_model.getCodeBlocksContaining(body, monitor)
    count = 0
    while blocks.hasNext():
        blocks.next()
        count += 1
    return count


def safe_str(value):
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def describe_function(function, block_model, monitor):
    entry = function.getEntryPoint()
    body = function.getBody()

    try:
        num_params = int(function.getParameterCount())
    except Exception:
        num_params = None

    try:
        cc = function.getCallingConventionName()
    except Exception:
        cc = None

    return {
        "addr": int(entry.getOffset()),
        "name": safe_str(function.getName()) or "",
        "size": int(body.getNumAddresses()) if body is not None else None,
        "is_thunk": bool(function.isThunk()),
        "is_external": bool(function.isExternal()),
        "num_params": num_params,
        "has_varargs": bool(function.hasVarArgs()),
        "calling_convention": safe_str(cc),
        "basic_block_count": count_basic_blocks(function, block_model, monitor),
        "signature": safe_str(function.getSignature()),
    }


def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()
    block_model = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()

    total = 0
    with open(output_path, "w") as fh:
        for function in function_manager.getFunctions(True):
            try:
                record = describe_function(function, block_model, monitor)
            except Exception as exc:
                printerr(  # noqa: F821 — Ghidra builtin
                    "export_functions: failed on {}: {}".format(function, exc)
                )
                continue
            fh.write(json.dumps(record) + "\n")
            total += 1

    print("export_functions: wrote {} functions to {}".format(total, output_path))


main()
