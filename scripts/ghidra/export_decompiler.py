# ripcord — Ghidra decompiler output export
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis
# completes. For each function, runs the Ghidra decompiler and
# captures the pseudo-C output. Writes JSONL: one record per
# function with the decompiled C string.
#
# The decompiler is significantly slower than other extractors
# (~30s timeout per function, 5-10 minutes for a 300-function
# binary). Not included in the default Snakefile ghidra_extract
# rule to avoid slowing every pipeline run.
#
# Output: JSONL, one record per function:
#   {"addr": 134235200, "name": "FUN_08027a50",
#    "decompiled_c": "void FUN_08027a50(void) {\n  ...\n}",
#    "decompile_success": true}
#
# Invoked standalone:
#   pyghidraRun -H <project_dir> <project_name> \
#       -import <binary> -overwrite \
#       -scriptPath scripts/ghidra \
#       -postScript export_decompiler.py <output.jsonl>

import json
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_decompiler.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def safe_str(value):
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()
    monitor = ConsoleTaskMonitor()

    # Initialize the decompiler
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(program)

    total = 0
    success = 0
    skipped = 0
    failed = 0

    with open(output_path, "w") as fh:
        for function in function_manager.getFunctions(True):
            # Skip external functions — no body to decompile
            if function.isExternal():
                skipped += 1
                continue

            entry = function.getEntryPoint()
            name = safe_str(function.getName()) or ""
            addr = int(entry.getOffset())

            try:
                result = decomp.decompileFunction(function, 30, monitor)
                decomp_func = result.getDecompiledFunction() if result else None
                if decomp_func:
                    c_code = decomp_func.getC()
                    if c_code:
                        record = {
                            "addr": addr,
                            "name": name,
                            "decompiled_c": c_code,
                            "decompile_success": True,
                        }
                        success += 1
                    else:
                        record = {
                            "addr": addr,
                            "name": name,
                            "decompiled_c": "",
                            "decompile_success": False,
                        }
                        failed += 1
                else:
                    error_msg = ""
                    if result:
                        error_msg = safe_str(result.getErrorMessage()) or ""
                    record = {
                        "addr": addr,
                        "name": name,
                        "decompiled_c": "",
                        "decompile_success": False,
                    }
                    if error_msg:
                        printerr(  # noqa: F821
                            "export_decompiler: {} (0x{:x}): {}".format(
                                name, addr, error_msg
                            )
                        )
                    failed += 1
            except Exception as exc:
                printerr(  # noqa: F821
                    "export_decompiler: exception on {} (0x{:x}): {}".format(
                        name, addr, exc
                    )
                )
                record = {
                    "addr": addr,
                    "name": name,
                    "decompiled_c": "",
                    "decompile_success": False,
                }
                failed += 1

            fh.write(json.dumps(record) + "\n")
            total += 1

    decomp.dispose()

    print(
        "export_decompiler: wrote {} functions to {} ({} success, {} failed, {} skipped)".format(
            total, output_path, success, failed, skipped
        )
    )


main()
