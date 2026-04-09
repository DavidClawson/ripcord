# ripcord — Ghidra function metadata export
#
# Python 3 postScript run by `pyghidraRun -H` (analyzeHeadless launched
# under PyGhidra) after auto-analysis completes. Writes per-function
# metadata as JSON Lines to a path passed on the command line.
#
# Invoked by the Snakemake ghidra_export rule as:
#   pyghidraRun -H <project_dir> <project_name> \
#       -import <elf> \
#       -overwrite \
#       -scriptPath scripts/ghidra \
#       -postScript export_functions.py <output_jsonl_path>
#
# The current Ghidra program is available via `currentProgram`.
# The script arguments are available via `getScriptArgs()`.
#
# Uses only the standard library on purpose — keeps the extractor
# cheap to invoke and its output eyeballable as text. The ingest
# script is where rows get typed and written to Parquet.

import hashlib
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


def body_hash(function, memory):
    """SHA-256 of the raw bytes covering the function body.

    Returns the hex digest, or None if the body is empty or
    unreadable (e.g. external/overlay functions with no backing bytes).

    Reads from getMinAddress() for getNumAddresses() bytes. This is
    correct for contiguous function bodies (the common case on ARM).
    For non-contiguous bodies the hash covers the full address span
    including any gaps — acceptable for fingerprinting since the gap
    bytes are deterministic for a given binary.
    """
    body = function.getBody()
    if body is None:
        return None
    nbytes = int(body.getNumAddresses())
    if nbytes <= 0:
        return None
    try:
        import jpype  # type: ignore — available under PyGhidra
        buf = jpype.JArray(jpype.JByte)(nbytes)
        got = memory.getBytes(body.getMinAddress(), buf)
        if got != nbytes:
            return None
        # Convert signed Java bytes to unsigned Python bytes
        return hashlib.sha256(bytes([b & 0xFF for b in buf])).hexdigest()
    except Exception:
        return None


def describe_function(function, block_model, monitor, memory):
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
        "body_hash": body_hash(function, memory),
    }


def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()
    block_model = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()
    memory = program.getMemory()

    total = 0
    with open(output_path, "w") as fh:
        for function in function_manager.getFunctions(True):
            try:
                record = describe_function(function, block_model, monitor, memory)
            except Exception as exc:
                printerr(  # noqa: F821 — Ghidra builtin
                    "export_functions: failed on {}: {}".format(function, exc)
                )
                continue
            fh.write(json.dumps(record) + "\n")
            total += 1

    print("export_functions: wrote {} functions to {}".format(total, output_path))


main()
