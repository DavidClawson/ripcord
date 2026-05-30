# ripcord — Ghidra decompiler output export
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis
# completes. For each function, runs the Ghidra decompiler and
# captures the pseudo-C output. Writes JSONL: one record per
# function with the decompiled C string.
#
# Decompilation is the slowest extractor (~30s timeout per function).
# Within a single function the decompiler is serial, but functions are
# independent, so we fan out across a thread pool: each worker thread
# owns its own DecompInterface (and thus its own native `decompile`
# subprocess). PyGhidra runs CPython via JPype, which releases the GIL
# across JVM calls, so the blocking decompileFunction calls run
# concurrently and saturate multiple cores. On an 8-perf-core machine
# this is a ~5-6x wall-clock win over the previous serial loop.
#
# Results are sorted by address before writing, so the JSONL output is
# byte-identical to the old serial version (which emitted in
# getFunctions(True) / entry-point order).
#
# Worker count resolution: optional 2nd script arg > $RIPCORD_DECOMP_WORKERS
# > min(8, os.cpu_count()). 1 worker reproduces the old serial behavior.
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
#       -postScript export_decompiler.py <output.jsonl> [workers]

import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

DECOMPILE_TIMEOUT_SECS = 30


def get_args():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_decompiler.py <output.jsonl> [workers]")  # noqa: F821
        sys.exit(1)
    output_path = args[0]
    workers = None
    if len(args) >= 2 and args[1].strip():
        workers = args[1].strip()
    return output_path, workers


def resolve_workers(arg_workers):
    raw = arg_workers or os.environ.get("RIPCORD_DECOMP_WORKERS")
    if raw:
        try:
            n = int(raw)
            if n >= 1:
                return n
        except ValueError:
            printerr(  # noqa: F821
                "export_decompiler: ignoring non-integer worker count {!r}".format(raw)
            )
    return min(8, os.cpu_count() or 4)


def safe_str(value):
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def main():
    output_path, arg_workers = get_args()
    workers = resolve_workers(arg_workers)
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()

    # Materialize the work list in the main thread; skip external
    # functions (no body to decompile). Capture name/addr here so the
    # worker threads only touch the Function object via the decompiler.
    work = []
    skipped = 0
    for function in function_manager.getFunctions(True):
        if function.isExternal():
            skipped += 1
            continue
        entry = function.getEntryPoint()
        work.append(
            (function, int(entry.getOffset()), safe_str(function.getName()) or "")
        )

    # Each worker thread lazily builds its own DecompInterface + monitor.
    # Track them so we can dispose them all at the end.
    tls = threading.local()
    created = []
    created_lock = threading.Lock()

    def get_decomp():
        decomp = getattr(tls, "decomp", None)
        if decomp is None:
            decomp = DecompInterface()
            options = DecompileOptions()
            decomp.setOptions(options)
            decomp.openProgram(program)
            tls.decomp = decomp
            tls.monitor = ConsoleTaskMonitor()
            with created_lock:
                created.append(decomp)
        return decomp, tls.monitor

    def decompile_one(item):
        function, addr, name = item
        decomp, monitor = get_decomp()
        try:
            result = decomp.decompileFunction(function, DECOMPILE_TIMEOUT_SECS, monitor)
            decomp_func = result.getDecompiledFunction() if result else None
            if decomp_func:
                c_code = decomp_func.getC()
                if c_code:
                    return (
                        addr,
                        {
                            "addr": addr,
                            "name": name,
                            "decompiled_c": c_code,
                            "decompile_success": True,
                        },
                        "success",
                    )
                return (
                    addr,
                    {
                        "addr": addr,
                        "name": name,
                        "decompiled_c": "",
                        "decompile_success": False,
                    },
                    "failed",
                )
            error_msg = ""
            if result:
                error_msg = safe_str(result.getErrorMessage()) or ""
            if error_msg:
                printerr(  # noqa: F821
                    "export_decompiler: {} (0x{:x}): {}".format(name, addr, error_msg)
                )
            return (
                addr,
                {
                    "addr": addr,
                    "name": name,
                    "decompiled_c": "",
                    "decompile_success": False,
                },
                "failed",
            )
        except Exception as exc:
            printerr(  # noqa: F821
                "export_decompiler: exception on {} (0x{:x}): {}".format(
                    name, addr, exc
                )
            )
            return (
                addr,
                {
                    "addr": addr,
                    "name": name,
                    "decompiled_c": "",
                    "decompile_success": False,
                },
                "failed",
            )

    print(
        "export_decompiler: decompiling {} functions with {} worker(s)".format(
            len(work), workers
        )
    )

    results = []
    success = 0
    failed = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for addr, record, status in pool.map(decompile_one, work):
                results.append((addr, record))
                if status == "success":
                    success += 1
                else:
                    failed += 1
    finally:
        for decomp in created:
            try:
                decomp.dispose()
            except Exception:
                pass

    # Sort by address so output order matches the old serial loop
    # (getFunctions(True) yields entry-point-ascending order).
    results.sort(key=lambda r: r[0])

    total = 0
    with open(output_path, "w") as fh:
        for _addr, record in results:
            fh.write(json.dumps(record) + "\n")
            total += 1

    print(
        "export_decompiler: wrote {} functions to {} ({} success, {} failed, {} skipped)".format(
            total, output_path, success, failed, skipped
        )
    )


main()
