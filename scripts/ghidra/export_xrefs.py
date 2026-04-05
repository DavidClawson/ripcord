# ripcord — Ghidra non-call cross-reference export
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis
# completes. Iterates every reference originating inside a function
# body, filters out calls (which live in the `calls` table), and
# emits one JSON Lines row per remaining reference. The grain is
# (function_addr, from_addr, to_addr, ref_type).
#
# This captures every jump, fallthrough, data read/write, parameter
# reference, and thunk-pointer reference Ghidra's analyzers produced.
# Downstream queries typically filter by ref_type name to pick the
# subset they care about (e.g. data refs only, flow refs only).
#
# Invoked as a postScript alongside the other extractors:
#   -postScript export_xrefs.py <xrefs.jsonl>

import json
import sys


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_xrefs.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def describe_ref(function_entry, src_addr, ref):
    to_addr = ref.getToAddress()
    ref_type = ref.getReferenceType()
    return {
        "function_addr": int(function_entry.getOffset()),
        "from_addr": int(src_addr.getOffset()),
        "to_addr": int(to_addr.getOffset()) if to_addr is not None else None,
        "ref_type": str(ref_type.getName()),
        "is_primary": bool(ref.isPrimary()),
    }


def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()

    total = 0
    with open(output_path, "w") as fh:
        for function in function_manager.getFunctions(True):
            entry = function.getEntryPoint()
            body = function.getBody()
            if body is None:
                continue

            src_iter = reference_manager.getReferenceSourceIterator(body, True)
            while src_iter.hasNext():
                src_addr = src_iter.next()
                for ref in reference_manager.getReferencesFrom(src_addr):
                    if ref.getReferenceType().isCall():
                        continue  # calls handled by export_calls.py
                    try:
                        record = describe_ref(entry, src_addr, ref)
                    except Exception as exc:
                        printerr(  # noqa: F821 — Ghidra builtin
                            "export_xrefs: failed on {}@{}: {}".format(
                                function, src_addr, exc
                            )
                        )
                        continue
                    fh.write(json.dumps(record) + "\n")
                    total += 1

    print("export_xrefs: wrote {} non-call refs to {}".format(total, output_path))


main()
