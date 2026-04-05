# ripcord — Ghidra call reference export
#
# Python 3 postScript run by `pyghidraRun -H` (analyzeHeadless launched
# under PyGhidra) after auto-analysis completes. Iterates every call
# reference in every function body and writes one JSON Lines row per
# call site. The grain is (caller_addr, call_site_addr, callee_addr):
# a function with N distinct call instructions produces N rows; a
# caller that calls the same callee twice produces two rows, each
# with a different call_site_addr.
#
# Invoked alongside export_functions.py as a second -postScript in
# the same Ghidra session (so auto-analysis runs once):
#
#   pyghidraRun -H <project_dir> <project_name> \
#       -import <elf> \
#       -overwrite \
#       -scriptPath scripts/ghidra \
#       -postScript export_functions.py <functions.jsonl> \
#       -postScript export_calls.py      <calls.jsonl>
#
# Indirect calls whose targets Ghidra cannot statically resolve are
# emitted with callee_addr=null and is_computed=true. Downstream
# queries should handle both cases.

import json
import sys

# Ghidra API imports resolve only inside a running Ghidra session.


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_calls.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def describe_call_ref(caller_entry, src_addr, ref):
    ref_type = ref.getReferenceType()
    to_addr = ref.getToAddress()
    return {
        "caller_addr": int(caller_entry.getOffset()),
        "call_site_addr": int(src_addr.getOffset()),
        "callee_addr": int(to_addr.getOffset()) if to_addr is not None else None,
        "ref_type": str(ref_type.getName()),
        "is_computed": bool(ref_type.isComputed()),
        "is_conditional": bool(ref_type.isConditional()),
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

            # getReferenceSourceIterator visits only addresses that have
            # outgoing references inside the given AddressSetView — far
            # cheaper than iterating every byte in the function body.
            src_iter = reference_manager.getReferenceSourceIterator(body, True)
            while src_iter.hasNext():
                src_addr = src_iter.next()
                for ref in reference_manager.getReferencesFrom(src_addr):
                    if not ref.getReferenceType().isCall():
                        continue
                    try:
                        record = describe_call_ref(entry, src_addr, ref)
                    except Exception as exc:
                        printerr(  # noqa: F821 — Ghidra builtin
                            "export_calls: failed on {}@{}: {}".format(
                                function, src_addr, exc
                            )
                        )
                        continue
                    fh.write(json.dumps(record) + "\n")
                    total += 1

    print("export_calls: wrote {} call references to {}".format(total, output_path))


main()
