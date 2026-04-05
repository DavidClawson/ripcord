# ripcord — Ghidra defined-string export
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis
# completes. Iterates defined string data in the program via
# DefinedDataIterator.definedStrings() — the canonical Ghidra API
# for post-analysis string discovery — and writes one JSON Lines row
# per string.
#
# `value` is the decoded string contents; `data_type` preserves the
# Ghidra DataType name (e.g. "string", "unicode", "TerminatedString")
# so downstream consumers that care about encoding can filter.
#
# Invoked as a postScript alongside the other extractors:
#   -postScript export_strings.py <strings.jsonl>

import json
import sys

from ghidra.program.model.data import StringDataInstance  # type: ignore


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_strings.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def main():
    # The older DefinedDataIterator.definedStrings(program) convenience
    # method was removed in Ghidra 12.x. The canonical modern path is
    # to iterate listing.getDefinedData() and filter via
    # StringDataInstance.isString(data).
    #
    # Additionally, getDefinedData() returns string data from every
    # address space — including the overlay spaces Ghidra uses for
    # DWARF debug sections (.debug_str, .comment). Those strings are
    # not in the loaded program and would pollute the table with
    # hundreds of toolchain-metadata artifacts. Filter to the
    # loaded+initialized address set so we only emit strings that
    # actually live in the binary's runtime memory image.
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    listing = program.getListing()
    loaded = program.getMemory().getLoadedAndInitializedAddressSet()

    total = 0
    with open(output_path, "w") as fh:
        for data in listing.getDefinedData(True):
            if not loaded.contains(data.getAddress()):
                continue
            if not StringDataInstance.isString(data):
                continue
            try:
                sdi = StringDataInstance.getStringDataInstance(data)
                value = sdi.getStringValue()
                if value is None:
                    continue
                record = {
                    "addr": int(data.getAddress().getOffset()),
                    "value": str(value),
                    "length": int(data.getLength()),
                    "data_type": str(data.getDataType().getName()),
                }
            except Exception as exc:
                printerr(  # noqa: F821 — Ghidra builtin
                    "export_strings: failed at {}: {}".format(
                        data.getAddress() if data is not None else "<none>", exc
                    )
                )
                continue
            fh.write(json.dumps(record) + "\n")
            total += 1

    print("export_strings: wrote {} strings to {}".format(total, output_path))


main()
