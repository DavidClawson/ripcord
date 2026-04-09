# ripcord — Ghidra P-Code feature export
#
# Python 3 postScript run by `pyghidraRun -H` after auto-analysis
# completes. For each non-thunk function with body size >= 8 bytes,
# extracts P-Code opcode features: histogram, total ops, unique
# opcodes, and a sequence hash (SHA-256 of the concatenated opcode
# sequence). These features are ISA-invariant by construction —
# P-Code is Ghidra's intermediate representation, normalized across
# architectures, register allocations, and instruction encodings.
#
# This is the prerequisite for cross-ISA fingerprinting (design
# decision D9 in notes/design-decisions.md).
#
# Output: JSONL, one record per function:
#   {"addr": 268435904, "pcode_ops_total": 45, "pcode_unique_opcodes": 12,
#    "pcode_histogram": {"COPY": 8, "INT_ADD": 5, ...},
#    "pcode_sequence_hash": "abc123..."}
#
# Invoked as a postScript alongside the other extractors:
#   -postScript export_pcode.py <pcode.jsonl>

import hashlib
import json
import sys


def get_output_path():
    args = getScriptArgs()  # noqa: F821 — Ghidra builtin
    if len(args) < 1:
        printerr("usage: export_pcode.py <output.jsonl>")  # noqa: F821
        sys.exit(1)
    return args[0]


def extract_pcode_features(function, listing):
    """Extract P-Code opcode features for a single function.

    Returns a dict with pcode_ops_total, pcode_unique_opcodes,
    pcode_histogram (opcode -> count), and pcode_sequence_hash
    (SHA-256 of the concatenated opcode name sequence).
    """
    histogram = {}
    sequence = []

    for instruction in listing.getInstructions(function.getBody(), True):
        pcode_ops = instruction.getPcode()
        if pcode_ops is None:
            continue
        for op in pcode_ops:
            opcode_name = op.getMnemonic()
            histogram[opcode_name] = histogram.get(opcode_name, 0) + 1
            sequence.append(opcode_name)

    total = sum(histogram.values())
    unique = len(histogram)

    # SHA-256 of the opcode sequence for exact-match fingerprinting
    seq_str = ",".join(sequence)
    seq_hash = hashlib.sha256(seq_str.encode("utf-8")).hexdigest()

    return {
        "pcode_ops_total": total,
        "pcode_unique_opcodes": unique,
        "pcode_histogram": histogram,
        "pcode_sequence_hash": seq_hash,
    }


def main():
    output_path = get_output_path()
    program = currentProgram  # noqa: F821 — Ghidra builtin
    function_manager = program.getFunctionManager()
    listing = program.getListing()

    total = 0
    skipped = 0
    with open(output_path, "w") as fh:
        for function in function_manager.getFunctions(True):
            # Skip thunks — they have no real body to analyze
            if function.isThunk():
                skipped += 1
                continue

            # Skip tiny functions (< 8 bytes) — not enough signal
            body = function.getBody()
            if body is None or int(body.getNumAddresses()) < 8:
                skipped += 1
                continue

            try:
                features = extract_pcode_features(function, listing)
            except Exception as exc:
                printerr(  # noqa: F821 — Ghidra builtin
                    "export_pcode: failed on {}: {}".format(function, exc)
                )
                continue

            # Skip functions where P-Code extraction yielded nothing
            if features["pcode_ops_total"] == 0:
                skipped += 1
                continue

            entry = function.getEntryPoint()
            record = {
                "addr": int(entry.getOffset()),
                "pcode_ops_total": features["pcode_ops_total"],
                "pcode_unique_opcodes": features["pcode_unique_opcodes"],
                "pcode_histogram": features["pcode_histogram"],
                "pcode_sequence_hash": features["pcode_sequence_hash"],
            }
            fh.write(json.dumps(record) + "\n")
            total += 1

    print(
        "export_pcode: wrote {} functions to {} (skipped {})".format(
            total, output_path, skipped
        )
    )


main()
