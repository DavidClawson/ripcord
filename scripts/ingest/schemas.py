"""Central pyarrow schema definitions for the ripcord warehouse.

One module, one table per entry in TABLES. Each table has a
pyarrow schema and a row-transform function that takes a dict
parsed from the Ghidra JSONL output, the target `source` name,
and the extraction timestamp, and returns a dict matching the
schema.

This is the single source of truth for analytical-warehouse
column types. Adding a new table: add the schema, add the
transform, add the name to TABLES and ROW_TRANSFORMS, add a
Snakemake rule that invokes load_table.py with --table <name>.

Ground-truth tables populated by non-JSONL sources (e.g.
ground_truth_functions from `nm`) do not live here; they define
their schemas inline in their loader scripts because the loader
does data acquisition in addition to ingest.
"""

from __future__ import annotations

from typing import Callable

import pyarrow as pa


# ---------------------------------------------------------------------------
# functions — one row per Ghidra-discovered function body
# ---------------------------------------------------------------------------

FUNCTIONS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("addr", pa.int64()),
        ("name", pa.string()),
        ("size", pa.int64()),
        ("is_thunk", pa.bool_()),
        ("is_external", pa.bool_()),
        ("num_params", pa.int32()),
        ("has_varargs", pa.bool_()),
        ("calling_convention", pa.string()),
        ("basic_block_count", pa.int32()),
        ("signature", pa.string()),
        ("body_hash", pa.string()),  # SHA-256 of raw function bytes
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def functions_row(rec: dict, source: str, extracted_at) -> dict:
    return {
        "source": source,
        "addr": int(rec["addr"]),
        "name": rec.get("name") or "",
        "size": rec.get("size"),
        "is_thunk": rec.get("is_thunk"),
        "is_external": rec.get("is_external"),
        "num_params": rec.get("num_params"),
        "has_varargs": rec.get("has_varargs"),
        "calling_convention": rec.get("calling_convention"),
        "basic_block_count": rec.get("basic_block_count"),
        "signature": rec.get("signature"),
        "body_hash": rec.get("body_hash"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# calls — one row per call reference (call instruction -> target)
# ---------------------------------------------------------------------------
#
# A single caller may contain many call sites; a single callee may be
# referenced from many call sites. The grain is (caller_addr,
# call_site_addr, callee_addr). For indirect/computed calls where
# Ghidra cannot statically resolve the target, callee_addr is NULL and
# is_computed=true. ref_type is the Ghidra RefType name string (e.g.
# UNCONDITIONAL_CALL, COMPUTED_CALL, CONDITIONAL_CALL) for fidelity.

CALLS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("caller_addr", pa.int64()),
        ("call_site_addr", pa.int64()),
        ("callee_addr", pa.int64()),  # nullable for unresolved computed calls
        ("ref_type", pa.string()),
        ("is_computed", pa.bool_()),
        ("is_conditional", pa.bool_()),
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def calls_row(rec: dict, source: str, extracted_at) -> dict:
    callee = rec.get("callee_addr")
    return {
        "source": source,
        "caller_addr": int(rec["caller_addr"]),
        "call_site_addr": int(rec["call_site_addr"]),
        "callee_addr": int(callee) if callee is not None else None,
        "ref_type": rec.get("ref_type"),
        "is_computed": rec.get("is_computed"),
        "is_conditional": rec.get("is_conditional"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# basic_blocks — one row per Ghidra code block
# ---------------------------------------------------------------------------
#
# Extracted by iterating BasicBlockModel.getCodeBlocks over the whole
# program, not per-function, so blocks shared between functions (rare)
# aren't double-counted. function_addr is the containing function's
# entry point or NULL for blocks in code outside any function body
# (e.g. Ghidra-detected code the function analyzer didn't claim).

BASIC_BLOCKS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("function_addr", pa.int64()),  # nullable
        ("block_addr", pa.int64()),
        ("block_size", pa.int64()),  # in bytes (address count)
        ("instruction_count", pa.int32()),
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def basic_blocks_row(rec: dict, source: str, extracted_at) -> dict:
    function_addr = rec.get("function_addr")
    return {
        "source": source,
        "function_addr": int(function_addr) if function_addr is not None else None,
        "block_addr": int(rec["block_addr"]),
        "block_size": int(rec["block_size"]),
        "instruction_count": rec.get("instruction_count"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# xrefs — one row per non-call reference from within a function body
# ---------------------------------------------------------------------------
#
# Call references live in the `calls` table; every other reference
# lives here: jumps (flow), fallthroughs, data reads/writes, parameter
# references, thunk-pointer references, etc. Downstream queries
# typically filter by ref_type to pick a subset (e.g. WHERE ref_type
# LIKE '%DATA%' for data accesses only).
#
# function_addr is the containing function's entry point — analogous
# to calls.caller_addr. from_addr is the specific instruction making
# the reference. to_addr is the target and may be NULL for computed
# references Ghidra cannot statically resolve.

XREFS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("function_addr", pa.int64()),
        ("from_addr", pa.int64()),
        ("to_addr", pa.int64()),  # nullable for computed/unresolved refs
        ("ref_type", pa.string()),
        ("is_primary", pa.bool_()),
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def xrefs_row(rec: dict, source: str, extracted_at) -> dict:
    to = rec.get("to_addr")
    return {
        "source": source,
        "function_addr": int(rec["function_addr"]),
        "from_addr": int(rec["from_addr"]),
        "to_addr": int(to) if to is not None else None,
        "ref_type": rec.get("ref_type"),
        "is_primary": rec.get("is_primary"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# strings — one row per defined string in the binary
# ---------------------------------------------------------------------------
#
# Populated via DefinedDataIterator.definedStrings(program), which is
# Ghidra's canonical iterator over analysis-recognized string data
# (C strings, Pascal strings, Unicode strings, etc. — whatever the
# string analyzer classified). `value` is the decoded string content;
# `data_type` preserves the Ghidra DataType name for fidelity.

STRINGS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("addr", pa.int64()),
        ("value", pa.string()),
        ("length", pa.int32()),  # bytes, including terminator if any
        ("data_type", pa.string()),
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def strings_row(rec: dict, source: str, extracted_at) -> dict:
    return {
        "source": source,
        "addr": int(rec["addr"]),
        "value": rec.get("value") or "",
        "length": rec.get("length"),
        "data_type": rec.get("data_type"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# pcode_features — one row per function with P-Code opcode features
# ---------------------------------------------------------------------------
#
# ISA-invariant features extracted from Ghidra's P-Code intermediate
# representation. The histogram is a JSON-encoded dict of opcode names
# to counts; the sequence hash is SHA-256 of the ordered opcode stream.
# These enable cross-ISA function matching (design decision D9).

PCODE_FEATURES_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("addr", pa.int64()),
        ("pcode_ops_total", pa.int32()),
        ("pcode_unique_opcodes", pa.int32()),
        ("pcode_histogram", pa.string()),  # JSON string
        ("pcode_sequence_hash", pa.string()),  # SHA-256 hex
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def pcode_features_row(rec: dict, source: str, extracted_at) -> dict:
    # The histogram comes in as a dict from the JSONL; serialize to JSON string
    histogram = rec.get("pcode_histogram")
    if isinstance(histogram, dict):
        import json

        histogram = json.dumps(histogram, sort_keys=True)
    return {
        "source": source,
        "addr": int(rec["addr"]),
        "pcode_ops_total": rec.get("pcode_ops_total"),
        "pcode_unique_opcodes": rec.get("pcode_unique_opcodes"),
        "pcode_histogram": histogram,
        "pcode_sequence_hash": rec.get("pcode_sequence_hash"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# mmio_events — one row per MemoryIORead/MemoryIOWrite from a Renode trace
# ---------------------------------------------------------------------------
#
# Populated by parse_trace.py reading a Renode PCAndOpcode execution trace
# with TrackMemoryAccesses enabled. Each event records the peripheral
# register address, value, direction, and the PC of the instruction that
# issued the access. The scenario column distinguishes different execution
# scenarios (e.g. "boot", "idle", "stress") for the same target.

MMIO_EVENTS_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("scenario", pa.string()),
        ("sequence_idx", pa.int64()),
        ("pc", pa.int64()),
        ("address", pa.int64()),
        ("value", pa.int64()),
        ("direction", pa.string()),
        ("peripheral", pa.string()),
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def mmio_events_row(rec: dict, source: str, extracted_at) -> dict:
    pc = rec.get("pc")
    return {
        "source": source,
        "scenario": rec.get("scenario") or "",
        "sequence_idx": int(rec["sequence_idx"]),
        "pc": int(pc) if pc is not None else None,
        "address": int(rec["address"]),
        "value": int(rec["value"]),
        "direction": rec.get("direction") or "",
        "peripheral": rec.get("peripheral"),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# decompiled — one row per function with Ghidra's decompiled pseudo-C
# ---------------------------------------------------------------------------
#
# Extracted by running DecompInterface on each function. The decompiled_c
# column can be very large (10KB+ for complex init functions), so we use
# pa.large_string() to avoid the 2GB per-chunk limit of regular strings.
# Not included in the default Snakefile ghidra_extract rule because the
# decompiler is slow (~30s timeout per function).

DECOMPILED_SCHEMA = pa.schema(
    [
        ("source", pa.string()),
        ("addr", pa.int64()),
        ("name", pa.string()),
        ("decompiled_c", pa.large_string()),
        ("decompile_success", pa.bool_()),
        ("extracted_at", pa.timestamp("us", tz="UTC")),
    ]
)


def decompiled_row(rec: dict, source: str, extracted_at) -> dict:
    return {
        "source": source,
        "addr": int(rec["addr"]),
        "name": rec.get("name") or "",
        "decompiled_c": rec.get("decompiled_c") or "",
        "decompile_success": rec.get("decompile_success", False),
        "extracted_at": extracted_at,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TABLES: dict[str, pa.Schema] = {
    "functions": FUNCTIONS_SCHEMA,
    "calls": CALLS_SCHEMA,
    "basic_blocks": BASIC_BLOCKS_SCHEMA,
    "xrefs": XREFS_SCHEMA,
    "strings": STRINGS_SCHEMA,
    "pcode_features": PCODE_FEATURES_SCHEMA,
    "mmio_events": MMIO_EVENTS_SCHEMA,
    "decompiled": DECOMPILED_SCHEMA,
}

ROW_TRANSFORMS: dict[str, Callable] = {
    "functions": functions_row,
    "calls": calls_row,
    "basic_blocks": basic_blocks_row,
    "xrefs": xrefs_row,
    "strings": strings_row,
    "pcode_features": pcode_features_row,
    "mmio_events": mmio_events_row,
    "decompiled": decompiled_row,
}
