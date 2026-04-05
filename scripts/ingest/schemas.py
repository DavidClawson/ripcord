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
# Registry
# ---------------------------------------------------------------------------

TABLES: dict[str, pa.Schema] = {
    "functions": FUNCTIONS_SCHEMA,
    "calls": CALLS_SCHEMA,
}

ROW_TRANSFORMS: dict[str, Callable] = {
    "functions": functions_row,
    "calls": calls_row,
}
