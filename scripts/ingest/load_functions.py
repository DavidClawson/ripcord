#!/usr/bin/env python3
"""Load a per-target function JSONL file into a typed Parquet table.

Reads one JSONL file produced by scripts/ghidra/export_functions.py and
writes it as build/<target>/tables/functions.parquet with an explicit
pyarrow schema. One invocation, one target, one output file — the
Snakemake rule fans out over targets via wildcards.

The schema defined here is the single source of truth for the
`functions` table. There is no separate DDL file; if a column type
needs to change, change it here and re-run the pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        required=True,
        help="target name, stamped into every row as the `source` column",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="path to the output .parquet file",
    )
    parser.add_argument(
        "jsonl",
        type=Path,
        help="input JSONL file produced by the Ghidra extractor",
    )
    return parser.parse_args()


def read_jsonl_rows(path: Path, source: str, extracted_at: datetime):
    with path.open() as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"{path}:{line_number}: invalid JSON: {exc}"
                ) from exc
            yield {
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


def main() -> int:
    args = parse_args()

    if not args.jsonl.exists():
        print(f"error: {args.jsonl} does not exist", file=sys.stderr)
        return 1

    extracted_at = datetime.now(timezone.utc)
    rows = list(read_jsonl_rows(args.jsonl, args.source, extracted_at))

    args.output.parent.mkdir(parents=True, exist_ok=True)

    table = pa.Table.from_pylist(rows, schema=FUNCTIONS_SCHEMA)
    pq.write_table(table, args.output, compression="zstd")

    total_bytes = sum((r["size"] or 0) for r in rows)
    print(
        f"wrote {len(rows)} functions "
        f"({total_bytes} bytes of code) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
