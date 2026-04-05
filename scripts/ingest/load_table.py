#!/usr/bin/env python3
"""Load a JSONL extraction output into a typed Parquet table.

Generic replacement for per-table loader scripts. The schema and
row-transform for each table live in scripts/ingest/schemas.py; this
script is pure plumbing — pick a schema by name, read JSONL, apply
the transform, write Parquet.

Usage (typically invoked from the Snakefile):
    load_table.py --table functions --source pico_blinky \\
        --output build/pico_blinky/tables/functions.parquet \\
        build/pico_blinky/functions.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

# Import the schemas module as a sibling, regardless of invocation CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import schemas  # noqa: E402 — sys.path manipulation above


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--table",
        required=True,
        choices=sorted(schemas.TABLES.keys()),
        help="logical table name; selects schema and row transform",
    )
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
        help="input JSONL file produced by a Ghidra extraction script",
    )
    return parser.parse_args()


def iter_rows(path: Path, source: str, transform, extracted_at: datetime):
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
            yield transform(rec, source, extracted_at)


def main() -> int:
    args = parse_args()

    if not args.jsonl.exists():
        print(f"error: {args.jsonl} does not exist", file=sys.stderr)
        return 1

    schema = schemas.TABLES[args.table]
    transform = schemas.ROW_TRANSFORMS[args.table]

    extracted_at = datetime.now(timezone.utc)
    rows = list(iter_rows(args.jsonl, args.source, transform, extracted_at))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=schema)
    pq.write_table(table, args.output, compression="zstd")

    print(f"wrote {len(rows)} {args.table} rows to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
