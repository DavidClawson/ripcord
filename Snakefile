# ripcord — Phase 0 pipeline
#
# Extracts function-level metadata from each target binary via Ghidra
# headless (driving PyGhidra postScripts) and writes the results as
# typed Parquet files under build/<target>/tables/. Targets are
# declared in config.yaml.
#
# The warehouse is the tree of parquet files, not an embedded database
# file. Query it with scripts/query or any Parquet-capable tool. See
# notes/design-decisions.md §D15 for the rationale.
#
# Usage:
#   snakemake --cores 4          # run full pipeline
#   snakemake --cores 4 -n       # dry run, show DAG
#   snakemake clean              # remove all build outputs
#
# Environment variables honored:
#   GHIDRA_PYGHIDRA   path to pyghidraRun if not on $PATH (modern Ghidra
#                     ships this; invoking it with -H runs analyzeHeadless
#                     under PyGhidra so .py postScripts get Python 3)
#   PYTHON            path to the Python interpreter for ingest (default: python3)

import os
from pathlib import Path

configfile: "config.yaml"

GHIDRA_PYGHIDRA = os.environ.get("GHIDRA_PYGHIDRA", "pyghidraRun")
PYTHON = os.environ.get("PYTHON", "python3")

TARGETS = list(config["targets"].keys())
REPO_ROOT = Path(workflow.basedir).resolve()


rule all:
    input:
        expand("build/{target}/tables/functions.parquet",    target=TARGETS),
        expand("build/{target}/tables/calls.parquet",        target=TARGETS),
        expand("build/{target}/tables/basic_blocks.parquet", target=TARGETS),
        expand("build/{target}/tables/xrefs.parquet",        target=TARGETS),
        expand("build/{target}/tables/strings.parquet",      target=TARGETS),
        expand("build/{target}/tables/ground_truth_functions.parquet", target=TARGETS),


rule ghidra_extract:
    """Run Ghidra headless once per target, dumping every JSONL the
    pipeline cares about as postScript outputs from the same session.

    Running Ghidra once and emitting multiple JSONLs is strictly
    better than one-Ghidra-run-per-table: auto-analysis dominates the
    per-target wall time, so amortizing it across every extraction
    script keeps the "minutes, not days" constraint honest as the
    warehouse grows.

    Ghidra's project database lives under build/<target>/ghidra_project/
    so reruns are incremental. `pyghidraRun -H` is analyzeHeadless
    launched under PyGhidra, which is what lets the .py postScripts
    see a Python 3 runtime.
    """
    input:
        elf = lambda wc: config["targets"][wc.target]["elf"],
    output:
        functions_jsonl    = "build/{target}/functions.jsonl",
        calls_jsonl        = "build/{target}/calls.jsonl",
        basic_blocks_jsonl = "build/{target}/basic_blocks.jsonl",
        xrefs_jsonl        = "build/{target}/xrefs.jsonl",
        strings_jsonl      = "build/{target}/strings.jsonl",
    params:
        project_dir = lambda wc: f"build/{wc.target}/ghidra_project",
        project_name = lambda wc: wc.target,
        script_path = str(REPO_ROOT / "scripts" / "ghidra"),
        functions_out    = lambda wc: str((REPO_ROOT / f"build/{wc.target}/functions.jsonl").resolve()),
        calls_out        = lambda wc: str((REPO_ROOT / f"build/{wc.target}/calls.jsonl").resolve()),
        basic_blocks_out = lambda wc: str((REPO_ROOT / f"build/{wc.target}/basic_blocks.jsonl").resolve()),
        xrefs_out        = lambda wc: str((REPO_ROOT / f"build/{wc.target}/xrefs.jsonl").resolve()),
        strings_out      = lambda wc: str((REPO_ROOT / f"build/{wc.target}/strings.jsonl").resolve()),
    shell:
        r"""
        mkdir -p {params.project_dir} $(dirname {output.functions_jsonl})
        {GHIDRA_PYGHIDRA} -H {params.project_dir} {params.project_name} \
            -import {input.elf} \
            -overwrite \
            -scriptPath {params.script_path} \
            -postScript export_functions.py     {params.functions_out} \
            -postScript export_calls.py         {params.calls_out} \
            -postScript export_basic_blocks.py  {params.basic_blocks_out} \
            -postScript export_xrefs.py         {params.xrefs_out} \
            -postScript export_strings.py       {params.strings_out}
        test -s {output.functions_jsonl}
        test -s {output.calls_jsonl}
        test -s {output.basic_blocks_jsonl}
        test -s {output.xrefs_jsonl}
        test -s {output.strings_jsonl}
        """


rule ingest_functions:
    """Load one target's function JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/functions.jsonl",
    output:
        parquet = "build/{target}/tables/functions.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table functions \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule ingest_calls:
    """Load one target's call-reference JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/calls.jsonl",
    output:
        parquet = "build/{target}/tables/calls.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table calls \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule ingest_basic_blocks:
    """Load one target's basic-block JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/basic_blocks.jsonl",
    output:
        parquet = "build/{target}/tables/basic_blocks.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table basic_blocks \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule ingest_xrefs:
    """Load one target's non-call xref JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/xrefs.jsonl",
    output:
        parquet = "build/{target}/tables/xrefs.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table xrefs \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule ingest_strings:
    """Load one target's defined-string JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/strings.jsonl",
    output:
        parquet = "build/{target}/tables/strings.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table strings \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule ground_truth_functions:
    """Extract ground-truth text symbols from the ELF via `nm -S`.

    This is the Phase 0.6 validation loop, committed as a pipeline
    rule so every run produces a coverage signal. Joined against the
    Ghidra-derived `functions` table by address in
    notes/queries/coverage.sql.
    """
    input:
        elf = lambda wc: config["targets"][wc.target]["elf"],
    output:
        parquet = "build/{target}/tables/ground_truth_functions.parquet",
    params:
        arch = lambda wc: config["targets"][wc.target]["arch"],
    shell:
        r"""
        {PYTHON} scripts/ingest/load_ground_truth.py \
            --elf {input.elf} \
            --arch {params.arch} \
            --source {wildcards.target} \
            --output {output.parquet}
        """


rule clean:
    shell:
        "rm -rf build"
