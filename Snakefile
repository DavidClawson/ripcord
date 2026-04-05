# ripcord — Phase 0 pipeline
#
# Extracts function metadata from each target binary via Ghidra headless
# (driving a PyGhidra postScript) and writes the results as typed Parquet
# files under build/<target>/tables/. Targets are declared in config.yaml.
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
        expand("build/{target}/tables/functions.parquet", target=TARGETS),


rule ghidra_export:
    """Run Ghidra headless on one target binary and dump function metadata.

    The PyGhidra postScript writes a JSONL file (one function per line).
    Ghidra's project database lives under build/<target>/ghidra_project/
    so reruns are incremental. `pyghidraRun -H` is analyzeHeadless launched
    under PyGhidra, which is what lets the .py postScript see a Python 3
    runtime.
    """
    input:
        elf = lambda wc: config["targets"][wc.target]["elf"],
    output:
        jsonl = "build/{target}/functions.jsonl",
    params:
        project_dir = lambda wc: f"build/{wc.target}/ghidra_project",
        project_name = lambda wc: wc.target,
        script_path = str(REPO_ROOT / "scripts" / "ghidra"),
        output_abs = lambda wc: str((REPO_ROOT / f"build/{wc.target}/functions.jsonl").resolve()),
    shell:
        r"""
        mkdir -p {params.project_dir} $(dirname {output.jsonl})
        {GHIDRA_PYGHIDRA} -H {params.project_dir} {params.project_name} \
            -import {input.elf} \
            -overwrite \
            -scriptPath {params.script_path} \
            -postScript export_functions.py {params.output_abs}
        test -s {output.jsonl}
        """


rule ingest_functions:
    """Load one target's function JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/functions.jsonl",
    output:
        parquet = "build/{target}/tables/functions.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_functions.py \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule clean:
    shell:
        "rm -rf build"
