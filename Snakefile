# ripcord — Phase 0 pipeline
#
# Extracts function metadata from each target binary via Ghidra headless
# (using a Ghidrathon script) and ingests the results into a DuckDB
# warehouse. Targets are declared in config.yaml.
#
# Usage:
#   snakemake --cores 4          # run full pipeline
#   snakemake --cores 4 -n       # dry run, show DAG
#   snakemake -- clean           # remove all build outputs
#
# Environment variables honored:
#   GHIDRA_HEADLESS   path to analyzeHeadless if not on $PATH
#   PYTHON            path to the Python interpreter for ingest (default: python3)

import os
from pathlib import Path

configfile: "config.yaml"

GHIDRA_HEADLESS = os.environ.get("GHIDRA_HEADLESS", "analyzeHeadless")
PYTHON = os.environ.get("PYTHON", "python3")

TARGETS = list(config["targets"].keys())
REPO_ROOT = Path(workflow.basedir).resolve()


rule all:
    input:
        "build/warehouse.duckdb"


rule ghidra_export:
    """Run Ghidra headless on one target binary and dump function metadata.

    The Ghidrathon script writes a JSONL file (one function per line).
    Ghidra's project database lives under build/<target>/ghidra_project/
    so reruns are incremental.
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
        {GHIDRA_HEADLESS} {params.project_dir} {params.project_name} \
            -import {input.elf} \
            -overwrite \
            -scriptPath {params.script_path} \
            -postScript export_functions.py {params.output_abs}
        test -s {output.jsonl}
        """


rule ingest_to_duckdb:
    """Load all per-target JSONL files into a single DuckDB warehouse."""
    input:
        jsonls = expand("build/{target}/functions.jsonl", target=TARGETS),
        schema = "schema/001_init.sql",
    output:
        db = "build/warehouse.duckdb",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_functions.py \
            --db {output.db} \
            --schema {input.schema} \
            {input.jsonls}
        """


rule clean:
    shell:
        "rm -rf build"
