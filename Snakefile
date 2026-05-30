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
#   snakemake --cores 4 --resources ghidra=1    # run full pipeline
#   snakemake --cores 4 --resources ghidra=1 -n # dry run, show DAG
#   snakemake clean                             # remove all build outputs
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
PYTHON = os.environ.get("PYTHON", "uv run python")
RENODE = os.environ.get("RENODE", "/Applications/Renode.app/Contents/MacOS/renode")
SOUFFLE = os.environ.get("SOUFFLE", "souffle")

TARGETS = list(config["targets"].keys())
REPO_ROOT = Path(workflow.basedir).resolve()


def ghidra_import_flags(target):
    """Headless -import flags for a target.

    Raw binaries (`raw_binary: true` in config) have no format header, so
    Ghidra can't infer the language or load address — without these flags it
    blocks on an interactive processor prompt under headless. ELF targets carry
    that metadata in the header, so they get no extra flags (auto-detect).

    `ghidra_processor` may override the language id; it defaults to the generic
    Cortex-M Thumb variant, which covers every current raw target (AT32F403A).
    """
    t = config["targets"][target]
    if not t.get("raw_binary"):
        return ""
    base = t["base_addr"]
    base = hex(base) if isinstance(base, int) else str(base)
    proc = t.get("ghidra_processor", "ARM:LE:32:Cortex")
    return f"-loader BinaryLoader -loader-baseAddr {base} -processor {proc}"


def targets_with_scenarios():
    """Return targets that have at least one Renode scenario configured."""
    return [t for t in TARGETS if "scenarios" in config["targets"][t]]


def scenarios_for_target(target):
    """Return the scenarios dict for a target, or empty dict."""
    return config["targets"][target].get("scenarios", {})


def all_renode_outputs():
    """Expand Renode trace + MMIO parquet outputs for all (target, scenario) pairs."""
    outputs = []
    for t in targets_with_scenarios():
        for s in scenarios_for_target(t):
            outputs.append(f"build/{t}/tables/mmio_events_{s}.parquet")
    return outputs


def all_datalog_outputs():
    """Expand Datalog derived outputs for all targets."""
    outputs = []
    for t in TARGETS:
        outputs.append(f"build/{t}/datalog/reaches.csv")
    return outputs


rule all:
    input:
        expand("build/{target}/tables/functions.parquet",    target=TARGETS),
        expand("build/{target}/tables/calls.parquet",        target=TARGETS),
        expand("build/{target}/tables/basic_blocks.parquet", target=TARGETS),
        expand("build/{target}/tables/xrefs.parquet",        target=TARGETS),
        expand("build/{target}/tables/strings.parquet",      target=TARGETS),
        expand("build/{target}/tables/pcode_features.parquet", target=TARGETS),
        expand("build/{target}/tables/decompiled.parquet", target=TARGETS),
        expand("build/{target}/tables/recovered_calls.parquet", target=TARGETS),
        expand("build/{target}/tables/peripheral_xrefs.parquet", target=TARGETS),
        expand("build/{target}/tables/ground_truth_functions.parquet", target=TARGETS),
        expand("build/{target}/tables/functions_enriched.parquet", target=TARGETS),
        all_renode_outputs(),
        all_datalog_outputs(),


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
    resources:
        ghidra=1,
    output:
        functions_jsonl    = "build/{target}/functions.jsonl",
        calls_jsonl        = "build/{target}/calls.jsonl",
        basic_blocks_jsonl = "build/{target}/basic_blocks.jsonl",
        xrefs_jsonl        = "build/{target}/xrefs.jsonl",
        strings_jsonl      = "build/{target}/strings.jsonl",
        pcode_jsonl        = "build/{target}/pcode.jsonl",
    params:
        project_dir = lambda wc: f"build/{wc.target}/ghidra_project",
        project_name = lambda wc: wc.target,
        script_path = str(REPO_ROOT / "scripts" / "ghidra"),
        import_flags     = lambda wc: ghidra_import_flags(wc.target),
        seed_file        = lambda wc: str((REPO_ROOT / f"targets/{wc.target}/seeds.txt").resolve()),
        functions_out    = lambda wc: str((REPO_ROOT / f"build/{wc.target}/functions.jsonl").resolve()),
        calls_out        = lambda wc: str((REPO_ROOT / f"build/{wc.target}/calls.jsonl").resolve()),
        basic_blocks_out = lambda wc: str((REPO_ROOT / f"build/{wc.target}/basic_blocks.jsonl").resolve()),
        xrefs_out        = lambda wc: str((REPO_ROOT / f"build/{wc.target}/xrefs.jsonl").resolve()),
        strings_out      = lambda wc: str((REPO_ROOT / f"build/{wc.target}/strings.jsonl").resolve()),
        pcode_out        = lambda wc: str((REPO_ROOT / f"build/{wc.target}/pcode.jsonl").resolve()),
    shell:
        r"""
        mkdir -p {params.project_dir} $(dirname {output.functions_jsonl})
        # Strip the uv .venv from PATH so pyghidraRun uses Ghidra's own bundled
        # venv (which has PyGhidra) instead of detecting the active .venv and
        # blocking on a "install PyGhidra into this venv?" prompt under headless.
        GHIDRA_PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '\.venv' | paste -sd ':' -)"
        env -u VIRTUAL_ENV PATH="$GHIDRA_PATH" {GHIDRA_PYGHIDRA} -H {params.project_dir} {params.project_name} \
            -import {input.elf} \
            {params.import_flags} \
            -overwrite \
            -scriptPath {params.script_path} \
            -preScript set_aggressive_analysis.py \
            -postScript create_vector_functions.py \
            -postScript create_seed_functions.py {params.seed_file} \
            -postScript harvest_pointers.py \
            -postScript export_functions.py     {params.functions_out} \
            -postScript export_calls.py         {params.calls_out} \
            -postScript export_basic_blocks.py  {params.basic_blocks_out} \
            -postScript export_xrefs.py         {params.xrefs_out} \
            -postScript export_strings.py       {params.strings_out} \
            -postScript export_pcode.py         {params.pcode_out} \
            < /dev/null
        test -s {output.functions_jsonl}
        test -s {output.calls_jsonl}
        test -s {output.basic_blocks_jsonl}
        test -s {output.xrefs_jsonl}
        test -s {output.strings_jsonl}
        test -s {output.pcode_jsonl}
        """


rule ghidra_decompile:
    """Run Ghidra headless to decompile all functions in the target binary.

    This is a SEPARATE rule from ghidra_extract because decompilation is
    significantly slower (~5-10 min vs ~1 min for extraction). It reuses
    the existing Ghidra project (created by ghidra_extract) via -process
    instead of -import.
    """
    input:
        elf = lambda wc: config["targets"][wc.target]["elf"],
        functions_jsonl = "build/{target}/functions.jsonl",
    resources:
        ghidra=1,
    output:
        decompiled_jsonl = "build/{target}/decompiled.jsonl",
    params:
        project_dir = lambda wc: f"build/{wc.target}/ghidra_project",
        project_name = lambda wc: wc.target,
        # The program inside the Ghidra project is named by the basename
        # of the file imported in ghidra_extract (-import {elf}), not by
        # the target name — e.g. stock_v120.bin, zephyr.elf. The -process
        # filter must match that, or headless aborts with "Requested
        # project program file(s) not found".
        program_name = lambda wc: os.path.basename(config["targets"][wc.target]["elf"]),
        script_path = str(REPO_ROOT / "scripts" / "ghidra"),
        decompiled_out = lambda wc: str((REPO_ROOT / f"build/{wc.target}/decompiled.jsonl").resolve()),
    shell:
        r"""
        # Same .venv-strip as ghidra_extract: keep pyghidraRun on Ghidra's own
        # venv so it doesn't block on the install-into-active-venv prompt.
        GHIDRA_PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '\.venv' | paste -sd ':' -)"
        env -u VIRTUAL_ENV PATH="$GHIDRA_PATH" {GHIDRA_PYGHIDRA} -H {params.project_dir} {params.project_name} \
            -process {params.program_name} \
            -scriptPath {params.script_path} \
            -postScript export_decompiler.py {params.decompiled_out} \
            < /dev/null
        test -s {output.decompiled_jsonl}
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


rule ingest_pcode:
    """Load one target's P-Code feature JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/pcode.jsonl",
    output:
        parquet = "build/{target}/tables/pcode_features.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table pcode_features \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule ingest_decompiled:
    """Load one target's decompiled pseudo-C JSONL into a typed Parquet table."""
    input:
        jsonl = "build/{target}/decompiled.jsonl",
    output:
        parquet = "build/{target}/tables/decompiled.parquet",
    shell:
        r"""
        {PYTHON} scripts/ingest/load_table.py \
            --table decompiled \
            --source {wildcards.target} \
            --output {output.parquet} \
            {input.jsonl}
        """


rule recover_calls:
    """Recover indirect call edges from existing warehouse tables + binary.

    Runs the standalone recovery script (no Ghidra session needed) which:
    1. Reads Cortex-M vector table from the binary → ISR handlers
    2. Scans xrefs table for non-call refs to function entries → func ptrs
    3. Infers registrar→callback dispatch edges from calls + xrefs

    Produces recovered_calls.jsonl, then ingests to Parquet.
    """
    input:
        functions = "build/{target}/tables/functions.parquet",
        calls = "build/{target}/tables/calls.parquet",
        xrefs = "build/{target}/tables/xrefs.parquet",
        elf = lambda wc: config["targets"][wc.target]["elf"],
    output:
        parquet = "build/{target}/tables/recovered_calls.parquet",
    params:
        jsonl = "build/{target}/recovered_calls.jsonl",
    shell:
        r"""
        {PYTHON} scripts/recovery/recover_calls.py {wildcards.target}
        {PYTHON} scripts/ingest/load_table.py \
            --table recovered_calls \
            --source {wildcards.target} \
            --output {output.parquet} \
            {params.jsonl}
        """


rule classify_peripherals:
    """Classify peripheral register accesses per function using SVD maps.

    Reads the xrefs table, filters to peripheral memory regions
    (0x40000000+ vendor, 0xE0000000+ system), and resolves each
    address against the target's SVD register map. Produces
    peripheral_xrefs.parquet with register-level classification.

    Works with or without an SVD file: with SVD gets full register
    names (USART2.STS, GPIOA.ODR); without gets Cortex-M system
    peripherals only (NVIC, SysTick, SCB).
    """
    input:
        xrefs = "build/{target}/tables/xrefs.parquet",
    output:
        parquet = "build/{target}/tables/peripheral_xrefs.parquet",
    params:
        jsonl = "build/{target}/peripheral_xrefs.jsonl",
    shell:
        r"""
        {PYTHON} scripts/peripheral/classify_peripherals.py {wildcards.target}
        {PYTHON} scripts/ingest/load_table.py \
            --table peripheral_xrefs \
            --source {wildcards.target} \
            --output {output.parquet} \
            {params.jsonl}
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


rule fingerprint_writeback:
    """Write structural fingerprint matches back as enriched function tables.

    Runs after all per-target ingest rules complete. Reads all targets'
    parquet tables, computes cross-target structural matches within
    build-tuple groups, and writes functions_enriched.parquet per target.
    """
    input:
        functions    = expand("build/{target}/tables/functions.parquet",    target=TARGETS),
        calls        = expand("build/{target}/tables/calls.parquet",        target=TARGETS),
        basic_blocks = expand("build/{target}/tables/basic_blocks.parquet", target=TARGETS),
        xrefs        = expand("build/{target}/tables/xrefs.parquet",        target=TARGETS),
    output:
        expand("build/{target}/tables/functions_enriched.parquet", target=TARGETS),
    shell:
        r"""
        {PYTHON} scripts/ingest/write_back_fingerprints.py \
            --config config.yaml \
            --build-dir build
        """


rule renode_trace:
    """Run a Renode scenario to produce an execution trace with MMIO events.

    Only runs for targets that have scenarios configured in config.yaml.
    Generates a temporary .resc wrapper that parameterizes the ELF path
    and trace output location, then invokes Renode headless.
    """
    input:
        elf = lambda wc: config["targets"][wc.target]["elf"],
        resc = lambda wc: config["targets"][wc.target]["scenarios"][wc.scenario]["resc"],
        repl = lambda wc: config["targets"][wc.target]["scenarios"][wc.scenario]["repl"],
    output:
        trace = "build/{target}/traces/{scenario}.trace",
        log = "build/{target}/traces/{scenario}.log",
    params:
        duration = lambda wc: config["targets"][wc.target]["scenarios"][wc.scenario].get("duration", "0:0:2"),
    shell:
        r"""
        mkdir -p $(dirname {output.trace})
        # Generate a parameterized .resc wrapper so we control output paths
        WRAPPER=$(mktemp /tmp/renode_XXXXXX.resc)
        cat > "$WRAPPER" <<RESC
mach create
machine LoadPlatformDescription @{input.repl}
sysbus LoadELF @{input.elf}
showAnalyzer uart0
logLevel -1 sysbus
logFile $CWD/{output.log} true
cpu CreateExecutionTracing "tracer" $CWD/{output.trace} PCAndOpcode
tracer TrackMemoryAccesses
emulation RunFor "{params.duration}"
quit
RESC
        {RENODE} --disable-xwt --console "$WRAPPER"
        rm -f "$WRAPPER"
        test -s {output.trace}
        """


rule ingest_mmio:
    """Parse a Renode execution trace into MMIO events JSONL, then load to Parquet."""
    input:
        trace = "build/{target}/traces/{scenario}.trace",
    output:
        parquet = "build/{target}/tables/mmio_events_{scenario}.parquet",
    params:
        jsonl = "build/{target}/mmio_events_{scenario}.jsonl",
    shell:
        r"""
        {PYTHON} scripts/renode/parse_trace.py \
            --trace {input.trace} \
            --scenario {wildcards.scenario} \
            --output {params.jsonl}
        {PYTHON} scripts/ingest/load_table.py \
            --table mmio_events \
            --source {wildcards.target} \
            --output {output.parquet} \
            {params.jsonl}
        rm -f {params.jsonl}
        """


rule datalog_export:
    """Export base facts from the warehouse for Souffle consumption.

    Produces tab-separated .facts files (no header) matching the .input
    declarations in reachability.dl. Includes recovered call edges from
    vector table, function-pointer references, and registrar dispatch.
    """
    input:
        calls = "build/{target}/tables/calls.parquet",
        functions = "build/{target}/tables/functions.parquet",
        recovered_calls = "build/{target}/tables/recovered_calls.parquet",
    output:
        calls_facts = "build/{target}/datalog/calls.facts",
        functions_facts = "build/{target}/datalog/functions.facts",
    shell:
        r"""
        {PYTHON} scripts/datalog/export_facts.py {wildcards.target}
        test -f {output.calls_facts}
        test -f {output.functions_facts}
        """


rule datalog_derive:
    """Run Souffle reachability rules over exported facts.

    Derives transitive call reachability, orchestrator detection,
    unreachable-from-main analysis, and subsystem clustering. All
    outputs are tab-separated CSV files in the target's datalog dir.
    """
    input:
        calls_facts = "build/{target}/datalog/calls.facts",
        functions_facts = "build/{target}/datalog/functions.facts",
        rules = "scripts/datalog/reachability.dl",
    output:
        reaches = "build/{target}/datalog/reaches.csv",
        reach_count = "build/{target}/datalog/reach_count.csv",
        orchestrators = "build/{target}/datalog/orchestrators.csv",
        unreachable = "build/{target}/datalog/unreachable_from_main.csv",
        subsystem_pairs = "build/{target}/datalog/subsystem_pairs.csv",
    shell:
        r"""
        cd build/{wildcards.target}/datalog && \
        {SOUFFLE} {REPO_ROOT}/scripts/datalog/reachability.dl
        """


rule clean:
    shell:
        "rm -rf build"
