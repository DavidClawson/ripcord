# ripcord — enable aggressive code-discovery analyzers (preScript).
#
# Runs BEFORE Ghidra's auto-analysis (it is a -preScript), so the headless
# framework performs the heavy analysis pass itself with these options on.
# This is the safe way to crank analysis: triggering a full re-analysis from a
# *post*Script (AutoAnalysisManager.reAnalyzeAll + startAnalysis) deadlocks at
# 0% CPU under headless.
#
# Goal: measure how much more of a stripped raw image gets decoded when the
# default-off "aggressive" analyzers are enabled — the superset-style
# instruction finder, exhaustive function-start search, and switch recovery.
#
# Invoked as:  -preScript set_aggressive_analysis.py

from ghidra.program.model.listing import Program

# Option names whose presence (substring match) should be forced ON. Ghidra
# names vary slightly by version, so match loosely rather than hard-code.
WANT_ON = [
    "Aggressive Instruction Finder",       # superset disassembly in gaps
    "ARM Aggressive Instruction Finder",
    "Function Start Search",               # prologue scanning
    "Decompiler Switch Analysis",          # jump-table recovery
    "Decompiler Parameter ID",
    "Shared Return Calls",
    "Non-Returning Functions - Discovered",
    "Create Address Tables",               # pointer-table discovery
    "ARM Symbol",
]


def main():
    prog = currentProgram  # noqa: F821 — Ghidra builtin
    opts = prog.getOptions(Program.ANALYSIS_PROPERTIES)
    names = list(opts.getOptionNames())
    print("set_aggressive_analysis: %d analysis options present" % len(names))
    enabled = 0
    for n in names:
        for w in WANT_ON:
            if w.lower() in n.lower():
                try:
                    setAnalysisOption(prog, n, "true")  # noqa: F821 — Ghidra builtin
                    print("  ON  %s" % n)
                    enabled += 1
                except Exception as exc:
                    printerr("  FAIL %s: %s" % (n, exc))  # noqa: F821
                break
    print("set_aggressive_analysis: enabled %d aggressive options" % enabled)


main()
