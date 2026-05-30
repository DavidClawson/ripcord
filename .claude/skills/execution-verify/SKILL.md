---
name: execution-verify
description: Promote a single static claim about a firmware function or hardware-boundary transaction to an execution-verified contract by running it in Renode and diffing the trace, then recording it in the ripcord contract ledger. Use when you have a decompile-derived hypothesis ("this function writes the burst buffer to state+0x5B0", "command 0x09 puts 0x0A on SPI3") and want to confirm or refute it by execution rather than more static reading. This is the tight per-claim loop; `firmware-bringup` is the full pipeline that gets a target to where this loop can run.
---

# Execution-verify a claim (ripcord)

The ripcord thesis in its smallest unit: **no claim is canonical until
execution backs it.** This skill is the loop that turns one
`decompile-derived` hypothesis into an `execution-verified` contract — run
many times, it is how the contract ledger grows. Prerequisite: the target is
already in the warehouse and function-level emulatable (if not, run
`firmware-bringup` first).

## Operating rules

- **Confidence discipline.** Separate what the *firmware* did (observed:
  register/memory/MMIO deltas in the trace) from what a *stub invented* (a
  reply value — `unverified` until hardware). Separate an internal
  selector/dispatch code from a wire-level hardware transaction. Never log an
  inferred reply as fact. (See `notes/confidence-scheme.md`.)
- **One claim per cycle.** A contract is a single falsifiable statement with a
  spec you can run. If the claim is compound ("the engine does X, Y, and Z"),
  split it — each part promotes or refutes on its own evidence.
- **A refutation is a result, not a failure.** If the trace contradicts the
  claim, record the correction with a `supersedes` link to the wrong contract.
  A wrong turn is a row with a pointer, not a silent edit.

## The loop

1. **State the claim** as one falsifiable sentence with a concrete, observable
   prediction (a byte on a bus, a value at an address, a call edge taken).
2. **Find the entry + context.** Locate the function/region (`scripts/query`
   over `functions` / `peripheral_xrefs`; `scripts/analysis/disasm.py` for the
   prologue). Determine the register context and any memory globals the real
   caller/boot would have set. For a handler reached past a blocking primitive,
   enter post-receive and stage inputs via `--mem` (see the technique catalog
   in the `firmware-bringup` skill).
3. **Run it.**
   `scripts/renode/emulate_function.py --target T --entry <pc>
   --stop <after-the-observable> --reg <ctx> --mem <globals/inputs> --run`.
   Cap `--duration`/`--timeout`; if it spins, the trace explodes — diagnose the
   stall (a poll on an unmodeled peripheral, a scheduler yield) and either model
   it or NOP-patch past it (`--mem 0x<callsite>=0xBF00BF00`).
4. **Diff the trace against the prediction.** Read the `mmio_events` summary and
   the raw `build/<T>_fn_*_trace.log`: the exact bytes on the bus, the
   contiguous SRAM writes, the dispatch target taken. Match or mismatch is the
   verdict. Delete the trace when done.
5. **Record the contract.** Update the ledger at `build/contracts.sqlite`:
   - inspect: `scripts/contracts/ledger.py list` / `show <id>`;
   - a claim enters `decompile-derived`; running its spec is what promotes it to
     `provenance='execution-verified'` (`scripts/contracts/ledger.py verify
     <id>` where a runnable spec exists). New contracts / appended evidence are
     added through the ledger's Python API (`add_contract`) or, for an evidence
     append on an already-verified contract, a direct SQL `UPDATE` of the
     `evidence` field (the ` || `-delimited append pattern). Tag the new
     evidence with date, the exact emulation command, and what was observed vs.
     still inferred.

## Output

Report: the claim, the emulation invocation, the decisive trace evidence
(bytes/addresses), the verdict (**confirmed** / **refuted+corrected** /
**partial** — and exactly which part remains `decompile-derived` or hardware-
bound), and the ledger contract id touched. If the claim concerned a
hardware-boundary reply *value* the stub supplied, say so plainly: structure is
execution-verified, the value is not — that is the hardware ceiling, see
`HARDWARE_HANDOFF.md`.
