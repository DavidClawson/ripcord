---
name: firmware-bringup
description: Bring up a firmware target in ripcord from opaque binary to an execution-verified hardware-boundary (MMIO) transcript. Use when the user wants to emulate a firmware target, capture how the MCU drives a peripheral or opaque device (FPGA/ASIC), reverse-engineer a hardware protocol, triage why a firmware image won't boot in Renode, or reproduce/extend the FNIRSI scope bring-up. Chains identify → pipeline → boot-triage → decompose → function-level emulation → reconcile.
---

# Firmware bring-up (ripcord)

Drive a firmware target from opaque binary to an **execution-verified
hardware-boundary transcript** in the `mmio_events` warehouse. The full,
authoritative recipe — with the decision points — lives in
`notes/firmware-bringup-runbook.md`. **Read that file first**, then execute
the phases below. The worked example (FNIRSI 2C53T) is in
`notes/renode-at32-bringup.md`; the static protocol it verifies against is
`notes/scope_acquisition_spec.md`.

This skill is the ripcord thesis in miniature: convert a *static* hypothesis
about how the MCU drives its hardware into an *observed* transcript. For an
opaque peripheral, that transcript is the reverse-engineered interface.

## Operating rules

- **Confidence discipline.** Tag every claim by provenance. A value the
  firmware wrote is observed; a reply the stub invented is `unverified` until a
  hardware trace confirms it. Never present an inferred FPGA/peripheral reply as
  fact. (See `notes/confidence-scheme.md`.)
- **Don't fake a cold boot for a two-stage image.** If boot triage shows the
  app isn't independently cold-bootable (Phase B decision), pivot to
  function-level emulation — do not invent bootloader context to force the
  reset path.
- **Prefer empiricism over theory.** When unsure why execution stalls, run it
  and read the trace; each stall names the next thing to model. Don't
  over-reason a disassembly when a 2-second emulation answers it.
- Work the existing tools; don't re-implement what's listed. Add a target via
  `config.yaml` only — no new pipeline stages without the user's ask.

## Phases (see the runbook for the decision points)

1. **Ingest.** `scripts/identify.py <binary>`; add to `config.yaml`
   (`base_addr` + `raw_binary: true` for raw images); run
   `snakemake --cores 4 --resources ghidra=1`.
2. **Boot triage.** Boot from the reset vector with a platform `.repl`
   (reuse `scripts/renode/at32f403a.repl` for STM32F1-class chips). Classify:
   progresses / `configASSERT`-hang / status-poll spin / **two-stage**. Use the
   runbook's red-flag checklist to detect not-cold-bootable images.
3. **Function-level emulation** (if not cold-bootable):
   - find the driver via `peripheral_xrefs`;
   - split monster functions with `scripts/analysis/decompose.py`;
   - recover command bytes + the entry register context with
     `scripts/analysis/disasm.py` (`--filter skeleton` / `--filter calls`);
   - extend the peripheral stub (the `scripts/renode/fpga_protocol.py` pattern);
   - run `scripts/renode/emulate_function.py --target T --entry <lo>
     --stop <after-key-op> --reg <base-regs> --mem <globals> --run`.
4. **Reconcile.** Diff the captured transcript against the static spec; upgrade
   confirmed facts `static-inferred → execution-verified`; iterate the
   poll/assert-satisfaction loop until the boundary runs to completion.

## Output

Report: where boot triage landed (and why), the isolated driver function/phase,
the captured MMIO/command sequence, what it confirmed vs corrected in the static
spec, and the next stall to satisfy. Log a dated run entry in the relevant
`notes/*-bringup.md` so the loop's progress is durable.
