# Firmware bring-up runbook — opaque binary → hardware-boundary transcript

A repeatable recipe for taking a new firmware target from "opaque binary" to
an **execution-verified peripheral/hardware-boundary transcript** in the
`mmio_events` warehouse. Distilled from the FNIRSI 2C53T bring-up (see
`renode-at32-bringup.md` for the worked example). The judgment calls are
written as explicit decision points so a fresh session can follow the path
instead of rediscovering it.

The goal is the same as ripcord's thesis: turn a *static* hypothesis about how
the MCU drives its hardware into an *observed* transcript. For an opaque
peripheral (FPGA/ASIC), that transcript **is** the reverse-engineered interface.

## Tools this runbook uses

| step | tool |
|---|---|
| identify ISA / base / chip | `scripts/identify.py` |
| build the warehouse | `snakemake --cores 4 --resources ghidra=1` |
| query facts | `scripts/query` |
| disassemble a region | `scripts/analysis/disasm.py` |
| split a monster function | `scripts/analysis/decompose.py` |
| emulate a function | `scripts/renode/emulate_function.py` + a platform `.repl` |
| model the opaque peripheral | a stub like `scripts/renode/fpga_protocol.py` |
| trace → warehouse | `scripts/renode/parse_trace.py` (`--platform <chip>`) |

## Phase A — ingest

1. `scripts/identify.py firmware.bin` → ISA, load base, chip family. For raw
   images set `base_addr` + `raw_binary: true` in `config.yaml`; for ELF the
   base comes from the program headers.
2. Add the target to `config.yaml` (+ an SVD under `targets/_svd/` if available)
   and run the pipeline. You now have `functions`, `calls`, `xrefs`,
   `decompiled`, `peripheral_xrefs`, `recovered_calls`, etc.

## Phase B — boot triage (does it cold-boot?)

Stand up a platform `.repl` (reuse `at32f403a.repl` for any STM32F1-class chip;
clone it for a new family) and a boot `.resc` that loads the image at its base
and starts from the reset vector (`vector[1]`).

Run it, then classify the outcome from the trace:

- **Runs, touches MMIO, progresses** → great, capture and move to Phase D.
- **Hangs almost immediately on a `b .` self-loop with interrupts masked**
  (`setBasePriority`/`for(;;)`) → a `configASSERT`/fault trap fired. Find the
  trapping function (`disasm.py` at the hang PC → map to a warehouse function →
  read its `decompiled` C). Decide:
  - **DECISION — is the entry even a real reset handler?** Check the
    `recovered_calls` `vector_table` rows and whether Ghidra placed a *function*
    at `vector[1]`. Red flags for **two-stage / not-cold-bootable**:
    - `vector[1]` is an "undiscovered entry point" sitting in a gap with no
      Ghidra function;
    - its first instructions have **no prologue** and use a callee-saved
      register (e.g. `r5`) as a live pointer, or call a high-fan-in library
      primitive (a queue/list op) immediately;
    - the image is app-only and a bootloader region (below the app base) is
      absent.
    If two-stage → **do not fake the entry; pivot to Phase C (function-level).**
- **Spins forever in a tight loop polling a status/ready bit** → the relevant
  peripheral isn't modeled. Add a stub that returns the ready value (poll-
  satisfaction loop), re-run.

> Lesson from FNIRSI: the app's `vector[1]` pointed at application code that
> assumed bootloader-established context (`r5` = state struct, queues created).
> Cold-booting it was structurally wrong. The tell was a `configASSERT(NULL)`
> on the very first instruction.

## Phase C — function-level emulation (for not-cold-bootable targets)

1. **Find the driver.** `peripheral_xrefs` → which function accesses the target
   peripheral (SPI/USART/DMA/GPIO). Often it's buried in a Ghidra-merged blob.
2. **Split it.** `decompose.py --target T --function F` breaks a monster init
   function into peripheral-coherent phases; pick the phase whose dominant
   peripheral is the boundary you care about.
3. **Read the phase.** `disasm.py --target T --start <phase.lo> --end <phase.hi>`
   (use `--filter skeleton` for the mov-imm/str/ldr/bl view, `--filter calls`
   to see helpers). Recover:
   - the **command bytes** (`movs rX,#imm` feeding a `str [base,#DT]`);
   - the **register context** the entry assumes (which regs hold the peripheral
     base, the GPIO/CS base, SysTick, etc. — set just before the phase);
   - any **RAM globals** read (delay reload values, handles) → pre-set them.
   - **DECISION — pick an entry with no `bl` calls in the core span** if you can;
     it lets you skip stubbing helpers. (FNIRSI's transfer loop was fully
     inlined.)
4. **Model the opaque side.** Extend the peripheral stub (`fpga_protocol.py`
   pattern): return ready status bits so polls pass, and scripted/idle replies
   seeded from the static spec; tag every unobserved reply `unverified`.
5. **Emulate + capture.**
   ```
   scripts/renode/emulate_function.py --target T --entry <lo> --stop <after-key-op> \
       --reg sp=<top> --reg <base-regs...> --mem <globals...> --run
   ```
   It generates the `.resc`, runs Renode, parses the trace into
   `mmio_events_fn_<entry>.jsonl`, and prints the write-value sequence.

## Phase D — reconcile and iterate

- Diff the captured transcript against the static spec. Confirmations upgrade
  facts `static-inferred → execution-verified` (`confidence-scheme.md`);
  divergences are corrections (look first at indirect dispatch / DMA, where
  static analysis is weakest).
- Iterate the **poll/assert-satisfaction loop**: each new stall names the next
  register the stub must satisfy or the next descriptor the firmware needs. The
  growing stub becomes the executable interface spec.
- "Done" for a boundary = the firmware drives it to completion against the
  model with no divergence from a (eventual) hardware trace.

## Realistic effort

- **Same target, re-run:** ~30 min (pipeline + the saved `.resc`/emulate
  command + queries).
- **Sibling target, same chip:** ~half a day — the platform `.repl` and stub
  transfer; the work is re-locating the driver function and its entry context.
- **New chip family:** add a platform `.repl` (memory map + ready-stubs for
  RCC/Flash + peripheral stubs) and a `parse_trace.py` peripheral map first.
