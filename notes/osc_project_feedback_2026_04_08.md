# Feedback from osc Project Review (2026-04-08)

This note compares the current `ripcord` writeups against the hardware-confirmed
map and newer reverse-engineering work in `/Users/david/Desktop/osc`.

The goal is not to relitigate every hypothesis. It is to preserve what is
already strong, flag the claims that look overstated, and suggest the next
queries that would most improve the warehouse output.

## What Looks Strong

### 1. `scope_acquisition_spec.md` is directionally very useful

The strongest parts are:

- the staged prerequisite list (`PB11`, `PC6`, `PB6`, USART2, SPI3, H2 upload,
  scheduler, timer-driven runtime)
- the boot/runtime split
- the grouped scope-entry families
- the emphasis on timer-driven re-arm and acquisition cadence

This document is already useful as a practical checklist for why a custom
firmware might still get flat `0xFF` reads even after basic transport works.

### 2. `fpga_version_evolution.md` has a good high-level conclusion

The strongest conclusion is that the FPGA-facing peripheral *surface* looks
stable from V1.0.7 onward. That is a useful prioritization result. It suggests
later versions are unlikely to reveal a completely different SPI3/USART2
architecture.

### 3. The warehouse work is strongest when it stays at the level of
peripheral surface, xref density, and version deltas

Those are the places where `ripcord` adds real value quickly:

- stable-vs-changing regions
- candidate owner families
- which notes deserve a deeper decompile pass

## What Should Be Softened or Corrected

### 1. Separate hardware-confirmed pin roles from xref-based guesses

The current `osc` hardware work strongly suggests:

- `PB6` is the software-controlled SPI3 chip select
- `PC6` is an enable/gate line, not the primary chip-select line
- `PB11` is an FPGA active-mode control, not a display bit-bang data/clock line

Because of that, claims like these should be softened or corrected:

- `fpga_interaction_analysis.md` calling `PC6` the SPI chip-select line
- `fpga_interaction_analysis.md` treating the PB11 cluster as display SPI

The likely failure mode here is xref over-attribution: seeing a GPIO touched by
many functions and assigning one role too early.

### 2. Be careful with “exact wire-level” wording around `0x0B..0x11`

The biggest divergence from newer work is in `scope_acquisition_spec.md`.

The document currently presents `0x0B..0x11`, `0x16..0x19`, `0x1A..0x1E`,
`0x20/0x21`, and `0x26..0x28` as if they are directly the final UART wire-level
`cmd_lo` stream. Newer queue-split work in `/Users/david/Desktop/osc` suggests
that at least part of that family is better understood as upstream/internal
selectors which are translated downstream before the final 16-bit TX words are
enqueued.

Recommendation:

- keep the grouped-family model
- soften “exact wire-level command sequence” to “best current staged model”
- explicitly label which bytes are observed final TX words versus inferred
  internal selectors

### 3. Avoid main-loop/task-role claims from zero-callers alone

`fpga_interaction_analysis.md` is currently the least reliable of the three
notes because it over-assigns semantic roles from xrefs alone.

Examples that should be softened:

- `FUN_08027a50` as “main loop”
- `FUN_0801de98` as “scope acquisition task”
- “only FUN_08027a50 directly accesses SPI3, therefore all SPI3 handling is
  entirely inside the main BSP function”

The safer wording is:

- `FUN_08027a50` is a monolithic master-init / BSP owner with runtime-adjacent
  behavior
- `FUN_0801de98` is a large secondary owner touching scope-adjacent state, but
  not enough evidence yet to call it the acquisition task

### 4. Stable peripheral counts do not prove fully stable semantics

`fpga_version_evolution.md` is strongest when it says the FPGA-facing
peripheral access pattern is frozen. That is a strong and useful finding.

It becomes too strong when that turns into:

- “the FPGA protocol layer did not change”
- “V1.0.7 is the canonical reference in full”

Identical SPI3/USART2/DMA2 access counts are good evidence of a stable hardware
surface. They do not prove that higher-level state choreography, selector
translation, or queue usage is identical in semantics across versions.

Recommendation:

- keep “peripheral surface frozen”
- soften “protocol unchanged” to “no evidence of peripheral-surface changes”

## Suggested Improvements to Future ripcord Notes

### 1. Add claim-level provenance tags

For each key claim, mark one of:

- hardware-confirmed
- direct disassembly / direct xref
- decompile-derived
- synthesized model
- low-confidence hypothesis

This would prevent readers from giving the same weight to a bench-confirmed pin
role and a plausible xref-based task guess.

### 2. Distinguish final transport artifacts from upstream selectors

For MCU↔FPGA work, keep two separate layers in every note:

- internal selectors / queue items / state-machine families
- final wire-level UART words or SPI transactions

This distinction appears to be the main place where otherwise-good warehouse
results become overcommitted.

### 3. Make confidence proportional to evidence type

Good places to be decisive:

- version-delta counts
- absolute peripheral xref counts
- presence/absence of a hardware-access surface

Places to be more cautious:

- exact task names
- exact pin roles inferred from xrefs
- “this is the acquisition task”
- “this is the exact wire protocol” when translation layers still exist

## Highest-Value Next Queries for ripcord

If the goal is to help unblock scope mode on the `osc` side, the next most
useful warehouse outputs would be:

1. Trace the final 16-bit words enqueued to the UART TX queue, not just the
   upstream selector families.
2. Distinguish which command-group claims are final wire observations and which
   are normalized internal selector families.
3. Re-check any PB11 / PC6 / PB6 role claims against hardware-confirmed maps
   before publishing them as facts.
4. Keep using cross-version analysis for prioritization, but avoid treating
   identical peripheral counts as proof of identical runtime choreography.

## Bottom Line

The strongest `ripcord` contribution so far is architectural narrowing:

- boot/runtime prerequisites matter
- grouped scope-entry families matter
- timer-driven runtime matters
- the hardware-facing surface is stable after V1.0.7

The main place to improve is confidence discipline:

- be sharper about what is observed versus inferred
- keep internal selectors separate from final wire traffic
- avoid hard task/pin labels until there is either bench support or a stronger
  disassembly anchor
