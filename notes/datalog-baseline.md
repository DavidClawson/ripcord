# Datalog Derivation Layer — Baseline (2026-04-08)

## Setup

**Souffle 2.5** installed via `brew install souffle` (64-bit, ARM).
Runs in interpreted mode over tab-separated `.facts` files exported
from the warehouse. No compilation step needed at current scale.

Derivation rules: `scripts/datalog/reachability.dl`
Fact export helper: `scripts/datalog/export_facts.py`
DuckDB equivalent: `notes/queries/reachability.sql`

## What gets derived

Five output relations from two base facts (calls, function names):

| output                    | rows (pico_freertos_hello) | rows (zephyr_hello_world) |
|---------------------------|---------------------------|--------------------------|
| `reaches.csv`             | 1,768                     | 607                      |
| `reach_count.csv`         | 265                       | 110                      |
| `orchestrators.csv`       | 20                        | 4                        |
| `unreachable_from_main.csv` | 184                     | 104                      |
| `subsystem_pairs.csv`     | 109                       | 3                        |

Runtime: sub-second on both targets (708 and 154 call edges respectively).

## Key findings

### Reachability from main

**pico_freertos_hello:** 80 of 265 functions (30%) reachable from
`main` via direct calls. Max depth 8. The remaining 184 functions
include ISR handlers, FreeRTOS task functions (`prvTimerTask`,
`async_context_task`), queue/semaphore internals called from ISR
context, and library support functions.

The 70% "unreachable" figure is expected and informative — it
identifies the entire set of functions that enter execution through
non-call-graph paths (interrupt vectors, function-pointer dispatch
via `xTaskCreate`, callback registration). This is exactly the set
that needs special treatment in any whole-program analysis.

**zephyr_hello_world:** Similar pattern. `z_arm_reset` has the
highest transitive reach (33 functions), followed by
`z_arm_hard_fault` (33) and `z_arm_fault` (32). Only 6 of 110
functions are reachable from `main` through `bg_thread_main`.

### Top orchestrators (pico_freertos_hello)

Functions with both high direct fan-out (>=5) and high transitive
reach (>=20):

| function                               | direct | transitive |
|----------------------------------------|--------|------------|
| `main_task`                            | 5      | 79         |
| `async_context_task`                   | 13     | 41         |
| `vTaskStartScheduler`                  | 5      | 40         |
| `async_context_freertos_execute_sync`  | 7      | 40         |
| `async_context_freertos_init`          | 6      | 40         |
| `async_context_freertos_*_worker` (x4) | 12     | 37         |
| `_ftoa` / `_etoa`                      | 14/13  | 22         |
| `xQueueSemaphoreTake`                  | 13     | 20         |
| `prvTimerTask`                         | 10     | 23         |

Two distinct orchestrator populations: application-level
coordinators (`main_task`, `async_context_*`) and infrastructure
(`vTaskStartScheduler`, `xPortStartScheduler`, queue operations).
The `_ftoa`/`_etoa` pair is a printf subsystem artifact — they call
many math helpers.

### Subsystem clusters

The strongest cluster is the `async_context_freertos_*_worker`
family: 4 functions sharing 11 callees each (pairwise). These are
the add/remove x at-time/when-pending worker functions — they share
nearly identical call structure because they're symmetric operations
on the async context.

Second cluster: `xQueueGenericSend` / `xQueueReceive` /
`xQueueSemaphoreTake` sharing 10-11 callees — the core FreeRTOS
queue/semaphore API.

Third cluster: `_ftoa` / `_etoa` sharing 8 callees — printf's
float-to-ASCII and exponent formatting.

## Souffle vs DuckDB recursive CTEs

Both produce identical results. Tradeoffs:

- **Souffle** is the right tool when derivation rules get complex
  (taint analysis, multi-hop reasoning with constraints, negation
  over derived facts). Souffle's semi-naive evaluation is
  asymptotically better than CTE iteration for deep transitive
  closures. It also makes rules declarative and composable.

- **DuckDB CTEs** are sufficient for the current three derivations
  and don't require an extra tool. Good for ad-hoc exploration.

**Decision: keep both.** Souffle for the committed derivation layer
(will grow with taint analysis, contradiction detection, etc.),
DuckDB CTEs for ad-hoc queries during exploration. The fact export
step is trivial and already scripted.

## Next steps

1. Add the Souffle step to the Snakefile as an optional rule
   (derived facts depend on calls + functions tables).
2. Add xrefs-based derivations: "which functions can write to
   address X" (register-write reachability for Stage 3/4 overlap).
3. Add computed-call-target analysis: the 184 unreachable functions
   include FreeRTOS tasks passed to `xTaskCreate` as function
   pointers. Recovering these edges would close a significant gap
   in the call graph.
