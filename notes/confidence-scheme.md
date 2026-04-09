# Confidence scoring scheme

Defines the column-level confidence representation for every
warehouse table that carries inferred or derived claims. Any code
that writes a `confidence` column must conform to this document.

## How to use this doc

Reference this file when:

- Adding a `confidence` column to any Parquet table in the warehouse.
- Writing an extractor, ingest script, or query that produces or
  consumes confidence scores.
- Designing the Phase 3 agent swarm's evidence log schema (this doc
  defines the column contract that the evidence log must be
  compatible with, but does not define the evidence log itself).

## Representation: 0.0–1.0 float

Every confidence score is a `FLOAT` column in Parquet, constrained
to the closed interval [0.0, 1.0]. NULL means "no claim made" (the
column is empty because the row has no inferred value to be
confident about). 0.0 means "a claim exists but there is no
evidence for it" — a different semantic from NULL.

**Why a continuous float, not categorical:** The evidence log needs
arithmetic. Thresholding ("show me everything above 0.8"),
comparison ("which of two conflicting claims is stronger"),
ordering ("prioritize the least-confident functions for agent
work"), and aggregation ("mean confidence across a library's
matched functions") all require a numeric type. Categorical labels
(low/medium/high) don't compose — you can't average them, you
can't threshold at an arbitrary cut, and you lose the ability to
express "this is a 0.92, better than a typical structural match
but not quite byte-identical." A float encodes the ordering and
the magnitude; categories encode only the bucket.

**Named thresholds for human readability:**

| threshold       | label      | meaning                                       |
|-----------------|------------|-----------------------------------------------|
| = 1.0           | exact      | byte-identical match with confirmed name       |
| >= 0.95         | verified   | multiple independent signals agree             |
| >= 0.80         | high       | strong structural match, minor ambiguity       |
| >= 0.50         | medium     | plausible match, needs corroboration           |
| < 0.50          | low        | weak or single-signal evidence                 |
| = 0.0           | none       | claim exists but has no supporting evidence    |

These labels are for display and documentation. They never appear
in the warehouse — the float is the truth. Queries can use them
as thresholds: `WHERE confidence >= 0.80` means "high or better."

## Calibration anchors

Concrete examples grounded in the project's current signals, so
that future producers assign scores on the same scale.

### 1.0 — byte-identical match

The function's `body_hash` (once that column exists) matches a
reference corpus function with the same hash and the same name.
The code is the same code. Reserved for cases where there is no
ambiguity: same bytes, same name, same behavior.

### ~0.96 — structural 8-tuple match with name confirmation

The function's structural signature `(size, basic_block_count,
instruction_count, outgoing_calls, distinct_callees, read_refs,
write_refs, jump_refs)` is identical to a reference function, and
both sides have matching non-auto-generated names. This is the
empirical precision of the Zephyr baseline: 72 of 75 clusters
correct, ~96% cluster-level precision. The 4% gap is within-target
structural twins, not cross-target false positives.

### ~0.85 — structural 8-tuple match without name confirmation

Same structural match, but one side has an auto-generated name
(`FUN_00008a3c`) while the other has a real name. The structural
evidence is strong but the name transfer is unconfirmed — the
function could be a structural twin of something else in the
target.

### ~0.70 — relaxed structural match (5-tuple)

Match on `(size, basic_block_count, instruction_count,
outgoing_calls, distinct_callees)` only, dropping xref features.
Weaker discrimination: the xref-count features were responsible
for splitting several ambiguous clusters in the Zephyr baseline.
Useful when xref data is incomplete or when matching across
targets where xref counts are known to vary.

### ~0.50 — skeleton match

Match on `(size, basic_block_count, instruction_count)` only.
Catches functions with the same gross shape but potentially
different call and reference structure. High false-positive rate
on small functions (many functions have 1 block, 3 instructions,
14 bytes). Useful as a candidate filter, not as a final answer.

### < 0.30 — single-feature heuristic

Size-only match, name-substring match, or other single-signal
heuristics. These are hints, not identifications. They belong in
the evidence log as supporting evidence for a higher-confidence
claim, not as standalone identifications in the canonical table.

### 0.0 — no evidence

A claim was made (e.g., an agent proposed a name) but no
structural, byte-level, or behavioral evidence supports it.
Distinct from NULL: the claim exists, it just has nothing
backing it.

## The `evidence_method` companion column

Every `confidence` column must be accompanied by an
`evidence_method STRING` column in the same table. This column
records how the confidence score was produced — not just how
confident the claim is, but what kind of evidence generated it.

**Why this is mandatory:** Two claims at 0.85 confidence are not
equivalent if one comes from a structural 8-tuple match and the
other comes from an agent proposal. The evidence method determines
what kinds of additional evidence could corroborate or contradict
the claim, what failure modes to expect, and how to prioritize
verification work.

**Format:** snake_case string tag. Examples:

| tag                              | meaning                                                |
|----------------------------------|--------------------------------------------------------|
| `body_hash_exact`                | byte-identical match via body_hash column               |
| `structural_8tuple_name_match`   | 8-tuple structural match + matching names               |
| `structural_8tuple_no_name`      | 8-tuple structural match, name unconfirmed              |
| `structural_5tuple`              | relaxed 5-tuple structural match                        |
| `structural_skeleton`            | size + blocks + instructions only                       |
| `name_substring`                 | heuristic name match (e.g., contains "memcpy")          |
| `agent_proposal`                 | LLM agent proposed this claim                           |
| `agent_proposal_verified`        | agent proposal that passed execution-based verification |

New methods are added as the pipeline gains new signal sources.
The tag vocabulary is not closed, but producers should reuse
existing tags when the method genuinely matches.

## Composition rules

When multiple independent signals support the same claim:

**Take the max, not a product or average.** If a function has a
structural 8-tuple match at 0.96 AND a body_hash match at 1.0,
the composed confidence is 1.0, not `0.96 * 1.0 = 0.96` and not
`(0.96 + 1.0) / 2 = 0.98`.

**Justification:** The signals in this pipeline are correlated,
not independent. A byte-hash match implies a structural match
(same bytes = same size, blocks, instructions, calls, xrefs). A
structural match with name confirmation is strictly stronger
evidence than a structural match without it. Multiplying
correlated probabilities double-counts the shared evidence;
averaging dilutes the strongest signal with weaker ones. Max
preserves the semantics: "the best evidence we have supports this
claim at confidence X."

**The evidence_method for a composed score concatenates the
contributing methods**, joined by `+`, in descending confidence
order. Example: `body_hash_exact+structural_8tuple_name_match`.
This preserves the full provenance chain while the max-confidence
float gives the headline number.

**Exception:** if a future signal source produces genuinely
independent evidence (e.g., execution-based verification is
independent of structural matching because it tests behavior, not
shape), that signal can *upgrade* an existing confidence beyond
the individual max. The upgrade rule: if an `agent_proposal` at
0.70 passes Unicorn differential testing, the result is
`agent_proposal_verified` at 0.90+, not `max(0.70, ...)`. This
is a promotion, not a composition — the evidence_method changes
to reflect the new, stronger basis. Define specific promotion
rules when the verification pipeline exists; don't over-specify
now.

## Update rules

### Higher-confidence signal for the same claim

Replaces the existing `confidence` and `evidence_method`. The
canonical table always shows the strongest evidence. The evidence
log (Phase 3, not yet designed) retains the full history.

### Conflicting signal (different claim, comparable confidence)

When two signals disagree — e.g., structural matching says the
function is `z_thread_abort` at 0.96 but an agent proposes
`k_thread_suspend` at 0.85 — both are preserved in the evidence
log. The canonical table shows whichever has higher confidence.

A `conflict BOOLEAN` column (default FALSE) is set to TRUE on any
row where the evidence log contains a competing claim within 0.15
of the canonical claim's confidence. This flags rows where the
identification is contested and human review or additional evidence
would be high-value. The 0.15 threshold is a starting point; adjust
based on empirical false-conflict rates once the pipeline produces
enough contested identifications to measure.

### Retraction

If evidence is later found to be invalid (e.g., a reference corpus
entry was misbuilt), the confidence is set to 0.0 and the
evidence_method is set to `retracted:<original_method>`. The claim
remains in the evidence log with its retraction marker. Downstream
consumers that filter on `confidence >= 0.50` automatically exclude
retracted claims.

## Schema implications

The first table to gain these columns is `functions`. The new
columns are:

```
inferred_name       STRING    -- NULL if no name inferred
inferred_library    STRING    -- NULL if no library identified
confidence          FLOAT     -- NULL if no claim; 0.0–1.0 if claim exists
evidence_method     STRING    -- NULL iff confidence is NULL
conflict            BOOLEAN   -- default FALSE
```

These columns are added to the pyarrow schema in
`scripts/ingest/schemas.py`. They are NULL for all rows produced
by Stage 0 extraction (which has no inference); they are populated
by Stage 1 library identification or later stages.

Other tables that will eventually carry confidence scores (e.g.,
`registers.inferred_name`) must use the same column names and the
same semantics defined here. One scheme, project-wide.

## What this doc does NOT define

- **The evidence log schema.** That is a Phase 3 concern (the
  SQLite coordination layer described in `pipeline-architecture.md`
  Stage 6). This doc defines the column-level contract that the
  evidence log's producers and consumers must agree on. The log's
  own table structure — append-only rows, agent IDs, timestamps,
  contradiction links — is a separate design.
- **Agent-specific confidence calibration.** When LLM agents
  produce confidence scores, they will need prompt-level guidance
  on what the numbers mean. That guidance should reference this
  doc's calibration anchors, but the prompt engineering is not
  specified here.
- **Per-method confidence curves.** As the pipeline matures, each
  evidence_method will develop its own empirical precision curve
  (e.g., "structural_8tuple_name_match is 96% precise on Zephyr
  same-build pairs"). Those curves inform the confidence values
  assigned by each method but are tracked in the method's own
  documentation, not here. This doc defines the scale; the methods
  populate it.
