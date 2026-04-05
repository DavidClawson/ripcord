# Function Fingerprinting

A research thread, not strictly required for v1 of the pipeline, but
potentially the highest-leverage auxiliary capability we could build.
Goal: given an unknown function in a stripped firmware binary, classify
it — "this is the FreeRTOS scheduler," "this is an STM32 HAL UART
wrapper," "this is SHA-256," "this is application logic" — without
needing an exact byte-for-byte match against a known reference.

This is a well-studied problem in academic binary analysis and in
commercial tools like IDA's FLIRT and Google's BinDiff, but nobody has
built a clean, open, multi-signal classifier specifically for embedded
firmware RE. That's the gap worth filling.

## The core insight

Function identification is not a single-signal problem. Different kinds
of code have different kinds of tells, at different levels of the
binary, with different robustness to compilation variation. A good
classifier combines many cheap signals before reaching for any
expensive ones, and uses each signal in the context where it is
strongest.

The cheapest signals are staggeringly good for specific categories. You
don't need deep learning to recognize SHA-256 — you need to see if the
function touches `0x6A09E667`. You don't need a GNN to recognize an HAL
UART wrapper — you need to see that it touches addresses in the UART
peripheral range and has fewer than twenty instructions. The elaborate
techniques are for the residue that remains after the simple ones have
done their work.

## Signals, cheapest to richest

### 1. Constants

**By far the most powerful single signal, and the most under-appreciated.**

Cryptographic code is drowning in magic numbers that are effectively
impossible to fake accidentally:

- **SHA-256:** `0x6A09E667`, `0xBB67AE85`, `0x3C6EF372`, `0xA54FF53A`,
  `0x510E527F`, `0x9B05688C`, `0x1F83D9AB`, `0x5BE0CD19` (the eight
  initial hash values, plus the 64 round constants)
- **SHA-1:** `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`,
  `0xC3D2E1F0`
- **MD5:** `0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476` (same
  first four as SHA-1), plus the table of sines used as round constants
- **AES:** the S-box (256 bytes, first entry `0x63`, second `0x7C`),
  the inverse S-box, `Rcon` (round constants), MixColumns matrix
- **Curve25519:** the prime `2^255 - 19`, the curve constant `486662`
- **P-256:** the curve's a, b, p, n, Gx, Gy constants
- **ChaCha20/Salsa20:** `"expand 32-byte k"` as a literal
- **CRC:** polynomial tables (CRC-32 `0xEDB88320`, CRC-16-CCITT
  `0x1021`, etc.)

Most DSP and compression algorithms have similarly distinctive
constants: FFT twiddle factors, Huffman tables, Reed-Solomon field
polynomials, DCT coefficients, YUV conversion matrices, JPEG quantization
tables.

A **constant signature** — just the sorted set of immediate values and
referenced .rodata constants used in a function — classifies an enormous
fraction of library code essentially for free. Build this database
once (a few hundred entries covers most of what you'll actually see in
embedded firmware) and run it against every function in every target.

### 2. Strings referenced

If any symbols, error messages, log strings, debug prints, or format
strings survived stripping — and they usually do, because they live in
`.rodata` — they are almost self-identifying.

- `"Task %s stack overflow"` → FreeRTOS stack overflow hook
- `"HAL_UART_Transmit_DMA"` → ST HAL debug print
- `"USB: device reset"` → USB stack
- `"NAND: bad block %d"` → flash driver
- Even without exact strings, the *distribution* of string types —
  many short tokens vs. long sentences, error-code format strings,
  protocol keywords — is a feature.

### 3. Addresses touched

Memory-mapped I/O addresses on a given chip family are stable and
documented. A function that writes to `0x40011000` on an STM32F4 is
touching USART1 — the address itself tells you so.

- Peripheral base addresses → peripheral driver
- Interrupt vector table region → exception handler / startup code
- SCB / NVIC region → core system code, context switch, fault handler
- External bus (FSMC/EXMC on this chip) → external device driver
  (this is the cord project's whole problem)

A function whose MMIO access set is contained entirely within one
peripheral region is almost certainly that peripheral's driver.

### 4. Call graph neighborhood

A function's position in the call graph is enormously informative,
often more so than the function's bytes:

- A function called from the interrupt vector table is an ISR.
- A function that calls `xTaskCreate` is application startup.
- A function that *is called by* `xTaskCreate` is FreeRTOS internal.
- A function that sits between application code and MMIO is an HAL
  wrapper.
- A function with no external callers but many callees is likely
  `main` or an application dispatcher.

Label propagation through the call graph is cheap: once you've
identified a seed set of functions by other signals, their neighbors
inherit probabilistic labels. Iterate to fixpoint.

### 5. Control flow shape

Different kinds of code have distinctive CFG topologies, and these are
robust across compilers because the *structure* of the algorithm
determines the structure of the code.

- **RTOS context switch:** save all registers, walk a ready list or
  priority queue, select a task, restore registers, exception return.
  Very distinctive CFG — large basic block of loads/stores,
  list-walking loop, large basic block of restores.
- **AES rounds:** nested loop, outer iteration count 10/12/14,
  characteristic shift/XOR/table-lookup pattern.
- **Ring buffer operations:** small state machine with head/tail
  arithmetic and a wraparound branch.
- **Polling loops:** tight cycle with a single exit condition on a
  volatile read.
- **Linked list walks:** loop with a `next = curr->next; curr = next`
  pattern, null-terminated.
- **State machines:** large switch statement or dense if/else chain
  with one variable driving everything.

Features to extract: basic block count, edge count, loop count,
back-edge depth, longest path, cyclomatic complexity, branching
factor, dominator tree shape.

### 6. Normalized instruction n-grams

Take sequences of N consecutive instructions, normalize away register
allocation and immediates, compute frequency distributions. Different
function classes have characteristic distributions:

- Crypto: XOR/shift/rotate/AND-heavy
- RTOS kernel: interrupt masking (`cpsid`/`cpsie`), atomic operations,
  list/queue manipulation
- HAL drivers: mostly load/store, few branches
- Application: balanced mix, usually function-call-heavy

A classifier on these features alone (random forest or gradient-boosted
trees) catches a lot of the "what family is this" question before
anything fancier.

### 7. Byte-level patterns (FLIRT-style)

The weakest signal alone, but the cheapest to compute and useful as a
tiebreaker. Exact byte matches with wildcards for relocated addresses
and immediates. Works when the unknown binary was compiled with the
same toolchain as your reference. Fragile to compiler version changes.

### 8. Learned embeddings — the research frontier

Train a neural model to produce per-function vectors such that
semantically similar functions cluster. Classification becomes a
nearest-neighbor search in embedding space.

Published approaches:

- **Asm2Vec** (Ding et al.) — word2vec applied to assembly. Robust
  across optimization levels. Good starting point.
- **Gemini** (Xu et al.) — graph neural networks on CFGs. Learns an
  embedding that respects structural similarity.
- **SAFE** (Massarelli et al.) — self-attentive function embeddings.
- **PalmTree** (Li et al.) — BERT-style pretraining for assembly
  language modeling.
- **jTrans** (Wang et al.) — transformer model for binary similarity.
- **BinShot, CodeCMR** — more recent contrastive approaches.

These work well but need GPU training and a labeled corpus. They shine
in the fuzzy middle — functions that don't match exactly but are
"clearly the same kind of thing."

### 9. Symbolic-execution semantic hashing

Run the function in a symbolic executor (angr) on a canonical input
distribution, hash the input-output relationship. Two functions that
compute the same mathematical function produce the same semantic hash
regardless of how they're written. Catches code that is byte-different,
CFG-different, *and* constant-different but computationally equivalent
— e.g., two hand-written CRC implementations that differ in how the
polynomial is unrolled.

Expensive. Reserve for high-stakes verification.

### 10. LLM-as-classifier (fallback)

For the residue that none of the above classify, assemble a structured
dossier for each function — instruction summary, constants, strings,
caller list, callee list, MMIO regions touched, inferred category of
neighbors — and ask an LLM for a classification with reasoning. Works
well because the LLM is pattern-matching over structured evidence, not
guessing from raw bytes. Reserve for the 5-10% of functions where
everything cheaper failed.

## Existing tools worth knowing

- **FLIRT** (IDA Pro) — byte patterns with wildcards. The industry
  baseline for library identification. Exact compiler/version matches
  only. Closed format but there's open documentation.
- **Lumina** (Hex-Rays) — crowd-sourced function knowledge base in IDA.
  Useful when someone has already RE'd your target; useless for a
  novel binary.
- **Karta** (Check Point, free IDA plugin) — *specifically designed for
  library identification in firmware* using structural features and
  version-aware matching. The closest public tool to what we'd want.
  Read their paper and source.
- **BinDiff** (Google/Zynamics, free) — graph-based similarity between
  two binaries. The workhorse for "I have a compiled reference, find
  matches in this other binary."
- **Diaphora** — open-source BinDiff alternative for IDA/Ghidra.
- **FunctionSimSearch** (Google) — MinHash over weighted CFG features
  for fast similarity search at scale. Open source.
- **Ghidra function ID databases** — Ghidra's built-in equivalent to
  FLIRT. Weak out of the box but extensible.
- **Gemini, SAFE, Asm2Vec, jTrans, PalmTree** — academic neural
  embedding systems; some have code available.

## The synthesis: a self-improving classifier + corpus loop

None of the existing tools combine all these signals the way a modern
pipeline could, and none of them are designed to produce an
ever-growing labeled corpus as a side effect. The interesting research
shape is:

1. **Build a labeled corpus** (the fingerprint library) by scraping
   and compiling open source embedded code at scale. Every function is
   tagged with its source name, origin library and version, and
   category (scheduler, HAL, driver, crypto, compression, protocol,
   application, etc.).
2. **Extract a fat feature vector per function**: constants, strings,
   MMIO ranges, CFG descriptors, instruction-mix histograms,
   call-graph-neighborhood fingerprints, and optionally a learned
   embedding from Asm2Vec or similar.
3. **Train a multi-label classifier** on the corpus. Gradient-boosted
   trees for the fast path; an LLM-backed classifier for the hard
   path; both producing confidence scores.
4. **Apply the classifier to any target binary**. High-confidence
   matches populate the warehouse directly. Low-confidence ones
   become tasks for the agent swarm with the classifier's top-K
   guesses as context.
5. **Feed verified results back into the corpus.** Any function that
   gets confidently identified in a target binary and passes
   downstream verification (via differential testing) is a new
   labeled training example. The corpus grows; the classifier
   improves; future targets get identified more accurately.

**The fingerprint library and the classifier are two sides of the same
thing, and building one is building the other.** This is the
self-improving loop: every project using the pipeline contributes back
to the corpus, which improves every future project.

## A cheap start for this specific project

You don't need any of the fancy stuff to get enormous value on day one.
For cord specifically:

1. **Build a FreeRTOS-only classifier** by compiling FreeRTOS in a
   handful of configurations (GCC versions, optimization levels) and
   extracting per-function structural hashes and constant sets. Target
   a single chip family (Cortex-M4) to start.
2. **Build an AT32 SDK classifier** the same way from the vendor
   library already in this repo.
3. **Run both against the cord firmware.** Match everything you can
   with high confidence, tag it, and stop.

That's maybe a week of work and probably identifies 50-80% of the
binary. Every subsequent phase (agents, Datalog, Unicorn verification)
runs on a warehouse where most of the noise is already labeled.

## The narrow "FreeRTOS vs HAL vs crypto" question

For just these three categories, you don't need ML at all:

- **Crypto detection:** constants database. One day of work, ~99%
  reliable for any well-known primitive. Essentially free.
- **FreeRTOS detection:** structural match on the scheduler, queue, and
  list implementations against a compiled reference. Karta-style
  matching handles this. One to two days.
- **HAL detection:** "touches MMIO addresses in vendor-specific
  peripheral ranges" plus "short function that wraps a read-modify-write
  pattern." One day.

All three detectors together in a week, zero training data, zero
classifier, and they cover most of the easy cases. The classifier is
for the residue. Start with the cheap detectors; earn your way into the
expensive techniques only when you hit things they can't handle.

## A concrete first experiment

Cheapest way to validate the whole fingerprinting thesis:

1. Compile FreeRTOS for a Cortex-M4 target in three configurations:
   `-O0`, `-O2`, `-Os`, with GCC 12.
2. Strip all three binaries.
3. Extract per-function features: constant sets, string refs, CFG
   descriptors, call-graph neighborhoods.
4. Build a tiny lookup-table classifier keyed on
   `(constant_set_hash, cfg_hash) → function_name` from the unstripped
   reference.
5. Score: what fraction of functions does the classifier correctly
   identify across all three optimization levels?

Two days of work. Tells you whether byte-level matching is robust
enough to optimization changes on its own, or whether you need
structural features and learned embeddings from day one. Gives you a
concrete lower bound on the value of the fingerprinting approach
before you invest in the harder techniques.

## Why this matters beyond cord

A good open multi-signal function classifier for embedded firmware
doesn't exist publicly. FLIRT is IDA-locked. Ghidra's function ID
databases are weak. BinDiff is for pairs, not for classification.
Academic neural embeddings are research prototypes. Nothing ties these
techniques together with a labeled corpus and an RE pipeline that can
consume and produce labels.

Building this is a **reusable capability that outlives any single
target**. Every future firmware RE project starts with a substantial
fraction of its binary already identified. The corpus itself —
open-source, CI-buildable, hash-addressable — is publishable and
benefits the broader community. And the research narrative (a
self-improving classifier + corpus loop for embedded binary analysis)
is genuinely publishable as academic work if that's of interest.

The cord project is the first customer; the infrastructure is general.
