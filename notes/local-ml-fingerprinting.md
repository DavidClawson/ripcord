# Local ML Fingerprinting

A research thread that extends `fingerprinting.md` with a learned-model
approach: train a small embedding model on a corpus of compiled
open-source firmware, run it locally on Apple Silicon, and use its
output as a fast deterministic pre-pass before any LLM work. Pairs
naturally with the rule-based fingerprinting already described
elsewhere in these notes — rules handle the easy cases, a learned
model handles the fuzzy residue.

## Why this idea has unusually good economics for ML

Most ML projects in reverse engineering and security fail on labels.
Labeled data is expensive; humans have to tag functions one by one and
quality control is slow.

For this problem, **labels are free by construction**. You compile
open-source firmware from known source, and every function in the
output binary comes with:

- Its source function name
- Its source file and module
- Its DWARF type info (parameters, return, locals)
- Its position in the call graph
- The exact compiler, version, flags, and target used
- Optional: debug line info tying instructions to source lines

You can generate unlimited labeled data by compiling more projects,
with more toolchain configurations, for more target chips. The same
infrastructure that powers the validation corpus from
`test-corpus-and-validation.md` also powers ML training. Every CI
build is a new batch of training examples.

This is the single most important property of the idea. Most
adjacent problems don't have it.

## Pick the right model type

"Embedding model" is ambiguous. Three distinct things it could mean:

**Classifier.** Fixed label set, outputs a probability distribution
over known categories (`FreeRTOS_scheduler`, `STM32_HAL_UART`,
`AES_core`, `application`, etc.). Simple and effective but brittle —
adding a new category means retraining, and anything the classifier
hasn't seen gets silently misclassified as "something it has seen."

**Contrastive embedding model.** Outputs a vector per function such
that semantically similar functions are close in vector space.
Classification becomes nearest-neighbor lookup against a labeled
reference set. **More flexible** because adding a new category means
adding a new reference point, not retraining. The embedding itself is
also a feature that other tools and classifiers can consume.

**Self-supervised masked language model.** Trained with a BERT-style
objective (mask an instruction, predict it) on a large unlabeled
corpus. Produces general-purpose representations without requiring
labels. PalmTree is the canonical published example.

**Recommended recipe: MLM pretraining, then contrastive fine-tuning.**
Pretrain on a big pile of unlabeled embedded binaries to learn what
"instructions that go together" look like, then fine-tune on a smaller
labeled set with contrastive pairs (same source function across
different toolchain configs → positive pair; different functions →
negative pair). This is the standard modern recipe and it works well
in low-data regimes, which this is.

## Tokenization is the most important design decision

Raw bytes are a bad tokenization — too low-level, compiler-fragile.
Disassembled instructions with concrete operands are better but still
register-allocation-fragile. The published academic answer is
**normalized disassembly**: keep opcodes, replace register names with
ABI roles, bucket immediates by magnitude class, keep control flow
markers explicit. Asm2Vec, PalmTree, jTrans all use variants.

**But there's a better answer nobody seems to have tried: tokenize
Ghidra P-Code instead of disassembly.**

P-Code is already a normalized architecture-independent IR. By the
time P-Code is generated, most of the things you would otherwise have
to train the model to normalize have *already been normalized* by
Ghidra:

- **Register allocation invariance** — P-Code uses abstract varnodes,
  not physical registers.
- **Addressing mode invariance** — complex addressing modes are broken
  out into explicit arithmetic operations.
- **Calling convention invariance** — arguments and returns are
  abstracted.
- **Cross-architecture portability** — the same P-Code opcodes work
  across ARM, x86, MIPS, PowerPC, etc. A model trained on Cortex-M4
  P-Code has a fighting chance of generalizing to Cortex-M7, RISC-V,
  or x86 with modest fine-tuning.

Most existing binary embedding work predates Ghidra's 2019 open
release and inherited the "assembly is the input" convention from
earlier tools. Training on P-Code instead is a plausible improvement
that costs essentially nothing extra — the extraction pipeline already
produces P-Code for other reasons.

**This is the single most interesting research angle in the whole
pipeline.** Not because it's dramatic, but because it's a simple
modification to an existing well-studied recipe that has a real chance
of being a genuine improvement.

## Multi-modal features

Even with great tokenization, a pure sequence model throws away
information. Modern recipe: multiple encoders, one per modality, with
late fusion trained end-to-end on the contrastive objective.

Views worth encoding:

1. **P-Code instruction sequence** — transformer encoder, captures
   local operation patterns.
2. **Control flow graph** — graph neural network or hand-crafted graph
   features. Captures structure (loop depth, branching factor,
   dominator tree shape).
3. **Constant set** — sparse embedding over referenced immediates and
   rodata values. Crypto constants, CRC polynomials, and DSP tables
   light up this channel brightly.
4. **String reference set** — sparse embedding over referenced strings
   if any survived stripping.
5. **Call-graph neighborhood** — graph embedding of the 1-hop or 2-hop
   neighborhood in the overall call graph. Context-aware.
6. **MMIO access profile** — which peripheral regions the function
   touches, as a categorical vector. HAL drivers have distinctive
   profiles here.

Concatenate the per-modality vectors, pass through a small fusion
MLP, produce the final function embedding. Train end-to-end.

Different function categories are distinctive in different modalities.
Crypto shows up in constants. HAL drivers show up in MMIO profile.
Kernel scheduler shows up in CFG shape. Application orchestration
shows up in call-graph neighborhood. A multi-modal model catches all
of them; a pure sequence model catches only the ones visible in the
instruction stream.

## Running on an M1 Max

The compute requirements are entirely within reach. M1 Max has:

- ~25 TOPS on the Neural Engine
- 32-core GPU with ~10 TFLOPS fp16
- 32 or 64 GB of unified memory (no CPU/GPU copy overhead)

For models in the 30-100M parameter range, which is overkill for this
task but comfortable for the hardware:

- **Inference**: ~1-10 ms per function on the Neural Engine via Core
  ML, or on the GPU via MLX. Classifying 5,000 functions in a 700KB
  firmware binary takes seconds end to end.
- **Training**: fine-tuning on a few hundred thousand labeled pairs is
  hours of wall time. Full MLM pretraining from scratch on a larger
  unlabeled corpus is days. Neither is prohibitive on a laptop.
- **Memory**: comfortable headroom even with 32GB. You won't be memory
  bound.

### Framework choice

- **MLX** (Apple's native ML framework, late 2023 onward) — designed
  specifically for Apple Silicon, uses unified memory natively, simpler
  than Core ML. Probably the right default for this project in 2026.
- **PyTorch with MPS backend** — more mature ecosystem, works fine on
  Apple Silicon for both training and inference. Safe choice if you
  want maximum library compatibility.
- **Core ML + `coremltools`** — the production deployment path to the
  Neural Engine. Only worth the conversion overhead if you need ANE
  dispatch specifically or want to deploy to iOS/iPadOS. For a local
  Mac workflow, MLX on the GPU is usually fast enough.
- **llama.cpp / ggml with Metal backend** — if you end up using a
  larger pretrained code model rather than training your own, this is
  the fastest inference path on Apple Silicon.

Note on the Neural Engine specifically: the ANE is optimized for
certain operator patterns (conv-heavy, some matmul) and Core ML
dispatches there automatically when the model fits. For transformer
models with dynamic sequence lengths, the GPU via MPS or MLX is often
the faster path. Don't fixate on "runs on ANE" as a goal. The right
framing is "runs fast on Apple Silicon" and MLX or Core ML handles the
dispatch decisions automatically.

## The corpus is harder than the model

The model architecture is commodity in 2026. The thing that actually
determines whether this works is the corpus, and it's where the real
engineering effort goes.

Good corpus needs:

- **Diverse project sources**: FreeRTOS, Zephyr, NuttX, mbed, ESP-IDF,
  Arduino cores, vendor HALs from every major MCU manufacturer (ST,
  NXP, Nordic, Silabs, Microchip, Artery, TI), common libraries
  (lwIP, mbedTLS, wolfSSL, FatFS, LittleFS, tinyusb, libopencm3).
- **Multiple toolchain configurations per project**: GCC 10 through
  14, Clang, `-O0` through `-O3` and `-Os`/`-Oz`, with and without LTO,
  with/without `-ffunction-sections`, for several `-mcpu` targets.
- **Multiple architectures**: Cortex-M0, M0+, M3, M4, M7, M33, plus
  RISC-V as it gains ground in embedded. Cortex-M4 is the priority
  for the cord project but diversity helps generalization.
- **Automated build infrastructure**: Docker-based build farm or CI
  matrix that produces thousands of labeled binaries unattended.
- **Label extraction**: from unstripped ELFs, extract per-function
  name, source file+line, module, DWARF types, call graph position.

Rough target for a first corpus: ~1-2 million labeled functions across
~100 projects and ~20 toolchain configurations. That's a few weeks of
setup, then corpus entries are generated for free.

**The corpus is also a standalone public good.** No open labeled
corpus of embedded binaries for fingerprinting research exists today.
Publishing one — independent of any model trained on it — would be a
real contribution to the field and is reusable for every downstream
project in perpetuity.

## Phasing into the existing roadmap

`fingerprinting.md` describes rule-based fingerprinting as Phase 1.
The ML approach extends that with later phases:

1. **Phase 1 — Rules.** Constants, strings, MMIO ranges, structural
   matching against compiled references. No ML. Probably 60-80%
   coverage of library code in typical firmware. Already documented.
2. **Phase 2 — Hand-crafted features + GBDT.** Extract explicit
   features (instruction histograms, CFG descriptors, constant set
   hashes, call-graph neighborhood fingerprints), train an XGBoost or
   LightGBM classifier. Very interpretable, fast iteration, no deep
   learning infrastructure. Adds ~10-15% over rules. Great middle step
   because the feature extraction code also feeds the deep model.
3. **Phase 3 — Small P-Code embedding model on Apple Silicon.** The
   idea in this file. MLM pretraining on unlabeled binaries,
   contrastive fine-tuning on the labeled corpus, local inference via
   MLX or Core ML. Catches the fuzzy cases rules and GBDTs miss.
4. **Phase 4 — Multi-modal model.** P-Code sequence encoder + CFG
   graph encoder + constants/strings/MMIO sparse encoders + call-graph
   context, combined via late fusion. The full research version. Only
   worth building if Phase 3 plateaus and the residue matters.

Each phase is independently useful. You can stop at any phase and
still have a working pipeline.

## What's genuinely novel versus existing work

Most of the techniques above are published in some form. The pieces
that are potentially new and worth explicit attention:

1. **Training function embeddings on Ghidra P-Code instead of
   disassembly.** A small, simple, plausibly substantial improvement
   on published methods. Nobody seems to have tried it yet because
   most published work predates modern Ghidra tooling.
2. **The paired corpus + classifier + open pipeline as a community
   resource.** A public labeled corpus of embedded binaries with
   reference models trained on it doesn't exist. Publishing one is a
   contribution independent of any single project using it.
3. **Tight integration with a fact database and agent swarm.** Most
   published binary similarity work is standalone — produce embeddings,
   do nearest-neighbor search, publish accuracy numbers. Integrating
   the classifier into a pipeline where its outputs directly populate
   a structured warehouse and gate LLM agent tasks is a different
   architectural claim that hasn't really been tested in published
   form.

Neither of these is strictly necessary for the cord project — the
rule-based phase probably gets you far enough to finish that specific
target. But if research direction is part of the appeal alongside the
immediate practical goal, this is where real contribution lives.

## Sidebar: is Ghidra pseudo-C actually compilable?

A question that came up while discussing this: does Ghidra output C
that compiles and runs?

**Short answer: not reliably, and not as-is.** Ghidra's decompiler
output is *C-like pseudocode* that's readable and semantically
meaningful but not directly compilable, for specific reasons:

- Made-up type names like `undefined4`, `undefined8`, `byte`, `dword`
  that aren't standard C and aren't defined in the output file.
- References to internal Ghidra labels like `DAT_20001000` and
  `PTR_FUN_8004a20` that aren't declared anywhere.
- No headers, no forward declarations, no struct definitions alongside
  function bodies.
- Pseudo-operations like `CONCAT44(a, b)` or `SUB84(x, 4)` for
  operations that don't have clean C equivalents.
- Heavy casts through invented types.
- Occasional calling-convention leakage and raw register references
  when analysis was incomplete.

With post-processing it can often be made to compile: provide a
header defining the synthetic types, declare the `DAT_*` references
as externs, replace the intrinsics, hand-fix bad signatures. There
are community tools and scripts that do this. **retdec** (Avast, open
source) is an alternative decompiler whose explicit goal is compilable
output; it does better than Ghidra for simple functions, comparably
or worse for complex ones.

For this pipeline's purposes, though, **whether Ghidra output compiles
is the wrong question.** Ghidra's pseudocode is a feature extraction
intermediate, not an end state. The real intermediate representations
are:

- **P-Code and HighPCode** — normalized, precise, unambiguous, the
  right input for tools and model training.
- **The fact database** — for queries and agent consumption.
- **Rendered C or Rust** — a late-stage human-readable view,
  produced only when you want something humans will read.

The verification step isn't "recompile Ghidra output and diff" — it's
Unicorn differential testing and Renode trace comparison. Ghidra's C
output is just a human-friendly rendering along the way. Treating it
as "structured notes the tool is showing you" rather than "source code
you could build" is the productive mental model.

## Open questions to resolve before starting

1. **MLX or PyTorch MPS for training?** Probably MLX for new code in
   2026, PyTorch for anything that needs the wider library ecosystem.
   Worth a small prototype to compare for this specific workload.
2. **Corpus scope v1.** How many projects, how many configs, how many
   architectures? Start small (10 projects × 4 configs × 1 arch) and
   expand once the pipeline works.
3. **Labeling granularity.** Function-level labels are the obvious
   unit. Should there also be basic-block or subroutine-level labels?
   Probably not for v1.
4. **Confidence calibration.** Neural classifier raw softmax scores
   are notoriously miscalibrated. Plan for temperature scaling or
   Platt scaling on held-out data before trusting "90% confidence"
   outputs.
5. **Compiler-specific vs. compiler-agnostic model.** A model trained
   on GCC output might not generalize to Clang. Multi-compiler
   training data is essential; otherwise performance collapses on
   out-of-distribution targets.
6. **Target architecture scope.** Cortex-M4 only, or all Cortex-M, or
   broader? Depends on corpus availability. Start narrow, expand.
7. **How to publish the corpus** (if at all). License choice, hosting,
   versioning. Deferred until there's something worth publishing.
