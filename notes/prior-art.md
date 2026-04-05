# Prior Art and Adjacent Communities

No one (publicly) has built exactly what this pipeline describes —
parallel LLM swarms over a blackboard database with hardware-trace-anchored
differential verification for firmware replication against opaque FPGAs.
But every individual piece has been built by someone, and several adjacent
communities have solved related problems well. The N64 decompilation scene
and the Asahi Linux project are the two most directly useful references.

## Communities doing binary RE at serious scale

### Malware analysis / threat intelligence

**Who:** Mandiant, Kaspersky, Microsoft Defender, ESET, FireEye, internal
teams at large security vendors.

**Goal:** Triage thousands of samples fast, extract indicators of
compromise, write detection rules.

**Tooling:** IDA Pro (industry standard for high-end work), Ghidra, Binary
Ninja. YARA for pattern matching. FLIRT/FLARE for library identification.
Proprietary ML triage pipelines.

**Relevance:** Low. They go wide and shallow; we go narrow and deep.
Worth knowing the techniques exist.

### Vulnerability research / exploit development

**Who:** Google Project Zero, Trail of Bits, NCC Group, IOActive,
Quarkslab, ZDI, academic groups at CMU, UCSB, Eurecom.

**Goal:** Find bugs and write exploits against specific targets.

**Tooling:** IDA/Ghidra/Binary Ninja + angr, BAP, Triton, Manticore. They
pioneered most of the symbolic-execution-for-RE tooling we'd use.

**Relevance:** High for technique. Trail of Bits specifically publishes
serious open-source tooling (anvill, mcsema, remill, cclyzer) and writes
extensively about binary analysis pipelines. Follow their blog.

### Academic binary analysis

**Who:** UCSB (angr origin, Shoshitaishvili et al.), CMU (BAP, Doop,
pointer analysis tradition), Eurecom, TU Darmstadt, Georgia Tech.

**Papers to know:**
- *(State of) The Art of War: Offensive Techniques in Binary Analysis* —
  the angr paper, S&P 2016
- Doop / Soufflé papers on Datalog-based static analysis
- DIRE / DIRTY — learned variable naming from stripped binaries
- LLM4Decompile, DeGPT, SLaDe, Resym — LLM-assisted decompilation research
- Nova (Meta, 2024) — assembly-to-source with language models

**Relevance:** Medium-high. Reading one or two angr papers will pay for
itself. Resym in particular addresses the "type recovery is the hard
problem" issue we discussed.

### Firmware security research

**Who:** Red Balloon Security (Ang Cui), Quarkslab, Tactical Network
Solutions, academic IoT security groups.

**Tooling:** FIRMADYNE, FirmAE, Firmware Analysis Toolkit, Binwalk, EMBA,
HALucinator.

**Relevance:** Medium. Mostly focused on Linux-based IoT firmware (which
this is not), but HALucinator is directly relevant: it identifies HAL
functions in firmware and replaces them with Python stubs during
emulation. That's the library-identification step from Stage 1 taken to
its logical conclusion.

### Asahi Linux

**Who:** Alyssa Rosenzweig, Asahi Lina, marcan, and collaborators.

**Goal:** Reverse engineer Apple Silicon (M1/M2 GPU, SoC peripherals) to
run Linux.

**Why it matters to this project:** The methodology is uncannily similar
to what we're trying to do. Opaque peripheral, driver-side code on the
"known" side, hardware tracing, patient protocol reconstruction. Alyssa
Rosenzweig's blog posts on GPU reverse engineering are some of the best
public writing on this kind of work. Read them. The parallel to the
MCU↔FPGA situation is exact — just at a different scale.

**Takeaway:** Their workflow is hardware-trace-anchored exactly like ours
should be. They've validated that "capture traces of the real thing, then
reimplement against the trace" is a workable approach to opaque hardware.

### Retro decompilation community — the most useful reference

**Who:** The N64, GameCube, Wii, GBA, DS, PS1, PS2 decompilation projects.
Super Mario 64, Ocarina of Time, Majora's Mask, Paper Mario, and dozens
more.

**Goal:** "Matching decompilation" — produce C source code that recompiles
*byte-for-byte identical* to the original ROM.

**Why it matters to this project:** These teams have spent years solving
a structurally identical problem — a small group of contributors working
in parallel on a single large binary, with fast automated feedback loops
and shared state. Their tooling is more mature than almost anything in
the academic space and is all open source.

**Tools to look at:**

- **decomp.me** — a *web app* where anyone can try to lift a small
  function and an automated backend instantly tells them whether their C
  recompiles to the same assembly as the original. This is the feedback
  loop you want: small unit of work, automated verification, shared
  state, many contributors. It is brilliant and under-referenced outside
  the scene. **Go look at it.**
- **m2c** — a MIPS-to-C decompiler tuned for "output a human would have
  written, so it has a chance of matching when recompiled." Ghidra's
  decompiler isn't tuned this way.
- **splat** — a binary-splitting tool that carves a ROM into sections
  (code, data, rodata) and produces a buildable project tree. The
  equivalent for this project would be a tool that carves the firmware
  into per-function files plus a build system that reassembles them.
- **asm-differ / objdiff** — diff your compiled output against the
  original assembly, highlight the differences, guide the next
  refinement. This is exactly what a Unicorn-based differential test
  harness needs on the output side.
- **decomp-permuter** — a fuzzer for C source code that tries small
  variations until the compiled output matches the original. This is
  genuinely sophisticated and directly applicable to firmware RE.
- **Project repos to browse:** sm64, pmret (Paper Mario), oot (Ocarina
  of Time), sotn-decomp (Symphony of the Night on PS1). Look at how
  they organize work, handle context headers, use CI for matching
  verification, and flag NON_MATCHING functions.

**The spiritual lesson:** The breakthrough isn't a smarter decompiler;
it's a fast closed-loop feedback system on small units of work shared
across many contributors. That's the same thesis as the LLM swarm in
this pipeline, just with humans instead of agents. You can steal their
entire workflow template and swap agents in for humans.

### Hardware reversing hobbyists

**Who:** Ken Shirriff (die-level chip analysis), Travis Goodspeed (RF,
embedded), Michael Ossmann, the hackaday.io scene, various YouTube
channels (stacksmashing / hextree.io).

**Relevance:** Low for pipeline design, but worth reading for technique
and motivation. Hextree's training videos show a lot of current best
practice at the bench level.

### Decompiler research itself

**Who:** Hex-Rays (IDA, closed-source decompiler, industry leader), NSA
(Ghidra decompiler), retdec (Avast, open source), angr's decompiler,
Binary Ninja's decompiler.

**Relevance:** We're consumers of Ghidra's decompiler, not building one.
But watching the research direction matters — learned decompilation
(LLM4Decompile, DIRE, DIRTY, Resym) is moving fast and some of those
techniques might be directly importable.

### AI-assisted RE — the frontier

**Who:** Active research as of 2024-2026.

**Tools/projects:**
- **Binary Ninja Sidekick** — integrated LLM assistant
- **Gepetto, GptHidra** — Ghidra plugins that use LLMs to name and
  annotate functions
- **LLM4Decompile** (Fudan University) — fine-tuned Code Llama for
  decompilation
- **Nova** (Meta research) — assembly-to-source with language models
- **DecompAI, reverser.ai** and similar — startups in the space

**Relevance:** High, but note that most published work is "LLM helps
name variables in one function at a time" — the easy-but-less-useful
version. The harder-and-more-useful version (swarms coordinated through
a structured fact database with hardware-trace anchoring) is what this
pipeline is about, and is not something I've seen published end-to-end.

## Where this project sits in the landscape

Resource-wise: **hobbyist firmware reverser.** One person, specific
target, modest budget, two weeks in.

Ambition-wise: **AI-RE frontier with hardware-grounded verification.**
The combination is rare. Closest spiritual cousin is an Asahi Linux driver
reverser crossed with a decomp.me contributor.

Honest observations:

1. **Two weeks is early in a project like this.** Asahi's GPU RE took
   years. SM64 decomp took years. The time spent on pipeline tooling now
   will compound through the rest of the campaign.
2. **Borrow workflow from the decomp scene.** Small-unit work, automated
   verification on every change, shared state in version control or a
   DB, a NON_MATCHING tier for proposals that are functional but not
   byte-exact, progress measured as "percent verified." All of this
   translates directly and is worth not reinventing.
3. **The novelty is at the integration level, not the component level.**
   Every tool you need exists. The contribution is the glue, the
   blackboard, the verification loop, and the hardware-boundary framing.

## Key resources to actually read

If you only read a handful of things before starting to build:

1. **decomp.me** — browse the site, try lifting one function, see how the
   feedback loop feels.
2. **Alyssa Rosenzweig's Asahi GPU RE blog posts** — methodology for
   opaque hardware peripherals.
3. **angr documentation + the 2016 S&P paper** — understand the symbolic
   execution mental model.
4. **Trail of Bits blog archives** — search for "binary analysis,"
   "decompilation," "mcsema," "anvill."
5. **Snakemake tutorial** — 30 minutes, pays off immediately.
6. **Soufflé tutorial** — also 30 minutes, Datalog clicks fast.
7. **HALucinator paper** — library-aware firmware emulation.
8. **A Super Mario 64 or Paper Mario decomp repo README** — see how a
   mature parallel RE project organizes itself.
