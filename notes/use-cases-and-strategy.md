# Use Cases and Strategy

Working notes on who actually reverse engineers firmware, why, and
what the product shape might look like if this pipeline grew beyond a
one-project tool. Honest about the market being niche. Useful mostly
as a reference for thinking about scope decisions: "would this
contribute to something bigger, or is it only useful for cord?"

## Who reverse engineers firmware, and why

At least ten distinct use cases, grouped by motivation and rough
market size:

### Defensive / security

1. **Vulnerability discovery.** Finding bugs in firmware you don't own,
   for bug bounty programs, red team engagements, security research,
   or threat intelligence. Customers: Project Zero, Trail of Bits, NCC
   Group, academic security labs, corporate internal red teams. They
   pay well for tools that save time.
2. **Vulnerability verification.** Confirming CVEs in firmware you
   deployed on your own network. Customers: enterprise IT security,
   medical device operators, industrial control system owners.
3. **SBOM extraction.** Identifying what libraries and versions are in
   a binary, mapping against CVE databases. Customers: device
   manufacturers, regulated industries (medical, automotive, critical
   infrastructure, energy), government procurement. **This is the
   fastest-growing commercial segment** because SBOM requirements are
   becoming regulated (FDA medical device guidance, EU Cyber
   Resilience Act, US Executive Order 14028). Budgets are real.
4. **Malware analysis.** Understanding hostile code in compromised
   devices (router malware, ICS malware, supply chain compromise).
   Customers: Mandiant, Kaspersky, Microsoft Defender, ESET, national
   CERTs, CISA. Mature market, big budgets, established tooling.
5. **Supply chain verification.** Proving your vendor didn't ship code
   they shouldn't have — backdoors, unlicensed libraries, unexpected
   telemetry. Customers: procurement at regulated organizations,
   defense contractors. Overlaps with SBOM but distinct in framing.

### Offensive / competitive

6. **Interoperability and replacement.** Writing your own firmware for
   existing hardware — OpenWrt, PineTime InfiniTime, reFLASH-style
   hobbyist rewrites, DMCA-1201-exempted compatible-accessory work.
   **This is the cord project's use case.** Customers: hobbyists (pay
   little), open-source hardware communities (pay nothing but
   contribute code), a handful of companies building compatible
   products (pay well but small).
7. **Protocol reverse engineering.** Figuring out how a device talks
   to its peers, usually for compatibility, monitoring, or
   alternative-client development. Distinct from full firmware RE
   because you only need the communication layer.
8. **Competitive intelligence.** Understanding a competitor's product
   for benchmarking, feature parity, or interoperability. Legally
   gray in some jurisdictions but with significant precedent (Compaq
   BIOS, Samba, WINE, ReactOS).

### Recovery / ownership

9. **Source code recovery.** You own the product but lost the source
   — acquired companies, terminated contractors, failed version
   control, decade-old devices. More common than you'd think.
   Customers: the owning company. No ethical issues, real budgets,
   time-sensitive.
10. **Hardware replication for production continuity.** Original
    manufacturer discontinued the chip, left the market, or refused
    support; you need to ship compatible firmware on new hardware.
    Adjacent to cord but for industrial rather than consumer contexts.

### Educational

11. **CTF / learning / academic publication.** Not a commercial
    segment but the source of most of the open tooling and research
    progress. Pay nothing, generate citations and contribute code.

## Where cord specifically sits

Cord is use case 6: interoperability and replacement. One person, one
target, hobbyist-to-semi-professional scope. Direct commercial market
for that specific use case is small.

**But the pipeline built for it serves all the other use cases too.**
The core technical problem is identical: extract facts from binary,
identify libraries, understand control flow, characterize hardware
interactions, verify results. What differs between use cases is
mostly:

- **Output format** — SBOM wants a dependency list; vuln research
  wants exploitable-bug candidates; cord wants a hardware spec.
- **Depth of analysis** — malware triage wants shallow and fast;
  replacement firmware wants deep and complete.
- **Verification bar** — security research can accept "probably
  correct"; replacement firmware needs "verifiably equivalent at the
  hardware boundary."

Every one of these is a different *rendered view* on the same fact
database. This is architecturally significant: **the pipeline is
general-purpose by construction, even though cord is a narrow use
case**.

## Existing tools and competitive landscape

Commercial firmware analysis tools that exist today:

- **IDA Pro + Hex-Rays Decompiler.** Industry standard for high-end RE.
  Closed source, expensive ($1000s/seat), no ML-assisted features
  until recently (Hex-Rays Lumen/Decompiler Sidekick). Serves use
  cases 1, 2, 4, 6, 9.
- **Binary Ninja.** Modern alternative to IDA, integrated AI
  assistant (Sidekick), scripted analysis. Mid-market pricing. Growing.
- **Ghidra.** Open source, NSA-released in 2019. The foundation most
  open tooling builds on. Serves everything at zero cost but with a
  steep learning curve.
- **ONEKEY** (German firmware security platform). Enterprise SBOM and
  vulnerability detection. Closed, expensive, focused on use cases 3,
  4, 5.
- **Finite State.** Enterprise firmware security platform. Similar
  positioning to ONEKEY. Focuses on SBOM and CVE matching.
- **ReFirm Labs / Binwalk Pro.** Acquired by Microsoft, incorporated
  into their security offerings.
- **Karamba Security, Red Balloon Security, Claroty, Nozomi Networks.**
  Various corners of industrial and IoT security with firmware
  analysis components.
- **angr, radare2/rizin, Cutter, BAP, Triton, Manticore, Miasm.**
  Open-source tools serving academic, security research, and CTF
  communities.

**What doesn't exist** in any of them as of early 2026:

- A learned multi-signal function classifier running locally on
  commodity hardware, integrated with a structured fact database.
- A hardware-trace-anchored verification loop using emulation as the
  correctness oracle.
- LLM agent swarms coordinated through a shared blackboard with
  execution-based verification.
- An open labeled corpus of embedded binaries for fingerprinting
  research.

The individual pieces exist in academic papers and research prototypes
but no production tool combines them. That's the gap worth building
into, whether the goal is an open research platform, a commercial
product, or a hosted service.

## Open source versus paid service

The honest answer: both can work, they serve different audiences, and
the smart play is a layered model.

### Arguments for open source

- **Trust.** Security-adjacent tooling is viewed with suspicion when
  closed. Auditability matters. Ghidra being open is why it took
  over.
- **Community network effects.** Corpus contributions, bug reports,
  extensions, plugins — all compound when the tool is open.
- **Academic and research use.** Citable, forkable, extensible.
- **Legal safety.** Open-source tools are generally protected under
  security research exemptions in ways hosted services aren't.
- **Hobbyist reach.** The people who most want to reverse engineer
  their hardware don't pay for tools.

### Arguments for paid service

- **Enterprise segments have real budgets.** SBOM-driven
  regulated-industry work, malware analysis at security vendors, and
  supply chain verification for defense all have paying customers.
- **Hosted services remove setup friction.** Upload a binary, get
  results. Valuable for occasional users.
- **Compute costs are real.** Running serious analysis on a big
  firmware takes time and money. Passing that through to users is
  reasonable.
- **The corpus and trained models can be proprietary** even if the
  framework is open. That's the actual moat.

### Recommended shape: open framework, hosted premium

The pattern that works for adjacent tooling (GitLab, Sentry,
HashiCorp, dbt, Hugging Face) is:

- **Open source the framework.** Ghidra scripts, Snakemake pipeline,
  DuckDB schemas, verification harnesses, rule-based fingerprinting,
  Renode integration, agent coordination primitives. Permissive or
  weak-copyleft license. Anyone can self-host on their own hardware.
- **Proprietary corpus and trained models** as an optional premium
  layer. The rule-based classifier and a small reference model ship
  with the open tool; the best-trained model and the full corpus are
  paid.
- **Hosted service** for enterprise customers who want someone else to
  run the hardware, manage updates, and provide support. Pricing
  based on binary size, analysis depth, and retention.
- **Community contributions feed the corpus.** Users of the open tool
  can contribute labeled data back; contributions improve the hosted
  model, which funds continued development of the open framework.

This gives adoption and credibility via the open path, revenue via
the enterprise path, and a sustainable flywheel between them.

### The "upload your firmware to a website" shape specifically

Tempting product shape but has real complications:

- **Liability.** If users upload malware, stolen firmware, or
  competitor IP, the service operator is in the middle. DMCA, CFAA,
  and international equivalents all have edge cases. Security
  research exemptions exist but are narrow and jurisdiction-specific.
- **Trust.** Users with proprietary firmware are unlikely to upload to
  a third-party service they don't control. The enterprise market
  strongly prefers self-hosted.
- **Compute economics.** Deep analysis takes real CPU time. Unit
  economics only work at prices that exclude hobbyists.
- **Abuse.** Free tiers attract low-effort abuse; paid tiers
  exclude exactly the community that drives adoption.

**Better shape for most of these concerns: self-hosted tool that
optionally calls out to a hosted model/corpus service for
classification.** The user's binary stays on their machine; only
extracted features (which are non-reversible — you can't reconstruct
the binary from a feature vector) go to the hosted side. This makes
the trust story easy, sidesteps most liability, and lets the hosted
service focus on what it's actually good at (running the big model
and maintaining the corpus). The framework does the heavy lifting
locally.

## Honest framing: this is a niche, not a unicorn market

The total addressable market for "firmware reverse engineering tools"
is genuinely small compared to mainstream dev tools. The companies
that make money in this space are small — a handful of employees —
and the customers are specialized. IDA Pro has been the gold standard
for twenty years and Hex-Rays is still a small company by software
standards. Finite State and ONEKEY are niche enterprise vendors.

Don't expect a unicorn outcome. Expect:

- A modest open-source project with a small but dedicated community
  if it's well-executed.
- A consulting and support business around it that can sustain a few
  people if it proves valuable to enterprise customers.
- Academic recognition and citations if the research angles
  (P-Code embedding, open corpus, blackboard architecture) hold up.
- Personal mastery of a domain that transfers to adjacent opportunities
  in embedded security, hardware design, and platform engineering.

Not expect:

- Venture-scale returns.
- Mass-market adoption.
- Immediate enterprise sales without significant go-to-market work.

The project is worth doing on its technical merits and its value to
the specific cord problem. The broader product and research upside is
real but secondary and shouldn't drive scope decisions. If you would
not do this project for the cord-specific outcome alone, the
productization speculation isn't a reason to start it.

If you *would* do it for cord alone, then every piece of infrastructure
you build has optional downstream value, and the productization
framing gives you useful guidance on which pieces to build cleanly
versus which ones to leave quick and dirty.

## A note on legal posture

Reverse engineering law is jurisdiction-specific and scenario-specific.
General principles that usually hold in the US and EU:

- **Interoperability RE is generally protected.** Writing firmware
  that makes existing hardware work with new software, or vice versa,
  has clear precedent.
- **Security research has explicit exemptions** under DMCA 1201 in
  the US, with periodic renewals. EU has similar protections under
  various directives.
- **Circumventing DRM** for purposes other than interoperability or
  security research is risky.
- **Distributing circumvention tools** is riskier than using them.
- **Commercial services that enable circumvention** are the riskiest
  category.

None of this is legal advice. For the cord project as currently
framed (reverse engineering your own hardware for replacement
firmware), the posture is strong. For any hosted service shape, a
genuine legal review is table stakes before launch.

## What to do with this for now

Nothing immediately. This file exists to capture the framing so that:

- Scope decisions on the cord project can be made with a view toward
  what might be reusable later.
- The research angles from `local-ml-fingerprinting.md` and
  `fingerprinting.md` have a context in which their value can be
  weighed.
- If cord succeeds and interest in the broader direction survives,
  there's a starting point for thinking about shape rather than a
  blank page.

Revisit when cord is substantially further along and it's clear which
pieces of the pipeline generalized cleanly.
