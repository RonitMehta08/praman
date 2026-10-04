# PRAMAN — Project Overview Deck

**Nine slides covering the project.** Each slide gives you the exact text
to put on it, a one-line layout note, and 20–30 s of speaker notes (put those in
PowerPoint's Notes pane, not on the slide).

**Before you export:** every figure here is a measurement read from
`reports/metrics/*.json`. Regenerate them first so nothing is stale:

```bash
.venv/Scripts/python.exe scripts/bench/run_all.py --check
```

---

## Slide 1 — Project Overview

> **Layout:** Project name huge, one-line tagline under it, then a clean
> one-line operating profile. Nothing else. This slide is a label, not an argument.

# PRAMAN
*Sanskrit **pramāṇa** — "proof", "a valid means of knowledge"*

**AI-Driven Multi-Vendor Network Security Compliance Auditor**
*Hand it a router config. Get back a signed, re-verifiable compliance verdict — offline.*

**Operating profile:** Offline-first auditing, with an optional hosted sample demo.

**Speaker notes:** "This is PRAMAN — Sanskrit for
*proof*. That name is the whole thesis: a compliance report should be evidence
you can independently re-check, not an opinion you have to trust. Everything I'm
about to show you is already running."

---

## Slide 2 — The Network Audit Problem

> **Layout:** Title band at top, the one-sentence problem in large type in the
> middle, the four constraint chips at the bottom. Keep it to ~40 words of body
> text — this slide states the problem, slide 3 dissects it.

### Title

**Automated, vendor-agnostic security compliance auditing for network device
configurations — with cryptographically verifiable evidence, fully offline.**

### The problem in one sentence

> Network operators must prove that **every** router, switch and firewall in an
> estate satisfies **CIS Benchmarks, DISA STIGs, NIST SP 800-53 and ISO 27001** —
> and must be able to prove it **again** at the next audit. Today that work is
> **manual, per-device, per-framework, and unverifiable**.

### The four constraints any real solution must satisfy

| | |
|---|---|
| **Multi-vendor** | Cisco IOS · ASA · NX-OS · Juniper Junos · FortiGate · Arista EOS · PAN-OS — seven syntaxes, one set of ideas |
| **Multi-framework** | One device's evidence must answer four different standards |
| **Offline** | Configurations are sensitive or classified; nothing may leave the machine |
| **Provable** | The report must be re-checkable **without trusting the tool that printed it** |

**Speaker notes:** "The task sounds like a checklist and isn't. An operator has
to prove compliance for every device against four standards, then prove it again
next quarter. And two constraints rule out most existing tooling immediately:
these configs can't be uploaded anywhere, and a PDF from a black-box scanner
isn't evidence — it's a claim."

---

## Slide 3 — Problem Identification

> **Layout:** Three stacked bands — "Why it's hard", "What it costs today",
> "What's missing". Bold every number. No paragraphs.

### Why this is genuinely hard, not just tedious

- **The two sides share no vocabulary.** A config is written in a *vendor's
  grammar* (`transport input none`). A benchmark is written as *prose about a
  concept* ("disable unused management transports"). Nothing joins them
  automatically.
- **The naive design explodes combinatorially.** Couple each framework directly
  to each vendor's syntax and you need **4 frameworks × 8 vendors = 32 parsers**,
  each re-implementing the same question in a different dialect.
- **Every vendor is a different dialect.** Seven syntaxes for the same seven
  ideas — and vendors keep adding more.
- **Benchmarks version continuously.** CIS Cisco IOS 15 is at v4.1.1; STIGs ship
  revisions (v3r8, v2r5, v1r5). A hard-coded auditor is stale the quarter after
  it ships.
- **An unknown line is a silent hole.** Any config a parser doesn't recognise
  either gets dropped (a false pass) or guessed at (a false finding). Both are
  worse than saying "I don't know".

### What it costs today

| Pain | Reality |
|---|---|
| Manual audit | **Hours per device** against ~90 CIS controls — read, judge, type |
| Four frameworks | **Four separate passes** over the *same* evidence |
| Commercial tools | Licence cost · cloud dependency · per-device agents · closed logic |
| Unknown format | A dead end — file a vendor ticket, wait for a release |
| Audit trust | A PDF is only as good as trust in the tool that printed it |
| Human error | A mistyped remediation command on a production router is an outage |

### What's missing from existing tooling

- Nothing **normalises across vendors** — so coverage is a per-vendor rewrite
- Nothing produces **tamper-evident** output — so re-verification means re-auditing
- Nothing is honest about **what it did not check** — the easiest way for a
  compliance tool to look good is to quietly skip the hard controls

**Speaker notes:** "The core difficulty isn't volume, it's vocabulary. Configs
are vendor syntax; benchmarks are English prose about concepts. Bolt them
together directly and you need a parser per framework-vendor pair — thirty-two
of them. And the third band is the gap we care about most: existing tools don't
tell you what they *couldn't* check, which is exactly where the risk hides."

---

## Slide 4 — Proposed Solution

> **Layout:** One statement at the top, the pipeline diagram in the middle,
> three short "what this buys" bullets at the bottom. This slide should feel
> *emptier* than slide 3 — the diagram carries it. Resist adding prose.

### Put a canonical fact model between the two worlds

We refuse to join vendor syntax to benchmark prose directly. Instead, **every
vendor's config is normalised into one shared vocabulary of 330 dotted canonical
paths**, and **every compliance rule is written against those paths — never
against a vendor's grammar.**

A fact is a triple — **`(path, value, provenance)`**:
`snmp.community` = `public`, from **line 47** of `core-rtr-01.conf`.

```
config text ──▶ pattern pack ──▶ canonical facts ──▶ rules ──▶ findings ──▶ signed PDF
                (YAML/vendor)     (330 paths)        (YAML)       │              │
                     │                                           │              │
               unparsed lines                          framework projection  hash-chained
                     │                                     (NIST · ISO)      Ed25519 ledger
                     ▼                                                           │
        AI tiers 1 → 2 → 3 ──▶ Training GUI ──▶ new pattern ────────────────────┘
      (TF-IDF / SetFit / LLM)  (operator confirms)  (hot-reloaded, no restart)
```

### What that one decision buys

- **A new vendor is a YAML file** — not a parser. **Zero engine code.**
- **A new benchmark is a YAML file** — not an engine change.
  *Proof: our DISA STIG pack added **34 catalogs** and **3 previously-dark
  frameworks** with **zero lines of engine code**.*
- **One parse answers four frameworks**, instead of four audits per device.

### Three design commitments that follow from it

1. **The AI teaches the parser; it never decides a verdict.** Unrecognised lines
   escalate through three classifier tiers that *propose* a canonical path. An
   operator confirms once, and the confirmation becomes a **deterministic
   pattern**, hot-reloaded with no redeploy.
2. **`notchecked` is a first-class verdict.** Score = `pass / (pass + fail)`, so
   **coverage can never be improved by declining to check something.** A control
   we can't decide is returned with a *reason*, never dropped.
3. **Remediation is quoted, never generated.** Each failure ships the
   **publisher's own fix CLI**. No model ever writes a command that touches a
   router.

**Speaker notes:** "This is the one architectural decision everything else falls
out of. Normalise seven vendor syntaxes into 330 canonical paths, and write
rules against paths. That collapses thirty-two parsers into seven data files plus
one engine — and extending the tool becomes authoring data, not shipping code.
The three commitments at the bottom are what keep it trustworthy: the AI only
helps parse, we publish what we can't check, and fix commands are the
publisher's words, never a model's."

---

## Slide 5 — Key Features

> **Layout:** Five feature rows on the left as `**Name** — what it does +
> the measured number`; the 3-tier AI ladder as a small diagram on the right.
> If it feels tight, move the AI ladder to a backup slide.

**1 · Unified multi-vendor ingestion**
Pattern-driven parsing where **a vendor is a data file**. **7 vendor packs**
shipped — Cisco IOS, ASA, NX-OS, Juniper Junos, FortiGate, Arista EOS, PAN-OS.
Vendor detected **from content, not filename**: **20/20** test configs correct.
**98.68%** of significant lines parsed → **4,302 facts** from 20 configs.

**2 · Multi-framework compliance engine**
**454 rules** over **13 benchmarks** / **42 normalised catalogs** / **3,366
controls**, projecting into **4 frameworks**. CIS and DISA STIG are evaluated
**directly against facts**; NIST SP 800-53 and ISO 27001 are **projected through
the publishers' own crosswalks** — and every projected verdict is **labelled as
projected**, because a roll-up is weaker evidence than a measurement.

**3 · AI training loop that closes unknown formats**
Three tiers propose a canonical path for a line no pattern matched; an operator
confirms it **once** in the GUI; it becomes a **deterministic, hot-reloaded
pattern**. **No vendor ticket. No redeploy. No model in the verdict path.**

| Tier | Method | Size | Role |
|---|---|---|---|
| **1** | TF-IDF + calibrated linear classifier | 1.5 MB | Instant; ships in the repo |
| **2** | **SetFit** few-shot over MiniLM-L6-v2 | ~89 MB | Learns from a handful of operator examples |
| **3** | **Qwen3-4B**, QLoRA 4-bit (GGUF) | 2.4 GB | Optional, GPU; last resort before abstaining |

Measured guarantees: abstention on **42 real unparsed lines — 1.00** · abstention
on **10 deliberate non-config lines — 1.00** · suggestions outside the 330-path
schema — **0** · a missing tier **reports its own absence** rather than guessing.

**4 · Actionable, signed reporting**
Per-device PDF carrying the failing control, **the evidence line**, and the
**publisher's remediation CLI** — plus machine-readable **OSCAL 1.2.3** and
**SARIF 2.1.0** exports, both validated against the publishers' own JSON Schemas.
**272 of 454 rules (59.9%)** carry a **MITRE ATT&CK** technique so a failure
reads as an exposure, not a checkbox *(our own editorial mapping — labelled as
ours, and deliberately kept outside the Merkle root so it can never move a
verdict)*.

**5 · Tamper-evident audit ledger**
Audits are **hash-chained** and **Ed25519-signed**; findings commit through a
**Merkle root**; the PDF carries an `X-PRAMAN-Record-Hash` header.
`/audit/verify` re-reads SQLite and re-checks **four independent links per
record**, so altering any earlier record invalidates every record after it.

**Plus:** whole-estate ZIP intake (**2,000 members / 512 MB**) as a cancellable
background job · role-based access (`viewer` → `auditor` → `approver`) with the
operator's name **inside** the signed record · **1,798 tests** passing.

**Speaker notes:** "Five features. Ingestion where a vendor is a data file.
A rule engine spanning four frameworks. The AI training loop — three tiers
propose, a human confirms once, and the answer becomes deterministic; note the
abstention rate is 1.00 on both real unparsed lines and deliberate garbage,
because silence is a correct answer here. Then signed reporting with the
publisher's own fix commands, and a ledger that makes the report re-checkable
without trusting us."

---

## Slide 6 — Target Users

> **Layout:** Four user cards, each `Who · What they do today · What changes`.
> Two lines per card maximum. Small icons help; more text doesn't.

**1 · Defence and government network operators**
Auditing sensitive or classified estates on **air-gapped** networks.
*Today:* fully manual — no tool that phones home is permitted.
*What changes:* one offline Python process on the assessor's own laptop.
**No cloud, no API key, no network egress.** Configs never leave the machine.

**2 · Enterprise NOC / SOC and network security teams**
Under continuous CIS / STIG / ISO 27001 obligations across mixed-vendor estates.
*What changes:* whole-estate ZIP upload, **one parse answers four frameworks**,
and every failure arrives with the publisher's own fix CLI.

**3 · Compliance auditors and external assessors**
Who must **re-verify a report months later** without trusting the tool that
produced it.
*What changes:* the hash-chained, Ed25519-signed ledger plus `/audit/verify` —
and **OSCAL / SARIF** exports that drop straight into their existing pipeline.

**4 · Regulated-sector IT — banking, power, telecom, public sector**
Under RBI / CERT-In / sectoral configuration-audit mandates on the same classes
of equipment.
*What changes:* repeatable, defensible evidence at **zero licence cost and zero
cloud spend**.

**And quietly, the vendor-neutral middle:** because a vendor is a YAML pack, a
team running equipment we have never seen can **add support themselves** without
waiting on us.

**Speaker notes:** "The primary user is the operator on an air-gapped network —
that constraint drove the entire design. But the same tool serves enterprise SOC
teams under continuous compliance obligations, external auditors who need
machine-readable evidence, and regulated sectors under CERT-In style audit
mandates. And because vendors are data files, users can extend it themselves."

---

## Slide 7 — Expected Impact

> **Layout:** The `Before → After` table is the spine of this slide — put it at
> the top, full width. Then three short impact bands. Bold the right column.

| | Manual / current tooling | With PRAMAN |
|---|---|---|
| One device, ~90 CIS controls | **Hours** of reading and judgement | **454 rules in p50 8.4 ms** |
| Four frameworks | Four separate audits | **One parse → CIS · STIG · NIST · ISO** |
| Report generation | Hand-assembled spreadsheet | **Signed PDF in ~1 s** (p50 **0.80 s**) |
| Re-verifying last quarter's audit | Trust the tool, or redo it | **Cryptographically re-checkable** |
| An unknown config format | Vendor ticket → wait for a release | **Mapped once in the GUI, permanent** |
| Remediation | Operator writes the command | **Publisher's own CLI, quoted verbatim** |
| Sensitive configs | Uploaded to a cloud service | **Never leave the machine** |

**Operational impact**
Estate auditing becomes **continuous instead of annual**, because the marginal
cost of a re-audit is milliseconds and a whole estate is one ZIP. Every failure
arrives with a fix that is safe to paste.

**Security impact**
Misconfiguration is one of the most-exploited initial-access paths into network
infrastructure. **272 of 454 rules carry a MITRE ATT&CK technique**, so a finding
reads as *what an attacker gains* rather than *a failed checkbox* — which is what
turns an audit into prioritised remediation.

**Trust and assurance impact**
The output is **evidence, not an opinion**: hash-chained, Ed25519-signed,
Merkle-committed, and re-verifiable by a third party. Benchmark content stays the
publishers', with **pinned digests checked by `scripts/verify_sources.py`**, so
the control text we report against is provably the text the publisher shipped.

**Economic and strategic impact**
Zero licence cost · zero cloud spend · **no per-device agent** · runs on a 16 GB
laptop with **no Docker and no GPU required**. A fully offline, indigenous
auditor means **no third-party service ever sits in the audit path for sensitive
configurations.**

**Speaker notes:** "The headline is hours-to-milliseconds with a re-verifiable
report. But the impact we'd argue hardest for is the last two bands: the output
is evidence a third party can check, and because it's fully offline and
zero-cost, classified configurations never enter anyone's cloud."

---

## Slide 8 — Proposed Technology Stack

> **Layout:** One grouped table. Keep the "Why this" column — graders reward the
> *reasoning*, not a logo wall. If space is tight, drop the AI tier rows to the
> feature slide rather than dropping the justifications.

| Layer | Choice | Why this |
|---|---|---|
| **Language** | **Python 3.10+** | One runtime for parsing, ML and reporting; already on every assessor's laptop |
| **API** | **FastAPI** + Uvicorn | Typed request models, auto OpenAPI docs, serves the UI from the same process |
| **Storage** | **SQLite** (WAL) | Zero-admin, single file, air-gap friendly. Migration gated on `PRAGMA user_version` — a **future** DB is *refused*, never silently written to |
| **Frontend** | **Dependency-free ES modules**, 10 views | **No build step, no npm, no node_modules** — the UI ships as auditable source text |
| **Rules & vendor packs** | **YAML** pattern packs + mapping packs | Extension is authoring **data**, not shipping code — this is what makes vendor-agnosticism real |
| **Reporting** | **ReportLab**, with a pure-Python fallback | If ReportLab is absent, `minimal_pdf.py` still emits a valid PDF — **72.1× faster, same verdicts, same record hash** |
| **Integrity** | **Ed25519** + SHA-256 hash chain + **Merkle root** | Signed, append-only, tamper-evident audit records |
| **AuthN / AuthZ** | **PBKDF2** passwords, **3 ordered roles** (`viewer` → `auditor` → `approver`) | Operator's name goes **inside** the signed record. **No default account** — a fresh clone has nobody who can log in |
| **AI tier 1** | scikit-learn TF-IDF + `CalibratedClassifierCV` | 1.5 MB, instant, ships in the repo |
| **AI tier 2** | **SetFit** / sentence-transformers | Few-shot from a handful of operator examples — the realistic data regime |
| **AI tier 3** | **Qwen3-4B** + **QLoRA** 4-bit NF4, llama.cpp GGUF | Optional. 4-bit is the only way a 4 B model fits **6 GB** of VRAM |
| **Interop exports** | **OSCAL 1.2.3**, **SARIF 2.1.0** | Validated against the publishers' own JSON Schemas |
| **Threat context** | **MITRE ATT&CK** Enterprise bundle | Technique names, descriptions and mitigations read from the bundle's own relationships — **never hand-written** |
| **Quality gate** | **pytest** (1,798 tests) · **ruff** · benchmark `--check` | Every published number is regenerable; the suite **fails when one goes stale** |
| **Deployment** | `python scripts/serve.py`; **nginx** only for TLS | **No Docker, no GPU, no cloud, no network.** Binds loopback by default |

**Deliberately *not* in the stack:** no cloud service, no external API key, no
message queue, no container runtime, no JavaScript build toolchain. **Every one
of those is a dependency an air-gapped assessor cannot satisfy.**

**Speaker notes:** "Every choice is filtered through one constraint: it has to
work on an air-gapped laptop with no admin rights. That's why SQLite instead of
Postgres, plain ES modules instead of a JS framework, and why even the PDF
renderer has a pure-Python fallback that produces a byte-identical record hash.
The last line is the point — everything we left out, we left out because an
air-gapped user couldn't install it."

---

## Slide 9 — Initial Implementation Approach

> **Layout:** Five-phase horizontal timeline with ticks on phases 1–4 and an
> arrow on phase 5. The ticks are the slide's whole message. Put the "how we
> keep ourselves honest" bullets underneath in smaller type.

### Strategy: build the riskiest, most irreversible part first

**Phase 1 — Canonical vocabulary ✅**
Define the **330 dotted paths** and the `(path, value, provenance)` fact model
**before writing any parser**, because every parser and every rule depends on
it. Schema-validated (`canonical.schema.json`, `canonical_paths.schema.json`).

**Phase 2 — Pattern-driven ingestion ✅**
One data-driven engine + **7 vendor YAML packs**; content-based vendor detection.
**98.68%** of significant lines parsed — and the residue is **enumerated by
command** in `reports/metrics/parse_coverage.json`, not rounded away.

**Phase 3 — Rule engine and framework projection ✅**
**454 rules** over facts → **42 catalogs / 3,366 controls** → 4 frameworks, with
**`notchecked` as a first-class verdict** carrying a reason.

**Phase 4 — Evidence layer ✅**
Signed per-device PDF · hash-chained Ed25519 ledger with a Merkle root ·
`/audit/verify` · OSCAL + SARIF exports · role-based auth.

**Phase 5 — AI training loop — tier 1 shipped, tiers 2 & 3 trained ⏩**
Tier 1 ships in the repo; tiers 2 and 3 are **trained and measured** on our own
hardware (SetFit in 33.6 min; QLoRA in 16.4 min on a 6 GB RTX 4050, **11.8 M
trainable params = 0.29%** of 4.03 B).
**Next:** grow the label set beyond the 15 paths tier 1 can currently emit, so
the tiers help on the **routing-plane** residue and not only the management plane.

### How we keep ourselves honest — built in from day one

- **1,798 tests** · ruff clean · **one command regenerates every published number**
- `test_every_control_is_exercised_in_both_directions` — every automated control
  must **pass on one config and fail on another**. A control that only ever
  passes is hiding a rule that cannot detect its own violation.
- `test_notchecked_controls_are_reported_not_dropped` — an undecidable control is
  **returned with a reason**, never silently omitted
- `test_the_published_fixture_table_is_not_stale` — the docs are re-measured
  inside the test run, so **documentation cannot drift from behaviour**
- **`docs/GAPS.md`** lists all **22 unautomated controls individually**, with the
  reason each is unautomated and what it would take to close it

### Working prototype today — not a concept

**20 device configurations across 7 vendors ship with the project**, so a demo
needs no hardware: `python scripts/fixture_report.py`. Setup is **two
commands**; `python scripts/serve.py` is the entire deployment.

**Measured on an i5-13500H / 16 GB laptop:** vendor detection **20/20** · parse
p50 **8.2 ms** · rule evaluation p50 **8.4 ms** · PDF p50 **0.80 s** ·
**1,339 verdicts decided** across 20 configs (732 pass / 607 fail).

**Speaker notes:** "We built the hardest and most irreversible piece first — the
canonical vocabulary — because everything downstream depends on it. Phases one
through four are done and tested; the AI training loop is where the remaining
work is. And the honesty tests were written before most of the features: every
control has to be demonstrated both passing and failing, or we don't count it as
automated."

---

## Design checklist before you export

- [ ] **Bold every number.** A reviewer skims — the numbers are the argument.
- [ ] Slide 4 is **one diagram + a short caption**. Don't fill it with prose.
- [ ] Max **~6 bullets per band**. If a bullet wraps to three lines, cut it.
- [ ] Fill in **team details** (slide 1) and the **repository link**.
- [ ] Run `scripts/bench/run_all.py --check` and fix any figure that drifted.
- [ ] **Export as PDF** so the layout can't reflow on the reviewer's machine.

### Worth keeping as backup slides, for Q&A

Two questions get asked almost every time — have a slide ready rather than
crowding the main nine:

1. **"How do you know your AI isn't making things up?"** — Our tier-1 classifier
   once scored `shutdown` at **0.929** and `zzzzzzzz qqqq` at **0.929**, above
   our 0.85 gate, answering **28 of 51** lines with the same class — including
   for a shopping list. A calibrated softmax reports *P(class | it is one of my
   classes)*; it cannot say "this isn't a config line". **We found it with a
   negative control we wrote to break ourselves**, and fixed it with an
   inference-time prior-collapse guard, held in place by a test. Abstention on
   non-config input is now **1.00**. *Lesson: a confidence threshold bounds how
   sure a model claims to be, not whether the question was in its domain.*
2. **"What's your real coverage?"** — **13.49% of all 3,366 loaded controls**,
   and we publish that number because most loaded catalogs are for platforms no
   pattern pack covers yet. What it actually audits: **DISA STIG ASA NDM 44/47 ·
   NX-OS NDM 39/42 · IOS NDM 32/35 · CIS Cisco IOS 15 71/90 · Juniper NDM 34/49**.
   Coverage is high where a config file decides the control and low where the
   control is about licensing or Active Directory — **guessing would raise the
   percentage and lower the value.**
