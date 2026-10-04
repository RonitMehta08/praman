# Slide 3 — Technical Approach · Speaking Script

**Target: 1:00 – 1:25.** Main script below is ~230 words ≈ **84 seconds** at a
normal, confident pace. Do not rush it — the pauses are what make it land.

---

## THE SCRIPT (speak this)

> This slide is how Praman actually works.
>
> **[point left column]**
> On the left is our stack. Python, FastAPI, SQLite — and a frontend of plain
> JavaScript. No node modules, no build step, no CDN. That's deliberate: Praman
> has to run offline, on an air-gapped laptop.
>
> **[point to the 5 boxes at the bottom]**
> The pipeline is five steps.
>
> **First — normalize.** The config is parsed by vendor YAML pattern packs.
> Seven vendors ship today.
>
> **Second — canonicalize.** *(slow down here)* This is the heart of it. Every
> vendor's syntax becomes the same **330 canonical paths**. So a rule is written
> once against a *path* — never against Cisco grammar or Juniper grammar. That's
> why adding a new vendor is a YAML file, not a new parser.
>
> **Third — assess.** 454 rules across 42 catalogs and 3,366 controls — CIS,
> STIG, NIST and ISO — evaluated in about **five milliseconds**.
>
> **Fourth — escalate.** **[point to the AI ladder, right]** When a line matches
> no pattern, it climbs our AI ladder — TF-IDF, then SetFit, then a local
> Qwen3-4B. And here's the key point: **the AI never decides a verdict.** It only
> *suggests a mapping*. A human confirms it, and it becomes a deterministic
> pattern — hot-reloaded, no redeploy.
>
> **Fifth — prove.** Every finding commits to a Merkle root, hash-chained and
> Ed25519 signed. So the report can be re-verified months later **without
> trusting the tool that made it**.
>
> **[point to the blue bar at the bottom]**
> Which is the promise on this slide: every config line gets a verdict, every
> verdict gets a signature, nothing gets silently skipped.

---

## 60-SECOND CUT (if they tell you to speed up)

> This is how Praman works. Left side — Python, FastAPI, SQLite, and a plain
> JavaScript frontend with no build step, because this has to run offline on an
> air-gapped laptop.
>
> Five steps. We **normalize** the config with vendor YAML packs — seven vendors.
> Then we **canonicalize**: every vendor's syntax collapses into the same **330
> canonical paths**. That's the core idea — a rule is written once against a path,
> so a new vendor is a YAML file, not a new parser.
>
> Then we **assess** — 454 rules over 3,366 controls across CIS, STIG, NIST and
> ISO, in about five milliseconds.
>
> If a line matches nothing, it **escalates** up our AI ladder — TF-IDF, SetFit,
> local Qwen3-4B. But the AI never decides a verdict. It only suggests a mapping;
> a human confirms it, and it becomes a permanent deterministic pattern.
>
> Finally we **prove** it — Merkle root, hash chain, Ed25519 signature.
>
> Every line gets a verdict. Every verdict gets a signature. Nothing gets
> silently skipped.

---

## DELIVERY NOTES

| Cue | What to do |
|---|---|
| Opening line | Say it flat and confident. Don't start with "So, um, basically…" |
| "330 canonical paths" | **Slow down and pause after.** This is your one novel idea — let it land. |
| "the AI never decides a verdict" | Say this *directly to the judges*, not to the screen. It is the line that separates you from every other AI-wrapper project in the room. |
| "six milliseconds" | Small pause before the number. Numbers land better with a beat in front of them. |
| Closing blue bar | Slow, three beats: *verdict … signature … nothing skipped.* Then stop. Do not add "yeah, so that's it." |
| Hands | Point at the slide 4 times only (marked above). Constant pointing reads as nervous. |

**Do not say:** "we tried to", "we hope to", "it kind of", "as you can see".
Everything on this slide is built and measured — speak in the present tense.

---

## LIKELY JUDGE QUESTIONS (30-second answers)

**"Where is the AI actually doing something?"**
> Two places. It classifies config lines our regex packs don't recognise, and it
> suggests the canonical path for them. It never touches the compliance verdict —
> that's deterministic rules, so an audit result is always reproducible. Our
> tier-1 abstention rate on non-config input is 1.00 — it stays quiet rather than
> guessing.

**"Why not React / a proper frontend framework?"**
> Because the deliverable has to run on an air-gapped assessor's laptop from a
> clone. A build toolchain is the one dependency that can't degrade gracefully —
> either `npm install` reached the internet, or there's no UI at all. We took
> hand-written components as the cost. `python scripts/serve.py` is the whole
> deployment.

**"Is the blockchain part real, or just a hash?"**
> It's a hash chain, and we call it that. Each audit record binds verdicts to the
> exact config hash, chains to its predecessor, and commits findings through a
> Merkle root, signed with Ed25519. `/audit/verify` re-reads rows from SQLite and
> re-checks four independent links per record — so tampering with any earlier
> record invalidates every record after it.

**"How do you scale to a new vendor?"**
> One YAML pattern pack. Zero engine code. Our proof: adding the DISA STIG pack —
> 34 catalogs, 32 rules, three previously-dark frameworks — needed zero lines of
> engine code.

**"What's your coverage?"**
> Depends which denominator, and we publish both. 71 of 90 controls on CIS Cisco
> IOS 15, 32 of 35 on the DISA STIG router benchmark. Across *all* 3,366 loaded
> controls it's 13.49%, because most catalogs are for platforms we don't have a
> pattern pack for yet — and we publish that number rather than hide it. Anything
> we can't decide comes back as `notchecked` with a reason, never dropped.

---

# DEEP DIVE 1 — "Where do you use FastAPI and SQLite?"

## The 20-second answer (say this first)

> FastAPI **is** the product — it's not a wrapper around a script. The entire
> tool is one FastAPI process: it serves 28 REST endpoints *and* serves the
> frontend itself, so `python scripts/serve.py` is the whole deployment. SQLite
> is our system of record — devices, facts, findings, the audit ledger and the
> training queue are all tables in one file, `data/praman.db`. No database
> server, no container, no cloud. That's what lets it run air-gapped.

## FastAPI — where exactly (`backend/app/main.py`)

28 endpoints across eight groups. If a judge asks "show me", name these:

| Group | Endpoints | What it does |
|---|---|---|
| **Ingest** | `POST /ingest`, `POST /ingest/bulk`, `POST /simulate` | Upload a config → parsed to canonical facts. Bulk takes an archive and reports **per-member** outcomes. |
| **Audit** | `POST /audit/commit`, `GET /audit/records`, `GET /audit/verify`, `GET /audit/access` | Commit findings to the ledger; re-verify the chain; read who touched what. |
| **Devices** | `GET /devices`, `/devices/{id}`, `/devices/{id}/report.pdf`, `/devices/{id}/remediation` | Per-device findings, the signed PDF, and the fix CLI. |
| **Exports** | `GET /devices/{id}/oscal.json`, `POST /simulate/sarif` | OSCAL 1.2.3 Assessment Results from a **committed** audit; SARIF 2.1.0 from a **simulation**, for a CI gate. |
| **Training (C2)** | `GET /training/queue`, `POST /training/map`, `GET /training/mappings`, `POST /training/retire`, `GET /training/export` | The human-in-the-loop loop — this is the AI training module. |
| **Identity** | `POST /auth/login`, `POST /auth/logout`, `GET /auth/whoami` | Three roles; the authenticated operator is hashed **into** each ledger record. |
| **Jobs** | `GET /jobs`, `GET /jobs/{id}`, `POST /jobs/{id}/cancel` | `POST /ingest/bulk?background=true` returns a job id instead of blocking; these poll it and stop it. Cancelling keeps the members already ingested. |
| **Metadata** | `GET /health`, `/vendors`, `/frameworks`, `/canonical/paths` | Self-describing API; `/canonical/paths` returns all 330 paths. |

**Three things worth naming if they push:**

1. **Pydantic models are the contract.** Request and response models
   (`IngestResponse`, `CommitResponse`, `SimulateResponse`) mean the API shape is
   validated, not documented-and-hoped. FastAPI generates OpenAPI from them free.
2. **Typed exception handlers.** `ParseError`, `MappingError` and `ExportError`
   have registered handlers (`main.py:230`, `main.py:243`, `main.py:251`), so a
   malformed config returns a structured 4xx explaining what failed — not a 500
   stack trace.
3. **It serves the frontend too.** `main.py:1901` — and there is deliberately
   **no SPA catch-all**, because a fallback that returns `index.html` for every
   unknown path turns an API typo into a 200 with HTML in it.

## SQLite — where exactly (`backend/db/connection.py`)

**Six tables, one file:**

| Table | Holds |
|---|---|
| `devices` | one row per config ingested, with its `config_hash` |
| `canonical_facts` | the 330-path facts, with line numbers and provenance |
| `findings` | every verdict — pass, fail, **and `notchecked`** |
| `audit_records` | the ledger: `seq`, `prev_hash`, `record_hash`, `merkle_root`, `signature` |
| `training_queue` | unparsed lines awaiting a human decision (C2) |
| `mapping_store` | confirmed human mappings — the hot-reload source |

**The engineering choices to name:**

- **WAL mode** (`PRAGMA journal_mode=WAL`) — readers don't block the writer, so
  the UI can poll findings while an ingest is still running.
- **`PRAGMA foreign_keys=ON`** — findings and facts can't outlive their device.
- **JSON1** — `evidence`, `references`, `summary`, and fact `value` are JSON
  columns, so a fact's value keeps its type instead of being flattened to text.
- **Six indexes** on the hot paths — `findings(audit_id)`, `findings(device_id)`,
  `findings(framework)`, `canonical_facts(device_id)`, `canonical_facts(path)`,
  `training_queue(status)`.
- **Append-only triggers** — this is the good one, see below.

### The line that will impress them (`connection.py:145`)

> We enforce append-only **at the storage layer**, not just in application code.
> There are two SQLite triggers on `audit_records` that `RAISE(ABORT)` on any
> UPDATE or DELETE. So the hash chain makes tampering *detectable*, and the
> triggers make the ordinary kinds of it *impossible* — a stray UPDATE in a
> migration, or a support engineer "fixing" a timestamp, is caught at the
> statement with a message saying why, instead of surfacing weeks later as an
> unexplained verification failure.
>
> And we're honest about the limit: someone who can write to the file can also
> `DROP TRIGGER`. That attacker is the hash chain's job. We test that too — the
> test suite drops the triggers on purpose to play that attacker.

## ⚠️ Slide correction: FTS5

Your slide says **"SQLite (WAL, FTS5)"**. WAL is real and used. **FTS5 is not
actually used anywhere in the codebase** — only mentioned in a docstring. There
*is* a vector index (`sqlite-vec`) in `scripts/build_template_index.py`, but it
isn't wired into the running app.

If a judge asks "where's your full-text search?", the safe answer is:

> Full-text search isn't in the current path — our lookups are indexed
> equality on device, path and framework, which is what the query pattern
> actually needs. WAL and JSON1 are what we rely on today.

**Better: change the slide to "SQLite (WAL, JSON1)"** — both true, and JSON1 is
the more interesting claim anyway. Never leave a claim on a slide you can't
demonstrate; judges dig exactly there.

---

# DEEP DIVE 2 — "Security & Proof": what it is and where it lives

## The 25-second framing (lead with this)

> The "Security & Proof" box answers one question: **why should anyone believe
> our report six months from now?**
>
> A compliance report is only useful if it's evidence. So we don't just print a
> verdict — we commit to it. Every audit is hashed, chained to the previous
> audit, and signed. And crucially, it can be re-verified by a program that
> **imports nothing from our codebase** — because a verifier that calls into the
> thing it's verifying only proves the thing agrees with itself.

## The four links — the core mental model

Memorise this chain. It's the whole answer:

```
findings ──▶ merkle_root ──▶ record_hash ──▶ signature
                  │
        and across records: record_hash ──▶ next record's prev_hash
```

Each link catches a different attack, and each fails independently:

| Link | What it catches | Where |
|---|---|---|
| **`merkle_valid`** | a **verdict** was altered, added or removed | `chain.py:compute_merkle_root` |
| **`hash_valid`** | a field was altered — summary, timestamp, device id | `chain.py:compute_record_hash` |
| **`chain_valid`** | a record was **removed, reordered or spliced** | `prev_hash` comparison |
| **`signature_valid`** | a record was **forged wholesale** by someone without the key | Ed25519 via `cryptography` |

> Checking three of four proves nothing about the fourth — so `/audit/verify`
> checks all four and reports **`None`, never `True`**, for anything it couldn't
> check. "I didn't look" is not the same answer as "it's fine."

## Where each piece lives in the project

**1. `backend/ledger/chain.py` — the writer.**
Called by `POST /audit/commit` (`main.py:860`). On commit we:
- bind the verdicts to the **exact `config_hash`** they came from — so "these
  findings came from those bytes" is checkable later
- compute a Merkle root over the findings
- hash the record, chain it via `prev_hash`, sign the hash with Ed25519
- write it in one transaction

**2. `backend/ledger/verify.py` — the standalone verifier.**
This is the piece to be proud of. It **imports nothing from `backend/`**. A third
party can run:

```bash
python -m backend.ledger.verify data/praman.db
```

Exit codes are distinct on purpose: **0** = every link of every record checked and
passed; **1** = a link is broken; **2** = *incomplete* — consistent, but something
couldn't be checked. So a CI job can never mistake "we didn't look" for "we
looked and it was fine."

**3. `SQLite append-only triggers`** — defence in depth (see Deep Dive 1).

**4. `backend/ingest/redact.py` — credential redaction.**
Secrets never reach the database, the PDF, the ledger or the training queue —
enable secrets, local passwords, SNMP communities, pre-shared keys, TACACS and
RADIUS keys, across all seven vendor packs.

**5. `backend/report/attach.py` + `sign.py` — the PDF side.**
The rendered PDF gets the findings and canonical facts **embedded as
attachments**, and *then* it's signed (PAdES, via pyHanko). Order matters: pyHanko
signs through an incremental update, so anything attached after signing lands
outside the signed byte range. The PDF also carries `X-PRAMAN-Record-Hash` and
`X-PRAMAN-Audit-Id` headers tying it back to a ledger row.

## THREE STORIES THAT WIN THE ROOM

These are your best material — they show engineering judgment, not just features.
Judges remember stories, not feature lists.

### Story 1 — "Our integrity check was broken, and we found it"

> Our record hash originally covered whatever keys the caller's dict happened to
> carry. The commit path passed a dict that also held the full findings list. The
> verifier read the row back from SQLite — where findings live in their own table
> and can't be a column. So the two hashed **different inputs**, and every record
> in the ledger failed its own integrity check: 13 of 13 on our dev database.
>
> The lesson is the sharp bit: **a check that fails on healthy data cannot detect
> unhealthy data.** A genuinely altered record looked exactly like a sound one.
> The fix is an explicit eight-field list — `RECORD_HASH_FIELDS`. Findings are
> deliberately excluded, because they're already committed by `merkle_root`,
> which *is* a column — and that's what makes offline verification possible at
> all.

### Story 2 — "Our Merkle tree had the one property it needed to not have"

> The textbook Merkle tree duplicates an unpaired last node. That makes `[a,b,c]`
> and `[a,b,c,c]` hash to the **same root** — so someone could append a duplicate
> of the final finding to a committed audit without invalidating the ledger. That
> is the entire point of the structure, and it was the one property ours didn't
> have.
>
> We **promote** the odd node unchanged instead. We also tag leaves `0x00` and
> internal nodes `0x01`, per RFC 6962 — without that, a root can't tell *two
> findings* from *one finding whose text happens to be two concatenated digests*.

### Story 3 — "Our redaction was silently corrupting audits"

> Redaction used to run **before** the parser. But pattern packs read
> whitespace-delimited fields, so replacing a secret with a token containing
> spaces shifted every field after it and the whole line stopped matching.
>
> Measured over our fixtures: **58 facts lost across 11 canonical paths, and 31
> verdicts changed.** All in the bad direction. A deliberately insecure fixture
> reported *compliant*, because CIS 1.5.7 and 1.5.8 flipped FAIL → PASS. Thirteen
> real FAILs degraded to `notapplicable`. And the `enable secret` pattern was
> capturing the hash-type *digit* as the secret — redacting the metadata while
> leaving the actual hash in the clear.
>
> So redaction now runs **after** the parse, over the parse result. The security
> control was breaking the correctness of the thing it protected, and we only
> found it by measuring.

## If they ask: "Is this actually blockchain?"

Answer this head-on and confidently. Do not oversell — overselling here is how
teams lose credibility in one sentence.

> No, and we don't call it one. There's no distributed consensus and no network —
> it would be dishonest to claim otherwise for a theme keyword.
>
> What we use are the **cryptographic primitives that make a blockchain
> tamper-evident**, applied to an audit ledger: a hash chain, a Merkle
> commitment, and digital signatures. For this threat model that's the right
> tool. The asset is a single-operator, air-gapped audit trail — consensus
> across nodes would add nothing, and a network is exactly what the deployment
> forbids.
>
> The property we actually need is: *tampering with record `n` invalidates every
> record after it, and anyone can check that without trusting us.* That's what we
> built, and it's the property we can demonstrate right now.

## Quick reference — one line each

| Ask | Answer |
|---|---|
| Hash function | SHA-256 |
| Signature | Ed25519, via `cryptography >= 50.0.0` |
| Key location | `data/private/ed25519_signing.key`, public key published alongside |
| PDF signature | PAdES via pyHanko; B-LT with a real cert + TSA, self-signed demo key otherwise — and it **says which** |
| Ledger anchor | The `AuditRecord`, not the PDF. "A PDF is a rendering; the record is the evidence." |
| No key present? | Report still generates; `X-PRAMAN-Signature` says **unsigned**. Honest degradation, never silent. |

---

# ⚠️ THINGS TO FIX / KNOW BEFORE YOU PRESENT

## 1. The test count

The slide image says **"pytest – 1,010 tests green"**, but the repo is currently
at **1,798 tests** (`README.md`, `docs/PRESENTATION.md`).

Pick one:
- **Best:** update the slide graphic to `1,798`, and say "over seventeen hundred tests".
- **If the slide is frozen:** say **"over a thousand tests, all green"** — true for
  both numbers, and you never contradict your own slide on stage.

The `1,010` above is quoted deliberately: it is what the frozen slide image says,
not a claim about the repository. `tests/test_published_counts.py` keeps the
second figure current and leaves the first alone.

Re-verify before submitting:

```bash
.venv/Scripts/python.exe -m pytest -q
```

## 2. "FTS5" on the slide

Not used in the codebase (see Deep Dive 1). Change the slide to
**"SQLite (WAL, JSON1)"**, or be ready with the honest answer above.

## 3. "10 offline views" vs vendor count

The slide says **10 offline views** — correct, that's the frontend. But don't
confuse it with **7 vendor pattern packs** and **20 shipped fixture configs**.
Three different numbers, easy to swap under pressure:

- **7** vendors (Cisco IOS, NX-OS, ASA, Arista EOS, Juniper JunOS, Fortinet, Palo Alto)
- **10** frontend views
- **20** device configs shipped
- **330** canonical paths
- **454** rules · **42** catalogs · **3,366** controls

## 4. The one thing never to say

Never say the AI decides a verdict. It doesn't, by design — and that design is
your strongest answer in the room. The AI *suggests a canonical path*; a human
confirms; it becomes a deterministic pattern. Compliance verdicts are always
reproducible.
