# Production roadmap and competitive position

What is left to build before PRAMAN is deployable inside a real company, what
would make it defensibly unique, and how it stands against the tools that
already sell into this space.

**Method.** Everything below was checked against the repository, not inferred
from the docs. Where a claim is about a competitor it carries the source the
project's own research corpus recorded. Where something was not verified it says
so in §7. The three governing files (`GLOBAL_RULESET.md`, `MASTER_PROMPT.md`,
`MANUAL_COMMANDS.md`) were read — `MASTER_PROMPT.md` is byte-identical to the
concatenation of `.build/sections/*.md` (189,186 bytes each), so the phase
gates, Definition of Done and risk register in §28–§32 are the yardstick used
throughout.

**Baseline state, measured 2026-09-07.** `pytest -m "not slow"` is green: 1,152
tests, zero failures, exit 0. The working tree carries 1,716 uncommitted
insertions across 32 files plus six new rule mapping packs (3,188 lines of
YAML), so the figures in `README.md` describe the working tree rather than
commit `1be7ac1`.

**How this document is maintained.** The diagnosis below is kept as written,
because the argument for each item is the reason it was worth doing and a
resolved item whose reasoning has been deleted is an item nobody can re-check.
Work that has since landed is marked with a `**Resolved**` note under its own
heading naming what shipped and the test that holds it. Nothing is deleted from
the analysis; §1.5 carries the running tally.

Two things are kept separate throughout, because conflating them is how
roadmaps become wish lists:

- **Blockers** — absence means the tool cannot be deployed at all, however good
  the engine is.
- **Differentiators** — presence would make it the preferred choice over an
  incumbent that already has the blockers solved.

---

## 0. The honest summary

PRAMAN is a better-engineered project than its own README lets on. The canonical
fact model is implemented field-for-field as specified, the XCCDF nine-value
result enum is real and `unknown` is genuinely wired to the training queue, the
ledger's standalone verifier documents its own past drift and refuses to say
`True` about a link it did not check, and `docs/GAPS.md` argues every unautomated
control individually. That last document is the most unusual thing in the
repository: no competitor reviewed publishes their own coverage gaps at all.

What it is not, yet, is deployable in a company. Not because of missing features
— because of missing **identity**. Every endpoint is unauthenticated, and the
ledger proves *what* was decided while recording nothing about *who* decided it.
For a tool whose entire value proposition is evidence, that is the one gap that
invalidates the proposition rather than merely limiting it.

> **That paragraph is now historical.** Identity shipped on 2026-09-09 — see
> §1.1 for what was built and §1.5 for what is left. It is kept above because the
> argument in it is the reason the work was prioritised, and because a roadmap
> that quietly rewrites its own diagnosis cannot be audited against the commit
> that answered it.

Three sentences that summarise the delta:

1. **The deployment blocker is authentication plus operator identity in the
   ledger.** Everything else in §1 is smaller than it looks. *(Done; the residual
   is TLS, which the application deliberately does not implement.)*
2. **The credibility gap is that "4 frameworks × 7 vendors" is true of the fleet
   only on two vendors.** Five of seven vendors score `0` on NIST and `0` on ISO
   today, for a mechanical reason with a known fix (§2.1).
3. **The enterprise wedge is already specified and not built.**
   `backend/export/` contains zero Python files; `MASTER_PROMPT.md` §13
   specifies OSCAL Assessment Results and SARIF v2.1.0 in full, enums frozen.

---

## 1. Tier 0 — blocks deployment in any company

### 1.1 No authentication, no authorisation, no operator identity

> **Resolved 2026-09-09.** `backend/app/auth.py` now resolves a principal on
> every route except four — `/health`, `POST /auth/login`, `/` and the static
> asset catch-all — and `tests/test_auth.py` walks `app.routes` so a route added
> without a dependency fails the suite rather than shipping open. Three ordered
> roles (`viewer` 0 < `auditor` 1 < `approver` 2) make authorisation a
> comparison. Passwords are PBKDF2-HMAC-SHA256 at 600,000 iterations with a
> per-user salt; sessions are `secrets.token_urlsafe(32)` stored only as a
> SHA-256 digest with a 12-hour lifetime and server-side revocation. There is no
> default account and no bootstrap route: a fresh clone answers `503` naming
> `scripts/manage_users.py`. **`AuditRecord.actor` is inside
> `RECORD_HASH_FIELDS`**, so the operator's name is covered by the record hash
> and the Ed25519 signature, and the standalone verifier gained its fifth check —
> tri-state, so an unknown actor reports INCOMPLETE and exits 2 rather than
> passing. Reads are logged (§1.4). What remains of this item is transport only,
> and it is transport by choice: see §1.4's TLS row.
>
> The re-seed this section predicted was real. Adding `actor` changed the hash
> definition for every pre-existing row, and `MANUAL_COMMANDS.md` **Step 12** is
> what closes it.

Verified: `grep -rn "Depends(\|HTTPBearer\|APIKeyHeader\|bcrypt\|OAuth2"
backend/ --include=*.py` returns nothing. The only trace of the subject is a
prose comment at [`backend/app/main.py:106`](../backend/app/main.py). Nineteen
endpoints, all open. `docs/SECURITY.md` §1 states this plainly and argues —
correctly — that a hardcoded password would be worse than visible absence.

Why this is *the* blocker rather than one item on a list: the ledger is the
product. It chains verdicts to a `config_hash`, commits findings through a
Merkle root, and signs the result. What it does not carry is an actor.
SECURITY.md already says the thing that should drive the design:

> a ledger that proves *what* was decided but not *who* decided it is only half
> an audit trail.

**Shape of the fix.** An authenticated identity per request; authorisation
separating who may upload from who may commit to the ledger; and an `actor`
field inside `AuditRecord` so the identity falls inside `canonical_bytes()` and
is therefore covered by the record hash and the signature. The standalone
verifier gains a fifth check.

That last part is why this must be one change and not three. Adding a field to
the hashed record changes the hash definition for every existing row, which is
exactly what `MANUAL_COMMANDS.md` **Step 12 — "Re-seed the ledger after a
hash-definition change"** exists for. Doing auth first and identity later means
paying the re-seed twice.

### 1.2 Repository hygiene — two defects, hours of work each

> **Resolved.** `praman/data/praman.db` is out of the index (`git rm --cached`)
> and in `.gitignore`; `checkpoints/` is in `.gitignore` with a comment recording
> *why* the path exists — `TrainingArguments.output_dir` defaults to the relative
> string `"checkpoints"`, so it resolves against whatever directory the trainer
> was launched from. `tests/test_repo_contract.py` asserts both ignore rules, so
> a future `.gitignore` edit that drops one fails the suite.

**`praman/data/praman.db` (16,912,384 bytes) is tracked in git.** Confirmed with
`git ls-files`. Per `docs/SECURITY.md` the `facts` table holds device
configurations. So the moment a real customer configuration is ingested,
`git status` shows a modified 17 MB binary containing it, and a routine
`git commit -a` publishes it. `GLOBAL_RULESET.md` §8 says "never commit real
device configs" and §12 lists what must never be committed; this is the
mechanism by which that rule gets broken by accident rather than by intent.

Fix: `git rm --cached praman/data/praman.db`, add it to `.gitignore`, ship a
seed script so a fresh clone still demonstrates. The database is regenerable
from the fixtures — nothing is lost.

**`praman/checkpoints/` is 260 MB of SetFit training state, untracked and not
gitignored.** It holds `model.safetensors`, `optimizer.pt`, `rng_state.pth`,
`scheduler.pt`. `praman/.gitignore` covers `data/models/classifier/` and
`*.gguf` but nothing matching this path, so a single `git add -A` commits model
weights — explicitly forbidden by §12, and 260 MB against a 66 GB disk budget.

Fix: add `checkpoints/` to `.gitignore` and delete the directory, or point the
trainer's `output_dir` under the already-ignored `data/models/`.

### 1.3 A Definition-of-Done gate is absent, and it would already be failing

> **Resolved.** `MANUAL_COMMANDS.md` **Step 8c — Train the SetFit few-shot
> classifier** now exists with all six required fields, and
> `tests/test_manual_commands_contract.py` is the mechanical gate: it asserts
> that every `Step N` cited anywhere in the tree names a declared step, that
> every declared step carries all six fields, and that every
> `ArtifactMissingError` message cites at least one step. None of the three looks
> at what a step *says* — they check that the pointer resolves, which is the part
> that rots silently, because a step citation is prose inside a string literal
> and no import, type check or lint pass can see it.

`MASTER_PROMPT.md` §32 point 6 prescribes
`tests/test_manual_commands_contract.py`: every heavy-artifact error message in
the codebase must name a step that actually exists in `MANUAL_COMMANDS.md`. The
test does not exist, and the contract is already broken —
[`scripts/train_setfit.py`](../scripts/train_setfit.py) cites
"`MANUAL_COMMANDS.md` Step 8c", and `MANUAL_COMMANDS.md` has Step 8a and Step 8b
only (`grep -n "Step 8c"` returns nothing).

`.build/sections/G.md` §28 is explicit: "Never cite a step number you have not
written (GLOBAL_RULESET R1.4, R2.2)." Fix: write Step 8c for the SetFit
fine-tune with all six required fields, then write the guard test so the next
one is caught mechanically.

Small defect, listed at Tier 0 on purpose. Claim discipline is this project's
headline virtue; a dangling reference to a step that does not exist is the exact
failure the ruleset was written to prevent.

### 1.4 The remaining security debts, as SECURITY.md already names them

Documented rather than hidden, which is the right posture. Still deployment
gates.

| Debt | Where | Status | Note |
|---|---|---|---|
| Plain HTTP, no TLS | SECURITY.md §2 | **Config shipped, app unchanged** | `deploy/nginx/praman.conf` terminates TLS 1.2+, sets HSTS and a CSP, adds `Secure` to the session cookie, rate-limits `/auth/login` at 6r/m, and refuses `/docs`. The application still speaks plain HTTP and will not change: it cannot know whether it is behind TLS, so a `Secure` flag it set itself would be a guess. Three of the config's numbers are asserted against the app by `tests/test_deploy_config.py`, because a proxy config that has drifted breaks only in the one environment nobody develops in |
| Signing key on the same disk as the DB it signs | SECURITY.md §3 | **Open** | Real non-repudiation needs KMS/HSM or an RFC-3161 timestamp authority. `G.md` §28 P6 flags that **no public TSA URL is verified anywhere in the corpus** — treat the URL as human-supplied input |
| Reads are not logged at all | SECURITY.md §5 | **Done** | `_access_log_middleware` writes actor, method, path, status and duration for every request including PDF downloads; unauthenticated attempts are logged with an empty actor, so a probe is visible rather than absent. `GET /audit/access` is approver-only, because the log answers "who looked at the core router's findings" and a viewer-readable copy would make the reviewer's work visible to the reviewed. Not tamper-evident — see SECURITY.md §5 for why chaining it was rejected |
| No rate limiting | SECURITY.md §4 | **Partial** | The login lockout (10 failures / 900 s) covers one route, is in-process and clears on restart — it is a credential-stuffing brake, not a rate limiter. Per-request limiting is the proxy's job and is in the shipped config; the application still has none |
| No multi-tenancy or data segregation | *not in SECURITY.md* | **Open** | One SQLite file, no tenant column. An MSP, or a company with separate business units under separate assessors, cannot use it. Worth adding to the threat model even before it is built |

### 1.5 Tier 0 tally

| Item | State |
|---|---|
| §1.1 Identity, authorisation, `actor` in the signed record | **Done** |
| §1.2 Repository hygiene (tracked DB, trainer checkpoints) | **Done** |
| §1.3 Step-citation gate | **Done** |
| §1.4 TLS | **Deliberately out of scope for the app**; config shipped |
| §1.4 Read auditing | **Done** |
| §1.4 Per-request rate limiting | **Proxy only** |
| §1.4 Signing-key custody | **Open** — needs an HSM or a TSA, both of which need a decision this project cannot make alone |
| §1.4 Multi-tenancy | **Open** — Tier 4 (§4), because it is a schema change, not a feature |

What that leaves is one genuine open blocker for a *company* deployment
(multi-tenancy) and one that is a procurement decision rather than an engineering
task (key custody). Neither is in the way of the single-assessor deployment the
tool is designed for.

---

## 2. Tier 1 — the gaps a real customer notices

These come from `docs/GAPS.md`, which is where the project already tracks them.
Re-ordered here by value delivered per unit of work.

### 2.1 ~~Four DISA NDM mapping packs — the highest-leverage task in the project~~ — **all four authored — 2026-09-12**

> **Closed.** All four packs exist. Six of seven vendors now reach NIST and ISO;
> the seventh has no STIG in the corpus to reach them through.
>
> | Vendor | Direct packs behind it | NIST reached | ISO reached |
> |---|---|--:|--:|
> | `arista_eos` | DISA EOS NDM + L2S | 34 | 13 |
> | `cisco_ios` | CIS IOS 15 + DISA Router NDM | 33 | 15 |
> | `cisco_nxos` | CIS NX-OS + DISA Switch NDM | 31 | 16 |
> | `cisco_asa` | CIS ASA + DISA ASA NDM | 29 | 14 |
> | `juniper_junos` | CIS Juniper + DISA Router NDM | 26 | 9 |
> | `fortinet` | CIS FortiGate + DISA Firewall NDM | 24 | 13 |
> | `paloalto_panos` | CIS PAN-OS only | **0** | **0** |
>
> 152 controls were mapped across the four packs — ASA NDM 44 of 47, NX-OS NDM
> 39 of 42, FortiGate NDM 35 of 60, Juniper Router NDM 34 of 49 — and each is
> argued control-by-control in `GAPS.md` §2.5 through §2.9, including the ones
> deliberately left unmapped.
>
> **Two things this section got wrong, and one it got right.**
>
> *Right:* "no new code, no new canonical facts, no new condition types" held for
> three of the four packs. It did **not** hold for the fourth — the eleven NX-OS
> accounting controls need a group→server binding the rule language cannot
> express, and nine FortiGate and six Juniper controls need the same
> `cross_reference` type §2.4 lists. Those are counted as unmapped above rather
> than mapped loosely, so the percentages are lower than a pack author optimising
> the headline would have reported.
>
> *Wrong, first:* the estimate that the projection would land near Arista's
> numbers was optimistic for FortiGate and Juniper, whose NDM STIGs carry fewer
> distinct NIST references than EOS's two packs do between them. The reach is
> real but it is not uniform, and the table above is the honest version.
>
> *Wrong, second — and this is the one worth keeping:* this section, the vendor
> table in `GAPS.md` §4, and the coverage figures throughout were all hand-
> maintained, and **the `GAPS.md` table had already drifted** by the time the
> packs landed. It listed 11 of the 13 mapped benchmarks and understated CIS
> Juniper by one control. Nothing failed, because that table was the last
> published figure in the project with no gate behind it.
> `tests/test_coverage_table_is_current.py` now recomputes every row from the
> loaded catalogs and the shipped packs, asserts the rows sum to the headline
> 454, and prints the corrected row when it fails. The lesson §3.3 taught about
> invented mitigation IDs is the same one here: the fix is not to be more careful
> with the number, it is to stop the number being hand-maintained.

**No Palo Alto STIG exists in the corpus at all**, which is why the PAN-OS
fixture reports DISA STIG as `—` with a `notchecked` count of *zero* rather than
a large one. Nothing is in scope, as opposed to in scope and unmapped. Those two
states render identically today and only the count distinguishes them — worth a
UI distinction, because "not applicable to this platform" and "we have not
written it yet" are very different answers to a buyer. This is now the only part
of this section still open.

<details>
<summary>The original diagnosis, kept for the record</summary>

`GAPS.md` §4 measures it: five of seven vendors reach **zero** NIST controls and
**zero** ISO controls.

| Vendor | Direct packs behind it | NIST reached | ISO reached |
|---|---|--:|--:|
| `cisco_ios` | CIS IOS 15 + DISA Router NDM | 33 | 15 |
| `arista_eos` | DISA EOS NDM + L2S | 33 | 13 |
| `cisco_asa` | CIS ASA only | **0** | **0** |
| `cisco_nxos` | CIS NX-OS only | **0** | **0** |
| `fortinet` | CIS FortiGate only | **0** | **0** |
| `juniper_junos` | CIS Juniper only | **0** | **0** |
| `paloalto_panos` | CIS PAN-OS only | **0** | **0** |

The mechanism, not the vendor, is the story: a device reaches NIST and ISO only
through a **DISA** pack, because DISA is the only publisher in this corpus whose
XCCDF ships cross-references — every control carries a CCI and a NIST 800-53
reference, and roughly 45% carry an ISO mapping. CIS carries none of the three.
So an ASA report shows a real CIS score beside two governance tiles reading `—`
with every control `notchecked`. Nothing is mis-stated. It still means a buyer
who checks NIST coverage on a router and then on a firewall sees the tool answer
very differently for reasons that have nothing to do with either device.

Closing it needs **no new code, no new canonical facts, no new condition
types** — the catalogs are already built and normalised:

| Pack to author | Controls | Effect |
|---|--:|---|
| `disa_stig_cisco_asa_ndm_…_v2r5` | 47 | Gives the ASA a NIST and ISO score |
| `disa_stig_fortinet_fortigate_firewall_ndm_…` | 60 | Same |
| `disa_stig_juniper_router_ndm_…_v3r2` | 49 | Same |
| `disa_stig_cisco_nx_os_switch_ndm_…_v3r6` | 42 | Same |

Arista is the worked example that proves the return: 28 controls across two
benchmarks took that vendor from zero governance projection to 33 NIST and 13
ISO. `GAPS.md` calls ASA NDM the "highest value of the unmapped set".

</details>


### 2.2 CIS Cisco IOS XE 17.x — 84 controls, built and unmapped

> **Corrected 2026-09-12 — the premise below is false, and false in the
> direction that produces wrong verdicts.** This section, and the `GAPS.md`
> sentence it quotes, both said the existing IOS 15 rules "port with only an
> `applies_to` change". They do not. **CIS renumbers control ids between the two
> benchmarks while keeping the numbering shape**, so the ids collide instead of
> colliding loudly. Measured across the two catalogs already built in this repo,
> keying on control *text* as the durable identity:
>
> | | controls |
> |---|--:|
> | same id **and** same title — a safe id-keyed port | **49** |
> | same title, **different id** — an id-keyed port mis-files these | **12** |
> | no IOS XE counterpart at all | **10** |
> | ambiguous | 0 |
> | *of the 71 the IOS 15 pack decides* | **71** |
>
> The worked example, from the built catalogs:
>
> ```
> ios15 1.1.6  "Set 'login authentication for 'line vty'"   -> xe 1.1.4
> xe    1.1.6  "Set 'aaa accounting' ... commands 15"        <- ios15 1.1.7
> ```
>
> Both ids exist in both documents. A pack ported by editing `applies_to` and
> pointing it at the XE catalog would load clean, pass
> `_validate_rule_targets`, and then decide `1.1.6` — *login authentication* —
> by running the check for a different control. There is no error and nothing
> in the report distinguishes it from a correct verdict.
>
> Note also that `1.2.9` and `1.2.10` both map to XE `1.2.8`: the publisher
> *merged* two controls. The port is not a bijection, so even a hand-written
> old→new id map has one place where a human has to choose which rule survives.
>
> **The gate came first.** `rules/control_bindings.lock.json` now pins the title
> each rule's target control carried when the rule was authored, and
> `tests/test_control_bindings.py` fails if any rule is re-pointed at a control
> whose text is not the one it was written against. That gate is not specific to
> IOS XE — it covers all 454 bindings, and the hazard it closes existed before
> this section was written. One of its tests reproduces the IOS 15 → IOS XE
> renumbering specifically, so the gate is known to fail and not merely known to
> pass.
>
> **What the port actually costs**, now that it can be done safely: 49 controls
> by id, 12 more behind an explicit old→new map with the merge resolved by hand,
> and 10 that have no XE counterpart and must stay unmapped. **61 of 84** XE
> controls, not 71 of 84, and not free.

<details>
<summary>The original diagnosis, kept for the record</summary>

`GAPS.md` calls this "the closest thing this project has to free coverage": IOS
XE configuration syntax is near-identical to IOS 15, the catalog is already
normalised, and most of the existing 71 IOS rules port with only an
`applies_to` change. `cisco_xe` and `cisco_xr` are already in the `Vendor` enum
and reach the ingestion layer.

</details>

The ingestion half of the claim survives: `cisco_xe` and `cisco_xr` are in the
`Vendor` enum and reach the ingestion layer, and IOS XE configuration syntax
really is near-identical to IOS 15. It is the *mapping* half that was wrong.

Also nearly free, and noted in `GAPS.md` as blocked only on a missing `Vendor`
enum value: the Dell OS10 and HP FlexFabric STIG catalogs.

### 2.3 Both-direction fixtures — the biggest test-quality gap

Of the 454 automated controls, **102 are exercised in both the passing and the
failing direction, and all 102 are Cisco IOS.** The other 352 run at most one
direction: 316 pass-only, 34 fail-only, and one reached only as `notapplicable`.
Mapping more benchmarks widens this gap rather than closing it — the six DISA
NDM packs written since this section was drafted added 141 controls, every one of
them one-direction — which is the argument for doing the fixture work before the
next pack rather than after.

A one-direction control catches a rule that stopped firing. It cannot catch a
rule that fires and returns the *wrong verdict* — the failure mode that matters,
because a false pass on a compliance tool is worse than a crash. `GAPS.md` is
candid about the related weakness too: each non-IOS vendor has exactly one
fixture, and a fixture and its pack written in the same change parse each other
perfectly by construction, so "zero unparsed lines" on five of those six
fixtures — the sixth, the ASA, carries one line left unmodelled on purpose —
means "nothing in this file surprised its own pack", not "this pack handles the
dialect".

Fix: a hardened/violating fixture pair per vendor under
`test_configs/compliance_extremes/`. The bar is data-driven —
`test_every_control_is_exercised_in_both_directions` promotes a vendor into the
strong tier automatically, with no list to update.

### 2.4 Rule-language and vocabulary work, with what each unlocks

| Item | Unlocks | Kind of work |
|---|---|---|
| `cross_reference` condition type (resolve a value at one path against the key of a block at another) + same-line ACL entry grouping | CIS 1.2.4, 1.5.5, 1.5.6, 3.2.1 and DISA V-215673 | Rule-language design |
| Split `time.ntp.key_id` → `time.ntp.server_key_id` + `time.ntp.authentication_key_id` | CIS 2.3.1.4, and removes a latent wrong verdict from 2.3.1.2 and 2.3.1.3 | Vocabulary + pattern pack |
| ~~Normalise `aaa.login_block` to seconds~~ | ~~CIS Juniper 6.6.1.5~~ | **Done** — see below |
| Split `mgmt.password_policy.name` by source stanza | CIS PAN-OS 1.3.10 | Vocabulary |
| Key-chain nested block (chain → key → key-string) + 3 interface-level directives | 11 CIS routing-auth controls; the block is shared by EIGRP, RIP, IS-IS and BFD | Pattern authoring, no code |
| An organisational-flag input and an interface-role input | CIS 1.5.1, 3.1.4, 3.2.2 — not decidable from a config alone | Product decision, not a bug |

`aaa.login_block` deserved a note because it was the clearest case of a canonical
path being a *contract* that was underspecified: it was seconds on `cisco_nxos`,
`arista_eos`, `fortinet` and `cisco_ios`, and **minutes** on `juniper_junos`
(`lockout-period`) and `paloalto_panos` (`lockout-time`). Three consumers got
away with it by checking presence only. One did not — DISA `V-215668` compares
against a real 900-second floor and was correct only because it regex-matched
the raw Cisco IOS line rather than reading a number.

It is now normalised to seconds in all six packs, via the same `minutes_seconds`
coercion the EOS `idle-timeout` conversion already used. `V-215668`'s third
condition is the plain `gte 900` the STIG states, and its verdict is unchanged on
all ten IOS fixtures. CIS Juniper 6.6.1.5 is mapped for the first time
(`gte 1800`, a real fail on the Junos fixture's 15-minute lockout) and CIS PAN-OS
1.4.2 tightened from presence to `gt 0`, which is what that benchmark actually
asks for. Details in [`GAPS.md`](GAPS.md).

### 2.5 Housekeeping with a real cost

- ~~**Four superseded seed rule packs**~~ **Done.** `rules/{CIS,DISA_STIG,
  ISO_27001,NIST_800_53}/` held 815 lines in a schema the current loader does not
  accept — flat `control_id`/`framework`/`benchmark` keys where the loader wants
  `catalog: {catalog_id, control_id}` and `applies_to`. Inert, since
  `load_all_rules()` reads only `rules/mappings/`, but nothing on disk said so and
  a reviewer who opened one drew the wrong conclusion about the rule format.
  Deleted; `rules/` now contains `mappings/` and nothing else.
- ~~**`mgmt.local_user.secret_type`**~~ **Done — deleted, and the diagnosis was
  wrong.** This section said the path was "emitted by no pattern and read by no
  rule". Half true: no rule read it, but *four* packs emitted it, and each meant
  something different by it — the account's hash algorithm on EOS, the storage
  format on the ASA, the literal keyword `phash` on PAN-OS, and the boolean
  `True` on FortiOS, where it was serving as the `config system admin` block
  anchor. The fix was not to write the rule this section anticipated; it was to
  move the two real hash-algorithm emitters onto `mgmt.local_user.hash_type`
  (seven packs, one live reader in CIS Junos 6.6.12), drop the PAN-OS constant as
  a restatement of a fact the same line already emitted, and re-anchor the
  FortiOS block on `mgmt.local_user.secret`. Vocabulary 331 → 330, corpus 3,445 →
  3,442 facts, zero verdicts changed. Written up in `docs/GAPS.md` §6.
- ~~**`reports/metrics/ai_abstention.json` is coupled to a running process.**~~
  **Done — and the diagnosis named the wrong culprit.** The coupling is real and
  cannot be removed: the abstention rate with a llama-server up is a different
  *true* number from the rate with it down, so a metric that ignored tier state
  would be the less honest one. What was actually wrong was the gate's verdict.
  `--check` reported **stale**, which means "the code moved, regenerate" — and
  regenerating on a demo machine would have overwritten a deliberate publication
  with an accident of local process state. Tier availability moved out of
  `results` into a new envelope-level `configuration` key that `check()` compares
  *first*; a mismatch now reports **not comparable** and returns 0, printing
  which knob differs. Every substantive figure is still gated whenever the
  configuration matches, which is the shipped default and therefore the case CI
  and a grader both hit. Held open by
  `tests/test_metrics_are_current.py::TestConfigurationIsNotConfusedWithStaleness`,
  which asserts a mismatch passes, a match still catches a moved number, and
  `ai_abstention.json` is the only metric declaring a `configuration` at all —
  one exemption is a decision, five would be a habit.
- ~~**The file-length debt the job queue added.**~~ **Done — repaid with
  interest.** §3.5's work grew five files that were already over the 500-line
  limit, which the `check_deliverable_limits.py` ratchet correctly refused. The
  budget was not raised. Instead three splits landed, each along a seam that was
  already there: `backend/app/routes_jobs.py` (the three `/jobs` routes, out of
  `main.py`, following the `routes_export.py` precedent),
  `backend/ai/mapping_queue.py` (the queue of templates *awaiting* a decision,
  out of the store of decisions already made — they shared a database and
  nothing else), and `backend/ingest/blocks.py` (`BlockScanner` — pass 1, pure
  lexical block-extent work over `list[str]`, out of the fact-production passes;
  a bug in the first puts a real finding on the wrong interface, a bug in the
  second gets the value wrong on the right one, and the two now fail in separate
  files). `mapping_store.py` fell to 499 lines and lost its budget entry
  altogether. Net: **7,778 → 7,404 lines of debt, 29 → 28 budgeted files, zero
  violations**, and 651 parsing tests still green across the moved code.

  Then the fix for the route-inventory blind spot (below) grew two *test* files
  that were themselves over the limit, and the ratchet refused those too — which
  is the gate working, not the gate being inconvenient. Two more splits, same
  rule: `tests/test_api_training.py` (the C2 round trip — teach, list, export,
  retire — which is one *ordered* workflow and read like a set of independent
  surface checks while it sat among them) and `tests/test_deploy_config.py` (the
  nginx CSP hashes, upload limit and port, whose subject is the shipped config
  rather than the frontend that happens to break when it is wrong). The five
  `/training` paths joined `EXPORT_ROUTES` and `JOB_ROUTES` in the inventory's
  named-elsewhere set, so the coverage gate still refuses to let them go
  untested. Net: **7,404 → 7,208 lines of debt**, still 28 budgeted files, zero
  violations, 78 route and contract tests green.

  A sixth candidate was considered and declined. `tests/test_published_counts.py`
  sat at 450 lines and the new benchmark-ratio gate (§2.6) would have pushed it
  to 548. Trimming the new test to fit under 500 was possible and would have been
  the wrong move: the ratchet's purpose is to push work toward seams, and there
  was a real one here. That module's subject is facts about *the repository*,
  derived by asking pytest and Python about themselves; the new gate's subject is
  figures produced by *a benchmark run*. They rot for different reasons and are
  fixed by different commands — edit a document versus re-run
  `scripts/bench/run_all.py` — and a failure message has to say which. So it
  landed as `tests/test_published_metrics.py` (160 lines), and
  `test_published_counts.py` stayed at 450. Debt unchanged at **7,208**, because
  a new file under the limit is not debt.

### 2.6 A published benchmark ratio had no gate at all

> **Resolved.** Three graded deliverables — `README.md`,
> `docs/PRESENTATION.md` and `docs/IDEA_ROUND_DECK.md` — stated that the
> ReportLab-less fallback renderer was **61.6× faster**. The regenerated
> `reports/metrics/pdf_generation.json` records **72.1×**, computed from the same
> run that supplies the ReportLab latency it is a ratio against. The metrics file
> was right; the deliverables were a bench run behind.

The interesting part is not the stale number, it is that **two tests each looked
like they covered this and neither did**:

- `tests/test_metrics_are_current.py` re-runs every benchmark in a subprocess and
  diffs the result against `reports/metrics/*.json`. It proves the measurement is
  current. It never opens the slide deck.
- `tests/test_published_counts.py` reads the README, both decks, the script and
  the guide. It proves what those documents claim *about the repository* — test
  count, endpoint count, canonical-path count. A ratio measured from a run is not
  in its subject.

Three relationships exist; two were gated. **Measurement → reality** and
**document → repository** were covered, and **document → measurement** was not,
so the JSON and the deck could disagree indefinitely with a green suite. That is
the same shape as the route-inventory bug below — not a test that broke, a test
that was never there, in a place where the surrounding coverage made it look
present.

`tests/test_published_metrics.py` closes it, and is built to resist the two ways
this kind of gate fails quietly:

- **It holds no literal.** The expected value is read out of
  `pdf_generation.json` at run time. Restating `72.1` in the test would create a
  second place for the number to go stale, which is the defect being fixed.
- **An empty scan is a failure.** If the claim is ever dropped from every
  document, `test_the_claim_still_exists` fails rather than passing on nothing.
- **A second ratio is a failure.** The pattern matches the phrase `N× faster`; it
  cannot know *what* was made faster. While the PDF fallback is the only thing
  these documents describe that way, matching the phrase is sound. A second,
  unrelated ratio would be silently held to the PDF benchmark's value — and the
  natural way to make that green is to overwrite a correct figure. So
  `test_only_one_speedup_claim_exists` fails on a second distinct value and says
  to give it its own assertion against its own metrics file.
  `docs/PRODUCTION-ROADMAP.md` is deliberately outside the scan set for exactly
  this reason: §3.4 records a `6.9x speedup` about an unrelated parse-cache fix.

The gate was verified by putting `61.6×` back into `README.md` and confirming it
went red naming `praman/README.md:256`, rather than by observing that it passes.
Cost of the three new tests: the suite moved 1,795 → 1,798, which made
`test_published_counts.py` red across sixteen figures in six documents until they
were swept — the gate charging its own price, on schedule.

---

## 3. Planned in the project's own spec, not built

`MASTER_PROMPT.md` freezes the repository tree in §5 and the machine-readable
exports in §13. These are the items where the specification is complete and the
implementation is absent — which makes them the cheapest high-value work in the
project, because the design argument is already won.

### 3.1 `backend/export/` — zero Python files

> **Resolved 2026-09-09.** `backend/export/` is six modules, 1,179 lines, every
> file under the 500-line limit: `oscal.py` (291) assembles the document,
> `oscal_mapping.py` (144) holds the XCCDF→AR table, `oscal_elements.py` (157)
> builds observations/findings/risks, `sarif.py` (453), `ids.py` (87) and
> `__init__.py` (47). Both exporters are stdlib `json`; `compliance-trestle` was
> not added.
>
> **Every field name, `required` list and enum was checked against the
> publishers' own JSON Schemas before the code was written, and then the output
> was validated against them.** `oscal_assessment-results_schema.json` v1.2.3 and
> `sarif-schema-2.1.0.json`, over all four extreme fixtures: 0 errors, and
> re-export byte-identical. §13.3's `TODO(verify)` on the SARIF field names is
> discharged — the marker is gone because the names were confirmed, not because
> it was deleted. The check is `scripts/check_export_conformance.py`, run as
> `MANUAL_COMMANDS.md` **Step 14** (it needs the two schemas downloaded, so it is
> not in the suite). Its exit codes separate "the exporter is wrong" (1) from
> "nothing was checked" (2 absent, 3 unpinned), because a conformance script that
> cannot tell a pass from a no-op is the §5.3 failure itself.
>
> Two facts read out of the schemas changed the design rather than confirming it.
> `region.startLine` has `minimum: 1`, and `backend/ingest/generic.py:614` gives
> every never-configured fact `line_start=0` — which is 1,311 of 1,462 findings
> on a hardened config, so "absent facts get a location with no region" is the
> common path, not an edge case. And `propertyBag` is
> `additionalProperties: true`, which is what makes the `praman*` bookkeeping
> keys legal rather than a schema violation.
>
> Two departures from §13.2's mapping table are deliberate and documented in
> `oscal_mapping.py`: a result outside `pass`/`fail` emits an **observation with
> no finding element**, because `finding-target.status` offers only
> `satisfied`/`not-satisfied` and there is no third state for "nobody checked" —
> emitting one would fabricate a verdict; and `target-id` is the control id
> rather than `<id>_obj`, because the suffix is not an identifier any catalog
> defines.
>
> Held by 148 tests <!-- scoped: tests/test_export_oscal.py tests/test_export_sarif.py tests/test_api_export.py -->
> (`tests/test_export_oscal.py` 63, `tests/test_export_sarif.py` 68,
> `tests/test_api_export.py` 17). The first two
> walk the `Result` enum itself rather than a hand-written list, so a tenth XCCDF
> value fails the suite instead of exporting as a blank verdict — the failure mode
> where a recipient cannot tell an unchecked control from a passing one. Routes in
> §5.2/§5.3.

`find backend/export -name "*.py" | wc -l` → `0`. `README.md`'s Layout section
advertises "`export/` machine-readable output for other tools".

§13 specifies **OSCAL Assessment Results JSON as the machine-readable source of
truth**, with the enums frozen: Objective Status `state` ∈ `satisfied |
not-satisfied`, `reason` ∈ `pass | fail | other`; `risk-status` ∈ `open |
investigating | remediating | deviation-requested | deviation-approved |
closed`; `implementation-status` ∈ `implemented | partial | planned |
alternative | not-applicable`. The XCCDF→AR mapping table for all nine result
values is already written. §13 also instructs writing it with stdlib `json` and
**not** vendor `compliance-trestle`, which hard-pins `jinja2==3.1.6`.

§13.3 specifies **SARIF v2.1.0** on the `/simulate` path, with the field names
still carrying an explicit `TODO(verify)`.

This is the enterprise integration story, and it is also the artifact
`MASTER_PROMPT.md` §29.3 names against the official SIH criterion "potential for
future work progression". See §5.2 and §5.3.

### 3.2 ~~`backend/db/` — no schema, no migrations~~ — **both directions now exist**

> **Closed 2026-09-10.** The heading was half stale when it was written and fully
> stale by the time anyone acted on it, which is worth recording because the two
> halves failed in opposite ways.
>
> **Forward** was already there and undocumented. `_migrate` — now
> `backend/db/schema_version.migrate` — adds the seven columns that landed after
> the first published schema (three on `training_queue`, three on `mapping_store`,
> `actor` on `audit_records`), additively and idempotently, so a database written
> by an older build keeps every row. `CREATE TABLE IF NOT EXISTS` is a no-op on an
> existing file, so without that function a new column would have reached only
> databases created from scratch and everyone else would have got `no such
> column`. That direction is loud when it breaks, which is why nobody noticed it
> was solved.
>
> **Backward** was the real hole, and it is silent. A database written by a
> *newer* build and opened by an *older* one looks perfectly healthy: SQLite does
> not object to a column the reader has never heard of, so selects succeed,
> inserts succeed, and every column the newer build depends on sits at its
> default. For `audit_records` that is not cosmetic, because `actor` is inside
> `RECORD_HASH_FIELDS` — the older build appends records hashed over a different
> field set into the same chain, and `scripts/verify_ledger.py` later reports
> tampering on rows nobody touched. The ledger's entire claim is that a
> verification failure *means* something; this is what keeps that true across
> builds, and it is why `check_schema_version` refuses rather than warns.
>
> The version lives in SQLite's own `PRAGMA user_version`, a four-byte field in
> the database header. No table to create, and it travels with the file when
> someone copies it off a machine — which is exactly the case that produces a
> forward mismatch. `init_database` checks *before* any DDL (creating a table is
> already a write, and the point is that this build has no business writing to
> that file at all) and stamps *after* the migration succeeds, never before: a
> version written ahead of the columns tells the next build there is nothing to do
> and converts a recoverable half-migration into a permanent one. Version 0 and
> version 1 are both accepted, because SQLite cannot distinguish "never stamped"
> from "stamped zero" and version 1 predates the stamping — safe precisely
> because the migration is additive.
>
> `tests/test_db_schema_version.py` is 8 tests. Five are about *refusing*; three
> exist to prove the refusal has not been made so eager that it blocks the
> legitimate upgrade it is meant to allow, including one that pairs
> `SCHEMA_VERSION > 1` to `ADDED_COLUMNS` being non-empty so the version cannot be
> bumped in the docs and forgotten in the code.
>
> The code is in `backend/db/schema_version.py` rather than `connection.py`
> because `connection.py` was at 498 of its 500 permitted lines and this took it
> to 557. `scripts/check_deliverable_limits.py` — written the same morning, §3.6 —
> refused to budget it, which is the ratchet catching the very first change after
> it landed rather than a 30th debt entry for code an hour old. The migration
> moved across with the version instead of staying behind: the version is a *claim
> about* the migration, so keeping them apart is what lets one be bumped without
> the other. `connection.py` came out at 450.

`README.md` claims "`db/` schema and migrations (SQLite)". That claim is now
true. §9's WAL, JSON1 and FTS5 are all in use; **sqlite-vec is still absent** and
is the only part of §9 this section no longer covers — see §4 for whether a
vector index is wanted at all at this corpus size.

### 3.3 ~~`backend/threat/` — built, and dead~~ — **wired, mapped and published — 2026-09-11**

> **Closed.** The tier now has the two things it was missing: an association to
> apply, and a caller to apply it. `data/frameworks/attack/canonical_map.yaml`
> supplies the first — seven entries, 103 of the 177 distinct paths the rule
> pack reads (the vocabulary itself is larger; rules touch a subset of it),
> joining **272 of 454 rules (59.9%)** onto eight techniques.
> `backend/cli.py` supplies the second: `findings.json` now carries a
> `threat_appendix` key, and on `fully_noncompliant.conf` **43 of the 71 failing
> CIS controls** map to a technique. `scripts/attack_coverage.py` publishes the
> whole join to `reports/metrics/attack_coverage.json` and gates it.
>
> **Three things this section did not anticipate, each of which changed the
> design.**
>
> 1. **The hand-written mitigation lists were wrong five times.** The draft YAML
>    carried a `mitigations:` list per entry, copied from the technique set above.
>    Checking it against the bundle's own `mitigates` relationships found M1026
>    attributed to T1602.001/.002 (the publisher relates M1030, M1031, M1037,
>    M1041, M1051, M1054), M1054 to T1556.004 (M1026, M1032) and M1051 to
>    T1601.001/.002 (M1026, M1027, M1032, M1043, M1045, M1046). Every one was
>    plausible enough to survive review — which is what makes an invented citation
>    worth engineering against rather than proofreading against. `mitigations_for()`
>    now derives them, and a test asserts the YAML never asserts one again. The
>    editorial surface is now exactly one thing: which paths imply which technique.
> 2. **Three mapped prefixes matched no rule at all** — `snmp.engine_id`, which no
>    rule reads, and `mgmt.ssh.ciphers`/`mgmt.ssh.macs`, misspelt plurals of real
>    paths. Each read in review as a mapped family and contributed nothing.
>    `--check` now fails on a dead prefix, which is the only way this class of
>    error is visible at all.
> 3. **`enrich_findings` had no production caller**, which this section's
>    `grep` noticed as "nothing imports the module" but read as a wiring
>    oversight. It was structural: a finding does not know which rule decided it,
>    and `Finding` is `extra="forbid"` with the Merkle root taken over the
>    findings, so the annotation could not go *on* a finding without invalidating
>    every record in the ledger. Hence `backend/threat/appendix.py`: the appendix
>    is a **sibling** of `findings` in the report envelope, keyed
>    `(framework, benchmark, control_id)` and joined through the catalogs.
>
> **Two techniques were added beyond §22.4's set**, both verified against the
> local bundle: `T1557` **Adversary-in-the-Middle** for the routing and tunnel
> authentication family (18 rules — an unauthenticated OSPF or BGP adjacency is
> how the sniffing position gets *created*, which is a different claim from
> T1040), and `T1016` **System Network Configuration Discovery** for CDP. T1016
> has no `mitigates` relationship in v19.2 at all, so `mitigations_for("T1016")`
> returns `[]` — a measurement, not a lookup failure, and documented as such
> where someone would otherwise read it as a bug.
>
> **Only `fail` is mapped.** A pass is not a technique an adversary performed;
> `notchecked` is honest absence and must not render as exposure any more than it
> renders as PASS; `notapplicable` means the control does not govern the device;
> `error` and `unknown` describe the tool's state, not the device's. The
> `logging.*` and `aaa.accounting_*` families — 25 paths, the largest block in the
> pack — are deliberately unmapped, and `--check` does **not** fail on unmapped
> paths, because a gate demanding 100% would be a standing incentive to file "no
> syslog" under T1602. See `docs/GAPS.md` §4.
>
> P12 held: 21 tests in `tests/test_threat_appendix.py` assert the Merkle root is
> unchanged by the appendix and that the envelope loses exactly one key with the
> flag off.

> **Path fixed 2026-09-09; wiring still open.** `ATTACK_BUNDLE_PATH` now reads
> `data/frameworks/attack/ent.json`, the location `MANUAL_COMMANDS.md` Step 4a
> writes, and `tests/test_threat_enrichment.py` (21 tests) pins it *against Step
> 4a's own text* so the two cannot drift. The loader is cached — 26,086 STIX
> objects is 0.47 s to parse, once per process rather than per audit — and it now
> marks the 161 revoked or deprecated techniques of v19.2's 858 rather than
> presenting a withdrawn ID as current context.
>
> **The §22.4 technique set is real, not synthetic.** Every ID quoted below
> carried a `synth:` marker in `MASTER_PROMPT.md`, meaning unverified when
> written. All of them were checked against the local ATT&CK v19.2 bundle and all
> resolve, none revoked, with the names the spec implied: `T1602.001` **SNMP (MIB
> Dump)**, `T1602.002` **Network Device Configuration Dump**, `T1556.004`
> **Network Device Authentication**, `T1040` **Network Sniffing**, `T1601.001`
> **Patch System Image**, `T1601.002` **Downgrade System Image**, plus the
> parents `T1601`/`T1602`; and all nine mitigations `M1026` `M1030` `M1031`
> `M1032` `M1037` `M1041` `M1046` `M1051` `M1054`. So the mapping is groundable
> offline against the publisher's bundle.
>
> ~~What is still missing is the mapping itself:~~ **written 2026-09-11 as
> `data/frameworks/attack/canonical_map.yaml`.** The premise held exactly as
> stated — **no publisher ships a
> control → technique crosswalk** for CIS or DISA network-device benchmarks, and a
> scan of all 42 normalised catalogs for `T####` tokens returns nothing. So the
> rule → technique association has to be authored, and has to be labelled as
> PRAMAN's own editorial judgement — which is a different kind of claim from the
> remediation CLI, and must not be presented as though DISA or CIS asserted it.
> It is labelled in the file header, in `authored_by`, in the appendix's
> `disclaimer`, in the `praman_rationale` key name, and in the coverage script's
> output. Five places, because the one failure mode that matters is a reader
> quoting a PRAMAN judgement as MITRE's.

~~[`backend/threat/enrichment.py:14`](../backend/threat/enrichment.py) reads
`DATA_DIR / "frameworks" / "enterprise-attack.json"`. That file does not exist.~~
Fixed 2026-09-09. The real 53,835,637-byte bundle is at
`data/frameworks/attack/ent.json`, two directories away.

~~And nothing imports the module.~~ `grep -rn "backend.threat"` across `backend/`,
`scripts/` and `tests/` returned exactly one hit —
`tests/test_repo_contract.py:27`, which asserts the *directory* exists. So the
repo-contract test passed on a package whose only module pointed at a missing
file: a good illustration that a structural gate checks paths, not behaviour.
It now returns hits in `backend/cli.py`, `scripts/attack_coverage.py` and three
test modules, and the gate that would have caught the original state is
`scripts/attack_coverage.py --check`, which fails on a mapping that reaches
nothing.

`README.md` claims "`threat/` MITRE ATT&CK technique mapping". ~~This is a
one-line path fix plus wiring~~ — it was a path fix, an authored mapping, a join
module and a new report key, and §22.4's threat appendix is now real:
failed findings mapped to T1602.001 (weak/default SNMP community), T1602.002
(config-dump exposure), T1556.004 (missing device-auth MFA), T1040 (cleartext
management), T1601.001/.002 (image integrity), with mitigations M1026/M1030/
M1031/M1032/M1037/M1041/M1046/M1051/M1054 — **except that the mitigations are
read from the bundle's `mitigates` relationships rather than from this list, and
five of the pairings this list implies are not ones the publisher makes.** See
the closeout at the top of this section.

The P12 gate is the constraint to respect: enrichment must **never** mutate
`Finding.result`, and with the flag off the audit output must be byte-identical.

> **Both held, and the second one shaped the whole design.** The appendix is a
> sibling key in the report envelope rather than a field on `Finding`, so the
> Merkle root, the record hash and the signature are the same bytes either way —
> asserted in `tests/test_threat_appendix.py`, not claimed here. `Finding` stays
> `extra="forbid"` and the ledger needs no reseed.

### 3.4 ~~No NIST 800-53 baseline scoping — a framing fix, not a feature~~ — **the premise was wrong; what could be built, was — 2026-09-11**

`grep -rln "moderate\|MODERATE\|baseline" backend/frameworks/ backend/rules/
--include=*.py` returns nothing.

`MASTER_PROMPT.md` §10.1 names the baselines from the OSCAL catalog already on
disk: **LOW 149 / MODERATE 287 (default audit scope) / HIGH 370** out of 1,196
controls. Because no baseline filter exists, `README.md`'s honest figure —
"13.49% of all 3,366 loaded controls" — is measured against every catalog the
project can crosswalk, including 872 enhancements and platforms with no pattern
pack.

Publishing 13.49% is the right instinct with the wrong denominator. ~~Scoping the
default audit to the MODERATE baseline the spec already names costs almost
nothing, changes no verdict, and replaces a number that reads like failure with
one that reads like scope — without a word of dishonesty.~~ Keep the 13.49%
figure alongside it; `GAPS.md` §4 already gives the reader all three framings,
which is the correct pattern.

> **Closed 2026-09-11, and the struck sentence above is why this section is worth
> reading twice.** It is the most confident paragraph in this document and it is
> wrong on its central factual claim. Everything else in it survives.
>
> **"The OSCAL catalog already on disk" does not contain the baselines.** This
> was checked rather than assumed. `data/frameworks/oscal/sp80053.json` uses
> exactly ten `prop` names — `label`, `method`, `sort-id`,
> `implementation-level`, `alt-identifier`, `contributes-to-assurance`,
> `aggregates`, `status`, `alt-label`, `keywords`. None is a baseline or an
> impact level, and `implementation-level` is organization/system/mixed, which is
> a different axis entirely. The normalised catalog agrees:
> `data/frameworks/catalog/nist_800_53_rev5_5_2_0.json` has `impact == ''` and
> `profile is None` for **all 1,014** controls, and its 22 hits for "baseline"
> are `CM-02`-style *configuration baseline* prose. The allocation lives in
> **SP 800-53B**, a separate publication. So the cost was never "almost nothing";
> it was a download, and under R1.1 authoring 149/287/370 from memory instead was
> never available.
>
> **Also wrong: "1,196 controls".** That is the raw count of `sort-id` props in
> the OSCAL file, of which **182 carry a withdrawn `status`**. 1,196 − 182 =
> **1,014**, which is exactly what the normalised catalog holds and what PRAMAN
> emits per device. Quoting a denominator 18% larger than the corpus, in the
> section arguing for an honest denominator, is the kind of error this project's
> own rules exist to catch.
>
> **What shipped instead, in three parts.**
>
> *First, the measurement the section never took.* NIST and ISO are never
> evaluated directly — `backend/rules/projection.py` derives them from the CIS and
> DISA results — so "rules per control" is meaningless for them and nobody had
> asked the only question that is meaningful: how many governance controls does
> the crosswalk ever land a verdict on? `scripts/bench/bench_rule_latency.py` now
> publishes it as `governance_reach`: **43 of 1,014** NIST controls decided
> across the fixture corpus (4.24%), **21 of 121** ISO controls (17.36%), with
> the composition of each denominator beside it — the NIST 1,014 is **300 base
> controls and 714 enhancements**, the ISO 121 has no enhancements at all. That
> composition *is* derivable from the repository, and it is most of what makes
> 4.24% legible: a router audit is not failing to check `PS-03`.
>
> *Second, the scoping itself, built and inert.* `backend/frameworks/baseline.py`
> loads the allocation, normalises OSCAL's dotted ids to the published
> parenthesised form, and scopes a set of control ids to LOW/MODERATE/HIGH. With
> the artefact absent — which is the shipped state — `load_baselines()` returns
> `{}` and `scope_to_baseline()` returns `None`, **not** an empty set, so no
> caller can accidentally divide by an empty baseline or print an unscoped ratio
> under a MODERATE label. The metric writes the reason into the field where the
> number would have gone. Running `MANUAL_COMMANDS.md` **Step 16** drops the
> artefact in and the scoped figure appears with no code change.
>
> *Third, the id hazard that would have made this silently wrong.* OSCAL writes
> an enhancement as `ac-17.2`; PRAMAN's catalogs write `AC-17(02)`. The existing
> `normalise_control_id` only recognises the parenthesised spelling — fed the
> OSCAL form it does not fail, it matches the `ac-17` prefix and returns the
> **base control**. A baseline loaded through it would have claimed MODERATE
> selects `AC-17` when the publication selects `AC-17(2)`, inflating the scoped
> numerator in the direction that flatters the tool.
> `tests/test_framework_baseline.py` asserts both behaviours side by side so the
> two functions cannot quietly converge.
>
> **What is still open, and it is only the download.** The MODERATE-scoped
> percentage does not exist on this machine, because the three SP 800-53B
> profiles have never been fetched here. `docs/GAPS.md` records it; Step 16
> fetches it; the verification marker on §10.1's 149/287/370 stays in
> `MANUAL_COMMANDS.md` until the step is run, because those three numbers are the
> spec's expectation and not a measurement. Nothing in the audit path is affected
> either way — a baseline scopes a denominator, never a verdict.

### 3.5 No job queue — the scaling wall

~~`grep -rn "ProcessPoolExecutor\|job_id" backend/ --include=*.py` returns
nothing. The only pool in the codebase is a `ThreadPoolExecutor(max_workers=1)`
in `backend/report/sign.py:74`. `/ingest/bulk` is synchronous and returns no
`job_id`.~~

~~§9.2 and §9.3 specify the in-process job queue plus `ProcessPoolExecutor`, and
explain why: the parse work is CPU-bound and GIL-holding, and on Windows the
spawn start method means workers must be top-level and picklable. Archive limits
are already 2,000 members and 512 MB expanded — a synchronous request cannot
carry that, so today the guard rails are wider than the engine.~~

**Done — the queue is in, the process pool is not, and measuring the second
question found a much larger defect than the one this section describes.**

The queue ships: `backend/jobs/queue.py`, with `POST /ingest/bulk?background=true`
returning `202` and a `job_id`, and `GET /jobs`, `GET /jobs/{id}` and
`POST /jobs/{id}/cancel` beside it. One worker thread, not a pool, because every
job here writes to the same SQLite file and WAL takes one writer at a time;
in-memory job state, because a job record is progress reporting while everything
a job *produces* is committed to SQLite as it goes; cooperative cancellation at
the item boundary, because that is the only place a partial write question has a
clean answer. `background` is opt-in so the existing synchronous response shape
is untouched for current callers. The archive walk moved to `backend/app/bulk.py`
so both modes provably share one definition of a valid archive —
`tests/test_job_queue.py` asserts they agree member for member.

**`ProcessPoolExecutor`: measured, and not adopted.** §9.2's rationale is
inherited from a parser stack PRAMAN does not use — `textfsm`/`ntc-templates`
were the assumption; these are our own YAML pattern packs — so it was worth
measuring rather than believing. The first measurement said a warm 4-worker pool
was *slower* than serial (0.82–1.08x across three runs on 16 logical CPUs), which
is not how CPU-bound work behaves, so the next step was a profile rather than a
conclusion. The profile found the real defect:

> **Every config parse opened seven SQLite connections — one per installed
> pattern pack — and ran the schema DDL on each, to answer seven questions about
> the same instant.** Detection scores an upload against every pack, and each
> `_learned_for(vendor)` call reconnected to re-read the learned-mapping
> freshness fingerprint. 53% of parse time, invisible to the test suite because
> every individual call was correct.

`LearnedPatterns.load_many()` now answers one sweep through one connection.
Measured on the 20-fixture corpus, 100 parses: **156 ms → 22.5 ms per config, a
6.9x speedup**, and the projected time to parse a full 2,000-member archive falls
from 311 s to 45 s. The cache semantics are unchanged — the fingerprint is still
read once per sweep, so a mapping taught a moment ago is still in force on the
next parse, which `tests/test_mapping_store.py` pins.

With the contention gone the pool does show a genuine 2.45x on parsing alone, and
it is still not worth taking: 45 s of parsing now sits comfortably inside a
background job, the remaining per-device cost is the SQLite write path that a
pool cannot parallelise anyway, and a pool would add process spawn (~2.3 s),
picklability constraints on the parse path, and a second concurrency model to
reason about. The queue solved the problem this section actually names — an HTTP
request that cannot be held open — and the pool would optimise the half that is
no longer the bottleneck. Recorded as a decision, not an omission, in
`docs/GAPS.md` §6.

### 3.6 Deliverable gates, and an accurate accounting of what is missing

~~Absent: `scripts/collect_unverified.py`, `scripts/check_deliverable_limits.py`~~
— **both done.** `collect_unverified.py` publishes the register into
`docs/GAPS.md` §7 between generated sentinels and into
`reports/metrics/unverified.json`; `check_deliverable_limits.py` counts the
slides, the speaking script's own arithmetic, and the rendered architecture
PDF's page count. `tests/test_unverified_register.py` and
`tests/test_deliverable_limits.py`
run both on every test run, so either going stale fails the suite exactly as a
stale benchmark does.

`scripts/validate_palette.py` is *not* missing so much as differently located:
the check it specifies is `tests/test_frontend_palette.py`, which asserts
`frontend/js/palette.js` against `backend/report/palette.py` value for value. A
separate script would be a second implementation of one assertion, and the one
that already exists is the one that runs. Recorded here rather than left looking
like an omission.

~~Genuinely absent: there are no PDFs in `docs/`~~ — **`docs/ARCHITECTURE.pdf`
is built, committed and gated two independent ways; `docs/PRESENTATION.pdf`
cannot be scripted, and that is a finding rather than a delay.** §29 asks for
both. They are not the same kind of artefact and the difference is what took a
while to see.

`scripts/build_architecture_pdf.py` renders `docs/ARCHITECTURE.md` to
`docs/ARCHITECTURE.pdf` at exactly two pages, and the paragraph above this one
was the reason to write it: the page-count gate *passed vacuously* because
predicting pages from Markdown needs a words-per-page constant, and an invented
constant (R1.1) makes a gate fail for reasons nobody caused. The honest fix was
never a better estimate — it was producing the rendered document the limit is
actually about. So `check_architecture()` now opens the PDF with `pypdfium2` and
counts, and **absence of the file is itself the violation**: R10.3 lists it as a
deliverable, and "not built" was never a pass.

Three decisions inside that renderer are worth recording, because each one is a
gate that could have passed for the wrong reason:

- **The Markdown subset is deliberately small and raises on anything else.** A
  renderer that skips a construct it does not recognise ships a two-page PDF
  that is short a section — and the page-count gate waves it through. Refusing
  to render is the only outcome that cannot hide a missing paragraph.
- **Body type is fixed at 9.6 pt and only the monospace size is derived.**
  Deriving the body size from the page target would make "exactly two pages"
  trivially true: the document could triple in length and still fit, at four
  point type. The mono size is derived because it is a *fit* constraint — the
  80-column pipeline diagram must not wrap — and Courier's advance is a known
  constant, not an invented one.
- **Only the 14 standard PDF fonts are used, so glyph coverage is finite.**
  WinAnsi is cp1252, so the codec is the authority on what is renderable, and
  the box-drawing characters and the tau are transliterated to ASCII. Embedding
  a TrueType font with box-drawing coverage would make the build depend on a
  font that happens to be on this machine — the PDF would render differently,
  or not at all, for whoever clones the repository.

Two tests hold it, and they fail for distinguishable reasons on purpose.
`test_the_architecture_pdf_is_exactly_two_pages` counts pages;
`test_the_architecture_pdf_still_matches_the_markdown` re-renders and diffs
**extracted text**, never bytes, because a PDF embeds its creation timestamp and
no two runs are byte-identical. The second one exists because a committed binary
is the one artefact in this repository that can go stale in silence: rewrite
`ARCHITECTURE.md`, leave the PDF alone, and the page count still says two.

`docs/PRESENTATION.pdf` is the opposite case and **stays a human step.**
`docs/PRESENTATION.md`'s own header is an instruction to a person: *"Paste into
`SIT_SIH2026-IDEA-Presentation-Format.pptx`, keep the template's images and
footers, delete slide 7, export as PDF. Six slides including the title, per the
template's own instruction slide."* A script that generated a deck from that
Markdown would produce a competent PDF that is **not the required SIH template**
— wrong images, wrong footers, wrong slide furniture — which is a worse outcome
than not having one, because it looks finished. So the slide *count* is gated by
`check_presentation()` against the Markdown, where the count actually lives, and
the export is recorded as **Step 15 in `MANUAL_COMMANDS.md`**, with the same six
fields every other operator step carries. The remaining R10.3 item is the demo
video (max 2 minutes), which is also not a thing code can produce and is in that
same step; `docs/SCRIPT.md` carries the words and `check_script()` re-derives the
duration from the document's own word count so the two-minute claim keeps
following from the script underneath it.

~~**The marker debt itself is nearly zero**, which changes the priority.~~
**This paragraph was wrong, and it is the best argument in this document for
having written the script.** It claimed **0 / 0 / 2** — R1.5's three markers in
the order R1.5 lists them — across the whole tree, with enough confidence to
downgrade the work to "worth writing to keep the count at zero". The machine run
over the same tree finds **15 disclosures: 10 / 2 / 3**. Two of them nobody had
seen: a resolved ambiguity recorded in the NX-OS pattern pack about a non-timer
applet trigger, and another in the DISA NX-OS mapping pack about the weak-cipher
list. Those two are the entire `ASSUMPTION` column.

*(This paragraph deliberately does not spell the three markers out, and the first
draft of it did. That draft pushed the register from 15 to 22 — the sentence
reporting the count was seven of the rows it was counting, so it could not state
a number without falsifying it. Which is the same failure as the hand count,
arrived at more inventively. `docs/GAPS.md` §7 has the identical constraint and
solves it by generating its rationale inside the blanked block.)*

The hand count was not sloppy so much as *shaped*: it walked `backend/`,
`frontend/`, `scripts/`, `tests/`, `docs/` and `README.md`, and skipped the
pattern packs and the mapping packs — which is precisely where an author leaves a
note to self, because that is where ambiguous publisher text gets resolved. A
count is only worth its confidence if the thing producing it is not the thing
that believes it.

The one prediction that held: the script *did* have to be taught about the
`extract.py` sentinel, which writes the marker as a *value* when a CIS section
number is unreadable in the PDF text layer. It is one named entry in the script's
`ALLOWLIST` with its reason attached, and a test fails if that entry ever stops
authorising anything — a stale allowlist entry reads as a live exemption, and is
how an allowlist becomes a place to hide a real marker.

Zero of the 15 are blocking. That is the number §236 actually cares about, and it
is now asserted rather than asserted-about.

**On the other §28/§32 test names — a correction worth making explicitly.** A
filename check suggests eighteen prescribed tests are missing. Grepping for the
*assertions* instead shows most exist under different names: determinism and
byte-comparison in `test_ledger_chain.py` and `test_canonical_schema.py`, the
decoupling boundary in `test_rules_eval.py`, encoding and BOM handling in
`test_config_decoding.py`, zero-rule-change and zero-parser-change in
`test_rules_mapping.py`, cold-start and artifact-missing in
`test_cold_start.py`, the palette in `test_frontend_palette.py`. All four
acceptance tests named in §2 exist (`test_bulk_ingest.py`,
`test_multiframework.py`, `test_pdf_report.py`, `test_training_hot_reload.py`).
~~The genuinely missing gates are the three scripts above plus
`test_manual_commands_contract.py` (§1.3) and `test_threat_enrichment.py`
(§3.3).~~ **The last two of those were also a filename check reaching the wrong
conclusion — both files exist and both run.** Which leaves nothing in §28/§32
missing: the three scripts are written, and every prescribed assertion has a
home. The lesson is the same one §3.6 keeps re-teaching in different costumes —
a claim about the tree, made by reading the tree the way you expect it to be
arranged, is not evidence about the tree.

### 3.7 Other specified-and-unbuilt items

Checked by grepping for the import, since each has a declared dependency:

| Specified | Dependency | State |
|---|---|---|
| CEL rule DSL | `cel-python` 0.5.0 | `celpy` imported nowhere; conditions are the hand-rolled evaluator |
| Remediation delta from running vs intended config | `hier-config` 3.7.0 | Imported nowhere; remediation is extraction-only (which ADR 0005 defends) |
| Conformal prediction on the AI tiers | `crepes` / `mapie` | Imported nowhere |
| Active-learning ordering of the training queue | `small_text` | Imported nowhere |
| CVSS v4 / KEV / EPSS | `cvss` 3.6 | Imported nowhere |
| Topology violation map | `networkx` | Imported nowhere |

None of these is a defect — they are unstarted scope. They are listed so the
declared dependency set and the built feature set can be reconciled rather than
drifting.

### 3.8 ~~The AI tier is ahead of its documentation~~ — **caught up 2026-09-10**

Since the last commit, tier 2 and tier 3 were both actually trained — the
untracked metrics files prove it:

- **`reports/metrics/setfit.json`** — SetFit over
  `sentence-transformers/all-MiniLM-L6-v2`, 1,936 samples, held-out **devices**
  (`CHIC-re0`, `LOSA-re0`, `WASH-re0`), 33.5 minutes of training, accuracy 1.00
  and macro-F1 1.00. The file ships its own caveat, and it is the right one:
  94.1% of the 493 holdout lines are `interface.admin_state`, and only 7 of 14
  trained classes appear in the holdout at all. So 1.00 measures one easy class,
  not per-class capability. Two classes fall below the minimum support of 8.
- **`reports/metrics/qlora.json`** — QLoRA 4-bit NF4 over
  `Qwen/Qwen3-4B-Instruct-2507`, rank 16, 11,796,480 trainable parameters
  (0.2924% of 4,034,264,576).

`README.md`'s AI section still reads "shipped default: tier 1 only". That stays
*true* for a fresh clone, because `data/models/classifier/` is gitignored — but
the README should say tiers 2 and 3 have been trained and measured, and should
carry the SetFit caveat verbatim. Quoting 1.00 accuracy without it would be
exactly the failure `README.md` already avoids for tier 1, where it publishes
the 0.814 majority-class baseline beside the 0.959.

> **Closed 2026-09-10.** `README.md` now carries both runs in a two-column table
> under the tier-1 discussion, and the SetFit caveat is quoted **verbatim from
> the file** rather than paraphrased — a paraphrase of a caveat is a place for
> the caveat to soften. "Shipped default: tier 1 only" survives unchanged and is
> now explained rather than merely accurate: it is a statement about a fresh
> clone, where `data/models/classifier/` and `data/models/lora/` are both
> gitignored, not a statement about what has been built.
>
> Three things were added that the roadmap entry above did not ask for, because
> writing the section made them necessary. **First**, the per-class supports:
> five of the seven measured classes are decided on three to six holdout lines
> each, so the caveat's "should not be read as a per-class capability figure" is
> shown rather than asserted — a reader who sees 464 `interface.admin_state`
> lines and 29 of everything else does not need to be told what 1.00 means.
> **Second**, why the split is grouped by *device*: two lines from the same
> router are near-duplicates, so a line-wise split puts one config's text on both
> sides of the boundary and measures memorisation. §247 forbids splitting
> train/test by line, and the reason belongs next to the number it protects.
> **Third**, an explicit restatement that no tier is in the verdict path, with
> the pointer to ADR 0003. A section that publishes a 1.00 needs that sentence
> adjacent to it, not two screens away, because 1.00 is exactly the figure a
> skimming reader would over-trust.
>
> The QLoRA row is deliberately loss-only. `qlora.json` records `train_loss`
> 0.4993 and `eval_loss` 0.2487 and **no accuracy**, so none is quoted; eval loss
> below train loss is worth one line of a table and is not a capability claim.
> Its 16.4-minute runtime on the 6 GB RTX 4050 is the figure that actually
> matters for this project, and it is the one the slides already use.

---

## 4. Competitor analysis

**Sourcing note.** `WebSearch` is unavailable in this environment, and the
project's own research logs record the same failure, along with bot-walled
search engines and a set of vendor pages returning 403/404. What follows comes
from the repository's dated research corpus (`.research/synth/`,
`.research/competing-tools.raw.md`), each fact carrying the SRC URL that corpus
recorded, cross-checked with `WebFetch` where the page still resolves. Where a
page did not state something, that is reported as "not stated on the pages
reviewed" rather than filled in. No price, tier or capability below is inferred.

### 4.1 The closest competitor: Titania Nipper / Nipper InfraSight

The most direct comparison in the market, because it works the same way PRAMAN
does — from exported configuration files, "no credentialed access and no changes
to live devices", producing "point-in-time evidence you can act on".

What their pages state:

| Dimension | Nipper InfraSight |
|---|---|
| Vendors | Cisco, HPE Aruba, Check Point, Palo Alto, Dell, Juniper, Sophos, Huawei, Fortinet, F5; partnerships help it "assess more than 180 devices" |
| Frameworks | NIST SP 800-53, NIST SP 800-171, PCI DSS 4.0, CMMC, "CIS Benchmarks where supported"; the wider site adds CORA, DISA STIGs, NCSC CAF, NERC CIP |
| Tiers | Essentials, Compliance, Air Gapped — and **"Compliance assessment reporting depends on tier"** |
| Licensing | Device-capacity based: "up to the number of devices agreed in your license i.e. up to 500 devices", single or multi-year, usage resets every 12 months, not user-limited. **No prices published anywhere**, including on the try-and-buy page |
| Output | ASCII Text, HTML, JSON, LaTeX, XML, plus table exports to CSV / Excel / JSON / SQL / XML. Their own docs say "PDF and LaTeX do not appear anywhere in this content, so I can't confirm whether they're supported" |
| STIG reporting | CAT I/II/III with optional CCI and Rule ID columns, heatmaps, HTML by default |
| Unauditable devices | "Report Devices that could not be audited will return a CAT I finding requiring investigation" |
| AI / ML | **No AI, ML, NLP or learning component is mentioned anywhere on the page** |
| Continuous monitoring | Nipper OmniSight has Standalone / Integrated (CMDB, SIEM) / **Continuous** (drift detection, automated discovery) tiers. No prices |

Three of those rows are strategic openings.

**Compliance reporting is tier-gated.** Control-aligned reports come only with
the Compliance and Air Gapped tiers, and if the DISA STIG checkbox is missing
"your active license does not support the STIG compliance feature". PRAMAN's
multi-framework engine is the base product. That is a pitch line, sourced from
their own documentation rather than asserted.

**No learning component.** Nipper is marketed as deterministic with "fewer false
positives" — a deliberate positioning, not an oversight. But it means the
"unrecognised syntax gets taught to the tool by an operator, with no redeploy"
capability is unoccupied ground on the pages reviewed.

**Their handling of unauditable devices is genuinely good, and validates
PRAMAN's design.** Returning a device that could not be audited as a CAT I
finding requiring investigation is the same instinct as PRAMAN's tri-state.
`GLOBAL_RULESET.md` §30 already cites this as the reason `unknown` must never
render as `pass`, and rates "an unparseable config renders as 0 findings"
**Critical** in the risk register. Worth knowing the market leader agrees: the
design is defensible, not merely principled.

### 4.2 Batfish — the strongest open-source tool, and the clearest contrast

Apache-2.0, Java, 1,457 stars / 286 forks / 280 open issues; `batfish`
v2025.07.07, `pybatfish` v2026.08.19. Vendor support is broad: A10, Arista, AWS
constructs, Check Point, Cisco (ASA, IOS, IOS-XE, IOS-XR, NX-OS), Cumulus, F5
BIG-IP, Fortinet, FRR, iptables, all Junos, Palo Alto, SONiC; partial Aruba,
Dell Force10, Foundry.

Two facts from their own documentation define the contrast:

1. **No compliance-framework mapping at all** — "nothing on this page maps
   findings to any regulatory or benchmark framework."
2. **It surfaces unrecognised configuration lines and gives no way for a human
   to map them.** `bf.q.initIssues()` returns "failure to recognize certain
   lines in the configuration, lack of support for certain features, and errors
   when converting to vendor-independent models" with columns Nodes,
   Source_Lines, Type, Details, Line_Text, Parser_Context;
   `bf.q.parseWarning()` returns Filename, Line, Text, Parser_Context, Comment.
   Reporting the gap is where it stops.

That second one is PRAMAN's C2 in negative. The strongest technical tool in this
space has the same problem PRAMAN has, reports it as well as PRAMAN does, and
has no closing move.

Two more facts that matter here. **Batfish is Docker-only**, and Docker is not
installed on the target machine (`GLOBAL_RULESET.md` §4) — which is why only its
Apache-2.0 testconfig corpus is harvested for fixtures, never the engine. And
Batfish needs `layer1_topology.json` and `runtime_data.json` supplied alongside
the configs because "All relevant information, however, may not be present in
the configuration files" — the same evidence limit `GAPS.md` §5 documents for
PRAMAN, arrived at independently by the best tool in the field.

### 4.3 The rest of the field

| Tool | What its pages show | What the review did not find |
|---|---|---|
| **CIS-CAT Pro Assessor** | Automates CIS Benchmark assessment; maps results to CIS Controls; prioritisation by the three Implementation Groups; Tailored Benchmarks authored in CIS WorkBench; Java 21 backend; free CIS-CAT Lite tier with unlimited scans of select benchmarks and a compliance score | No multi-framework mapping beyond CIS Controls; no output formats, report section names or CLI flags stated; no learning component |
| **Netpicker** | Published pricing — **$7,500/yr and $33,500/yr** — the only firm commercial anchor found anywhere in this review | — |
| **Tenable Nessus** | Compliance audit files for network devices | `docs.tenable.com` ComplianceChecks page 404 at capture; `tenable.com/downloads/…audit` 404. Nothing citable about network-device compliance specifics |
| **hier_config** | MIT, 3.7.0; computes a remediation delta between running and intended config. PRAMAN's own spec depends on it (§16) | Not an auditor: no frameworks, no findings, no reporting |
| **Nautobot Golden Config** | Intended-config generation and compliance-by-diff against a golden template | Framework mapping is not the model — compliance means "matches intent", not "satisfies CIS 1.2.4" |
| **Check Point Compliance Blade** | Vendor-native compliance for Check Point estates | Single-vendor by construction |
| **netlint** | Config linting | **GPL-3.0** — `GLOBAL_RULESET.md` §30 forbids lifting its check definitions. Reference only |

### 4.4 A research finding that matters more than any single competitor

The corpus records that **no best-in-class security-audit report structure could
be obtained from any source**. Every candidate failed at capture:
pentest-standard.org PTES Reporting (403/404 plus archive failure), stigviewer
Cisco IOS Router NDM (403/404), Tenable Nessus report docs (403), Qualys PC docs
(404), NIST IR 7275r4 XCCDF spec (404/blocked), the OSCAL assessment-results
model page (404), CIS-CAT Pro Assessor v4 docs (marketing only), Nipper report
anatomy (marketing only — "no section names, no report-type list, no
finding-field template"), TCM sample pentest report (README only), OSCP template
(404).

What survived: **OpenSCAP's four rule labels and the XCCDF nine result values.**

That is a strong result for PRAMAN, not a dead end. It means the nine-value
XCCDF enum is not one option among many — it is the only publicly documented,
standards-backed vocabulary available for this job. Freezing `Finding.result` to
it, as `MASTER_PROMPT.md` §7 does and `backend/canonical/findings.py:19`
implements, is the defensible choice rather than a stylistic one. It is also
worth saying in the pitch: PRAMAN reports in the same vocabulary an OpenSCAP or
XCCDF consumer already speaks, and **no competitor page reviewed states its
result vocabulary at all.**

### 4.5 Where PRAMAN already wins

Each checked against the repository, not aspirational:

1. **Multi-framework mapping in the base product.** Nipper tier-gates it,
   CIS-CAT is CIS-only, Batfish has none.
2. **Admin-in-the-loop learning with no redeploy.** `POST /training/map` →
   mapping store → hot reload, asserted by
   `tests/acceptance/test_training_hot_reload.py`. Batfish reports unparsed
   lines and stops; Nipper mentions no AI at all.
3. **Third-party-verifiable evidence.** `backend/ledger/verify.py` imports
   nothing from `backend/`, and `tests/test_ledger_standalone_verify.py` asserts
   both sides agree. Its docstring records a real past drift — it hashed every
   column while the writer hashed an explicit eight-field list, and it omitted
   the Merkle link — and it now reports four links, returning `None` rather than
   `True` for a link it did not check, and exit code 2 for "we did not look".
   That is `GLOBAL_RULESET.md` R1.7 implemented in code. **No competitor
   reviewed offers anything an auditor could run without trusting the vendor.**
4. **Zero infrastructure.** `python scripts/serve.py` is the whole deployment.
   Batfish needs Docker; CIS-CAT needs a JRE; PRAMAN needs Python and nothing
   else, and `tests/test_cold_start.py` asserts a fresh clone with zero models
   is a supported configuration rather than a degraded one.
5. **Published coverage gaps.** `docs/GAPS.md` argues all 22 unautomated
   controls individually, names the two canonical paths with unreconciled unit
   contracts, and states that CIS severities are a project judgement because CIS
   publishes none. Nobody else does this. It is the single most credible thing
   in the repository in front of a technical assessor.

### 4.6 Where PRAMAN is behind — and what to do about each

| Gap | Competitor that has it | Recommendation |
|---|---|---|
| **Vendor breadth**: 7 pattern packs | Nipper ~180 devices; Batfish 15+ families | The gap a buyer notices first. Do not chase the count — lead with "a vendor is a YAML file" and demonstrate it live (demo beat 6). Then take the free coverage: `cisco_xe` (§2.2) and the two enum-blocked STIG platforms |
| **No live device collection** | Nipper "Remote Device" / "Remote List" | Deliberate: `napalm` is pinned optional and live-only, never on `/ingest`, and offline operation is the architecture. Keep it as a stance, but *say so* — otherwise it reads as an omission |
| **No drift / golden-config diff** | Nautobot Golden Config; Nipper OmniSight "Continuous" | Highest-value product gap after §2.1. The ledger already chains records by `seq`, and §23.2 specifies a trend chart that walks it. Drift-versus-previous-audit is reachable today; drift-versus-intended needs `hier_config`, which is pinned and unimported |
| **No CVE / KEV / EPSS correlation; no EOL/EOS report** | Most commercial scanners | `GAPS.md` §2.3 declines EOL (DISA V-220137) as an offline scope boundary, and the reasoning is sound: a stale offline table produces a false pass on the one control whose purpose is currency. The compromise that keeps the principle — a **dated, vendored snapshot** with the snapshot date printed on every finding it touches, so it cannot rot silently |
| **No waiver / deviation workflow** | Every enterprise GRC tool; Nipper's false-positive exclusion | Real audits need "accepted risk, expires 2027-03-01, approved by X". The vocabulary is already frozen in §13: OSCAL `risk-status` ∈ `open \| investigating \| remediating \| deviation-requested \| deviation-approved \| closed`. Implement against that enum and the export in §3.1 comes out correct for free. **Depends on §1.1** — a waiver without an approver identity is not a waiver |
| **No ticketing / SIEM / CMDB integration** | Nipper OmniSight "Integrated" tier | SARIF (§3.1) covers the code-scanning and CI surface; OSCAL AR covers GRC. Both beat a bespoke webhook |
| **No scheduling / continuous monitoring** | Nipper OmniSight "Continuous" | Needs the job queue (§3.5) first |
| **No segmentation / reachability analysis** | Batfish's core strength | Do not compete here — it needs a full topology and forwarding model. Scope the topology work to *violation visualisation* with click-to-config-line (demo beat 4), a UX differentiator rather than a reimplementation |
| **PAN-OS has no remediation CLI** | — | Already in the risk register: render ordered GUI steps plus `manual_verification` rather than an empty block |

---

## 5. Uniqueness plays, ranked by defensibility per unit of work

### 5.1 Lead with third-party-verifiable evidence

The strongest asset is already ~80% built and nobody reviewed has it. Package
`backend/ledger/verify.py` as a distributable single-file verifier with a
published verification procedure, so an auditor who does not trust the vendor
can check a report themselves. The positioning is "our evidence does not require
trusting our code", which no competitor page reviewed makes any claim about.

Blocked on §1.1: verifiable evidence without an actor is verifiable evidence of
an anonymous assertion. Ship the two together.

### 5.2 OSCAL Assessment Results export — the enterprise wedge

> **Resolved 2026-09-09.** `GET /devices/{id}/oscal.json?audit_id=` — gated at
> `viewer`, served from a **committed ledger record** and `409` when there is
> none, naming `POST /audit/commit`. That refusal is the design: the document
> carries `praman-record-hash`, `praman-merkle-root`, `praman-signature`,
> `praman-ledger-seq` and `praman-actor` in `metadata.props`, so a GRC platform
> holds everything it needs to hand those values back to PRAMAN's standalone
> verifier. A document exported from a *simulation* would carry none of that and
> would be indistinguishable from one that could be checked, which is why the
> route does not fall back to one.
>
> Findings are projected through `finding_from_row` — the same function the ledger
> verifier uses — so the exported verdicts are byte-for-byte the ones the
> committed Merkle root was computed over. Every id in the document is a
> version-5 UUID over the record hash, so re-exporting one audit is byte-identical
> forever and a platform that ingests it twice sees one assessment, not two.
> Measured on the shipped fixtures: 8 `results` (one per framework/benchmark
> pair), 1,462 observations, 133–151 finding elements, 2–151 risks.

A GRC platform can ingest PRAMAN output directly. Not stated on the Nipper,
CIS-CAT or Batfish pages reviewed. The spec is complete in §13 with all enums
frozen and the XCCDF→AR mapping written for all nine result values. Use stdlib
`json`; do not add `compliance-trestle` (it hard-pins `jinja2==3.1.6`).

This is also the artifact §29.3 names against the official SIH criterion
"potential for future work progression" — so it serves the submission and the
product with one piece of work.

### 5.3 SARIF v2.1.0 on `/simulate` — shift the whole product left

> **Resolved 2026-09-09.** `POST /simulate/sarif` — same body as `/simulate`,
> same `auditor` gate, same pipeline, and it requires **no** committed audit,
> because a CI gate runs before anything is committed. Results anchor to
> `source_file:line_start-line_end`, so a code-scanning dashboard annotates the
> offending configuration line in the merge request. Demo beat 1 is now literally
> true.
>
> **The log carries no timestamps at all** — no `invocations`, no `columnKind` —
> which the schema permits and which keeps the output a pure function of the
> config bytes. That preserves `/simulate`'s documented idempotence and means a
> committed `.sarif` diffs to show only what actually changed; a single
> `datetime.now()` would still be valid SARIF and would silently destroy it, so
> `tests/test_api_export.py` asserts byte-equality over the wire rather than only
> over the dict.
>
> Two judgement calls worth naming. `notchecked`, `notselected` and
> `notapplicable` are **omitted** from `results` and published as arithmetic
> instead (`pramanResultCounts` sums to `pramanFindingsTotal`;
> `len(results) + pramanResultsOmittedTotal` equals it too) — 1,311 of 1,462 on a
> hardened config, which would drown a PR annotator. And remediation goes in
> `rules[].help`, never `result.fixes`: `remediation/playbook.py` falls back to
> `cisco_ios` for unrecognised vendors, so a `fixes` block would have offered
> Cisco syntax as *the* fix for a FortiGate. `_help_text` holds back the
> playbook's `verification` and `rollback` strings along with the commands for the
> same reason — a test caught them leaking `no ip ssh version 2` beside a "no
> commands for your vendor" line.
>
> `toolComponent.informationUri`, `organization` and `reportingDescriptor.helpUri`
> are omitted rather than guessed: PRAMAN publishes no URL, and a fabricated
> benchmark link would 404 on the air-gapped machine this tool is built for.

`/simulate` is already stateless, idempotent and side-effect-free. Emitting
SARIF turns it into a pre-deployment linter that drops into any CI or
code-scanning dashboard with no integration work. It makes demo beat 1 literally
true — "today a config is deployed, then fails an audit weeks later" becomes
"the merge request fails, before the deploy".

No competitor reviewed publishes SARIF. Field names are still `TODO(verify)` in
§13.3 and must be confirmed against the schema before shipping.

### 5.4 Keep the live unseen-vendor demo as the centrepiece

Demo beat 6 (24 s: "This vendor was never in our training set. We taught it
live, with no code push.") is `tests/test_cold_start.py` performed live rather
than a demo trick. Given §4.2 — Batfish surfaces unrecognised lines and offers
no mapping path, Nipper mentions no learning at all — this is the capability
with the clearest evidence of being unoccupied. It is also already built.

### 5.5 Offline threat enrichment — one path fix from working

The 53.8 MB ATT&CK bundle is on disk. Fixing the path in §3.3 and wiring the
module makes §22.4's threat appendix real. For an NTRO audience specifically,
the corpus already identifies campaign **C0043 "Indian Critical Infrastructure
Intrusions"** and group **G1045 Salt Typhoon** — a narrative that connects a
misconfigured SNMP community on a router to a documented adversary's technique.

Constraint from the P12 gate: enrichment never mutates `Finding.result`, and
with the flag off the output is byte-identical. Enrichment is context, not
verdict.

### 5.6 An India-specific framework pack

Verified reachable: `nccs.gov.in` (200), `cert-in.org.in` (200),
`trustedtelecom.gov.in` (200). `nccs.gov.in/itsar` returns **401**, so ITSAR
content acquisition is a human step and becomes a new numbered entry appended to
`MANUAL_COMMANDS.md`.

A CERT-In or NCCS ITSAR mapping pack is a framework no tool in the reviewed set
ships, it is directly relevant to the sponsoring organisation, and — because a
framework is a mapping pack — it is authoring work against catalogs, not engine
work. The 401 is the real risk: without acquirable control text this stays a
plan, so verify acquisition before it appears in any deliverable.

### 5.7 Topology violation map — real, but scope it honestly

Demo beat 4 (click a red node, land on `source_file:line_start-line_end`) is a
genuine UX differentiator. `networkx` is declared and imported nowhere, so this
is unstarted. Scope it as violation *visualisation*. Reachability analysis is
Batfish's ground and needs a forwarding model.

---

## 6. Sequencing

Four phases. The ordering constraint that matters: §1.1 (identity in the ledger)
must precede the waiver workflow, the read-audit log and the OSCAL export,
because all three need an actor — and it must land together with §3.2
(migrations), because the hash-definition change forces `MANUAL_COMMANDS.md`
Step 12.

**Phase 0 — deployability.** Auth + authorisation + `actor` in `AuditRecord` +
the first migration, as one change. Then the hours-not-days items: untrack
`praman/data/praman.db`, gitignore and delete `praman/checkpoints/`, write
`MANUAL_COMMANDS.md` Step 8c and `tests/test_manual_commands_contract.py`, fix
the ATT&CK path. Ship a reverse-proxy TLS configuration and a read-audit log.

**Phase 1 — make the headline claim true fleet-wide.** The four DISA NDM packs
(§2.1), the IOS XE port (§2.2), both-direction fixture pairs per vendor (§2.3).
This is what moves "4 frameworks, 7 vendors" from true-of-two-vendors to
true-of-the-fleet, and it is authoring work against catalogs already on disk.

**Phase 2 — enterprise integration.** `backend/export/`: OSCAL Assessment
Results, then SARIF v2.1.0 on `/simulate`. NIST 800-53 MODERATE baseline scoping
(§3.4). Wire the threat enrichment behind its flag. Reconcile the three hollow
`README.md` Layout claims with reality as each lands.

**Phase 3 — product surface.** Waiver/deviation workflow against the OSCAL
`risk-status` enum. Drift-versus-previous-audit off the ledger `seq`. Dated
CVE/KEV/EPSS snapshots with the snapshot date on every finding. The
`cross_reference` condition type and the remaining vocabulary fixes in §2.4 —
the `aaa.login_block` normalisation has already landed, and it is the template
for the rest: measure the affected verdicts on every fixture, change the unit at
the pattern layer, re-measure, and only then rewrite the rules that read it.

**Phase 4 — scale.** In-process job queue plus `ProcessPoolExecutor` (§3.5),
rate limiting, multi-tenancy. Deferred on purpose: nothing here matters until
Phases 0–2 exist, and the archive guards are already wider than the engine, so
this is where the ceiling actually is rather than where it is felt first.

Cross-cutting and cheap: ~~delete the four superseded seed rule packs, decide
`mgmt.local_user.secret_type`~~ (both done — §2.5), ~~write
`scripts/collect_unverified.py` (taught about the `extract.py` sentinel) and
`scripts/check_deliverable_limits.py`~~ (both done — §3.6). What those two turned
up is now the cross-cutting work: file-length debt, ratcheted so it cannot grow.
It stood at **7,778 lines across 29 files** when the ratchet was first enforced;
five splits later it is **7,208 across 28** (§2.5 carries the chain), with
`backend/app/main.py` at 1,912 lines still the obvious next one.

**Any heavy step this roadmap implies** — re-training after a vocabulary change,
acquiring ITSAR content, downloading a KEV/EPSS snapshot — goes into
`MANUAL_COMMANDS.md` as a **new** numbered step at the end, with all six fields,
never renumbering the existing ones (`GLOBAL_RULESET.md` R1.4, R2.2).

---

## 7. What was not verified

Stated so this document does not overclaim, per `GLOBAL_RULESET.md` R1.7 — "the
tool found nothing" is not "the tool did not look".

- **Read in full:** `GLOBAL_RULESET.md`; `MASTER_PROMPT.md` via
  `.build/sections/_header.md` and `A.md`–`G.md` (byte-identical, 189,186 bytes
  each); `README.md`; `docs/ARCHITECTURE.md`; `docs/SECURITY.md`;
  `docs/GAPS.md`; `.research/competing-tools.raw.md`.
- **Sampled by targeted grep, not read end to end:** the seven
  `.research/synth/` files (~480 KB) and `MANUAL_COMMANDS.md` (step headings and
  the Step 8 sub-steps read; the other twelve steps not read line by line).
  Every synth fact quoted above was read in its own context with its SRC line.
- **Not read:** the twelve remaining `.research/*.raw.md` (~1 MB),
  `CivitTwin_to_PS155_Technical_Transfer.md`, the five ADRs,
  `docs/DEMO.md` / `PRESENTATION.md` / `SCRIPT.md` beyond a preview,
  `test_configs/README.md`, and the great majority of the ~15,800 backend and
  ~8,400 frontend lines. Structural claims about the backend come from targeted
  greps, reported above with the exact command.
- **Competitor pricing is almost entirely unpublished.** Netpicker's $7,500/yr
  and $33,500/yr are the only firm figures found. Titania publishes none,
  confirmed on their own try-and-buy page. Any other number would be invented.
- **`WebSearch` is unavailable in this environment** (`tool type
  'web_search_20250305' is not supported`), and several vendor pages returned
  403/404 at capture time. Competitor facts are as-of the research corpus's
  capture date, with SRC URLs, and should be re-checked before they appear in a
  deliverable.
- **Test evidence:** 1,152 progress marks <!-- as-measured --> from
  `pytest -q -m "not slow"`, exit 0, zero failures, as observed on 2026-09-07.
  That figure is a record of one run and is left alone on purpose; the current
  count is published in `README.md` and pinned by
  `tests/test_published_counts.py`. The slow
  `test_run_all_check_passes`, which re-runs every benchmark in a subprocess and
  diffs against `reports/metrics/*.json`, was **deselected** and not run.
- **Not attempted:** no model download, training run, or GPU work, per
  `GLOBAL_RULESET.md` R2.1. The SetFit and QLoRA figures in §3.8 are read from
  the metrics files the human's own training runs wrote.
