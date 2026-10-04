# The 2-minute demo, shot by shot

This demo is designed for **2 minutes**. That is roughly 300 spoken words,
which is not enough for a tour — so this is not a tour. It shows the four things
a reader cannot verify from the README alone, and skips everything they can.

**What is deliberately not shown:** the setup (it is two commands in the README),
the layout of the code, the ADRs, and eight of the ten views. A demo that pans
across screens spends its whole budget proving the screens exist.

**What is shown, and why each earns its seconds:** that an unseen format can be
taught through the GUI with no redeploy (C2, the capability most likely to be
faked); that four frameworks come out of one parse (C3); that the fix text is the
publisher's, not the model's (C4); and that the report can be re-verified after
the fact (the trust argument).

---

## Before recording

Run this once. It resets to a known state so the recording is reproducible and
nothing on screen is a leftover from a previous take.

```bash
.venv/Scripts/python.exe scripts/bench/run_all.py --check && .venv/Scripts/python.exe -m pytest -q
```

Then start the server and leave it running:

```bash
.venv/Scripts/python.exe scripts/serve.py
```

Open <http://127.0.0.1:8012> at **1440×900**. Larger and the text is unreadable
when the video is scaled down; smaller and the findings table wraps.

Have these ready in separate tabs or a scratch file, because typing them on
camera costs 15 seconds you do not have:

- `test_configs/realistic/telnet_exposed.conf`
- `test_configs/compliance_extremes/fully_hardened.conf`
- the line to teach: `ip pim sparse-mode` — real Cisco syntax, no pattern claims
  it, and it is short enough to type on camera in about three seconds

---

## Shot 1 — Ingest a real config · 0:00–0:25

**Do:** Drag `telnet_exposed.conf` onto the Upload view. Let the redirect land on
the device page.

**Say:** *"A router config goes in. PRAMAN detects the vendor from the content,
normalises it to a canonical fact model, and evaluates it against four
frameworks. No cloud, no API key — this is one Python process on a laptop."*

**On screen:** the device page, populated. Point at the compliance score and the
severity breakdown.

**Why this shot:** it establishes that the input is a real configuration file and
not a fixture in a special format, and that the output arrives in one step.

## Shot 2 — Four frameworks, one parse · 0:25–0:50

**Do:** Open the Findings view. Filter to `fail`. Switch the framework selector
from **CIS** to **DISA STIG**, then to **NIST 800-53**.

**Say:** *"Same facts, four frameworks. CIS and STIG are evaluated directly. NIST
and ISO are projected through the publishers' own crosswalks — DISA ships a CCI
to NIST mapping for every control — and projected verdicts are labelled as
projected, because a roll-up is weaker evidence than a measurement."*

**On screen:** the framework badge changing while the underlying device does not.
Land on one `notchecked` row so its reason string is visible.

**Why this shot:** C3 is the capability most easily faked by relabelling one
framework's output four times. The `notchecked` reason is the tell that it is
not doing that.

## Shot 3 — Teach it an unseen line · 0:50–1:25

This is the longest shot because it is the training capability most likely to be
claimed without being implemented.

**Do:**
1. Open the **Training** view. The queue holds the lines no pattern claimed.
2. Point out that the AI tier has **abstained** on these rather than guessing.
   Say the number: *"tier 1 can only emit 15 of 330 canonical paths, so on
   routing configuration it stays silent — that is by design, and it is
   measured."*
3. Type `ip pim sparse-mode`, map it to a canonical path from the dropdown, save.
4. **Without restarting anything**, re-upload the same config.
5. Show the line now parsed — it appears in the device's facts.

**Say:** *"The operator maps it once. The mapping becomes a deterministic pattern
in the library, hot-reloaded — no redeploy, no restart, and from here on the
answer comes from a pattern rather than a model. The AI's only job was to shorten
the operator's search through 330 paths, and when it cannot do that honestly it
says nothing."*

**Why this shot:** it demonstrates C2 end to end, and it demonstrates the
project's central claim about the AI — that it suggests and a human decides,
with the verdict path staying deterministic either way.

## Shot 4 — Publisher's fix, signed report · 1:25–1:50

**Do:** Open **Remediation**. Show a fix block. Then download the per-device PDF
and scroll to the remediation section.

**Say:** *"Every remediation command is extracted from the benchmark author's own
fix text — never generated. Where the publisher wrote prose instead of commands
it is marked manual, so a blank block is never presented as a fix."*

**On screen:** the `kind: cli` vs `kind: manual` distinction, then the PDF's
`X-PRAMAN-Record-Hash`.

**Why this shot:** an auditor acting on a hallucinated `no ip http server`
variant is the failure mode that makes a tool like this dangerous. This shot is
the answer to it.

## Shot 5 — Re-verify the ledger · 1:50–2:00

**Do:** Open **Ledger**. Hit verify. Show all-green.

**Say:** *"Every audit is hash-chained and Ed25519-signed. Verification re-reads
the rows from SQLite and re-checks four independent links per record, so the
report can be audited later without trusting the process that produced it."*

**Why this shot:** it closes on the property that makes the output evidence
rather than a screenshot, and it takes ten seconds.

---

## Timing discipline

| Shot | Ends at | Cut this first if over |
|---|---|---|
| 1 Ingest | 0:25 | the drag animation — start with the file already dropped |
| 2 Frameworks | 0:50 | the third framework switch; two proves the point |
| 3 Training | 1:25 | **nothing** — this is the shot that cannot be cut |
| 4 Remediation | 1:50 | the PDF scroll; the header hash alone carries it |
| 5 Ledger | 2:00 | the narration, not the green check |

If the recording overruns, cut shot 4's PDF scroll before touching shot 3.

## Two things to say and one to avoid

**Say the honest number.** *"71 of 90 CIS controls and 32 of 35 STIG NDM
controls are automated, and all 22 that are not are listed individually in
GAPS.md."* Volunteering the gap is more convincing in a 2-minute video than a
coverage claim a reviewer has no way to check.

**Say what the AI does not do.** *"The AI never decides a verdict."* That one
sentence pre-empts the obvious question about an "AI-powered" compliance tool.

**Do not say "accurate".** There is no hand-labelled ground truth for the
classifier in this repo, so no accuracy figure in the video would be defensible.
The measurable property is abstention, and it is measured — see
[`../README.md#measured-results`](../README.md#measured-results).
