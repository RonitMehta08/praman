# Test configurations

Device configurations shipped with PRAMAN so every feature can be exercised
without access to a real network. Nothing here is generated at test time: these
are the inputs the test suite, the benchmark scripts and the demo all run
against, so a change in behaviour shows up as a diff in a number you can see.

Every file is a **synthetic** configuration written for this project. No file
contains a credential, address or key from a real device. Where a fixture needs
to look insecure it uses well-known defaults (`cisco`, `public`, `private`) on
documentation-range addresses (RFC 5737 `203.0.113.0/24`, RFC 1918 space), and
says so in its own header.

## Why the folders

A fixture is only useful if you can say what a failure in it means. The five
categories exist because the answer differs:

| Category | A failure here means | Fixtures |
|---|---|---|
| `compliance_extremes/` | **A rule is wrong.** These configs have a known, total verdict. | 6 |
| `realistic/` | Something changed — investigate which. Scores here are observations, not contracts. | 5 |
| `multivendor/` | **A vendor pack or its mapping pack regressed.** One config per non-IOS platform. | 6 |
| `device_identity/` | The report cannot say *which* device it is about. | 2 |
| `feature_coverage/` | A parser regression. These reach canonical paths no compliance benchmark touches. | 1 |

### `compliance_extremes/` — the pole pairs

These are the only fixtures whose results are asserted exactly, and they are the
only tests in the project that can catch a **wrong verdict** rather than a crash.

A pole *pair* is two files for one platform, and three platforms have one:
Cisco IOS (`fully_hardened.conf` / `fully_noncompliant.conf`), Arista EOS
(`eos_fully_*.conf`) and PAN-OS (`panos_fully_*.conf`). Within each pair:

- **The hardened file** satisfies the published remediation text for every
  control the engine claims to automate on that platform. Every `fail` it
  produces is therefore a false positive in the rule pack, not a finding about
  the device. False positives are how an auditor stops trusting a tool.
- **The violating file** violates all of them. Every `pass` it produces is
  a missed finding. **False negatives outrank false positives** in this
  project's policy: a missed finding leaves a device exposed while the report
  says it is fine.

A `notapplicable` on either pole is a third kind of failure, and the tests assert
zero of those too. It means the fixture never managed to express the control's
applicable case, so the rule is untested in that direction — the verdict is not
wrong yet, but nothing is stopping it from becoming wrong. This is not
hypothetical: writing the Arista violating file is what exposed V-255979 as a
rule that was simultaneously scoped by `requires_paths` and carrying
`on_missing: fail`, so absence resolved to `notapplicable` and the rule could
never fail on any input at all.

Both halves of a pair must automate the **identical** control set. If the
hardened file reached a control the violating one did not, that control would
only ever be tested in the passing direction. `tests/test_rules_mapping.py`
asserts the set equality.

### `realistic/` — configs that look like they came off a device

Partially compliant, internally inconsistent, and messy in the ways real
configurations are: a hardened core switch with a forgotten `line aux`, a branch
router where SSH was configured but telnet never removed. These drive the demo,
the frontend test script and the latency benchmarks, and they are where the
score lands somewhere a human has to read.

Their scores are **not** asserted. A score is a function of the fixture and the
rule pack together, so pinning it would turn every legitimate new rule into a
test failure. What *is* asserted is that each one lands strictly between 0% and
100% — a "partially compliant" fixture that drifts to a pole has stopped being
partially compliant, usually because a pattern pack edit changed what it parses,
and a demo built on it would mislead.

### `multivendor/` — one device per non-IOS platform

PS 26155 C5 asks for vendor-agnostic scalability, and a claim of vendor-agnosticism
that only ever runs against Cisco IOS is not evidence of anything. These six files
are the evidence: one realistic device per remaining platform, each in that
vendor's own configuration dialect, each carrying enough of a real posture that its
benchmark has something to decide.

| Fixture | Platform | Dialect it proves the parser handles |
|---|---|---|
| `asa_dmz_firewall.conf` | Cisco ASA 9.x | `ASA Version`, named `access-list` lines, `ssh version`, ASA's `aaa authentication` forms |
| `eos_dc_leaf_switch.conf` | Arista EOS 4.x | `management ssh` / `management api` sub-modes, `aaa authorization exec` |
| `fortigate_perimeter.conf` | FortiOS 7.4 | `config`/`edit`/`set`/`next`/`end` nesting, where a value is `set x y` inside two levels of block |
| `juniper_edge_router.conf` | Junos | brace-delimited hierarchy with `set`-free stanzas and statement-terminating `;` |
| `nxos_datacenter_switch.conf` | Cisco NX-OS | `feature` gating, `ip access-list`, NX-OS-only `ssh key` and `password strength-check` |
| `panos_perimeter_firewall.conf` | PAN-OS 11 | XML-derived `set`-path config, `deviceconfig system` tree |

What each one is *for*, and what a failure means:

- **A vendor pack regressed.** Every one of these parses with **zero unparsed
  lines**, and that is a weaker claim than it looks: a fixture and its pattern pack
  written in the same change will parse each other perfectly by construction. The
  number that carries information is the count in the *verdict* table, because the
  rules were written from the benchmark text rather than from the fixture — so a
  rule that expects a fact the pack does not emit shows up as `notchecked`, not as a
  passing test.
- **A mapping pack regressed.** Each of these fixtures is the only device in the
  corpus that its benchmark applies to. If a CIS FortiGate rule stops firing, this
  file is the only place in the project where anything notices.
- **The em dash in the Score column is not a zero**, and these fixtures are where
  both reasons for it appear. `eos_dc_leaf_switch.conf | CIS` shows `—` with
  `notchecked = 0`: there is no CIS benchmark for EOS in the loaded catalogs, so
  *nothing is in scope* and the framework has no opinion on the device. That row
  will read that way permanently. The other reason is an em dash with a *non-zero*
  `notchecked` — every DISA_STIG row for a vendor whose NDM benchmark is loaded but
  whose mapping pack is not yet written. Those controls are in scope and simply
  have nothing deciding them, so the row moves off the em dash the day its pack
  lands, which is why the sentence names the shape rather than a fixture. Same em
  dash, opposite meanings, and the `notchecked` column is what distinguishes them.
  A printed `0.0%` in either row would be a report asserting total non-compliance
  about a device that was never measured.

Their scores are observations, like the `realistic/` rows, and they are not poles.
That is a real limitation rather than a formality: `asa_dmz_firewall.conf` scores
100.0% under CIS, which means all 45 CIS ASA controls are exercised in the
**passing direction only**. Across the four vendors with no pole pair, 274 of
their 304 controls only ever pass, 29 only ever fail and one is only ever
`notapplicable` — none is exercised both ways, because doing that needs a
hardened *and* a violating fixture per platform, and `compliance_extremes/`
supplies that pair for Cisco IOS, Arista EOS and PAN-OS only. The consequence is
stated precisely rather than glossed:
`test_every_control_is_exercised_in_both_directions` holds these four vendors to a
weaker bar (each control reached in at least one direction), which still catches a
rule that stopped firing but *cannot* catch a rule that returns the wrong verdict.
Adding a pole pair for a vendor promotes it to the strong bar automatically.

### `device_identity/` — proving the report knows which device it is about

PS 26155 C4 asks for a per-device report identifying the device "including serial
numbers and hardware", and neither appears anywhere in a running configuration.
Both come from `show version` / `show inventory` text bundled into the same
upload, which is how a real collection script hands a config over. Every other
fixture here is config-only, so before these two existed `device.serials` and
`device.hardware` were empty on every device in the database — the report said so
honestly, which is a correct message about a capability nothing exercised.

- **`stacked_switch_with_inventory.conf`** is the four-member stack. Serials and
  hardware are `list[str]` precisely because a stacked chassis has more than one
  of each, and because the dedup in `generic.py._build_device()` must collapse the
  serial that `show version` and `show inventory` both report while keeping
  first-seen order. A single-chassis fixture would pass with a `str` field and
  never notice.
- **`router_with_show_version.conf`** is the commoner half: most collection
  scripts capture `show version` and stop, so the serial has to be recoverable
  from the version banner alone, where IOS prints it under two different headings.
  This file also carries a motherboard serial that *differs* from the chassis
  serial, and asserts it is **not** captured — a number in `device.serials` that
  matches nothing in the asset register is worse than a missing one.

These two are the reason the verdict table shows them at all: they are ordinary
configs as far as the rule engine is concerned, so their scores are observations
like the `realistic/` rows. `tests/test_device_identity.py` asserts the identity
fields exactly.

### `feature_coverage/` — paths the benchmarks never reach

The CIS IOS 15 benchmark says nothing about IPsec, IKEv2 or IS-IS, so without a
dedicated fixture those parser patterns would ship untested. Three of the paths
in `crypto_ipsec_isis.conf` are there because a specific semantic bug was found
by inspection and must not come back — each is named in the file's own header,
including the one where `router isis` used to assert that IS-IS authentication
was configured, which was a false negative on the entire point of the control.

## Measured expectations

Every number below is generated by `scripts/fixture_report.py`, never typed by
hand. Regenerate after touching a fixture, a pattern pack or a mapping pack; CI
fails on a stale table via `--check`.

<!-- BEGIN fixture-table (generated by scripts/fixture_report.py) -->

### Parsing

One row per fixture: what the pattern pack extracted, before any rule ran.

*Unparsed* splits into the lines that carry configuration and the ones that
do not. Only the first column is a coverage claim: a fixture whose header
explains why each control fails contributes dozens of unparsed comment lines
and zero unparsed configuration. The published coverage figure in the project
README counts the significant column only.

| Fixture | Lines | Facts | Unparsed (config) | Unparsed (comments) |
|---|--:|--:|--:|--:|
| `compliance_extremes/eos_fully_hardened.conf` | 364 | 366 | 0 | 17 |
| `compliance_extremes/eos_fully_noncompliant.conf` | 285 | 188 | 0 | 74 |
| `compliance_extremes/fully_hardened.conf` | 278 | 250 | 7 | 0 |
| `compliance_extremes/fully_noncompliant.conf` | 117 | 132 | 4 | 0 |
| `compliance_extremes/panos_fully_hardened.conf` | 228 | 186 | 0 | 52 |
| `compliance_extremes/panos_fully_noncompliant.conf` | 196 | 120 | 2 | 83 |
| `device_identity/router_with_show_version.conf` | 204 | 129 | 6 | 0 |
| `device_identity/stacked_switch_with_inventory.conf` | 195 | 130 | 4 | 0 |
| `feature_coverage/crypto_ipsec_isis.conf` | 76 | 81 | 4 | 0 |
| `multivendor/asa_dmz_firewall.conf` | 363 | 375 | 1 | 0 |
| `multivendor/eos_dc_leaf_switch.conf` | 344 | 366 | 0 | 0 |
| `multivendor/fortigate_perimeter.conf` | 366 | 280 | 0 | 0 |
| `multivendor/juniper_edge_router.conf` | 287 | 185 | 0 | 0 |
| `multivendor/nxos_datacenter_switch.conf` | 263 | 318 | 0 | 0 |
| `multivendor/panos_perimeter_firewall.conf` | 339 | 295 | 0 | 0 |
| `realistic/enterprise_complex.conf` | 280 | 430 | 18 | 0 |
| `realistic/insecure_minimal.conf` | 76 | 74 | 0 | 0 |
| `realistic/partial_compliance.conf` | 79 | 102 | 0 | 0 |
| `realistic/secure_baseline.conf` | 144 | 193 | 0 | 0 |
| `realistic/telnet_exposed.conf` | 92 | 102 | 0 | 0 |

20 fixtures, 4302 facts, 46 unparsed configuration lines (272 unparsed lines in total, the remainder being comments and separators).

### Verdicts

One row per fixture per directly-evaluated framework (CIS, DISA_STIG), governance projection off, so each row is what that framework's own rules decided rather than what a roll-up inferred. **Bold** rows are the pole fixtures, whose verdicts are constrained by `tests/test_rules_mapping.py`; the rest are observations.

| Fixture | Framework | Score | pass | fail | unknown | n/a | notchecked |
|---|---|--:|--:|--:|--:|--:|--:|
| `compliance_extremes/eos_fully_hardened.conf` | CIS | — | 0 | 0 | 0 | 0 | 0 |
| `compliance_extremes/eos_fully_hardened.conf` | DISA_STIG | **100.0%** | 28 | 0 | 0 | 0 | 86 |
| `compliance_extremes/eos_fully_noncompliant.conf` | CIS | — | 0 | 0 | 0 | 0 | 0 |
| `compliance_extremes/eos_fully_noncompliant.conf` | DISA_STIG | **0.0%** | 0 | 28 | 0 | 0 | 86 |
| `compliance_extremes/fully_hardened.conf` | CIS | **100.0%** | 71 | 0 | 0 | 0 | 19 |
| `compliance_extremes/fully_hardened.conf` | DISA_STIG | **96.9%** | 31 | 1 | 0 | 0 | 205 |
| `compliance_extremes/fully_noncompliant.conf` | CIS | **0.0%** | 0 | 71 | 0 | 0 | 19 |
| `compliance_extremes/fully_noncompliant.conf` | DISA_STIG | **0.0%** | 0 | 32 | 0 | 0 | 205 |
| `compliance_extremes/panos_fully_hardened.conf` | CIS | **100.0%** | 19 | 0 | 0 | 0 | 60 |
| `compliance_extremes/panos_fully_hardened.conf` | DISA_STIG | — | 0 | 0 | 0 | 0 | 0 |
| `compliance_extremes/panos_fully_noncompliant.conf` | CIS | **0.0%** | 0 | 19 | 0 | 0 | 60 |
| `compliance_extremes/panos_fully_noncompliant.conf` | DISA_STIG | — | 0 | 0 | 0 | 0 | 0 |
| `device_identity/router_with_show_version.conf` | CIS | 67.2% | 39 | 19 | 0 | 13 | 19 |
| `device_identity/router_with_show_version.conf` | DISA_STIG | 20.7% | 6 | 23 | 0 | 3 | 205 |
| `device_identity/stacked_switch_with_inventory.conf` | CIS | 52.8% | 28 | 25 | 1 | 17 | 19 |
| `device_identity/stacked_switch_with_inventory.conf` | DISA_STIG | 17.2% | 5 | 24 | 0 | 3 | 205 |
| `feature_coverage/crypto_ipsec_isis.conf` | CIS | 34.0% | 18 | 35 | 0 | 18 | 19 |
| `feature_coverage/crypto_ipsec_isis.conf` | DISA_STIG | 23.3% | 7 | 23 | 0 | 2 | 205 |
| `multivendor/asa_dmz_firewall.conf` | CIS | 100.0% | 45 | 0 | 0 | 0 | 33 |
| `multivendor/asa_dmz_firewall.conf` | DISA_STIG | 93.2% | 41 | 3 | 0 | 0 | 88 |
| `multivendor/eos_dc_leaf_switch.conf` | CIS | — | 0 | 0 | 0 | 0 | 0 |
| `multivendor/eos_dc_leaf_switch.conf` | DISA_STIG | 96.4% | 27 | 1 | 0 | 0 | 86 |
| `multivendor/fortigate_perimeter.conf` | CIS | 86.4% | 19 | 3 | 0 | 0 | 42 |
| `multivendor/fortigate_perimeter.conf` | DISA_STIG | 82.9% | 29 | 6 | 0 | 0 | 54 |
| `multivendor/juniper_edge_router.conf` | CIS | 89.4% | 42 | 5 | 0 | 0 | 125 |
| `multivendor/juniper_edge_router.conf` | DISA_STIG | 91.2% | 31 | 3 | 0 | 0 | 440 |
| `multivendor/nxos_datacenter_switch.conf` | CIS | 92.1% | 35 | 3 | 0 | 0 | 24 |
| `multivendor/nxos_datacenter_switch.conf` | DISA_STIG | 84.2% | 32 | 6 | 0 | 1 | 103 |
| `multivendor/panos_perimeter_firewall.conf` | CIS | 84.2% | 16 | 3 | 0 | 0 | 60 |
| `multivendor/panos_perimeter_firewall.conf` | DISA_STIG | — | 0 | 0 | 0 | 0 | 0 |
| `realistic/enterprise_complex.conf` | CIS | 79.0% | 49 | 13 | 0 | 9 | 19 |
| `realistic/enterprise_complex.conf` | DISA_STIG | 37.9% | 11 | 18 | 0 | 3 | 205 |
| `realistic/insecure_minimal.conf` | CIS | 10.3% | 6 | 52 | 1 | 12 | 19 |
| `realistic/insecure_minimal.conf` | DISA_STIG | 6.9% | 2 | 27 | 0 | 3 | 205 |
| `realistic/partial_compliance.conf` | CIS | 41.8% | 23 | 32 | 1 | 15 | 19 |
| `realistic/partial_compliance.conf` | DISA_STIG | 20.7% | 6 | 23 | 0 | 3 | 205 |
| `realistic/secure_baseline.conf` | CIS | 74.6% | 44 | 15 | 1 | 11 | 19 |
| `realistic/secure_baseline.conf` | DISA_STIG | 27.6% | 8 | 21 | 0 | 3 | 205 |
| `realistic/telnet_exposed.conf` | CIS | 17.2% | 10 | 48 | 1 | 12 | 19 |
| `realistic/telnet_exposed.conf` | DISA_STIG | 13.8% | 4 | 25 | 0 | 3 | 205 |

1339 automated results across 2 frameworks. Nothing is dropped: every control in scope for the device that no rule decided is returned as `notchecked`, which is what keeps the coverage figure honest.

Splitting that `notchecked` column, because its two halves mean different things — a control argued in [`docs/GAPS.md`](../docs/GAPS.md) is a judgement, a benchmark with no mapping pack yet is a roadmap item, and one number covering both would let the second read as the first:

| Framework | notchecked / fixture | in a mapped benchmark | in benchmarks with no pack yet |
|---|--:|--:|--:|
| CIS | 0–125 | 0–125 | 0 (0 benchmarks) |
| DISA_STIG | 0–440 | 0–25 | 0–425 (0–8 benchmarks) |

<!-- END fixture-table -->

Reading the columns that are easy to misread:

- **Score** is `pass / (pass + fail)`. `notchecked`, `notapplicable` and
  `unknown` are excluded from the ratio, because folding them in either
  direction would misstate the posture. Excluding them is also why the score
  cannot be improved by failing to check something.
- **The Cisco IOS pair is not symmetric**, and it is the only one that is not.
  `fully_noncompliant.conf` scores 0.0%
  under both frameworks, but `fully_hardened.conf` scores 100.0% under CIS and
  96.9% under DISA STIG. The single remaining failure is V-215698, NTP
  authentication: DISA's own check text records that Cisco IOS is limited to MD5
  and therefore "incurs a permanent finding". No configuration can pass it, so
  the fixture does not pretend to. It is declared once, in
  `tests/test_rules_mapping.py::PLATFORM_PERMANENT_FINDINGS`, and a test asserts
  the control still exists and still fails — an allowance nobody re-checks is how
  a documented exception turns into a silent waiver.
- **`notchecked` varies by vendor, not by device.** It is a property of which
  catalogs are in scope for the detected platform and which of those have a mapping
  pack — not of how the device is configured. Two fixtures of the same vendor always
  show the same number; two vendors rarely do. The split table above matters more
  than the total. Under CIS every `notchecked` control sits in a benchmark that
  *does* have a pack, so every one of them has a reason on record — individually in
  [`docs/GAPS.md`](../docs/GAPS.md) for CIS Cisco IOS 15, and by group in each other
  pack's header. Under DISA STIG it is mostly the opposite: at most 25 per fixture
  are argued, and the rest are whole benchmarks — up to eight of them — with no
  mapping pack written yet. Reporting them rather than dropping them is what keeps
  coverage honest at 454 of 3,366 normalised controls instead of 454 of 454.
- **DISA STIG scores are much lower than CIS scores on the same file**, and that
  is expected rather than a defect. A Network Device Management STIG asks for
  things a benchmark-hardened config has no reason to carry — a DoD trust point,
  a common-criteria password policy, FIPS-approved SSH algorithm lists — so a
  device tuned to CIS lands mid-table under STIG. The pair of numbers is the
  useful output; a tool that showed only the friendlier one would be the problem.
- **unknown = 1** on five fixtures — the four `realistic/` ones and the stacked
  switch — is CIS 2.1.1.1.3, the RSA modulus size. `crypto key generate rsa` is an
  exec command, so a running config genuinely does not record it. `unknown` is the
  correct answer; rendering it as `pass` would be the bug. DISA STIG reports no
  `unknown` at all on any fixture, which is a property of that pack worth keeping:
  every one of its 212 conditions is decidable against fact shapes these fixtures
  actually produce. So are all six multi-vendor packs' — 242 CIS conditions produce
  five `unknown` results between them, and all five are the same control.
- **Unparsed** lines are reported, never silently dropped. The counts above are
  route-maps, prefix-lists, BGP peering statements and similar — constructs no
  shipped rule reads. They are also the raw material for the training module:
  `POST /simulate` returns them, and the Training GUI is how you teach the parser
  a line it does not know.

## Coverage guarantee

Across these twenty fixtures, **every one of the 454 automated controls is
exercised** — no rule in any pack is dead. 149 of them are exercised in **both
directions**: each passes on at least one fixture and fails on at least one. They
are the three vendors with a pole pair — Cisco IOS 102, Arista EOS 28, PAN-OS 19.
`tests/test_rules_mapping.py::test_every_control_is_exercised_in_both_directions`
asserts both tiers and names the offenders if either stops being true. The one
exemption is V-215698, which is held to the failing direction only, for the platform
reason given above — which is why the strong tier is 150 controls and 149 of them
reach both directions.

The remaining 304 controls — the four vendors with no pole pair, ASA, NX-OS,
FortiGate and Junos — are exercised in at most one direction each: 274 only pass,
29 only fail, and one (DISA STIG NX-OS NDM V-220515) is reached only as
`notapplicable`, because its check text makes PKI applicability an organisational
question rather than a configuration one. That is stated as a set of numbers
rather than described as "covered" because the gap is exactly what the numbers
say. The strong bar needs a hardened *and* a violating fixture per platform, and
the honest alternative to a two-tier bar was not a stricter test but four vendors
with no coverage assertion at all.

This matters more than the count of fixtures. A control that only ever passes
hides a rule that cannot detect its own violation; a control that only ever
fails hides a rule no compliant device can satisfy. Both are wrong verdicts
waiting for a real device, and neither shows up as a test failure without a
fixture in the missing direction.

Coverage is keyed on `(framework, benchmark, control_id)`, and that is not
pedantry. CIS numbering restarts at 1.1.1 in every benchmark, so 38 of the control
ids this corpus reaches name a different control in two to four different
benchmarks — CIS 1.2.1 exists in the IOS, ASA, NX-OS and PAN-OS packs. While the
test keyed on the bare id, those were merged, and the merge did two things behind a
green run: 26 Cisco IOS controls dropped out of the strong tier because a shared
number made them look multi-vendor, and pass/fail directions were unioned across
benchmarks, so CIS ASA 1.2.1 passing on the ASA fixture satisfied the both-directions
bar for CIS IOS 1.2.1, which no fixture ever passed. A control credited with
coverage it does not have is worse than one honestly reported as uncovered.

The same argument applies one level up, to frameworks. Until recently the pole
tests evaluated `frameworks=["CIS"]` while a second mapping pack shipped, so the
32 newest and least reviewed rules had no false-positive or false-negative
detector at all — and the suite was green throughout, which is the more dangerous
of the two states. `test_every_direct_framework_produces_a_verdict` now asserts
that each directly-evaluated framework decides at least one control on each pole,
so a pack can no longer ship behind a passing test run.

## Running them

Offline, no server, no models — the invariants above:

```bash
.venv/Scripts/python.exe -m pytest tests/test_rules_mapping.py tests/test_pattern_packs.py -q
```

To regenerate the table:

```bash
.venv/Scripts/python.exe scripts/fixture_report.py
```

Against a running API, which additionally exercises ingestion, the AI tier
status and the response contract:

```bash
.venv/Scripts/python.exe scripts/run_frontend_tests.py
```

## Adding a fixture

1. **Pick the category by what a failure would mean**, using the table at the
   top. If you cannot say what a failure in your new file proves, it belongs in
   `realistic/` and its score should not be asserted.
2. **Write a header** stating category, vendor, purpose, and — if the file is
   deliberately insecure — a warning not to copy from it. Every fixture here
   carries one; it is what lets the next reader tell an intentional violation
   from an accident.
3. **Nothing else.** Both fixture globs are recursive
   (`tests/test_pattern_packs.py`, `scripts/run_frontend_tests.py`), so a new
   `.conf` is picked up by the parser invariants, the provenance checks, the
   determinism check and the coverage assertion with no test edits.
4. **If you touch either pole**, re-run the tests before anything else. Those
   two files are the project's only defence against a rule that quietly returns
   the wrong verdict.

A fixture for a new vendor needs a pattern pack in
`data/ingest/patterns/<vendor>.yaml` first — without one, no adapter claims the
file and the parser tests skip it rather than fail. `test_rules_mapping.py`
asserts detection, so add the pack in the same change.
