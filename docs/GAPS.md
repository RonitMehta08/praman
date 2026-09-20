# Known gaps

What PRAMAN does **not** check, and why.

This document exists because the easiest way for a compliance tool to look good
is to quietly not check the hard controls. A benchmark with 90 controls and 71
automated checks can be reported as "71 of 90" or as "100% of what we check" —
the second is technically true and useless. Every control listed here is
returned to the caller as `notchecked` with a reason, appears in the PDF report,
and is excluded from the compliance score in both directions, so it can never
flatter a device.

The score is `pass / (pass + fail)`. Nothing in this document is folded into it.

**Currency.** Both halves of this document are asserted by the test suite, so
neither can silently drift. `tests/test_rules_mapping.py::test_notchecked_controls_are_reported_not_dropped`
fails if an unmapped control stops being reported, and
`test_every_direct_framework_produces_a_verdict` fails if a whole framework goes
silent — the failure mode that let 32 DISA rules ship for a while with no
false-verdict detector behind them at all. The generated table in
[`test_configs/README.md`](../test_configs/README.md) publishes the per-fixture
`notchecked` counts, and those counts **vary by vendor, not by device**: 19 CIS
and 205 DISA on a Cisco IOS router (§1 and §2 below), but 125 CIS and 440 DISA on
the Junos fixture, 33 and 88 on the ASA, 60 and 0 on the Palo Alto. The spread
says nothing about the configurations. It is how much of each vendor's publisher
corpus has a mapping pack behind it, which §4 now inventories per vendor rather
than asserting for one platform. Regenerate the live lists at any time:

```bash
.venv/Scripts/python.exe scripts/fixture_report.py --detail fully_hardened
```

```bash
.venv/Scripts/python.exe scripts/fixture_report.py --check
```

---

## 1. CIS Cisco IOS 15 Benchmark v4.1.1 — 19 of 90 controls unautomated

Automated coverage is **71 of 90 controls (78.9%)**. The 19 below are grouped by
what is actually missing, because the categories have very different costs to
close.

### 1.1 Needs a cross-reference condition type (4 controls)

| Control | Title |
|---|---|
| 1.2.4 | Create 'access-list' for use with 'line vty' |
| 1.5.5 | Set the ACL for each 'snmp-server community' |
| 1.5.6 | Create an 'access-list' for use with SNMP |
| 3.2.1 | Set 'ip access-list extended' to Forbid Private Source Addresses from External Networks |

Each of these asks whether an ACL *named by one directive* is *defined
elsewhere* and *has particular contents*. The rule language evaluates conditions
against facts at canonical paths independently; it has no way to say "the value
at `line.vty.access_class` must equal the value at some `acl.name`, and that
ACL's entries must satisfy P".

A rule could be written that only checks the ACL is referenced, ignoring whether
it exists. That would return PASS for a vty line pointing at an access-class
that was never defined — which on IOS means the line is **unfiltered**. It would
be a false positive on the exact misconfiguration the control is written to
catch, so the control stays unautomated instead.

3.2.1 needs more than the cross-reference: it requires correlating
`acl.entry.action` with `acl.entry.source` *within the same entry*, and the
canonical model currently emits those as independent facts. 1.5.5 additionally
needs a per-community boolean that the community-string regex cannot separate
safely from the community name itself.

**To close:** a `cross_reference` condition type resolving a value at one path
against the key of a block at another, plus same-line entry grouping for ACL
entries. Design-level work on the rule language, not rule authoring.

### 1.2 Not decidable from a configuration file (3 controls)

| Control | Title |
|---|---|
| 1.5.1 | Set 'no snmp-server' to disable SNMP when unused |
| 3.1.4 | Set 'ip verify unicast source reachable-via' |
| 3.2.2 | Set inbound 'ip access-group' on the External Interface |

**1.5.1** is conditional on organisational intent: "disable SNMP *when unused*".
Whether SNMP is in use is a policy input about the monitoring estate, not a fact
in the config. Reporting a device with working SNMPv3 as non-compliant would be
wrong; so would passing a device with a forgotten SNMPv1 listener. The control
needs an input the tool is not given.

**3.1.4 and 3.2.2** are both explicitly scoped by the benchmark's own remediation
text to *the external interface*. The canonical model records interface names,
addresses and roles as configured, and nothing in a standalone configuration file
identifies which interface faces the untrusted network — `GigabitEthernet0/0`
with a public address may be a transit link, a DMZ, or a lab.

An earlier design mapped these under-strict, as "uRPF / an inbound ACL is in use
*anywhere*". That was reversed deliberately. An under-strict rule renders PASS
and **counts toward the compliance score**, claiming an assurance the evidence
does not support; `notchecked` says no automated check was performed and is
excluded. When the honest answer is "I cannot tell", saying so is the correct
output.

**To close:** an interface-role input (an uploaded topology, an operator
annotation in the UI, or a naming convention the operator declares), plus an
organisational SNMP-in-use flag for 1.5.1. This is product surface, not parsing.

### 1.3 Ambiguous in the canonical model (1 control)

| Control | Title |
|---|---|
| 2.3.1.4 | Set 'key' for each 'ntp server' |

`time.ntp.key_id` is emitted by two different IOS directives:
`ntp server <ip> key N` (a per-server key reference) and
`ntp authentication-key N md5 <hash>` (a global key definition). A rule reading
that path cannot tell whether it is looking at a server that references a key or
a key that exists unreferenced — so it cannot distinguish "every server has a
key" from "a key was defined and no server uses it". The second is the failure
the control is about.

This is a modelling defect, not a missing feature. The correct fix is to split
the path so the two directives stop colliding, at which point the control maps
straightforwardly.

**To close:** split into `time.ntp.server_key_id` (per-server) and
`time.ntp.authentication_key_id` (global) in the canonical vocabulary, update the
cisco_ios pattern pack, then write the rule. Small, well-understood, and it also
removes a latent wrong verdict from 2.3.1.2 and 2.3.1.3.

### 1.4 Needs pattern-pack work first (11 controls)

The routing-protocol authentication family. Not blocked on design — these need
parser patterns that do not exist yet.

| Control | Title | Missing construct |
|---|---|---|
| 3.3.1.1 | Set 'key chain' | global `key chain <name>` stanza |
| 3.3.1.2 | Set 'key' | `key <id>` inside a key chain |
| 3.3.1.3 | Set 'key-string' | `key-string <secret>` inside a key |
| 3.3.3.1 | Set 'key chain' (RIP) | as 3.3.1.1 |
| 3.3.3.2 | Set 'key' (RIP) | as 3.3.1.2 |
| 3.3.3.3 | Set 'key-string' (RIP) | as 3.3.1.3 |
| 3.3.1.4 | Set 'address-family ipv4 autonomous-system' | EIGRP named-mode address-family block |
| 3.3.1.5 | Set 'af-interface default' | EIGRP named-mode af-interface block |
| 3.3.1.8 | Set 'ip authentication key-chain eigrp' | interface-level EIGRP auth directive |
| 3.3.1.9 | Set 'ip authentication mode eigrp' | interface-level EIGRP auth directive |
| 3.3.2.2 | Set 'ip ospf message-digest-key md5' | interface-level OSPF digest key |

The `key chain` group (six controls) is one nested three-level block —
chain → key → key-string — which is worth modelling once because it is shared by
EIGRP, RIP, IS-IS and BFD. The EIGRP named-mode blocks (3.3.1.4, 3.3.1.5) are a
second, distinct configuration dialect from the classic `router eigrp` mode
already parsed. The three interface-level directives are ordinary line patterns
and are the cheapest of the group.

**To close:** ~4 new block definitions and ~6 line patterns in
`data/ingest/patterns/cisco_ios.yaml`, plus canonical paths for the key-chain
hierarchy. No code changes — a vendor is a data file, so this is authoring work.
Fixtures in both directions are required (see
[`test_configs/README.md`](../test_configs/README.md)).

---

## 2. DISA STIG Network Device Management packs

Per-pack coverage, all counted the same way — controls the pack maps, over
controls the publisher's XCCDF contains:

| Pack | Controls | Automated | Unautomated | Argued in |
| --- | --- | --- | --- | --- |
| `disa_stig_cisco_ios_router_ndm_…_v3r8` | 35 | 32 (91.4%) | 3 | §2.1–§2.3 |
| `disa_stig_cisco_asa_ndm_…_v2r5` | 47 | 44 (93.6%) | 3 | §2.5 |
| `disa_stig_fortinet_fortigate_firewall_ndm_…_v1r5` | 60 | 35 (58.3%) | 25 | §2.7 |
| `disa_stig_juniper_router_ndm_…_v3r2` | 49 | 34 (69.4%) | 15 | §2.8 |
| `disa_stig_cisco_nx_os_switch_ndm_…_v3r6` | 42 | 39 (92.9%) | 3 | §2.9 |
| `disa_stig_arista_mls_eos_4_x_ndm_…_v2r2` | 21 | 17 (81.0%) | 4 | the pack header |
| `disa_stig_arista_mls_eos_4_x_l2s_…_v2r3` | 18 | 11 (61.1%) | 7 | the pack header |

An NDM STIG reaches this coverage because it is almost entirely about the
management plane — AAA, logging, session control, password policy, SSH crypto —
which is exactly what a running configuration states outright. The controls below
are not close calls; each names something a configuration file does not contain.

Section numbering here is append-only. Subsections are added for each new pack
rather than renumbered, because other documents cite these numbers.

### 2.1 IOS Router — V-215673 (CISC-ND-000290) — ACL logging on interface-bound ACLs

> The Cisco router must be configured to generate audit records containing
> information to establish where the events occurred.

Requires a join the rule language cannot express: which ACLs are bound to an
interface, and whether *those* ACLs' entries carry `log` or `log-input`. The
canonical model holds `acl.entry.action` and `acl.entry.log` as independent facts
and interface bindings separately, with no way to say "for every ACL named by an
interface binding, every deny entry must log".

Encoding it without the join would be worse than leaving it unchecked. Requiring
`log` on every ACE would fail routers whose non-interface ACLs — SNMP community
filters, route maps, NTP peer lists — legitimately do not log, which is most
routers. This is the same limitation as CIS §1.1 above and closes with the same
work: a cross-reference condition type.

### 2.2 IOS Router — V-215710 (CISC-ND-001410) — configuration change notification

> The Cisco router must be configured to conduct backups of the configuration
> when changes occur.

DISA's check text is satisfied by an **EEM applet** that fires on a
configuration-change syslog event and copies the running config off-box. EEM
applets are procedural — `event manager applet … / action 1.0 cli command …` —
and are not parsed into canonical facts; treating an applet's presence as
evidence of what it *does* would be a guess about arbitrary CLI in an action
body.

The `archive` / `write-memory` stanza the fixtures do carry is a different
guarantee — a local rolling archive, not an off-box backup on change — so
mapping this control onto it would report a control satisfied by a mechanism the
publisher did not name.

### 2.3 IOS Router — V-220137 (CISC-ND-001470) — vendor-supported software release

> The Cisco router must be running an IOS release that is currently supported by
> Cisco Systems.

Needs an external, continuously-updated feed of Cisco EOL/EOS dates keyed by
release train. The version string is parsed and reported, so an auditor has the
evidence to decide this by hand; what cannot ship is the authority to decide it
automatically. Bundling a snapshot of support dates would produce a check that
silently rots — passing an EOL release because the offline table predates its
end-of-support announcement is a false pass on the one control whose whole
purpose is currency.

This is a deliberate scope boundary, not a backlog item: PRAMAN is offline by
design (GLOBAL_RULESET R1), and a control that cannot be decided offline is
reported as `notchecked` rather than decided badly.

### 2.4 IOS Router — V-215698 is mapped, and permanently fails

Not a gap — the opposite — but it belongs here because a reader will otherwise
take it for a bug. CISC-ND-001150 requires NTP sources to be authenticated with
a FIPS-validated algorithm, and DISA's own check text says:

> Cisco IOS is limited to MD5 for NTP authentication, and incurs a permanent
> finding as it is not FIPS compliant.

The rule is written to fail whenever the NTP key algorithm is MD5, which on this
platform is always. `compliance_extremes/fully_hardened.conf` configures NTP
authentication exactly as the published fix text shows and still fails this one
control, deliberately. The alternative — passing a device the publisher says is
non-compliant — would report FIPS compliance the platform does not have.

The exemption is declared in one place,
`tests/test_rules_mapping.py::PLATFORM_PERMANENT_FINDINGS`, and
`test_permanent_findings_are_real_and_still_failing` asserts the control still
exists and still fails, so the allowance cannot quietly widen into a waiver for
rules that break for ordinary reasons.

### 2.5 Cisco ASA NDM v2r5 — 3 of 47 controls unautomated

**V-239922 (CASA-ND-000920) — audit record storage allocation.**

> The Cisco ASA must be configured to allocate audit record storage capacity in
> accordance with organization-defined audit record storage requirements.

DISA's check names three flash directives — `logging flash-bufferwrap`, `logging
flash-minimum-free`, `logging flash-maximum-allocation`. None is parsed, and the
canonical model has no path for on-device log storage.

The tempting shortcut is `logging.buffered_size`, which the ASA pack does emit —
and it would be wrong. `logging buffer-size` sizes the **RAM** buffer, which is
lost on reload; the control is about **flash** allocation, which survives one.
Mapping the first onto the second would report storage capacity satisfied by a
buffer that does not retain anything. Closing this properly needs three new
canonical paths under `logging.*` and the patterns to fill them; it is deferred
rather than declined, because unlike §2.3 the evidence *is* in the configuration.

**V-239941 (CASA-ND-001350) — configuration backup on change.**

> The Cisco ASA must be configured to conduct backups of the configuration when
> changes occur.

The same limitation as §2.2 on a different platform, and for the same reason:
DISA's check text is satisfied by an **EEM applet** (`event manager applet
BACKUP_CONFIG / event syslog id 111010 / action 1 cli command "copy
startup-config scp://…"`). Applet bodies are arbitrary CLI in an action list, so
treating an applet's presence as evidence of what it *does* would be a guess.
The ASA pack emits no `file.*` path at all, so there is not even a wrong answer
available here.

**V-239944 (CASA-ND-001420) — vendor-supported software release.**

> The Cisco ASA must be running an operating system release that is currently
> supported by Cisco Systems.

Identical in kind to §2.3, and declined on the same offline-by-design grounds.
DISA's check even names the URL a reviewer must consult
(`cisco.com/…/eos-eol-notice-listing.html`), which is the clearest possible
statement that the answer is not in the configuration file. `device.os_version`
is parsed and reported — `9.16(4)23` on the shipped fixture — so an auditor has
the evidence to decide it by hand.

### 2.6 Cisco ASA NDM — three checks whose publisher escape clause the pack cannot see

Not unmapped, but not fully decided either. Each of these three controls is
mapped and returns a verdict, and each carries an alternative or
not-applicable clause in DISA's own text that a configuration file cannot
resolve. Recorded here because the honest reading of the verdict depends on it,
and each rule's `mapping_rationale` says the same thing at the point of use.

| Control | What the rule decides | What it cannot see |
| --- | --- | --- |
| V-239923 (CASA-ND-000930) | `logging trap <severity>` at critical or lesser, plus a `logging host` | DISA: *"A logging list can be used as an alternative to the severity level."* A named list's contents are a separate stanza the pack does not model, so a device alerting via `logging list` reports a finding it may not deserve |
| V-239924 (CASA-ND-000940) | Two or more `ntp server` statements | On Firepower chassis hardware NTP is configured in FXOS and never appears in the ASA CLI, so a correctly synchronised device of that model reports a finding |
| V-239932 (CASA-ND-001180) | `threat-detection basic-threat` | DISA: *"When operating the ASA in multi-context mode with a separate IDPS, threat detection cannot be enabled, and this check is Not Applicable."* Neither multi-context mode nor an external IDPS is visible in one context's configuration |

All three fail *towards* a finding rather than towards a pass, which is the
direction this project's policy requires when the evidence is incomplete
(`docs/adr/0002-notchecked-excluded-from-score.md`). A reviewer waiving one has
the publisher's own sentence to cite; a reviewer who was never shown the finding
would have nothing to waive.

The three deliberate FAILs on the ASA fixture are a different matter and are
**not** gaps: V-239902 (an Indian enterprise banner is not the DoD banner),
V-239912 (three local accounts where DISA allows one) and V-239919
(`minimum-changes 4` where DISA requires eight) are real findings against that
device, kept so the pack demonstrates that its rules can fail. They are
explained in the pack header.

### 2.7 Fortinet FortiGate NDM v1r5 — 25 of 60 controls unautomated

`rules/mappings/disa_stig/fortinet_fortigate_ndm_v1r5.yaml` maps 35. The 25 that
are not fall into four groups, and the groups matter more than the individual
controls: three of them name a specific, buildable piece of work.

**Needs a cross-reference condition type (9 controls).** V-234166, V-234185,
V-234187, V-234188, V-234189, V-234191, V-234197, V-234216 and, in part,
V-234186. Every one of these is a *permission join*: DISA asks the reviewer to
find which administrator holds a given profile, open that profile, and check one
permission inside it. The canonical model carries both halves —
`mgmt.local_user.privilege` records `prof_netops` against the account, and the
profile's own stanza is parsed — but a condition cannot follow the name from one
to the other. The evaluator has no condition type that resolves a value in one
fact into a lookup against another; adding one (`cross_reference`) is the same
prerequisite §1.1 records for four CIS IOS controls, and closing it there closes
these nine at the same time. Nothing about FortiOS is the obstacle.

**Needs pattern-pack work first (4 controls).**

| Control | What DISA reads | What is missing |
| --- | --- | --- |
| V-234180 (FGFW-ND-000105) | `config log disk setting` → `set max-log-file-size` | The directive is parseable and no pattern emits it. Even once it is, the control compares against an *organization-defined* storage requirement that is not in the file, so it would join §2.6's category rather than becoming fully decided |
| V-234192 (FGFW-ND-000165) | every account except `admin` assigned to a remote LDAP group | `config user ldap` is not parsed into any `aaa.*` fact |
| V-234208 (FGFW-ND-000245) | `config user ldap` → `set secure ldaps` | Same stanza, same gap. These two land together or not at all |
| V-234217 (FGFW-ND-000290) | IPv4/IPv6 DoS policy with L3/L4 anomaly checks enabled | DoS policies are a policy-object graph the canonical model does not carry, the same limit V-234199's first branch runs into |

**Ambiguous in the canonical model (2 controls).**

*V-234165 (FGFW-ND-000030) — only one local account.* The check is "verify the
admin account is the only account configured as Type Local". FortiOS marks an
account as remote by `set remote-auth enable` inside the same `config system
admin` stanza that names it, and the pack files every account name at
`mgmt.local_user.name` regardless. A `count == 1` rule would therefore report a
finding against a compliant device that authenticates four administrators
against RADIUS and keeps one local account of last resort — the exact
configuration the control is asking for. Separating the two needs either a
distinct path for remote-authenticated accounts or the same `cross_reference`
work above; until then the rule would be wrong more often than right on real
devices, and a wrong rule is worse than an honest `notchecked`.

*V-234221 (FGFW-ND-000311) — eight characters must change on a password change.*
The directive exists and is trivially parseable (`set change-8-characters
enable`), and the control is left unmapped because of a defect on our side
rather than theirs. `mgmt.password_policy.history` is already occupied twice
over: the ASA pack files `password-policy minimum-changes 8` there as an **int**,
which is a count of *characters that must differ*, and the FortiOS pack files
`reuse-password enable|disable` there as a **str**, which is *whether old
passwords may be reused*. Those are two different requirements sharing one path,
with two different types, and V-239919 in the ASA pack already reads the first
of them. Adding a third meaning would compound it. The fix is a vocabulary
change — a new `mgmt.password_policy.min_changes` path, the ASA pattern and its
rule repointed at it, then this control mapped — and it is queued with the other
vocabulary corrections in §2.4 rather than done inside a mapping pack.

**Not decidable from a configuration file (10 controls).** V-234170 (the banner
must be *retained* on screen and explicitly accepted — an interaction, not a
setting), V-234182 (Automation Stitches with a valid Action Email), V-234184
(inspects the timezone rendered into a stored log entry), V-234190 (log in as a
non-System administrator and observe that the Firmware option is absent),
V-234193 (a currently vendor-supported release — declined on the same
offline-by-design grounds as §2.3), V-234194 (compare enabled events against a
*locally developed list* that only the site holds), V-234196 (at least one saved
backup within the last week — device state, and the reason the mapped V-234195
says explicitly that it does not verify recency), V-234202 (`diagnose sys ntp
status` must report `server-version=4`, which is runtime output), V-234209
(attempt to log in as `admin` with a blank password) and V-234220 (verify the
*process* used to apply patches).

The six FAILs on the FortiGate fixture are a different matter and are **not**
gaps: V-234168, V-234169, V-234198, V-234210, V-234215 and V-234219 are real
findings against a CIS-hardened enterprise firewall measured against a DoD
STIG. They are explained in the pack header.

---

### 2.8 Juniper Router NDM v3r2 — 15 of 49 controls unautomated

`rules/mappings/disa_stig/juniper_router_ndm_v3r2.yaml` maps 34. The 15 that are
not fall into the same four groups as §2.7, and as there the groups matter more
than the individual controls.

**Needs a cross-reference condition type (6 controls).** V-217310, V-217317,
V-217318, V-217319, V-217336 and V-217342. Every one is a *name join*, in one of
two shapes. V-217310 and V-217342 ask the reviewer to read the filter name bound
to `lo0` and then open the `firewall filter` of that name to see what its terms
do; the canonical model holds both halves — `interface.acl_in` records
`protect-re`, `acl.name` records the filter, `acl.entry.*` records its terms —
and no condition can follow the name from one to the other. V-217317, V-217318,
V-217319 and V-217336 ask the same question of a login class: find the class a
user holds, open it, and check whether `deny-commands` or `deny-configuration`
covers `file delete`, `system syslog` or `request system software`. Adding a
`cross_reference` condition type is the prerequisite §1.1 already records for
four CIS IOS controls and §2.7 for nine FortiGate ones; closing it there closes
these six at the same time. Nothing about Junos is the obstacle.

**Needs pattern-pack work first (5 controls).**

| Control | What DISA reads | What is missing |
| --- | --- | --- |
| V-217324 (upper case) | `system login password minimum-upper-cases 1` | No canonical path. `mgmt.password_policy.complexity` holds Junos's `change-type`, which is a *policy selector* (`set-transitions` or `character-sets`), not a per-class minimum. Filing four different minimums into one path would repeat the `logging.facility` mistake §3 records |
| V-217325 (lower case) | `minimum-lower-cases 1` | Same |
| V-217326 (numeric) | `minimum-numerics 1` | Same |
| V-217327 (special) | `minimum-punctuations 1` | Same |
| V-217332 (CCI-001849) | `syslog { file LOG_FILE { archive size 1000000 files 12; } }` | `archive size … files …` is parseable and no pattern emits it. Even once it is, the control compares against an *organization-defined* storage requirement that is not in the file, so it would join §2.6's category rather than becoming fully decided |

The four password-complexity controls are one piece of work, not four: four new
`mgmt.password_policy.min_*` paths emitted by one pattern family, then four
one-leaf rules. They are queued with the §2.4 vocabulary batch rather than done
inside a mapping pack, because adding a canonical path is a change to the shared
vocabulary and every pack that could emit it should be considered at once —
FortiOS `set min-upper-case-letter`, PAN-OS `password-complexity
minimum-uppercase-letters` and IOS `aaa common-criteria policy` all express the
same four minimums.

**Ambiguous in the canonical model (2 controls).**

*V-217321 — only one local account of last resort.* Structurally identical to
FortiGate V-234165 in §2.7 and unmapped for the same reason. Junos marks an
account as remotely authenticated by leaving it out of `system login` entirely
and letting `authentication-order radius` resolve it, so `mgmt.local_user.name`
holds only local accounts — which sounds like it makes a `count == 1` rule
correct, until a site keeps a break-glass account *and* a named local account for
the console. The control is really "exactly one account exists that the
authentication server does not know about", and no configuration file states what
the authentication server knows.

*V-217352 — certificates from an approved service provider.* DISA reads
`security { pki { ca-profile <name> { ca-identity …; revocation-check …; } } }` —
a *certificate authority* profile. `crypto.pki.trustpoint` on Junos holds the
name of a **local certificate** (`jweb-cert` on the shipped fixture), which is
the device's own identity certificate rather than the CA it trusts. Writing a
rule against the path we have would compare the wrong object and could only be
accidentally right. A `crypto.pki.ca_profile` path plus a `ca-profile` block
pattern is the fix, and it belongs with the §2.4 batch for the same reason as the
password minimums.

**Not decidable from a configuration file (2 controls).** V-220142 (a master
password — DISA's own check note says "the master password is hidden from the
configuration", so no config file can carry the evidence, which is the cleanest
example in the whole document of a control that is genuinely undecidable offline)
and V-220143 (a currently vendor-supported Junos release — declined on the same
offline-by-design grounds as §2.3, and requiring a lookup against Juniper's EOL
page).

The three FAILs on the Junos fixture are a different matter and are **not** gaps:
V-217312, V-217328 and V-217335 are real findings against a CIS-hardened
enterprise edge router measured against a DoD STIG. They are explained in the
pack header, and V-217328 is worth singling out — it is the finding that only
became visible once `idle-timeout` stopped being read from the J-Web session
stanza, because a GUI timeout was answering a CLI-session control and could only
ever produce a false pass.

**One control moved out of this section while the pack was being written.**
V-217350 (CAT I, two authentication servers) was going to be listed here: the
pack matched `radius-server {` with a line pattern that recorded the protocol and
threw the servers away, so `count aaa.server.host >= 2` had nothing to count. It
is a block now, in both the brace and `set` serialisations, and the control is
mapped and passing. Two details of that work are worth recording because they
generalise:

* A block anchor could not carry a constant. Junos opens `tacplus-server {` and
  every other pack files that protocol as `tacacs+`, so the anchor needed a
  value the anchor line does not spell. `BlockPattern` now takes the same
  `literal:` key line patterns have always taken, with the run-mode case
  rejected explicitly — a run block groups consecutive lines by their anchor
  value, and a constant key would merge unrelated objects into one instance.
* The `set` serialisation flattens a stanza onto one line per attribute, so the
  same server reappears for `secret`, `timeout`, `retry` and `source-address`.
  Only the `secret` line emits `aaa.server.host`. A pattern that emitted the host
  from every attribute line would have counted one well-configured server as
  four — the same defect class as the `boot-server` fix recorded in §3, found
  before it shipped rather than after.

### 2.9 Cisco NX-OS Switch NDM v3r6 — 3 of 42 controls unautomated

`rules/mappings/disa_stig/cisco_nx_os_switch_ndm_v3r6.yaml` maps 39. The three
that are not are each a known category from earlier in this document rather than
anything new about NX-OS, which is worth stating plainly: a 93% pack whose
remaining gaps are all previously-argued shapes is a different situation from one
whose gaps are unexplored.

**V-220484 (CISC-ND-000290) — ACL logging.** DISA asks that ACLs configured to
deny traffic log the matches, which means reading the `log` keyword *on the same
ACE as* the `deny` action. The canonical model records ACE actions and ACE
options as separate facts with no binding between them, so a rule can see that
some entry denies and some entry logs and cannot see whether they are the same
entry. This is the identical gap §2.1 records for IOS V-215673, for the identical
reason, and it will close for both packs in the same change.

**V-220499 (CISC-ND-000980) — record time stamps mapped to UTC or GMT.** Not
unautomated for lack of evidence; unautomated because no configuration can fail
it. NX-OS stores and stamps in UTC internally, `clock timezone` only changes the
display offset, and the check text's own remedy is to *set* a timezone. A switch
with no `clock timezone` line is already UTC, and one with a timezone line
carries an offset from UTC by construction — so a rule over `time.timezone`
returns `pass` for every possible value including absence. A control that cannot
fail is a control that tells the reader nothing, and reporting it as
`notchecked` with this reason is more honest than a green tick that no device
could ever miss. The timezone and its offset are still parsed and still appear
in the report's evidence, so an auditor doing the check by hand has the line in
front of them.

**V-220517 (CISC-ND-001470) — vendor-supported software release.** Needs a
continuously-updated Cisco EOL/EOS feed keyed by NX-OS version. `os.version` is
parsed and reported; deciding it needs data that is not in the configuration and
not in this repository. §2.3 argues the same control for IOS at length, including
why a bundled snapshot of the EOL listing would be worse than no check.

---

## 3. Deliberate mapping decisions worth knowing about

### CIS 1.2.9 and 1.2.10 are mapped identically

Both are automated, both pass and fail together, and this is not a copy-paste
error. The benchmark publishes the same vty `exec-timeout` requirement twice
under two control numbers with the same remediation text. Collapsing them into
one rule would understate the control count; mapping one and skipping the other
would misrepresent which controls were assessed. They are mapped identically and
the duplication is recorded in each rule's `mapping_rationale`.

### Every timeout check is bounded at both ends

`exec-timeout 0 0` and `no exec-timeout` both mean *never time out* on IOS, and
both are recorded as 0 seconds because that is what the platform means by them.
A rule of the obvious form `exec_timeout <= 600` therefore **passes the least
secure setting the platform offers**. Every timeout rule in the pack is
`all_of[lte N, gt 0]`. This was found by inspection before any fixture existed
and is the reason `fully_noncompliant.conf` sets `exec-timeout 0 0` on some lines
and `no exec-timeout` on others.

### No `presence` check on a defaulted path

`presence` passes when any fact exists at a path, and a pack-level default *is* a
fact. `service.password_encryption` has a default of `false`, so a presence check
on it would pass for every device ever parsed. Defaulted paths use
`fact_check … eq true|false`. There are 19 such rules;
`tests/test_pattern_packs.py::test_pack_default_never_contradicts_an_observed_fact`
guards the mechanism they rely on.

### Feature-conditional controls report `notapplicable`, not `pass`

A router not running EIGRP is not applicable to the EIGRP authentication control.
Expressing that as a condition that happens to be satisfied would return PASS and
credit the device for a control it was never subject to. These rules use
`applies_to.requires_paths`, which reports `notapplicable` — excluded from the
score.

### CIS severities are assigned by this project

CIS publishes no severity ratings. Without an assignment every finding would
render as `unknown` severity and the severity distribution chart would be a
single bar, so `severity_override` is set on all 242 CIS rules across the six
mapped benchmarks and asserted by
`tests/test_rules_mapping.py::test_cis_rules_override_severity`. The scale, from
the pack header:

- **high** — unauthenticated or cleartext administrative access, or a
  remote-management plane exposed.
- **medium** — loss of accountability, weakened evidence, or a hardening step
  whose absence needs another failure to be exploitable.
- **low** — defence in depth.

This is a project judgement, not a publisher statement, and reports should be
read as such.

### One canonical fact had an unreconciled unit contract; it is now reconciled

A canonical path is a contract, and a multi-vendor project is where an
underspecified one starts costing something. The first of the two entries below
is kept as a worked record of what that costs and how it was paid off; the
second is still open.

**`aaa.login_block` was seconds on four vendors and minutes on two. It is now
seconds everywhere.** The path records the lockout duration after failed
authentication attempts, and the publisher syntax it comes from disagrees about
the unit:

| Pack | Directive | Publisher unit | Filed as |
|---|---|---|---|
| `cisco_nxos` | `system login block-for <n> attempts …` | seconds | int seconds |
| `arista_eos` | `aaa authentication policy lockout … duration <n>` | seconds | int seconds |
| `fortinet` | `set admin-lockout-duration <n>` | seconds | int seconds |
| `cisco_ios` | `login block-for <n> attempts … within …` | seconds | int seconds — was the whole line |
| `juniper_junos` | `lockout-period <n>` | **minutes** | int seconds via `minutes_seconds` |
| `paloalto_panos` | `set … management admin-lockout lockout-time <n>` | **minutes** | int seconds via `minutes_seconds` |

Three consumers had got away with the ambiguity because they check presence
only — CIS NX-OS 1.2.2, CIS FortiGate 2.2.2 and CIS PAN-OS 1.4.2 asserted that a
lockout exists without asserting a floor. One did not: DISA `V-215668` compares
against a real threshold, and it was correct only because it matched
`'block-for\s+(?:9\d\d|\d{4,})\s'` against the raw Cisco IOS line rather than
reading a number. **CIS Juniper 6.6.1.5 was left unmapped entirely**, because a
`>= 900` condition against a Junos value in minutes would fail every correctly
configured device, and a `>= 15` condition would pass a device configured for 15
seconds on any other vendor.

The fix was to normalise at the pattern-pack layer, where the EOS `idle-timeout`
minutes-to-seconds conversion already set the precedent, using the same
`minutes_seconds` coercion. What made it worth doing carefully rather than
casually is that it touches a live verdict: `V-215668`'s third condition became
the plain `gte 900` the STIG actually states, which is the same test expressed
against a number instead of a string. It was checked against every fixture
before and after — `fully_hardened.conf` passes, the other nine IOS fixtures
fail, exactly as they did. Two things the normalisation bought:

- **CIS Juniper 6.6.1.5 is now mapped** (`aaa.login_block gte 1800`). The Junos
  fixture configures `lockout-period 15`, which is 900 seconds, so it fails —
  correctly, and it is a fail the tool previously could not see at all.
- **CIS PAN-OS 1.4.2 tightened** from a presence check to `gt 0`, which is what
  the benchmark says ("a non-zero organization-defined value") rather than what
  the vocabulary could safely express.

Also worth stating plainly: nothing was lost in the IOS evidence by filing an
int instead of the line. Every `CanonicalFact` carries `raw_text` independently
of `value`, so the evidence an auditor reads on that finding is still
`login block-for 900 attempts 3 within 120`.

**`mgmt.password_policy.name` can be filed from two stanzas that mean opposite
things.** On PAN-OS the path is filled either from the global password-complexity
block or from a per-user password profile. A per-user profile named on a device
whose global policy is absent is a *weaker* posture than a global policy with no
per-user profiles, and the fact does not record which stanza it came from.
**CIS PAN-OS 1.3.10 is left unmapped** rather than asserting on it, because a
presence check would pass the weaker configuration. Resolving it needs either two
distinct paths or a qualifier on the fact — a vocabulary change, not a rule change.

Three further PAN-OS groups are unmapped for reasons that are stated in the pack
header and are worth knowing when reading a PAN-OS report: the CIS 1.3.x per-class
password minimums (the canonical model records complexity as one boolean, not four
character-class counts), CIS 3.2 and 3.3 (HA link monitoring, for which no
canonical fact exists), and CIS 6.15–6.18 (zone protection —
`control_plane.protection` records that a profile is attached but not its SYN-cookie
action or flood thresholds).

### Three Junos facts were filed against the wrong contract; all three are fixed

Found while writing the Juniper Router NDM pack (§2.8). None of them was a rule
bug — the rules were reading the vocabulary correctly. Each was a *pattern* filing
something into a path whose contract said a different thing, which is the failure
mode a shared vocabulary is most exposed to and the hardest to see from either end
alone: the pattern author knows the platform, the rule author knows the framework,
and neither is looking at the path's other six emitters. They are recorded
together because the shape repeats.

**`logging.facility` held a facility code on six packs and a message class on
Junos.** On `arista_eos`, `cisco_asa`, `cisco_ios`, `cisco_nxos`, `fortinet` and
`paloalto_panos` the path holds an RFC 5424 *facility code* — `local7`, `local6`
— which says which of syslog's numbered channels the device transmits on. The
Junos pack was filing the *message class* of a `syslog` statement there:
`change-log`, `authorization`, `interactive-commands`, `any`. Those name which
events are selected, not which channel carries them; the two are orthogonal, and
a rule asserting `logging.facility in [local6, local7]` would have found
`change-log` and had no way to tell that it was reading an answer to a different
question.

**Verdict impact: none, and that is the point.** No rule in any of the thirteen
mapped benchmarks reads `logging.facility` — it is emitted for evidence and for
the canonical-coverage view. So this cost nothing, and it was found only because
the Juniper NDM STIG asks whether configuration changes, logins and commands are
each logged, and the honest answer needed something the path could not express.
The fix decomposes the Junos class into the four booleans the vocabulary already
had, or in one case needed:

| Junos statement | Now emits |
|---|---|
| `change-log` | `logging.config_changes` |
| `authorization` | `logging.login_success`, `logging.login_failure` |
| `interactive-commands` | `logging.commands` |
| `any` | all four |

`any` emitting all four is not a shortcut. `any` selects every class the daemon
produces, so a device configured that way *is* logging each of these things, and
a rule that reads the specific boolean should see true.

**`logging.commands` is a canonical path added for this pack, and only Junos emits
it.** Nothing in the vocabulary recorded "the device logs the commands
administrators run", as distinct from logging that they authenticated. Three
Juniper NDM controls turn on exactly that distinction, so the path was added
rather than overloading `logging.config_changes` — a command log and a
configuration-change log are different evidence, and a device can produce either
without the other. The consequence to know when reading a report: **on every
other vendor `logging.commands` is absent, not false.** FortiOS `set
cli-audit-log enable`, the PAN-OS configuration log and IOS `archive log config`
are the same property spelled differently and none is emitted yet, so any rule
reading this path must stay scoped to `juniper_junos` until they are. A rule that
read it with `on_missing: fail` across all vendors would fail six platforms for a
gap in the parser, not in the device — the exact shape of the trap the vocabulary
batch in PRODUCTION-ROADMAP.md §2.4 exists to close.

**`boot-server` was inflating the redundant-time-source count.** Junos
`boot-server` names the source queried once at startup to set the clock before
the NTP daemon begins disciplining it. The pattern emitted `time.ntp.server` from
it, and two rules — CIS Juniper 6.7.1 and DISA `V-217334` — read `count
time.ntp.server >= 2` as the number of *redundant ongoing* sources. A device
configured `boot-server 10.30.0.10; server 10.30.0.10;` has one time source and
counted as two, which is a false pass on a real availability control. It now
emits only `time.ntp.enabled`, which is the part of it that was always true. On
the Junos fixture `time.ntp.server` went 3 → 2; both rules still pass, now on a
genuine two-server count. The same defect class — one object counted more than
once because two patterns emit it — was caught prospectively in the `set`-format
RADIUS work described in §2.8, before it could ship.

### Five NX-OS facts were filed against the wrong contract; all five are fixed

The same defect class as the Junos three above, found the same way — by writing a
mapping pack (§2.9) and discovering that a control was undecidable from facts
that looked, from the pattern-pack side, entirely reasonable. Recording them
together is the point: two independent vendor packs each shipped several
wrong-contract fillings, which says the failure mode is structural and not a
lapse on one pack. What would actually catch the class is a check that no
mapping-pack test currently performs — for each canonical path, compare the
*shape* of what every pack emits into it (integer vs enum vs free string, and the
value set) and flag a path whose emitters disagree. `TODO(verify):` no such
check exists yet and it is not on the roadmap; it is proposed here because
"be more careful" is what was already being done both times.

**`mgmt.password_policy.complexity` defaulted to the wrong polarity, and this one
did move verdicts.** NX-OS enables password strength checking by default and
prints nothing when it is on; the only line that appears is the negation, `no
password strength-check`. The pack's `defaults:` entry filed the absent case as
`false`, so every NX-OS switch that had never touched the setting — that is,
every compliant switch — was reported as failing CIS 1.4.1. Both publishers say
so outright: CIS 1.4.1's `default_value` opens "Password strength checking is
enabled by default. When enabled, this setting does not appear in the
configuration", and DISA V-220489 through V-220492 all read "Password complexity
is enabled by default … The following command should not be found in the
configuration: no password strength-check."
This is the one entry here with a verdict impact, and the direction matters: it
was manufacturing findings against compliant devices, which is the failure a
compliance tool is least able to detect from its own output, because a report
full of findings looks like a tool doing its job.

**`file.config_archive` was emitted by `feature scp-server` and `feature
sftp-server`.** Those lines turn on the daemons that let *other* devices copy
files to and from this switch. They say nothing about whether this switch backs
its own configuration up, which is what the path means on every other pack and
what DISA V-220514 asks. Both patterns were deleted, and the path is now emitted
from the EEM applet that actually performs the backup — the mechanism DISA's
check text walks the reviewer through, and the only one NX-OS has, since it has
no `archive` stanza.

**`logging.facility` was being filled from `logging level`.** `logging level
authpri 6` sets the severity at which one *facility's* messages are generated; the
pattern filed the facility name into `logging.facility`, whose contract is the
RFC 5424 channel the device transmits on — `local6`, `local7`. Same word,
different question, and the Junos entry above is the same mistake on a different
platform. The facility name now decomposes into the event booleans the vocabulary
already had (`logging.login_success`, `logging.login_failure` from `authpri`),
which is what makes V-220508 and V-220510 decidable, and `logging.facility` is
emitted from `logging server … facility …` where NX-OS actually states it.

**`time.ntp.key` held the key *number*.** On `cisco_ios`, `cisco_asa` and every
other pack that path holds the digest *algorithm* — `md5`, `sha1` — and the
number lives at `time.ntp.key_id`. The NX-OS pattern read `ntp
authentication-key 7 md5 …` and filed the `7`. DISA V-220502 is a permanent
finding on this platform precisely because the algorithm can only ever be MD5, so
the one control that turns on this path could not be written until the path held
the thing it is named for. The ASA pack carried the identical defect and was
corrected in the same change.

**`snmp.v3_priv` held the literal string `enforced`.** It was being emitted from
`snmp-server globalEnforcePriv`, which is a switch-wide *security level*
requirement, not an algorithm. On every other pack `snmp.v3_priv` holds the
privacy algorithm — `aes-128`, `des` — and PAN-OS's pack states that contract in
as many words. The consequence was that the only value the path could take on
NX-OS was a word that is not an algorithm, so V-220501 ("is SNMP encrypted with a
FIPS 140-2 approved algorithm") had no fact that could answer it. The algorithm
now comes off the `snmp-server user … priv aes-128` line where NX-OS writes it,
and the enforcement flag moved to `snmp.group_security`, which is where the other
packs record a required security level.

**Verdict impact of the other four: none at the time of the fix**, because no
rule read the NX-OS values — which is exactly why they survived. A path with one
emitter and no reader is unfalsifiable; it becomes wrong the moment someone
writes the rule that was supposed to use it, and by then the pattern looks
settled.

---

## 4. Framework and platform scope

### Frameworks

Two numbers are easy to conflate, so both are given. **Catalogs built** is how
much publisher material has been normalised into `ControlCatalog` form — it
bounds what *could* be assessed. **Controls automated** is how many have a rule
that evaluates against the canonical model. Only the second produces findings.

| Framework | Catalogs built | Controls in catalogs | How it is evaluated | Controls automated |
|---|--:|--:|---|--:|
| CIS | 7 | 629 | Direct — rules evaluated against the canonical model | 242 across 6 of 7 benchmarks |
| DISA STIG | 33 | 1,602 | Direct | 212 across 7 of 33 benchmarks |
| NIST SP 800-53 | 1 | 1,014 | Projected — rolled up from direct contributors | bounded by the above |
| ISO/IEC 27001 | 1 | 121 | Projected | bounded by the above |

**42 catalogs, 3,366 controls normalised, 454 automated (13.5%).** That ratio is
the honest statement of where this project stands: the publisher corpus is
ingested broadly and the rule authoring is deep on Cisco IOS and shallower on the
six other platforms. It is quoted here rather than buried because the alternative
framings — "78.9% of the CIS Cisco IOS 15 benchmark", or "every one of the seven
supported vendors is mapped" — are also true and much more flattering, and a
reader deserves all three. Regenerate any of the figures with:

```bash
.venv/Scripts/python.exe scripts/build_catalog.py --list
```

That command is read-only; it loads the built catalogs and the shipped mapping
packs and prints controls alongside automated controls per catalog. It never
prints one without the other, because a catalog inventory on its own overstates
what the tool assesses.

The projected frameworks are derived by roll-up over their contributing direct
findings (`backend/rules/projection.py`), so their coverage is bounded by the
direct packs beneath them, and the table above reports `0` for them because they
have no rules of their own — the count is a property of the device, not of the
catalog. Measured on `realistic/enterprise_complex.conf`, the two Cisco IOS packs
project onto **33 of 1,014 NIST controls** and **15 of 121 ISO controls**. A
different device reaches a different number, which is why no single figure is
quoted for them here.

Almost all of that projection comes from the DISA pack rather than the CIS one.
Every DISA control carries a CCI and a NIST 800-53 reference in its published
XCCDF, and roughly 45% carry an ISO mapping; the CIS Cisco IOS catalog carries
none of the three. So until the Router NDM pack was written, NIST and ISO
reported 100% `notchecked` on every device — a built catalog, a rendered tile in
the report, and not one verdict behind it. That state is now asserted against by
`tests/test_rules_mapping.py::test_every_direct_framework_produces_a_verdict`.

**That guarantee is per-estate, not per-device, and the difference used to be a
real gap.** The test passes as long as *some* device produces a verdict in each
direct framework, so at one point it was satisfied by the Cisco IOS and Arista
fixtures alone while five of the seven vendors reported two empty governance
tiles. Six of the seven now have a DISA pack behind them. Measured per vendor, on
the shipped fixture for each:

| Vendor | Direct packs behind it | NIST controls reached | ISO controls reached |
|---|---|--:|--:|
| `cisco_ios` | CIS IOS 15 + DISA Router NDM | 33 | 15 |
| `arista_eos` | DISA EOS NDM + L2S | 33 | 13 |
| `cisco_nxos` | CIS NX-OS + DISA NX-OS Switch NDM | 31 | 16 |
| `cisco_asa` | CIS ASA + DISA ASA NDM | 28 | 14 |
| `juniper_junos` | CIS Juniper + DISA Juniper Router NDM | 25 | 9 |
| `fortinet` | CIS FortiGate + DISA FortiGate NDM | 23 | 13 |
| `paloalto_panos` | CIS PAN-OS only | **0** | **0** |

Read the mechanism, not the vendor: a device reaches NIST and ISO only through a
**DISA** pack, because that is the only publisher corpus in this project that
ships cross-references. Every DISA control carries a CCI and a NIST 800-53
reference in its published XCCDF and roughly 45% carry an ISO mapping; no CIS
catalog carries any of the three. So a vendor's governance coverage is a direct
function of whether its NDM STIG has been mapped, and the spread between the
mapped vendors above is mostly pack size (39 rules on NX-OS, 34 on Junos) rather
than anything about the devices.

PAN-OS is the one vendor still reporting `—` with every governance control
`notchecked`, and it is not an authoring backlog item: **no Palo Alto STIG exists
in the corpus at all**, so there is nothing to map. Its DISA tile shows an em dash
with a `notchecked` count of *zero* — nothing in scope — which is a different
statement from an em dash with a large count, and that count is the only thing
distinguishing them in the report.

Seven DISA benchmarks are mapped. The remaining twenty-six are the next authoring
target, and the catalogs are already in place for all of them:

| Catalog | Controls | Status |
|---|--:|---|
| `disa_stig_cisco_ios_router_ndm_…_v3r8` | 35 | **32 mapped** — 3 unmapped, §2.1–§2.3 |
| `disa_stig_cisco_asa_ndm_…_v2r5` | 47 | **44 mapped** — 3 unmapped, §2.5 |
| `disa_stig_cisco_nx_os_switch_ndm_…_v3r6` | 42 | **39 mapped** — 3 unmapped, §2.9 |
| `disa_stig_arista_mls_eos_4_x_ndm_…_v2r2` | 21 | **17 mapped** — 4 unmapped, all argued in the pack header |
| `disa_stig_juniper_router_ndm_…_v3r2` | 49 | **34 mapped** — 15 unmapped, §2.8 |
| `disa_stig_fortinet_fortigate_firewall_ndm_…_v1r5` | 60 | **35 mapped** — 25 unmapped, §2.7 |
| `disa_stig_arista_mls_eos_4_x_l2s_…_v2r3` | 18 | **11 mapped** — 7 unmapped: one wants 802.1X, six are layer-2 features (DAI, IGMP snooping, native/default-VLAN hygiene) the EOS pattern pack does not file yet |
| `disa_stig_cisco_ios_switch_ndm_…_v3r8` | 35 | not started; **highest value of the unmapped set** — largely the same CISC-ND-* control set as the Router NDM pack. Measured: of the Router pack's 32 rules, **29 have a same-text counterpart** under a *different* V-number and **3 have none**, so this is a 29-rule id remap, not an `applies_to` change — every V-number differs (`V-215662` → `V-220570`). Unlike the CIS IOS XE case that renumbering fails loudly: none of the router V-numbers exist in the switch catalog, so a mechanical port cannot load |
| `disa_stig_cisco_nx_os_switch_l2s_…_v3r4` | 22 | not started; layer-2 features, the same category as the EOS L2S remainder |
| `disa_stig_cisco_ios_switch_l2s_…_v3r2` | 22 | not started; same category |
| `disa_stig_arista_mls_eos_4_x_router_…_v2r2` | 75 | not started; BGP/MSDP/MPLS and perimeter-filter controls, the same category as the RTR benchmarks below |
| `disa_stig_cisco_ios_router_rtr_…_v3r4` | 92 | not started; dominated by ACL-content, perimeter and multicast controls a config parse cannot decide |
| `disa_stig_cisco_nx_os_switch_rtr_…_v3r4` | 78 | not started; same caveat as RTR above |
| `disa_stig_cisco_ios_switch_rtr_…_v3r3` | 53 | not started; same caveat as RTR above |

The RTR rows are listed last rather than by size on purpose: they are the largest
remaining catalogs and the least decidable, because a router STIG is mostly about
what an ACL or a route filter *contains* and about neighbours a configuration file
does not name. Mapping them would add the most controls and the least value per
control — the opposite of the ordering a coverage percentage would suggest.

**No Palo Alto STIG exists in the corpus at all**, which is why
the PAN-OS fixture reports DISA STIG as `—` with a `notchecked` count of zero
rather than a large one: nothing is in scope, as opposed to in scope and unmapped.
The two cases render identically and the `notchecked` count is the only thing that
distinguishes them.

`realistic/telnet_exposed.conf` is kept as the fixture the Cisco IOS rules will be
validated against — its header lists the specific V-IDs it is built to trip.

### The governance denominator is the full catalog, not a baseline

Every figure above measures NIST 800-53 against **all 1,014** current controls.
That is the denominator PRAMAN can defend from what is on disk, and it is not the
one an auditor uses.

Real assessments scope SP 800-53 to a **baseline** — the subset that applies at a
given impact level — so a router is never judged against `PS-03` *Personnel
Screening* or the 714 enhancements that are out of scope for a moderate-impact
system. Measured across the whole fixture corpus, the crosswalk projection
decides **43 of 1,014** NIST controls (4.24%) and **21 of 121** ISO controls
(17.36%); the NIST 1,014 breaks down as **300 base controls and 714
enhancements**, the ISO 121 has no enhancements. Both figures, and that
composition, are published in `reports/metrics/rule_latency.json` under
`results.governance_reach`.

**The baseline allocation is not in this repository and was never derivable from
it.** `data/frameworks/oscal/sp80053.json` is the SP 800-53 *catalog*: it carries
what each control requires, not which baseline selects it. Its only `prop` names
are `label`, `method`, `sort-id`, `implementation-level`, `alt-identifier`,
`contributes-to-assurance`, `aggregates`, `status`, `alt-label` and `keywords` —
`implementation-level` is organization/system/mixed, a different axis. The
normalised catalog has `impact == ''` and `profile is None` for all 1,014
controls. The allocation is published in **SP 800-53B** as three separate OSCAL
profiles, and fetching them is `MANUAL_COMMANDS.md` **Step 16**.

So there is no MODERATE-scoped percentage in this project, and there is
deliberately no estimate of one. `MASTER_PROMPT.md` §10.1 states LOW 149 /
MODERATE 287 / HIGH 370, but that is the spec's expectation rather than a
measurement taken here, and writing it into a published metric would be a
fabricated citation under R1.1. `backend/frameworks/baseline.py` therefore
degrades the way every other optional artefact in this project does:
`load_baselines()` returns `{}`, `scope_to_baseline()` returns `None` rather than
an empty set — so a caller cannot silently divide by an empty baseline — and the
metric writes the reason into the field where the number would have gone. Run
Step 16 and the scoped figure appears with no code change.

`docs/PRODUCTION-ROADMAP.md` §3.4 originally claimed this scoping "costs almost
nothing" because the catalog was "already on disk", and quoted a denominator of
1,196. Both are corrected there: 1,196 is the raw `sort-id` count including 182
withdrawn controls, and 1,196 − 182 = 1,014.

### The ATT&CK mapping is PRAMAN's editorial judgement, and nothing else in the report is

`data/frameworks/attack/canonical_map.yaml` asserts which canonical
configuration paths imply which MITRE ATT&CK technique. **No publisher asserts
this.** MITRE's own published mappings cover NIST 800-53 and the CIS Critical
Security Controls; neither covers CIS Cisco IOS 15 or the DISA network-device
STIGs, and a scan of all 42 normalised catalogs for `T####` tokens returns
nothing. So the association was authored by this project, and the `threat_appendix`
in `findings.json` carries a `disclaimer` field saying so before anything else.

This is the **only** claim in a PRAMAN report that does not trace to a publisher.
Control text, severities where the publisher states them, remediation references,
technique names, descriptions, URLs and mitigations are all read from the
publishers' own documents and bundles. The editorial surface was deliberately
narrowed to one thing — path → technique — and the narrowing was not cosmetic:
an earlier draft also hand-listed the mitigations per technique, and checking
that draft against the ATT&CK bundle's own `mitigates` relationships found five
wrong pairings (M1026 attributed to T1602.001/.002, M1054 to T1556.004, M1051 to
T1601.001/.002). Every one was plausible. `mitigations_for()` derives them from
the bundle now, and a test fails if the YAML ever asserts one again.

**What is not mapped, and why that is not a gap to close.** The `logging.*` and
`aaa.accounting_*` families — 25 of the 177 distinct paths the rule pack reads,
the largest single block — carry no technique. A device that does not log is not
thereby exposed to a technique; it is exposed to the technique going *unnoticed*.
ATT&CK models adversary behaviour, not detection posture, so filing "syslog is
not configured" under T1602 would assert the adversary gained something from it.
`time.ntp.*` is excluded at one remove, for the same reason: its security value
is that the timestamps on those logs can be trusted. `device.hostname`,
`interface.description`, `ha.*`, `stp.*`, `control_plane.*`, `acl.*` and the
interface-hygiene family are excluded as real controls with no adversary
technique that turns on them.

Consequently **`scripts/attack_coverage.py --check` does not fail on an unmapped
path.** It fails on a mapped prefix that matches *no rule*, which is a coverage
claim with nothing behind it — three were caught that way on the first pass. A
gate demanding full coverage would be a standing incentive to file the logging
family under T1602, which is the dishonest mapping the exclusion exists to
prevent.

**Measured reach.** 272 of 454 rules (59.9%) and 103 of the 177 distinct paths
those rules read — not 103 of the 330-path vocabulary, which is the larger and
easier-sounding denominator — join onto eight techniques: T1040, T1016, T1557,
T1556.004, T1601.001, T1601.002, T1602.001, T1602.002. Only `fail` findings are
annotated — a pass is not a
technique an adversary performed, `notchecked` is honest absence and must not
render as exposure any more than it renders as PASS, `notapplicable` means the
control does not govern the device, and `error`/`unknown` describe the tool's
state rather than the device's. Published in
`reports/metrics/attack_coverage.json`.

### Excluded publisher documents

Not in the catalog at all, and not counted in any coverage figure:

- **Platforms out of scope for a network-device auditor:** F5 BIG-IP, Akamai,
  IBM DataPower, Cisco ISE, Cisco ACI.
- **Three SRGs** whose requirements are policy or procedural rather than
  configuration-checkable.
- **Dell OS10 and HP FlexFabric STIGs** — skipped for lack of a `Vendor` enum
  value and a pattern pack. Adding a vendor is a data file, so these are
  tractable; they are simply not done.
- **ISO/IEC 27001 Annex A control titles** are not reproduced. The standard's
  text is copyrighted and not redistributable, so ISO findings cite control
  identifiers without titles. This is a licensing constraint, not an oversight.

### Vendors

All seven supported vendors have both a pattern pack and a mapping pack, so every
one of them produces a real compliance score rather than a wall of `notchecked`.
Depth varies a great deal, and this is the table to read before quoting any single
coverage number:

| Vendor | Benchmark mapped | Automated | In benchmark | Coverage |
|---|---|--:|--:|--:|
| `cisco_ios` | CIS Cisco IOS 15 v4.1.1 | 71 | 90 | 78.9% |
| `cisco_ios` | DISA STIG IOS Router NDM v3r8 | 32 | 35 | 91.4% |
| `arista_eos` | DISA STIG EOS NDM v2r2 | 17 | 21 | 81.0% |
| `arista_eos` | DISA STIG EOS Layer-2 Switch v2r3 | 11 | 18 | 61.1% |
| `cisco_asa` | CIS Cisco ASA 9.x v1.1.0 | 45 | 78 | 57.7% |
| `cisco_asa` | DISA STIG Cisco ASA NDM v2r5 | 44 | 47 | 93.6% |
| `cisco_nxos` | CIS Cisco NX-OS v1.2.0 | 38 | 62 | 61.3% |
| `cisco_nxos` | DISA STIG NX-OS Switch NDM v3r6 | 39 | 42 | 92.9% |
| `fortinet` | CIS FortiGate 7.4.x v1.0.1 | 22 | 64 | 34.4% |
| `fortinet` | DISA STIG FortiGate Firewall NDM v1r5 | 35 | 60 | 58.3% |
| `juniper_junos` | CIS Juniper OS v2.0.0 | 47 | 172 | 27.3% |
| `juniper_junos` | DISA STIG Juniper Router NDM v3r2 | 34 | 49 | 69.4% |
| `paloalto_panos` | CIS Palo Alto Firewall 11 v1.2.0 | 19 | 79 | 24.1% |

Two of those percentages need reading carefully rather than comparing, and one
pairing in the table is worth reading as a pair.

**The same FortiGate scores 34.4% against CIS and 58.3% against the DISA NDM
STIG.** Nothing about the device or the pattern pack changes between those two
numbers. CIS FortiGate 7.4.x spans the whole appliance — security profiles,
SD-WAN, VPN, WiFi, policy objects — while the NDM STIG scopes itself to the
management plane of the device as a network element, which is almost entirely
configuration-decidable. A coverage percentage is a statement about the
benchmark's subject matter at least as much as about this tool, which is why
this table exists instead of one headline figure.

**CIS Juniper OS is 172 controls and the lowest denominator-adjusted coverage in
the set, mostly because of what its §1 contains.** That section is platform
lifecycle and physical-security guidance — supported releases, image verification,
console access control, out-of-band management practice — none of which a running
configuration decides. The 125 unmapped controls are not 125 missed opportunities;
a large fraction are not automatable from this evidence at all, and the heatmap
axis names that section "Platform lifecycle" for exactly this reason.

**CIS Palo Alto is the lowest raw figure and the most tractable.** PAN-OS
configuration is set-command flat and parses cleanly; the unmapped controls are
concentrated in areas where one canonical fact would unlock several at once (see
the two unit contracts in §3). It is the best return per rule written of anything
in this table.

`cisco_xe` and `cisco_xr` are in the `Vendor` enum and reach the ingestion layer,
but have no mapping pack. A CIS Cisco IOS XE 17.x catalog (84 controls) is built
and unmapped. This was previously described here as "the closest thing this
project has to free coverage, since IOS XE configuration syntax is near-identical
to IOS 15 and most of the 71 existing rules would port with only an `applies_to`
change". **The syntax half is true; the porting half was wrong and has been
corrected.** CIS renumbers control ids between the two benchmarks: of the 71
controls the IOS 15 pack decides, 49 keep both id and title in IOS XE, **12 keep
the title but change id**, and 10 have no XE counterpart. IOS 15 `1.1.6` is
"login authentication for 'line vty'"; IOS XE `1.1.6` is an accounting control.
Both ids exist in both documents, so an `applies_to`-only port would load
cleanly and then decide 12 controls by running the wrong check — a confident
verdict against a control that was never tested. A safe port reaches 61 of 84,
and needs an explicit old→new id map. See `docs/PRODUCTION-ROADMAP.md` §2.2 for
the full measurement.

`rules/control_bindings.lock.json` now pins the title each rule's target control
carried when the rule was authored, for all 454 bindings, so this class of
silent re-pointing fails a test rather than reaching a report.

It is listed as not started rather than quietly counted.

A configuration from a vendor with no pattern pack is detected as unclaimed and
reported as such rather than mis-parsed by the nearest available pack.

**What the fixture corpus does and does not prove about these packs.** Each
non-IOS vendor has exactly one fixture, and a fixture and its pack written in the
same change parse each other perfectly by construction. So zero unparsed lines on
the six multi-vendor fixtures is weaker evidence than the same figure on Cisco IOS,
where five fixtures written at different times exercise the pack from different
directions. More precisely: of the 454 automated controls, 102 are exercised in
**both** the passing and failing direction and all 102 are Cisco IOS; the other 352
are exercised in at most one direction — 316 pass-only, 34 fail-only, and one
(DISA STIG NX-OS NDM V-220515) reached only as `notapplicable`. A one-direction
control catches a rule that stopped firing entirely. It cannot catch a rule that
fires and returns the wrong verdict. Closing that needs a hardened/violating
fixture pair per vendor under `test_configs/compliance_extremes/`, at which point
`tests/test_rules_mapping.py::test_every_control_is_exercised_in_both_directions`
promotes the vendor into the strong tier automatically — the bar is data-driven,
not a list.

---

## 5. Evidence limits inherent to config-only input

These are not defects. They are what a running configuration can and cannot
tell you, and the tool reports them as `unknown` rather than guessing.

**CIS 2.1.1.1.3 (RSA modulus ≥ 2048)** returns `unknown` on four of the five
`realistic/` fixtures and on the stacked-switch fixture.
`crypto key generate rsa` is an exec-mode command; the resulting key is not
recorded in `show running-config`. Rendering this as `pass` would assert something
the evidence does not contain. To resolve it, upload
`show crypto key mypubkey rsa` output alongside the config.

That is not a hypothetical instruction — it is the one gap in this document with a
worked demonstration. Five fixtures do supply the key material, and the control
decides correctly on all five: `pass` at 2048 on `fully_hardened` and
`router_with_show_version`, `pass` at 4096 on `crypto_ipsec_isis` and
`enterprise_complex`, and `fail` at 1024 on `fully_noncompliant`. Same rule, same
device model, more evidence — so `unknown` here means the input was incomplete, not
that the check is unimplemented. It is also the only `unknown` any shipped fixture
produces, across all seven vendors and 454 automated controls.

**Serial numbers and hardware inventory** are parseable but empty on every
config-only upload, because `show running-config` does not contain them. Device
identity in a report is only as complete as the evidence supplied; upload
`show version` and `show inventory` to populate it.

**Unparsed lines are reported, never dropped** — 44 lines spanning 34 distinct
commands across the sixteen shipped fixtures. Constructs no shipped rule reads
(route-maps, prefix-lists, BGP peering, `snmp-server ifindex persist`,
`switchport trunk encapsulation`, `radius-server retransmit`, routing-protocol
`network` statements) are returned with their line numbers rather than silently
discarded, because a parser that drops what it does not understand is
indistinguishable from one that understands everything. They are also the input to
the training module.

All 43 are on Cisco IOS fixtures; the six multi-vendor fixtures report zero. That
is a weaker result than it appears, and §4's *Vendors* subsection says why: each of
those fixtures was written alongside the pattern pack that parses it, so they agree
with each other by construction. A zero there means "nothing in this file surprised
its own pack", not "this pack handles the dialect".

---

## 6. Housekeeping

- **`mgmt.local_user.secret_type` was deleted from the vocabulary, and the reason
  is worth keeping.** It was read by no rule and emitted by four packs — holding
  the per-account hash algorithm on EOS (`sha512`), the storage format on the ASA
  (`pbkdf2` / `encrypted` / `nt-encrypted`), the literal keyword `phash` on
  PAN-OS, and on FortiOS the boolean `True`, because it was the anchor of the
  `config system admin` block. Four quantities, one path, no reader. The two that
  were genuinely a hash algorithm moved to `mgmt.local_user.hash_type`, which
  seven packs already emit and CIS Junos 6.6.12 already reads; PAN-OS's constant
  restated a keyword its own `hash_type` fact already carried and was dropped;
  the FortiOS anchor moved to `mgmt.local_user.secret`, the presence boolean it
  should always have been. The vocabulary went 331 → 330 and the corpus lost
  three facts, all of them the PAN-OS constant. This is the same failure as the
  five NX-OS mis-filings in §3: **a path with emitters and no reader is
  unfalsifiable**, and every emitter is free to mean something different until
  the day a rule needs one of them.

- **`reports/metrics/ai_abstention.json` records the environment it was measured
  in.** Its `tiers_available.tier3` is `true`, which is only true while a local
  `llama-server` is running. Stop the server and
  `tests/test_metrics_are_current.py` will correctly fail, because the published
  abstention figures no longer describe the machine. That is the intended
  behaviour — a metrics file that survived its own preconditions would be worse —
  but it surprises anyone who runs the suite on a machine with no model loaded.
  Re-measure with:

  ```bash
  .venv/Scripts/python.exe scripts/bench/run_all.py --only bench_llm_abstention
  ```

  Roughly 165 s with the server up, a few seconds without. The regenerated file
  records whichever tiers were actually reachable, so the suite goes green either
  way; what it must not do is publish tier-3 numbers on a machine that has no
  tier 3.

- **29 source files exceed the 500-line limit, by 7,780 lines in total, and this
  is a ratchet rather than a fix.** `GLOBAL_RULESET.md` §145 says every file is
  ≤500 lines; `backend/app/main.py` is 1,928, `backend/report/render.py` is
  1,303, `tests/test_api_surface.py` is 1,157. Splitting all 29 is a real
  refactor with real regression risk and it is not what was in front of us, so
  `scripts/check_deliverable_limits.py` records each file at its current length
  and fails if any of them **grows**, if a new file crosses 500, or if a paid-off
  entry is left behind pretending the ceiling is still there. `--lower` can only
  move an entry down; adding one has to be done by hand, in a diff, with a
  reason. So the honest claim is not "we comply" — it is "the debt is measured,
  published, and cannot get worse", which is the claim a gate can actually hold.
  A gate that went red on all 29 the day it landed would have been skipped within
  a week, and then the growth would be unchecked too.

---

## 7. Verification markers, in full

`GLOBAL_RULESET.md` R1.5 gives three markers for text that is not fully
established, and §236 makes one of them a release gate. This register is the
whole set, regenerated by `scripts/collect_unverified.py` and re-checked on every
test run by `tests/test_unverified_register.py`, which is the only form in which
"the marker count is low" is worth reading. It was hand-counted once, published
in the roadmap as *0 / 0 / 2*, and the first machine run over the same tree found
an order of magnitude more — the hand count had walked `backend/` and skipped the
pattern packs and the mapping packs, which is exactly where an author leaves a
note to self. A number only ever recomputed by the person who believes it is not
a measurement.

Everything below the sentinel is generated, including the rationale: it names the
shipped roots and quotes each allowlist reason, and prose about a list drifts
from the list.

```bash
.venv/Scripts/python.exe scripts/collect_unverified.py --check
```

<!-- BEGIN GENERATED: unverified-register -->

Regenerated by `scripts/collect_unverified.py`, which separates two things that look identical in a grep. A marker in a **shipped** root — `backend/`, `frontend/`, `rules/`, `data/ingest/` — is a defect, because that text reaches an operator through the UI, a finding rationale or the signed PDF; it fails `--check` and never appears below. The same marker in a **document** is a disclosure, which is what R1.5 asked for, so it is published rather than punished.

**16 disclosed, 0 blocking.** `ASSUMPTION:` is exempt from blocking everywhere, including shipped roots: R1.5 defines it as a decision taken in the absence of data, which is a permanent property of that decision rather than an open task — a rule pack whose rationale tells the auditor which way it resolved an ambiguity is doing the right thing.

One exemption is granted by name rather than by kind: `praman/backend/frameworks/cis/extract.py` / `UNVERIFIED`. Sentinel *value*, not a note to self. When a CIS section number is unreadable in the PDF text layer, the extractor records the string rather than inventing a number (R1.7). Removing it would mean guessing, so the marker is the correct behaviour and the register exists partly to keep it legible.

| File | Line | Marker | Text |
|---|--:|---|---|
| `MANUAL_COMMANDS.md` | 48 | `TODO(verify)` | - `TODO(verify):` marks a value I could not confirm from the research corpus. **Resolve it before relying on it** — do not let a guessed filename into a build.  |
| `MANUAL_COMMANDS.md` | 851 | `TODO(verify)` | # TODO(verify): exact asset filenames for build b10610 (the Windows CUDA zip and the |
| `MANUAL_COMMANDS.md` | 866 | `TODO(verify)` | # TODO(verify): exact HuggingFace repo id and GGUF filename for |
| `MANUAL_COMMANDS.md` | 873 | `TODO(verify)` | # TODO(verify): the abetlen wheel index URL for llama_cpp_python-0.3.35-py3-none-win_amd64.whl. |
| `MANUAL_COMMANDS.md` | 1630 | `TODO(verify)` | 1. **Step 2 prints three non-zero counts.** `TODO(verify):` `MASTER_PROMPT.md` §10.1 states the allocation as **LOW 149 / MODERATE 287 / HIGH 370**. That figure |
| `MANUAL_COMMANDS.md` | 1676 | `UNVERIFIED` | \| `reports\metrics\*.json` \| Step 8a, Step 8c, `scripts\bench\*` \| any metric in docs/slides/PDF \| metric renders as `UNVERIFIED`; CI fails release \| |
| `MANUAL_COMMANDS.md` | 1730 | `TODO(verify)` | Every byte size, filename, version and count above was probed or parsed during the research phase and recorded under `.research\synth\`, with one exception note |
| `praman/README.md` | 271 | `TODO(verify)` | both, so this is not load cost. `TODO(verify):` the cause is not established — |
| `praman/backend/frameworks/cis/extract.py` | 495 | `UNVERIFIED` | f"Section recorded as UNVERIFIED.", |
| `praman/backend/frameworks/cis/extract.py` | 498 | `UNVERIFIED` | section_num = "UNVERIFIED" |
| `praman/data/ingest/patterns/cisco_nxos.yaml` | 1545 | `ASSUMPTION:` | is a poor fit. `ASSUMPTION:` a device with a non-timer trigger (`event |
| `praman/docs/GAPS.md` | 744 | `TODO(verify)` | value set) and flag a path whose emitters disagree. `TODO(verify):` no such |
| `praman/docs/PRODUCTION-ROADMAP.md` | 487 | `TODO(verify)` | > re-export byte-identical. §13.3's `TODO(verify)` on the SARIF field names is |
| `praman/docs/PRODUCTION-ROADMAP.md` | 532 | `TODO(verify)` | still carrying an explicit `TODO(verify)`. |
| `praman/docs/PRODUCTION-ROADMAP.md` | 1271 | `TODO(verify)` | No competitor reviewed publishes SARIF. Field names are still `TODO(verify)` in |
| `praman/rules/mappings/disa_stig/cisco_nx_os_switch_ndm_v3r6.yaml` | 583 | `ASSUMPTION:` | Blowfish, CAST, and CBC-mode AES. `ASSUMPTION:` this list is treated as |

<!-- END GENERATED: unverified-register -->

---

## How to read a PRAMAN report against this document

1. The compliance score covers **only** controls with an automated check that
   returned pass or fail. It is not a percentage of the benchmark.
2. `notchecked` counts are printed next to the score. A high count means low
   automation coverage, not a compliant device.
3. `unknown` means the evidence supplied could not decide the control. Supplying
   more evidence — `show version`, `show inventory`, `show crypto key` — moves
   controls out of `unknown` without changing a single rule.
4. `notapplicable` means the device is not subject to the control. It is
   excluded from the score in both directions.
5. Anything in this document is a gap in **the tool**, not in the device.
