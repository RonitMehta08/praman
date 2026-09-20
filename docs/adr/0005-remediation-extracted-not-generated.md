# ADR 0005 — Remediation CLI is extracted from the publisher, never generated

**Status:** accepted · **Date:** 2026-08

## Context

PS 26155 C4 asks for "device-specific step-by-step remediation CLI". The output
is a list of commands an operator will paste into a production router.

A local LLM is already in the project for C2. Generating remediation commands
with it would be a few hours' work and would produce fluent, tailored,
device-specific CLI for every finding, including the ones no publisher wrote fix
text for.

## Why we did not

Remediation output goes onto **production network equipment**. A plausible-looking
wrong command does not fail loudly:

- `access-list 10 deny any` before the permit lines locks out the management
  plane. The device is now unreachable and the command looked right.
- A generated `snmp-server community` line that drops the ACL argument silently
  widens exposure while appearing to fix the control.

A hallucinated audit *finding* is embarrassing. A hallucinated `no` command on a
core switch is an outage, and the tool has no way to tell the operator which of
its suggestions was invented. Fluency is precisely the wrong quality here: it
removes the reader's only signal that something is off.

There is also a provenance argument. PRAMAN's claim is that a finding traces to
published benchmark text. A generated fix breaks that chain at the point where
the operator acts on it — the one step where being able to check the source
matters most.

## Options considered

**A. Generate all remediation with the LLM.** Best coverage, best-looking output.
Rejected above.

**B. Generate only where the publisher wrote no fix text, labelled as generated.**
Superficially the right compromise. Rejected because the label does not survive
contact with reality: output gets copied into a change ticket, the ticket loses
the label, and the distinction that made it safe is gone. A tri-state that says
"the publisher has nothing here" is more useful than a fourth state that says
"this was invented, be careful."

**C. Extract from the publisher's own `fix_text` only.** Chosen.

## Decision

`backend/remediation/engine.py` parses CLI out of the publisher's `fix_text`
(CIS remediation sections, DISA STIG fix text). Nothing is synthesised.

`kind` is a **tri-state**, and it is the honesty mechanism:

| `kind` | Meaning |
|---|---|
| `cli` | Commands were extracted from the publisher's text |
| `manual` | The publisher wrote prose only — no commands exist to extract |
| `none` | Neither source has anything for this control |

A blank block is never returned as though it were a fix. `manual` carries the
publisher's prose so the operator has something to act on; `none` says so
plainly.

**Precedence is catalog-first.** The hand-authored `PLAYBOOK` never overrides
publisher CLI — it only *adds* `verification`, `rollback` and `risk_of_fix`,
which are operational metadata the benchmarks do not provide. This ordering is
the whole ADR in one line: the publisher owns what to type, PRAMAN owns how to
check it worked and how to back it out.

Device-specific substitution is **textual and declared**: hostnames and
interface names are filled from the parsed config, and `placeholders` +
`requires_substitution` tell the operator which values they still have to
supply. `is_runnable` is false for any step with an unfilled placeholder, so
"paste this" and "edit this first" are distinguishable by a machine and not just
by reading.

## Costs we accepted

**Coverage is bounded by the publishers.** Controls whose fix text is prose come
back `manual`, and there is nothing to be done about that within this decision.
On the shipped sample: 15 failing controls, 15 `cli`, 18 commands, 13 runnable
without substitution — better than expected, because NDM STIG fix text is
unusually command-heavy.

**Extraction is brittle.** Parsing CLI out of prose written for humans breaks on
unusual formatting. It fails toward `manual` rather than toward a wrong command,
which is the correct direction, but it does mean the `cli`/`manual` split moves
when a catalog is updated.

**No cross-control ordering.** Steps are sorted worst-severity-first, not
dependency-ordered — the tool does not know that an AAA change must precede a
`line vty` change. A generated plan could have attempted that, and would
sometimes have been wrong about it in ways that lock out the management plane.
Severity order is honest about what it is: a priority list, not a runbook.
