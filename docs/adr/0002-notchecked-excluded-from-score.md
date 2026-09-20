# ADR 0002 — `notchecked` is a first-class verdict, excluded from the score

**Status:** accepted · **Date:** 2026-08

## Context

The CIS Cisco IOS 15 benchmark has 90 controls. PRAMAN automates 71. The other
19 need things a configuration file does not contain, or a rule-language feature
that does not exist yet.

There are three ways to report that, and only one of them is honest.

## Options considered

**A. Report "100% of what we check."** Omit the 19 from the output entirely. The
tool then reports 71 of 71 and looks perfect. This is technically true and
useless, and it is what most tools do — it is also self-reinforcing, because the
cheapest way to raise the number is to stop checking a hard control.

**B. Map them under-strict so they return a verdict.** Write a rule that checks
something adjacent and call it done. An earlier design did exactly this for CIS
3.1.4 and 3.2.2, mapping "uRPF / an inbound ACL is in use *anywhere*" for
controls the benchmark explicitly scopes to *the external interface*. Rejected
and reversed: an under-strict rule renders **PASS** and **counts toward the
score**, claiming an assurance the evidence does not support. A false PASS on a
control about the untrusted-network boundary is the worst output the tool can
produce.

**C. Return them as a distinct verdict, excluded from the score.** Chosen.

## Decision

`notchecked` is a `Result` value alongside `pass`/`fail`/`unknown`/`notapplicable`.
A control PRAMAN cannot decide is returned to the caller with a reason, appears
in the PDF report, and is **excluded from the compliance score in both
directions**.

The score is `pass / (pass + fail)`. Nothing else enters it.

The property that matters: **coverage cannot be improved by declining to check
something.** Dropping a control does not raise the score, because the control was
never in the denominator. Adding a rule can lower the score, which is the correct
incentive.

`unknown` is kept separate from `notchecked` and means something different: a
rule ran and the evidence was genuinely inconclusive. CIS 2.1.1.1.3 (RSA modulus
size) is the canonical case — `crypto key generate rsa` is an exec command, so a
running config does not record it. The rule exists and correctly declines to
decide; that is not the same as no rule existing.

## Enforcement

A policy nobody checks is a policy that decays, so this is asserted rather than
documented:

- `test_notchecked_controls_are_reported_not_dropped` fails if an unmapped
  control stops being reported.
- `test_every_direct_framework_produces_a_verdict` fails if a whole framework
  goes silent — the failure mode that let 32 DISA rules ship for a while with no
  false-verdict detector behind them at all, suite green throughout.
- `test_the_published_fixture_table_is_not_stale` re-measures the published
  numbers inside the test run.
- `docs/GAPS.md` argues all 22 unautomated controls **individually**, with what
  it would take to close each.

## Costs we accepted

**The headline number is worse.** 71 of 90 reads as less impressive than 71 of
71, and in a judged competition that is a real cost paid on purpose.

**`notchecked` totals need their own explanation.** 205 for DISA STIG looks
alarming until it is split: 3 are argued decisions about Router NDM controls, 202
belong to four STIG benchmarks with no mapping pack written yet. Those halves
mean different things — a judgement versus a roadmap item — so
`scripts/fixture_report.py` publishes them as separate columns. One number
covering both would let a missing pack read as a considered decision, which is
option A wearing this ADR's clothes.
