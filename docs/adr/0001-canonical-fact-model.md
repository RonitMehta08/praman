# ADR 0001 — A canonical fact model between parsers and rules

**Status:** accepted · **Date:** 2026-08 · **Supersedes:** nothing

## Context

A compliance audit joins a device configuration (vendor grammar) to a benchmark
(prose about concepts). PS 26155 requires four frameworks (CIS, NIST SP 800-53,
DISA STIG, ISO 27001) and vendor-agnostic scalability across at least Cisco,
Juniper, Fortinet, Palo Alto and Arista.

The obvious implementation writes a checker per (vendor, benchmark) pair. Eight
vendors × four frameworks is thirty-two independent bodies of logic, each of
which has to be tested in both the passing and failing direction. The
combinatorics are not the real problem though — the real problem is that a rule
about `ip ssh version 2` gets rewritten five times, and the fifth copy is where
the wrong verdict lives.

## Options considered

**A. Direct vendor→benchmark checkers.** Fastest to a first demo: one vendor and
one benchmark can ship in a day with no abstraction to design. Rejected because
the second framework doubles the work and the second vendor doubles it again,
and because there is no single place to assert "this control is checked
consistently".

**B. Parse to a vendor-neutral AST, write rules against the AST.** Preserves
structure, which matters for a config-generation tool. Rejected: an AST is still
vendor-shaped (an IOS interface block and a JunOS `interfaces` stanza are
different trees), so rules end up branching on vendor anyway, and the AST is a
much larger contract to keep stable than a flat vocabulary.

**C. Normalise to a flat canonical fact vocabulary.** Every vendor's syntax maps
to the same dotted paths; every rule is written against paths only. Chosen.

## Decision

Facts are `(path, value, provenance)` triples over a closed vocabulary of
**330 dotted paths** (`backend/canonical/paths.py`). Rules reference paths and
never touch vendor syntax.

Consequences that follow mechanically:

- A new vendor is a **pattern pack** (`data/ingest/patterns/<vendor>.yaml`).
- A new benchmark is a **mapping pack** (`rules/mappings/<pack>/*.yaml`).
- Both are discovered by directory glob, so neither needs an engine change.

The DISA STIG pack was the test of this claim: 34 catalogs, 32 rules, and three
previously-unpopulated frameworks, added with **zero** lines of engine code.

## Costs we accepted

**The vocabulary is a bottleneck.** A control that needs a path nobody has
defined is blocked on a vocabulary decision, not on rule authoring — and
vocabulary decisions are the kind that are expensive to reverse once packs
depend on them. `docs/GAPS.md` §1.3 is a live example: `time.ntp.key_id` is
emitted by two different IOS directives, so a rule reading it cannot tell a
per-server key reference from a global key definition. That is a modelling
defect, and it exists because the path was named before both directives were
known.

**Flat paths lose within-record structure.** ACL entries are the case that
hurts: `acl.entry.action` and `acl.entry.source` arrive as independent facts, so
a rule cannot correlate them *within one entry*. Four CIS controls are
unautomated for exactly this reason (`GAPS.md` §1.1) and closing them needs a
`cross_reference` condition type — a rule-language change, not a rule.

We took these costs because they are **visible**: a missing path fails loudly at
authoring time, whereas the duplicated-rule failure mode of option A is a wrong
verdict that ships green.
