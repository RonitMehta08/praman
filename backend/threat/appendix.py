"""The §22.4 threat appendix: failing findings, and what an adversary does with them.

`mapping.py` answers "which technique does this canonical path imply". This
module answers the question an operator actually asks — *given this audit, what
does the failing set mean* — by joining findings back onto the rules that decided
them and folding the result into an appendix that rides **alongside** the
findings rather than inside them.

**Alongside is the whole design, and it is a P12 constraint rather than a
preference.** `Finding` is `extra="forbid"` and `AuditRecord.merkle_root` is
computed over the serialised findings, so a `threat_intel` field on `Finding`
would change the Merkle root of every audit ever taken and force a ledger
reseed — to carry an editorial annotation that is not evidence. The appendix is
therefore a sibling key in the report envelope: the record, the root and the
signature are byte-identical whether it is present or not, and
`tests/test_threat_appendix.py` asserts exactly that rather than describing it.

**Only failing findings are mapped, and the omissions are load-bearing.**

* A **pass** is not a technique an adversary performed; it is one they cannot.
  Attaching T1040 to a passing SSH control would read, in a PDF, as though the
  device were being sniffed.
* **notchecked** is the honest-absence result, and absence of evidence must never
  render as a claim in either direction — attaching a technique to it would dress
  "PRAMAN could not decide" as "PRAMAN found exposure".
* **error** and **unknown** likewise: they describe the tool's state, not the
  device's.

That leaves `fail` and `notapplicable`, and `notapplicable` is excluded too — the
control does not govern this device, so the technique is not reachable *here*.

**The join key.** A finding carries `(framework, benchmark, control_id)`; a rule
carries `(catalog_id, control_id)`. Those do not meet directly — `benchmark` is
the publisher's verbatim title and `catalog_id` is a slug — so the catalogs are
used as the bridge, which is why `build_index()` takes them. Resolving through
the catalog rather than by string-matching titles means a benchmark whose title
contains an en dash, or which two catalogs share, cannot silently mis-join.
"""

from __future__ import annotations

from typing import Any

from backend.app.config import FEATURE_THREAT_ENRICHMENT
from backend.frameworks.catalog import ControlCatalog
from backend.rules.models import Rule
from backend.threat.enrichment import attack_version, load_attack_techniques
from backend.threat.mapping import load_canonical_map, mitigations_for, rationale_for_paths

#: Results that get an appendix entry. See the module note: everything else is
#: either not an exposure or not a measurement.
MAPPED_RESULTS = frozenset({"fail"})


def build_index(
    rules: list[Rule], catalogs: list[ControlCatalog]
) -> dict[tuple[str, str, str], set[str]]:
    """Index ``(framework, benchmark, control_id)`` → canonical paths its rules read.

    Paths rather than techniques, deliberately: a control's rules are the durable
    fact, and which technique those paths imply is a question for the editorial
    map, which may change without the rule pack changing. Keeping the index in
    terms of paths means a change to `canonical_map.yaml` needs no reindex and
    cannot leave a stale technique cached against a control.
    """
    by_catalog_id = {c.catalog_id: c for c in catalogs}
    index: dict[tuple[str, str, str], set[str]] = {}

    for rule in rules:
        if not rule.enabled:
            continue
        catalog = by_catalog_id.get(rule.catalog.catalog_id)
        if catalog is None:
            # A rule pointing at a catalog that is not loaded. The evaluator's
            # own `_validate_rule_targets` raises on this at construction, so
            # reaching it here means the caller assembled the two lists by hand;
            # skipping is right regardless, because there is no framework or
            # benchmark to key the entry on and inventing one would be worse.
            continue
        key = (catalog.framework, catalog.benchmark, rule.catalog.control_id)
        index.setdefault(key, set()).update(rule.referenced_paths())

    return index


def appendix_for_findings(
    findings: list[dict[str, Any]],
    rules: list[Rule],
    catalogs: list[ControlCatalog],
) -> dict[str, Any]:
    """Build the threat appendix for one audit's findings.

    Accepts findings as dicts — the shape both the CLI and the API already hold
    at the point the report envelope is assembled — and never mutates them. The
    returned structure is the whole contribution of the threat tier to an audit,
    and it is reachable from nothing that decides a verdict.

    Returns ``{}`` when the feature is off, when the mapping is unavailable, when
    the ATT&CK bundle is absent, or when nothing failing maps — so a caller can
    omit the key entirely and keep the envelope byte-identical. The feature gate
    lives here rather than at each call site, matching `enrich_findings`: one
    place to look for "why is the appendix missing", and no way for a second
    caller to forget it.
    """
    if not FEATURE_THREAT_ENRICHMENT:
        return {}

    doc = load_canonical_map()
    if not doc:
        return {}

    index = build_index(rules, catalogs)
    techniques = load_attack_techniques()
    if not techniques:
        # The bundle is absent or unreadable. Every field that makes a technique
        # id *readable* — name, url, the ATT&CK release that defined it — comes
        # from the bundle, and `mitigations_for` would return `[]` for the same
        # reason. Emitting the appendix anyway would put bare strings like
        # "T1602.001" in a report with no name, no link and no version, which is
        # not a citation: technique ids are revoked and renumbered between
        # releases, so an unversioned one cannot be checked by the reader.
        # Omitting the key says "not produced", which is true; a hollow appendix
        # would say "produced, and this is what we found".
        return {}

    by_technique: dict[str, dict[str, Any]] = {}
    controls: list[dict[str, Any]] = []

    for finding in findings:
        if str(finding.get("result", "")) not in MAPPED_RESULTS:
            continue
        key = (
            str(finding.get("framework", "")),
            str(finding.get("benchmark", "")),
            str(finding.get("control_id", "")),
        )
        paths = index.get(key)
        if not paths:
            continue
        rationale = rationale_for_paths(paths)
        if not rationale:
            continue

        controls.append(
            {
                "control_id": key[2],
                "framework": key[0],
                "benchmark": key[1],
                "title": str(finding.get("title", "")),
                "severity": str(finding.get("severity", "")),
                "techniques": sorted(rationale),
            }
        )
        for tid, why in rationale.items():
            entry = by_technique.setdefault(
                tid,
                {
                    "id": tid,
                    "name": techniques.get(tid, {}).get("name", ""),
                    "url": techniques.get(tid, {}).get("url", ""),
                    "deprecated": techniques.get(tid, {}).get("deprecated"),
                    "praman_rationale": why,
                    "mitigations": mitigations_for(tid),
                    "controls": [],
                },
            )
            entry["controls"].append(key[2])

    if not controls:
        return {}

    for entry in by_technique.values():
        entry["controls"] = sorted(set(entry["controls"]))

    return {
        # Read first by anyone deciding how much the rest of this is worth.
        "disclaimer": (
            "The control-to-technique association below is PRAMAN's own editorial "
            "judgement, recorded in data/frameworks/attack/canonical_map.yaml. No "
            "publisher ships a control-to-technique crosswalk for CIS or DISA "
            "network-device benchmarks. Technique names, URLs and mitigations are "
            "MITRE's, read from the local ATT&CK bundle. Nothing here affected any "
            "verdict: the appendix is derived from findings that were already "
            "decided, and no value in it can change a result."
        ),
        "attack_version": attack_version(),
        "authored_by": doc.get("authored_by", ""),
        "failing_controls_mapped": len(controls),
        "techniques": [by_technique[t] for t in sorted(by_technique)],
        "controls": sorted(controls, key=lambda c: (c["framework"], c["control_id"])),
    }
