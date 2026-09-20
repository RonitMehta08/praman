"""Canonical path → MITRE ATT&CK mapping, and the join from rules onto it.

This is the half of the threat tier that `enrichment.py` has been waiting on.
`enrichment.py` reads `finding["references"]["attack"]` and looks the technique
up in the bundle; nothing in the shipped corpus populates that key, because no
publisher ships a control → technique crosswalk for network-device benchmarks.
This module supplies the missing association from
`data/frameworks/attack/canonical_map.yaml`, keyed on the canonical paths a rule
reads rather than on any publisher identifier.

**Three properties this module is built to hold, in descending order of how
badly it would matter to get them wrong.**

1. **Nothing here can reach a verdict.** There is no import of the evaluator, no
   reference to `Finding.result`, and no writer: every public function returns a
   new list or dict. A technique is an argument about why a failure matters, and
   `enrichment.py`'s docstring already makes the case for keeping arguments out
   of the column an auditor reads as a measurement. This module is on the far
   side of that line and stays there.

2. **The editorial surface is exactly one thing.** The YAML asserts which
   canonical paths imply which technique — PRAMAN's own judgement, labelled as
   such in the file header and in every rendering. Everything else the tier
   emits is the publisher's and is *derived at read time*: names, descriptions,
   URLs and kill-chain phases from `enrichment.load_attack_techniques()`,
   mitigations from the bundle's own `mitigates` relationships via
   `mitigations_for()`. An earlier draft of the YAML hand-listed mitigations and
   five of them were wrong — M1026 attributed to T1602.001/.002, M1054 to
   T1556.004, M1051 to T1601.001/.002 — each wrong in the plausible direction
   that survives review. Deriving them removed the entire class.

3. **Absent inputs degrade to empty, and empty is not zero.** A fresh clone has
   neither the 53.8 MB bundle (Step 4a) nor a reason to fail because of it.
   `load_canonical_map()` returns `{}` when the YAML is missing or malformed and
   `mitigations_for()` returns `[]` when the bundle is absent — the same
   honest-absence contract the AI tiers and `frameworks/baseline.py` use. The
   distinction that matters downstream: `[]` from `mitigations_for("T1016")`
   means *the publisher relates no mitigation to this technique*, which is true
   and measured, while `{}` from `load_canonical_map()` means *not loaded*.
   `coverage_report()` carries `map_loaded` and `bundle_loaded` so a caller can
   tell the two apart without guessing.

**Why the join key is a canonical path and not a finding's evidence.** Measured
on the 16-fixture corpus: 272 of the 561 failing findings (48%) carry empty
evidence, because the most common way to fail a hardening control is for the
directive to be absent from the configuration entirely. An evidence join would
have silently dropped half the failures and dropped precisely the half where the
device is least configured. `Rule.referenced_paths()` is known statically,
before any device is parsed, so the mapping is a property of the rule pack.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

import yaml

from backend.app.config import DATA_DIR, FILE_ENCODING
from backend.rules.models import Rule
from backend.threat.enrichment import ATTACK_BUNDLE_PATH

#: The editorial mapping. Beside the bundle it annotates, so that "where does the
#: ATT&CK story live" has one answer rather than two.
CANONICAL_MAP_PATH = DATA_DIR / "frameworks" / "attack" / "canonical_map.yaml"


def _prefix_matches(path: str, prefix: str) -> bool:
    """True when ``path`` is ``prefix`` or a child of it.

    The dot is load-bearing. A plain ``startswith`` would let the prefix
    ``mgmt.http`` claim a hypothetical ``mgmt.http_proxy``, which is a different
    control; and it would let ``snmp.user`` claim ``snmp.username``. Matching on
    the separator keeps a prefix inside its own subtree.
    """
    return path == prefix or path.startswith(prefix + ".")


@lru_cache(maxsize=1)
def load_canonical_map() -> dict[str, Any]:
    """Parse the editorial mapping.

    Returns ``{}`` when the file is absent, unreadable, not a mapping, or has no
    ``mappings`` list — absence is a supported state, not a failure. Loaded with
    ``yaml.safe_load``: this file is repository data today, but every loader in
    this codebase that can be pointed at a path is written as though the path
    were attacker-controlled.
    """
    if not CANONICAL_MAP_PATH.exists():
        return {}

    try:
        raw = yaml.safe_load(CANONICAL_MAP_PATH.read_text(encoding=FILE_ENCODING))
    except (yaml.YAMLError, UnicodeDecodeError, OSError):
        return {}

    if not isinstance(raw, dict) or not isinstance(raw.get("mappings"), list):
        return {}

    entries: list[dict[str, Any]] = []
    for entry in raw["mappings"]:
        if not isinstance(entry, dict):
            continue
        paths = [p for p in entry.get("paths", []) or [] if isinstance(p, str)]
        techniques = [t for t in entry.get("techniques", []) or [] if isinstance(t, str)]
        if not paths or not techniques:
            # An entry with paths and no techniques claims nothing; an entry with
            # techniques and no paths can never be reached. Both are authoring
            # slips, and neither should be allowed to look like coverage.
            continue
        entries.append(
            {
                "paths": paths,
                "techniques": techniques,
                "why": str(entry.get("why", "")).strip(),
            }
        )

    if not entries:
        return {}

    return {
        "version": raw.get("version"),
        "attack_bundle": str(raw.get("attack_bundle", "")),
        "authored_by": str(raw.get("authored_by", "")),
        "authored_on": str(raw.get("authored_on", "")),
        "mappings": entries,
    }


def mapped_prefixes() -> list[str]:
    """Every canonical-path prefix the mapping asserts something about."""
    doc = load_canonical_map()
    return sorted({p for entry in doc.get("mappings", []) for p in entry["paths"]})


def techniques_for_paths(paths: list[str] | set[str]) -> list[str]:
    """Technique IDs implied by a set of canonical paths, sorted and deduplicated.

    A path may sit under more than one prefix and legitimately imply more than
    one technique — ``service.boot_network`` is both a configuration-retrieval
    channel (T1602.002) and an image-substitution channel (T1601.*) — so the
    result is a union rather than a first match.
    """
    doc = load_canonical_map()
    hits: set[str] = set()
    for entry in doc.get("mappings", []):
        for prefix in entry["paths"]:
            if any(_prefix_matches(p, prefix) for p in paths):
                hits.update(entry["techniques"])
                break
    return sorted(hits)


def rationale_for_paths(paths: list[str] | set[str]) -> dict[str, str]:
    """The ``why`` sentence behind each technique a set of paths implies.

    Carried alongside the IDs deliberately. The link is PRAMAN's editorial
    judgement, and a judgement that travels without its argument is how an
    authored mapping starts being read as a publisher's.
    """
    doc = load_canonical_map()
    out: dict[str, str] = {}
    for entry in doc.get("mappings", []):
        for prefix in entry["paths"]:
            if any(_prefix_matches(p, prefix) for p in paths):
                for tid in entry["techniques"]:
                    out.setdefault(tid, entry["why"])
                break
    return out


def techniques_for_rule(rule: Rule) -> list[str]:
    """Technique IDs implied by everything ``rule`` reads."""
    return techniques_for_paths(rule.referenced_paths())


@lru_cache(maxsize=1)
def _mitigation_index() -> dict[str, list[dict[str, str]]]:
    """Technique ID → the mitigations the publisher relates to it.

    Built from the bundle's ``relationship`` objects with
    ``relationship_type == "mitigates"``, joining a ``course-of-action`` source
    to an ``attack-pattern`` target through their STIX ids. Deprecated and
    revoked mitigations and relationships are dropped here, which is the opposite
    of what `enrichment._index()` does with techniques — and deliberately so. A
    withdrawn *technique* still has to be reported when a finding cites it, or
    the finding silently loses the context it asked for. A withdrawn
    *mitigation* is never cited by anything; it would only ever be advice, and
    offering superseded advice is worse than offering none.

    This costs a second full parse of the 53.8 MB bundle (~0.5 s), cached for the
    life of the process. It is off the audit path entirely — only
    `coverage_report()` and `scripts/attack_coverage.py` reach it — so the cost
    lands on a reporting command rather than on an ingest.
    """
    if not ATTACK_BUNDLE_PATH.exists():
        return {}

    try:
        data = json.loads(ATTACK_BUNDLE_PATH.read_text(encoding=FILE_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}

    objects = data.get("objects", [])
    technique_ids: dict[str, str] = {}
    mitigations: dict[str, dict[str, str]] = {}

    for obj in objects:
        kind = obj.get("type")
        if kind not in ("attack-pattern", "course-of-action"):
            continue
        external_id = ""
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                external_id = str(ref.get("external_id", ""))
                break
        if not external_id:
            continue
        if kind == "attack-pattern":
            technique_ids[obj["id"]] = external_id
        elif not (obj.get("x_mitre_deprecated") or obj.get("revoked")):
            mitigations[obj["id"]] = {
                "id": external_id,
                "name": str(obj.get("name", "")),
                "url": f"https://attack.mitre.org/mitigations/{external_id}/",
            }

    index: dict[str, dict[str, dict[str, str]]] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        target = technique_ids.get(obj.get("target_ref", ""))
        source = mitigations.get(obj.get("source_ref", ""))
        if target and source:
            index.setdefault(target, {})[source["id"]] = source

    return {tid: [m[k] for k in sorted(m)] for tid, m in index.items()}


def mitigations_for(technique_id: str) -> list[dict[str, str]]:
    """Publisher-related mitigations for one technique, sorted by ID.

    An empty list has two causes and the caller can tell them apart by asking
    whether the bundle loaded at all. With the bundle present, `[]` is a
    measurement: T1016 System Network Configuration Discovery, for instance, has
    no ``mitigates`` relationship in v19.2, because discovery techniques abuse
    features working as designed and the publisher relates no preventive control
    to them.
    """
    return list(_mitigation_index().get(technique_id, []))


def coverage_report(rules: list[Rule]) -> dict[str, Any]:
    """Join the rule pack onto the mapping and describe the result.

    Everything a reader needs to judge the mapping rather than trust it: how many
    rules it reaches, which paths it reaches them through, which of its own
    prefixes match nothing (`dead_prefixes` — a coverage claim with nothing
    behind it, and what `--check` fails on), and which referenced paths it does
    not touch (`unmapped_paths` — mostly the logging and accounting families the
    YAML header argues should stay unmapped).
    """
    from backend.threat.enrichment import load_attack_techniques

    doc = load_canonical_map()
    techniques = load_attack_techniques()
    prefixes = mapped_prefixes()

    all_paths: set[str] = set()
    covered: set[str] = set()
    by_technique: dict[str, set[str]] = {}

    for rule in rules:
        paths = set(rule.referenced_paths())
        all_paths |= paths
        hits = techniques_for_paths(paths)
        if hits:
            covered.add(rule.id)
        for tid in hits:
            by_technique.setdefault(tid, set()).add(rule.id)

    matched_prefixes = {
        prefix
        for prefix in prefixes
        if any(_prefix_matches(path, prefix) for path in all_paths)
    }

    detail: dict[str, Any] = {}
    for tid in sorted(by_technique):
        known = techniques.get(tid, {})
        detail[tid] = {
            "name": known.get("name", ""),
            "deprecated": known.get("deprecated"),
            "rules": len(by_technique[tid]),
            "mitigations": [m["id"] for m in mitigations_for(tid)],
        }

    return {
        "map_loaded": bool(doc),
        "bundle_loaded": bool(techniques),
        "authored_by": doc.get("authored_by", ""),
        "attack_bundle": doc.get("attack_bundle", ""),
        "rules_total": len(rules),
        "rules_mapped": len(covered),
        "paths_total": len(all_paths),
        "paths_mapped": len({p for p in all_paths if techniques_for_paths({p})}),
        "techniques": detail,
        "dead_prefixes": sorted(set(prefixes) - matched_prefixes),
        "unmapped_paths": sorted(p for p in all_paths if not techniques_for_paths({p})),
    }
