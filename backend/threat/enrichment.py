"""Threat intelligence enrichment — MITRE ATT&CK mapping.

Enriches findings with ATT&CK technique metadata.
Uses the enterprise-attack STIX JSON bundle for offline lookups (SPINE §21).

**This tier is context, never a verdict.** `enrich_findings` adds a
`threat_intel` key and touches nothing else; no value it produces can change a
`Finding.result`, and there is no code path from this module into the evaluator.
An ATT&CK technique is an argument about *why* a failure matters, and arguments
do not belong in the column an auditor reads as a measurement.

Two things about this module that are easy to misread:

1. **The bundle is not in the repository.** `ent.json` is 53.8 MB and matched by
   the workspace `.gitignore`, so a fresh clone does not have it and
   `load_attack_techniques()` returns `{}` — the same honest-absence contract the
   AI tiers use. `MANUAL_COMMANDS.md` Step 4a copies it in, and Step 4a's own
   artifact table already records the degradation as "enrichment omitted,
   findings unaffected".
2. **Nothing in the shipped corpus emits `references["attack"]` yet.** No CIS
   catalog, no DISA XCCDF and neither crosswalk carries an ATT&CK technique ID —
   checked by scanning all 42 normalised catalogs for `T####` tokens, which
   returns nothing. So with the bundle present and the flag on, this function is
   still a no-op: it is waiting on a control → technique mapping, not on a bug.

   That mapping is specified rather than open-ended. `MASTER_PROMPT.md` §22.4
   names the technique set for network devices, and every ID in it was checked
   against the local v19.2 bundle on 2026-09-09 — all eight techniques
   (`T1040` Network Sniffing, `T1556.004` Network Device Authentication,
   `T1601.001` Patch System Image, `T1601.002` Downgrade System Image,
   `T1602` Data from Configuration Repository, `T1602.001` SNMP (MIB Dump),
   `T1602.002` Network Device Configuration Dump) and all nine mitigations
   (`M1026`, `M1030`, `M1031`, `M1032`, `M1037`, `M1041`, `M1046`, `M1051`,
   `M1054`) resolve, and none is revoked or deprecated. The spec carried them
   with a `synth:` marker, meaning unverified at the time of writing; they are
   verified now, against the publisher's own bundle rather than against memory.
   Authoring the rule-to-technique mapping is what remains, and it will be
   labelled PRAMAN's own editorial judgement — MITRE publishes no
   control → technique crosswalk for CIS or DISA network-device benchmarks.

The path in this module was wrong until 2026-09-09 — it read
`frameworks/enterprise-attack.json` while Step 4a writes
`frameworks/attack/ent.json`. The failure was silent by construction: a missing
bundle and a mistyped path produce the same `{}`, which is the general hazard in
any loader whose absent case is legitimate. `tests/test_threat_enrichment.py`
now pins the path against the location Step 4a documents.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from backend.app.config import DATA_DIR, FEATURE_THREAT_ENRICHMENT, FILE_ENCODING

#: Where ``MANUAL_COMMANDS.md`` Step 4a puts the Enterprise bundle. Not a
#: guess and not configurable: one documented location means one thing to check
#: when enrichment is empty.
ATTACK_BUNDLE_PATH = DATA_DIR / "frameworks" / "attack" / "ent.json"

#: Longest description carried into a finding. Enough for the technique's opening
#: sentence; the full text is a click away on the URL, and a finding is not the
#: place to reproduce a page of MITRE prose.
DESCRIPTION_CHARS = 200


def _index(objects: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build the technique index from a parsed STIX bundle's object list."""
    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Extract technique ID from external_references
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break

        if not tech_id:
            continue

        description = obj.get("description", "")
        truncated = len(description) > DESCRIPTION_CHARS
        techniques[tech_id] = {
            "id": tech_id,
            "name": obj.get("name", ""),
            # The ellipsis is not decoration. Without it a sentence cut at 200
            # characters reads as a complete statement MITRE never made.
            "description": (
                description[:DESCRIPTION_CHARS] + "…" if truncated else description
            ),
            "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            "kill_chain_phases": [
                p.get("phase_name", "")
                for p in obj.get("kill_chain_phases", [])
            ],
            # 161 of the 858 techniques in v19.2 are revoked or deprecated.
            # They are kept rather than filtered out, because a rule that cites a
            # withdrawn technique should say so — dropping it would leave the
            # finding silently without the context it asked for, which is the
            # same mistake as scoring a control PRAMAN could not decide.
            "deprecated": bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
        }

    return techniques


@lru_cache(maxsize=1)
def load_attack_techniques() -> dict[str, dict[str, Any]]:
    """Load MITRE ATT&CK techniques from the STIX bundle.

    Returns a dict keyed by technique ID (e.g. "T1040") with technique metadata.
    Empty when the bundle is absent or unreadable — see the module note; that is
    a supported state, not a failure.

    Cached for the life of the process. The bundle is 53.8 MB and 26,086 STIX
    objects, which is 0.47 s to parse on the reference machine — small enough to
    do once at first use and far too large to do per audit.
    """
    if not ATTACK_BUNDLE_PATH.exists():
        return {}

    try:
        data = json.loads(ATTACK_BUNDLE_PATH.read_text(encoding=FILE_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}

    return _index(data.get("objects", []))


@lru_cache(maxsize=1)
def attack_version() -> str:
    """The ATT&CK release the local bundle came from, e.g. ``"19.2"``.

    Empty string when the bundle is absent. Read from the bundle's
    ``x-mitre-collection`` object rather than from a constant, because a report
    that cites a technique has to be able to say which ATT&CK release defined
    it — technique IDs are revoked and renumbered between releases, so "T1066"
    without a version is not a citation.
    """
    if not ATTACK_BUNDLE_PATH.exists():
        return ""

    try:
        data = json.loads(ATTACK_BUNDLE_PATH.read_text(encoding=FILE_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return ""

    for obj in data.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version", ""))
    return ""


def enrich_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Add ATT&CK technique metadata to findings that reference attack IDs.

    Mutates finding dicts in place (adds "threat_intel" key).
    Returns the same list for chaining.

    With `FEATURE_THREAT_ENRICHMENT` off, or the bundle absent, the list comes
    back untouched — not merely equal but the same objects, so serialising it
    produces identical bytes either way.
    """
    if not FEATURE_THREAT_ENRICHMENT:
        return findings

    techniques = load_attack_techniques()
    if not techniques:
        return findings

    for finding in findings:
        refs = finding.get("references", {})
        attack_ids = refs.get("attack", [])
        if not attack_ids:
            continue

        enrichments = []
        for tid in attack_ids:
            if tid in techniques:
                enrichments.append(techniques[tid])

        if enrichments:
            finding["threat_intel"] = enrichments

    return findings
