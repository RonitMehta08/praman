"""NIST SP 800-53B baseline allocation — LOW / MODERATE / HIGH membership.

This module answers one question: *is this control in the MODERATE baseline?*
It exists because the coverage figure PRAMAN publishes is only as meaningful as
its denominator, and "13.49% of 3,366 loaded controls" is measured against every
catalog the project can crosswalk — including 714 NIST enhancements and
platforms with no pattern pack. A tool that audits a router is not failing to
check ``PS-03`` (Personnel Screening); it is not in scope for a router, and it is
not in the LOW baseline either.

**The allocation is not in the repository, and it was never derivable from what
is.** ``data/frameworks/oscal/sp80053.json`` is the SP 800-53 *catalog* — it
carries what each control requires, not which baseline selects it. Measured on
the local copy: the only ``prop`` names it uses are ``label``, ``method``,
``sort-id``, ``implementation-level``, ``alt-identifier``,
``contributes-to-assurance``, ``aggregates``, ``status``, ``alt-label`` and
``keywords``. There is no baseline or impact property, and
``implementation-level`` is organization/system/mixed — not LOW/MODERATE/HIGH.
The normalised catalog agrees: ``impact`` is ``''`` for all 1,014 controls and
``profile`` is ``None`` for all of them. Baseline membership lives in SP 800-53B,
published separately as three OSCAL profiles. ``MANUAL_COMMANDS.md`` Step 16
fetches them; until it is run, :func:`load_baselines` returns ``{}``.

That empty return is the contract, not a fallback. It is the same honest-absence
rule the ATT&CK bundle and the AI tiers use: an absent artefact produces a
*stated* absence, never a guessed number and never a silently smaller
denominator. Inventing LOW 149 / MODERATE 287 / HIGH 370 from memory would have
been a one-line change and a fabricated citation.

What *is* derivable from the catalog on disk is the composition of the
denominator, and :func:`catalog_composition` publishes it: 1,014 current
controls, of which 300 are base controls and 714 are enhancements.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.app.config import FILE_ENCODING, FRAMEWORKS_DIR
from backend.frameworks.crosswalk import normalise_control_id

#: Where ``MANUAL_COMMANDS.md`` Step 16 writes the extracted allocation. One
#: documented location, for the same reason the ATT&CK bundle has one: when the
#: baseline view is empty there should be exactly one thing to check.
BASELINE_PATH = FRAMEWORKS_DIR / "oscal" / "baselines.json"

#: The three impact levels SP 800-53B allocates. PRIVACY is published alongside
#: them by NIST but is not an impact level and is deliberately not accepted here
#: — treating it as a fourth tier would misstate what a "MODERATE system" means.
BASELINE_NAMES = ("low", "moderate", "high")

#: OSCAL control ids are dotted and lowercase (``ac-17.2``); PRAMAN catalogs use
#: the parenthesised published form (``AC-17(02)``). The dot must be rewritten
#: before normalisation, because ``normalise_control_id`` matches an enhancement
#: only in parentheses — fed ``ac-17.2`` it would happily return ``AC-17`` and
#: quietly fold an enhancement into its base control, which is the difference
#: between "the baseline selects AC-17" and "the baseline selects AC-17(2)".
_OSCAL_ENHANCEMENT_RE = re.compile(r"^([A-Za-z]{2,3}-\d{1,3})\.(\d{1,3})$")


def normalise_oscal_id(raw: str) -> str | None:
    """Normalise an OSCAL control id such as ``ac-17.2`` to ``AC-17(02)``.

    Returns None when the string does not name a control, so a malformed or
    unexpected entry is dropped rather than turned into a plausible-looking id.
    """
    match = _OSCAL_ENHANCEMENT_RE.match((raw or "").strip())
    if match:
        return normalise_control_id(f"{match.group(1)}({match.group(2)})")
    return normalise_control_id(raw)


def _collect_ids(node: Any, out: list[str]) -> None:
    """Walk a parsed OSCAL profile collecting every ``with-ids`` string.

    Deliberately structure-agnostic. The nesting of ``imports`` →
    ``include-controls`` → ``with-ids`` is part of the OSCAL profile model and
    could gain a level in a future OSCAL release; the key name is the stable
    part, so that is what this matches. A shape this loader did not anticipate
    yields an empty list, which Step 16's verification step reports as a count of
    zero rather than as a baseline that silently selects nothing.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "with-ids" and isinstance(value, list):
                out.extend(str(v) for v in value if isinstance(v, str))
            else:
                _collect_ids(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_ids(item, out)


def extract_profile_ids(profile: dict[str, Any]) -> list[str]:
    """Extract the normalised control ids selected by one OSCAL baseline profile.

    Sorted and de-duplicated. Used by ``MANUAL_COMMANDS.md`` Step 16 to turn the
    three published profiles into :data:`BASELINE_PATH`; exposed here rather than
    inlined in the step so the extraction that produces the artefact is the same
    code the tests cover.
    """
    raw: list[str] = []
    _collect_ids(profile, raw)
    normalised = {n for n in (normalise_oscal_id(r) for r in raw) if n}
    return sorted(normalised)


@lru_cache(maxsize=1)
def load_baselines() -> dict[str, frozenset[str]]:
    """Load the LOW/MODERATE/HIGH allocation, or ``{}`` when it is absent.

    Empty is a supported state and means "Step 16 has not been run", not
    "no control is in any baseline". Callers must distinguish the two: reporting
    coverage against an empty MODERATE baseline would divide by zero, and
    reporting it against the full catalog while *calling* it MODERATE would be
    the dishonesty this whole module exists to avoid.
    """
    if not BASELINE_PATH.exists():
        return {}
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding=FILE_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}

    baselines = data.get("baselines")
    if not isinstance(baselines, dict):
        return {}

    loaded: dict[str, frozenset[str]] = {}
    for name in BASELINE_NAMES:
        members = baselines.get(name)
        if isinstance(members, list) and members:
            loaded[name] = frozenset(str(m) for m in members)
    return loaded


def baseline_source() -> str:
    """The provenance string the artefact records, or ``""`` when absent.

    A baseline-scoped number is a citation, so the report has to be able to say
    which publication it scoped against — SP 800-53B is revised, and a control
    moves between baselines across revisions.
    """
    if not BASELINE_PATH.exists():
        return ""
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding=FILE_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return ""
    return str(data.get("source", ""))


def scope_to_baseline(control_ids: set[str], name: str) -> set[str] | None:
    """Restrict ``control_ids`` to the named baseline.

    Returns None when the allocation is not on disk or the name is unknown —
    the caller is then obliged to publish the unscoped figure and say why, which
    is what ``scripts/bench/bench_rule_latency.py`` does.
    """
    members = load_baselines().get(name.lower())
    if members is None:
        return None
    return {c for c in control_ids if c in members}


def catalog_composition(controls: list[str]) -> dict[str, int]:
    """Split published control ids into base controls and enhancements.

    Derivable from the catalog already on disk, and worth publishing precisely
    because the baseline allocation is not: a denominator of 1,014 that is 70%
    enhancements describes a different corpus than one of 300 base controls, and
    a reader comparing coverage figures between tools needs to know which they
    are looking at.
    """
    enhancements = sum(1 for c in controls if "(" in c)
    return {
        "controls": len(controls),
        "base_controls": len(controls) - enhancements,
        "enhancements": enhancements,
    }


def write_baselines(profiles: dict[str, dict[str, Any]], source: str) -> Path:
    """Write the extracted allocation to :data:`BASELINE_PATH`.

    ``profiles`` maps a name in :data:`BASELINE_NAMES` to a parsed OSCAL profile.
    Deterministic, sorted JSON, so re-running Step 16 against the same
    publication produces the same bytes and a diff means the publication changed.
    """
    payload = {
        "source": source,
        "baselines": {
            name: extract_profile_ids(profiles[name])
            for name in BASELINE_NAMES
            if name in profiles
        },
    }
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding=FILE_ENCODING,
    )
    load_baselines.cache_clear()
    return BASELINE_PATH
