"""Test: ATT&CK threat enrichment — the loader's absent case must be an *honest*
absent case.

This module exists because of a specific bug and a general hazard.

The bug: `ATTACK_BUNDLE_PATH` pointed at `data/frameworks/enterprise-attack.json`
while `MANUAL_COMMANDS.md` Step 4a writes `data/frameworks/attack/ent.json`. So
`load_attack_techniques()` returned `{}` on every machine, including the one with
the bundle sitting on disk.

The general hazard is why the bug survived: **a legitimately-absent artifact and
a mistyped path produce the same answer.** `{}` is correct behaviour on a fresh
clone — the bundle is 53.8 MB and gitignored — so nothing about the empty result
looked wrong, and there was no assertion that could tell the two apart. Every
loader in this project with an honest-absence contract has the same shape, and
the only defence is to pin the path against the document that creates the file.

Four things are asserted:

1. The path is exactly where Step 4a puts it, cross-checked against
   `MANUAL_COMMANDS.md` itself so the two cannot drift apart.
2. The index is built correctly from a bundle, including the parts that would be
   *wrong* rather than missing: sub-technique URLs, truncation, and revoked
   techniques.
3. Enrichment is inert when it should be — flag off, bundle absent, no
   references — and inert means *the same objects back*, not equal ones.
4. Enrichment can never write a verdict field.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from backend.app.config import DATA_DIR
from backend.threat import enrichment
from backend.threat.enrichment import (
    ATTACK_BUNDLE_PATH,
    DESCRIPTION_CHARS,
    _index,
    attack_version,
    enrich_findings,
    load_attack_techniques,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANUAL_COMMANDS = PROJECT_ROOT.parent / "MANUAL_COMMANDS.md"

#: The location Step 4a writes, as a POSIX-relative path under ``data/``.
EXPECTED_RELATIVE = "frameworks/attack/ent.json"


def _bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    return {"type": "bundle", "id": "bundle--test", "objects": objects}


def _technique(
    tech_id: str,
    name: str = "Network Sniffing",
    description: str = "An adversary reads network traffic.",
    **extra: Any,
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": "attack-pattern",
        "name": name,
        "description": description,
        "external_references": [{"source_name": "mitre-attack", "external_id": tech_id}],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
        ],
    }
    obj.update(extra)
    return obj


# ── 1. The path ──────────────────────────────────────────────────────


def test_the_bundle_path_is_where_step_4a_puts_it() -> None:
    """The one assertion that would have caught the original defect."""
    assert ATTACK_BUNDLE_PATH.relative_to(DATA_DIR).as_posix() == EXPECTED_RELATIVE


def test_step_4a_still_writes_the_path_the_loader_reads() -> None:
    """Pin the code to the document, in the direction that actually rots.

    Nobody edits `enrichment.py` and `MANUAL_COMMANDS.md` in the same sitting. If
    Step 4a is ever rewritten to put the bundle somewhere else, the loader goes
    back to returning `{}` forever and no other test in this suite would notice,
    because `{}` is a supported answer.

    Matched against the Windows-style path the step actually contains, since that
    is the literal an operator copies.
    """
    if not MANUAL_COMMANDS.is_file():  # pragma: no cover
        pytest.skip("MANUAL_COMMANDS.md lives at the workspace root, which is absent")

    text = MANUAL_COMMANDS.read_text(encoding="utf-8")
    windows = "praman\\data\\" + EXPECTED_RELATIVE.replace("/", "\\")
    assert windows in text, (
        f"MANUAL_COMMANDS.md no longer mentions {windows}. Either the step moved "
        "the bundle — in which case ATTACK_BUNDLE_PATH is now wrong and silently "
        "returns {} — or the step was deleted."
    )


# ── 2. The index ─────────────────────────────────────────────────────


def test_a_sub_technique_url_uses_the_slash_form() -> None:
    """`T1055.011` is `/techniques/T1055/011/`, not `/techniques/T1055.011/`.

    The dotted form 404s. A finding carrying a dead link to MITRE is worse than
    one carrying none, because the reader concludes the tool is stale rather than
    that the URL is malformed.
    """
    index = _index([_technique("T1055.011", name="Extra Window Memory Injection")])
    assert index["T1055.011"]["url"] == "https://attack.mitre.org/techniques/T1055/011/"


def test_a_top_level_technique_url_is_unchanged() -> None:
    index = _index([_technique("T1040")])
    assert index["T1040"]["url"] == "https://attack.mitre.org/techniques/T1040/"


def test_a_truncated_description_says_that_it_is_truncated() -> None:
    """A sentence cut at 200 characters must not read as a finished sentence."""
    long = "A" * (DESCRIPTION_CHARS + 50)
    index = _index([_technique("T1040", description=long)])
    described = index["T1040"]["description"]
    assert described.endswith("…")
    assert len(described) == DESCRIPTION_CHARS + 1


def test_a_short_description_is_left_alone() -> None:
    index = _index([_technique("T1040", description="Short.")])
    assert index["T1040"]["description"] == "Short."


@pytest.mark.parametrize(
    "flags",
    [{"revoked": True}, {"x_mitre_deprecated": True}, {"revoked": True, "x_mitre_deprecated": True}],
)
def test_a_withdrawn_technique_is_kept_and_marked(flags: dict[str, Any]) -> None:
    """Kept, not dropped — and flagged, not presented as current.

    Filtering these out would leave a rule that cites a withdrawn technique with
    no context at all and no explanation of why, which is the same failure as
    scoring a control the tool could not decide. 161 of v19.2's 858 techniques
    are in this state, so it is the common case, not an edge one.
    """
    index = _index([_technique("T1066", **flags)])
    assert index["T1066"]["deprecated"] is True


def test_a_current_technique_is_not_marked_deprecated() -> None:
    index = _index([_technique("T1040")])
    assert index["T1040"]["deprecated"] is False


def test_objects_that_are_not_techniques_are_ignored() -> None:
    """A real bundle is 26,086 objects of which 858 are techniques."""
    index = _index(
        [
            {"type": "intrusion-set", "name": "Some Group"},
            {"type": "x-mitre-tactic", "name": "Credential Access"},
            _technique("T1040"),
            # An attack-pattern with no mitre-attack reference has no citable ID.
            {"type": "attack-pattern", "name": "Unreferenced", "external_references": []},
        ]
    )
    assert list(index) == ["T1040"]


def test_kill_chain_phases_are_flattened_to_names() -> None:
    index = _index([_technique("T1040")])
    assert index["T1040"]["kill_chain_phases"] == ["credential-access"]


# ── 3. Absence, and the version marker ───────────────────────────────


def test_an_absent_bundle_loads_as_empty_rather_than_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh clone has no bundle. That is a supported configuration."""
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", tmp_path / "absent.json")
    load_attack_techniques.cache_clear()
    attack_version.cache_clear()
    try:
        assert load_attack_techniques() == {}
        assert attack_version() == ""
    finally:
        load_attack_techniques.cache_clear()
        attack_version.cache_clear()


def test_a_corrupt_bundle_loads_as_empty_rather_than_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half-copied 53 MB file is the realistic corruption, and it must not take
    the audit down with it: enrichment is context, and context is optional."""
    broken = tmp_path / "ent.json"
    broken.write_text('{"objects": [{"type": "attack-pat', encoding="utf-8")
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", broken)
    load_attack_techniques.cache_clear()
    attack_version.cache_clear()
    try:
        assert load_attack_techniques() == {}
        assert attack_version() == ""
    finally:
        load_attack_techniques.cache_clear()
        attack_version.cache_clear()


def test_the_version_comes_from_the_bundle_not_a_constant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Technique IDs are revoked and renumbered between releases, so an ID
    without a release is not a citation."""
    path = tmp_path / "ent.json"
    path.write_text(
        json.dumps(
            _bundle(
                [
                    {
                        "type": "x-mitre-collection",
                        "name": "Enterprise ATT&CK",
                        "x_mitre_version": "19.2",
                    },
                    _technique("T1040"),
                ]
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", path)
    attack_version.cache_clear()
    try:
        assert attack_version() == "19.2"
    finally:
        attack_version.cache_clear()


# ── 4. Enrichment stays out of the verdict path ──────────────────────


def _finding(**extra: Any) -> dict[str, Any]:
    base = {"control_id": "1.1.1", "result": "fail", "references": {}}
    base.update(extra)
    return base


def test_the_flag_off_returns_the_same_objects_not_merely_equal_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`byte-identical with the flag off` has to mean identity, not equality.

    A copy that happens to serialise the same today is one refactor away from
    reordering a key. Asserting `is` makes the guarantee structural.
    """
    monkeypatch.setattr(enrichment, "FEATURE_THREAT_ENRICHMENT", False)
    findings = [_finding(references={"attack": ["T1040"]})]
    original = findings[0]
    assert enrich_findings(findings) is findings
    assert findings[0] is original
    assert "threat_intel" not in original


def test_an_absent_bundle_leaves_findings_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(enrichment, "FEATURE_THREAT_ENRICHMENT", True)
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", tmp_path / "absent.json")
    load_attack_techniques.cache_clear()
    try:
        findings = [_finding(references={"attack": ["T1040"]})]
        assert enrich_findings(findings) == [_finding(references={"attack": ["T1040"]})]
    finally:
        load_attack_techniques.cache_clear()


def test_enrichment_adds_context_and_changes_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of the module, and its whole limit.

    `result` is the field an auditor reads as a measurement. If any code path
    could reach it from here, the AI-out-of-the-verdict-path guarantee would have
    a second door.
    """
    path = tmp_path / "ent.json"
    path.write_text(json.dumps(_bundle([_technique("T1040")])), encoding="utf-8")
    monkeypatch.setattr(enrichment, "FEATURE_THREAT_ENRICHMENT", True)
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", path)
    load_attack_techniques.cache_clear()
    try:
        findings = [_finding(references={"attack": ["T1040"]})]
        enrich_findings(findings)
        finding = findings[0]
        assert finding["result"] == "fail"
        assert finding["control_id"] == "1.1.1"
        assert set(finding) == {"control_id", "result", "references", "threat_intel"}
        assert [t["id"] for t in finding["threat_intel"]] == ["T1040"]
    finally:
        load_attack_techniques.cache_clear()


def test_an_unknown_technique_id_is_dropped_rather_than_invented(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reference the local bundle does not contain gets no entry — the one place
    where silence is right, because the alternative is a name this process made
    up for an ID it has never seen."""
    path = tmp_path / "ent.json"
    path.write_text(json.dumps(_bundle([_technique("T1040")])), encoding="utf-8")
    monkeypatch.setattr(enrichment, "FEATURE_THREAT_ENRICHMENT", True)
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", path)
    load_attack_techniques.cache_clear()
    try:
        findings = [_finding(references={"attack": ["T9999"]})]
        enrich_findings(findings)
        assert "threat_intel" not in findings[0]
    finally:
        load_attack_techniques.cache_clear()


def test_a_finding_with_no_attack_reference_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ent.json"
    path.write_text(json.dumps(_bundle([_technique("T1040")])), encoding="utf-8")
    monkeypatch.setattr(enrichment, "FEATURE_THREAT_ENRICHMENT", True)
    monkeypatch.setattr(enrichment, "ATTACK_BUNDLE_PATH", path)
    load_attack_techniques.cache_clear()
    try:
        findings = [_finding(), _finding(references={"cis": ["1.1.1"]})]
        enrich_findings(findings)
        assert all("threat_intel" not in f for f in findings)
    finally:
        load_attack_techniques.cache_clear()


# ── The real bundle, when the operator has run Step 4a ───────────────


@pytest.mark.skipif(
    not ATTACK_BUNDLE_PATH.exists(),
    reason="ent.json is gitignored; MANUAL_COMMANDS.md Step 4a copies it in",
)
def test_the_real_bundle_indexes_and_reports_its_release() -> None:
    """Skipped on a fresh clone by design — but on a machine that has run Step 4a
    this is the assertion that the path fix actually took effect."""
    load_attack_techniques.cache_clear()
    attack_version.cache_clear()
    try:
        index = load_attack_techniques()
        assert len(index) > 500, "the Enterprise bundle carries 858 techniques in v19.2"
        assert "T1040" in index
        assert index["T1040"]["url"] == "https://attack.mitre.org/techniques/T1040/"
        assert attack_version(), "the bundle must name the release it came from"
    finally:
        load_attack_techniques.cache_clear()
        attack_version.cache_clear()
