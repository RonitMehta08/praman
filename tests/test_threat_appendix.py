"""The threat appendix: that it is context, and that it stays outside the record.

Two properties, and the second is the one with teeth.

*Context, never a verdict.* Nothing in `backend/threat/appendix.py` can change a
`Finding.result`, and the appendix is built from findings that were already
decided. That is checked structurally — the import simply must not be there —
rather than by observing that results happen not to move.

*Outside the record.* `AuditRecord.merkle_root` is computed over the serialised
findings, so an appendix carried *inside* a finding would change the root of
every audit and force a ledger reseed, to carry an annotation that is not
evidence. P12 states the requirement as byte-identity with the feature off, and
these tests assert byte-identity rather than describing it.
"""

from __future__ import annotations

import json

import pytest

from backend.frameworks.catalog import CatalogControl, ControlCatalog
from backend.ledger.chain import compute_merkle_root
from backend.rules.models import Rule
from backend.threat import appendix as appendix_mod
from backend.threat import mapping
from backend.threat.appendix import MAPPED_RESULTS, appendix_for_findings, build_index

CATALOG = ControlCatalog(
    catalog_id="cis_test",
    framework="CIS",
    benchmark="CIS Test Benchmark",
    benchmark_version="v1.0.0",
    source_document="test.pdf",
    controls=[
        CatalogControl(control_id="1.1", title="Use SNMPv3", severity="high"),
        CatalogControl(control_id="1.2", title="Disable telnet", severity="high"),
        CatalogControl(control_id="1.3", title="Log everything", severity="medium"),
    ],
)


def _rule(rule_id: str, control_id: str, path: str) -> Rule:
    return Rule.model_validate(
        {
            "id": rule_id,
            "catalog": {"catalog_id": "cis_test", "control_id": control_id},
            "condition": {"type": "presence", "path": path},
            "mapping_rationale": "test fixture",
        }
    )


RULES = [
    _rule("r-snmp", "1.1", "snmp.version"),
    _rule("r-telnet", "1.2", "mgmt.telnet.enabled"),
    _rule("r-log", "1.3", "logging.enable"),
]


def _finding(control_id: str, result: str, title: str = "t") -> dict:
    return {
        "control_id": control_id,
        "framework": "CIS",
        "benchmark": "CIS Test Benchmark",
        "benchmark_version": "v1.0.0",
        "title": title,
        "result": result,
        "severity": "high",
        "evidence": [],
        "rationale": "r",
    }


@pytest.fixture(autouse=True)
def _clear_caches():
    mapping.load_canonical_map.cache_clear()
    yield
    mapping.load_canonical_map.cache_clear()


# ── only failures are mapped ────────────────────────────────────────────────


def test_only_failing_findings_are_mapped():
    assert set(MAPPED_RESULTS) == {"fail"}


@pytest.mark.parametrize("result", ["pass", "notchecked", "notapplicable", "error", "unknown"])
def test_a_non_failing_finding_gets_no_technique(result: str):
    """Each exclusion is a different claim PRAMAN refuses to make.

    A pass is not a technique the adversary performed, it is one they cannot.
    `notchecked` is honest absence, and absence of evidence must not render as
    exposure any more than it renders as PASS. `notapplicable` means the control
    does not govern this device. `error` and `unknown` describe the tool's state,
    not the device's.
    """
    out = appendix_for_findings([_finding("1.1", result)], RULES, [CATALOG])
    assert out == {}


def test_a_failing_mapped_control_produces_an_entry():
    out = appendix_for_findings([_finding("1.1", "fail", "Use SNMPv3")], RULES, [CATALOG])
    assert out["failing_controls_mapped"] == 1
    assert [t["id"] for t in out["techniques"]] == ["T1602.001"]
    assert out["controls"][0]["control_id"] == "1.1"
    assert out["controls"][0]["techniques"] == ["T1602.001"]


def test_a_failing_unmapped_control_produces_nothing():
    """`logging.enable` is unmapped on purpose — see the canonical_map header."""
    assert appendix_for_findings([_finding("1.3", "fail")], RULES, [CATALOG]) == {}


def test_the_appendix_carries_its_own_disclaimer():
    out = appendix_for_findings([_finding("1.2", "fail")], RULES, [CATALOG])
    disclaimer = out["disclaimer"].lower()
    assert "editorial" in disclaimer
    assert "no publisher" in disclaimer
    assert "verdict" in disclaimer


def test_praman_rationale_is_named_as_pramans():
    """The key name is the label. `rationale` alone would read as MITRE's."""
    out = appendix_for_findings([_finding("1.2", "fail")], RULES, [CATALOG])
    for technique in out["techniques"]:
        assert technique["praman_rationale"]


# ── the join ────────────────────────────────────────────────────────────────


def test_the_index_joins_through_the_catalog_not_the_title():
    index = build_index(RULES, [CATALOG])
    assert index[("CIS", "CIS Test Benchmark", "1.1")] == {"snmp.version"}


def test_a_rule_whose_catalog_is_not_loaded_is_skipped_not_guessed():
    """There is no framework or benchmark to key it on; inventing one is worse."""
    orphan = _rule("r-orphan", "1.1", "snmp.version")
    orphan.catalog.catalog_id = "not_loaded"
    assert build_index([orphan], [CATALOG]) == {}


def test_a_disabled_rule_contributes_nothing():
    disabled = _rule("r-off", "1.1", "snmp.version")
    disabled.enabled = False
    assert build_index([disabled], [CATALOG]) == {}


def test_a_finding_for_another_benchmark_does_not_collide():
    """Same control id, different benchmark — the key is a triple for this reason."""
    other = _finding("1.1", "fail")
    other["benchmark"] = "CIS Some Other Benchmark"
    assert appendix_for_findings([other], RULES, [CATALOG]) == {}


def test_findings_are_never_mutated():
    findings = [_finding("1.1", "fail"), _finding("1.2", "fail")]
    before = json.dumps(findings, sort_keys=True)
    appendix_for_findings(findings, RULES, [CATALOG])
    assert json.dumps(findings, sort_keys=True) == before


# ── P12: the record does not move ───────────────────────────────────────────


def test_the_merkle_root_is_identical_with_and_without_the_appendix():
    """The appendix is a sibling of `findings`, so the root cannot see it.

    This is the reason the annotation is not a `Finding` field. `Finding` is
    `extra="forbid"` and the root is taken over the serialised findings, so
    adding one would have invalidated every record in the ledger — to carry an
    editorial judgement that is not evidence.
    """
    findings = [_finding("1.1", "fail"), _finding("1.2", "fail")]
    root_before = compute_merkle_root(findings)
    out = appendix_for_findings(findings, RULES, [CATALOG])
    assert out
    assert compute_merkle_root(findings) == root_before


def test_the_envelope_is_byte_identical_with_the_feature_off(monkeypatch):
    findings = [_finding("1.1", "fail")]
    monkeypatch.setattr(appendix_mod, "FEATURE_THREAT_ENRICHMENT", False)
    assert appendix_for_findings(findings, RULES, [CATALOG]) == {}

    monkeypatch.setattr(appendix_mod, "FEATURE_THREAT_ENRICHMENT", True)
    assert appendix_for_findings(findings, RULES, [CATALOG]) != {}


def test_no_appendix_when_the_map_is_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(mapping, "CANONICAL_MAP_PATH", tmp_path / "gone.yaml")
    mapping.load_canonical_map.cache_clear()
    assert appendix_for_findings([_finding("1.1", "fail")], RULES, [CATALOG]) == {}


def test_no_appendix_when_the_attack_bundle_is_absent(monkeypatch):
    """A technique id with no name, url or ATT&CK version is not a citation.

    The bundle is a Step 4a artefact and may legitimately be missing. Every
    readable field of a technique comes from it, so building the appendix anyway
    would emit `T1602.001` bare — and technique ids are revoked and renumbered
    between releases, so an unversioned one cannot be checked by the reader. The
    key is omitted instead, which says "not produced" rather than "produced, and
    this is what we found".
    """
    monkeypatch.setattr(appendix_mod, "load_attack_techniques", dict)
    assert appendix_for_findings([_finding("1.1", "fail")], RULES, [CATALOG]) == {}


def test_the_appendix_module_cannot_reach_the_evaluator():
    with open(appendix_mod.__file__, encoding="utf-8") as handle:
        text = handle.read()
    for forbidden in ("from backend.rules.evaluator", "Result.", "Finding("):
        assert forbidden not in text, f"threat/appendix.py reaches {forbidden}"


# ── the CLI door ────────────────────────────────────────────────────────────


def test_the_cli_writes_the_appendix_outside_the_record(tmp_path):
    """The audit record stored in findings.json must not contain the appendix."""
    from backend import cli

    record = {
        "actor": "service:offline-cli",
        "audit_id": "a",
        "merkle_root": "deadbeef",
        "record_hash": "cafe",
        "signature": "sig",
        "findings": [_finding("1.1", "fail")],
    }
    cli._write_outputs(
        tmp_path,
        {"device_id": "d"},
        [_finding("1.1", "fail")],
        {"total": 1},
        "x.conf",
        record,
        appendix_for_findings([_finding("1.1", "fail")], RULES, [CATALOG]),
    )
    payload = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert "threat_appendix" in payload
    assert "threat_appendix" not in payload["audit_record"]
    assert payload["audit_record"]["merkle_root"] == "deadbeef"
    assert all("threat_intel" not in f for f in payload["findings"])


def test_the_cli_omits_the_key_entirely_rather_than_writing_an_empty_one(tmp_path):
    """An empty appendix reads as "we looked and found nothing", which is a claim."""
    from backend import cli

    cli._write_outputs(tmp_path, {"device_id": "d"}, [], {"total": 0}, "x.conf", None, None)
    payload = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert "threat_appendix" not in payload
