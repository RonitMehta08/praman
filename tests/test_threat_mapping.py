"""The rule → ATT&CK join: that it is honest, and that it stays honest.

`backend/threat/mapping.py` is the one place in PRAMAN where the tool asserts
something no publisher said. Everything else in the evidence chain traces to CIS,
DISA, NIST or MITRE; the path → technique link is PRAMAN's own editorial
judgement. So these tests are less about arithmetic than about keeping the
authored surface exactly as small as it claims to be, and keeping the boundary
between "we said this" and "MITRE said this" where the documentation puts it.

Bundle-dependent tests skip when `ent.json` is absent (Step 4a), because a fresh
clone legitimately does not have 53.8 MB of STIX and the join itself does not
need it — the join is a property of the rule pack.
"""

from __future__ import annotations

import json

import pytest
import yaml

from backend.rules.loader import load_all_rules
from backend.threat import mapping
from backend.threat.enrichment import ATTACK_BUNDLE_PATH, load_attack_techniques

needs_bundle = pytest.mark.skipif(
    not ATTACK_BUNDLE_PATH.exists(),
    reason="ATT&CK bundle absent — MANUAL_COMMANDS.md Step 4a",
)


@pytest.fixture(autouse=True)
def _clear_caches():
    """Every loader here is `lru_cache`d; a monkeypatched path must not persist."""
    mapping.load_canonical_map.cache_clear()
    mapping._mitigation_index.cache_clear()
    yield
    mapping.load_canonical_map.cache_clear()
    mapping._mitigation_index.cache_clear()


def _write_map(tmp_path, monkeypatch, payload):
    path = tmp_path / "canonical_map.yaml"
    path.write_text(
        payload if isinstance(payload, str) else yaml.safe_dump(payload),
        encoding="utf-8",
    )
    monkeypatch.setattr(mapping, "CANONICAL_MAP_PATH", path)
    mapping.load_canonical_map.cache_clear()
    return path


# ── the gate ────────────────────────────────────────────────────────────────


def test_every_mapped_prefix_reaches_at_least_one_rule():
    """A prefix matching no rule is a coverage claim with nothing behind it.

    This is what `scripts/attack_coverage.py --check` fails on, and it caught
    three in the first draft: `snmp.engine_id`, which no rule reads, and
    `mgmt.ssh.ciphers` / `mgmt.ssh.macs`, misspelt plurals of `mgmt.ssh.cipher`
    and `mgmt.ssh.mac`. Each would have read in review as a mapped family and
    contributed nothing to the join.
    """
    report = mapping.coverage_report(load_all_rules())
    assert report["dead_prefixes"] == []


def test_the_shipped_map_actually_loads():
    doc = mapping.load_canonical_map()
    assert doc, "canonical_map.yaml failed to load"
    assert doc["mappings"], "canonical_map.yaml parsed to zero usable entries"


def test_the_map_labels_itself_as_editorial():
    """The label is the whole reason this file is allowed to exist."""
    assert "editorial" in mapping.load_canonical_map()["authored_by"].lower()


def test_every_technique_carries_an_argument():
    """A judgement that travels without its argument gets read as a publisher's."""
    for entry in mapping.load_canonical_map()["mappings"]:
        assert entry["why"], f"{entry['techniques']} asserts a link with no rationale"
        assert len(entry["why"]) > 40, f"{entry['techniques']} rationale is too thin to review"


# ── honest absence ──────────────────────────────────────────────────────────


def test_absent_map_is_empty_rather_than_an_exception(tmp_path, monkeypatch):
    monkeypatch.setattr(mapping, "CANONICAL_MAP_PATH", tmp_path / "nope.yaml")
    mapping.load_canonical_map.cache_clear()

    assert mapping.load_canonical_map() == {}
    assert mapping.mapped_prefixes() == []
    assert mapping.techniques_for_paths({"snmp.community"}) == []
    assert mapping.rationale_for_paths({"snmp.community"}) == {}


def test_malformed_map_degrades_to_absent(tmp_path, monkeypatch):
    _write_map(tmp_path, monkeypatch, "mappings: [oh dear\n  - unbalanced")
    assert mapping.load_canonical_map() == {}


def test_a_map_that_is_not_a_mapping_yields_nothing(tmp_path, monkeypatch):
    _write_map(tmp_path, monkeypatch, ["not", "a", "dict"])
    assert mapping.load_canonical_map() == {}


def test_half_written_entries_are_dropped_rather_than_half_honoured(tmp_path, monkeypatch):
    """Paths with no techniques claim nothing; techniques with no paths are unreachable."""
    _write_map(
        tmp_path,
        monkeypatch,
        {
            "mappings": [
                {"paths": ["snmp.community"], "techniques": [], "why": "x"},
                {"paths": [], "techniques": ["T1040"], "why": "x"},
                {"paths": ["mgmt.telnet"], "techniques": ["T1040"], "why": "x"},
            ]
        },
    )
    doc = mapping.load_canonical_map()
    assert len(doc["mappings"]) == 1
    assert mapping.techniques_for_paths({"snmp.community"}) == []
    assert mapping.techniques_for_paths({"mgmt.telnet"}) == ["T1040"]


def test_non_string_entries_are_filtered_not_coerced(tmp_path, monkeypatch):
    _write_map(
        tmp_path,
        monkeypatch,
        {"mappings": [{"paths": ["mgmt.telnet", 7], "techniques": ["T1040", None], "why": "x"}]},
    )
    entry = mapping.load_canonical_map()["mappings"][0]
    assert entry["paths"] == ["mgmt.telnet"]
    assert entry["techniques"] == ["T1040"]


# ── the join itself ─────────────────────────────────────────────────────────


def test_prefix_matching_respects_the_dot(tmp_path, monkeypatch):
    """`mgmt.http` must not swallow `mgmt.http_proxy`, which is a different control."""
    _write_map(
        tmp_path,
        monkeypatch,
        {"mappings": [{"paths": ["mgmt.http"], "techniques": ["T1040"], "why": "x"}]},
    )
    assert mapping.techniques_for_paths({"mgmt.http"}) == ["T1040"]
    assert mapping.techniques_for_paths({"mgmt.http.server_enabled"}) == ["T1040"]
    assert mapping.techniques_for_paths({"mgmt.http_proxy"}) == []
    assert mapping.techniques_for_paths({"mgmt.https"}) == []


def test_one_path_may_imply_several_techniques():
    """Network boot is both a config-retrieval channel and an image channel."""
    hits = mapping.techniques_for_paths({"service.boot_network"})
    assert set(hits) >= {"T1601.001", "T1601.002", "T1602.002"}


def test_the_join_runs_off_referenced_paths_not_evidence():
    """48% of failing findings carry empty evidence; the join must not depend on it."""
    rules = load_all_rules()
    mapped = [r for r in rules if mapping.techniques_for_rule(r)]
    assert len(mapped) > 200
    for rule in mapped[:25]:
        assert mapping.techniques_for_rule(rule) == mapping.techniques_for_paths(
            rule.referenced_paths()
        )


def test_logging_and_accounting_stay_unmapped_on_purpose():
    """A device that does not log is not exposed to a technique by that fact.

    It is exposed to the technique going unnoticed, which is detection coverage
    and a different axis. Filing it under T1602 would assert the adversary
    gained something from the missing syslog, which is not true. The YAML header
    argues this at length; this pins it so the argument cannot quietly lapse.
    """
    for path in (
        "logging.enable",
        "logging.buffered",
        "logging.config_changes",
        "logging.console",
        "aaa.accounting_commands",
        "aaa.accounting_exec",
        "time.ntp.enabled",
        "time.ntp.authentication",
    ):
        assert mapping.techniques_for_paths({path}) == [], f"{path} should not be mapped"


def test_remote_syslog_is_the_one_logging_path_that_is_mapped():
    """And it is mapped for what crosses the wire, not for the logging."""
    assert mapping.techniques_for_paths({"logging.remote_syslog"}) == ["T1040"]


# ── the boundary between what PRAMAN says and what MITRE says ───────────────


def test_the_yaml_asserts_no_mitigation_of_its_own():
    """Hand-authored mitigations were wrong five times; they are derived now.

    The draft attributed M1026 to T1602.001/.002, M1054 to T1556.004 and M1051
    to T1601.001/.002 — none of which the publisher relates. Each was plausible
    enough to survive review, which is exactly what makes an invented citation
    dangerous. The class is gone only as long as the YAML stays out of that
    business.
    """
    raw = yaml.safe_load(mapping.CANONICAL_MAP_PATH.read_text(encoding="utf-8"))
    for entry in raw["mappings"]:
        assert "mitigations" not in entry, (
            "canonical_map.yaml is asserting mitigations again — derive them from "
            "the bundle's `mitigates` relationships instead"
        )


@needs_bundle
def test_mitigations_come_from_the_publishers_relationships():
    ids = [m["id"] for m in mapping.mitigations_for("T1602.001")]
    assert ids == ["M1030", "M1031", "M1037", "M1041", "M1051", "M1054"]
    assert "M1026" not in ids, "the invented mitigation is back"

    assert [m["id"] for m in mapping.mitigations_for("T1556.004")] == ["M1026", "M1032"]
    assert "M1051" not in [m["id"] for m in mapping.mitigations_for("T1601.001")]


@needs_bundle
def test_a_technique_with_no_publisher_mitigation_returns_an_empty_list():
    """T1016 has no `mitigates` relationship in v19.2, and that is the answer.

    Discovery techniques abuse features working as designed, so the publisher
    relates no preventive control. `[]` here is a measurement, not a lookup
    failure — which is why `coverage_report()` publishes `bundle_loaded`
    separately, so a caller can tell "none" from "not loaded".
    """
    assert mapping.mitigations_for("T1016") == []
    assert mapping.coverage_report([])["bundle_loaded"] is True


@needs_bundle
def test_deprecated_mitigations_never_surface():
    """The bundle carries legacy `X Mitigation` course-of-action objects.

    They are deprecated, and several carry the *technique's* external id — the
    one for T1040 is literally called "Network Sniffing Mitigation" and has
    external_id T1040. Offering superseded advice is worse than offering none,
    so they are filtered, and a technique id must never appear as a mitigation.
    """
    for tid in ("T1040", "T1016", "T1046", "T1557"):
        ids = [m["id"] for m in mapping.mitigations_for(tid)]
        assert tid not in ids
        assert all(m.startswith("M") for m in ids)


@needs_bundle
def test_a_shared_external_id_does_not_leak_across_object_types():
    """`enrichment._index()` filters to `attack-pattern`, and that filter is load-bearing.

    Two objects in v19.2 carry external_id T1040: the live technique "Network
    Sniffing" and a deprecated course-of-action "Network Sniffing Mitigation".
    The index is last-write-wins on the id, so without the type filter the
    surviving entry would depend on bundle ordering, and a finding could be
    enriched with a withdrawn mitigation's text presented as technique context.
    """
    technique = load_attack_techniques()["T1040"]
    assert technique["name"] == "Network Sniffing"
    assert technique["deprecated"] is False


@needs_bundle
def test_no_mapped_technique_is_withdrawn():
    """Citing a revoked technique would be citing an ID the publisher retired."""
    techniques = load_attack_techniques()
    for entry in mapping.load_canonical_map()["mappings"]:
        for tid in entry["techniques"]:
            assert tid in techniques, f"{tid} is not in the local bundle"
            assert not techniques[tid]["deprecated"], f"{tid} is withdrawn"


# ── the tier cannot reach a verdict ─────────────────────────────────────────


def test_the_mapping_module_cannot_reach_the_evaluator():
    """Structural, not behavioural: the import simply must not be there.

    A test that checks results are unchanged would pass for a module that
    *could* change them and happened not to. The guarantee worth having is that
    there is no path at all.
    """
    source = mapping.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    for forbidden in ("from backend.rules.engine", "from backend.canonical.findings", "Finding("):
        assert forbidden not in text, f"threat/mapping.py reaches {forbidden}"


def test_coverage_report_returns_fresh_containers():
    """No caller can mutate the cached map through a returned object."""
    rules = load_all_rules()[:20]
    first = mapping.coverage_report(rules)
    first["techniques"].clear()
    assert mapping.coverage_report(rules)["techniques"]

    prefixes = mapping.mapped_prefixes()
    prefixes.clear()
    assert mapping.mapped_prefixes()


# ── the published number ────────────────────────────────────────────────────


@needs_bundle
def test_published_metric_matches_the_measurement():
    path = mapping.CANONICAL_MAP_PATH.parent.parent.parent.parent
    metric = path / "reports" / "metrics" / "attack_coverage.json"
    assert metric.exists(), "run: python scripts/attack_coverage.py --write"

    published = json.loads(metric.read_text(encoding="utf-8"))
    measured = mapping.coverage_report(load_all_rules())
    for key in ("rules_total", "rules_mapped", "paths_total", "paths_mapped", "dead_prefixes"):
        assert published[key] == measured[key], (
            f"{key} drifted — run: python scripts/attack_coverage.py --write"
        )
