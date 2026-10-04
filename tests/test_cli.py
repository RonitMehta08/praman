"""``backend/cli.py`` — the offline entry point.

Why this module exists
----------------------
The CLI had **no test of any kind** and had drifted from the API in two ways that
a reader of the source would not notice, because both were silent:

* It carried its own two-entry list of hardcoded adapter classes instead of the
  shared ``PatternAdapterRegistry``. Dropping a new pattern pack into
  ``data/ingest/patterns/`` onboarded the vendor for the API and left the CLI
  unable to read that vendor's configs at all — so capability C5, "add a vendor
  without touching code", was false through this door while being true through
  the other one.
* ``--framework`` was ``required=True``, validated against a list containing
  ``STIG`` (not a value the ``Framework`` enum has), and then never passed to the
  evaluator. Every run scored all four frameworks. The flag looked like a filter
  and was decoration.

Neither would have been caught by a test that merely ran the CLI and checked the
exit code, which is why the assertions here are about *what came out* rather than
about whether it ran.

These tests invoke ``cmd_audit`` in-process rather than as a subprocess: the
module's expensive state (catalogs, rule packs, pattern library) is built at
import, so a subprocess per case would pay ~1 s of load each time to test
argument plumbing that ``main()`` already covers in one case below.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.canonical.findings import Framework
from backend.cli import FRAMEWORK_CHOICES, cmd_audit, main
from backend.rules.projection import DIRECT_FRAMEWORKS

CONFIG_DIR = PROJECT_ROOT / "test_configs"
FIXTURE = CONFIG_DIR / "realistic" / "secure_baseline.conf"


def _args(out: Path, *, config: Path = FIXTURE, framework: str = "CIS") -> argparse.Namespace:
    """The namespace ``main()`` would have built for these flags."""
    return argparse.Namespace(command="audit", config=str(config), framework=framework, out=str(out))


def _run(tmp_path: Path, **kwargs) -> tuple[int, dict]:
    """Run one audit and return ``(exit_code, findings.json)``."""
    out = tmp_path / "out"
    code = cmd_audit(_args(out, **kwargs))
    payload = json.loads((out / "findings.json").read_text(encoding=FILE_ENCODING))
    return code, payload


class TestFrameworkFlag:
    """``--framework`` must select, and must offer only real framework names."""

    def test_the_choices_are_the_enum_and_nothing_else(self) -> None:
        """No name the rest of the system cannot match.

        The old list offered ``STIG``. Nothing rejects it — ``Finding.framework``
        is a plain ``str`` — so a ``--framework STIG`` run wrote a findings.json
        whose framework field matched no catalog, no crosswalk and no UI filter.
        Deriving the choices from the enum makes that class of typo impossible
        rather than merely absent today.
        """
        assert [f.value for f in Framework] == FRAMEWORK_CHOICES
        assert "STIG" not in FRAMEWORK_CHOICES
        assert "DISA_STIG" in FRAMEWORK_CHOICES

    @pytest.mark.parametrize("framework", ["CIS", "DISA_STIG", "NIST_800_53", "ISO_27001"])
    def test_only_the_requested_framework_comes_back(self, tmp_path: Path, framework: str) -> None:
        """The flag filters, which is the whole point of it being required.

        Asserted as a set equality rather than "contains the one I asked for":
        the bug being guarded was *extra* frameworks coming back, so an assertion
        that tolerates extras cannot see it. Before the fix each of these four
        cases returned all 1,462 findings and passed any looser check.
        """
        _, payload = _run(tmp_path, framework=framework)
        assert {f["framework"] for f in payload["findings"]} == {framework}
        assert payload["summary"]["total"] == len(payload["findings"])

    def test_the_frameworks_partition_the_full_run(self, tmp_path: Path) -> None:
        """The four single-framework runs sum to the whole catalog, exactly.

        A filter can be wrong in two directions and the per-framework tests above
        only see one of them. If ``--framework CIS`` silently dropped controls
        that belong to CIS, each individual run would still contain nothing but
        CIS and every assertion above would hold. Summing the four against an
        unfiltered evaluation is what closes that side.
        """
        totals = {}
        for framework in FRAMEWORK_CHOICES:
            _, payload = _run(tmp_path / framework, framework=framework)
            totals[framework] = payload["summary"]["total"]

        from backend.ingest.generic import PatternAdapterRegistry
        from backend.rules.evaluator import RulesEvaluator

        text = FIXTURE.read_text(encoding=FILE_ENCODING)
        adapter = PatternAdapterRegistry().detect(text, FIXTURE.name)
        everything = RulesEvaluator().evaluate(
            adapter.parse(text, FIXTURE.name).facts,
            adapter.pack.vendor,
            adapter.pack.os_family,
        )
        assert sum(totals.values()) == len(everything), (
            f"the four framework runs sum to {sum(totals.values())} but an "
            f"unfiltered run yields {len(everything)} -- the filter is either "
            f"dropping or duplicating controls. Per framework: {totals}"
        )


class TestVendorAgnosticism:
    """The CLI must use the shared registry, not a private adapter list."""

    def test_it_parses_every_shipped_fixture(self, tmp_path: Path) -> None:
        """All ten fixtures, through the CLI, with no parse-error finding.

        This is the test that would have failed on the old private adapter list
        the moment a fixture was added for a vendor whose support arrived as a
        YAML pack. It is deliberately over the whole fixture directory rather
        than over one file: the failure mode is per-vendor, so a single-file test
        is a coin flip.
        """
        configs = sorted(CONFIG_DIR.rglob("*.conf"))
        assert len(configs) >= 10, "the fixture set has shrunk; this test is now weaker"

        for config in configs:
            code, payload = _run(tmp_path / config.stem, config=config, framework="CIS")
            ids = {f["control_id"] for f in payload["findings"]}
            assert code == 0, f"{config.name}: CLI returned {code}"
            assert "PARSE-ERROR" not in ids, (
                f"{config.name}: the CLI could not parse a fixture the API can. "
                "This is the private-adapter-list regression."
            )
            assert payload["device"]["vendor"], f"{config.name}: no vendor was detected"

    def test_the_registry_is_the_one_the_api_uses(self) -> None:
        """Same class, so a new pattern pack reaches both doors at once.

        Asserted on identity of the type rather than on behaviour because the
        behavioural version — "onboard a fake vendor and check both paths see it"
        — needs a pattern pack on disk, and a test that writes into
        ``data/ingest/patterns/`` races the library's own change detection.
        """
        import backend.cli as cli
        from backend.ingest.generic import PatternAdapterRegistry

        assert isinstance(cli._REGISTRY, PatternAdapterRegistry)
        assert not hasattr(cli, "_ADAPTERS"), (
            "the private adapter list is back; the CLI and the API will drift again"
        )


class TestRefusalsAndDegradation:
    """The paths that matter most are the ones where something is wrong."""

    def test_a_missing_config_is_an_error_not_an_empty_report(self, tmp_path: Path) -> None:
        """Exit 1 and no findings.json, rather than a clean audit of nothing.

        An empty report that exits 0 is the worst available outcome here: it is
        indistinguishable, to a script, from a device that passed everything.
        """
        out = tmp_path / "out"
        code = cmd_audit(_args(out, config=tmp_path / "does-not-exist.conf"))
        assert code == 1
        assert not (out / "findings.json").exists(), (
            "a findings.json for a config that was never read would be a report "
            "about nothing that a caller cannot tell from a report about a device"
        )

    def test_an_unparseable_config_reports_an_error_finding(self, tmp_path: Path) -> None:
        """R1.7: no parser matched must not become a clean pass.

        The content is deliberately valid text that is simply not a network
        config, which is the realistic version of this failure — a wrong file
        dragged into the tool, not a corrupt one.
        """
        junk = tmp_path / "shopping-list.conf"
        junk.write_text("milk\neggs\nbread\n", encoding=FILE_ENCODING)
        out = tmp_path / "out"
        code = cmd_audit(_args(out, config=junk))

        assert code == 1, "an unparseable config must not exit 0"
        payload = json.loads((out / "findings.json").read_text(encoding=FILE_ENCODING))
        assert [f["control_id"] for f in payload["findings"]] == ["PARSE-ERROR"]
        finding = payload["findings"][0]
        assert finding["result"] == "error"
        assert finding["severity"] == "high"
        assert "pattern pack" in finding["rationale"], (
            "the rationale should name the fix -- add a pattern pack -- not just "
            "state that detection failed"
        )

    def test_the_enum_serialises_as_its_value(self, tmp_path: Path) -> None:
        """``result`` is ``"pass"``, never ``"Result.PASS"``.

        This is not cosmetic. The Merkle root is computed over these dicts, so a
        bare ``model_dump`` produced a root over bytes no reader of the emitted
        findings.json could reproduce — the record's own findings would verify as
        tampered with. The CLI docstring records this; the assertion makes it a
        gate.
        """
        _, payload = _run(tmp_path)
        results = {f["result"] for f in payload["findings"]}
        assert results, "no findings to check"
        assert all("." not in r and r.islower() for r in results), (
            f"a result is not a plain enum value: {sorted(results)}"
        )
        frameworks = {f["framework"] for f in payload["findings"]}
        assert all("." not in f for f in frameworks), sorted(frameworks)


class TestOfflineLedgerRecord:
    """The CLI writes a self-contained record, and it has to be checkable."""

    def test_the_record_is_present_and_findings_are_not_duplicated(self, tmp_path: Path) -> None:
        """``audit_record`` carries the hashes but not a second findings list.

        The findings appear once, at the top level. Embedding them again inside
        the record would double a 97 KB file for no reader's benefit, and would
        create two copies that a later edit could put out of step — at which
        point the Merkle root matches one of them and the question of which is
        "the findings" has no answer.
        """
        _, payload = _run(tmp_path)
        record = payload["audit_record"]
        assert "findings" not in record
        for field in ("audit_id", "config_hash", "merkle_root", "record_hash", "created_at"):
            assert record[field], f"{field} is empty in the offline record"
        assert record["seq"] == 0 and record["prev_hash"] == "", (
            "an offline record is not part of the server's chain and must not "
            "claim a position in it"
        )

    def test_the_merkle_root_recomputes_from_the_emitted_findings(self, tmp_path: Path) -> None:
        """Recompute it from the JSON on disk, which is what a verifier has.

        Computing it from in-memory objects would test that the function is
        deterministic — true and uninteresting. The claim worth checking is that
        the root in the file describes the findings in the *same* file, because
        that is the only pair a third party can compare.
        """
        from backend.ledger.chain import compute_merkle_root

        _, payload = _run(tmp_path)
        assert compute_merkle_root(payload["findings"]) == payload["audit_record"]["merkle_root"]

    def test_a_tampered_finding_breaks_the_root(self, tmp_path: Path) -> None:
        """The negative control for the test above.

        Without this, ``compute_merkle_root`` returning a constant would pass.
        """
        from backend.ledger.chain import compute_merkle_root

        _, payload = _run(tmp_path)
        findings = payload["findings"]
        original = findings[0]["result"]
        findings[0]["result"] = "pass" if original != "pass" else "fail"
        assert compute_merkle_root(findings) != payload["audit_record"]["merkle_root"], (
            "flipping a verdict left the Merkle root unchanged, so the root does "
            "not actually bind the findings"
        )


class TestArgumentParsing:
    """``main()`` itself, once, for the plumbing the other tests bypass."""

    def test_main_dispatches_audit_and_rejects_a_bad_framework(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real ``argv`` round trip, plus the rejection ``argparse`` owns."""
        out = tmp_path / "out"
        monkeypatch.setattr(
            "sys.argv",
            ["praman-cli", "audit", "--config", str(FIXTURE), "--framework", "CIS", "--out", str(out)],
        )
        assert main() == 0
        assert (out / "findings.json").exists()

        monkeypatch.setattr(
            "sys.argv",
            ["praman-cli", "audit", "--config", str(FIXTURE), "--framework", "STIG", "--out", str(out)],
        )
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2, "an unknown framework should be an argparse usage error"

    def test_a_direct_framework_produces_verdicts_not_only_notchecked(self, tmp_path: Path) -> None:
        """CIS and DISA STIG are evaluated against facts, so they must decide.

        A run that came back entirely ``notchecked`` would still satisfy every
        shape assertion above while proving the rules never fired. Restricted to
        the direct frameworks because the projected two are crosswalked from
        these, and demanding verdicts there would be asserting the crosswalk.
        """
        for framework in sorted(DIRECT_FRAMEWORKS):
            _, payload = _run(tmp_path / framework, framework=framework)
            by_result = payload["summary"]["by_result"]
            decided = by_result.get("pass", 0) + by_result.get("fail", 0)
            assert decided > 0, f"{framework}: no control was decided either way"
            assert by_result.get("fail", 0) > 0 or framework == "CIS", (
                f"{framework}: nothing failed on a fixture chosen to fail things"
            )
