"""Tests for the per-device report -- the one artefact that leaves the building.

A report is read by someone who was not in the room. Every failure mode here is
a failure of *reading*: a number that is right in the data and wrong on the page,
a blank row that looks like a clean result, a command with somebody else's
hostname on it. So these tests read the rendered PDF back as text and assert on
what a person would see, rather than asserting that the renderer was called.

Text extraction is the right level for that. Asserting on PDF bytes would pass
for a report that drew white text on white paper, and asserting on the flowable
list would pass for one that never built. ``pdfplumber`` sees roughly what a
reader sees.

The renderer takes a ``summary`` argument it deliberately ignores. Several tests
pass a *wrong* summary on purpose: the previous renderer trusted it, and a caller
passing flat counts got an empty Executive Summary.
"""

from __future__ import annotations

import sys
from io import BytesIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.report.minimal_pdf import MinimalPdf, pdf_string, wrap
from backend.report.palette import RESULT_COLORS, SEVERITY_COLORS
from backend.report.render import (
    ROSTER_ENUMERATION_LIMIT,
    _control_key,
    _on_ink,
    _ordered,
    _render_degraded,
    _text,
    prepare,
    render_pdf,
)

pdfplumber = pytest.importorskip("pdfplumber")

DEVICE = {
    "device_id": "dev-r1",
    "hostname": "core-rtr-01",
    "vendor": "cisco_ios",
    "os_family": "ios",
    "os_version": "15.2(7)E3",
    "hardware": ["WS-C3750X-48P", "PWR-C1-350WAC"],
    "serials": ["FDO1734Z1AB", "FDO1734Z1CD"],
    "config_hash": "9f" * 32,
}

RECORD = {
    "audit_id": "aud-0003",
    "device_id": "dev-r1",
    "created_at": "2026-08-29T10:15:00+00:00",
    "seq": 3,
    "prev_hash": "aa" * 32,
    "record_hash": "bb" * 32,
    "merkle_root": "cc" * 32,
    "signature": "dd" * 32,
}

#: A control CIS ships prompt-prefixed CLI for, used wherever a test needs a
#: remediation block that resolves against the built catalogs.
CIS_WITH_CLI = "2.1.1.1.2"


def _finding(**overrides: object) -> dict:
    """A complete CIS finding. Overrides replace whole keys."""
    finding = {
        "control_id": "1.1.1",
        "framework": "CIS",
        "benchmark": "CIS Cisco IOS 15",
        "benchmark_version": "v4.1.1",
        "title": "Set 'transport output ssh' on all VTY lines",
        "result": "fail",
        "severity": "high",
        "rationale": "transport output permits telnet, so an operator hop leaves in clear text.",
        "evidence": [
            {
                "path": "line.vty.transport_output",
                "value": "telnet ssh",
                "present": True,
                "source_file": "core-rtr-01.conf",
                "line_start": 118,
                "line_end": 118,
                "raw_text": " transport output telnet ssh",
                "parser_id": "patterns.cisco_ios@1.0",
                "confidence": 1.0,
            }
        ],
        "remediation_ref": None,
        "references": {"catalog_id": "cis_cisco_ios_15_v4_1_1"},
    }
    finding.update(overrides)
    return finding


def _read(pdf_bytes: bytes) -> str:
    """All pages as one string, the way a reader takes it in."""
    with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)


@pytest.fixture(scope="module")
def report_text() -> str:
    """One full render, reused. Rendering is the slow part, not asserting."""
    findings = [
        _finding(),
        _finding(control_id="1.1.2", result="pass", severity="low", title="Set 'no ip http server'"),
        _finding(
            control_id="1.2.4",
            result="notchecked",
            severity="medium",
            title="Review the enable secret hashing algorithm",
            rationale="No automated check exists for this control.",
            evidence=[],
        ),
        _finding(
            control_id="V-215823",
            framework="DISA_STIG",
            benchmark="Cisco IOS Router NDM STIG",
            benchmark_version="V3R8",
            result="fail",
            severity="medium",
            references={},
        ),
    ]
    return _read(render_pdf(DEVICE, findings, {"total": 4}, RECORD))


# ── The report is a PDF, always ───────────────────────────────────────


def test_the_report_is_a_pdf(report_text: str) -> None:
    """The header is not decoration: the route declares this content type."""
    pdf = render_pdf(DEVICE, [_finding()], {}, RECORD)
    assert pdf.startswith(b"%PDF-"), pdf[:40]
    assert pdf.rstrip().endswith(b"%%EOF")


def test_the_degraded_report_is_also_a_pdf() -> None:
    """The defect this replaced.

    The old fallback returned ``json.dumps(...)`` bytes, which the route served
    as ``application/pdf``. Every consumer in the chain -- browser, mail client,
    evidence archive -- would have reported a corrupt PDF, and the real cause
    (ReportLab missing) would never have appeared in that message.
    """
    degraded = _render_degraded(
        prepare(DEVICE, [_finding()], RECORD), reason="ReportLab is not installed"
    )
    assert degraded.startswith(b"%PDF-")
    with pdfplumber.open(BytesIO(degraded)) as pdf:
        assert pdf.pages, "a PDF with no pages is not a readable document"


def test_both_paths_report_the_same_score() -> None:
    """Two renderers, one set of figures.

    They share a :class:`~backend.report.render.ReportData` precisely so this
    cannot drift. A fallback that reported a different score from the real
    renderer would be wrong only on the copy that got filed.
    """
    findings = [_finding(), _finding(control_id="1.1.2", result="pass")]
    full = _read(render_pdf(DEVICE, findings, {}, RECORD))
    degraded = _read(_render_degraded(prepare(DEVICE, findings, RECORD), reason="probe"))
    assert "50.0%" in full
    assert "50.0%" in degraded


def test_the_degraded_report_says_it_is_degraded() -> None:
    """Silently dropping the charts and remediation would misrepresent coverage."""
    text = _read(_render_degraded(prepare(DEVICE, [_finding()], RECORD), reason="probe"))
    assert "text-only" in text.lower()
    assert "reportlab" in text.lower()


def test_the_report_is_byte_identical_across_runs() -> None:
    """Two renders of one committed audit must agree byte for byte.

    ReportLab stamps a creation date by default, which would make the archived
    copy and a re-render differ for a reason that has nothing to do with the
    device -- and make any hash over the PDF useless as an identifier.
    """
    findings = [_finding()]
    assert render_pdf(DEVICE, findings, {}, RECORD) == render_pdf(DEVICE, findings, {}, RECORD)


# ── C4: device identity, including hardware and serials ───────────────


def test_the_device_is_identified_by_serial_and_hardware(report_text: str) -> None:
    """Device reports include serial numbers and hardware explicitly."""
    assert "FDO1734Z1AB" in report_text
    assert "FDO1734Z1CD" in report_text
    assert "WS-C3750X-48P" in report_text
    assert "15.2(7)E3" in report_text


def test_a_list_is_never_printed_as_a_python_repr(report_text: str) -> None:
    """The old cover page printed ``['FDO1734Z1AB', 'FDO1734Z1CD']``.

    Brackets and quotes on the page are a tell that nobody read the output --
    on the two fields that identify the device in its report.
    """
    assert "['" not in report_text
    assert "']" not in report_text
    assert "FDO1734Z1AB, FDO1734Z1CD" in report_text


def test_a_missing_serial_says_which_upload_would_supply_it() -> None:
    """Config-only input has no serials. A blank row reads as an oversight.

    Naming the missing input turns a gap into an instruction, which matters
    because config-only is the common case for this system.
    """
    bare = {"device_id": "dev-x", "vendor": "cisco_ios", "os_family": "ios"}
    text = _read(render_pdf(bare, [_finding()], {}, RECORD))
    assert "show version" in text
    assert "show inventory" in text


def test_a_device_with_no_hostname_is_labelled_not_blanked() -> None:
    """An unconfigured hostname is a finding in its own right, not an error."""
    bare = {"device_id": "dev-x", "vendor": "cisco_ios"}
    assert "not configured" in _read(render_pdf(bare, [_finding()], {}, RECORD))


# ── The score, and its denominator ────────────────────────────────────


def test_the_score_comes_from_the_engines_own_function() -> None:
    """One definition of the number, shared with the API and the CLI."""
    findings = [
        _finding(result="pass"),
        _finding(control_id="1.1.2", result="pass"),
        _finding(control_id="1.1.3", result="fail"),
        _finding(control_id="1.1.4", result="notchecked"),
    ]
    data = prepare(DEVICE, findings, RECORD)
    assert data.score["score"] == pytest.approx(66.7)
    assert data.score["scored_controls"] == 3
    assert "66.7%" in _read(render_pdf(DEVICE, findings, {}, RECORD))


def test_the_score_always_carries_its_basis(report_text: str) -> None:
    """A percentage with no stated denominator is a marketing figure."""
    assert "pass / (pass + fail)" in report_text
    assert "excluded from the ratio" in report_text.lower()


def test_unscored_controls_are_counted_where_a_reader_can_see_them(report_text: str) -> None:
    """1.2.4 is notchecked. It must appear as excluded, not vanish.

    A control silently dropped from both numerator and denominator is how a
    score of 100% coexists with a device nobody checked.
    """
    assert "1 not checked" in report_text
    assert "1.2.4" in report_text


def test_the_summary_argument_cannot_change_a_single_figure() -> None:
    """The renderer ignores ``summary``, and this proves it.

    The argument survives for signature compatibility. It arrives in at least two
    shapes -- ``{total, by_result, by_severity}`` from ``build_summary`` and flat
    counts from other callers -- and trusting it produced an empty summary for the
    second kind. A lying summary must not move the numbers.
    """
    findings = [_finding(result="pass"), _finding(control_id="1.1.2", result="fail")]
    honest = render_pdf(DEVICE, findings, {"by_result": {"pass": 1, "fail": 1}}, RECORD)
    lying = render_pdf(DEVICE, findings, {"by_result": {"pass": 99, "fail": 0}}, RECORD)
    assert honest == lying
    assert "50.0%" in _read(honest)


# ── Coverage: what was not audited, and how much of it ────────────────
#
# The defect these exist for was found by rendering a real device: 1,462 findings
# of which 1,391 were notchecked, each given a full detailed block, produced a
# 266-page report whose every page after the fourth said "no automated check
# exists". The fix has two failure modes pulling opposite ways -- a report too
# long to read, and a report that quietly drops the controls it did not check and
# so overstates its own coverage. Both are tested.


def _roster_device(count: int, *, result: str = "notchecked") -> list[dict]:
    """``count`` unevaluated controls plus one real failure to score against."""
    findings = [_finding(control_id="1.1.1", result="fail")]
    findings.extend(
        _finding(
            control_id=f"9.{index}",
            result=result,
            title=f"Unmapped control {index}",
            evidence=[],
        )
        for index in range(1, count + 1)
    )
    return findings


def test_a_control_nobody_checked_does_not_get_a_page_of_its_own() -> None:
    """1,400 unevaluated controls must not become 250 pages.

    The page count is the assertion because it is the thing that made the report
    unusable. A reader will not find the twenty-three failures that matter in a
    document where 96% of the pages say only that a control was never checked.
    """
    findings = _roster_device(1400)
    pdf = render_pdf(DEVICE, findings, {}, RECORD)
    with pdfplumber.open(BytesIO(pdf)) as opened:
        pages = len(opened.pages)
    assert pages <= 12, f"1,400 unevaluated controls produced {pages} pages"


def test_a_large_roster_still_states_its_own_size() -> None:
    """Compressing the roster must not be indistinguishable from omitting it.

    Above the enumeration limit the ids are not printed -- but the count, the
    per-framework breakdown and the pointer to the attachment that does hold every
    id all are. Silence about a control reads as coverage of it.
    """
    text = _read(render_pdf(DEVICE, _roster_device(1400), {}, RECORD))
    assert "Coverage" in text
    assert "1400 of 1401 controls reached no verdict" in text
    assert "1400 notchecked" in text
    assert "01_findings.json" in text, "the reader needs somewhere to get the ids"


def test_a_short_roster_is_enumerated_in_full() -> None:
    """Below the limit, every unevaluated control id is on the page.

    A ten-control roster fits, and a reader looking for one specific control
    should not have to open a JSON attachment to find out it was skipped.
    """
    count = 10
    assert count <= ROSTER_ENUMERATION_LIMIT
    text = _read(render_pdf(DEVICE, _roster_device(count), {}, RECORD))
    for index in range(1, count + 1):
        assert f"9.{index}" in text, f"control 9.{index} is missing from the roster"
    assert "not enumerated here" not in text


def test_the_roster_says_why_each_control_was_not_evaluated() -> None:
    """``notchecked`` is jargon; the report must say what it means.

    To a reader who has not read the XCCDF specification, "notchecked" is
    indistinguishable from "checked, nothing wrong" -- which is the exact
    misreading that turns an unaudited control into an assumed-compliant one.
    """
    findings = _roster_device(3)
    findings.append(
        _finding(control_id="8.1", result="notapplicable", title="Wireless controls", evidence=[])
    )
    text = _read(render_pdf(DEVICE, findings, {}, RECORD))
    assert "no automated check is mapped" in text
    assert "does not apply to this device's platform" in text


def test_an_unevaluated_control_is_never_counted_as_a_pass() -> None:
    """The roster changes presentation, not arithmetic.

    One failure and 1,400 unchecked controls is a score of 0.0, not of 99.9. The
    split that shortened the report must not have moved a single control into the
    denominator or out of it.
    """
    text = _read(render_pdf(DEVICE, _roster_device(1400), {}, RECORD))
    assert "0.0%" in text
    assert "1400 not checked" in text


def test_the_roster_carries_no_remediation() -> None:
    """A fix for a control that may well be compliant would change a working box.

    ``notchecked`` means PRAMAN does not know. Printing the publisher's fix text
    against it invites an operator to reconfigure a device on no evidence.
    """
    findings = [
        _finding(control_id=CIS_WITH_CLI, result="notchecked", evidence=[]),
    ]
    data = prepare(DEVICE, findings, RECORD)
    assert data.entries == ()
    assert len(data.roster) == 1
    assert "Remediation" not in _read(render_pdf(DEVICE, findings, {}, RECORD))


def test_the_degraded_report_accounts_for_the_roster_too() -> None:
    """Both renderers, or the fallback copy is the one that overstates coverage.

    The degraded path is the copy that gets filed when ReportLab is missing from a
    deployment, and nobody compares it against the graphical one.
    """
    data = prepare(DEVICE, _roster_device(1400), RECORD)
    text = _read(_render_degraded(data, reason="ReportLab is not installed"))
    assert "COVERAGE" in text, "the fallback renderer uppercases its headings"
    assert "1400 notchecked" in text
    assert "01_findings.json" in text


# ── Reading order: the worst thing first ──────────────────────────────


def test_failures_are_printed_before_passes() -> None:
    """Catalogue order buries a high-severity failure behind forty passes.

    The report is read by someone deciding what to do next, often only as far as
    the second page. What is wrong has to be on it. The two passes keep
    control-id order rather than severity order: the severity of a control that
    passed is not risk, and a reader hunting for 1.1.1 should find it first.
    """
    findings = [
        _finding(control_id="1.1.1", result="pass", severity="low"),
        _finding(control_id="1.1.2", result="pass", severity="high"),
        _finding(control_id="1.1.3", result="fail", severity="medium"),
        _finding(control_id="1.1.4", result="fail", severity="high"),
    ]
    order = [finding["control_id"] for finding, _ in _ordered(tuple((f, None) for f in findings))]
    assert order == ["1.1.4", "1.1.3", "1.1.1", "1.1.2"]


def test_a_high_severity_failure_outranks_a_low_one() -> None:
    """Within the failures, risk decides the order."""
    findings = [
        _finding(control_id="2.1", result="fail", severity="low"),
        _finding(control_id="2.2", result="fail", severity="unknown"),
        _finding(control_id="2.3", result="fail", severity="high"),
        _finding(control_id="2.4", result="fail", severity="medium"),
    ]
    order = [finding["control_id"] for finding, _ in _ordered(tuple((f, None) for f in findings))]
    assert order == ["2.3", "2.4", "2.1", "2.2"]


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("2.9", "2.10"),
        ("1.1.1", "1.1.10"),
        ("V-215807", "V-215823"),
        ("2.1.1.1.2", "2.1.1.2"),
    ],
)
def test_control_ids_sort_the_way_a_reader_expects(earlier: str, later: str) -> None:
    """Lexicographic order puts 2.10 before 2.9 and scatters a benchmark section.

    In a 90-control benchmark that is not cosmetic: the operator working through
    section 2.1 finds its controls interleaved with section 2.10's.
    """
    assert _control_key(earlier) < _control_key(later)


# ── Charts, and their mandated twins ──────────────────────────────────


def test_every_chart_is_accompanied_by_its_numbers(report_text: str) -> None:
    """R23: a chart without a table cannot be checked.

    The chart's own axis labels are not enough -- the twin table states the count
    and the share, which is what someone re-deriving the figure needs.
    """
    assert "Compliance score" in report_text
    assert "Severity of failures" in report_text
    assert "Pass and fail by framework" in report_text
    assert "All results, including the non-verdicts" in report_text
    # Twin-table headers. These exist only in table form -- no chart axis
    # produces the word "Share" or the pair "Measure / Value".
    assert "Share" in report_text
    assert "Measure" in report_text


def test_severity_is_charted_from_failures_only() -> None:
    """The subtle one.

    ``build_summary``'s ``by_severity`` counts every finding, so charting it puts
    passing controls in the high-severity bar. Here two controls are rated high
    and only one fails; a report that says "2" is describing the benchmark's
    ratings, not this device's risk.
    """
    findings = [
        _finding(result="fail", severity="high"),
        _finding(control_id="1.1.2", result="pass", severity="high"),
        _finding(control_id="1.1.3", result="fail", severity="low"),
    ]
    data = prepare(DEVICE, findings, RECORD)
    assert data.failure_severities == {"high": 1, "low": 1}
    assert "high" not in {k: v for k, v in data.failure_severities.items() if v == 2}


def test_a_thin_chart_is_absent_and_explained() -> None:
    """One audit is not a trend, and the report says so rather than drawing one."""
    text = _read(render_pdf(DEVICE, [_finding()], {}, RECORD))
    assert "at least two committed audits" in text


def test_a_trend_appears_once_the_ledger_has_history() -> None:
    """Indexed by ledger sequence, which is what the chart builder promises."""
    text = _read(
        render_pdf(
            DEVICE, [_finding()], {}, RECORD,
            history=[(1, 40.0), (2, 55.5), (3, 61.0)],
        )
    )
    assert "at least two committed audits" not in text
    assert "61.0" in text


def test_no_failures_is_stated_rather_than_charted_as_zero() -> None:
    """A bar chart of four zeroes reads as a rendering bug, not as a clean device."""
    text = _read(render_pdf(DEVICE, [_finding(result="pass")], {}, RECORD))
    assert "No control failed" in text


# ── Verdicts are legible without colour ───────────────────────────────


def test_every_verdict_carries_a_word_and_a_mark(report_text: str) -> None:
    """R11.2: never state anything by colour alone.

    Eight percent of male readers have a red-green deficiency, and a great many
    compliance reports are printed in greyscale.
    """
    assert "FAIL" in report_text
    assert "PASS" in report_text
    assert "HIGH SEVERITY" in report_text
    assert "[!]" in report_text


def test_an_unknown_severity_is_not_given_the_low_risk_colour() -> None:
    """``SEVERITY_COLORS`` has three keys on purpose.

    An unrated control falling back to ``low``'s pale pink tells the reader it is
    low risk. Nobody said that. It gets the amber of an unknown result instead.
    """
    assert "unknown" not in SEVERITY_COLORS["light"]
    assert RESULT_COLORS["unknown"] != SEVERITY_COLORS["light"]["low"]
    text = _read(render_pdf(DEVICE, [_finding(severity="unknown")], {}, RECORD))
    assert "UNKNOWN SEVERITY" in text


@pytest.mark.parametrize(
    ("background", "expected"),
    [
        (SEVERITY_COLORS["light"]["high"], "#ffffff"),   # #801f1f, dark
        (SEVERITY_COLORS["light"]["low"], "#000000"),    # #eb9a9a, pale
        (RESULT_COLORS["notselected"], "#000000"),       # #e1e0d9, near-white
        (RESULT_COLORS["fail"], "#ffffff"),              # #d03b3b
    ],
)
def test_chip_text_stays_legible_on_every_chip_colour(background: str, expected: str) -> None:
    """The severity ramp spans pale pink to near-black; one text colour cannot serve both."""
    assert _on_ink(background) == expected


# ── Evidence: the six-field provenance ────────────────────────────────


def test_a_verdict_cites_the_line_it_was_read_from(report_text: str) -> None:
    """Without a file and a line number a verdict is an assertion."""
    assert "core-rtr-01.conf:118" in report_text
    assert "transport output telnet ssh" in report_text
    assert "line.vty.transport_output" in report_text


def test_an_absent_line_is_printed_as_absent_not_as_blank() -> None:
    """``present: false`` is frequently the entire reason for the failure.

    Rendering it as an empty cell is the report-level version of scoring missing
    evidence as a pass.
    """
    finding = _finding(
        evidence=[{
            "path": "mgmt.ssh.version",
            "value": None,
            "present": False,
            "source_file": "core-rtr-01.conf",
            "line_start": None,
            "line_end": None,
            "raw_text": "",
            "parser_id": "patterns.cisco_ios@1.0",
            "confidence": 1.0,
        }]
    )
    assert "not present in configuration" in _read(render_pdf(DEVICE, [finding], {}, RECORD))


def test_a_finding_with_no_evidence_says_so() -> None:
    """A finding the renderer cannot trace must announce that, not print nothing."""
    text = _read(render_pdf(DEVICE, [_finding(evidence=[])], {}, RECORD))
    assert "cannot be traced" in text


def test_an_ai_assisted_fact_is_flagged_as_such() -> None:
    """Confidence below 1.0 means a model classified this leaf.

    The verdict is still deterministic -- but the input to it was not certain, and
    a reader deciding whether to act on the finding needs that.
    """
    finding = _finding(
        evidence=[{
            "path": "line.aux.exec_timeout",
            "value": 0,
            "present": True,
            "source_file": "core-rtr-01.conf",
            "line_start": 91,
            "line_end": 91,
            "raw_text": " exec-timeout 0 0",
            "parser_id": "setfit.cisco_ios@0.3",
            "confidence": 0.82,
        }]
    )
    text = _read(render_pdf(DEVICE, [finding], {}, RECORD))
    assert "AI-assisted" in text
    assert "0.82" in text


def test_a_config_line_containing_markup_cannot_break_the_report() -> None:
    """Config text arrives in an uploaded file, so it is attacker-influenced.

    ReportLab paragraphs are mini-XML. An unescaped ``<b>`` in an interface
    description would reformat the report; an unclosed tag would abort the build.
    """
    finding = _finding(
        title="Interface <b>description</b> & policy",
        rationale="description set to <script>alert(1)</script> & unclosed <b",
        evidence=[{
            "path": "interface.description",
            "value": "<not-a-tag",
            "present": True,
            "source_file": "core-rtr-01.conf",
            "line_start": 12,
            "line_end": 12,
            "raw_text": " description <uplink & core>",
            "parser_id": "patterns.cisco_ios@1.0",
            "confidence": 1.0,
        }],
    )
    text = _read(render_pdf(DEVICE, [finding], {}, RECORD))
    assert "alert(1)" in text
    assert "uplink & core" in text


# ── Remediation: cited, device-specific, never generated ──────────────


def test_a_failure_gets_the_publishers_command_on_this_devices_prompt() -> None:
    """C4's "device-specific step-by-step remediation CLI", literally.

    The publisher writes ``hostname (config)#``. What reaches the operator has to
    say ``core-rtr-01(config)#`` or they are reading someone else's device.
    """
    text = _read(render_pdf(DEVICE, [_finding(control_id=CIS_WITH_CLI)], {}, RECORD))
    assert "core-rtr-01(config)#" in text
    assert "hostname (config)#" not in text


def test_every_command_block_carries_its_citation() -> None:
    """What separates an extracted command from a generated one."""
    text = _read(render_pdf(DEVICE, [_finding(control_id=CIS_WITH_CLI)], {}, RECORD))
    assert "CIS Cisco IOS 15" in text
    assert "Source" in text


def test_a_template_is_flagged_before_the_operator_reaches_it() -> None:
    """Ordering is the whole point.

    Someone who reads top to bottom and stops at the first runnable-looking line
    must already have passed the sentence saying it contains a placeholder.
    """
    text = _read(render_pdf(DEVICE, [_finding(control_id=CIS_WITH_CLI)], {}, RECORD))
    note_at = text.find("templates, not ready to paste")
    command_at = text.find("core-rtr-01(config)#")
    assert note_at != -1, "the substitution warning is missing"
    assert note_at < command_at, "the warning prints after the command it warns about"
    assert "substitute first" in text


def test_a_passing_control_gets_no_remediation() -> None:
    """A fix printed under a pass invites an operator to change a working device."""
    text = _read(render_pdf(DEVICE, [_finding(control_id=CIS_WITH_CLI, result="pass")], {}, RECORD))
    assert "Remediation" not in text


def test_an_indeterminate_control_gets_no_remediation() -> None:
    """``unknown`` means the check did not conclude, not that the control failed."""
    text = _read(
        render_pdf(DEVICE, [_finding(control_id=CIS_WITH_CLI, result="unknown")], {}, RECORD)
    )
    assert "Remediation" not in text


def test_an_uncovered_control_says_so_rather_than_going_blank() -> None:
    """A blank remediation section reads as "compliant" to anyone skimming."""
    text = _read(
        render_pdf(
            DEVICE,
            [_finding(control_id="V-999999", framework="DISA_STIG", references={})],
            {}, RECORD,
        )
    )
    assert "gap in PRAMAN's coverage" in text


def test_unrated_risk_is_stated_rather_than_defaulted() -> None:
    """"Risk: low" would be an invention. Nobody rated it."""
    text = _read(render_pdf(DEVICE, [_finding(control_id=CIS_WITH_CLI)], {}, RECORD))
    assert "not rated by the publisher" in text


def test_the_renderer_cannot_reach_the_ai_package() -> None:
    """Structural, not behavioural: R3 forbids generated CLI in this path.

    A behavioural test only proves no model ran on the inputs it was given. This
    proves the import is not there to be called.
    """
    source = Path(__file__).resolve().parents[1] / "backend" / "report" / "render.py"
    text = source.read_text(encoding="utf-8")
    for forbidden in ("backend.ai", "llama", "llm_", "openai"):
        assert forbidden not in text, f"{forbidden} reached the renderer"


# ── Verification: hashes in full ──────────────────────────────────────


def test_hashes_are_printed_in_full(report_text: str) -> None:
    """The defect this replaced.

    The old renderer wrote ``str(record_hash)[:32] + "..."``. A truncated hash
    cannot be recomputed, so the Verification section verified nothing while
    looking as though it did.
    """
    for value in (RECORD["record_hash"], RECORD["merkle_root"], RECORD["prev_hash"]):
        assert value in report_text, f"{value[:12]}... was truncated"


def test_no_hash_is_followed_by_an_ellipsis(report_text: str) -> None:
    """Specifically the ``hash + "..."`` shape, which is the one that misleads."""
    assert f"{RECORD['record_hash'][:32]}..." not in report_text


def test_a_genesis_record_explains_its_empty_previous_hash() -> None:
    """Empty ``prev_hash`` is a fact about the chain, not a missing value."""
    genesis = {**RECORD, "seq": 1, "prev_hash": ""}
    text = _read(render_pdf(DEVICE, [_finding()], {}, genesis))
    assert "first record in the ledger" in text


def test_every_page_carries_the_record_hash(report_text: str) -> None:
    """Reports get printed and pages get separated.

    A page with no link back to a ledger record is an unattributable claim about
    a device.
    """
    pdf = render_pdf(
        DEVICE, [_finding(control_id=f"1.1.{n}") for n in range(30)], {}, RECORD
    )
    with pdfplumber.open(BytesIO(pdf)) as doc:
        assert len(doc.pages) > 1, "need a multi-page report to test the footer"
        for index, page in enumerate(doc.pages, start=1):
            page_text = page.extract_text() or ""
            assert RECORD["record_hash"][:16] in page_text, f"page {index} has no record hash"
            assert f"page {index}" in page_text


# ── Empty and hostile inputs ──────────────────────────────────────────


def test_no_findings_is_not_reported_as_compliant() -> None:
    """Zero findings means no rule applied, which is a coverage statement.

    Rendering it as a clean report is the most consequential misreading this
    document could invite.
    """
    text = _read(render_pdf(DEVICE, [], {}, RECORD))
    assert "not a clean bill of health" in text
    assert "no rule" in text


def test_a_finding_missing_optional_keys_still_renders() -> None:
    """SQLite rows and hand-built dicts do not all carry every key."""
    minimal = {"control_id": "x", "result": "fail", "severity": "high"}
    assert render_pdf(DEVICE, [minimal], {}, RECORD).startswith(b"%PDF-")


def test_an_empty_audit_record_still_produces_a_readable_report() -> None:
    """The renderer must not be the thing that fails when the ledger row is thin."""
    assert render_pdf(DEVICE, [_finding()], {}, {}).startswith(b"%PDF-")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, ""),
        (True, "yes"),
        (False, "no"),
        (["a", "b"], "a, b"),
        ([], ""),
        ([None, "a"], "a"),
        ({"b": 2, "a": 1}, "a: 1; b: 2"),
        (7, "7"),
    ],
)
def test_display_coercion_never_leaks_a_repr(value: object, expected: str) -> None:
    """Every shape that reaches a cell, and what a reader should see."""
    assert _text(value) == expected


# ── The minimal PDF writer ────────────────────────────────────────────


def test_a_parenthesis_in_config_text_cannot_corrupt_the_file() -> None:
    """Parentheses delimit PDF strings. ``ip nat pool (inside)`` is real config.

    Unescaped, it ends the string object early and the file will not open --
    a corruption triggered by the contents of a customer's config.
    """
    assert pdf_string("pool (inside) \\ x") == rb"(pool \(inside\) \\ x)"


def test_text_outside_latin1_degrades_visibly_rather_than_silently() -> None:
    """A replacement character is a visible defect; a truncated file is not.

    Accented Latin survives -- ``WinAnsiEncoding`` covers it, and a Spanish
    interface description should render correctly. CJK and the box-drawing
    characters this project's own docs use do not, and become ``?``.
    """
    assert pdf_string("descripción") == b"(descripci\xf3n)"
    assert pdf_string("日本 ─ ok") == b"(?? ? ok)"


def test_a_long_hash_is_wrapped_rather_than_run_off_the_page() -> None:
    """A hash that runs past the margin is not a verifiable hash."""
    lines = wrap("f" * 200, 400.0)
    assert len(lines) > 1
    assert "".join(lines) == "f" * 200


def test_the_minimal_writer_paginates() -> None:
    """More lines than fit on a page must not overprint the footer."""
    doc = MinimalPdf()
    for index in range(400):
        doc.body(f"line {index}")
    with pdfplumber.open(BytesIO(doc.build())) as pdf:
        assert len(pdf.pages) >= 5


def test_the_minimal_writers_xref_offsets_are_correct() -> None:
    """pikepdf parses the cross-reference table; pdfplumber is more forgiving.

    Every xref entry must be exactly 20 bytes because readers seek by
    multiplication. One byte off makes the whole file unreadable, and a
    hand-rolled writer is exactly where that happens.
    """
    pikepdf = pytest.importorskip("pikepdf")
    doc = MinimalPdf(title="offsets")
    doc.heading("h")
    doc.body("body")
    with pikepdf.Pdf.open(BytesIO(doc.build())) as pdf:
        assert len(pdf.pages) == 1
