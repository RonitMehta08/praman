"""Per-device compliance report -- Stage 1 of ``render -> attach -> sign``.

This is the artefact C4 asks for, and the only part of PRAMAN that leaves the
building. It gets attached to an email, filed as evidence, and read by someone
who was not present for the audit. Four things follow from that.

**Absence of evidence is not a pass.** Every count here is derived from the
findings list rather than read out of the caller's ``summary`` dict. The summary
travels in more than one shape -- ``build_summary`` produces
``{total, by_result, by_severity}`` while some callers pass flat counts -- and a
renderer that trusted it printed an empty Executive Summary for the second kind.
More subtly, ``build_summary``'s ``by_severity`` counts *every* finding, so
charting it labels the severity of things that passed as though it were risk.
The severity chart is built from failures alone.

**One number, one definition.** The headline score comes from
:func:`~backend.rules.evaluator.compute_compliance_score`, the same function the
engine and API use, and its ``basis`` sentence is printed next to it. A score
without its denominator is a marketing figure.

**Every chart ships with its table.** :mod:`backend.report.charts` returns a
:class:`~backend.report.charts.Chart` carrying both, laid out side by side, so
the renderer cannot present a picture whose numbers disagree with the figures.
Charts that would mislead at small n return ``None`` and are simply absent.

**Commands are cited, never generated.** Remediation comes from
:mod:`backend.remediation.engine`, which extracts the publisher's own fix text
and rewrites the prompt for this device. No model is in this path (R3).

Hashes are printed in full. A truncated hash cannot be verified, so the
Verification section is the one place where wrapping ugly text is the correct
trade. ReportLab 5.0.1 default-denies remote fetch (S22.2); every asset is local.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from xml.sax.saxutils import escape

from backend.remediation.engine import (
    KIND_CLI,
    KIND_MANUAL,
    KIND_NONE,
    Remediation,
    resolve_remediation,
)
from backend.report import charts as chart_builders
from backend.report.minimal_pdf import MinimalPdf
from backend.report.palette import RESULT_COLORS, SEVERITY_COLORS
from backend.rules.evaluator import compute_compliance_score, result_value

#: Result order for the summary table: the outcomes that carry a verdict first,
#: then the ones that explain why a verdict is missing.
RESULT_ORDER = (
    "pass", "fail", "error", "unknown",
    "fixed", "notapplicable", "notchecked", "notselected", "informational",
)

SEVERITY_ORDER = ("high", "medium", "low", "unknown")

#: R11.2 forbids conveying state by colour alone. Each chip carries a mark and a
#: word as well as its hue, so the report survives greyscale printing and the
#: eight percent of male readers with a red-green deficiency.
RESULT_MARKS = {
    "pass": "[+]", "fail": "[!]", "error": "[x]", "unknown": "[?]",
    "fixed": "[*]", "notapplicable": "[/]", "notchecked": "[ ]",
    "notselected": "[ ]", "informational": "[i]",
}
SEVERITY_MARKS = {"high": "[!!!]", "medium": "[!!]", "low": "[!]", "unknown": "[?]"}

#: Only a failure gets a remediation block. ``unknown`` and ``error`` mean the
#: check did not reach a verdict, and printing a fix for a control that may well
#: be compliant would have the operator change a working device.
_REMEDIABLE = frozenset({"fail"})

#: Fields whose absence is meaningful. A blank Serial Numbers row reads as an
#: oversight; "not present in the supplied input" reads as what it is, and tells
#: the operator which upload would fill it.
_INVENTORY_HINT = (
    "not present in the supplied input -- upload 'show version' and "
    "'show inventory' output alongside the configuration to populate this"
)

#: Shown when a ledger record carries no ``actor``. Only records written before
#: operator identity existed can be in that state, and saying so is the point: a
#: blank cell invites the reader to assume the field was never populated, when in
#: fact this report was produced from a row that nobody can be held to.
#: ``scripts/reset_ledger.py`` (MANUAL_COMMANDS.md Step 12) is what clears it.
_UNATTRIBUTED = "not recorded -- this audit predates operator identity"


def _text(value: Any) -> str:
    """Coerce to display text without ever printing a Python repr.

    ``str(["WS-C2960", "PWR-C1"])`` renders as ``['WS-C2960', 'PWR-C1']`` in the
    PDF, brackets and quotes included, which is what the previous cover page did
    for hardware and serial numbers -- the two fields C4 names explicitly.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(item) for item in value if _text(item))
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_text(item)}" for key, item in sorted(value.items()))
    return str(value)


def _score_text(score: dict) -> str:
    """The score as it should be *printed*: an em dash when nothing was scored.

    ``score_from_counts`` returns a float, so it must return ``0.0`` when the
    denominator is empty. On a report cover that reads as "this device failed
    every check", which is the opposite of the truth — nothing was checked. The
    case is not hypothetical: an Arista switch has no CIS benchmark in the loaded
    catalogs, so a CIS report on one decides nothing, and a printed 0.0% would be
    a signed PDF asserting total non-compliance about a device the framework has
    no opinion on. The counts line directly below always states the denominator,
    so the em dash costs the reader nothing.
    """
    if int(score.get("scored_controls", 0) or 0) == 0:
        return "—"
    return f"{score['score']}%"


def _esc(value: Any) -> str:
    """Escape for ReportLab's mini-XML paragraph markup.

    Config text is attacker-influenced -- it arrives in an uploaded file -- and an
    interface description containing ``<b>`` would otherwise change the report's
    formatting or abort the build.
    """
    return escape(_text(value))


def _on_ink(hex_colour: str) -> str:
    """Black or white, whichever is legible on the given background.

    Relative luminance by the sRGB coefficients. The severity ramp runs from
    ``#eb9a9a`` to ``#801f1f``, so a fixed text colour is unreadable at one end
    or the other.
    """
    raw = hex_colour.lstrip("#")
    red, green, blue = (int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return "#000000" if 0.299 * red + 0.587 * green + 0.114 * blue > 0.6 else "#ffffff"


def _result_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by XCCDF result, from the findings themselves."""
    counts: dict[str, int] = {}
    for finding in findings:
        value = result_value(finding)
        counts[value] = counts.get(value, 0) + 1
    return counts


def _framework_counts(findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Pass/fail per framework, for the stacked bar."""
    counts: dict[str, dict[str, int]] = {}
    for finding in findings:
        value = result_value(finding)
        if value not in ("pass", "fail"):
            continue
        bucket = counts.setdefault(str(finding.get("framework") or "unknown"), {})
        bucket[value] = bucket.get(value, 0) + 1
    return counts


def _failure_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Severity distribution over failures only.

    A severity is a property of an unmet control, not of a finding. Counting the
    severity of passes inflates the high-severity bar with controls that are
    satisfied -- which reads as risk that is not there.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        if result_value(finding) != "fail":
            continue
        severity = str(finding.get("severity") or "unknown").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _identity(device: dict[str, Any], audit_record: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """The device-identity block C4 requires, including hardware and serials.

    ``Committed by`` is here rather than in :func:`_verification` on purpose: it
    identifies the audit the way the rows above identify the device, and a reader
    deciding whether to act on this report wants it on the same page as the
    verdicts. It is a hashed field of the ledger record, so unlike a footer
    somebody typed, it cannot be changed without breaking the signature printed
    two pages later.
    """
    return (
        ("Device ID", _text(device.get("device_id"))),
        ("Hostname", _text(device.get("hostname")) or "not configured"),
        ("Vendor", _text(device.get("vendor"))),
        ("OS family", _text(device.get("os_family"))),
        ("OS version", _text(device.get("os_version")) or _INVENTORY_HINT),
        ("Hardware", _text(device.get("hardware")) or _INVENTORY_HINT),
        ("Serial numbers", _text(device.get("serials")) or _INVENTORY_HINT),
        ("Configuration SHA-256", _text(device.get("config_hash"))),
        ("Audit ID", _text(audit_record.get("audit_id"))),
        ("Audited at", _text(audit_record.get("created_at"))),
        ("Committed by", _text(audit_record.get("actor")) or _UNATTRIBUTED),
        ("Ledger sequence", _text(audit_record.get("seq"))),
    )


def _verification(audit_record: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Ledger fields, untruncated.

    ``prev_hash`` is empty for the genesis record, which is a fact about the
    chain rather than a missing value, so it is labelled as such.
    """
    prev = _text(audit_record.get("prev_hash"))
    return (
        ("Ledger sequence", _text(audit_record.get("seq"))),
        ("Previous record hash", prev or "(none -- this is the first record in the ledger)"),
        ("Record hash", _text(audit_record.get("record_hash"))),
        ("Merkle root over findings", _text(audit_record.get("merkle_root"))),
        ("Ed25519 signature", _text(audit_record.get("signature"))),
    )


#: Results that get a full block: verdict, evidence table, remediation.
#: A control PRAMAN never checked has nothing to show in either of the latter
#: two, and giving it a full block is how a real device produced a 266-page
#: report in which 1,391 of 1,462 entries said only "no automated check exists".
#: Those controls are still listed -- in a compact coverage roster, because
#: dropping them would overstate what was audited -- but they are not detailed.
_DETAILED = frozenset({"pass", "fail", "error", "unknown", "fixed", "informational"})

#: Results that mean "this control was not evaluated", listed in the roster.
_NOT_EVALUATED = frozenset({"notchecked", "notapplicable", "notselected"})

#: Above this many rosters rows, the roster is summarised by framework instead of
#: enumerated. 1,400 control ids across 40 pages is not something anyone reads,
#: and the count plus the framework breakdown is the part that carries meaning.
ROSTER_ENUMERATION_LIMIT = 60

#: What each non-verdict actually means, in the reader's terms. Printed with the
#: coverage roster because ``notchecked`` on its own is indistinguishable from
#: "checked, nothing wrong" to anyone who has not read the XCCDF specification --
#: and that misreading is the one this whole section exists to prevent.
NOT_EVALUATED_REASONS = {
    "notchecked": (
        "no automated check is mapped for this control on this platform; assess "
        "it by hand against the benchmark text"
    ),
    "notapplicable": (
        "the control does not apply to this device's platform, role or enabled "
        "features"
    ),
    "notselected": "the control lies outside the selected benchmark profile",
}

#: Reading order for the detailed findings: what needs doing, then what went
#: wrong, then what could not be determined, then what is fine. A reader who
#: stops after two pages has still seen every failure.
_ENTRY_ORDER = ("fail", "error", "unknown", "informational", "fixed", "pass")
_ENTRY_RANK = {name: index for index, name in enumerate(_ENTRY_ORDER)}
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

#: Results whose severity is risk, and so worth sorting by. The severity of a
#: control that *passed* is the severity it would have had -- ordering the passes
#: by it says nothing and costs a reader the control-id order they can scan.
#: Charting the severity of passes is the same mistake one level up; see the
#: module docstring on ``by_severity``.
_SEVERITY_IS_RISK = frozenset({"fail", "error"})
_SEGMENT = re.compile(r"[.\-_/]")


@dataclass(frozen=True)
class ReportData:
    """Everything both renderers print, computed once.

    The degraded text renderer and the ReportLab renderer consume this same
    object. That is deliberate: two independent computations of the same figures
    is how a fallback path ends up reporting a different score from the real one,
    and nobody would notice until the fallback was the copy that got filed.
    """

    identity: tuple[tuple[str, str], ...]
    score: dict[str, Any]
    result_counts: dict[str, int]
    framework_counts: dict[str, dict[str, int]]
    failure_severities: dict[str, int]
    trend: tuple[tuple[int, float], ...]
    entries: tuple[tuple[dict[str, Any], Remediation | None], ...]
    roster: tuple[dict[str, Any], ...]
    verification: tuple[tuple[str, str], ...]
    device_label: str

    @property
    def roster_by_framework(self) -> dict[str, dict[str, int]]:
        """Unevaluated controls per framework and reason, for the coverage note."""
        grouped: dict[str, dict[str, int]] = {}
        for finding in self.roster:
            bucket = grouped.setdefault(str(finding.get("framework") or "unknown"), {})
            reason = result_value(finding)
            bucket[reason] = bucket.get(reason, 0) + 1
        return grouped


def prepare(
    device: dict[str, Any],
    findings: list[dict[str, Any]],
    audit_record: dict[str, Any],
    history: list[tuple[int, float]] | None = None,
) -> ReportData:
    """Derive every figure the report prints, once, from the findings.

    Findings split two ways. Those that reached a verdict get a detailed block;
    those that were never evaluated go to the coverage roster. The split is a
    presentation decision only -- every finding appears in the score counts, and
    all of them are embedded in the PDF as machine-readable attachments.
    """
    entries: list[tuple[dict[str, Any], Remediation | None]] = []
    roster: list[dict[str, Any]] = []
    for finding in findings:
        result = result_value(finding)
        if result in _DETAILED:
            remediation = (
                resolve_remediation(finding, device) if result in _REMEDIABLE else None
            )
            entries.append((finding, remediation))
        else:
            roster.append(finding)

    return ReportData(
        identity=_identity(device, audit_record),
        score=compute_compliance_score(findings),
        result_counts=_result_counts(findings),
        framework_counts=_framework_counts(findings),
        failure_severities=_failure_severities(findings),
        trend=tuple(history or ()),
        entries=tuple(entries),
        roster=tuple(roster),
        verification=_verification(audit_record),
        device_label=_text(device.get("hostname") or device.get("device_id") or "device"),
    )


def _control_key(control_id: str) -> tuple[tuple[int, int, str], ...]:
    """Sort key over dotted control ids that puts 2.9 before 2.10.

    Lexicographic ordering of ``"2.10"`` and ``"2.9"`` puts them the wrong way
    round, which in a 90-control benchmark scatters a section across the report.
    Numeric segments sort as numbers, everything else as text, so ``V-215807``
    and ``2.1.1.1.2`` both come out in the order a reader expects.
    """
    return tuple(
        (0, int(segment), "") if segment.isdigit() else (1, 0, segment.lower())
        for segment in _SEGMENT.split(control_id)
    )


def _ordered(
    entries: tuple[tuple[dict[str, Any], Remediation | None], ...],
) -> list[tuple[dict[str, Any], Remediation | None]]:
    """Detailed findings in reading order: most actionable first.

    Catalogue order is the order the rules happen to be written in, which buries
    a high-severity failure behind forty passes. Sorting by verdict then severity
    means the first thing the reader sees is the worst thing that is wrong.

    Severity only orders the results where it means risk. Passes fall back to
    control-id order, which is the order someone looking for one specific control
    can actually scan.
    """
    def key(item: tuple[dict[str, Any], Remediation | None]) -> tuple[Any, ...]:
        finding = item[0]
        result = result_value(finding)
        severity = str(finding.get("severity") or "unknown").lower()
        return (
            _ENTRY_RANK.get(result, len(_ENTRY_ORDER)),
            _SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))
            if result in _SEVERITY_IS_RISK
            else 0,
            str(finding.get("framework") or ""),
            _control_key(str(finding.get("control_id") or "")),
        )

    return sorted(entries, key=key)


def _roster_rows(roster: tuple[dict[str, Any], ...]) -> list[tuple[str, str, str, str]]:
    """The roster as ``(control id, framework, reason, title)``, in reading order."""
    rows = [
        (
            _text(finding.get("control_id")),
            _text(finding.get("framework")),
            result_value(finding),
            _text(finding.get("title")),
        )
        for finding in roster
    ]
    return sorted(rows, key=lambda row: (row[1], _control_key(row[0])))


def _coverage_prose(data: ReportData) -> tuple[str, str]:
    """The two sentences that head the coverage section.

    Kept out of both renderers so the text cannot drift between them, and so the
    count in the sentence is the count in the table by construction.
    """
    total = int(data.score["total_controls"])
    reasons = sorted({result_value(finding) for finding in data.roster})
    named = ", ".join(
        f"{sum(1 for f in data.roster if result_value(f) == reason)} {reason}"
        for reason in reasons
    )
    headline = (
        f"{len(data.roster)} of {total} controls reached no verdict on this "
        f"device ({named}). They are excluded from the score and listed here "
        "because omitting them would present partial coverage as full coverage."
    )
    detail = " ".join(
        f"{reason}: {NOT_EVALUATED_REASONS[reason]}."
        for reason in reasons
        if reason in NOT_EVALUATED_REASONS
    )
    return headline, detail


def render_pdf(
    device: dict[str, Any],
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
    audit_record: dict[str, Any],
    *,
    history: list[tuple[int, float]] | None = None,
    theme: str = "light",
) -> bytes:
    """Render the per-device compliance report.

    Args:
        device: Device record dict.
        findings: Finding dicts, as the API serves them.
        summary: The caller's summary. Accepted for signature compatibility and
            for its ``total``, but no figure in the report is taken from it --
            see the module docstring.
        audit_record: The committed ledger record this report cites.
        history: ``(seq, score)`` for this device's earlier audits, oldest first.
            Supplied the trend chart appears; omitted it does not, because a
            single point is not a trend.
        theme: ``light`` or ``dark``, resolved against the frozen palette.

    Returns:
        PDF bytes. Always a PDF -- if ReportLab is unavailable the report
        degrades to monospaced text rather than to another format, because the
        route that serves these bytes declares them a PDF.
    """
    data = prepare(device, findings, audit_record, history)
    try:
        return _render_with_reportlab(data, theme=theme)
    except ImportError:
        return _render_degraded(data, reason="ReportLab is not installed")


# ── ReportLab path ────────────────────────────────────────────────────


def _render_with_reportlab(data: ReportData, *, theme: str) -> bytes:
    """Assemble the full report. Raises ImportError if ReportLab is absent."""
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        KeepTogether,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    sheet = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("PTitle", parent=sheet["Title"], fontSize=20, spaceAfter=4),
        "subtitle": ParagraphStyle(
            "PSubtitle", parent=sheet["Normal"], fontSize=9.5,
            textColor=colors.HexColor("#6b6a63"), spaceAfter=14,
        ),
        "h1": ParagraphStyle("PH1", parent=sheet["Heading1"], fontSize=14, spaceBefore=10, spaceAfter=6),
        "h2": ParagraphStyle("PH2", parent=sheet["Heading2"], fontSize=10.5, spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("PBody", parent=sheet["Normal"], fontSize=9, leading=12, spaceAfter=5),
        "small": ParagraphStyle(
            "PSmall", parent=sheet["Normal"], fontSize=7.5, leading=10,
            textColor=colors.HexColor("#6b6a63"), spaceAfter=3,
        ),
        "mono": ParagraphStyle("PMono", parent=sheet["Normal"], fontName="Courier", fontSize=7.5, leading=10),
        "cell": ParagraphStyle("PCell", parent=sheet["Normal"], fontSize=7.5, leading=9.5),
    }

    frame_width = A4[0] - 3 * cm
    story: list[Any] = []

    story.append(Paragraph("PRAMAN compliance report", styles["title"]))
    story.append(
        Paragraph(
            f"{_esc(data.device_label)} &mdash; audited against "
            f"{_esc(', '.join(sorted(data.framework_counts)) or 'no framework')}. "
            "Verdicts are deterministic; no language model contributed to any "
            "result or command in this document.",
            styles["subtitle"],
        )
    )

    story.append(Paragraph("Device identity", styles["h1"]))
    story.append(_kv_table(data.identity, frame_width, styles, Table, TableStyle, colors, Paragraph))

    story.append(Paragraph("Compliance posture", styles["h1"]))
    gauge = chart_builders.compliance_gauge(
        float(data.score["score"]),
        passes=int(data.score["passed"]),
        fails=int(data.score["failed"]),
        theme=theme,
    )
    story.extend(_chart_block(gauge, frame_width, styles, Table, TableStyle, colors, Paragraph, Spacer))
    story.append(Paragraph(f"Basis: {_esc(data.score['basis'])}.", styles["small"]))
    story.append(
        Paragraph(
            f"{data.score['total_controls']} controls evaluated; "
            f"{data.score['scored_controls']} carried a verdict. "
            f"Excluded from the ratio: {data.score['notchecked']} not checked, "
            f"{data.score['notapplicable']} not applicable, "
            f"{data.score['unknown']} indeterminate, {data.score['error']} in error.",
            styles["small"],
        )
    )

    for chart in (
        chart_builders.result_distribution(data.result_counts, theme=theme),
        chart_builders.framework_stacked_bars(data.framework_counts, theme=theme),
        chart_builders.severity_bars(data.failure_severities, theme=theme),
        chart_builders.trend_line(list(data.trend), theme=theme),
    ):
        story.extend(
            _chart_block(chart, frame_width, styles, Table, TableStyle, colors, Paragraph, Spacer)
        )

    if not data.failure_severities:
        story.append(
            Paragraph(
                "No control failed, so there is no severity distribution to chart.",
                styles["small"],
            )
        )
    if len(data.trend) < 2:
        story.append(
            Paragraph(
                "A trend needs at least two committed audits of this device; "
                f"the ledger holds {len(data.trend) or 1}.",
                styles["small"],
            )
        )

    story.append(PageBreak())
    story.append(Paragraph("Findings", styles["h1"]))
    if not data.entries and not data.roster:
        story.append(
            Paragraph(
                "This audit produced no findings. That is not a clean bill of "
                "health: it means no rule in the loaded mapping packs applied to "
                "this device.",
                styles["body"],
            )
        )
    elif data.entries:
        story.append(
            Paragraph(
                f"{len(data.entries)} control(s) reached a verdict and are detailed "
                "below, most severe failures first. Controls that were not "
                "evaluated are listed under Coverage.",
                styles["small"],
            )
        )

    for finding, remediation in _ordered(data.entries):
        story.append(
            KeepTogether(
                _finding_block(
                    finding, remediation, frame_width, styles, theme,
                    Table, TableStyle, colors, Paragraph, Spacer,
                )
            )
        )

    story.extend(
        _coverage_block(data, frame_width, styles, Table, TableStyle, colors, Paragraph)
    )

    story.append(PageBreak())
    story.append(Paragraph("Verification", styles["h1"]))
    story.append(
        Paragraph(
            "These values are printed in full and unabbreviated. Recompute the "
            "record hash over the ledger row's canonical JSON, or verify the "
            "signature against the published Ed25519 public key, to confirm this "
            "report describes an unaltered audit. The findings and the canonical "
            "facts they were read from are embedded in this PDF as attachments.",
            styles["body"],
        )
    )
    story.append(
        _kv_table(
            data.verification, frame_width, styles, Table, TableStyle, colors, Paragraph,
            mono_values=True,
        )
    )

    buffer = BytesIO()
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        title=f"PRAMAN report {data.device_label}",
        author="PRAMAN -- AI-driven multi-vendor network compliance auditor",
        subject="Network security configuration compliance audit",
        # Fixed CreationDate and Producer. Two reports over one committed audit
        # must be byte-identical, or the signature and the archive copy diverge
        # for reasons that have nothing to do with the device.
        invariant=1,
    )
    footer = _footer_painter(data, colors)
    doc.addPageTemplates([
        PageTemplate(
            id="main",
            frames=[Frame(1.5 * cm, 1.8 * cm, frame_width, A4[1] - 3.4 * cm, id="body")],
            onPage=footer,
        )
    ])
    doc.build(story)
    return buffer.getvalue()


def _footer_painter(data: ReportData, colors: Any) -> Any:
    """A footer carrying the record hash, so a loose page is still traceable."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm

    record_hash = dict(data.verification).get("Record hash", "")

    def paint(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Courier", 6.5)
        canvas.setFillColor(colors.HexColor("#6b6a63"))
        canvas.drawString(
            1.5 * cm, 1.05 * cm,
            f"{data.device_label}  record {record_hash[:16] or 'unsigned'}",
        )
        canvas.drawRightString(A4[0] - 1.5 * cm, 1.05 * cm, f"page {doc.page}")
        canvas.setStrokeColor(colors.HexColor("#c3c2b7"))
        canvas.setLineWidth(0.4)
        canvas.line(1.5 * cm, 1.45 * cm, A4[0] - 1.5 * cm, 1.45 * cm)
        canvas.restoreState()

    return paint


def _kv_table(
    rows: tuple[tuple[str, str], ...],
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
    *,
    mono_values: bool = False,
) -> Any:
    """A two-column label/value table whose values wrap rather than overflow."""
    style_key = "mono" if mono_values else "cell"
    body = [
        [Paragraph(f"<b>{_esc(label)}</b>", styles["cell"]), Paragraph(_esc(value), styles[style_key])]
        for label, value in rows
    ]
    table = Table(body, colWidths=[width * 0.28, width * 0.72], hAlign="LEFT")
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f4f3ee")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dedcd2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    return table


def _coverage_block(
    data: ReportData,
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
) -> list[Any]:
    """The controls that reached no verdict, accounted for rather than dropped.

    These used to get a full detailed block each, which on a real device meant a
    266-page report where 1,391 of 1,462 entries said only "no automated check
    exists". Removing them outright is the opposite error: silence about a control
    reads as coverage of it. So they appear as a roster -- enumerated while a
    reader would plausibly read the list, summarised by framework once they would
    not, and in either case with the exact count and the reason stated.
    """
    if not data.roster:
        return []

    headline, detail = _coverage_prose(data)
    block: list[Any] = [
        Paragraph("Coverage", styles["h1"]),
        Paragraph(_esc(headline), styles["body"]),
    ]
    if detail:
        block.append(Paragraph(_esc(detail), styles["small"]))

    grouped = data.roster_by_framework
    reasons = [
        reason
        for reason in ("notchecked", "notapplicable", "notselected")
        if any(reason in counts for counts in grouped.values())
    ]
    summary_rows: list[tuple[str, ...]] = [("Framework", *reasons, "Total")]
    for framework in sorted(grouped):
        counts = grouped[framework]
        summary_rows.append(
            (
                framework,
                *(str(counts.get(reason, 0)) for reason in reasons),
                str(sum(counts.values())),
            )
        )
    block.append(
        _grid_table(summary_rows, width, styles, Table, TableStyle, colors, Paragraph)
    )

    if len(data.roster) <= ROSTER_ENUMERATION_LIMIT:
        rows: list[tuple[str, ...]] = [("Control", "Framework", "Reason", "Title")]
        rows.extend(_roster_rows(data.roster))
        block.append(
            _grid_table(
                rows, width, styles, Table, TableStyle, colors, Paragraph,
                weights=(0.16, 0.15, 0.14, 0.55),
            )
        )
    else:
        block.append(
            Paragraph(
                f"The {len(data.roster)} control ids are not enumerated here -- a "
                "list that long is not read. Every one of them, with its title and "
                "the reason it was not evaluated, is in the machine-readable "
                "01_findings.json attached to this PDF.",
                styles["small"],
            )
        )
    return block


def _grid_table(
    rows: list[tuple[str, ...]],
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
    *,
    weights: tuple[float, ...] | None = None,
) -> Any:
    """A headed grid whose first row is a header and whose cells wrap."""
    header, *body_rows = rows
    columns = len(header) or 1
    if weights is None:
        first = 0.34 if columns > 1 else 1.0
        weights = (first, *((1.0 - first) / (columns - 1) for _ in range(columns - 1)))
    body = [[Paragraph(f"<b>{_esc(cell)}</b>", styles["cell"]) for cell in header]]
    body.extend(
        [Paragraph(_esc(cell), styles["cell"]) for cell in row] for row in body_rows
    )
    table = Table(
        body, colWidths=[width * weight for weight in weights], hAlign="LEFT", repeatRows=1
    )
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f3ee")),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#a9a79c")),
            ("LINEBELOW", (0, 1), (-1, -2), 0.3, colors.HexColor("#e6e4da")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ])
    )
    return table


def _twin_table(
    chart: Any,
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
) -> Any:
    """The table half of a Chart -- the same numbers, readable."""
    body = [[Paragraph(f"<b>{_esc(header)}</b>", styles["cell"]) for header in chart.headers]]
    body.extend(
        [Paragraph(_esc(cell), styles["cell"]) for cell in row] for row in chart.rows
    )
    columns = len(chart.headers) or 1
    first = width * 0.42 if columns > 1 else width
    rest = (width - first) / (columns - 1) if columns > 1 else 0.0
    table = Table(body, colWidths=[first] + [rest] * (columns - 1), hAlign="LEFT")
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f3ee")),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#a9a79c")),
            ("LINEBELOW", (0, 1), (-1, -2), 0.3, colors.HexColor("#e6e4da")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ])
    )
    return table


def _chart_block(
    chart: Any,
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
    Spacer: Any,  # noqa: N803
) -> list[Any]:
    """Lay a chart beside its twin table, or nothing at all.

    ``None`` means the builder judged the data too thin to chart honestly. The
    caller does not get to override that, which is why this returns an empty list
    rather than a placeholder.
    """
    if chart is None:
        return []
    gutter = 14.0
    drawing_width = float(chart.drawing.width)
    table_width = max(120.0, width - drawing_width - gutter)
    pair = Table(
        [[chart.drawing, _twin_table(chart, table_width, styles, Table, TableStyle, colors, Paragraph)]],
        colWidths=[drawing_width + gutter, table_width],
        hAlign="LEFT",
    )
    pair.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ])
    )
    block: list[Any] = [
        Paragraph(_esc(chart.title), styles["h2"]),
        pair,
        Paragraph(_esc(chart.caption), styles["small"]),
    ]
    if chart.note:
        block.append(Paragraph(_esc(chart.note), styles["small"]))
    block.append(Spacer(1, 8))
    return block


def _chip(
    label: str,
    mark: str,
    hex_colour: str,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
) -> Any:
    """A coloured status chip carrying a mark and a word as well as a hue."""
    text = f'<font color="{_on_ink(hex_colour)}"><b>{_esc(mark)} {_esc(label.upper())}</b></font>'
    chip = Table([[Paragraph(text, styles["cell"])]], hAlign="LEFT")
    chip.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(hex_colour)),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    return chip


def _finding_block(
    finding: dict[str, Any],
    remediation: Remediation | None,
    width: float,
    styles: dict[str, Any],
    theme: str,
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
    Spacer: Any,  # noqa: N803
) -> list[Any]:
    """One control: verdict, why, the evidence, and what to do about it."""
    result = result_value(finding)
    severity = str(finding.get("severity") or "unknown").lower()
    result_colour = RESULT_COLORS.get(result, RESULT_COLORS["unknown"])
    # "unknown" is not in the severity ramp on purpose -- an unrated control must
    # not borrow the low-risk colour. It falls back to the amber of an unknown
    # result, which is its own chip.
    severity_colour = SEVERITY_COLORS.get(theme, SEVERITY_COLORS["light"]).get(
        severity, RESULT_COLORS["unknown"]
    )

    chips = Table(
        [[
            _chip(result, RESULT_MARKS.get(result, "[?]"), result_colour,
                  styles, Table, TableStyle, colors, Paragraph),
            _chip(f"{severity} severity", SEVERITY_MARKS.get(severity, "[?]"), severity_colour,
                  styles, Table, TableStyle, colors, Paragraph),
        ]],
        hAlign="LEFT",
    )
    chips.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    block: list[Any] = [
        Paragraph(
            f"<b>{_esc(finding.get('control_id'))}</b> &nbsp; {_esc(finding.get('title'))}",
            styles["h2"],
        ),
        Paragraph(
            f"{_esc(finding.get('framework'))} &middot; "
            f"{_esc(finding.get('benchmark'))} {_esc(finding.get('benchmark_version'))}",
            styles["small"],
        ),
        chips,
        Spacer(1, 4),
    ]
    if finding.get("rationale"):
        block.append(Paragraph(_esc(finding.get("rationale")), styles["body"]))

    crosswalk = _crosswalk(finding)
    if crosswalk:
        block.append(Paragraph(f"Also satisfies: {_esc(crosswalk)}", styles["small"]))

    block.extend(_evidence_block(finding, width, styles, Table, TableStyle, colors, Paragraph))
    block.extend(
        _remediation_block(remediation, width, styles, Table, TableStyle, colors, Paragraph, Spacer)
    )
    block.append(Spacer(1, 12))
    return block


def _crosswalk(finding: dict[str, Any]) -> str:
    """The other frameworks this control maps to, for the C3 cross-view."""
    references = finding.get("references") or {}
    if not isinstance(references, dict):
        return ""
    parts = []
    for key, label in (("nist_800_53", "NIST SP 800-53"), ("iso_27001", "ISO 27001"), ("cci", "CCI")):
        value = _text(references.get(key))
        if value:
            parts.append(f"{label} {value}")
    return "; ".join(parts)


def _evidence_block(
    finding: dict[str, Any],
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
) -> list[Any]:
    """The observed facts, with the six-field provenance that makes them checkable.

    A verdict with no citable line number is an assertion. ``present: false`` is
    printed as its own row rather than as an empty value, because "the line is
    absent" is frequently the whole reason for the failure.
    """
    evidence = finding.get("evidence") or []
    if not isinstance(evidence, list) or not evidence:
        return [
            Paragraph(
                "No canonical fact was recorded for this control, so this verdict "
                "cannot be traced to a configuration line.",
                styles["small"],
            )
        ]

    body = [[
        Paragraph("<b>Canonical path</b>", styles["cell"]),
        Paragraph("<b>Observed</b>", styles["cell"]),
        Paragraph("<b>Source</b>", styles["cell"]),
        Paragraph("<b>Parser</b>", styles["cell"]),
    ]]
    raw_rows: list[tuple[int, str]] = []
    for fact in evidence:
        if not isinstance(fact, dict):
            continue
        present = fact.get("present")
        observed = (
            "not present in configuration"
            if present is False
            else _text(fact.get("value"))
        )
        start, end = fact.get("line_start"), fact.get("line_end")
        span = f"{start}" if start == end or end in (None, "") else f"{start}-{end}"
        source = f"{_text(fact.get('source_file'))}:{span}" if start else _text(fact.get("source_file"))
        confidence = fact.get("confidence")
        parser = _text(fact.get("parser_id"))
        if isinstance(confidence, (int, float)) and float(confidence) < 1.0:
            # Below 1.0 means an AI-assisted classification reached this leaf.
            # It must be visible: the verdict is deterministic, but the input to
            # it was not certain.
            parser = f"{parser} (confidence {float(confidence):.2f}, AI-assisted)"
        body.append([
            Paragraph(_esc(fact.get("path")), styles["mono"]),
            Paragraph(_esc(observed), styles["cell"]),
            Paragraph(_esc(source), styles["mono"]),
            Paragraph(_esc(parser), styles["small"]),
        ])
        raw = _text(fact.get("raw_text")).strip()
        if raw and isinstance(start, int):
            raw_rows.append((start, raw))

    table = Table(
        body,
        colWidths=[width * 0.26, width * 0.24, width * 0.26, width * 0.24],
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f3ee")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e6e4da")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ])
    )
    out: list[Any] = [Paragraph("Evidence", styles["h2"]), table]
    for line_number, raw in raw_rows:
        out.append(Paragraph(f"{line_number}: {_esc(raw)}", styles["mono"]))
    return out


def _remediation_block(
    remediation: Remediation | None,
    width: float,
    styles: dict[str, Any],
    Table: Any,  # noqa: N803
    TableStyle: Any,  # noqa: N803
    colors: Any,
    Paragraph: Any,  # noqa: N803
    Spacer: Any,  # noqa: N803
) -> list[Any]:
    """The publisher's fix, rewritten for this device.

    Caveats print *before* the commands. An operator who reads top to bottom and
    stops at the first runnable-looking line must have already seen that the line
    contains a placeholder.
    """
    if remediation is None:
        return []

    out: list[Any] = [Paragraph("Remediation", styles["h2"])]
    for note in remediation.notes:
        out.append(
            Paragraph(f"<b>Note.</b> {_esc(note)}", styles["small"])
        )

    if remediation.kind == KIND_NONE:
        return out

    if remediation.kind == KIND_MANUAL and remediation.guidance:
        out.append(Paragraph(_esc(remediation.guidance), styles["body"]))
    elif remediation.guidance:
        out.append(Paragraph(_esc(remediation.guidance), styles["small"]))

    if remediation.kind == KIND_CLI and remediation.steps:
        rows = [[
            Paragraph("<b>#</b>", styles["cell"]),
            Paragraph("<b>Mode</b>", styles["cell"]),
            Paragraph("<b>Command as it appears on this device</b>", styles["cell"]),
        ]]
        for index, step in enumerate(remediation.steps, start=1):
            flag = "" if step.is_runnable else " &larr; substitute first"
            rows.append([
                Paragraph(str(index), styles["cell"]),
                Paragraph(_esc(step.mode), styles["cell"]),
                Paragraph(f"{_esc(step.prompt)}{flag}", styles["mono"]),
            ])
        table = Table(
            rows, colWidths=[width * 0.06, width * 0.16, width * 0.78], hAlign="LEFT"
        )
        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f3ee")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fbfbf8")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e6e4da")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ])
        )
        out.extend([table, Spacer(1, 4)])

    detail = [
        (label, value)
        for label, value in (
            ("Verify with", remediation.verification),
            ("Roll back with", remediation.rollback),
            ("Risk of applying", remediation.risk),
            ("Source", remediation.source),
        )
        if value and value != "unknown"
    ]
    if remediation.risk == "unknown":
        detail.append((
            "Risk of applying",
            "not rated by the publisher -- assess against this device's role "
            "before applying",
        ))
    if detail:
        out.append(
            _kv_table(tuple(detail), width, styles, Table, TableStyle, colors, Paragraph)
        )
    return out


# ── Degraded path ─────────────────────────────────────────────────────


def _render_degraded(data: ReportData, *, reason: str) -> bytes:
    """Text-only report, still a valid PDF.

    Same figures as the full renderer -- they come from the same
    :class:`ReportData` -- minus the charts, the colour and the layout. It says
    so on the first page.
    """
    doc = MinimalPdf(title=f"PRAMAN report {data.device_label}")
    doc.heading("PRAMAN compliance report (text-only rendering)")
    doc.body(
        f"{reason}, so this report carries no charts, colour or typography. "
        "Every figure below is the same figure the full renderer would print. "
        "Install ReportLab to restore the graphical report."
    )
    doc.heading("Device identity")
    for label, value in data.identity:
        doc.pair(label, value)

    doc.heading("Compliance posture")
    doc.pair("Score", _score_text(data.score))
    doc.pair("Basis", str(data.score["basis"]))
    doc.pair(
        "Counts",
        f"{data.score['passed']} pass, {data.score['failed']} fail of "
        f"{data.score['scored_controls']} scored; "
        f"{data.score['total_controls']} controls evaluated",
    )
    for name in RESULT_ORDER:
        count = data.result_counts.get(name, 0)
        if count:
            doc.pair(f"  {name}", str(count))

    if data.framework_counts:
        doc.heading("By framework")
        for framework in sorted(data.framework_counts):
            counts = data.framework_counts[framework]
            doc.pair(framework, f"{counts.get('pass', 0)} pass, {counts.get('fail', 0)} fail")

    doc.heading("Failures by severity")
    if data.failure_severities:
        for severity in SEVERITY_ORDER:
            count = data.failure_severities.get(severity, 0)
            if count:
                doc.pair(severity, str(count))
    else:
        doc.body("No control failed.")

    doc.heading("Findings")
    if not data.entries and not data.roster:
        doc.body(
            "This audit produced no findings. That is not a clean bill of health: "
            "it means no rule in the loaded mapping packs applied to this device."
        )
    for finding, remediation in _ordered(data.entries):
        doc.blank()
        doc.body(
            f"{_text(finding.get('control_id'))}  {_text(finding.get('title'))}"
        )
        doc.body(
            f"{result_value(finding).upper()} / "
            f"{_text(finding.get('severity') or 'unknown')} severity / "
            f"{_text(finding.get('framework'))} "
            f"{_text(finding.get('benchmark'))} {_text(finding.get('benchmark_version'))}",
            indent=14,
        )
        if finding.get("rationale"):
            doc.body(_text(finding.get("rationale")), indent=14)
        for fact in finding.get("evidence") or []:
            if not isinstance(fact, dict):
                continue
            observed = (
                "not present in configuration"
                if fact.get("present") is False
                else _text(fact.get("value"))
            )
            doc.body(
                f"{_text(fact.get('path'))} = {observed}  "
                f"[{_text(fact.get('source_file'))}:{_text(fact.get('line_start'))} "
                f"via {_text(fact.get('parser_id'))}]",
                indent=14,
            )
            raw = _text(fact.get("raw_text")).strip()
            if raw:
                doc.body(raw, indent=28)
        if remediation is None:
            continue
        for note in remediation.notes:
            doc.body(f"NOTE: {note}", indent=14)
        if remediation.kind == KIND_MANUAL and remediation.guidance:
            doc.body(remediation.guidance, indent=14)
        for index, step in enumerate(remediation.steps, start=1):
            suffix = "" if step.is_runnable else "   <-- substitute first"
            doc.body(f"{index}. {step.prompt}{suffix}", indent=14)
        for label, value in (
            ("Verify with", remediation.verification),
            ("Roll back with", remediation.rollback),
            ("Source", remediation.source),
        ):
            if value:
                doc.body(f"{label}: {value}", indent=14)

    if data.roster:
        doc.heading("Coverage")
        headline, detail = _coverage_prose(data)
        doc.body(headline)
        if detail:
            doc.body(detail)
        for framework in sorted(data.roster_by_framework):
            counts = data.roster_by_framework[framework]
            doc.pair(
                framework,
                ", ".join(f"{count} {reason}" for reason, count in sorted(counts.items())),
            )
        if len(data.roster) <= ROSTER_ENUMERATION_LIMIT:
            doc.blank()
            for control_id, framework, reason, title in _roster_rows(data.roster):
                doc.body(f"{control_id}  [{reason}]  {framework}  {title}", indent=14)
        else:
            doc.body(
                f"The {len(data.roster)} control ids are not enumerated here -- a "
                "list that long is not read. Every one of them is in the "
                "machine-readable 01_findings.json attached to this PDF."
            )

    doc.heading("Verification")
    doc.body(
        "Printed in full. Recompute the record hash over the ledger row's "
        "canonical JSON to confirm this report describes an unaltered audit."
    )
    for label, value in data.verification:
        doc.pair(label, value)
    return doc.build()
