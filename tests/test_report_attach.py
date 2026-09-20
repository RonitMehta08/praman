"""Evidence attachment — the stage that makes a report checkable.

This module had two bugs and no tests, and the two facts are the same fact. It
reached for ``pdf.root`` where pikepdf spells the document catalogue ``pdf.Root``,
so it raised ``AttributeError`` on every call with pikepdf installed; and nothing
called it, because the report route went render → sign and skipped it. Every
report the product had ever produced shipped without its machine-readable
evidence, and no test noticed because no test existed.

So these tests check the two things that failure mode teaches:

* the attachments are **actually in the output**, read back through a PDF library
  rather than inferred from a byte search — flate-compressed JSON is not findable
  as text, so a substring assertion would have passed on an empty PDF;
* the stage **reports its own outcome**, because a stage that returns the input
  bytes on failure is indistinguishable from one that succeeded.
"""

from __future__ import annotations

import json
from io import BytesIO

import pytest

from backend.report.attach import (
    CANONICAL_NAME,
    FINDINGS_NAME,
    AttachResult,
    attach_evidence,
)
from backend.report.render import render_pdf

pikepdf = pytest.importorskip(
    "pikepdf", reason="pikepdf is the module under test; skip rather than fail"
)

FINDINGS = [
    {
        "control_id": "1.2.1",
        "framework": "CIS",
        "title": "Set 'transport input ssh'",
        "result": "fail",
        "severity": "high",
        "evidence": [
            {
                "path": "line.vty.transport_input",
                "value": "telnet ssh",
                "source_file": "core-rtr-01.conf",
                "line_start": 118,
                "line_end": 118,
                "parser_id": "cisco_ios@1",
                "confidence": 1.0,
            }
        ],
    }
]

FACTS = [
    {
        "device_id": "dev-r1",
        "path": "line.vty.transport_input",
        "value": "telnet ssh",
        "present": True,
        "source_file": "core-rtr-01.conf",
        "line_start": 118,
        "line_end": 118,
        "raw_text": " transport input telnet ssh",
        "parser_id": "cisco_ios@1",
        "confidence": 1.0,
    }
]


@pytest.fixture(scope="module")
def rendered() -> bytes:
    """Stage 1 output. The real renderer, so the test covers the real input."""
    return render_pdf(
        {
            "device_id": "dev-r1",
            "hostname": "core-rtr-01",
            "vendor": "cisco_ios",
            "os_family": "ios",
        },
        FINDINGS,
        {"pass": 0, "fail": 1, "score": 0.0},
        {
            "seq": 3,
            "record_hash": "ab" * 32,
            "prev_hash": "",
            "created_at": "2026-08-29T10:00:00+00:00",
            "signature": "ed25519:x",
        },
    )


def _attachment(pdf_bytes: bytes, name: str) -> bytes:
    """Read one attachment back out, the way a verifier would."""
    with pikepdf.Pdf.open(BytesIO(pdf_bytes)) as pdf:
        assert name in pdf.attachments, (
            f"{name} missing; present: {list(pdf.attachments)}"
        )
        return pdf.attachments[name].get_file().read_bytes()


# ── The evidence is there, and it is the evidence ─────────────────────


def test_both_evidence_files_are_embedded(rendered: bytes) -> None:
    """Read back through pikepdf, not searched for as text.

    The payloads are flate-compressed in the output, so a ``b"control_id" in pdf``
    assertion would fail on a working implementation and pass on one that wrote an
    empty attachment. Reading them back is the only assertion that means anything.
    """
    result = attach_evidence(rendered, FINDINGS, FACTS)
    assert result.attached is True, result.detail

    findings = json.loads(_attachment(result.pdf, FINDINGS_NAME))
    facts = json.loads(_attachment(result.pdf, CANONICAL_NAME))

    assert findings == FINDINGS, "the attachment must be the findings, unaltered"
    assert facts == FACTS


def test_the_attached_findings_carry_their_provenance(rendered: bytes) -> None:
    """Six-field provenance has to survive into the artefact.

    A finding without ``source_file`` and ``line_start`` is an opinion. The
    attachment is where a verifier goes to check a verdict against the device's
    own configuration, so dropping provenance here would make the embedded
    evidence no better than the prose it accompanies.
    """
    result = attach_evidence(rendered, FINDINGS, FACTS)
    evidence = json.loads(_attachment(result.pdf, FINDINGS_NAME))[0]["evidence"][0]

    for field in (
        "path",
        "value",
        "source_file",
        "line_start",
        "line_end",
        "parser_id",
        "confidence",
    ):
        assert field in evidence, f"provenance field {field} lost in transit"


def test_attachment_bytes_are_deterministic(rendered: bytes) -> None:
    """Equal findings must produce equal attachment bytes.

    ``sort_keys=True`` is what makes this true, and it is what lets a golden-file
    report test exist at all. Without it, dict ordering differences across runs
    would show up as a changed PDF and the golden test would have to be deleted.
    """
    first = attach_evidence(rendered, FINDINGS, FACTS)
    second = attach_evidence(rendered, FINDINGS, FACTS)
    assert _attachment(first.pdf, FINDINGS_NAME) == _attachment(
        second.pdf, FINDINGS_NAME
    )
    assert _attachment(first.pdf, CANONICAL_NAME) == _attachment(
        second.pdf, CANONICAL_NAME
    )


def test_each_file_is_attached_exactly_once(rendered: bytes) -> None:
    """The bug the module's own comment warns about.

    pikepdf's ``attachments`` mapping already writes the ``/EmbeddedFiles`` name
    tree. Adding a ``FileAttachment`` annotation as well makes viewers list every
    file twice, which reads to an auditor as two versions of the evidence.
    """
    result = attach_evidence(rendered, FINDINGS, FACTS)
    with pikepdf.Pdf.open(BytesIO(result.pdf)) as pdf:
        assert sorted(pdf.attachments) == [FINDINGS_NAME, CANONICAL_NAME]


def test_the_viewer_is_told_to_show_the_attachments(rendered: bytes) -> None:
    """Present is not the same as visible.

    Most viewers hide the attachments pane by default, so evidence that is
    embedded but not surfaced is evidence nobody opens. ``PageMode`` is the one
    line that changes that — and reaching for it via the wrong attribute name is
    what broke this module.
    """
    result = attach_evidence(rendered, FINDINGS, FACTS)
    with pikepdf.Pdf.open(BytesIO(result.pdf)) as pdf:
        assert str(pdf.Root.PageMode) == "/UseAttachments"


def test_names_are_ordered_by_their_numeric_prefix(rendered: bytes) -> None:
    """Findings before facts, in viewers that sort by name.

    The prefixes are the whole reason the names are not just ``findings.json``.
    """
    result = attach_evidence(rendered, FINDINGS, FACTS)
    assert result.names == (FINDINGS_NAME, CANONICAL_NAME)
    assert FINDINGS_NAME < CANONICAL_NAME


def test_an_empty_audit_still_attaches(rendered: bytes) -> None:
    """Zero findings is a result, not a reason to skip the stage.

    A device with nothing to report still gets a report, and a verifier still
    needs to see that the findings list was empty rather than missing.
    """
    result = attach_evidence(rendered, [], [])
    assert result.attached is True, result.detail
    assert json.loads(_attachment(result.pdf, FINDINGS_NAME)) == []


# ── Failure is reported, not hidden ───────────────────────────────────


def test_unattachable_input_returns_the_input_and_says_so() -> None:
    """A report that cannot carry evidence must still be a readable report.

    Both halves matter, and the second is the one that was missing: the caller
    gets bytes it can serve, *and* a flag saying they are not what was asked for.
    """
    junk = b"this is not a PDF"
    result = attach_evidence(junk, FINDINGS, FACTS)

    assert result.attached is False
    assert result.pdf == junk
    assert result.names == ()
    assert "attaching evidence failed" in result.detail
    assert "GET /devices/{device_id}/findings" in result.detail, "the remedy"


def test_unserialisable_values_do_not_fail_the_stage(rendered: bytes) -> None:
    """A stray non-JSON value must cost readability, not the whole attachment.

    Findings come out of SQLite via ``dict(row)``, so a value the encoder does not
    know is a plausible accident. ``default=str`` degrades it to its repr rather
    than losing every other finding in the document.
    """
    class Opaque:
        def __str__(self) -> str:
            return "opaque-value"

    findings = [{"control_id": "1.1.1", "result": "pass", "weird": Opaque()}]
    result = attach_evidence(rendered, findings, [])

    assert result.attached is True, result.detail
    assert json.loads(_attachment(result.pdf, FINDINGS_NAME))[0]["weird"] == (
        "opaque-value"
    )


def test_header_value_distinguishes_the_two_outcomes() -> None:
    """What a client reads to decide whether the PDF is self-contained."""
    attached = AttachResult(
        pdf=b"%PDF-", attached=True, detail="embedded 2 finding(s)",
        names=(FINDINGS_NAME, CANONICAL_NAME),
    )
    assert attached.header_value == f"attached; {FINDINGS_NAME}, {CANONICAL_NAME}"

    failed = AttachResult(pdf=b"%PDF-", attached=False, detail="pikepdf missing")
    assert failed.header_value == "none; pikepdf missing"


def test_the_stage_does_not_claim_pdf_a_conformance(rendered: bytes) -> None:
    """A false PDF/A-3 claim is a validation failure, not a cosmetic one.

    Conformance needs an output intent, an XMP declaration and embedded-font
    guarantees this pipeline does not make. Asserting the absence keeps a
    well-meaning future edit from adding the claim without the substance.
    """
    result = attach_evidence(rendered, FINDINGS, FACTS)
    with pikepdf.Pdf.open(BytesIO(result.pdf)) as pdf:
        assert "/OutputIntents" not in pdf.Root
        metadata = bytes(pdf.Root.Metadata.read_bytes()) if "/Metadata" in pdf.Root else b""
    assert b"pdfaid" not in metadata
