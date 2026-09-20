"""Report signing — the claim a signature makes, and the claim it must not make.

A compliance report is a document someone acts on. Two failure modes matter, and
they pull in opposite directions:

* **A report that silently didn't sign.** The prior version of ``sign.py`` caught
  every exception and returned the unsigned bytes, so success and failure were
  byte-indistinguishable to the caller — and the fallback path failed on *every*
  call because it imported a name ``cryptography`` does not have. Every report
  ever produced was unsigned and looked signed. So the tests here assert on
  :class:`SigningResult`, not just on the bytes.

* **A report that overclaims.** The demo signer is ephemeral and self-signed. It
  proves the bytes are unaltered and nothing about who produced them. That
  distinction has to survive into ``detail``, because ``detail`` is what reaches
  the operator, and an operator who believes a demo signature is auditable will
  hand it to an auditor.

The integrity claim is tested the only way worth testing it: sign, flip a byte,
and check that validation notices. An assertion that a ``/Sig`` dictionary exists
would pass for a signature computed over nothing.
"""

from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path

import pytest

from backend.report.attach import attach_evidence
from backend.report.render import render_pdf
from backend.report.sign import SIGNATURE_FIELD, SigningResult, _demo_signer, sign_pdf

pyhanko = pytest.importorskip(
    "pyhanko", reason="pyHanko is the module under test; skip rather than fail"
)


# ── Fixtures: a real report, not a synthetic PDF ──────────────────────


@pytest.fixture(scope="module")
def report_pdf() -> bytes:
    """Stage 1 + 2 output for a plausible device.

    The real renderer rather than a hand-built one-page PDF: signing has to work
    on the document the product actually produces, including its attachments,
    incremental-update history and outline. A synthetic PDF would pass while the
    real one failed on any of those.
    """
    device = {
        "device_id": "dev-r1",
        "hostname": "core-rtr-01",
        "vendor": "cisco_ios",
        "os_family": "ios",
        "os_version": "15.7(3)M",
        "model": "ISR4331/K9",
        "serials": ["FDO21520TGH"],
        "source_file": "core-rtr-01.conf",
    }
    findings = [
        {
            "control_id": "1.1.1",
            "framework": "CIS",
            "title": "Enable 'aaa new-model'",
            "result": "pass",
            "severity": "medium",
            "evidence": [
                {
                    "path": "aaa.new_model",
                    "value": True,
                    "source_file": "core-rtr-01.conf",
                    "line_start": 42,
                    "line_end": 42,
                    "parser_id": "cisco_ios@1",
                    "confidence": 1.0,
                }
            ],
        },
        {
            "control_id": "1.2.1",
            "framework": "CIS",
            "title": "Set 'transport input ssh'",
            "result": "fail",
            "severity": "high",
            "evidence": [],
        },
    ]
    summary = {
        "pass": 1,
        "fail": 1,
        "error": 0,
        "unknown": 0,
        "notchecked": 0,
        "notapplicable": 0,
        "score": 50.0,
    }
    audit_record = {
        "seq": 7,
        "record_hash": "9f2c" * 16,
        "prev_hash": "0" * 64,
        "created_at": "2026-08-29T10:00:00+00:00",
        "signature": "ed25519:deadbeef",
    }
    rendered = render_pdf(device, findings, summary, audit_record)
    evidence = attach_evidence(rendered, findings, [])
    assert evidence.attached, evidence.detail
    return evidence.pdf


@pytest.fixture(scope="module")
def signed(report_pdf: bytes) -> SigningResult:
    """Signed once per module: RSA keygen and CMS assembly are not free."""
    return sign_pdf(report_pdf)


def _embedded_signature(pdf_bytes: bytes):
    """The one embedded signature in a signed PDF, read back through pyHanko."""
    from pyhanko.pdf_utils.reader import PdfFileReader

    signatures = PdfFileReader(BytesIO(pdf_bytes)).embedded_signatures
    assert len(signatures) == 1, f"expected exactly one signature, got {len(signatures)}"
    return signatures[0]


# ── The signature is real ─────────────────────────────────────────────


def test_signing_succeeds_on_a_rendered_report(signed: SigningResult) -> None:
    """Stage 3 works on stage 2's output, with no configuration at all.

    Nothing is set up here — no ``.pfx``, no TSA, no environment. That is the
    demo path, and it must work, because a path that only works when configured
    is a path nobody discovers is broken.
    """
    assert signed.signed is True, signed.detail
    assert signed.pdf.startswith(b"%PDF-")
    assert signed.signer == "PRAMAN Demo Signer (ephemeral, self-signed)"


def test_the_signature_field_is_the_one_the_report_names(signed: SigningResult) -> None:
    """The verification page tells the reader a field name; it must be that one.

    The report prints ``SIGNATURE_FIELD`` so a reader knows what to look for in
    their viewer. If the writer used a different name the instruction sends them
    hunting for something that is not there, and they conclude the report is
    unsigned.
    """
    assert _embedded_signature(signed.pdf).field_name == SIGNATURE_FIELD


def test_signing_appends_rather_than_rewriting(
    report_pdf: bytes, signed: SigningResult
) -> None:
    """An incremental update: the signed bytes contain the unsigned ones verbatim.

    This is what makes the signature cover the document that was reviewed. A
    signer that re-serialised the PDF would produce a valid signature over a
    document nobody had seen — same content, different bytes, and the attachments
    silently reordered or dropped.
    """
    assert signed.pdf.startswith(report_pdf)
    assert len(signed.pdf) > len(report_pdf)


def test_attachments_survive_signing(signed: SigningResult) -> None:
    """The embedded evidence is the point of the attach stage.

    ``01_findings.json`` is how a verifier checks the PDF's prose against
    machine-readable findings. A signature that dropped it would leave a document
    that is provably unaltered and no longer evidence.
    """
    pikepdf = pytest.importorskip("pikepdf")
    with pikepdf.Pdf.open(BytesIO(signed.pdf)) as pdf:
        assert "01_findings.json" in pdf.attachments


def test_the_signature_covers_the_bytes(signed: SigningResult) -> None:
    """The integrity claim, checked by cryptography rather than by structure.

    Validation is run against a context that trusts the demo certificate,
    isolating the question to "do the bytes match what was signed" — the only
    thing a self-signed key can answer. ``allow_fetching=False`` keeps the test
    offline, which R7 requires of the whole suite.
    """
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    embedded = _embedded_signature(signed.pdf)
    context = ValidationContext(
        trust_roots=[_demo_signer().signing_cert], allow_fetching=False
    )
    status = validate_pdf_signature(embedded, signer_validation_context=context)

    assert status.intact is True, "the digest does not match the signed bytes"
    assert status.valid is True, "the CMS signature does not verify"


def test_tampering_after_signing_is_detected(
    report_pdf: bytes, signed: SigningResult
) -> None:
    """The property that makes the signature worth applying.

    One byte inside the report's first content stream is flipped — a byte the
    signature covers, in the region that renders the verdicts. Length is held
    constant so the PDF still parses and the document structure is untouched: the
    only thing that changes is content, which is precisely what a signature is
    for. Without this test, every other assertion here would still pass for a
    signature computed over the wrong bytes, or over nothing.

    ``intact`` is the assertion, not ``valid``. pyHanko separates them: ``valid``
    says the CMS blob verifies against the digest it *claims*, and stays True
    here; ``intact`` says that digest matches the bytes actually present. A test
    asserting only ``valid`` would pass on a tampered document.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    body = re.search(rb"stream\r?\n", report_pdf)
    assert body, "fixture PDF has no stream to tamper with"
    target = body.end() + 10

    tampered = bytearray(signed.pdf)
    tampered[target] ^= 0xFF
    assert len(tampered) == len(signed.pdf), "length must be held constant"

    embedded = PdfFileReader(BytesIO(bytes(tampered))).embedded_signatures[0]
    context = ValidationContext(
        trust_roots=[_demo_signer().signing_cert], allow_fetching=False
    )
    status = validate_pdf_signature(embedded, signer_validation_context=context)
    assert status.intact is False, "a modified report validated as intact"


# ── The signature does not overclaim ──────────────────────────────────


def test_the_demo_signature_says_it_is_a_demo(signed: SigningResult) -> None:
    """``detail`` is the only place the trust model reaches a human.

    The operator sees a green tick and this sentence. It has to contain both the
    limitation and the remedy, or the tick is the whole message.
    """
    detail = signed.detail.lower()
    assert "self-signed" in detail
    assert "demo" in detail
    assert "not who issued them" in detail
    assert "pfx" in detail, "the remedy has to be in the message"


def test_header_value_carries_the_state_and_the_reason(signed: SigningResult) -> None:
    """The response header a client reads to decide whether to trust the file."""
    assert signed.header_value.startswith("signed; ")
    assert signed.detail in signed.header_value

    unsigned = SigningResult(pdf=b"%PDF-", signed=False, detail="no key configured")
    assert unsigned.header_value == "unsigned; no key configured"


def test_a_demo_signature_is_not_claimed_to_be_timestamped(
    signed: SigningResult,
) -> None:
    """No TSA was configured, so nothing may suggest B-LT.

    The distinction is not cosmetic: without a TSA the signature carries only the
    signer's own clock, and a verifier has no reason to trust that.
    """
    assert "timestamp" not in signed.detail.lower()


# ── Failure is reported, not hidden ───────────────────────────────────


def test_unsignable_input_returns_the_input_and_says_so() -> None:
    """A report that cannot be signed must still be readable, and labelled.

    Both halves matter. Returning an error page would deny the operator a report
    they can still verify against the ledger; returning the bytes silently is the
    bug this module was rewritten to fix.
    """
    junk = b"this is not a PDF"
    result = sign_pdf(junk)

    assert result.signed is False
    assert result.pdf == junk, "the caller still gets something to serve"
    assert "signing failed" in result.detail
    assert "ledger record hash" in result.detail, "the fallback route to trust"


def test_a_broken_pfx_is_reported_by_name(tmp_path: Path, report_pdf: bytes) -> None:
    """An operator who mis-set ``PRAMAN_SIGNING_PFX`` needs to be told which file.

    Silently falling back to the demo key here would be the worst outcome: the
    organisation configured a real identity, the report is signed by a throwaway
    one, and ``detail`` reads like success.
    """
    bad = tmp_path / "corporate-signing.pfx"
    bad.write_bytes(b"not a PKCS#12 container")

    result = sign_pdf(report_pdf, pfx_path=bad, passphrase=b"hunter2")

    assert result.signed is False
    assert "corporate-signing.pfx" in result.detail
    assert result.pdf == report_pdf


def test_a_missing_pfx_falls_back_to_the_demo_key(
    tmp_path: Path, report_pdf: bytes
) -> None:
    """Absent is configuration; present-but-broken is a mistake.

    The two are treated differently on purpose — the default deployment has no
    ``.pfx`` and must still produce a signed report, so absence cannot be an
    error. It must still be labelled a demo.
    """
    result = sign_pdf(report_pdf, pfx_path=tmp_path / "nonexistent.pfx")

    assert result.signed is True, result.detail
    assert "self-signed" in result.detail


def test_signing_is_repeatable(report_pdf: bytes) -> None:
    """Two reports in one process both sign.

    The demo signer is a process-wide cached singleton behind a lock. If the
    cache or the ``IncrementalPdfFileWriter`` were reused wrongly, the first
    report would sign and the second would fail — a bug that only appears on the
    second request and so never in a single-report smoke test.
    """
    first = sign_pdf(report_pdf)
    second = sign_pdf(report_pdf)
    assert first.signed and second.signed, (first.detail, second.detail)
    assert _embedded_signature(first.pdf).field_name == SIGNATURE_FIELD
    assert _embedded_signature(second.pdf).field_name == SIGNATURE_FIELD


def test_signing_works_from_inside_a_running_event_loop(report_pdf: bytes) -> None:
    """The defect the end-to-end probe found, and the reason it hid so well.

    pyHanko's synchronous ``sign_pdf`` calls ``asyncio.run()`` internally, which
    raises inside an async FastAPI handler. Because this module reports failures
    instead of raising them, *every* report served over HTTP came back unsigned
    with a polite explanation, while every report from the CLI and from this test
    file signed correctly. The suite was green and the deployed system produced
    unsigned compliance documents.

    Calling ``sign_pdf`` the way the route calls it -- from within a coroutine --
    is the only assertion that would have caught it.
    """
    import asyncio

    async def sign_as_the_route_does() -> object:
        return sign_pdf(report_pdf)

    result = asyncio.run(sign_as_the_route_does())
    assert result.signed is True, result.detail
    assert _embedded_signature(result.pdf).field_name == SIGNATURE_FIELD


def test_a_report_fetched_over_http_is_actually_signed() -> None:
    """End to end, through the real route, because that is where it broke.

    A unit test of ``sign_pdf`` under ``asyncio.run`` proves the mechanism. This
    proves the wiring: the header the route publishes says ``signed``, and the
    bytes it serves carry a signature a verifier can find.
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from backend.app.main import app

    config = (
        Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cisco_ios_sample.conf"
    ).read_bytes()

    client = TestClient(app)
    ingested = client.post(
        "/ingest", files={"file": ("signing-probe.conf", config, "text/plain")}
    )
    assert ingested.status_code == 200, ingested.text
    device_id = ingested.json()["device_id"]
    committed = client.post("/audit/commit", json={"device_id": device_id})
    assert committed.status_code == 200, committed.text

    response = client.get(f"/devices/{device_id}/report.pdf")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf"
    header = response.headers["X-PRAMAN-Signature"]
    assert header.startswith("signed;"), header
    assert _embedded_signature(response.content).field_name == SIGNATURE_FIELD


# ── The demo identity itself ───────────────────────────────────────────


def test_the_demo_signer_is_cached_per_process() -> None:
    """One identity per process, so a run's reports are mutually comparable."""
    assert _demo_signer() is _demo_signer()


def test_the_demo_certificate_labels_itself_unfit_for_production() -> None:
    """The warning has to live in the artefact, not only in the log line.

    A PDF outlives the response that produced it. Someone opening this report in
    six months sees the certificate's subject and nothing else, so the subject is
    where "not for production" has to be written.
    """
    subject = _demo_signer().signing_cert.subject.human_friendly
    assert "Not for production use" in subject
    assert "PRAMAN Demo Signer" in subject


def test_the_demo_key_is_never_written_to_disk() -> None:
    """A demo key that persists is a demo key someone eventually trusts.

    ``data/private/`` holds the ledger's Ed25519 key, which is meant to persist.
    A PKCS#12 or PEM appearing beside it would be indistinguishable from a real
    signing identity to the next person who looks.
    """
    private_dir = Path("data/private")
    if not private_dir.exists():
        return
    stray = [
        entry.name
        for entry in private_dir.iterdir()
        if entry.suffix.lower() in {".pfx", ".p12", ".pem"}
    ]
    assert stray == [], f"signing material appeared on disk: {stray}"
