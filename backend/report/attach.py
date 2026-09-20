"""PDF attachment — Stage 2 of the report pipeline: the machine-readable evidence.

    render.py  →  attach.py  →  sign.py

A rendered report is prose. It says a control failed; it does not let a verifier
recompute that from the device's own configuration. So the findings and the
canonical facts they were derived from are embedded in the PDF as attachments,
and the signature applied by stage 3 then covers them. One file, self-verifying:
the reader gets the document, the evidence, and the proof neither was altered.

That ordering is not negotiable. pyHanko signs through an incremental update, so
anything added after signing lands outside the byte range the signature covers —
attached evidence added at stage 3+1 would be evidence the signature says nothing
about, which is worse than none.

**This stage reports its outcome.** It used to return raw ``bytes`` and catch only
``ImportError``, which produced two separate failures: with pikepdf absent it
returned the unattached PDF indistinguishably from success, and with pikepdf
present it raised ``AttributeError`` on every single call, because it reached for
``pdf.root`` where pikepdf spells the document catalogue ``pdf.Root``. Nothing
caught either one, because nothing called this module — the report route went
straight from render to sign, and every report ever produced shipped without its
evidence. Hence :class:`AttachResult`, and hence the tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from io import BytesIO
from typing import Any

#: Attachment names, numerically prefixed. Acrobat and most viewers list
#: attachments in insertion order but several sort by name, so the prefix is what
#: makes "findings first" true everywhere rather than incidentally.
FINDINGS_NAME = "01_findings.json"
CANONICAL_NAME = "02_canonical.json"


@dataclass(frozen=True)
class AttachResult:
    """The outcome of the attach stage.

    Attributes:
        pdf: The PDF bytes to pass to stage 3. On failure these are the input
            bytes unchanged — a report without its evidence is still a report —
            but ``attached`` is False.
        attached: Whether the evidence files were actually embedded.
        detail: One sentence for the operator, with the remedy when the answer
            is no.
        names: The attachment names present, for a caller that wants to tell the
            reader what to look for.
    """

    pdf: bytes
    attached: bool
    detail: str
    names: tuple[str, ...] = ()

    @property
    def header_value(self) -> str:
        """Compact form for an HTTP response header."""
        if self.attached:
            return f"attached; {', '.join(self.names)}"
        return f"none; {self.detail}"


def attach_evidence(
    pdf_bytes: bytes,
    findings: list[dict[str, Any]],
    canonical_facts: list[dict[str, Any]],
) -> AttachResult:
    """Embed findings and canonical facts into the PDF as file attachments.

    Args:
        pdf_bytes: Raw PDF bytes from :func:`~backend.report.render.render_pdf`.
        findings: Finding dicts, exactly as the API serves them, so a verifier
            comparing the attachment against ``GET /findings`` sees the same
            document rather than two renderings of one.
        canonical_facts: The facts the findings were evaluated against. This is
            the half that makes a verdict checkable: with the canonical model in
            hand, a reader can re-run the rule themselves.

    Returns:
        An :class:`AttachResult`. Never raises — a report that cannot carry its
        evidence must still reach the operator, labelled.

    Note:
        No ``/AF`` associated-file entry and no ``FileAttachment`` annotation is
        added. pikepdf's ``attachments`` mapping already writes the
        ``/Names/EmbeddedFiles`` tree, and adding an annotation as well makes
        viewers list every file twice. This is also deliberately *not* claimed as
        PDF/A-3: conformance needs an output intent, an XMP declaration and font
        embedding guarantees this pipeline does not make, and a false claim is a
        validation failure rather than a cosmetic one.
    """
    try:
        from pikepdf import AttachedFileSpec, Name, Pdf
    except ImportError as exc:
        return AttachResult(
            pdf=pdf_bytes,
            attached=False,
            detail=(
                f"pikepdf is not installed ({exc}); the report carries no "
                "machine-readable evidence. Install it with: pip install pikepdf"
            ),
        )

    try:
        # ``default=str`` so a datetime or Decimal that reached a finding cannot
        # fail the whole stage; ``sort_keys`` so two runs over equal findings
        # produce equal bytes, which the golden-file report tests rely on.
        findings_json = json.dumps(
            findings, indent=2, sort_keys=True, default=str
        ).encode("utf-8")
        canonical_json = json.dumps(
            canonical_facts, indent=2, sort_keys=True, default=str
        ).encode("utf-8")

        with Pdf.open(BytesIO(pdf_bytes)) as pdf:
            pdf.attachments[FINDINGS_NAME] = AttachedFileSpec(
                pdf,
                findings_json,
                mime_type="application/json",
                description="PRAMAN findings for this device, one per control",
            )
            pdf.attachments[CANONICAL_NAME] = AttachedFileSpec(
                pdf,
                canonical_json,
                mime_type="application/json",
                description="Canonical facts the findings were evaluated against",
            )
            # Open the attachments pane, so the evidence is visible rather than
            # merely present. `Root` is the document catalogue — lowercase `root`
            # is not a pikepdf attribute and was this module's original bug.
            pdf.Root.PageMode = Name.UseAttachments

            output = BytesIO()
            pdf.save(output)

        return AttachResult(
            pdf=output.getvalue(),
            attached=True,
            detail=(
                f"embedded {len(findings)} finding(s) and "
                f"{len(canonical_facts)} canonical fact(s)"
            ),
            names=(FINDINGS_NAME, CANONICAL_NAME),
        )
    except Exception as exc:  # broad by design: the reason is the payload
        return AttachResult(
            pdf=pdf_bytes,
            attached=False,
            detail=(
                f"attaching evidence failed ({type(exc).__name__}: {exc}); the "
                "report is readable but carries no machine-readable evidence. "
                "Fetch it from GET /devices/{device_id}/findings instead."
            ),
        )
