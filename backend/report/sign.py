"""PDF signing — Stage 3 of the report pipeline: PAdES signature via pyHanko.

Signing runs LAST — after attach — because pyHanko signs through
``IncrementalPdfFileWriter`` and the writer must not be reused afterwards.

**This stage never lies about its outcome.** The previous version of this module
caught every exception and returned the *unsigned* bytes, so a report that failed
to sign was indistinguishable from one that signed cleanly — and it failed on
every call, because the self-signed path imported a function name that does not
exist in ``cryptography``. A silently unsigned compliance report is worse than no
signature at all: it is a document that looks authoritative to the person reading
it and proves nothing to the person verifying it. So :func:`sign_pdf` returns a
:class:`SigningResult` carrying ``signed`` and a human-readable ``detail``, and
every caller is expected to surface it.

Trust model, stated plainly:

* With a real ``.pfx`` (``pfx_path``) and a TSA URL, output is PAdES-B-LT — the
  signature chains to a CA the verifier already trusts.
* Without one, output is signed by an **ephemeral self-signed demo key** created
  in memory for this process. It proves the bytes were not altered after signing
  and nothing about who produced them. That is enough for a demonstration and
  not enough for an audit, which is exactly what ``detail`` says.
* The ledger's Ed25519 record signature — not this — is the project's integrity
  anchor. A PDF is a rendering; the ``AuditRecord`` is the evidence.

**Signing must work from inside a running event loop.** pyHanko's synchronous
``signers.sign_pdf`` calls ``asyncio.run()`` internally, which raises
``RuntimeError: asyncio.run() cannot be called from a running event loop`` when
invoked from an async FastAPI handler. Because this module reports failures
rather than raising them, that produced the worst possible outcome: every report
served over HTTP came back unsigned with an explanation, while the CLI path signed
cleanly, so the test suite and the demo disagreed with production. :func:`sign_pdf`
therefore does its work on a dedicated thread with its own loop — see
:func:`_run_isolated`.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

#: Field name of the signature widget, referenced by the verification page of
#: the report so a reader knows what to look for in their PDF viewer.
SIGNATURE_FIELD = "PRAMANSignature"

_DEMO_LOCK = threading.Lock()
_DEMO_SIGNER: Any | None = None


def _run_isolated(work: Any) -> Any:
    """Call ``work()`` on a thread that has no event loop of its own.

    Signing is synchronous from this module's point of view, but pyHanko reaches
    for ``asyncio.run()`` underneath, and that is illegal on a thread whose loop
    is already running. When there is no running loop -- the CLI, a test, a
    script -- ``work()`` is called directly; the extra thread would only add
    latency. When there is one, the call is handed to a worker thread, which
    gets a clean slot for pyHanko's own ``asyncio.run()``.

    The event loop is not blocked in any meaningful sense: the handler is already
    awaiting this synchronous stage, so the wait is the same wait, on a thread
    where it is legal.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return work()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="praman-sign") as pool:
        return pool.submit(work).result()


@dataclass(frozen=True)
class SigningResult:
    """The outcome of the signing stage.

    Attributes:
        pdf: The PDF bytes to serve. On failure these are the *unsigned* input
            bytes — a readable report is still more useful than an error page —
            but ``signed`` is False and ``detail`` says why.
        signed: Whether a cryptographic signature was actually applied.
        detail: One sentence for the operator, including the remedy when the
            answer is no.
        signer: Who signed, when known.
    """

    pdf: bytes
    signed: bool
    detail: str
    signer: str = ""

    @property
    def header_value(self) -> str:
        """Compact form for an HTTP response header."""
        state = "signed" if self.signed else "unsigned"
        return f"{state}; {self.detail}"


def sign_pdf(
    pdf_bytes: bytes,
    pfx_path: Path | None = None,
    passphrase: bytes = b"",
    tsa_url: str | None = None,
) -> SigningResult:
    """PAdES-sign a PDF, reporting honestly whether it worked.

    Args:
        pdf_bytes: Raw PDF bytes, after the attach stage.
        pfx_path: A PKCS#12 file holding the organisation's signing identity.
            When absent, an ephemeral self-signed demo key is used.
        passphrase: Passphrase for the ``.pfx``.
        tsa_url: Time Stamp Authority. Supplying one raises the signature from
            B-B to B-LT. Left None the signature carries only the signer's own
            clock, which a verifier has no reason to trust.

    Returns:
        A :class:`SigningResult`. Never raises: a report that cannot be signed
        must still reach the operator, labelled.
    """
    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import signers, timestamps
        from pyhanko.sign.fields import SigSeedSubFilter
    except ImportError as exc:
        return SigningResult(
            pdf=pdf_bytes,
            signed=False,
            detail=(
                f"pyHanko is not installed ({exc}); the report is unsigned. "
                "Install it with: pip install pyHanko"
            ),
        )

    try:
        if pfx_path and pfx_path.exists():
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_file=str(pfx_path), passphrase=passphrase
            )
            if signer is None:
                raise ValueError(
                    f"could not load a signing identity from {pfx_path.name} "
                    "(wrong passphrase, or the file holds no key)"
                )
            signer_name = f"PKCS#12 identity from {pfx_path.name}"
            trust_note = "signed with the supplied organisational key"
        else:
            signer = _demo_signer()
            signer_name = "PRAMAN Demo Signer (ephemeral, self-signed)"
            trust_note = (
                "signed with an ephemeral self-signed demo key: it proves the "
                "bytes are unaltered, not who issued them. Supply a .pfx via "
                "PRAMAN_SIGNING_PFX for an auditable signature"
            )

        meta = signers.PdfSignatureMetadata(
            field_name=SIGNATURE_FIELD,
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        )
        timestamper = timestamps.HTTPTimeStamper(url=tsa_url) if tsa_url else None

        writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
        output = BytesIO()
        _run_isolated(
            lambda: signers.sign_pdf(
                writer,
                signature_meta=meta,
                signer=signer,
                timestamper=timestamper,
                output=output,
            )
        )
        if tsa_url:
            trust_note += "; timestamped by the configured TSA"
        return SigningResult(
            pdf=output.getvalue(),
            signed=True,
            detail=trust_note,
            signer=signer_name,
        )
    except Exception as exc:  # broad by design: the reason is the payload
        return SigningResult(
            pdf=pdf_bytes,
            signed=False,
            detail=(
                f"signing failed ({type(exc).__name__}: {exc}); the report is "
                "unsigned. Verify it instead against the ledger record hash "
                "printed on its verification page."
            ),
        )


def _demo_signer() -> Any:
    """Build (once per process) a self-signed signer for demonstrations.

    Cached because a fresh identity per report would make the signatures
    mutually unrelated, and held in memory rather than written to disk because a
    demo key that persists is a demo key someone eventually trusts.

    The conversion through DER is not incidental: pyHanko speaks asn1crypto,
    ``cryptography`` speaks its own types, and handing a ``cryptography`` key
    straight to ``SimpleSigner`` is the mistake that made this path dead code.
    """
    global _DEMO_SIGNER
    with _DEMO_LOCK:
        if _DEMO_SIGNER is not None:
            return _DEMO_SIGNER

        import datetime

        from asn1crypto import keys as asn1_keys
        from asn1crypto import x509 as asn1_x509
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from pyhanko.sign import signers
        from pyhanko_certvalidator.registry import SimpleCertificateStore

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "PRAMAN Demo Signer"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PRAMAN"),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, "Not for production use"
                ),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(key, hashes.SHA256())
        )

        signing_cert = asn1_x509.Certificate.load(
            certificate.public_bytes(serialization.Encoding.DER)
        )
        signing_key = asn1_keys.PrivateKeyInfo.load(
            key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        registry = SimpleCertificateStore()
        registry.register(signing_cert)

        _DEMO_SIGNER = signers.SimpleSigner(
            signing_cert=signing_cert,
            signing_key=signing_key,
            cert_registry=registry,
        )
        return _DEMO_SIGNER
