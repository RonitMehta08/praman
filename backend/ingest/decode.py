"""Turning bytes on disk or on the wire into config text, with one policy.

Why this is a module and not two functions
------------------------------------------
There were two decode paths and they disagreed. The API decoded uploads through a
candidate list beginning with ``utf-8-sig``; the CLI called
``Path.read_text(encoding="utf-8")``. So the same file produced two outcomes
depending on how it was audited:

* **A UTF-8 BOM** — which Notepad, PowerShell ``Out-File`` and several TFTP
  collectors emit by default — survived the CLI's decode as a leading ``\\ufeff``
  and attached itself to whatever command was on line 1. If that line was
  ``hostname``, the hostname pattern stopped matching and the device lost its
  identity: ``device.hostname`` came back ``None`` and the per-device report could
  not say which device it was about. Measured on a real fixture: 193 facts either
  way, but one extra unparsed line and, when ``hostname`` was first, no hostname.
* **A cp1252 byte** — a smart quote in an interface description, routine in
  configs edited on Windows — raised ``UnicodeDecodeError`` out of the CLI as an
  unhandled traceback, while the same upload through ``/ingest`` parsed fine.

Neither is an exotic input, and "it depends which entry point you used" is not a
defensible answer for a tool whose output is meant to be evidence. So the policy
lives here once and both entry points call it.

The policy
----------
Try each encoding in :data:`DECODINGS` in order and take the first that decodes.
The list ends with ``latin-1``, which maps every byte 0x00-0xFF to a codepoint and
therefore cannot raise, so the function is **total**: it never refuses a file.
That is deliberate. Configurations are pasted, mailed and copied off TFTP servers
by people who never think about encoding, and a compliance tool that returns 500
on a stray 0x92 byte in a description string is a tool that does not get used.

NFKC normalisation follows, so visually identical commands hash identically. The
config hash is an identity — two byte sequences that render the same must not
produce two devices in the estate view.

What this does *not* do
-----------------------
It does not repair mojibake. A cp1252 file decoded as latin-1 differs in the
0x80-0x9F range, so a smart quote may land as a control character rather than as
``'``. That affects free-text fields — descriptions, banners — and no canonical
path derives a compliance verdict from those, so the verdict is unaffected while
the evidence line may look odd. Guessing harder (chardet, byte-frequency
heuristics) would trade a cosmetic defect for a silent one.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

#: Tried in order. ``utf-8-sig`` must come first: it is ``utf-8`` plus BOM
#: removal, and plain ``utf-8`` accepts a BOM-prefixed file *successfully* while
#: leaving the BOM in the string. Putting ``utf-8`` first would therefore never
#: reach the sig variant and the bug this module exists to fix would be intact.
#:
#: ``cp1252`` before ``latin-1`` because it is the stricter of the two — it has
#: undefined slots that raise, so a file that decodes cleanly as cp1252 was
#: probably written as cp1252. ``latin-1`` last because it always succeeds and so
#: is the terminator, not a candidate.
DECODINGS = ("utf-8-sig", "utf-8", "cp1252", "latin-1")


def decode_config(raw: bytes) -> str:
    """Decode configuration bytes without ever refusing the file.

    Args:
        raw: Configuration bytes from an upload, an archive member or a file.

    Returns:
        NFKC-normalised text with any byte-order mark removed.
    """
    for encoding in DECODINGS:
        try:
            return normalise(raw.decode(encoding))
        except UnicodeDecodeError:
            continue
    # Unreachable while latin-1 is last, and kept because "unreachable" is a
    # property of the tuple above rather than of this function.
    return normalise(raw.decode("latin-1", errors="replace"))


def decode_config_file(path: Path) -> str:
    """Read and decode a config file from disk under the same policy as an upload.

    Reads bytes rather than text so the encoding decision happens in exactly one
    place. ``Path.read_text(encoding=...)`` at a call site is how the two paths
    diverged in the first place.
    """
    return decode_config(path.read_bytes())


def normalise(text: str) -> str:
    """NFKC-normalise already-decoded text and strip a leading BOM.

    Exposed separately for the ``/simulate`` endpoint, which receives config text
    as a JSON string that has already been decoded by the HTTP layer. A BOM can
    still be present there — a client that reads a BOM-prefixed file as ``utf-8``
    and posts the resulting string passes the ``\\ufeff`` straight through — so
    the strip is not redundant.
    """
    return unicodedata.normalize("NFKC", text.lstrip("﻿"))
