"""Walking a ZIP of device configurations — the estate-scale ingest path (C1).

Split out of ``backend/app/main.py`` for two reasons. The first is size: that
file is already over the 500-line limit and this is the largest block in it that
is not a route. The second is the one that matters — the same walk now runs in
two places, synchronously inside a request and on the job queue's worker thread,
and a bulk import whose two modes could disagree about what a valid archive is
would be worse than having only one of them.

So the walk is one generator. :func:`read_members` yields one outcome per
member and never raises for a bad member; the caller decides what to do between
items, which for the async path is "check whether the operator cancelled".

Archive validation lives in :func:`open_archive` and happens before any member
is read, because the limits are the ones that stop a zip bomb and a limit
checked halfway through has already lost.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from io import BytesIO
from typing import Any, NamedTuple

from backend.app.config import (
    MAX_ARCHIVE_MEMBERS,
    MAX_MEMBER_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
)


class ArchiveRejectedError(Exception):
    """The archive as a whole is unusable. Carries the HTTP status to return.

    A domain exception rather than ``HTTPException`` so this module stays
    importable without FastAPI in scope and usable from the CLI; the route
    translates it at the boundary.
    """

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class MemberOutcome(NamedTuple):
    """What happened to one archive member.

    ``error`` and ``text`` are mutually exclusive: a member either decoded to
    configuration text or it did not, and modelling that as two optional fields
    on one record keeps the caller's loop a single branch.
    """

    name: str
    text: str | None
    error: str | None


def reject_unsafe_member(name: str) -> None:
    """Refuse an archive member name that tries to escape its own tree.

    Nothing here is written to disk, so traversal cannot overwrite a file. It is
    still rejected, because the name is stored as provenance and rendered in the
    UI, and ``../../etc/passwd`` appearing as a device's source file is a finding
    an auditor should never have to explain away.
    """
    pure = name.replace("\\", "/")
    if pure.startswith("/") or ".." in pure.split("/") or ":" in pure.split("/")[0][1:]:
        raise ValueError("member name attempts directory traversal or names an absolute path")


def open_archive(raw: bytes) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    """Open and validate an uploaded archive, or raise :class:`ArchiveRejectedError`.

    Both ceilings are checked against the *declared* sizes in the central
    directory, which is cheap and catches the honest oversized upload. The
    crafted archive that understates its own sizes is caught later, during the
    read, where the lie becomes memory — see :func:`read_members`.
    """
    try:
        archive = zipfile.ZipFile(BytesIO(raw), "r")
    except zipfile.BadZipFile as err:
        raise ArchiveRejectedError(
            400,
            "uploaded file is not a valid ZIP archive. Send a .zip of "
            "configuration files, or use POST /ingest for a single file.",
        ) from err

    members = [info for info in archive.infolist() if not info.is_dir()]
    if len(members) > MAX_ARCHIVE_MEMBERS:
        archive.close()
        raise ArchiveRejectedError(
            413,
            f"archive holds {len(members)} files, above the "
            f"{MAX_ARCHIVE_MEMBERS} limit. Split it into batches.",
        )
    declared_total = sum(info.file_size for info in members)
    if declared_total > MAX_TOTAL_UNCOMPRESSED_BYTES:
        archive.close()
        raise ArchiveRejectedError(
            413,
            "archive expands to "
            f"{declared_total // (1024 * 1024)} MB, above the "
            f"{MAX_TOTAL_UNCOMPRESSED_BYTES // (1024 * 1024)} MB limit. "
            "This is the zip-bomb guard; split the archive if the size is genuine.",
        )
    return archive, members


def read_members(
    archive: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    decode: Any,
) -> Iterator[MemberOutcome]:
    """Yield each member's text, or the reason it could not be read.

    One member failing does not fail the archive. A 400-device upload where two
    files are Word documents should ingest 398 devices and say which two failed —
    an all-or-nothing bulk import is a bulk import that never completes.
    """
    consumed = 0
    for info in members:
        name = info.filename
        try:
            reject_unsafe_member(name)
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError(
                    f"member is {info.file_size // 1024} KB, above the "
                    f"{MAX_MEMBER_BYTES // 1024} KB per-file limit"
                )
            # Read with an explicit ceiling as well as trusting the header: a
            # crafted archive can understate file_size, and the read is where
            # that lie becomes memory.
            with archive.open(info, "r") as handle:
                payload = handle.read(MAX_MEMBER_BYTES + 1)
            if len(payload) > MAX_MEMBER_BYTES:
                raise ValueError(
                    "member expands past the per-file limit; its declared size "
                    "did not match its contents"
                )
            consumed += len(payload)
            if consumed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ValueError("archive expanded past the total size limit")
            yield MemberOutcome(name=name, text=decode(payload), error=None)
        except Exception as exc:
            yield MemberOutcome(name=name, text=None, error=f"{type(exc).__name__}: {exc}")
