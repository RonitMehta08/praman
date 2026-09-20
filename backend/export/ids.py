"""Identifier plumbing shared by the OSCAL and SARIF exporters.

Three problems live here, and all three are about *not* silently changing an
identifier a publisher wrote.

**Deterministic UUIDs.** OSCAL requires a version-4 or version-5 UUID in a dozen
places. A version-4 UUID would make every export of one committed audit a
different document, which defeats the point of exporting from a hash-chained
ledger: a GRC platform that ingests the same audit twice would see two unrelated
assessments. Every UUID here is a version-5 (SHA-1 name-based) UUID over a
namespace and a stable key, so exporting ledger record ``seq=18`` in a year
produces byte-identical JSON. ``uuid5`` writes version ``5`` and variant ``10xx``
into the right nibbles, which is what OSCAL's ``UUIDDatatype`` pattern
``[45][0-9A-Fa-f]{3}-[89ABab]`` requires.

**OSCAL tokens.** ``finding-target.target-id`` is an OSCAL ``TokenDatatype`` —
an XML Schema NCName, ``^(\\p{L}|_)(\\p{L}|\\p{N}|[.\\-_])*$``. A DISA id like
``V-215668`` satisfies it. A CIS id like ``1.1.4`` does not, because NCName
forbids a leading digit. The naive fix — rewrite it to ``1-1-4`` — invents an
identifier CIS never published. So the id is *prefixed*, never rewritten, and the
verbatim publisher id always travels beside it in a property. A consumer that
wants to match against the benchmark reads the property; a consumer that only
needs a schema-valid key reads the token.

**Namespace.** ``urn:praman:oscal`` is deliberately a URN and not an ``https``
URL. OSCAL's ``ns`` field wants a URI to disambiguate whose property name this
is, not a document to fetch; PRAMAN runs air-gapped, so a URL that would 404 on
the one machine that matters is a worse answer than a URN that never claimed to
resolve.
"""

from __future__ import annotations

import re
import uuid

#: Namespace for every PRAMAN-defined OSCAL property name. See module docstring.
PRAMAN_NS = "urn:praman:oscal"

#: Root namespace for every deterministic UUID this package mints. Derived once
#: from a fixed URN so the constant itself is reproducible from the string above
#: rather than being a magic literal somebody would have to trust.
PRAMAN_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:praman:export")

#: XML Schema NCName, which is what OSCAL's TokenDatatype is defined as. Python's
#: ``re`` has no ``\p{L}``, so this is the ASCII subset: every control id in the
#: shipped catalogs is ASCII, and :func:`oscal_token` falls back to a prefix
#: rather than accepting anything this rejects.
_NCNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9._\-]*$")

#: Characters NCName allows after the first. Anything else is replaced, and the
#: replacement is recorded so the export says it happened.
_NOT_NCNAME_BODY = re.compile(r"[^A-Za-z0-9._\-]")


def deterministic_uuid(*parts: str) -> str:
    """A version-5 UUID over `parts`, stable across processes and machines.

    Parts are joined with ``\\x1f`` (unit separator) rather than a printable
    character so no combination of ids can collide with a different combination
    by containing the separator — ``("a|b", "c")`` and ``("a", "b|c")`` would
    otherwise hash identically.
    """
    return str(uuid.uuid5(PRAMAN_UUID_NAMESPACE, "\x1f".join(parts)))


def oscal_token(control_id: str, framework: str) -> tuple[str, bool]:
    """`control_id` as an OSCAL TokenDatatype, plus whether it had to be changed.

    Returns ``(token, was_adjusted)``. When ``was_adjusted`` is true the caller
    **must** publish the verbatim ``control_id`` alongside the token — every
    caller in this package does, through ``praman-control-id``.

    The prefix is the framework name lowercased with underscores kept, so CIS
    ``1.1.4`` becomes ``cis-1.1.4``: still recognisable, still traceable, and
    obviously not something CIS wrote.
    """
    if _NCNAME.match(control_id):
        return control_id, False
    prefix = framework.strip().lower().replace(" ", "_") or "praman"
    candidate = f"{prefix}-{control_id.strip()}"
    if _NCNAME.match(candidate):
        return candidate, True
    # A control id with characters NCName forbids anywhere — none exist in the
    # shipped catalogs, so this is the branch that keeps a future catalog from
    # emitting an invalid document rather than one that runs today.
    return f"{prefix}-{_NOT_NCNAME_BODY.sub('_', control_id.strip())}", True
