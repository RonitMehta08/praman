"""The work every route does before it can answer: parse, evaluate, look up.

These three functions used to be private helpers inside ``backend/app/main.py``.
They live here because a second module now needs them — ``routes_export.py`` —
and the alternative was for that module to reimplement them.

That would not have been a style problem. :func:`parse_config` is where redaction
happens, and its guarantee is stated as a property of *funnelling*: every path
that turns bytes into facts goes through this one function, so a new endpoint
cannot forget to redact. A route that built its own parse call would be exactly
the mistake that guarantee exists to make impossible. Putting the funnel in a
module both routers import makes the claim structural rather than a convention
somebody has to remember.

Nothing here touches the ledger and nothing here decides a verdict; the verdict
logic is in ``backend/rules`` and is reachable identically from
``backend/cli.py``.
"""

from __future__ import annotations

from fastapi import HTTPException

from backend.app.state import STATE
from backend.canonical.models import CanonicalFact
from backend.core_errors import ParseError
from backend.ingest.base import ParseResult
from backend.ingest.redact import redact_parse_result

__all__ = ["evaluate_facts", "parse_config", "require_device"]


def parse_config(raw_text: str, source_file: str) -> ParseResult:
    """Detect the vendor, parse, and redact the result.

    The error names the vendors that *are* loaded, because "no parser could
    handle this" without that list gives the operator nothing to act on — while
    with it, the fix (add a pattern pack, or check the file is a config at all)
    is obvious.

    Redaction happens here, on the far side of the parse, rather than at each
    caller on the near side of it. Both halves of that matter:

    * *Here*, because every ingestion path funnels through this function, so a
      new endpoint cannot forget to redact — which is the only kind of mistake
      that leaks a credential into the ledger.
    * *After* the parse, because the packs read whitespace-delimited fields.
      Rewriting the text first shifted every field after a secret and the line
      stopped matching, destroying the non-secret facts alongside the secret one:
      58 facts and 31 verdicts across the ten shipped fixtures, including a FAIL
      that became a PASS. backend/ingest/redact.py has the measurements.

    Evaluating the redacted facts is sound: the substitution is
    comparison-equivalent, so no verdict depends on it.
    """
    adapter = STATE.detect(raw_text, source_file)
    if adapter is None:
        raise ParseError(
            f"no pattern pack recognised '{source_file}'. Loaded vendors: "
            f"{', '.join(STATE.vendors()) or 'none'}. Add "
            f"data/ingest/patterns/<vendor>.yaml to onboard a new platform — no "
            "code change is required."
        )
    return redact_parse_result(adapter.parse(raw_text, source_file))


def evaluate_facts(
    facts: list[CanonicalFact], vendor: str, os_family: str, os_version=None
):
    """Run the deterministic engine over a device's facts.

    No ``frameworks`` filter and governance projection left on, deliberately:
    C3 asks for all four frameworks in one pass, and the projected ones (NIST
    800-53, ISO 27001) exist only as roll-ups of the direct ones. Filtering here
    would silently turn a four-framework audit into a one-framework audit.
    """
    evaluator = STATE.evaluator()
    findings = evaluator.evaluate(facts, vendor, os_family, os_version=os_version)
    return evaluator, findings


def require_device(conn, device_id: str):
    """Fetch a device row or 404 with the id that was asked for."""
    row = conn.execute(
        "SELECT * FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"device '{device_id}' not found")
    return row
