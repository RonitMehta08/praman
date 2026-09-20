"""The verification-marker register must be complete, current and non-blocking.

``GLOBAL_RULESET.md`` R1.5 gives three markers for text that is not fully
established, and §236 makes one of them a release gate: no ``UNVERIFIED`` and no
unresolved ``TODO`` ``(verify)`` may reach a shipped path. ``docs/GAPS.md`` §7
publishes the register that discharges the disclosure half of that rule, and
``scripts/collect_unverified.py --check`` is what proves it still matches the
repository.

The reason this is a test and not a CI step is the reason every other generated
artifact in this project is checked here: there is no CI. ``--check`` only
protects the register if something runs it, and pytest is the thing that runs.

Why this one imports instead of shelling out
--------------------------------------------
``tests/test_metrics_are_current.py`` runs ``scripts/bench/run_all.py`` as a
subprocess because the bench scripts mutate module-scope state and, in one case,
``builtins.__import__``. ``collect_unverified.py`` does none of that — it reads
files and returns dataclasses — so a subprocess would buy nothing and cost a
Python startup on every run. The one piece of global state it touches is
``sys.path``, which pytest has already arranged the same way.

The failure this is really guarding
-----------------------------------
The count was hand-maintained before the script existed. ``PRODUCTION-ROADMAP.md``
published *0 / 0 / 2* with a paragraph of confidence around it, and the machine
run over the same tree finds an order of magnitude more — the roadmap had walked
``backend/`` and skipped the pattern packs and the mapping packs, which is where
an author actually leaves a note to self, because that is where ambiguous
publisher text gets resolved. A number that is only ever recomputed by the person
who believes it is not a measurement.
"""

from __future__ import annotations

import json

from backend.app.config import FILE_ENCODING
from scripts.collect_unverified import (
    ALLOWLIST,
    BEGIN,
    END,
    GAPS,
    REGISTER_JSON,
    build_payload,
    collect,
    render_register,
)


def test_no_shipped_path_carries_an_unresolved_marker() -> None:
    """§236, enforced. ``backend/``, ``frontend/``, ``rules/``, ``data/ingest/``.

    A marker in one of those roots is not a note to a colleague: that text is
    reachable by an operator through the UI, a finding rationale or the signed
    PDF, and an auditor reading "TODO" beside a verdict has been told the verdict
    is provisional in the one place PRAMAN is asserting it is not.

    ``ASSUMPTION:`` is exempt by kind and one ``UNVERIFIED`` is exempt by name;
    both exemptions are argued in the script and in ``docs/GAPS.md`` §7 rather
    than assumed here.
    """
    blocking, _register, _errors = collect()
    assert not blocking, "Unresolved verification markers in shipped paths:\n" + "\n".join(
        f"  {hit.file}:{hit.line} [{hit.marker}] {hit.text}" for hit in blocking
    )


def test_every_allowlist_entry_still_authorises_something() -> None:
    """An allowlist that outlives its subject is worse than no allowlist.

    It reads as a live exemption, so the next author trusts it and does not look;
    meanwhile the marker it was written for is gone and the entry is silently
    authorising a file that no longer needs authorising. Stale entries are how an
    allowlist becomes a place to hide a real one.
    """
    _blocking, _register, errors = collect()
    assert not errors, "\n".join(errors)
    assert ALLOWLIST, (
        "The allowlist is empty. That is a fine state to be in, but delete this "
        "assertion deliberately rather than letting it pass vacuously."
    )


def test_the_published_register_is_not_stale() -> None:
    """``docs/GAPS.md`` §7 must match the repository, byte for byte.

    The block includes its own rationale — which roots block, why ``ASSUMPTION:``
    never does, and each allowlist reason — because that prose names the shipped
    roots and would otherwise drift from them. Generating it also puts it inside
    the region :func:`~scripts.collect_unverified._scan` blanks, so the document
    explaining the register does not become rows in it.
    """
    _blocking, register, _errors = collect()
    text = GAPS.read_text(encoding=FILE_ENCODING)
    assert BEGIN in text and END in text, (
        f"{GAPS.name} has lost its {BEGIN} / {END} sentinels. The register has "
        "nowhere to be published, so §236's disclosure half is undischarged."
    )
    assert render_register(register) in text, (
        f"{GAPS.name} no longer matches the repository. Regenerate it:\n"
        "  python scripts/collect_unverified.py --write"
    )


def test_the_published_json_matches_what_a_fresh_scan_finds() -> None:
    """``reports/metrics/unverified.json`` is the machine-readable half.

    Compared field by field rather than whole, because ``generated_at`` moves on
    every run: asserting the payloads are equal would fail on a clock tick, and a
    test that fails for a reason nobody caused is a test people learn to rerun
    until it passes.
    """
    assert REGISTER_JSON.exists(), (
        f"{REGISTER_JSON.name} is missing. Generate it:\n"
        "  python scripts/collect_unverified.py --write"
    )
    blocking, register, _errors = collect()
    fresh = build_payload(blocking, register)
    published = json.loads(REGISTER_JSON.read_text(encoding=FILE_ENCODING))
    drifted = [
        key
        for key in ("counts", "blocking", "register", "allowlisted")
        if published.get(key) != fresh[key]
    ]
    assert not drifted, (
        f"{REGISTER_JSON.name} has drifted in {drifted}. Regenerate it:\n"
        "  python scripts/collect_unverified.py --write"
    )


def test_the_scanner_does_not_count_its_own_output() -> None:
    """Blanking the generated block is load-bearing, so it is asserted.

    Writing the table into ``GAPS.md`` puts every marker string it quotes back
    into a scanned document. The first version did exactly that: the count jumped
    by 36 on the second run and would have kept climbing, because each run's
    output was the next run's input. ``_scan`` blanks the region between the
    sentinels before matching.

    Without this assertion the fix is invisible — the register would simply be
    wrong, plausibly, and in the direction that makes the project look worse
    rather than better, which is the direction nobody double-checks.
    """
    _blocking, register, _errors = collect()
    lines = GAPS.read_text(encoding=FILE_ENCODING).splitlines()
    first = next(i for i, line in enumerate(lines, 1) if BEGIN in line)
    last = next(i for i, line in enumerate(lines, 1) if END in line)
    caught = sorted(
        hit.line
        for hit in register
        if hit.file.endswith("docs/GAPS.md") and first <= hit.line <= last
    )
    assert not caught, (
        f"The register is quoting itself at {GAPS.name} lines {caught}, inside "
        f"its own generated block ({first}-{last}). Each run would then find more "
        "markers than the last."
    )
