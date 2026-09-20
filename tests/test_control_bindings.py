"""Every rule still decides the control it was written against.

`RulesEvaluator._validate_rule_targets` rejects a rule pointing at a control id
that does not exist. That catches a typo, and it catches porting a pack onto a
benchmark that renumbered *and* renamed — no V-number in the DISA IOS switch NDM
benchmark appears in the router NDM one, so a mis-port there cannot load.

It cannot catch a renumbering that keeps the shape of the id, and CIS does that
routinely. Measured against the two catalogs already built in this repo: of the
71 controls the CIS Cisco IOS 15 pack decides, 12 carry a *different* id in CIS
Cisco IOS XE 17.x for the same control text, and both ids exist in both
documents. `1.1.6` is "login authentication for 'line vty'" in IOS 15 and "aaa
accounting ... commands 15" in IOS XE. A pack ported by editing `applies_to`
would load, validate, and then answer the wrong question under the right label.

So the id alone is not a binding. `rules/control_bindings.lock.json` pins what
each target control *said*, and these tests are what make the lockfile load
bearing rather than decorative.
"""

from __future__ import annotations

import json

import pytest

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.frameworks.catalog import load_catalogs
from scripts.control_bindings import LOCK_PATH, drift, measure, published


@pytest.fixture(scope="module")
def measured() -> dict[str, dict[str, str]]:
    return measure()


def test_the_lockfile_exists_and_parses() -> None:
    assert LOCK_PATH.exists(), (
        f"{LOCK_PATH.name} is missing. Every rule's target control is unpinned, so a "
        "benchmark renumbering would re-point rules silently. Generate it with: "
        "python scripts/control_bindings.py --write"
    )
    payload = json.loads(LOCK_PATH.read_text(encoding=FILE_ENCODING))
    assert payload["bindings"], "the lockfile pins nothing"
    assert payload["controls_pinned"] == sum(len(v) for v in payload["bindings"].values())


def test_no_rule_has_been_re_pointed_at_a_different_control(measured) -> None:
    """The gate itself. A drifted title means the rule now decides something else."""
    problems = drift(measured, published())
    assert not problems, (
        "a rule's target control no longer carries the title it was authored "
        "against:\n" + "\n".join(problems) + "\n\nIf the publisher corrected a "
        "title, re-pin: python scripts/control_bindings.py --write\nIf two "
        "controls swapped ids, the rule is mis-bound — fix the rule, not the "
        "lockfile."
    )


def test_the_lockfile_covers_every_automated_control(measured) -> None:
    """An unpinned rule is an ungated rule; partial coverage is the quiet failure."""
    assert sum(len(v) for v in measured.values()) == sum(
        len(v) for v in published().values()
    )


def test_the_gate_catches_a_renumbering_rather_than_merely_passing_today() -> None:
    """Proof the check has teeth, using the real CIS IOS 15 → IOS XE renumbering.

    A gate that only ever passes is indistinguishable from a gate that cannot
    fail. This takes two control ids that genuinely swapped meaning between two
    catalogs shipped in this repo, and asserts the drift check reports it.
    """
    catalogs = {c.catalog_id: c for c in load_catalogs()}
    ios15 = catalogs["cis_cisco_ios_15_v4_1_1"]
    xe = catalogs["cis_cisco_ios_xe_17_x_v2_2_1"]

    ios15_titles = {c.control_id: c.title for c in ios15.controls}
    xe_titles = {c.control_id: c.title for c in xe.controls}

    moved = [
        cid
        for cid, title in ios15_titles.items()
        if cid in xe_titles and xe_titles[cid] != title
    ]
    assert moved, (
        "expected CIS IOS 15 and IOS XE to disagree about at least one control id; "
        "if this is no longer true the two catalogs were rebuilt and the premise "
        "behind the lockfile should be re-measured"
    )

    cid = moved[0]
    was = {"cis_cisco_ios_15_v4_1_1": {cid: ios15_titles[cid]}}
    now = {"cis_cisco_ios_15_v4_1_1": {cid: xe_titles[cid]}}
    problems = drift(now, was)
    assert len(problems) == 1
    assert cid in problems[0]
    assert "was:" in problems[0] and "now:" in problems[0]


def test_the_lockfile_is_not_hand_edited() -> None:
    """The header has to survive, because a hand-edited lockfile gates nothing."""
    payload = json.loads(LOCK_PATH.read_text(encoding=FILE_ENCODING))
    assert "Never hand-edit" in payload["_comment"]
    assert "control_bindings.py --write" in payload["_comment"]


def test_the_lockfile_is_committed() -> None:
    """A gitignored lockfile passes on the author's machine and nowhere else."""
    assert LOCK_PATH.is_relative_to(PROJECT_ROOT / "rules")
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding=FILE_ENCODING)
    for line in gitignore.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            assert stripped not in (LOCK_PATH.name, f"rules/{LOCK_PATH.name}")
