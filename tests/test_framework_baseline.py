"""Test: SP 800-53B baseline scoping — the absent case, and the id hazard.

Two things are being defended here, and only one of them is obvious.

**The absent case.** ``data/frameworks/oscal/baselines.json`` is produced by
``MANUAL_COMMANDS.md`` Step 16 and is not in the repository, so on a fresh clone
``load_baselines()`` returns ``{}``. That is correct, and it is also the exact
shape of bug that shipped in ``backend/threat/enrichment.py`` — a mistyped path
and a legitimately-missing artefact return the same empty answer, and nothing
about the emptiness looks wrong. So the path is pinned against the document that
creates the file, and ``scope_to_baseline`` is asserted to return ``None`` rather
than ``set()``: an empty set would make a caller compute 0/0 or, worse, publish a
MODERATE-scoped figure that silently selected nothing.

**The id hazard, which is the sharper one.** OSCAL writes an enhancement with a
dot — ``ac-17.2`` — and PRAMAN's catalogs write it in parentheses — ``AC-17(02)``.
``normalise_control_id`` only recognises the parenthesised form, so fed the OSCAL
spelling it does not fail: it matches the ``ac-17`` prefix and returns the *base
control*. A baseline loaded through it would claim MODERATE selects ``AC-17``
when the publication selects ``AC-17(2)``, and every downstream number would be
wrong in the direction that flatters the tool. ``test_oscal_dotted_enhancement_
is_not_folded_into_its_base`` pins the difference against the older function so
the two cannot quietly converge.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.frameworks import baseline as baseline_mod
from backend.frameworks.baseline import (
    BASELINE_NAMES,
    BASELINE_PATH,
    catalog_composition,
    extract_profile_ids,
    load_baselines,
    normalise_oscal_id,
    scope_to_baseline,
    write_baselines,
)
from backend.frameworks.catalog import CATALOG_DIR
from backend.frameworks.crosswalk import normalise_control_id

MANUAL_COMMANDS = PROJECT_ROOT / "MANUAL_COMMANDS.md"
NIST_CATALOG = CATALOG_DIR / "nist_800_53_rev5_5_2_0.json"


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """The loader is lru_cached for the process; every test starts cold."""
    load_baselines.cache_clear()
    yield
    load_baselines.cache_clear()


def _point_at(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setattr(baseline_mod, "BASELINE_PATH", path)
    load_baselines.cache_clear()


# ---------------------------------------------------------------- the contract


def test_path_matches_the_step_that_creates_it() -> None:
    """Step 16 and BASELINE_PATH must name the same file.

    Checked against the document rather than against a second constant, because
    two constants in the same repository drift together and a constant and a
    runbook drift apart — which is the failure this pins.
    """
    relative = BASELINE_PATH.relative_to(PROJECT_ROOT)
    assert relative == Path("data/frameworks/oscal/baselines.json")
    text = MANUAL_COMMANDS.read_text(encoding=FILE_ENCODING)
    assert "## Step 16" in text
    windows_form = str(relative).replace("/", "\\")
    assert windows_form in text or str(relative) in text


def test_absent_allocation_is_empty_and_scoping_is_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh clone: no file, no baselines, and no scoped answer at all."""
    _point_at(monkeypatch, tmp_path / "absent.json")
    assert load_baselines() == {}
    assert baseline_mod.baseline_source() == ""
    # None, not set(): "there is no allocation" and "the allocation selects
    # nothing" must not be the same value to a caller.
    assert scope_to_baseline({"AC-17(02)"}, "moderate") is None


def test_malformed_allocation_degrades_to_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Truncated or wrongly-shaped JSON is absence, never a partial baseline."""
    broken = tmp_path / "baselines.json"
    broken.write_text('{"baselines": {"moderate": [', encoding=FILE_ENCODING)
    _point_at(monkeypatch, broken)
    assert load_baselines() == {}

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text('{"baselines": ["AC-17(02)"]}', encoding=FILE_ENCODING)
    _point_at(monkeypatch, wrong_shape)
    assert load_baselines() == {}


def test_present_allocation_scopes_and_cites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the artefact on disk, scoping restricts and the source is quotable."""
    path = tmp_path / "baselines.json"
    path.write_text(
        json.dumps(
            {
                "source": "SP 800-53B MODERATE baseline profile",
                "baselines": {"moderate": ["AC-17(02)", "AU-03"], "low": ["AU-03"]},
            }
        ),
        encoding=FILE_ENCODING,
    )
    _point_at(monkeypatch, path)

    assert load_baselines()["moderate"] == frozenset({"AC-17(02)", "AU-03"})
    assert baseline_mod.baseline_source() == "SP 800-53B MODERATE baseline profile"
    decided = {"AC-17(02)", "AU-03", "PS-03"}
    assert scope_to_baseline(decided, "moderate") == {"AC-17(02)", "AU-03"}
    assert scope_to_baseline(decided, "LOW") == {"AU-03"}
    # HIGH was not in the artefact. Absent for one level is still absent.
    assert scope_to_baseline(decided, "high") is None


# --------------------------------------------------------------- the id hazard


def test_oscal_dotted_enhancement_is_not_folded_into_its_base() -> None:
    """The regression this module was written for.

    ``normalise_control_id`` is not wrong — it was written for the parenthesised
    spelling and does that correctly. It is simply the wrong function for an
    OSCAL id, and it fails by returning something plausible.
    """
    assert normalise_control_id("ac-17.2") == "AC-17"  # the trap
    assert normalise_oscal_id("ac-17.2") == "AC-17(02)"  # the fix
    assert normalise_oscal_id("ac-17") == "AC-17"
    assert normalise_oscal_id("AC-17(2)") == "AC-17(02)"
    assert normalise_oscal_id("sc-7.11") == "SC-07(11)"


def test_unparseable_ids_are_dropped_not_invented() -> None:
    assert normalise_oscal_id("") is None
    assert normalise_oscal_id("not-a-control") is None
    assert normalise_oscal_id("5.2") is None


# ------------------------------------------------------------- the extraction


def test_extraction_is_structure_agnostic_and_deduplicates() -> None:
    """``with-ids`` is collected wherever it appears, at any depth."""
    profile = {
        "profile": {
            "imports": [
                {"include-controls": [{"with-ids": ["ac-2", "ac-2.1"]}]},
                {"include-controls": [{"with-ids": ["ac-2", "au-3.1"]}]},
            ],
            "modify": {"nested": {"deeper": [{"with-ids": ["sc-7"]}]}},
        }
    }
    assert extract_profile_ids(profile) == [
        "AC-02",
        "AC-02(01)",
        "AU-03(01)",
        "SC-07",
    ]


def test_unexpected_shape_yields_nothing_rather_than_guessing() -> None:
    """Step 16's verification step reports zero; it does not get a half-baseline."""
    assert extract_profile_ids({"profile": {"imports": [{"controls": ["ac-2"]}]}}) == []
    assert extract_profile_ids({}) == []


def test_write_baselines_round_trips_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-running Step 16 on the same publication must produce the same bytes."""
    _point_at(monkeypatch, tmp_path / "baselines.json")
    profiles = {
        "moderate": {"imports": [{"include-controls": [{"with-ids": ["ac-2.1"]}]}]},
        "low": {"imports": [{"include-controls": [{"with-ids": ["au-3"]}]}]},
    }
    first = write_baselines(profiles, source="unit test").read_bytes()
    second = write_baselines(profiles, source="unit test").read_bytes()
    assert first == second

    loaded = load_baselines()
    assert loaded["moderate"] == frozenset({"AC-02(01)"})
    assert loaded["low"] == frozenset({"AU-03"})
    # HIGH was not supplied and is therefore not claimed.
    assert "high" not in loaded
    assert set(loaded) <= set(BASELINE_NAMES)


# ------------------------------------------------------ the derivable framing


def test_catalog_composition_matches_the_catalog_on_disk() -> None:
    """1,014 current NIST controls = 300 base + 714 enhancements.

    This is the part of §3.4 that *is* derivable from the repository, and it is
    asserted against the built catalog rather than hard-coded alone so that a
    catalog rebuild against a later SP 800-53 revision fails here loudly instead
    of leaving the published composition stale.
    """
    controls = json.loads(NIST_CATALOG.read_text(encoding=FILE_ENCODING))["controls"]
    ids = [c["control_id"] for c in controls]
    assert catalog_composition(ids) == {
        "controls": 1014,
        "base_controls": 300,
        "enhancements": 714,
    }


def test_baseline_allocation_is_genuinely_not_in_the_catalog() -> None:
    """The roadmap's premise, disproved where it will be noticed if it changes.

    §3.4 claimed baseline scoping "costs almost nothing" because the OSCAL
    catalog is "already on disk". It does not carry the allocation: ``impact`` is
    empty and ``profile`` is null for every control. If a future catalog build
    ever does populate them, this test fails and the whole Step 16 detour can be
    deleted — which is the outcome worth being told about.
    """
    controls = json.loads(NIST_CATALOG.read_text(encoding=FILE_ENCODING))["controls"]
    assert controls, "catalog is empty; build it with scripts/build_catalog.py"
    assert all(c.get("impact", "") == "" for c in controls)
    assert all(c.get("profile") is None for c in controls)
