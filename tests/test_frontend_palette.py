"""Test: the frontend palette must not drift from the backend palette.

`frontend/js/palette.js` names this file in its own docstring as the guard that
makes it a mirror rather than a copy people hope stays in sync. This is that
guard. Three artefacts carry the same colours and are edited by different hands
at different times:

  * ``backend/report/palette.py`` — the source of truth, cited to GLOBAL_RULESET
    R11.2/R11.3, used by the reportlab charts in the signed PDF.
  * ``frontend/js/palette.js``   — the same values for the on-screen SVG charts.
  * ``frontend/app.css``         — the same values again as CSS custom properties,
    for pills, chips and evidence markers.

The failure this prevents is not cosmetic. An operator who reads a green bar on
screen and an amber one in the filed report has been shown two different audits,
and the PDF is the artefact that gets signed. So the test compares values rather
than trusting comments, and it also refuses any hex in the CSS that is not either
a palette value or on an explicitly-justified list — otherwise the drift arrives
as a new colour chosen by taste rather than as an edited one.

Nothing here parses JavaScript in general. It reads `export const NAME = <literal>`
declarations, which is all `palette.js` contains above its four helper functions,
and fails loudly if a declaration it expects has stopped being a plain literal.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path

import pytest

from backend.canonical.findings import Result
from backend.report import palette as backend_palette
from backend.rules.evaluator import DEFAULT_SEVERITY

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PALETTE_JS = PROJECT_ROOT / "frontend" / "js" / "palette.js"
APP_CSS = PROJECT_ROOT / "frontend" / "app.css"


# ── Reading the JavaScript ───────────────────────────────────────────────


def _strip_comments(text: str) -> str:
    """Drop `//` and `/* */` comments.

    Safe here because `palette.js` holds no string containing `//` — every value
    is a `#rrggbb` hex or a bare identifier. A URL or a regex in the file would
    break this, which is why the extraction below asserts on its own output
    instead of quietly returning something plausible.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def _js_literal(name: str, source: str) -> object:
    """Return the value of `export const <name> = <literal>;` as Python data."""
    match = re.search(rf"export const {re.escape(name)}\s*=\s*", source)
    assert match, f"{PALETTE_JS.name} no longer exports `{name}`"

    # Walk to the matching bracket rather than regexing to the next `;`, so a
    # nested object cannot end the match early.
    start = match.end()
    opener = source[start]
    assert opener in "{[", f"`{name}` is not an object or array literal"
    closer = "}" if opener == "{" else "]"
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opener:
            depth += 1
        elif source[index] == closer:
            depth -= 1
            if depth == 0:
                raw = source[start : index + 1]
                break
    else:  # pragma: no cover — a syntax error in palette.js, not a drift
        pytest.fail(f"unbalanced brackets in `{name}`")

    # JS object literal → JSON: single quotes become double, bare keys get
    # quoted, trailing commas go.
    json_text = raw.replace("'", '"')
    json_text = re.sub(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)", r'\1"\2"\3', json_text)
    json_text = re.sub(r",(\s*[}\]])", r"\1", json_text)
    try:
        return json.loads(json_text)
    except json.JSONDecodeError as err:  # pragma: no cover
        pytest.fail(f"could not read `{name}` as a literal: {err}\n{json_text}")


@pytest.fixture(scope="module")
def js() -> dict[str, object]:
    source = _strip_comments(PALETTE_JS.read_text(encoding="utf-8"))
    names = [
        "FRAMEWORK_COLORS",
        "SEVERITY_COLORS",
        "RESULT_COLORS",
        "NODE_STATUS_COLORS",
        "HEATMAP_COLORS",
        "TREND_COLORS",
        "SURFACE_COLORS",
        "GAUGE_BANDS",
        "RESULT_ORDER",
        "SEVERITY_ORDER",
    ]
    return {name: _js_literal(name, source) for name in names}


# ── Reading the CSS ──────────────────────────────────────────────────────


def _css_block(selector: str, css: str) -> dict[str, str]:
    """Return the custom properties declared in one selector's first block."""
    match = re.search(rf"{re.escape(selector)}\s*\{{(.*?)\n\}}", css, flags=re.DOTALL)
    assert match, f"{APP_CSS.name} has no `{selector}` block"
    body = re.sub(r"/\*.*?\*/", "", match.group(1), flags=DOTALL_FLAG)
    return {
        prop.strip(): value.strip()
        for prop, value in re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", body)
    }


DOTALL_FLAG = re.DOTALL


@pytest.fixture(scope="module")
def css() -> str:
    return APP_CSS.read_text(encoding="utf-8")


# ── Backend ↔ palette.js ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "FRAMEWORK_COLORS",
        "SEVERITY_COLORS",
        "RESULT_COLORS",
        "NODE_STATUS_COLORS",
        "HEATMAP_COLORS",
        "TREND_COLORS",
        "SURFACE_COLORS",
    ],
)
def test_palette_tables_match(js: dict[str, object], name: str) -> None:
    """Every shared table is value-identical in both files."""
    backend_value = getattr(backend_palette, name)
    assert js[name] == backend_value, (
        f"{name} has drifted.\n"
        f"  backend/report/palette.py: {backend_value}\n"
        f"  frontend/js/palette.js:    {js[name]}"
    )


def test_gauge_bands_match(js: dict[str, object]) -> None:
    """`GAUGE_BANDS` is tuples in Python and arrays in JS; compare as lists."""
    backend_bands = [list(band) for band in backend_palette.GAUGE_BANDS]
    assert js["GAUGE_BANDS"] == backend_bands


def test_gauge_bands_tile_zero_to_one_hundred(js: dict[str, object]) -> None:
    """The bands must be contiguous and cover the whole range.

    A gap would leave `gaugeBandColor()` falling through to the last band, so a
    score of 74.9 could paint green. The bands are a PRAMAN convention rather
    than a published metric, which makes them easy to edit casually — this is the
    check that an edit stays a partition.
    """
    bands = js["GAUGE_BANDS"]
    assert bands[0][0] == 0
    assert bands[-1][1] == 100
    for lower, upper in itertools.pairwise(bands):
        assert lower[1] == upper[0], f"gap or overlap between {lower} and {upper}"


# ── Invariants the palettes document about themselves ────────────────────


def test_result_colors_cover_every_xccdf_value(js: dict[str, object]) -> None:
    """All nine XCCDF result values have a colour, in both files.

    A missing key is worse than a wrong colour: `resultColor()` folds the unknown
    key to `notchecked` grey, so a new result value would render as "we did not
    look at this" — the one thing it must never be mistaken for.
    """
    enum_values = {member.value for member in Result}
    assert set(backend_palette.RESULT_COLORS) == enum_values
    assert set(js["RESULT_COLORS"]) == enum_values


def test_result_order_is_a_permutation_of_result_colors(js: dict[str, object]) -> None:
    """The legend order must list every value exactly once."""
    order = js["RESULT_ORDER"]
    assert len(order) == len(set(order)), "duplicate in RESULT_ORDER"
    assert set(order) == set(js["RESULT_COLORS"])
    assert order[:2] == ["pass", "fail"], (
        "the two verdicts must lead the legend; a coverage state listed among "
        "them invites a reader to treat it as a third verdict"
    )


def test_severity_has_no_unknown_colour(js: dict[str, object]) -> None:
    """`unknown` severity is the absence of a rating, not a fourth rung.

    Both files say so in a comment. Giving it a stop on the red ordinal ramp
    would render "nobody rated this control" as a severity an auditor could cite.
    """
    for theme in ("light", "dark"):
        assert DEFAULT_SEVERITY not in backend_palette.SEVERITY_COLORS[theme]
        assert DEFAULT_SEVERITY not in js["SEVERITY_COLORS"][theme]
    assert DEFAULT_SEVERITY in js["SEVERITY_ORDER"], (
        "the ordering list still has to place `unknown` somewhere, and last is "
        "where the remediation API sorts it"
    )


def test_severity_order_matches_the_evaluator_vocabulary(js: dict[str, object]) -> None:
    """Worst-first, and no severity the evaluator cannot emit."""
    rated = set(backend_palette.SEVERITY_COLORS["light"])
    assert js["SEVERITY_ORDER"] == ["high", "medium", "low", DEFAULT_SEVERITY]
    assert set(js["SEVERITY_ORDER"]) - {DEFAULT_SEVERITY} == rated


def test_node_status_colours_are_reserved(js: dict[str, object]) -> None:
    """R11.5 reserves the three status hues; they must not be a framework hue.

    The topology map paints a node red for "at least one high-severity fail". If
    red were also a categorical framework colour, a legend elsewhere on the page
    would teach the reader the wrong meaning for it.
    """
    status = set(js["NODE_STATUS_COLORS"].values())
    for theme in ("light", "dark"):
        frameworks = set(js["FRAMEWORK_COLORS"][theme].values())
        overlap = status & frameworks
        # DISA STIG green and `fixed` green are the same hue by design, so only
        # the amber and red status colours are checked for collision.
        assert not (overlap - {"#1baf7a", "#199e70"}), (
            f"status colour reused as a {theme} framework colour: {overlap}"
        )


# ── palette.py ↔ app.css ─────────────────────────────────────────────────


def test_css_result_variables_match_the_palette(css: str) -> None:
    """`--c-pass` … `--c-informational` are the nine RESULT_COLORS."""
    root = _css_block(":root", css)
    for result, hex_value in backend_palette.RESULT_COLORS.items():
        prop = f"--c-{result}"
        assert prop in root, f"{APP_CSS.name} does not declare {prop}"
        assert root[prop].lower() == hex_value.lower(), (
            f"{prop} is {root[prop]}, palette.py says {hex_value}"
        )


def test_css_result_variables_are_theme_independent(css: str) -> None:
    """A verdict colour that shifts with the theme is one an auditor cannot cite.

    Both palettes state that the nine result colours are surface-independent. The
    way that breaks in CSS is a well-meant override in the dark block, so this
    asserts the dark block does not redeclare any of them.
    """
    dark = _css_block('[data-theme="dark"]', css)
    redeclared = [f"--c-{result}" for result in backend_palette.RESULT_COLORS if f"--c-{result}" in dark]
    assert not redeclared, f"dark theme overrides verdict colours: {redeclared}"


def test_css_surface_matches_the_palette(css: str) -> None:
    """The chart surface in the CSS and in the PDF charts is one colour."""
    assert _css_block(":root", css)["--surface"].lower() == (
        backend_palette.SURFACE_COLORS["light"].lower()
    )
    assert _css_block('[data-theme="dark"]', css)["--surface"].lower() == (
        backend_palette.SURFACE_COLORS["dark"].lower()
    )


def _palette_hexes() -> set[str]:
    """Every hex the frozen palette publishes, lowercased."""
    found: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, str):
            if value.startswith("#"):
                found.add(value.lower())
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    for name in dir(backend_palette):
        if name.isupper():
            walk(getattr(backend_palette, name))
    return found


# The neutral ladder. GLOBAL_RULESET R11 fixes these, but `palette.py` has no
# reason to export them — reportlab draws on a white page and never needs an ink
# or a raised surface. They are listed here so that a *new* colour in the CSS is
# a test failure rather than a silent addition, which is the whole point of a
# frozen palette.
NEUTRALS = {
    # Light
    "#ffffff",  # --surface-raised, --accent-ink
    "#f4f3ef",  # --surface-sunken
    "#0b0b0b",  # --ink
    "#55534d",  # --ink-dim
    "#c9c7bd",  # --grid-strong
    "#e1e0d9",  # --grid  (also RESULT_COLORS.notselected)
    # Dark
    "#232322",  # --surface-raised
    "#131312",  # --surface-sunken
    "#b4b2ab",  # --ink-dim
    "#8a8880",  # --ink-faint
    "#2c2c2a",  # --grid
    "#40403c",  # --grid-strong
    "#08131f",  # --accent-ink, dark
    # @media print only: the print sheet forces a white page and black ink
    # regardless of theme, and greys its borders so a photocopy stays legible.
    "#fff",
    "#000",
    "#999",
}


def test_css_introduces_no_unlisted_colour(css: str) -> None:
    """Every hex in the stylesheet is a palette value or a listed neutral.

    This is the check that catches drift arriving as an addition. Picking a nicer
    red for one badge does not break any equality assertion above — it just
    quietly puts a second red on the page.
    """
    used = {hex_value.lower() for hex_value in re.findall(r"#[0-9a-fA-F]{3,8}\b", css)}
    unlisted = sorted(used - _palette_hexes() - NEUTRALS)
    assert not unlisted, (
        "app.css uses colours that are in neither backend/report/palette.py nor "
        f"the documented neutral ladder: {unlisted}. Add the value to palette.py "
        "if it is a real palette entry, or to NEUTRALS in this test with the "
        "custom property it serves."
    )
