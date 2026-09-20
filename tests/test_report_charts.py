"""Report charts — the claims the frozen visual system makes, checked against the shapes.

A chart is the one part of a compliance report that can mislead without being
wrong. The numbers can all be correct while the picture says something else: an
autoscaled axis turns a two-point improvement into a transformation, a bar rounded
at both ends loses its baseline, a pale-blue "zero" reads as a small non-zero, and
a score sitting exactly on a risk threshold gets rendered as belonging to two
bands at once. That last one was a real defect in the first version of this module
and is tested by name below.

So these tests do not assert pixel positions — those would break on any layout
tweak and protect nothing. They assert the properties the frozen spec exists to
guarantee:

* **the guards** — a builder returns ``None`` rather than charting a single number;
* **the geometry limits** — bar cap, gridline weight, gridline *style*, marker size;
* **palette fidelity** — every colour traces to ``palette.py``, so a future edit
  cannot introduce a hue that means nothing;
* **the twin table agrees with the drawing**, since the renderer trusts one object
  for both and a disagreement would be invisible in review;
* **determinism**, which the golden-file report test depends on.
"""

from __future__ import annotations

from math import atan2, degrees

import pytest
from reportlab.graphics.shapes import Circle, Drawing, Line, Path, String, Wedge

from backend.report import charts
from backend.report.palette import (
    FRAMEWORK_COLORS,
    GAUGE_BANDS,
    HEATMAP_COLORS,
    RESULT_COLORS,
    SEVERITY_COLORS,
    TREND_COLORS,
)

# ── Representative data, reused so the assertions are comparable ──────

FRAMEWORK_COUNTS = {
    "CIS": {"pass": 52, "fail": 19},
    "DISA_STIG": {"pass": 30, "fail": 5},
    "NIST_800_53": {"pass": 11, "fail": 9},
    "ISO_27001": {"pass": 4, "fail": 2},
}
SEVERITY_COUNTS = {"high": 7, "medium": 9, "low": 3, "unknown": 2}
RESULT_COUNTS = {
    "pass": 52,
    "fail": 19,
    "notchecked": 558,
    "unknown": 3,
    "notapplicable": 12,
}
TREND_POINTS = [(1, 41.0), (2, 55.5), (3, 61.2), (4, 73.4)]
HEATMAP_ROWS = [
    ("1 Management Plane", [7, 4, 0]),
    ("2 Control Plane", [0, 2, 1]),
    ("3 Data Plane", [3, 0, 0]),
]
HEATMAP_COLUMNS = ["core-rtr-01", "core-sw-01", "edge-fw-01"]


def _shapes(chart: charts.Chart) -> list:
    """Flatten the one group every builder wraps its output in."""
    flat: list = []
    for item in chart.drawing.contents:
        flat.extend(getattr(item, "contents", [item]))
    return flat


def _of(chart: charts.Chart, kind: type) -> list:
    return [shape for shape in _shapes(chart) if isinstance(shape, kind)]


def _bar_box(path: Path) -> tuple[float, float]:
    """Width and height of a bar path's bounding box, in points."""
    xs, ys = path.points[0::2], path.points[1::2]
    return max(xs) - min(xs), max(ys) - min(ys)


def _hexes(chart: charts.Chart) -> set[str]:
    """Every colour the chart actually paints, lowercased."""
    found: set[str] = set()
    for shape in _shapes(chart):
        for attribute in ("fillColor", "strokeColor"):
            colour = getattr(shape, attribute, None)
            if colour is not None:
                found.add(colour.hexval().replace("0x", "#").lower())
    return found


def _palette_hexes() -> set[str]:
    """The frozen palette, flattened, plus this module's own ink and paper."""
    values = {charts.INK, charts.MUTED, "#ffffff"}
    for mapping in (FRAMEWORK_COLORS, SEVERITY_COLORS, HEATMAP_COLORS, TREND_COLORS):
        for entry in mapping.values():
            if isinstance(entry, dict):
                values.update(entry.values())
            elif isinstance(entry, (list, tuple)):
                values.update(entry)
            else:
                values.add(entry)
    values.update(RESULT_COLORS.values())
    values.update(colour for _low, _high, colour in GAUGE_BANDS)
    return {value.lower() for value in values}


ALL_BUILDERS = [
    pytest.param(
        lambda: charts.compliance_gauge(73.4, passes=52, fails=19), id="gauge"
    ),
    pytest.param(
        lambda: charts.framework_stacked_bars(FRAMEWORK_COUNTS), id="framework"
    ),
    pytest.param(lambda: charts.severity_bars(SEVERITY_COUNTS), id="severity"),
    pytest.param(lambda: charts.result_distribution(RESULT_COUNTS), id="result"),
    pytest.param(lambda: charts.trend_line(TREND_POINTS), id="trend"),
    pytest.param(
        lambda: charts.control_heatmap(HEATMAP_ROWS, HEATMAP_COLUMNS), id="heatmap"
    ),
]


# ── Every chart, whatever it draws ────────────────────────────────────


@pytest.mark.parametrize("build", ALL_BUILDERS)
def test_a_chart_is_a_drawing_and_a_table(build) -> None:
    """The twin table is not optional, and it is not the renderer's job.

    In a PDF a chart is invisible to a screen reader and worthless in grayscale,
    so the table is what makes the document usable rather than decorative. It
    lives on the same object as the drawing precisely so a renderer cannot ship
    one without the other, or ship a table whose numbers drifted from the picture.
    """
    chart = build()
    assert chart is not None
    assert isinstance(chart.drawing, Drawing)
    assert chart.drawing.width > 0 and chart.drawing.height > 0
    assert chart.title and chart.caption
    assert chart.headers, "a table with no headers is a grid of unlabelled numbers"
    assert chart.rows, "the table must carry the values the chart drew"
    for row in chart.rows:
        assert len(row) == len(chart.headers), f"ragged row {row} vs {chart.headers}"


@pytest.mark.parametrize("build", ALL_BUILDERS)
def test_charts_are_deterministic(build) -> None:
    """Same input, same shapes — what lets a golden-file report test exist.

    ReportLab's own chart classes pick tick intervals from the data, so adding a
    single finding could shift every gridline and change the PDF bytes. Drawing
    by hand is what makes the output a function of the input alone, and this test
    is the reason that choice is worth its extra code.
    """
    first, second = build(), build()
    assert _describe(first) == _describe(second)
    assert first.rows == second.rows
    assert first.caption == second.caption


def _describe(chart: charts.Chart) -> list[tuple]:
    """A comparable summary of the shapes, ignoring object identity."""
    summary = []
    for shape in _shapes(chart):
        summary.append((
            type(shape).__name__,
            tuple(round(value, 4) for value in getattr(shape, "points", ())),
            getattr(shape, "text", None),
            str(getattr(shape, "fillColor", None)),
            round(float(getattr(shape, "fillOpacity", 1.0) or 1.0), 4),
        ))
    return summary


@pytest.mark.parametrize("build", ALL_BUILDERS)
def test_every_colour_traces_to_the_frozen_palette(build) -> None:
    """No invented hues.

    The palette was machine-validated for contrast and colourblind separation
    (R11.3), and a hex typed directly into a builder skips that entirely. It would
    also break the product's one-colour-one-meaning rule: the reader learns that
    a particular red means "fail", and a second, slightly different red teaches
    them it means nothing.
    """
    allowed = _palette_hexes()
    used = _hexes(build())
    assert used <= allowed, f"colours outside the palette: {sorted(used - allowed)}"


@pytest.mark.parametrize("build", ALL_BUILDERS)
def test_bars_never_exceed_the_thickness_cap(build) -> None:
    """24 px, converted at 96 dpi to 18 pt.

    A cap rather than a target. With three categories an uncapped bar grows into a
    block, and the reader starts comparing areas instead of lengths — which is the
    wrong comparison, because only one dimension encodes the value.
    """
    for path in _of(build(), Path):
        _length, thickness = _bar_box(path)
        assert thickness <= charts.BAR_CAP_PT + 0.01, f"{thickness:.2f}pt bar"


@pytest.mark.parametrize("build", ALL_BUILDERS)
def test_no_line_is_heavier_than_the_data_line_weight(build) -> None:
    """One weight limit, no carve-outs — and gridlines must be solid.

    Solid is the load-bearing half. Dashed gridlines compete with dashed data
    lines for the same visual channel, and at hairline weight a dash pattern stops
    reading as a line at all — it reads as printer noise, which is worse than no
    gridline.

    The ceiling catches everything drawn as a stroke, including the gauge needle,
    which was 1.6 pt until this test refused it. There is no case for a pointer
    heavier than the data it points at.
    """
    chart = build()
    for line in _of(chart, Line):
        width = float(line.strokeWidth)
        assert width <= charts.LINE_WIDTH_PT + 0.01, f"{width:.2f}pt line"
        assert not getattr(line, "strokeDashArray", None), "gridlines must be solid"


# ── The guards: don't chart what is one number ────────────────────────


def test_one_framework_is_not_a_stacked_bar() -> None:
    """A single stacked bar is a table with extra steps.

    Comparison is the whole reason to stack, and there is nothing to compare a
    lone bar against — the reader is left estimating a proportion from a length
    when the two numbers would have told them exactly.
    """
    assert charts.framework_stacked_bars({"CIS": {"pass": 52, "fail": 19}}) is None


def test_no_failures_is_a_sentence_not_an_empty_axis() -> None:
    """Zero failures is the best possible result and must not look like a bug.

    An axis with four empty rows reads as a chart that failed to load, which
    invites the reader to distrust the rest of the report. The renderer prints
    the sentence instead.
    """
    assert charts.severity_bars({"high": 0, "medium": 0, "low": 0}) is None
    assert charts.severity_bars({}) is None


def test_one_audit_is_not_a_trend() -> None:
    """A line through one point asserts a direction nobody has observed."""
    assert charts.trend_line([(1, 50.0)]) is None
    assert charts.trend_line([]) is None


def test_one_result_value_is_not_a_distribution() -> None:
    assert charts.result_distribution({"pass": 9}) is None
    assert charts.result_distribution({}) is None


def test_a_degenerate_heatmap_is_refused() -> None:
    """One row or one column is a list, and a list is better as a list."""
    assert charts.control_heatmap([("a", [1]), ("b", [2])], ["only"]) is None
    assert charts.control_heatmap([("a", [1, 2])], ["x", "y"]) is None


# ── The gauge ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, (0, 50)),
        (49.9, (0, 50)),
        (50.0, (50, 75)),
        (74.9, (50, 75)),
        (75.0, (75, 90)),
        (89.9, (75, 90)),
        (90.0, (90, 100)),
        (100.0, (90, 100)),
    ],
)
def test_a_score_on_a_threshold_lands_in_exactly_one_band(
    score: float, expected: tuple[int, int]
) -> None:
    """The defect this parametrisation exists for.

    ``GAUGE_BANDS`` are written with shared endpoints — 50 satisfies both
    ``0..50`` and ``50..75`` — so the first version of this chart lit two bands at
    once. That is worst exactly where it matters most: a score sitting on a
    threshold is the case a reader most needs resolved, and "both" is not an
    answer they can act on.
    """
    chart = charts.compliance_gauge(score, passes=1, fails=1)
    lit = [
        (int(low), int(high))
        for (low, high, _colour), wedge in zip(
            GAUGE_BANDS, _of(chart, Wedge), strict=True
        )
        if wedge.fillOpacity == 1.0
    ]
    assert lit == [expected], f"score {score} lit {lit}"
    assert charts._gauge_band(score)[:2] == expected


def test_the_needle_angle_is_the_score() -> None:
    """The needle is the only part a reader reads positionally.

    Recovering the score back out of the geometry is the assertion, because an
    off-by-a-constant in the angle mapping would still produce a plausible-looking
    dial that was simply wrong — the most dangerous kind of chart bug.
    """
    for score in (0.0, 25.0, 50.0, 73.4, 100.0):
        chart = charts.compliance_gauge(score, passes=1, fails=1)
        needle = _of(chart, Line)[0]
        hub = _of(chart, Circle)[0]
        angle = degrees(atan2(needle.y2 - hub.cy, needle.x2 - hub.cx)) % 360.0
        assert abs((180.0 - angle) / 1.8 - score) < 0.05


def test_the_band_is_written_in_words_as_well_as_colour() -> None:
    """Colour never carries the message on its own.

    This report gets printed, photocopied and read by people who do not separate
    the red band from the green one. If the band is only a hue, they get the
    number and no risk context at all.
    """
    chart = charts.compliance_gauge(62.0, passes=31, fails=19)
    texts = {shape.text for shape in _of(chart, String)}
    assert "below target" in texts
    assert dict(chart.rows)["Band"] == "below target (50-75%)"
    assert "below target" in chart.caption


def test_the_denominator_is_always_stated() -> None:
    """100% over four automated checks is not a compliant device.

    The score's denominator is the difference between a real result and a
    flattering one, so it appears on the dial, in the caption and in the table —
    a reader who sees only the percentage has been given a number without a claim.
    """
    chart = charts.compliance_gauge(100.0, passes=4, fails=0)
    assert "4 of 4 scored controls pass" in {s.text for s in _of(chart, String)}
    assert "across 4 scored controls" in chart.caption
    assert dict(chart.rows)["Scored controls"] == "4"
    assert "notchecked" in chart.note, "the note must say what was excluded"


def test_the_gauge_does_not_claim_a_publisher_grade() -> None:
    """The bands are PRAMAN's presentation, and the note has to admit it.

    CIS and DISA rate individual controls; neither certifies a device by score.
    A gauge reading "at target" beside a CIS logo is exactly how a presentation
    artefact gets mistaken for a certification.
    """
    note = charts.compliance_gauge(95.0, passes=19, fails=1).note.lower()
    assert "presentation threshold" in note
    assert "not a publisher grade" in note


@pytest.mark.parametrize(("score", "shown"), [(140.0, "100.0%"), (-3.0, "0.0%")])
def test_out_of_range_scores_are_clamped(score: float, shown: str) -> None:
    """A needle drawn off the dial is worse than a clamped one.

    Nothing should produce a score outside 0-100, but a projection bug or a
    divide-by-a-stale-denominator could, and the failure mode must stay legible
    rather than becoming a shape pointing into the page margin.
    """
    chart = charts.compliance_gauge(score, passes=7, fails=0)
    assert dict(chart.rows)["Score"] == shown


# ── Framework stacked bars ────────────────────────────────────────────


def test_framework_hue_means_the_framework_and_red_means_failure() -> None:
    """Two questions, two channels.

    The pass segment carries the framework's categorical hue and the fail segment
    carries the shared fail red. If failure were also encoded by hue, red would
    mean ISO 27001 in one bar and failure in the next, and the legend would have
    to explain that away.
    """
    chart = charts.framework_stacked_bars(FRAMEWORK_COUNTS)
    used = _hexes(chart)
    assert RESULT_COLORS["fail"].lower() in used
    for name in FRAMEWORK_COUNTS:
        assert FRAMEWORK_COLORS["light"][name].lower() in used, f"{name} hue missing"


def test_the_stacked_table_matches_the_bars() -> None:
    """One object, so the numbers cannot disagree — verified rather than assumed."""
    chart = charts.framework_stacked_bars(FRAMEWORK_COUNTS)
    table = {row[0]: row for row in chart.rows}
    for name, counts in FRAMEWORK_COUNTS.items():
        row = table[name.replace("_", " ")]
        assert row[1] == str(counts["pass"])
        assert row[2] == str(counts["fail"])
        total = counts["pass"] + counts["fail"]
        assert row[3] == f"{counts['pass'] / total * 100:.0f}%"


def test_frameworks_with_nothing_scored_are_omitted_not_drawn_empty() -> None:
    """A framework with no automated checks has no pass rate to show.

    Drawing it as a zero-length bar says "0% compliant", which is a verdict. The
    truth is that nothing was evaluated, and that belongs in the results
    distribution as notchecked, not here.
    """
    chart = charts.framework_stacked_bars({
        "CIS": {"pass": 52, "fail": 19},
        "DISA_STIG": {"pass": 30, "fail": 5},
        "ISO_27001": {"pass": 0, "fail": 0, "notchecked": 121},
    })
    labels = {shape.text for shape in _of(chart, String)}
    assert "ISO 27001" not in labels
    assert not any(row[0] == "ISO 27001" for row in chart.rows)


def test_projection_is_disclosed() -> None:
    """NIST and ISO results are derived, and the chart must not imply otherwise.

    A reader who thinks PRAMAN checked 1,014 NIST controls directly will
    over-trust the number. The note says the results roll up from CIS and STIG
    contributors, which is also why an unknown contributor makes the parent
    indeterminate rather than passing.
    """
    note = charts.framework_stacked_bars(FRAMEWORK_COUNTS).note.lower()
    assert "projected" in note
    assert "indeterminate" in note


def test_only_pass_and_fail_are_stacked() -> None:
    """The other seven XCCDF values are neither, and folding them would be a verdict.

    Counting notchecked toward the total would depress every pass rate; counting
    it toward passes is the "absence of evidence renders as PASS" mistake the
    architecture forbids outright. So it is excluded here and charted separately.
    """
    with_noise = {
        name: {**counts, "notchecked": 400, "notapplicable": 9, "unknown": 4}
        for name, counts in FRAMEWORK_COUNTS.items()
    }
    assert charts.framework_stacked_bars(with_noise).rows == (
        charts.framework_stacked_bars(FRAMEWORK_COUNTS).rows
    )


# ── Severity ──────────────────────────────────────────────────────────


def test_severity_is_ordered_worst_first() -> None:
    """The reader's question is "how bad is the worst of it"."""
    chart = charts.severity_bars(SEVERITY_COUNTS)
    assert tuple(row[0] for row in chart.rows) == ("High", "Medium", "Low", "Unknown")


def test_unknown_severity_is_not_given_a_low_risk_colour() -> None:
    """An unrated control must not read as a low-risk one.

    ``SEVERITY_COLORS`` deliberately has no ``unknown`` key — that absence is the
    palette telling this module not to place it on the ordinal red ramp. It takes
    the ``unknown`` *result* colour instead, so "we do not know" is one colour
    across the whole product.
    """
    assert "unknown" not in SEVERITY_COLORS["light"], "the palette's own guard"
    used = _hexes(charts.severity_bars({"high": 0, "medium": 0, "low": 0, "unknown": 5}))
    assert RESULT_COLORS["unknown"].lower() in used
    assert SEVERITY_COLORS["light"]["low"].lower() not in used


def test_severity_counts_only_failures() -> None:
    """A severity chart over passing controls describes the benchmark, not the device.

    Worse, on one axis a tall low-severity bar of *passes* reads as good news
    sitting next to bad news. The caption says "failing control(s)" so the
    denominator is unambiguous.
    """
    chart = charts.severity_bars(SEVERITY_COUNTS)
    assert "failing control" in chart.caption
    assert str(sum(SEVERITY_COUNTS.values())) in chart.caption
    assert "not a low severity" in chart.note


def test_severity_shares_sum_to_a_hundred() -> None:
    """Rounded shares that do not add up make a reader doubt the arithmetic."""
    chart = charts.severity_bars({"high": 7, "medium": 9, "low": 3, "unknown": 1})
    total = sum(int(row[2].rstrip("%")) for row in chart.rows)
    assert 99 <= total <= 101, f"shares sum to {total}%"


# ── Result distribution ───────────────────────────────────────────────


def test_the_result_chart_shows_what_the_score_hides() -> None:
    """558 notchecked controls beside a 73% score is the whole point.

    ``pass/(pass+fail)`` says nothing about coverage, so a device with four
    automated checks can post a near-perfect score. This chart is what stops that
    reading as compliance, and the note names both non-verdicts explicitly.
    """
    chart = charts.result_distribution(RESULT_COUNTS)
    rows = {row[0]: row[1] for row in chart.rows}
    assert rows["notchecked"] == "558"
    assert rows["pass"] == "52"
    note = chart.note.lower()
    assert "no automated check exists yet" in note
    assert "neither is a pass" in note


def test_results_appear_in_xccdf_severity_of_meaning_order() -> None:
    """Verdicts first, then the reasons there was no verdict.

    Alphabetical would put ``error`` above ``pass`` and bury ``fail`` in the
    middle, which makes the reader hunt for the two rows they came for.
    """
    chart = charts.result_distribution(RESULT_COUNTS)
    order = [row[0] for row in chart.rows]
    assert order[:2] == ["pass", "fail"]
    assert order.index("unknown") < order.index("notchecked")


def test_results_that_did_not_occur_are_absent() -> None:
    """Nine empty rows for nine XCCDF values is a spec listing, not a result."""
    chart = charts.result_distribution(RESULT_COUNTS)
    assert {row[0] for row in chart.rows} == set(RESULT_COUNTS)


def test_each_result_keeps_its_own_colour() -> None:
    """The nine result colours are a shared vocabulary across PDF and UI."""
    used = _hexes(charts.result_distribution(RESULT_COUNTS))
    for name in RESULT_COUNTS:
        assert RESULT_COLORS[name].lower() in used, f"{name} lost its colour"


# ── Trend ─────────────────────────────────────────────────────────────


def test_the_trend_axis_is_fixed_at_zero_to_a_hundred() -> None:
    """An autoscaled score axis is how a compliance dashboard misleads its owner.

    Scores of 71 and 73 on an autoscaled axis look like a step change. Pinning the
    axis is what makes a small improvement look small — the numbers are identical
    either way, and only one of the two pictures is honest.
    """
    chart = charts.trend_line([(1, 71.0), (2, 73.0)])
    ticks = {shape.text for shape in _of(chart, String)}
    assert {"0", "100"} <= ticks, f"axis ends missing from {sorted(ticks)}"
    assert "0-100%" in chart.caption


def test_the_trend_is_indexed_by_ledger_sequence_not_time() -> None:
    """``seq`` is gap-free by construction; a date axis would smooth over a gap.

    Two audits on one afternoon are two positions on this axis and one on a date
    axis. The sequence numbers are printed so a reader can tie each point back to
    a ledger record and re-verify it.
    """
    chart = charts.trend_line(TREND_POINTS)
    labels = {shape.text for shape in _of(chart, String)}
    assert {"#1", "#2", "#3", "#4"} <= labels
    assert tuple(row[0] for row in chart.rows) == ("#1", "#2", "#3", "#4")


def test_the_trend_reports_the_change_against_the_previous_audit() -> None:
    """The delta is the reader's actual question, so it is not left as arithmetic."""
    chart = charts.trend_line(TREND_POINTS)
    assert chart.rows[0][2] == "—", "the first audit has nothing to compare against"
    assert chart.rows[-1][2] == "+12.2"
    assert "+12.2" in " ".join(shape.text for shape in _of(chart, String))


def test_audits_arriving_out_of_order_are_sorted() -> None:
    """Query order is not ledger order, and a mis-drawn line would show a regression.

    The API's ``ORDER BY`` could change, or a caller could pass a dict's values.
    Sorting by ``seq`` here means the chart cannot invent an improvement or a
    collapse that the ledger does not record.
    """
    scrambled = charts.trend_line([(4, 73.4), (1, 41.0), (3, 61.2), (2, 55.5)])
    assert scrambled.rows == charts.trend_line(TREND_POINTS).rows


def test_markers_are_large_enough_to_hit() -> None:
    """8 px minimum, converted to 6 pt — a marker is also the thing a reader points at."""
    for circle in _of(charts.trend_line(TREND_POINTS), Circle):
        assert circle.r * 2 >= charts.MARKER_DIAMETER_PT - 0.01


# ── Heatmap ───────────────────────────────────────────────────────────


def test_zero_failures_is_a_dash_not_the_palest_colour() -> None:
    """A pale-blue "none" competes with a genuine low count.

    The two cells then differ only by a contrast step the printer may not
    reproduce, and a family with no failures becomes indistinguishable from one
    with a handful. A dash cannot be confused with a quantity.
    """
    chart = charts.control_heatmap(HEATMAP_ROWS, HEATMAP_COLUMNS)
    texts = [shape.text for shape in _of(chart, String)]
    zeros = sum(
        1 for _name, values in HEATMAP_ROWS for value in values if value == 0
    )
    assert texts.count("-") == zeros
    assert "0" not in texts, "zero must not be drawn as a number in a cell"


def test_every_heatmap_cell_prints_its_count() -> None:
    """The ramp says where to look; the number says how much.

    Only one of those survives a photocopier, and an auditor reading a printout
    needs the count. This is the "table-view twin" requirement applied inside the
    chart itself.
    """
    chart = charts.control_heatmap(HEATMAP_ROWS, HEATMAP_COLUMNS)
    texts = [shape.text for shape in _of(chart, String)]
    for _name, values in HEATMAP_ROWS:
        for value in values:
            if value:
                assert str(value) in texts


def test_the_heatmap_table_carries_every_cell() -> None:
    chart = charts.control_heatmap(HEATMAP_ROWS, HEATMAP_COLUMNS)
    assert chart.headers == ("Control family", *HEATMAP_COLUMNS)
    for row, (name, values) in zip(chart.rows, HEATMAP_ROWS, strict=True):
        assert row == (name, *[str(value) for value in values])


def test_a_short_heatmap_row_is_padded_not_crashed() -> None:
    """Ragged input is a plausible accident, and it must not lose the other rows.

    A device added between two audits produces a family with fewer readings than
    columns. Padding renders the missing cells as "none" rather than raising and
    taking the whole report with it.
    """
    chart = charts.control_heatmap(
        [("1 Management Plane", [7]), ("2 Control Plane", [0, 2, 1])], HEATMAP_COLUMNS
    )
    assert chart is not None
    assert chart.rows[0] == ("1 Management Plane", "7", "0", "0")


def test_the_heatmap_states_its_peak() -> None:
    """Without the peak, "darker is more" gives the reader no scale at all."""
    chart = charts.control_heatmap(HEATMAP_ROWS, HEATMAP_COLUMNS)
    assert "peak is 7" in chart.caption
