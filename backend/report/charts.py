"""Report charts — ReportLab ``Drawing`` objects on the frozen palette.

``render.py``'s docstring has always said "charts arrive as Drawing objects from
charts.py". This is that module; until now it did not exist, which is why the
renderer imported ``GAUGE_BANDS`` and ``FRAMEWORK_COLORS`` and used neither, and
why the per-device report was a wall of tables.

Two decisions shape everything here.

**Every chart ships with its own table.** :class:`Chart` carries the drawing *and*
the rows it was drawn from, so the renderer cannot lay out a chart whose numbers
disagree with the table beside it — the two come from one object. This is the
frozen visual system's "table-view twin" requirement (§23.3), and in a PDF it is
not optional: a chart is inaccessible to a screen reader and unreadable in
grayscale, so the table is what makes the document usable rather than decorative.

**The shapes are drawn by hand, not delegated to ``barcharts``.** The frozen spec
constrains bar thickness, the rounded data-end, gridline weight and gridline style,
and ReportLab's chart classes expose none of those — ``bars[i]`` has no corner
radius, and the axis classes rescale in ways that would silently violate the cap.
Hand-drawn primitives are also deterministic, which the golden-file report tests
depend on: ``VerticalBarChart`` picks tick intervals from the data, so adding one
finding could shift every gridline and change the PDF bytes.

Units are PostScript points, and the spec's pixel limits are converted at the
CSS reference 96 dpi (1 px = 0.75 pt): the 24 px bar cap becomes 18 pt, the 4 px
rounded end 3 pt, and the 8 px marker minimum 6 pt.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from math import cos, radians, sin

from reportlab.graphics.shapes import Circle, Drawing, Group, Line, Path, String, Wedge
from reportlab.lib.colors import HexColor

from backend.report.palette import (
    FRAMEWORK_COLORS,
    GAUGE_BANDS,
    HEATMAP_COLORS,
    RESULT_COLORS,
    SEVERITY_COLORS,
    TREND_COLORS,
)

# ── Geometry, from the frozen visual system (§23.4) ───────────────────

#: Maximum bar thickness. The spec says 24 px; at the CSS reference 96 dpi that
#: is 18 pt. A cap rather than a target: with few categories the bars would
#: otherwise grow into blocks, which reads as area rather than length.
BAR_CAP_PT = 18.0

#: Radius of the rounded data-end. 4 px → 3 pt. Only the value end is rounded;
#: the baseline end stays square so the bar's origin is unambiguous.
BAR_ROUND_PT = 3.0

#: Gridlines are hairline and **solid**. Dashed gridlines compete with dashed
#: data lines, and at hairline weight a dash pattern renders as noise.
GRID_WIDTH_PT = 0.4

#: Data lines are 2 px → 1.5 pt, markers at least 8 px → 6 pt diameter.
LINE_WIDTH_PT = 1.5
MARKER_DIAMETER_PT = 6.0

#: Type sizes. Small, because these live inside a document that has its own
#: typography; the chart must not shout over the prose around it.
LABEL_SIZE = 7.0
VALUE_SIZE = 7.0
FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"

#: Ink for axes, labels and the gauge needle. Not pure black: the palette's
#: surfaces are off-white, and pure black on off-white is harsher than the rest
#: of the document's type.
INK = "#26251f"
MUTED = "#6b6a63"

#: Severity is an ordinal ramp with three named stops, and ``unknown`` is
#: deliberately not one of them — an unrated control must not read as low risk.
#: It takes the ``unknown`` *result* colour so the same "we do not know" idea is
#: the same colour everywhere in the product.
_UNKNOWN_SEVERITY_COLOR = RESULT_COLORS["unknown"]

#: Severity, worst first: the reader's question is "how bad is the worst of it",
#: so the answer belongs at the top of the axis.
SEVERITY_ORDER = ("high", "medium", "low", "unknown")

#: Framework order is fixed and never cycled, so a colour means one framework
#: across every chart in every report.
FRAMEWORK_ORDER = ("CIS", "NIST_800_53", "DISA_STIG", "ISO_27001")

#: The two results a stacked compliance bar is about. The other seven XCCDF
#: values are not failures and not successes; folding them in either direction
#: would be the "absence of evidence renders as PASS" mistake, so they get their
#: own chart instead.
_SCORED = ("pass", "fail")


@dataclass(frozen=True)
class Chart:
    """A drawing and the table that says the same thing.

    Attributes:
        drawing: The ReportLab flowable-compatible ``Drawing``.
        title: Heading for the block.
        caption: One sentence stating what the chart shows, including the
            denominator. A chart without its denominator invites the reader to
            supply one.
        headers: Column headers for the twin table.
        rows: The exact values drawn, as display strings.
        note: Optional qualification — what is excluded, and why.
    """

    drawing: Drawing
    title: str
    caption: str
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    note: str = ""


def _hex(value: str) -> HexColor:
    return HexColor(value)


def _label(
    text: str,
    x: float,
    y: float,
    *,
    size: float = LABEL_SIZE,
    anchor: str = "start",
    colour: str = INK,
    bold: bool = False,
) -> String:
    label = String(x, y, text, fontSize=size, fillColor=_hex(colour))
    label.fontName = FONT_BOLD if bold else FONT
    label.textAnchor = anchor
    return label


def _rounded_bar(
    x: float,
    y: float,
    length: float,
    thickness: float,
    colour: str,
    *,
    horizontal: bool = True,
) -> Path:
    """One bar: square at the baseline, rounded at the value end.

    The asymmetry is the point. A bar rounded at both ends reads as a pill —
    a floating quantity with no origin — and the reader loses the baseline the
    length is measured from. Rounding only the data end keeps the origin crisp
    while softening the edge the eye actually lands on.

    Short bars are the awkward case: a 2 pt bar cannot carry a 3 pt radius. The
    radius is clamped to half the length, so a very small value degrades to a
    semicircular nub rather than an inverted curve.
    """
    radius = min(BAR_ROUND_PT, abs(length) / 2.0, thickness / 2.0)
    path = Path(fillColor=_hex(colour), strokeColor=None, strokeWidth=0)

    if horizontal:
        end = x + length
        path.moveTo(x, y)
        path.lineTo(end - radius, y)
        # Quarter-circle corners. Two quadratic-ish curves via curveTo with the
        # standard circular control-point offset (kappa ≈ 0.5523).
        k = radius * 0.5523
        path.curveTo(end - radius + k, y, end, y + radius - k, end, y + radius)
        path.lineTo(end, y + thickness - radius)
        path.curveTo(
            end,
            y + thickness - radius + k,
            end - radius + k,
            y + thickness,
            end - radius,
            y + thickness,
        )
        path.lineTo(x, y + thickness)
    else:
        top = y + length
        k = radius * 0.5523
        path.moveTo(x, y)
        path.lineTo(x, top - radius)
        path.curveTo(x, top - radius + k, x + radius - k, top, x + radius, top)
        path.lineTo(x + thickness - radius, top)
        path.curveTo(
            x + thickness - radius + k,
            top,
            x + thickness,
            top - radius + k,
            x + thickness,
            top - radius,
        )
        path.lineTo(x + thickness, y)
    path.closePath()
    return path


def _gridlines(
    group: Group,
    *,
    x: float,
    y: float,
    width: float,
    height: float,
    divisions: int,
    maximum: float,
    horizontal: bool = True,
) -> None:
    """Hairline solid gridlines with numeric labels, drawn behind the data."""
    if maximum <= 0:
        return
    for step in range(divisions + 1):
        fraction = step / divisions
        value = maximum * fraction
        if horizontal:
            gx = x + width * fraction
            group.add(
                Line(gx, y, gx, y + height, strokeColor=_hex(MUTED),
                     strokeWidth=GRID_WIDTH_PT, strokeOpacity=0.35)
            )
            group.add(_label(_tick(value), gx, y - 9, anchor="middle", colour=MUTED))
        else:
            gy = y + height * fraction
            group.add(
                Line(x, gy, x + width, gy, strokeColor=_hex(MUTED),
                     strokeWidth=GRID_WIDTH_PT, strokeOpacity=0.35)
            )
            group.add(_label(_tick(value), x - 4, gy - 2.5, anchor="end", colour=MUTED))


def _tick(value: float) -> str:
    """Tick labels: integers stay integers. ``2.0 controls`` is a fiction."""
    return str(round(value)) if abs(value - round(value)) < 0.05 else f"{value:.1f}"


def _nice_maximum(value: float) -> float:
    """Round an axis maximum up to something a reader can divide by four.

    Deliberately a pure function of the maximum and nothing else: an axis chosen
    from the full data set would move when one finding is added, and every
    gridline in the PDF would shift. The golden-file report test would then fail
    on any content change, which makes it useless as a regression test.
    """
    if value <= 0:
        return 4.0
    for step in (4, 8, 12, 20, 40, 80, 120, 200, 400, 800, 2000, 4000):
        if value <= step:
            return float(step)
    return float(int(value / 1000 + 1) * 1000)


# ── 1. Compliance-score gauge (§23.2) ─────────────────────────────────

#: What each :data:`~backend.report.palette.GAUGE_BANDS` interval is called.
#: Keyed by the band's lower bound, so the wording cannot drift out of step with
#: the frozen thresholds. These are PRAMAN's own presentation bands, not a
#: publisher rating — CIS and DISA grade individual controls, not devices — and
#: the chart's note says so, because a reader who mistakes "at target" for
#: "certified" has been misled by the picture.
GAUGE_BAND_NAMES = {
    0: "needs remediation",
    50: "below target",
    75: "approaching target",
    90: "at target",
}


def _gauge_band(score: float) -> tuple[int, int, str]:
    """The single band a score belongs to, as ``(low, high, colour)``.

    Half-open on the upper edge with the top band closed, because the bands as
    written overlap at their endpoints: 50 satisfies both ``0..50`` and
    ``50..75``. Lighting up two bands at once is worst exactly where it matters
    most — a score sitting on a threshold is the case a reader most needs
    resolved, and the first version of this chart rendered it as belonging to
    both.
    """
    for low, high, colour in GAUGE_BANDS:
        if low <= score < high:
            return int(low), int(high), colour
    low, high, colour = GAUGE_BANDS[-1]
    return int(low), int(high), colour


def compliance_gauge(
    score: float,
    *,
    passes: int,
    fails: int,
    theme: str = "light",
    width: float = 200.0,
) -> Chart:
    """The PRAMAN compliance score, as a banded semicircular gauge.

    Args:
        score: ``pass / (pass + fail) * 100``, over selected and applicable
            controls only. The denominator matters more than the number: a 100 %
            score over four automated controls is not a compliant device, and the
            caption says so.
        passes: Numerator, printed under the dial.
        fails: The rest of the denominator.
        theme: ``light`` or ``dark``.
        width: Drawing width in points.

    Returns:
        A :class:`Chart`. The gauge is the one place the "don't chart a single
        number" rule is deliberately broken, because the bands carry information
        the number does not: 74 and 76 differ by two points and land in different
        risk bands, and the reader needs to see which side of the line they are on.
    """
    height = width * 0.62
    drawing = Drawing(width, height)
    group = Group()

    cx, cy = width / 2.0, height * 0.30
    outer = width * 0.42
    inner = outer * 0.66
    clamped = max(0.0, min(100.0, float(score)))
    # An empty denominator is not a score of zero. `score_from_counts` must return
    # a float and returns 0.0 here, which on a dial puts the needle hard left in
    # the red band under the word "critical" -- a signed PDF asserting that a
    # device failed everything, when in fact nothing was decided about it. The
    # case arises whenever a framework has no benchmark for the platform (CIS has
    # none for Arista EOS), so it is reachable from a normal audit, not an edge
    # case. Unscored draws the bands with no needle and no number.
    unscored = passes + fails == 0

    # Bands. Angles run 180 degrees (score 0, left) to 0 (score 100, right), so
    # a score maps to `180 - score * 1.8`.
    active_band = _gauge_band(clamped)
    for low, high, colour in GAUGE_BANDS:
        band = Wedge(
            cx, cy, outer,
            180.0 - high * 1.8,
            180.0 - low * 1.8,
            annular=True,
            radius1=inner,
        )
        band.fillColor = _hex(colour)
        band.strokeColor = None
        # Unreached bands are held back so the eye lands on the one the score is
        # in, without hiding where the other thresholds sit. With nothing scored
        # there is no band to land on, so all of them stay held back equally.
        band.fillOpacity = (
            0.22 if unscored or (low, high) != active_band[:2] else 1.0
        )
        group.add(band)

    # Needle. Drawn as a line plus a hub rather than a filled triangle: at this
    # size a triangle's own width becomes a couple of score points of ambiguity.
    if not unscored:
        angle = radians(180.0 - clamped * 1.8)
        tip = outer * 1.03
        group.add(
            Line(
                cx + inner * 0.55 * cos(angle),
                cy + inner * 0.55 * sin(angle),
                cx + tip * cos(angle),
                cy + tip * sin(angle),
                strokeColor=_hex(INK),
                strokeWidth=LINE_WIDTH_PT,
                strokeLineCap=1,
            )
        )
        group.add(Circle(cx, cy, 2.6, fillColor=_hex(INK), strokeColor=None))

    band_name = "not scored" if unscored else GAUGE_BAND_NAMES[active_band[0]]
    group.add(
        _label(
            "—" if unscored else f"{clamped:.1f}%",
            cx, cy + outer * 0.30, size=17, anchor="middle", bold=True,
            colour=MUTED if unscored else INK,
        )
    )
    # The band, in words, next to the number. Colour alone never carries the
    # message: this report is printed, photocopied and read by people who do not
    # distinguish the red band from the green one.
    group.add(_label(band_name, cx, cy + outer * 0.30 - 11,
                     anchor="middle",
                     colour=MUTED if unscored else active_band[2], bold=True))
    group.add(_label("no control carried a verdict" if unscored
                     else f"{passes} of {passes + fails} scored controls pass",
                     cx, cy - 12, anchor="middle", colour=MUTED))
    # Band edges, so the reader can place the needle without a legend.
    for value in (0, 50, 75, 90, 100):
        a = radians(180.0 - value * 1.8)
        group.add(_label(str(value),
                         cx + (outer + 8) * cos(a),
                         cy + (outer + 6) * sin(a),
                         anchor="middle", colour=MUTED))

    drawing.add(group)

    return Chart(
        drawing=drawing,
        title="Compliance score",
        caption=(
            "No control carried a verdict, so there is no score. This is not a "
            "score of zero: nothing was measured."
            if unscored
            else f"{clamped:.1f}% ({band_name}) — {passes} pass, {fails} fail across "
            f"{passes + fails} scored controls."
        ),
        headers=("Measure", "Value"),
        rows=(
            ("Score", "—" if unscored else f"{clamped:.1f}%"),
            (
                "Band",
                "not scored" if unscored
                else f"{band_name} ({active_band[0]}-{active_band[1]}%)",
            ),
            ("Pass", str(passes)),
            ("Fail", str(fails)),
            ("Scored controls", str(passes + fails)),
        ),
        note=(
            "Scored controls are those selected for this device and applicable "
            "to it. Controls with no automated check are counted as notchecked "
            "and excluded from both numerator and denominator, so the score "
            "never improves by failing to look. The bands are PRAMAN's own "
            "presentation thresholds, not a publisher grade: CIS and DISA rate "
            "individual controls, and neither certifies a device by score."
        ),
    )


# ── 2. Pass/fail by framework — stacked bar (§23.2) ───────────────────


def framework_stacked_bars(
    counts: dict[str, dict[str, int]],
    *,
    theme: str = "light",
    width: float = 250.0,
) -> Chart | None:
    """Pass and fail per framework, stacked so the bar length is the total.

    Args:
        counts: ``{framework: {result: count}}``, as the summary provides it.
        theme: ``light`` or ``dark``.
        width: Drawing width in points.

    Returns:
        A :class:`Chart`, or ``None`` when a single framework has any scored
        controls — one stacked bar is a table with extra steps.

    Stacked rather than grouped because the question is "what proportion of this
    framework passes", and a shared baseline answers proportion better than two
    bars the reader has to divide. Four frameworks in a stacked bar is the one
    arrangement R11.3 recorded as passing the colourblind check; the same four on
    a radar or scatter failed, which is why neither appears anywhere.
    """
    present = [
        name for name in FRAMEWORK_ORDER
        if sum(counts.get(name, {}).get(result, 0) for result in _SCORED) > 0
    ]
    if len(present) < 2:
        return None

    palette = FRAMEWORK_COLORS.get(theme, FRAMEWORK_COLORS["light"])
    totals = {
        name: sum(counts.get(name, {}).get(result, 0) for result in _SCORED)
        for name in present
    }
    maximum = _nice_maximum(max(totals.values()))

    left, right = 78.0, 18.0
    plot_width = width - left - right
    thickness = min(BAR_CAP_PT, 100.0 / len(present))
    row_pitch = thickness + 10.0
    plot_height = row_pitch * len(present)
    height = plot_height + 34.0
    baseline = 24.0

    drawing = Drawing(width, height)
    group = Group()
    _gridlines(group, x=left, y=baseline, width=plot_width, height=plot_height,
               divisions=4, maximum=maximum)

    rows: list[tuple[str, ...]] = []
    for index, name in enumerate(reversed(present)):
        y = baseline + index * row_pitch + (row_pitch - thickness) / 2.0
        framework = counts.get(name, {})
        passed = int(framework.get("pass", 0))
        failed = int(framework.get("fail", 0))
        total = passed + failed

        # The pass segment carries the framework's own colour; the fail segment
        # carries the shared fail red. Framework identity and outcome are two
        # different questions, and answering both with the categorical hue would
        # make "red" mean ISO in one bar and failure in the next.
        if passed:
            group.add(_rounded_bar(
                left, y, plot_width * passed / maximum, thickness, palette[name]
            ))
        if failed:
            group.add(_rounded_bar(
                left + plot_width * passed / maximum,
                y,
                plot_width * failed / maximum,
                thickness,
                RESULT_COLORS["fail"],
            ))

        group.add(_label(name.replace("_", " "), left - 6, y + thickness / 2 - 2.4,
                         anchor="end"))
        rate = f"{passed / total * 100:.0f}%" if total else "—"
        group.add(_label(
            f"{passed}/{total}  {rate}",
            left + plot_width * total / maximum + 5,
            y + thickness / 2 - 2.4,
            colour=MUTED,
        ))
        rows.append((name.replace("_", " "), str(passed), str(failed), rate))

    group.add(_label("Scored controls", left + plot_width / 2, 4,
                     anchor="middle", colour=MUTED))
    drawing.add(group)

    return Chart(
        drawing=drawing,
        title="Pass and fail by framework",
        caption=(
            "Bar length is the number of scored controls per framework; the red "
            "segment is the failures."
        ),
        headers=("Framework", "Pass", "Fail", "Pass rate"),
        rows=tuple(reversed(rows)),
        note=(
            "NIST SP 800-53 and ISO 27001 results are projected: a control is "
            "satisfied when every contributing CIS or STIG check passes, and "
            "indeterminate when any contributor is unknown."
        ),
    )


# ── 3. Severity distribution — failures only (§23.2) ──────────────────


def severity_bars(
    counts: dict[str, int],
    *,
    theme: str = "light",
    width: float = 250.0,
) -> Chart | None:
    """How bad the failures are, worst first.

    Args:
        counts: ``{severity: number_of_failures}``. Only failures — a "severity
            distribution" over passing controls describes the benchmark's
            priorities, not the device's risk, and putting the two on one axis
            invites the reader to read a tall low-severity bar as good news.
        theme: ``light`` or ``dark``.
        width: Drawing width in points.

    Returns:
        A :class:`Chart`, or ``None`` when there are no failures at all — the
        honest rendering of zero failures is the sentence "no failures", not an
        empty axis.

    The ramp is single-hue red by ordinal position, which R11.3 recorded as
    passing the colourblind check where a five-colour categorical severity
    palette failed.
    """
    total = sum(int(counts.get(name, 0)) for name in SEVERITY_ORDER)
    if total <= 0:
        return None

    ramp = SEVERITY_COLORS.get(theme, SEVERITY_COLORS["light"])
    maximum = _nice_maximum(max(int(counts.get(n, 0)) for n in SEVERITY_ORDER))

    left, right = 62.0, 34.0
    plot_width = width - left - right
    thickness = BAR_CAP_PT
    row_pitch = thickness + 8.0
    plot_height = row_pitch * len(SEVERITY_ORDER)
    height = plot_height + 34.0
    baseline = 24.0

    drawing = Drawing(width, height)
    group = Group()
    _gridlines(group, x=left, y=baseline, width=plot_width, height=plot_height,
               divisions=4, maximum=maximum)

    rows: list[tuple[str, ...]] = []
    for index, name in enumerate(reversed(SEVERITY_ORDER)):
        value = int(counts.get(name, 0))
        y = baseline + index * row_pitch + (row_pitch - thickness) / 2.0
        colour = ramp.get(name, _UNKNOWN_SEVERITY_COLOR)
        if value:
            group.add(_rounded_bar(
                left, y, plot_width * value / maximum, thickness, colour
            ))
        group.add(_label(name.title(), left - 6, y + thickness / 2 - 2.4, anchor="end"))
        group.add(_label(
            f"{value}  ({value / total * 100:.0f}%)" if value else "0",
            left + plot_width * value / maximum + 5,
            y + thickness / 2 - 2.4,
            colour=MUTED,
        ))
        rows.append((name.title(), str(value),
                     f"{value / total * 100:.0f}%" if value else "0%"))

    group.add(_label("Failed controls", left + plot_width / 2, 4,
                     anchor="middle", colour=MUTED))
    drawing.add(group)

    return Chart(
        drawing=drawing,
        title="Severity of failures",
        caption=f"{total} failing control(s), by the publisher's severity rating.",
        headers=("Severity", "Failures", "Share"),
        rows=tuple(reversed(rows)),
        note=(
            "Unknown is not a low severity: it means the publisher rated the "
            "control and this benchmark did not carry the rating through, so it "
            "needs a human decision rather than a default."
        ),
    )


# ── 4. Result distribution — all nine XCCDF values ────────────────────


def result_distribution(
    counts: dict[str, int],
    *,
    theme: str = "light",
    width: float = 250.0,
) -> Chart | None:
    """Every XCCDF result value that occurred, including the ones that are not verdicts.

    This chart exists because the score hides it. ``pass/(pass+fail)`` says
    nothing about how many controls were never checked, and a device with four
    automated checks and six hundred notchecked controls can post a perfect score.
    Printing the whole distribution is what keeps that from reading as compliance.

    Args:
        counts: ``{result: count}`` over the nine XCCDF values.
        theme: ``light`` or ``dark``.
        width: Drawing width in points.

    Returns:
        A :class:`Chart`, or ``None`` when fewer than two distinct results
        occurred.
    """
    order = (
        "pass", "fail", "error", "unknown", "notchecked",
        "notapplicable", "notselected", "informational", "fixed",
    )
    present = [name for name in order if int(counts.get(name, 0)) > 0]
    if len(present) < 2:
        return None

    total = sum(int(counts.get(name, 0)) for name in present)
    maximum = _nice_maximum(max(int(counts.get(n, 0)) for n in present))

    left, right = 74.0, 40.0
    plot_width = width - left - right
    thickness = min(BAR_CAP_PT, 130.0 / len(present))
    row_pitch = thickness + 6.0
    plot_height = row_pitch * len(present)
    height = plot_height + 34.0
    baseline = 24.0

    drawing = Drawing(width, height)
    group = Group()
    _gridlines(group, x=left, y=baseline, width=plot_width, height=plot_height,
               divisions=4, maximum=maximum)

    rows: list[tuple[str, ...]] = []
    for index, name in enumerate(reversed(present)):
        value = int(counts.get(name, 0))
        y = baseline + index * row_pitch + (row_pitch - thickness) / 2.0
        group.add(_rounded_bar(
            left, y, plot_width * value / maximum, thickness, RESULT_COLORS[name]
        ))
        group.add(_label(name, left - 6, y + thickness / 2 - 2.4, anchor="end"))
        group.add(_label(
            f"{value}  ({value / total * 100:.1f}%)",
            left + plot_width * value / maximum + 5,
            y + thickness / 2 - 2.4,
            colour=MUTED,
        ))
        rows.append((name, str(value), f"{value / total * 100:.1f}%"))

    group.add(_label("Controls", left + plot_width / 2, 4,
                     anchor="middle", colour=MUTED))
    drawing.add(group)

    return Chart(
        drawing=drawing,
        title="All results, including the non-verdicts",
        caption=f"{total} control(s) evaluated for this device.",
        headers=("Result", "Controls", "Share"),
        rows=tuple(reversed(rows)),
        note=(
            "Only pass and fail enter the compliance score. notchecked means no "
            "automated check exists yet; unknown means the check ran and the "
            "evidence was insufficient. Neither is a pass."
        ),
    )


# ── 5. Trend over audits (§23.2) ──────────────────────────────────────


def trend_line(
    points: list[tuple[int, float]],
    *,
    theme: str = "light",
    width: float = 250.0,
) -> Chart | None:
    """Score against ledger sequence number.

    Args:
        points: ``(seq, score)`` pairs. Sequence number, not timestamp: ``seq`` is
            the ledger's own ordering and is gap-free by construction, so a
            missing point is visible as a missing point rather than smoothed over
            by a date axis. Two audits on one afternoon are also two positions on
            this axis and one on a date axis.
        theme: ``light`` or ``dark``.
        width: Drawing width in points.

    Returns:
        A :class:`Chart`, or ``None`` with fewer than two audits — a trend line
        through one point is a claim about a direction nobody has observed.
    """
    ordered = sorted(points, key=lambda item: item[0])
    if len(ordered) < 2:
        return None

    colour = TREND_COLORS.get(theme, TREND_COLORS["light"])
    left, right, top = 34.0, 16.0, 14.0
    plot_width = width - left - right
    plot_height = 86.0
    height = plot_height + 40.0
    baseline = 26.0

    drawing = Drawing(width, height)
    group = Group()
    # Fixed 0-100 axis. An autoscaled score axis makes a two-point improvement
    # look like a transformation, which is the most common way a compliance
    # dashboard misleads its own owner.
    _gridlines(group, x=left, y=baseline, width=plot_width, height=plot_height,
               divisions=4, maximum=100.0, horizontal=False)

    span = max(1, ordered[-1][0] - ordered[0][0])
    coordinates = [
        (
            left + plot_width * (seq - ordered[0][0]) / span,
            baseline + plot_height * max(0.0, min(100.0, score)) / 100.0,
        )
        for seq, score in ordered
    ]
    for (x1, y1), (x2, y2) in pairwise(coordinates):
        group.add(Line(x1, y1, x2, y2, strokeColor=_hex(colour),
                       strokeWidth=LINE_WIDTH_PT, strokeLineCap=1))
    for (x, y), (seq, _score) in zip(coordinates, ordered, strict=True):
        group.add(Circle(x, y, MARKER_DIAMETER_PT / 2.0,
                         fillColor=_hex(colour), strokeColor=_hex("#ffffff"),
                         strokeWidth=0.7))
        group.add(_label(f"#{seq}", x, baseline - 10, anchor="middle", colour=MUTED))

    latest, previous = ordered[-1][1], ordered[-2][1]
    delta = latest - previous
    group.add(_label(
        f"{latest:.1f}%  ({delta:+.1f} vs audit #{ordered[-2][0]})",
        left, baseline + plot_height + top - 8, bold=True,
    ))
    group.add(_label("Audit sequence", left + plot_width / 2, 4,
                     anchor="middle", colour=MUTED))
    drawing.add(group)

    return Chart(
        drawing=drawing,
        title="Score over audits",
        caption=(
            f"{len(ordered)} committed audits, oldest first. Axis fixed at "
            "0-100% so a small change looks small."
        ),
        headers=("Audit", "Score", "Change"),
        rows=tuple(
            (
                f"#{seq}",
                f"{score:.1f}%",
                "—" if index == 0 else f"{score - ordered[index - 1][1]:+.1f}",
            )
            for index, (seq, score) in enumerate(ordered)
        ),
    )


# ── 6. Per-control heatmap (§23.2) ────────────────────────────────────


def control_heatmap(
    rows: list[tuple[str, list[int]]],
    columns: list[str],
    *,
    theme: str = "light",
    width: float = 250.0,
) -> Chart | None:
    """Failure counts as a grid — control families down, devices or audits across.

    Args:
        rows: ``(row_label, values)`` pairs, one per control family.
        columns: Column labels, in the order the values appear.
        theme: ``light`` or ``dark``.
        width: Drawing width in points.

    Returns:
        A :class:`Chart`, or ``None`` when the grid has fewer than two rows or
        two columns — at that size a table is strictly better.

    Bins are a five-stop blue ordinal ramp, and the count is printed in every
    cell. Printing the number is not redundancy: the ramp answers "where should I
    look", the number answers "how much", and only one of those survives a
    photocopier.
    """
    if len(rows) < 2 or len(columns) < 2:
        return None

    ramp = HEATMAP_COLORS.get(theme, HEATMAP_COLORS["light"])
    peak = max((max(values) if values else 0) for _label_text, values in rows)

    left, top = 96.0, 16.0
    cell_width = max(20.0, (width - left - 6.0) / len(columns))
    cell_height = 14.0
    height = cell_height * len(rows) + top + 20.0

    drawing = Drawing(width, height)
    group = Group()

    for column, name in enumerate(columns):
        group.add(_label(name, left + cell_width * (column + 0.5),
                         height - top + 4, anchor="middle", colour=MUTED))

    table_rows: list[tuple[str, ...]] = []
    for index, (name, values) in enumerate(rows):
        y = height - top - cell_height * (index + 1)
        group.add(_label(name, left - 6, y + 4, anchor="end"))
        for column in range(len(columns)):
            value = values[column] if column < len(values) else 0
            x = left + cell_width * column
            if value <= 0:
                # Zero is not the palest blue. A pale-blue "none" competes with a
                # genuine low count; an empty cell with a dash does not.
                group.add(_label("-", x + cell_width / 2, y + 4,
                                 anchor="middle", colour=MUTED))
            else:
                bin_index = min(len(ramp) - 1, int((value - 1) * len(ramp) / max(1, peak)))
                group.add(_rounded_bar(
                    x + 1, y + 1, cell_width - 2, cell_height - 2, ramp[bin_index]
                ))
                # White on the darker half of the ramp, ink on the lighter half.
                group.add(_label(
                    str(value), x + cell_width / 2, y + 4, anchor="middle",
                    colour="#ffffff" if bin_index >= 2 else INK,
                ))
        table_rows.append((name, *[
            str(values[c]) if c < len(values) else "0" for c in range(len(columns))
        ]))

    drawing.add(group)

    return Chart(
        drawing=drawing,
        title="Failures by control family",
        caption=f"Darker is more failures; peak is {peak}. A dash means none.",
        headers=("Control family", *columns),
        rows=tuple(table_rows),
    )
