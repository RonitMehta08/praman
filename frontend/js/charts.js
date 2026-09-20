/**
 * The §23.2 chart set, as inline SVG.
 *
 * These are the same charts the PDF renders, drawn from the same palette and
 * under the same frozen rules (§23.1): bars no thicker than 24px with a 4px
 * rounded data-end, 2px lines, markers at least 8px, hairline solid gridlines,
 * and a table view beside every chart. The rules are frozen because they were
 * validated once; re-deciding them per-chart is how a report ends up with six
 * different bar widths.
 *
 * Two rules do real work here and are worth naming. **Every chart has a table
 * twin** — not for decoration but because a chart is unreadable to a screen
 * reader and unquotable in an email, and an auditor needs the number, not the
 * shape. **Nothing that is one number gets charted**; the gauge is the sanctioned
 * exception because a gauge is a position on a scale, which is exactly the thing
 * a bare number fails to communicate.
 *
 * No SVG here is built from a template string. It all goes through `dom.js`, so a
 * hostname containing `</svg>` cannot break out of an attribute.
 */

import { svg, el, table, details, num, pct } from './dom.js';
import {
  RESULT_ORDER,
  SEVERITY_ORDER,
  resultColor,
  severityColor,
  frameworkColor,
  heatmapRamp,
  trendColor,
  gaugeBandColor,
  GAUGE_BANDS,
  NODE_STATUS_COLORS,
  isDark,
} from './palette.js';

/** CSS pixels to SVG user units. The frozen rules are stated in px at 96 dpi and
 * the PDF converts them at 0.75 pt/px; on screen 1 unit is 1 px, so the numbers
 * carry across unchanged. */
const BAR_MAX = 24;
const BAR_RADIUS = 4;
const LINE_WIDTH = 2;
const MARKER_MIN = 8;

function gridColor() {
  return isDark() ? '#2c2c2a' : '#e1e0d9';
}

function inkColor() {
  return isDark() ? '#ffffff' : '#0b0b0b';
}

function mutedInk() {
  return isDark() ? '#a8a7a1' : '#5e5c57';
}

/**
 * Wrap a chart and its table twin in one figure.
 *
 * The twin is a `<details>` rather than always-visible so the page stays scannable,
 * but it is present in the DOM either way, which is what matters for find-in-page
 * and for assistive technology.
 */
function figure(title, subtitle, chartNode, twin, opts = {}) {
  return el(
    'figure',
    { class: `chart ${opts.class || ''}`.trim() },
    el(
      'figcaption',
      { class: 'chart-caption' },
      el('span', { class: 'chart-title', text: title }),
      subtitle ? el('span', { class: 'chart-subtitle', text: subtitle }) : null
    ),
    chartNode,
    opts.legend || null,
    twin ? details('Table view', twin, { class: 'chart-twin' }) : null
  );
}

/** A legend. Colour is never the only channel (R11.4) — each swatch is labelled. */
function legend(entries) {
  return el(
    'ul',
    { class: 'chart-legend' },
    ...entries.map(([label, color, count]) =>
      el(
        'li',
        {},
        el('span', { class: 'legend-swatch', style: { '--swatch': color }, 'aria-hidden': 'true' }),
        el('span', { class: 'legend-label', text: label }),
        count === undefined ? null : el('span', { class: 'legend-count', text: num(count) })
      )
    )
  );
}

function root(width, height, label) {
  return svg('svg', {
    class: 'chart-svg',
    viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: 'xMidYMid meet',
    role: 'img',
    'aria-label': label,
  });
}

/** Floor an SVG's rendered width at its natural width, so it scrolls, not shrinks.
 *
 * `.chart-svg` is `width: 100%`, which scales the viewBox to the card. That is
 * right for a chart with a fixed column count and wrong for one whose width grows
 * with the data, because scaling shrinks the axis labels along with everything
 * else until they are unreadable. `min-width` leaves the fits-in-the-card case
 * untouched and makes the overflow case overflow, which is what the enclosing
 * `.chart-scroll` is there to handle.
 */
function withMinWidth(node, width) {
  node.style.minWidth = `${Math.round(width)}px`;
  return node;
}

/** A bar with only the data-end rounded.
 *
 * A fully rounded bar lies about where the value lands — the curve at the baseline
 * reads as a value above zero. Only the growing end gets the radius.
 */
function hBar(x, y, width, height, color, radius = BAR_RADIUS) {
  const r = Math.max(0, Math.min(radius, width, height / 2));
  if (r === 0 || width <= r) {
    return svg('rect', { x, y, width: Math.max(0, width), height, fill: color });
  }
  const right = x + width;
  const bottom = y + height;
  return svg('path', {
    d: `M${x},${y} H${right - r} A${r},${r} 0 0 1 ${right},${y + r} V${bottom - r} A${r},${r} 0 0 1 ${right - r},${bottom} H${x} Z`,
    fill: color,
  });
}

function vBar(x, y, width, height, color, radius = BAR_RADIUS) {
  const r = Math.max(0, Math.min(radius, width / 2, height));
  if (r === 0 || height <= r) {
    return svg('rect', { x, y, width, height: Math.max(0, height), fill: color });
  }
  const bottom = y + height;
  return svg('path', {
    d: `M${x},${bottom} V${y + r} A${r},${r} 0 0 1 ${x + r},${y} H${x + width - r} A${r},${r} 0 0 1 ${x + width},${y + r} V${bottom} Z`,
    fill: color,
  });
}

function textNode(x, y, content, opts = {}) {
  return svg('text', {
    x,
    y,
    fill: opts.fill || inkColor(),
    'font-size': opts.size || 11,
    'font-weight': opts.weight || 400,
    'text-anchor': opts.anchor || 'start',
    'dominant-baseline': opts.baseline || 'middle',
    text: content,
  });
}

// ═════════════════════════════════════════════════════════════════════
// 1. Compliance-score gauge
// ═════════════════════════════════════════════════════════════════════

function polar(cx, cy, radius, degrees) {
  const rad = ((degrees - 180) * Math.PI) / 180;
  return [cx + radius * Math.cos(rad), cy + radius * Math.sin(rad)];
}

function arcPath(cx, cy, radius, from, to) {
  const [x1, y1] = polar(cx, cy, radius, from);
  const [x2, y2] = polar(cx, cy, radius, to);
  const large = to - from > 180 ? 1 : 0;
  return `M${x1},${y1} A${radius},${radius} 0 ${large} 1 ${x2},${y2}`;
}

/**
 * The score, as a position on a banded scale.
 *
 * The subtitle is not optional. This ratio is a PRAMAN convention — pass over
 * pass-plus-fail across automated checks — and no published standard defines a
 * "compliance score". Printing 58.2% next to a CIS logo without saying so invites
 * a reader to quote it as a CIS figure, which would be a fabrication with our name
 * on it. The basis string comes from the API and is rendered verbatim.
 *
 * A zero denominator is rendered as "—", not as 0.0%, and the distinction is the
 * difference between two opposite facts. `score_from_counts` has to return a float
 * so it returns 0.0 when nothing was decided, but "no control was scored" and
 * "every scored control failed" are not the same posture, and 0.0% in 38-point
 * type says the second. An Arista switch audited against CIS is the case that
 * makes it concrete: there is no CIS benchmark for EOS, so nothing is in scope,
 * and a red 0.0% would report a catastrophically non-compliant device where the
 * truth is that this framework has nothing to say about it. `scored_controls` is
 * the field that separates them, which is why it is already on the API response.
 */
export function complianceGauge(score, opts = {}) {
  const value = Math.max(0, Math.min(100, Number(score?.score ?? 0)));
  const scored = Number(score?.scored_controls ?? 0);
  const unscored = scored === 0;
  const W = 320;
  const H = 190;
  const cx = W / 2;
  const cy = 150;
  const radius = 108;
  const thickness = 18;

  const node = root(
    W,
    H,
    unscored
      ? 'No compliance score: no control in this framework was decided for this device'
      : `Compliance score ${value.toFixed(1)} percent`
  );

  // Bands first, at low opacity, so the scale is visible without competing with
  // the value arc drawn over it.
  for (const [low, high, hex] of GAUGE_BANDS) {
    node.appendChild(
      svg('path', {
        d: arcPath(cx, cy, radius, (low / 100) * 180, (high / 100) * 180),
        fill: 'none',
        stroke: hex,
        'stroke-width': thickness,
        opacity: 0.22,
      })
    );
  }

  if (value > 0 && !unscored) {
    node.appendChild(
      svg('path', {
        d: arcPath(cx, cy, radius, 0, (value / 100) * 180),
        fill: 'none',
        stroke: gaugeBandColor(value),
        'stroke-width': thickness,
        'stroke-linecap': 'round',
      })
    );
  }

  node.appendChild(
    textNode(cx, cy - 34, unscored ? '—' : `${value.toFixed(1)}%`, {
      size: 38,
      weight: 700,
      anchor: 'middle',
      fill: unscored ? mutedInk() : undefined,
    })
  );
  node.appendChild(
    textNode(
      cx,
      cy - 6,
      unscored ? 'no control decided' : `${num(score?.passed ?? 0)} of ${num(scored)} decided`,
      {
        size: 11,
        anchor: 'middle',
        fill: mutedInk(),
      }
    )
  );
  node.appendChild(textNode(cx - radius, cy + 18, '0', { size: 10, anchor: 'middle', fill: mutedInk() }));
  node.appendChild(textNode(cx + radius, cy + 18, '100', { size: 10, anchor: 'middle', fill: mutedInk() }));

  const rows = [
    ['Score', unscored ? '—' : `${value.toFixed(1)}%`],
    ['Passed', num(score?.passed ?? 0)],
    ['Failed', num(score?.failed ?? 0)],
    ['Decided (scored)', num(score?.scored_controls ?? 0)],
    ['Not checked', num(score?.notchecked ?? 0)],
    ['Not applicable', num(score?.notapplicable ?? 0)],
    ['Unknown', num(score?.unknown ?? 0)],
    ['Error', num(score?.error ?? 0)],
    ['Controls in scope', num(score?.total_controls ?? 0)],
  ];

  return figure(
    'Compliance score',
    score?.basis || 'A PRAMAN-defined ratio, not a standard metric.',
    node,
    table(['Measure', 'Value'], rows, { class: 'data-table compact' }),
    { class: 'chart-gauge', ...opts }
  );
}

// ═════════════════════════════════════════════════════════════════════
// 2. Pass and fail by framework
// ═════════════════════════════════════════════════════════════════════

/**
 * One stacked bar per framework, segments separated by a 2px surface-coloured gap.
 *
 * The gap is in the frozen rules for a reason that shows up immediately with real
 * data: adjacent green and grey segments of similar length read as one bar without
 * it, and the reader undercounts the passes.
 *
 * `notchecked` is stacked here rather than dropped. On the shipped sample it is
 * 1,391 of 1,462 findings, and a chart that hid it would show a tidy green/red
 * split that implies the estate was fully audited.
 */
export function frameworkStackedBars(findings, opts = {}) {
  const byFramework = new Map();
  for (const finding of findings) {
    const framework = finding.framework || 'Other';
    const result = String(finding.result || 'unknown').toLowerCase();
    if (!byFramework.has(framework)) byFramework.set(framework, new Map());
    const bucket = byFramework.get(framework);
    bucket.set(result, (bucket.get(result) || 0) + 1);
  }

  const frameworks = [...byFramework.keys()].sort();
  if (frameworks.length === 0) return null;

  const present = RESULT_ORDER.filter((result) =>
    frameworks.some((framework) => (byFramework.get(framework).get(result) || 0) > 0)
  );

  const labelW = 116;
  const gutter = 12;
  const rowH = 34;
  const barH = Math.min(BAR_MAX, 22);
  const W = 560;
  const H = frameworks.length * rowH + 26;
  const plotW = W - labelW - gutter - 60;
  const maxTotal = Math.max(
    1,
    ...frameworks.map((framework) => [...byFramework.get(framework).values()].reduce((a, b) => a + b, 0))
  );

  const node = root(W, H, 'Pass and fail by framework');
  const surface = isDark() ? '#1a1a19' : '#fcfcfb';

  frameworks.forEach((framework, index) => {
    const y = index * rowH + 8;
    const counts = byFramework.get(framework);
    const total = [...counts.values()].reduce((a, b) => a + b, 0);

    node.appendChild(
      textNode(labelW - 8, y + barH / 2, framework.replace(/_/g, ' '), { anchor: 'end', weight: 600 })
    );

    let x = labelW + gutter;
    for (const result of present) {
      const count = counts.get(result) || 0;
      if (count === 0) continue;
      const width = (count / maxTotal) * plotW;
      const isLast = present.slice(present.indexOf(result) + 1).every((r) => (counts.get(r) || 0) === 0);
      node.appendChild(
        hBar(x, y, width, barH, resultColor(result), isLast ? BAR_RADIUS : 0)
      );
      // The 2px separator, painted in the surface colour rather than left as a gap
      // so segment order stays unambiguous when two segments share a hue family.
      if (!isLast && width > 2) {
        node.appendChild(
          svg('rect', { x: x + width - 2, y, width: 2, height: barH, fill: surface })
        );
      }
      x += width;
    }

    node.appendChild(
      textNode(labelW + gutter + plotW + 8, y + barH / 2, num(total), { size: 11, fill: mutedInk() })
    );
  });

  const rows = frameworks.map((framework) => {
    const counts = byFramework.get(framework);
    const total = [...counts.values()].reduce((a, b) => a + b, 0);
    const passed = counts.get('pass') || 0;
    const failed = counts.get('fail') || 0;
    const decided = passed + failed;
    return [
      framework.replace(/_/g, ' '),
      num(passed),
      num(failed),
      num(counts.get('notchecked') || 0),
      num(total),
      decided ? pct(passed / decided) : '—',
    ];
  });

  return figure(
    'Pass and fail by framework',
    'Bar length is the share of the largest framework, so widths compare across rows.',
    node,
    table(['Framework', 'Pass', 'Fail', 'Not checked', 'Total', 'Score'], rows, {
      class: 'data-table compact',
    }),
    {
      legend: legend(
        present.map((result) => [
          result,
          resultColor(result),
          frameworks.reduce((sum, f) => sum + (byFramework.get(f).get(result) || 0), 0),
        ])
      ),
      ...opts,
    }
  );
}

// ═════════════════════════════════════════════════════════════════════
// 3. Severity of failures
// ═════════════════════════════════════════════════════════════════════

/**
 * Failing findings by severity, on the ordinal red ramp.
 *
 * Only failures. A severity chart over all findings would be counting the
 * severity ratings of controls that passed, which tells you about the benchmark's
 * composition and nothing about this device's risk.
 */
export function severityBars(findings, opts = {}) {
  const failures = findings.filter((f) => String(f.result || '').toLowerCase() === 'fail');
  const counts = new Map(SEVERITY_ORDER.map((key) => [key, 0]));
  for (const finding of failures) {
    const key = String(finding.severity || 'unknown').toLowerCase();
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const present = SEVERITY_ORDER.filter((key) => counts.get(key) > 0);
  if (present.length === 0) return null;

  const total = failures.length;
  const labelW = 84;
  const rowH = 32;
  const barH = Math.min(BAR_MAX, 20);
  const W = 460;
  const H = present.length * rowH + 16;
  const plotW = W - labelW - 80;
  const maxCount = Math.max(...present.map((key) => counts.get(key)));

  const node = root(W, H, 'Severity of failures');
  present.forEach((key, index) => {
    const y = index * rowH + 8;
    const count = counts.get(key);
    node.appendChild(textNode(labelW - 8, y + barH / 2, key, { anchor: 'end', weight: 600 }));
    node.appendChild(hBar(labelW, y, (count / maxCount) * plotW, barH, severityColor(key)));
    node.appendChild(
      textNode(labelW + (count / maxCount) * plotW + 8, y + barH / 2, `${num(count)}  (${pct(count / total, 0)})`, {
        size: 11,
        fill: mutedInk(),
      })
    );
  });

  const rows = present.map((key) => [key, num(counts.get(key)), pct(counts.get(key) / total)]);

  return figure(
    'Severity of failures',
    `${num(total)} failing ${total === 1 ? 'control' : 'controls'}, worst first.`,
    node,
    table(['Severity', 'Failures', 'Share'], rows, { class: 'data-table compact' }),
    opts
  );
}

// ═════════════════════════════════════════════════════════════════════
// 4. All results, including the non-verdicts
// ═════════════════════════════════════════════════════════════════════

/**
 * Every one of the nine XCCDF result values.
 *
 * This chart exists to make the coverage story impossible to miss. The gauge
 * reports 58.2% over 55 decided controls out of 1,462 findings; without this
 * chart beside it, a reader has no way to see that 95% of the roster was never
 * checked. Tri-state honesty is a rendering requirement, not just a data model
 * one.
 */
export function resultDistribution(summary, opts = {}) {
  const byResult = summary?.by_result || {};
  const present = RESULT_ORDER.filter((key) => Number(byResult[key] || 0) > 0);
  if (present.length === 0) return null;

  const total = present.reduce((sum, key) => sum + Number(byResult[key]), 0);
  const labelW = 118;
  const rowH = 26;
  const barH = Math.min(BAR_MAX, 16);
  const W = 520;
  const H = present.length * rowH + 14;
  const plotW = W - labelW - 96;
  const maxCount = Math.max(...present.map((key) => Number(byResult[key])));

  const node = root(W, H, 'Distribution of all result values');
  present.forEach((key, index) => {
    const y = index * rowH + 6;
    const count = Number(byResult[key]);
    node.appendChild(textNode(labelW - 8, y + barH / 2, key, { anchor: 'end' }));
    node.appendChild(hBar(labelW, y, (count / maxCount) * plotW, barH, resultColor(key)));
    node.appendChild(
      textNode(labelW + (count / maxCount) * plotW + 8, y + barH / 2, num(count), {
        size: 11,
        fill: mutedInk(),
      })
    );
  });

  const rows = present.map((key) => [
    key,
    num(byResult[key]),
    pct(Number(byResult[key]) / total),
    key === 'pass' || key === 'fail' ? 'verdict' : 'not a verdict',
  ]);

  return figure(
    'All results, including the non-verdicts',
    'Only pass and fail are verdicts. The rest record what was not decided, and are excluded from the score.',
    node,
    table(['Result', 'Count', 'Share', 'Kind'], rows, { class: 'data-table compact' }),
    opts
  );
}

// ═════════════════════════════════════════════════════════════════════
// 5. Score over audits
// ═════════════════════════════════════════════════════════════════════

/**
 * One point per committed audit, walking the ledger by `seq`.
 *
 * A single blue series — the frozen rules cap overlapping forms at three series
 * and this has no reason to have more than one. Fewer than two points is not a
 * trend, so it returns null and the caller shows a sentence instead of an
 * axis with a dot on it.
 */
export function trendLine(points, opts = {}) {
  const series = points
    .filter((point) => Number.isFinite(Number(point.score)))
    .sort((a, b) => Number(a.seq) - Number(b.seq));
  if (series.length < 2) return null;

  const W = 560;
  const H = 200;
  const pad = { top: 16, right: 18, bottom: 34, left: 42 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  const node = root(W, H, 'Compliance score over committed audits');
  const grid = gridColor();

  // Gridlines: hairline and solid. Dashed gridlines were tried and read as data.
  for (let tick = 0; tick <= 100; tick += 25) {
    const y = pad.top + plotH - (tick / 100) * plotH;
    node.appendChild(
      svg('line', { x1: pad.left, y1: y, x2: pad.left + plotW, y2: y, stroke: grid, 'stroke-width': 1 })
    );
    node.appendChild(textNode(pad.left - 8, y, String(tick), { size: 10, anchor: 'end', fill: mutedInk() }));
  }

  const xFor = (index) =>
    series.length === 1 ? pad.left + plotW / 2 : pad.left + (index / (series.length - 1)) * plotW;
  const yFor = (score) => pad.top + plotH - (Math.max(0, Math.min(100, Number(score))) / 100) * plotH;

  const color = trendColor();
  node.appendChild(
    svg('polyline', {
      points: series.map((point, index) => `${xFor(index)},${yFor(point.score)}`).join(' '),
      fill: 'none',
      stroke: color,
      'stroke-width': LINE_WIDTH,
      'stroke-linejoin': 'round',
      'stroke-linecap': 'round',
    })
  );

  series.forEach((point, index) => {
    const cx = xFor(index);
    const cy = yFor(point.score);
    const marker = svg('circle', { cx, cy, r: MARKER_MIN / 2, fill: color });
    marker.appendChild(
      svg('title', {
        text: `seq ${point.seq} — ${Number(point.score).toFixed(1)}% (${point.hostname || point.device_id || 'device'})`,
      })
    );
    node.appendChild(marker);
    if (index === 0 || index === series.length - 1 || series.length <= 8) {
      node.appendChild(
        textNode(cx, H - pad.bottom + 14, `#${point.seq}`, { size: 10, anchor: 'middle', fill: mutedInk() })
      );
    }
  });

  const rows = series.map((point) => [
    `#${point.seq}`,
    point.hostname || point.device_id || '—',
    `${Number(point.score).toFixed(1)}%`,
    num(point.passed ?? '—'),
    num(point.failed ?? '—'),
  ]);

  return figure(
    'Score over audits',
    'One point per committed audit, in ledger order.',
    node,
    table(['Seq', 'Device', 'Score', 'Pass', 'Fail'], rows, { class: 'data-table compact' }),
    opts
  );
}

// ═════════════════════════════════════════════════════════════════════
// 6. Per-device heatmap
// ═════════════════════════════════════════════════════════════════════

/** Degrees the heatmap's column headers are rotated by.
 *
 * Named because the geometry below reads it three times — for the transform, for
 * the header height and for the right-hand overhang — and a header band computed
 * against one angle while the text is drawn at another clips silently.
 */
const LABEL_ROTATION = -38;

/**
 * Devices down, control families across, cell darkness = failure density.
 *
 * Light means clean, dark means concentrated failures, on the blue sequential
 * ramp. The one thing a heatmap must not do here is render "no data" and "no
 * failures" identically, so a family with nothing checked gets the hatched
 * treatment rather than the lightest blue.
 */
export function deviceHeatmap(rows, opts = {}) {
  if (!rows.length) return null;
  const families = [...new Set(rows.flatMap((row) => Object.keys(row.families || {})))].sort();
  if (!families.length) return null;

  const labelW = 150;
  const cellW = Math.max(34, Math.min(64, Math.floor(460 / families.length)));
  const cellH = 26;
  const gap = 2;

  // Column headers are rotated, so their length costs both height and width, and
  // a fixed header band clipped anything longer than about fifteen characters —
  // which is why the columns used to be named `1`, `2`, `3`. Measure the longest
  // label instead: 5.4px per character is a good enough estimate for this font at
  // 10px, and the two components of a -38° rotation split it between the axes.
  const RADIANS = (-LABEL_ROTATION * Math.PI) / 180;
  const longest = Math.max(...families.map((family) => family.length)) * 5.4;
  const headerH = Math.min(140, Math.max(58, Math.round(longest * Math.sin(RADIANS)) + 16));
  const overhang = Math.round(longest * Math.cos(RADIANS)) - cellW / 2;
  const W = labelW + families.length * (cellW + gap) + Math.max(8, overhang);
  const H = headerH + rows.length * (cellH + gap) + 8;

  const node = root(W, H, 'Failure density by device and control family');
  const ramp = heatmapRamp();
  const grid = gridColor();

  families.forEach((family, column) => {
    const x = labelW + column * (cellW + gap) + cellW / 2;
    const label = svg('text', {
      x,
      y: headerH - 10,
      fill: mutedInk(),
      'font-size': 10,
      'text-anchor': 'start',
      transform: `rotate(${LABEL_ROTATION} ${x} ${headerH - 10})`,
      text: family,
    });
    node.appendChild(label);
  });

  rows.forEach((row, index) => {
    const y = headerH + index * (cellH + gap);
    node.appendChild(
      textNode(labelW - 8, y + cellH / 2, row.hostname || row.device_id, { anchor: 'end', size: 11 })
    );

    families.forEach((family, column) => {
      const x = labelW + column * (cellW + gap);
      const cell = row.families?.[family];
      const decided = cell ? Number(cell.pass || 0) + Number(cell.fail || 0) : 0;

      if (!cell || decided === 0) {
        // Nothing decided here. Drawn as an outline, not as the palest blue,
        // because the palest blue means "checked, clean".
        node.appendChild(
          svg('rect', {
            x,
            y,
            width: cellW,
            height: cellH,
            fill: 'none',
            stroke: grid,
            'stroke-width': 1,
            rx: 2,
          })
        );
        const empty = svg('rect', { x, y, width: cellW, height: cellH, fill: 'transparent' });
        empty.appendChild(svg('title', { text: `${row.hostname || row.device_id} / ${family}: nothing decided` }));
        node.appendChild(empty);
        return;
      }

      const density = Number(cell.fail || 0) / decided;
      const stop = ramp[Math.min(ramp.length - 1, Math.floor(density * ramp.length))];
      const rect = svg('rect', { x, y, width: cellW, height: cellH, fill: stop, rx: 2 });
      rect.appendChild(
        svg('title', {
          text:
            `${row.hostname || row.device_id} / ${family}: ` +
            `${cell.fail || 0} fail, ${cell.pass || 0} pass (${(density * 100).toFixed(0)}% failing)`,
        })
      );
      node.appendChild(rect);
      node.appendChild(
        textNode(x + cellW / 2, y + cellH / 2, String(cell.fail || 0), {
          size: 10,
          anchor: 'middle',
          fill: density > 0.5 ? '#ffffff' : inkColor(),
        })
      );
    });
  });

  const twin = table(
    ['Device', ...families],
    rows.map((row) => [
      row.hostname || row.device_id,
      ...families.map((family) => {
        const cell = row.families?.[family];
        if (!cell) return '—';
        const decided = Number(cell.pass || 0) + Number(cell.fail || 0);
        return decided === 0 ? '—' : `${cell.fail || 0}/${decided}`;
      }),
    ]),
    { class: 'data-table compact' }
  );

  return figure(
    'Failure density by device and control family',
    'Darker means a larger share of the decided controls in that family failed. An outlined cell means nothing was decided there.',
    // Wrapped so the chart can scroll rather than scale. The family axis is as
    // wide as the estate is heterogeneous — each vendor's benchmark contributes
    // its own sections, because CIS section 3 is the data plane on a Cisco device
    // and High Availability on a Palo Alto one — so a seven-vendor estate produces
    // around thirty columns. Scaling that into a card renders the labels at about
    // 6px; scrolling keeps them legible and keeps every device on the chart.
    el('div', { class: 'chart-scroll' }, withMinWidth(node, W)),
    twin,
    {
      legend: legend([
        ['clean', ramp[0]],
        ['some failures', ramp[Math.floor(ramp.length / 2)]],
        ['mostly failing', ramp[ramp.length - 1]],
      ]),
      ...opts,
    }
  );
}

// ═════════════════════════════════════════════════════════════════════
// 7. Topology violation map
// ═════════════════════════════════════════════════════════════════════

/**
 * Devices as nodes, layer-1 adjacency as edges, node colour = worst verdict.
 *
 * Red means at least one high-severity failure, amber means only low or medium
 * ones, green means every applicable control passed. Those three are reserved
 * status colours and are never reused for a categorical series.
 *
 * The layout is a deterministic layered arrangement rather than a force
 * simulation. Determinism matters more than beauty here: an operator who
 * re-ingests and sees the whole map rearrange cannot tell whether the topology
 * changed or the physics settled differently.
 */
export function topologyMap(nodes, edges, opts = {}) {
  if (!nodes.length) return null;

  const perRow = Math.max(1, Math.ceil(Math.sqrt(nodes.length * 1.6)));
  const cellW = 168;
  const cellH = 96;
  const radius = 22;
  const rowCount = Math.ceil(nodes.length / perRow);
  const W = Math.max(360, perRow * cellW + 40);
  const H = rowCount * cellH + 56;

  const positions = new Map();
  nodes.forEach((node, index) => {
    const row = Math.floor(index / perRow);
    const column = index % perRow;
    const inRow = Math.min(perRow, nodes.length - row * perRow);
    const offset = (W - inRow * cellW) / 2;
    positions.set(node.device_id, [offset + column * cellW + cellW / 2, 34 + row * cellH + cellH / 2]);
  });

  const canvas = root(W, H, 'Topology with per-device compliance status');
  const grid = gridColor();

  for (const edge of edges) {
    const from = positions.get(edge.from);
    const to = positions.get(edge.to);
    if (!from || !to) continue;
    const line = svg('line', {
      x1: from[0],
      y1: from[1],
      x2: to[0],
      y2: to[1],
      stroke: grid,
      'stroke-width': LINE_WIDTH,
    });
    line.appendChild(svg('title', { text: edge.label || `${edge.from} — ${edge.to}` }));
    canvas.appendChild(line);
  }

  for (const node of nodes) {
    const [cx, cy] = positions.get(node.device_id);
    const color = NODE_STATUS_COLORS[node.status] || NODE_STATUS_COLORS.amber;

    const group = svg('g', {
      class: 'topo-node',
      tabindex: '0',
      role: 'button',
      'aria-label': `${node.hostname || node.device_id}: ${node.status} — ${node.high || 0} high, ${node.fail || 0} failing`,
      dataset: { deviceId: node.device_id },
    });
    if (opts.onSelect) {
      group.addEventListener('click', () => opts.onSelect(node));
      group.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          opts.onSelect(node);
        }
      });
    }

    group.appendChild(
      svg('circle', { cx, cy, r: radius, fill: color, stroke: isDark() ? '#1a1a19' : '#fcfcfb', 'stroke-width': 2 })
    );
    // The count inside the node, so the status is legible without relying on hue.
    group.appendChild(
      textNode(cx, cy, String(node.fail || 0), { size: 13, weight: 700, anchor: 'middle', fill: '#ffffff' })
    );
    group.appendChild(
      textNode(cx, cy + radius + 14, node.hostname || node.device_id, {
        size: 10,
        anchor: 'middle',
        fill: inkColor(),
      })
    );
    group.appendChild(
      svg('title', {
        text: `${node.hostname || node.device_id} — ${node.status}: ${node.high || 0} high-severity, ${node.fail || 0} failing of ${node.decided || 0} decided`,
      })
    );
    canvas.appendChild(group);
  }

  const rows = nodes.map((node) => [
    node.hostname || node.device_id,
    node.vendor || '—',
    node.status,
    num(node.high || 0),
    num(node.fail || 0),
    num(node.decided || 0),
    node.neighbours?.length ? node.neighbours.join(', ') : '—',
  ]);

  return figure(
    'Topology and violation map',
    opts.subtitle ||
      (edges.length
        ? 'Edges are inferred adjacency, not discovered from the wire. Click a node for its findings.'
        : 'No adjacency could be inferred from these configurations, so devices are shown unlinked.'),
    canvas,
    table(['Device', 'Vendor', 'Status', 'High', 'Fail', 'Decided', 'Neighbours'], rows, {
      class: 'data-table compact',
    }),
    {
      legend: legend([
        ['all applicable pass', NODE_STATUS_COLORS.green],
        ['low or medium failures', NODE_STATUS_COLORS.amber],
        ['high-severity failure', NODE_STATUS_COLORS.red],
      ]),
      ...opts,
    }
  );
}

// ═════════════════════════════════════════════════════════════════════
// Shared derivations
// ═════════════════════════════════════════════════════════════════════

/** The node status a device's findings imply.
 *
 * Deliberately pessimistic: one high-severity failure makes the node red no
 * matter how many controls passed, because that is the finding that gets someone
 * called at night. */
export function nodeStatus(findings) {
  let fail = 0;
  let high = 0;
  let decided = 0;
  for (const finding of findings) {
    const result = String(finding.result || '').toLowerCase();
    if (result === 'pass' || result === 'fail') decided += 1;
    if (result !== 'fail') continue;
    fail += 1;
    if (String(finding.severity || '').toLowerCase() === 'high') high += 1;
  }
  const status = high > 0 ? 'red' : fail > 0 ? 'amber' : 'green';
  return { status, fail, high, decided };
}

/**
 * What each CIS benchmark's top-level section numbers mean, for the heatmap axis.
 *
 * Keyed by benchmark, not by section number, and that is the whole point. This
 * used to be a flat `{1: 'Management plane', 2: 'Control plane', 3: 'Data plane'}`
 * applied to every CIS finding, which was correct while Cisco IOS was the only
 * mapped benchmark and became false the moment six more shipped: CIS Palo Alto
 * section 3 is High Availability and CIS FortiGate section 1 is DNS and WAN-side
 * service exposure, so a PAN-OS finding was rendering under a column headed "Data
 * plane". The function below already carried the argument against itself — "another
 * framework that happens to number its controls keeps its own prefix, because its
 * section 1 is not CIS's" — and the same sentence applies one level down.
 *
 * Every name is derived from the titles of the controls the shipped catalog
 * actually loaded, not quoted from the benchmark document, so it describes what
 * PRAMAN will put in that column. The four Cisco benchmarks really are structured
 * as the three planes; the other three are not, and are named as they are.
 *
 * A section not in this map keeps its bare number, which is what the whole axis
 * used to look like. An invented name would be worse than a number.
 */
const BENCHMARK_SECTIONS = {
  'CIS Cisco IOS 15': {
    short: 'IOS 15',
    // 38 + 29 + 23 = 90, the benchmark's published count, so every section is named.
    sections: { 1: 'Management plane', 2: 'Control plane', 3: 'Data plane' },
  },
  'CIS Cisco IOS XE 17.x': {
    short: 'IOS XE',
    sections: { 1: 'Management plane', 2: 'Control plane', 3: 'Data plane' },
  },
  'CIS Cisco ASA 9.x': {
    short: 'ASA',
    // §2 mixes OSPF/EIGRP/BGP authentication with untrusted-interface hardening and
    // §3 is inspection, ACLs, DoS and botnet protection, so ASA follows the same
    // three-plane structure as IOS rather than merely reusing its numbers.
    sections: { 1: 'Management plane', 2: 'Control plane', 3: 'Data plane' },
  },
  'CIS Cisco NX-OS': {
    short: 'NX-OS',
    // §2 is a single control, Control Plane Policing. §4 is backup schedules and
    // config-change alerting, which is management but not the management *plane*.
    sections: {
      1: 'Management plane',
      2: 'Control plane',
      3: 'Data plane',
      4: 'Config management',
    },
  },
  'CIS FortiGate 7.4.x': {
    short: 'FortiGate',
    sections: {
      1: 'Network setup',
      2: 'System & GUI',
      3: 'Firewall policies',
      4: 'Security profiles',
      5: 'Security Fabric',
      6: 'VPN',
      7: 'Logging',
    },
  },
  'CIS Juniper OS': {
    short: 'Junos',
    // §1 is lifecycle and physical-security guidance that a config cannot decide,
    // which is most of why this benchmark's coverage is low; the axis says so.
    sections: {
      1: 'Platform lifecycle',
      2: 'Routing Engine filters',
      3: 'Interfaces',
      4: 'Routing protocols',
      5: 'SNMP',
      6: 'System services',
    },
  },
  'CIS Palo Alto Firewall 11': {
    short: 'PAN-OS',
    sections: {
      1: 'Device setup',
      2: 'User-ID',
      3: 'High availability',
      4: 'Content updates',
      5: 'WildFire',
      6: 'Security profiles',
      7: 'Security policies',
      8: 'Decryption',
    },
  },
};

/** The control family a control id belongs to, for the heatmap columns.
 *
 * CIS numbers its controls hierarchically, so the leading component is a real
 * family — but a column headed `1` tells an operator nothing about what is weak
 * on that device, which is the only question this chart exists to answer. The
 * section's meaning depends on the benchmark, so both are read.
 *
 * DISA ids (`V-215832`) carry no hierarchy, so they group under their framework
 * rather than being split into 1,602 singleton columns. Same for NIST and ISO,
 * whose control ids PRAMAN projects rather than evaluates directly.
 */
export function controlFamily(finding) {
  const id = String(finding.control_id || '');
  const framework = String(finding.framework || 'Other');
  if (/^\d/.test(id)) {
    const head = id.split('.')[0];
    // Only CIS is sectioned this way. Another framework that happens to number
    // its controls keeps its own prefix, because its section 1 is not CIS's.
    if (framework === 'CIS') {
      const book = BENCHMARK_SECTIONS[String(finding.benchmark || '')];
      if (!book) return `CIS ${head}`;
      const name = book.sections[head];
      return name ? `${book.short} §${head} · ${name}` : `${book.short} §${head}`;
    }
    return `${framework.replace(/_/g, ' ')} ${head}`;
  }
  return framework.replace(/_/g, ' ');
}
