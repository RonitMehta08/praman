/**
 * The frozen PRAMAN palette — the exact hexes from `backend/report/palette.py`.
 *
 * These two files must carry identical values, because a chart in the UI and the
 * same chart in the PDF are the same chart. An operator who reads a green bar on
 * screen and an amber one in the filed report has been shown two different
 * audits. GLOBAL_RULESET R11.2/R11.3 is the provenance for every value here; none
 * of them may be adjusted to taste.
 *
 * `tests/test_frontend_palette.py` parses both files and fails on any divergence,
 * so this is a mirror with a guard rather than a copy people hope stays in sync.
 */

/** Framework categorical. Fixed order, never cycled — a 5th framework folds to
 * "Other" rather than getting a generated hue, because a hue nobody validated is
 * a hue that fails a colourblind check in front of an auditor. */
export const FRAMEWORK_COLORS = {
  light: {
    CIS: '#2a78d6',
    NIST_800_53: '#eb6834',
    DISA_STIG: '#1baf7a',
    ISO_27001: '#eda100',
  },
  dark: {
    CIS: '#3987e5',
    NIST_800_53: '#d95926',
    DISA_STIG: '#199e70',
    ISO_27001: '#c98500',
  },
};

/** Severity — a single-hue red ordinal ramp at stops 1/3/5.
 *
 * R11.3 records that a 5-colour categorical severity palette fails colourblind
 * checks and that this ramp passes. Note there is no `unknown` key: severity
 * `unknown` is not a fourth stop on an ordinal scale, it is the absence of a
 * rating, so it borrows `RESULT_COLORS.unknown` instead. */
export const SEVERITY_COLORS = {
  light: { low: '#eb9a9a', medium: '#cf3f3f', high: '#801f1f' },
  dark: { low: '#f7bdbd', medium: '#de6c6c', high: '#8f3030' },
};

/** All nine XCCDF result values. Surface-independent by design: a verdict colour
 * that shifted between light and dark mode would make two screenshots of one
 * audit disagree. */
export const RESULT_COLORS = {
  pass: '#0ca30c',
  fail: '#d03b3b',
  error: '#ec835a',
  unknown: '#fab219',
  fixed: '#1baf7a',
  notapplicable: '#898781',
  notchecked: '#c3c2b7',
  notselected: '#e1e0d9',
  informational: '#2a78d6',
};

/** Topology node status. Reserved status colours (R11.5) — never reused for a
 * categorical series. */
export const NODE_STATUS_COLORS = {
  green: '#0ca30c',
  amber: '#fab219',
  red: '#d03b3b',
};

/** Sequential ramp for the heatmap. */
export const HEATMAP_COLORS = {
  light: ['#86b6ef', '#5598e7', '#2a78d6', '#1c5cab', '#104281'],
  dark: ['#cde2fb', '#9ec5f4', '#5598e7', '#2a78d6', '#184f95'],
};

/** Single-series trend line. */
export const TREND_COLORS = { light: '#2a78d6', dark: '#3987e5' };

/** Chart surface. */
export const SURFACE_COLORS = { light: '#fcfcfb', dark: '#1a1a19' };

/** Gauge arc bands. A PRAMAN convention, not a published metric — the UI must
 * label it as tool-defined wherever it appears. */
export const GAUGE_BANDS = [
  [0, 50, '#d03b3b'],
  [50, 75, '#ec835a'],
  [75, 90, '#fab219'],
  [90, 100, '#0ca30c'],
];

/** Every result value, in the order a legend should list them: the two verdicts
 * first, then the states that are not verdicts. Reading order is an honesty
 * feature — `notchecked` sitting between `pass` and `fail` invites a reader to
 * treat it as a third verdict. */
export const RESULT_ORDER = [
  'pass',
  'fail',
  'error',
  'unknown',
  'fixed',
  'notapplicable',
  'notchecked',
  'notselected',
  'informational',
];

/** Severity worst-first, matching the order the remediation API sorts by. */
export const SEVERITY_ORDER = ['high', 'medium', 'low', 'unknown'];

/** Which results are actual verdicts. Everything else is a coverage statement,
 * and the difference is the single most important thing this UI communicates. */
export const VERDICTS = new Set(['pass', 'fail']);

/** True while the document is in dark mode. */
export function isDark() {
  return document.documentElement.dataset.theme === 'dark';
}

function mode() {
  return isDark() ? 'dark' : 'light';
}

/** Colour for a framework, folding anything unrecognised to a neutral rather
 * than inventing a hue. */
export function frameworkColor(framework) {
  const table = FRAMEWORK_COLORS[mode()];
  return table[framework] || RESULT_COLORS.notapplicable;
}

/** Colour for a severity. `unknown` falls through to the amber status colour,
 * which is deliberate: it reads as "not rated", not as a fourth rung. */
export function severityColor(severity) {
  const key = String(severity || '').toLowerCase();
  const table = SEVERITY_COLORS[mode()];
  return table[key] || RESULT_COLORS.unknown;
}

/** Colour for one of the nine result values. */
export function resultColor(result) {
  return RESULT_COLORS[String(result || '').toLowerCase()] || RESULT_COLORS.notchecked;
}

/** The heatmap ramp for the current surface. */
export function heatmapRamp() {
  return HEATMAP_COLORS[mode()];
}

/** The trend series colour for the current surface. */
export function trendColor() {
  return TREND_COLORS[mode()];
}

/** The band colour a score falls in. */
export function gaugeBandColor(score) {
  const value = Number.isFinite(score) ? score : 0;
  for (const [low, high, hex] of GAUGE_BANDS) {
    if (value >= low && value < high) return hex;
  }
  return GAUGE_BANDS[GAUGE_BANDS.length - 1][2];
}
