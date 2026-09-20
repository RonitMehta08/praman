"""PRAMAN deterministic colour palette — frozen.

Hex values are from GLOBAL_RULESET R11.2 / R11.3.
Identical values must appear in the frontend CSS custom properties.

R11.3 recorded results:
  - 4 frameworks in grouped/stacked bar: PASSES
  - 4 frameworks on overlapping form: FAILS on yellow↔orange (ΔE 13.7)

For any overlapping form, use 4 small-multiple radars or a grouped
horizontal bar, and cap overlapping/all-pairs forms at 3 series.
"""

from __future__ import annotations

# ─── Framework categorical (fixed order, never cycled) ─────────────────
FRAMEWORK_COLORS = {
    "light": {
        "CIS": "#2a78d6",
        "NIST_800_53": "#eb6834",
        "DISA_STIG": "#1baf7a",
        "ISO_27001": "#eda100",
    },
    "dark": {
        "CIS": "#3987e5",
        "NIST_800_53": "#d95926",
        "DISA_STIG": "#199e70",
        "ISO_27001": "#c98500",
    },
}

# ─── Severity — single-hue red ordinal ramp ───────────────────────────
# R11.3: categorical 5-colour severity FAILS colourblind checks;
# single-hue red ordinal ramp PASSES.
SEVERITY_COLORS = {
    "light": {
        "low": "#eb9a9a",      # stop 1
        "medium": "#cf3f3f",   # stop 3
        "high": "#801f1f",     # stop 5
    },
    "dark": {
        "low": "#f7bdbd",
        "medium": "#de6c6c",
        "high": "#8f3030",
    },
}

# ─── Finding.result legend (all 9 XCCDF values) ───────────────────────
# Each chip ships with an icon + label, never colour alone.
RESULT_COLORS = {
    "pass": "#0ca30c",
    "fail": "#d03b3b",
    "error": "#ec835a",
    "unknown": "#fab219",
    "fixed": "#1baf7a",
    "notapplicable": "#898781",
    "notchecked": "#c3c2b7",
    "notselected": "#e1e0d9",
    "informational": "#2a78d6",
}

# ─── Topology node status ─────────────────────────────────────────────
NODE_STATUS_COLORS = {
    "green": "#0ca30c",   # all applicable controls pass
    "amber": "#fab219",   # only low/medium fails
    "red": "#d03b3b",     # ≥1 high/CAT I fail
}

# ─── Sequential (heatmap) — blue ordinal ramp from R11.3 ──────────────
HEATMAP_COLORS = {
    "light": ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"],
    "dark": ["#cde2fb", "#9ec5f4", "#5598e7", "#2a78d6", "#184f95"],
}

# ─── Trend line ───────────────────────────────────────────────────────
TREND_COLORS = {
    "light": "#2a78d6",
    "dark": "#3987e5",
}

# ─── Surfaces ─────────────────────────────────────────────────────────
SURFACE_COLORS = {
    "light": "#fcfcfb",
    "dark": "#1a1a19",
}

# ─── Gauge bands (PRAMAN convention, §23.1) ───────────────────────────
GAUGE_BANDS = [
    (0, 50, "#d03b3b"),
    (50, 75, "#ec835a"),
    (75, 90, "#fab219"),
    (90, 100, "#0ca30c"),
]
