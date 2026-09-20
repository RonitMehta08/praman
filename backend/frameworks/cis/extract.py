"""Extract CIS Benchmark controls from PDF files.

Reads CIS Benchmark PDFs from a source directory, parses each control
recommendation (section number, title, profile, description, rationale,
audit, remediation, etc.), and writes per-benchmark JSON files with full
provenance fields as required by GLOBAL_RULESET.md R1.6.

Usage:
    python -m backend.frameworks.cis.extract \
        --source data/frameworks/cis/_source \
        --out data/frameworks/cis/
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CISControl:
    """A single CIS Benchmark recommendation/control."""

    benchmark: str
    benchmark_version: str
    section: str
    title: str
    automated: bool | None  # None when the PDF used the Scored/Not Scored vocabulary
    profile: str  # "Level 1", "Level 2", or "Level 1, Level 2"
    description: str
    rationale: str
    impact: str
    audit: str
    remediation: str
    default_value: str
    # Designation, recorded verbatim rather than normalised. CIS switched from
    # (Scored)/(Not Scored) to (Automated)/(Manual) around 2019-2020; the two
    # describe different things and are deliberately NOT mapped onto each other.
    scored: bool | None = None
    designation: str = ""
    designation_vocabulary: str = "unknown"  # automated_manual | scored_notscored | unknown
    references: list[str] = field(default_factory=list)
    cis_controls: list[str] = field(default_factory=list)
    # Provenance (R1.6)
    source_document: str = ""
    source_version: str = ""
    retrieved_at: str = ""
    source_url: str = "https://workbench.cisecurity.org/"


@dataclass
class BenchmarkMeta:
    """Metadata extracted from the first page(s) of a CIS Benchmark PDF."""

    name: str
    version: str
    date: str
    filename: str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Section number pattern used to locate a control HEADING once we already know
# where the control body starts. Deliberately NOT used to enumerate controls —
# see extract_controls() for why heading-shape enumeration is unsafe.
#
# Depth: up to 6 components. Cisco IOS benchmarks nest FIVE levels deep
# (e.g. "2.1.1.1.2 Set the 'ip domain-name'"); measured 3 such headings in
# CIS Cisco IOS 15 v4.1.1 and 3 in CIS Cisco IOS XE 17.x v2.2.1. An earlier
# {1,3} cap (four levels) silently failed to match them, and the backward walk
# then ran past the real heading into the previous control's CIS Controls
# mapping table, mis-attributing 4 IOS 15 controls to section "4.5" and 2
# IOS XE controls to "0.0". Deepest observed overall: 5. The cap is 6 to leave
# headroom without matching arbitrary dotted numbers in prose.
SECTION_LINE_RE = re.compile(r"^(\d+(?:\.\d+){1,5})[ \t]+(\S.*)$")

# Same thing, but with the LEADING COMPONENT MISSING. pdfplumber drops the first
# glyph of a heading when it sits at the top of a page and the PDF positions that
# glyph in a separate text run. Measured in CIS Palo Alto Firewall 11 v1.2.0,
# where both the heading and its table-of-contents entry extract as
# ".3 Ensure forwarding of decrypted content to WildFire is enabled" — the "5" is
# absent from the text layer entirely, so it cannot be read, only reconstructed
# from document order (see _recover_orphan_section).
#
# Without this pattern the backward walk falls THROUGH the real heading and stops
# on the previous control's CIS Controls cross-reference row
# ("8.3 Enable Operating System Anti-Exploitation Features/"), which silently
# produces both a wrong section number and a title built from mapping-table prose.
ORPHAN_SECTION_RE = re.compile(r"^(\.\d+(?:\.\d+){0,4})[ \t]+(\S.*)$")

# Signature of a row inside a control's "CIS Controls:" cross-reference table.
# Those tables carry a version column rendered on its own line as "v7" or "v8",
# either immediately before or immediately after the numbered row:
#
#     4.5 Use Multifactor Authentication For All Administrative
#     v7 Access ● ●                                  <- version AFTER the row
#
#     v7                                             <- version BEFORE the row
#     0.0 Explicitly Not Mapped
#
# Mapping rows are numbered exactly like control headings, so the backward walk
# can mistake one for a heading. Matching requires STRICT adjacency to the
# version line — see _is_cis_controls_row. This is defence in depth: with the
# section-depth cap fixed the walk reaches the real heading first, but if a
# future benchmark introduces another unmatched heading shape, this makes the
# walk report the problem instead of silently attributing the control to a
# CIS Controls number.
CIS_CONTROLS_VERSION_RE = re.compile(r"^v[78]\b")

# The designation that follows a control title. CIS changed vocabulary:
#   - benchmarks from ~2020 onward use (Automated) / (Manual)
#   - older benchmarks (e.g. CIS Juniper OS v2.0.0, 02-28-2019) use
#     (Scored) / (Not Scored)
# These are DIFFERENT axes: Automated/Manual describes whether assessment can be
# automated; Scored/Not Scored describes whether the item counts toward the
# benchmark score. They are NOT equivalent and must not be mapped onto each other.
DESIGNATION_RE = re.compile(r"\((Automated|Manual|Not\s+Scored|Scored)\)")

# The anchor that reliably marks the start of a real control body. Every CIS
# recommendation has exactly one; table-of-contents entries and CIS Controls
# cross-reference rows have none. Counting these gives the true control count.
BODY_ANCHOR = "Profile Applicability:"

# Page footer patterns to strip
PAGE_FOOTER_RE = re.compile(r"\n?\d+\s*\|\s*P\s*a\s*g\s*e\s*$", re.MULTILINE)
PAGE_FOOTER_ALT_RE = re.compile(r"\nPage\s+\d+\s*$", re.MULTILINE)
INTERNAL_ONLY_RE = re.compile(r"\n?Internal Only - General\s*$", re.MULTILINE)

# Known section labels inside a control (order matters for splitting)
CONTROL_SECTIONS = [
    "Profile Applicability:",
    "Description:",
    "Rationale:",
    "Impact:",
    "Audit:",
    "Remediation:",
    "Default Value:",
    "Additional Information:",
    "References:",
    "CIS Controls:",
]

# Version extraction from page 1
VERSION_RE = re.compile(r"v(\d+\.\d+\.\d+)")
DATE_RE = re.compile(r"(\d{2}-\d{2}-\d{4})")

# Benchmark name extraction from page 1 — captures everything after "CIS "
# up to "Benchmark" or end of line
BENCH_NAME_RE = re.compile(r"CIS\s+(.+?)(?:\s+Benchmark)?$", re.MULTILINE)


# ---------------------------------------------------------------------------
# PDF text extraction
# ---------------------------------------------------------------------------

def _extract_full_text(pdf_path: Path) -> tuple[str, BenchmarkMeta]:
    """Extract all text from a PDF and parse benchmark metadata from page 1.

    Args:
        pdf_path: Path to the CIS Benchmark PDF.

    Returns:
        Tuple of (full concatenated text, BenchmarkMeta).

    Raises:
        RuntimeError: If pdfplumber cannot open or read the PDF.
    """
    try:
        import pdfplumber
    except ImportError as exc:
        raise RuntimeError(
            "pdfplumber is required. Install it: pip install pdfplumber"
        ) from exc

    pages_text: list[str] = []
    meta = BenchmarkMeta(name="", version="", date="", filename=pdf_path.name)

    with pdfplumber.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages):
            text = page.extract_text() or ""

            # Clean footer noise
            text = PAGE_FOOTER_RE.sub("", text)
            text = PAGE_FOOTER_ALT_RE.sub("", text)
            text = INTERNAL_ONLY_RE.sub("", text)

            if i == 0:
                meta = _parse_meta(text, pdf_path.name)

            pages_text.append(text)

    full_text = "\n".join(pages_text)
    return full_text, meta


def _parse_meta(page1_text: str, filename: str) -> BenchmarkMeta:
    """Extract benchmark name, version, and date from page 1 text."""
    name_match = BENCH_NAME_RE.search(page1_text)
    ver_match = VERSION_RE.search(page1_text)
    date_match = DATE_RE.search(page1_text)

    name = name_match.group(1).strip() if name_match else filename
    version = ver_match.group(1) if ver_match else "unknown"
    date = date_match.group(1) if date_match else ""

    return BenchmarkMeta(name=name, version=version, date=date, filename=filename)


# ---------------------------------------------------------------------------
# Control parsing
# ---------------------------------------------------------------------------

def _split_control_body(body: str) -> dict[str, str]:
    """Split a control's body text into labeled sections.

    Finds each known label (e.g. 'Description:', 'Remediation:') and
    captures the text between consecutive labels.

    Returns:
        Dict mapping lowercase label names (without colon) to their text content.
    """
    # Find positions of all known section labels
    positions: list[tuple[int, str]] = []
    for label in CONTROL_SECTIONS:
        idx = body.find(label)
        if idx != -1:
            positions.append((idx, label))

    if not positions:
        return {"description": body.strip()}

    positions.sort(key=lambda x: x[0])

    sections: dict[str, str] = {}

    # Text before the first label (usually empty or part of description)
    preamble = body[: positions[0][0]].strip()
    if preamble:
        sections["preamble"] = preamble

    for i, (pos, label) in enumerate(positions):
        start = pos + len(label)
        end = positions[i + 1][0] if i + 1 < len(positions) else len(body)
        key = label.rstrip(":").lower().replace(" ", "_")
        sections[key] = body[start:end].strip()

    return sections


def _parse_profile(profile_text: str) -> str:
    """Extract profile level(s) from Profile Applicability text."""
    levels: list[str] = []
    if "Level 1" in profile_text:
        levels.append("Level 1")
    if "Level 2" in profile_text:
        levels.append("Level 2")
    return ", ".join(levels) if levels else "Unknown"


def _parse_references(ref_text: str) -> list[str]:
    """Extract reference URLs/items from the References section."""
    refs: list[str] = []
    for line in ref_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip numbered prefixes like "1." but keep the content
        cleaned = re.sub(r"^\d+\.\s*", "", line)
        if cleaned:
            refs.append(cleaned)

    # Merge continuation lines (URLs that wrap across lines)
    merged: list[str] = []
    for ref in refs:
        if (merged and not ref.startswith("http") and merged[-1].endswith("-")) or (merged and not ref.startswith("http") and not ref[0].isupper()):
            merged[-1] = merged[-1] + ref
        else:
            merged.append(ref)

    return merged


def _parse_cis_controls(controls_text: str) -> list[str]:
    """Extract CIS Controls identifiers from the CIS Controls section.

    These appear as lines like:
        5.6 Centralize Account Management
        8.2 Collect Audit Logs
    """
    controls: list[str] = []
    for line in controls_text.splitlines():
        line = line.strip()
        # Match control IDs like "5.6", "16.2", "8.2"
        match = re.match(r"^(\d+(?:\.\d+)?)\s+(.+)$", line)
        if match:
            ctrl_id = match.group(1)
            ctrl_name = match.group(2).strip()
            controls.append(f"{ctrl_id} {ctrl_name}")
    return controls


def _is_cis_controls_row(lines: list[str], idx: int) -> bool:
    """Return True if ``lines[idx]`` is a row of a CIS Controls mapping table.

    Detected by an IMMEDIATELY adjacent version-column line ("v7"/"v8"), which
    sits either directly before or directly after the numbered row. Real control
    headings are separated from the previous control's mapping table by at least
    a page footer, so strict adjacency distinguishes the two.

    Adjacency must be strict: a ±2 window also matches the mapping table's
    version line two rows above a genuine heading, which rejected 12 real
    headings across the corpus (629 controls fell to 617).

    Args:
        lines: Lines of the search window.
        idx: Index of the candidate heading line.

    Returns:
        True if the candidate is a mapping-table row rather than a heading.
    """
    for k in (idx - 1, idx + 1):
        if 0 <= k < len(lines) and CIS_CONTROLS_VERSION_RE.match(lines[k].strip()):
            return True
    return False


def _recover_orphan_section(fragment: str, prev_section: str) -> tuple[str, str]:
    """Reconstruct a section number whose leading component the PDF text lost.

    Some CIS PDFs drop the first glyph of a heading from the text layer, so a
    heading that reads "5.3 Ensure ..." on the page extracts as ".3 Ensure ...".
    The missing digit is not recoverable by reading — it is not in the text at
    all — so it is reconstructed from document order and then VALIDATED against
    the previous control's number. If validation fails, nothing is guessed.

    Args:
        fragment: The orphaned fragment as extracted, e.g. ".3".
        prev_section: Section number of the previously emitted control, e.g. "5.2".

    Returns:
        ``(section, note)``. On success ``section`` is the reconstructed number
        and ``note`` explains the basis. On failure ``section`` is ``""`` and
        ``note`` explains why, so the caller can report rather than invent.
    """
    orphan_parts = [p for p in fragment.split(".") if p]
    prev_parts = [p for p in prev_section.split(".") if p]

    if not orphan_parts or not prev_parts:
        return "", "no fragment or no preceding section to anchor against"
    if len(prev_parts) <= len(orphan_parts):
        return "", (
            f"preceding section {prev_section!r} is not deeper than fragment "
            f"{fragment!r}, so the missing prefix cannot be determined"
        )

    prefix = prev_parts[: len(prev_parts) - len(orphan_parts)]
    candidate = ".".join(prefix + orphan_parts)

    # Validate: the reconstructed number must be the immediate successor of the
    # previous one at the same depth. This is what makes the reconstruction a
    # deduction from document order rather than a guess.
    try:
        if int(orphan_parts[-1]) != int(prev_parts[-1]) + 1:
            return "", (
                f"reconstructed {candidate!r} does not follow {prev_section!r} "
                f"in sequence"
            )
    except ValueError:
        return "", f"non-numeric component in {fragment!r} or {prev_section!r}"

    return candidate, (
        f"leading component absent from the PDF text layer; reconstructed as "
        f"{candidate!r} from document order (follows {prev_section!r})"
    )


def extract_controls(full_text: str, meta: BenchmarkMeta) -> list[CISControl]:
    """Parse all controls from the full PDF text.

    Anchors on the ``Profile Applicability:`` label rather than on heading
    shape, then walks BACKWARDS to the nearest preceding section-numbered line
    to recover the section number, title and designation.

    Enumerating by heading shape (the obvious approach) is unsafe and was
    measured to fail in both directions on real CIS PDFs:

    * **Under-extraction** \u2014 control titles wrap across lines, so a pattern
      anchored to end-of-line misses them. Measured: 8 of 90 missed in
      CIS Cisco IOS 15 v4.1.1, 50 of 79 in CIS Palo Alto Firewall 11 v1.2.0.
    * **Over-extraction** \u2014 table-of-contents entries and CIS Controls
      cross-reference rows (``4.5 Use Multifactor Authentication ... \u25cf \u25cf``)
      look like headings. Measured: 17 phantom controls in
      CIS FortiGate 7.4.x v1.0.1, 4 in CIS NX-OS v1.2.0.

    Every real recommendation has exactly one ``Profile Applicability:``; TOC
    entries and cross-reference rows have none. So the count of that anchor is
    the ground-truth control count, and one control is emitted per anchor.

    Anchoring fixes the control COUNT, but the backward walk still has to find
    the right heading, and two measured layout quirks defeat a naive walk:

    * **Deeply nested numbers** — Cisco IOS headings reach five levels
      ("2.1.1.1.2"). A pattern capped at four silently skips them and the walk
      lands in the previous control's CIS Controls table, which is numbered the
      same way. Measured: 4 IOS 15 controls mis-attributed to "4.5" and 2
      IOS XE controls to "0.0" before ``SECTION_LINE_RE`` was widened.
    * **Dropped leading glyph** — pdfplumber omits the first character of a
      heading that starts a page in some PDFs, so "5.3 Ensure ..." extracts as
      ".3 Ensure ...". Measured: 1 control in CIS Palo Alto Firewall 11 v1.2.0,
      which the walk attributed to a cross-reference row's "8.3". Handled by
      ``ORPHAN_SECTION_RE`` plus ``_recover_orphan_section``.

    Args:
        full_text: Concatenated text of all PDF pages.
        meta: Benchmark metadata from page 1.

    Returns:
        List of CISControl dataclass instances.
    """
    anchors = [m.start() for m in re.finditer(re.escape(BODY_ANCHOR), full_text)]
    if not anchors:
        print(
            f"  WARNING: No '{BODY_ANCHOR}' anchors found in {meta.filename} \u2014 "
            f"this PDF's layout is not recognised.",
            file=sys.stderr,
        )
        return []

    controls: list[CISControl] = []
    now_utc = datetime.now(timezone.utc).isoformat()

    for i, anchor in enumerate(anchors):
        # Search window: from the previous anchor (or start) up to this one.
        window_start = anchors[i - 1] if i > 0 else 0
        window = full_text[window_start:anchor]

        # Walk backwards through the window for the last section-numbered line.
        # Accept an orphaned number (".3") as well as a full one ("5.3"): if the
        # PDF lost the leading glyph, the real heading is invisible to
        # SECTION_LINE_RE and the walk would otherwise continue past it and stop
        # inside the previous control's CIS Controls cross-reference table.
        lines = window.split("\n")
        head_idx: int | None = None
        section_num = ""
        section_note = ""
        raw_prefix = ""
        for j in range(len(lines) - 1, -1, -1):
            stripped = lines[j].strip()
            if not stripped:
                continue
            is_candidate = bool(
                SECTION_LINE_RE.match(stripped) or ORPHAN_SECTION_RE.match(stripped)
            )
            if is_candidate and _is_cis_controls_row(lines, j):
                # A CIS Controls mapping row, not a heading. Keep walking; if the
                # walk finds nothing else it reports rather than mis-attributes.
                continue
            m = SECTION_LINE_RE.match(stripped)
            if m:
                head_idx = j
                section_num = m.group(1)
                raw_prefix = m.group(1)
                break
            om = ORPHAN_SECTION_RE.match(stripped)
            if om:
                head_idx = j
                fragment = om.group(1)
                raw_prefix = fragment
                prev_section = controls[-1].section if controls else ""
                section_num, section_note = _recover_orphan_section(
                    fragment, prev_section
                )
                if section_num:
                    print(
                        f"  NOTE: {meta.filename} body #{i + 1}: {section_note}.",
                        file=sys.stderr,
                    )
                else:
                    # R1.7: report the shortfall, do not invent a number.
                    print(
                        f"  WARNING: {meta.filename} body #{i + 1}: heading "
                        f"number {fragment!r} is incomplete in the PDF text layer "
                        f"and could not be reconstructed ({section_note}). "
                        f"Section recorded as UNVERIFIED.",
                        file=sys.stderr,
                    )
                    section_num = "UNVERIFIED"
                break

        if head_idx is None:
            print(
                f"  WARNING: control body #{i + 1} in {meta.filename} has no "
                f"preceding section heading \u2014 skipped.",
                file=sys.stderr,
            )
            continue

        # The heading may wrap: join from the heading line to the anchor.
        heading_text = " ".join(x.strip() for x in lines[head_idx:] if x.strip())
        # Strip the number as it LITERALLY appears on the line, which is not
        # necessarily section_num: for a recovered orphan the line begins ".3"
        # while section_num is "5.3".
        heading_text = heading_text[len(raw_prefix):].strip()

        # Designation, verbatim. Absent in some layouts \u2014 record that honestly.
        dm = DESIGNATION_RE.search(heading_text)
        designation = " ".join(dm.group(1).split()) if dm else ""
        title = (heading_text[: dm.start()] if dm else heading_text).strip()
        title = title.replace("\u2018", "'").replace("\u2019", "'")
        title = " ".join(title.split())

        # Map the designation WITHOUT inventing an equivalence between the two
        # vocabularies. automated is None when the PDF used Scored/Not Scored,
        # because that vocabulary carries no automation claim at all.
        if designation in ("Automated", "Manual"):
            vocabulary = "automated_manual"
            automated: bool | None = designation == "Automated"
            scored: bool | None = None
        elif designation in ("Scored", "Not Scored"):
            vocabulary = "scored_notscored"
            automated = None
            scored = designation == "Scored"
        else:
            vocabulary = "unknown"
            automated = None
            scored = None

        # Body runs from this anchor to the next control's heading, or EOF.
        if i + 1 < len(anchors):
            nxt = full_text[anchor:anchors[i + 1]]
            nlines = nxt.split("\n")
            cut = len(nxt)
            for j in range(len(nlines) - 1, -1, -1):
                stripped = nlines[j].strip()
                if SECTION_LINE_RE.match(stripped) or ORPHAN_SECTION_RE.match(stripped):
                    if _is_cis_controls_row(nlines, j):
                        continue
                    cut = len("\n".join(nlines[:j]))
                    break
            body = nxt[:cut]
        else:
            body = full_text[anchor:]

        sections = _split_control_body(body)

        controls.append(
            CISControl(
                benchmark=meta.name,
                benchmark_version=f"v{meta.version}",
                section=section_num,
                title=title,
                automated=automated,
                scored=scored,
                designation=designation,
                designation_vocabulary=vocabulary,
                profile=_parse_profile(sections.get("profile_applicability", "")),
                description=sections.get("description", ""),
                rationale=sections.get("rationale", ""),
                impact=sections.get("impact", ""),
                audit=sections.get("audit", ""),
                remediation=sections.get("remediation", ""),
                default_value=sections.get("default_value", ""),
                references=_parse_references(sections.get("references", "")),
                cis_controls=_parse_cis_controls(sections.get("cis_controls", "")),
                source_document=meta.filename,
                source_version=f"v{meta.version}",
                retrieved_at=now_utc,
                source_url="https://workbench.cisecurity.org/",
            )
        )

    # R1.7: report a shortfall rather than shipping a quietly-truncated corpus.
    if len(controls) != len(anchors):
        print(
            f"  WARNING: {len(anchors)} control bodies detected but "
            f"{len(controls)} extracted in {meta.filename}.",
            file=sys.stderr,
        )

    # CIS section numbers are not guaranteed unique WITHIN one benchmark, so
    # (benchmark, benchmark_version, section) can collide. Surface it; do not
    # silently dedupe, which would discard a real control.
    counts: dict[str, int] = {}
    for c in controls:
        counts[c.section] = counts.get(c.section, 0) + 1
    dups = {k: v for k, v in counts.items() if v > 1}
    if dups:
        print(
            f"  WARNING: duplicate section numbers in {meta.filename}: {dups} \u2014 "
            f"(benchmark, version, section) is NOT a unique key here.",
            file=sys.stderr,
        )

    return controls


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    """Convert a benchmark name to a filesystem-safe slug.

    Example: 'Cisco IOS 15' -> 'cisco_ios_15'
    """
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = slug.strip("_")
    return slug


def write_output(
    controls: list[CISControl],
    meta: BenchmarkMeta,
    out_dir: Path,
) -> Path:
    """Write extracted controls to a JSON file.

    Args:
        controls: List of CISControl instances.
        meta: Benchmark metadata.
        out_dir: Output directory.

    Returns:
        Path to the written JSON file.
    """
    slug = _slugify(meta.name)
    filename = f"{slug}_v{meta.version}.json"
    out_path = out_dir / filename

    output: dict[str, Any] = {
        "benchmark": meta.name,
        "benchmark_version": f"v{meta.version}",
        "benchmark_date": meta.date,
        "source_document": meta.filename,
        "source_url": "https://workbench.cisecurity.org/",
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "control_count": len(controls),
        "controls": [asdict(c) for c in controls],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point for CIS Benchmark PDF extraction."""
    parser = argparse.ArgumentParser(
        description="Extract CIS Benchmark controls from PDF files.",
    )
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="Directory containing CIS Benchmark PDF files.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output directory for extracted JSON files.",
    )
    args = parser.parse_args()

    source_dir: Path = args.source
    out_dir: Path = args.out

    if not source_dir.is_dir():
        print(f"ERROR: Source directory does not exist: {source_dir}", file=sys.stderr)
        sys.exit(1)

    pdfs = sorted(source_dir.glob("*.pdf"))
    if not pdfs:
        print(f"ERROR: No PDF files found in {source_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(pdfs)} CIS Benchmark PDF(s) in {source_dir}")
    total_controls = 0

    for pdf_path in pdfs:
        print(f"\nProcessing: {pdf_path.name}")
        try:
            full_text, meta = _extract_full_text(pdf_path)
        except Exception as exc:
            print(f"  ERROR reading PDF: {exc}", file=sys.stderr)
            continue

        print(f"  Benchmark: {meta.name} {meta.version} ({meta.date})")

        controls = extract_controls(full_text, meta)
        if not controls:
            print("  WARNING: No controls extracted — skipping.", file=sys.stderr)
            continue

        # Count by profile
        l1_count = sum(1 for c in controls if "Level 1" in c.profile)
        l2_count = sum(1 for c in controls if "Level 2" in c.profile)
        auto_count = sum(1 for c in controls if c.automated is True)
        manual_count = sum(1 for c in controls if c.automated is False)
        scored_count = sum(1 for c in controls if c.scored is True)
        notscored_count = sum(1 for c in controls if c.scored is False)
        vocab = {c.designation_vocabulary for c in controls}

        out_path = write_output(controls, meta, out_dir)
        total_controls += len(controls)

        print(f"  Controls: {len(controls)} (L1: {l1_count}, L2: {l2_count})")
        print(f"  Designation vocabulary: {'/'.join(sorted(vocab))}")
        if auto_count or manual_count:
            print(f"  Automated: {auto_count}, Manual: {manual_count}")
        if scored_count or notscored_count:
            print(f"  Scored: {scored_count}, Not Scored: {notscored_count}")
        print(f"  Written to: {out_path}")

        # Provenance spot-check: verify first control has all R1.6 fields
        first = controls[0]
        provenance_ok = all([
            first.source_document,
            first.source_version,
            first.retrieved_at,
            first.source_url,
        ])
        status = "PASS" if provenance_ok else "FAIL"
        print(f"  Provenance (R1.6): {status}")

    print(f"\nDone. Total controls extracted: {total_controls}")


if __name__ == "__main__":
    main()
