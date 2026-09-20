"""Render ``docs/ARCHITECTURE.md`` to the two-page PDF ``GLOBAL_RULESET.md`` R10.3 asks for.

R10.3 names five deliverables and gives three of them a hard limit. The
architecture document's limit is **exactly two pages**, and until this script
existed the limit could not be checked at all: page count is a property of a
rendered document, and ``scripts/check_deliverable_limits.py`` deliberately
refused to guess it from the Markdown because a words-per-page constant would be
invented (R1.1) and a gate built on an invented constant fails for reasons nobody
caused. So the gate sat vacuous. This closes it by producing the artefact the
gate measures.

    python scripts/build_architecture_pdf.py            # write docs/ARCHITECTURE.pdf
    python scripts/build_architecture_pdf.py --check     # exit 1 if stale or not 2 pages

``--check`` renders to a temporary file and compares **extracted text and page
count**, never bytes. A PDF embeds its creation timestamp, so two byte-identical
runs are impossible and a byte comparison would report drift on every invocation
— the same trap ``scripts/bench/run_all.py --check`` avoids by diffing substance
rather than files.

Three deliberate narrownesses:

**The Markdown subset is small and fails loudly.** Headings, paragraphs, bullet
lists, fenced code and a horizontal rule are understood; anything else raises.
A general Markdown renderer is a solved problem this repository has no reason to
re-solve, and the failure mode that matters is the quiet one — a renderer that
skips a construct it does not know ships a two-page PDF missing a section, and
the page-count gate would pass. Refusing to render is the only outcome that
cannot hide a missing paragraph.

**Only the 14 standard PDF fonts are used, so glyph coverage is finite.**
Helvetica and Courier are WinAnsi-encoded: the box-drawing characters in the
pipeline diagram, and the Greek tau in the abstention discussion, have no glyph.
:data:`TRANSLITERATION` maps each one to an ASCII equivalent and any remaining
character outside WinAnsi is a build error rather than a silent ``?``. The
alternative was embedding a TrueType font with box-drawing coverage, which would
make the build depend on a font file that happens to be on this machine — the PDF
would then render differently, or not at all, for whoever clones the repository.

**Exactly two pages is asserted, not aimed for.** The script reports how full the
second page is, because "exactly two" is a constraint the document can grow out
of, and a fill percentage is the warning an author gets before the gate turns
red rather than after.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import FILE_ENCODING, PROJECT_ROOT

SOURCE = PROJECT_ROOT / "docs" / "ARCHITECTURE.md"
TARGET = PROJECT_ROOT / "docs" / "ARCHITECTURE.pdf"

#: R10.3: "architecture document (max 2 pages)". Held as equality rather than a
#: ceiling, matching ``check_deliverable_limits.ARCHITECTURE_MAX_PAGES`` — a
#: one-page architecture document for a system this size would mean something was
#: dropped in rendering, which is the failure this script is built to refuse.
PAGES = 2

PAGE_WIDTH = 595.28  # A4 in PostScript points
PAGE_HEIGHT = 841.89
MARGIN_X = 46.0
MARGIN_TOP = 40.0
MARGIN_BOTTOM = 34.0

BODY_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"
ITALIC_FONT = "Helvetica-Oblique"
MONO_FONT = "Courier"

#: Typography is fixed, and the page count is what falls out of it. Deriving the
#: body size from the target page count instead would make "exactly two pages"
#: trivially true — the document could triple in length and still fit, at four
#: point type — which is a gate passing for the wrong reason. 9.6pt Helvetica on
#: a 503pt column is roughly 95 characters per line: dense, and legible printed.
BODY_SIZE = 9.6
BODY_LEADING = 11.7
H1_SIZE = 16.0
H2_SIZE = 10.8

#: The mono size *is* derived, because it is a fit constraint rather than a page
#: budget: the ASCII pipeline diagram is one 80-column block and must not wrap.
#: Courier is metrically fixed at 0.6 em per glyph, so the largest size that fits
#: the column is computable. Capped at the body size so the diagram never
#: out-shouts the prose it illustrates.
_COURIER_ADVANCE = 0.6

#: Inline code is set slightly smaller than the prose around it. Courier's x-height
#: is taller than Helvetica's at the same nominal size, so matching the numbers
#: would make every ``path.like.this`` louder than the sentence containing it.
INLINE_CODE_RATIO = 0.87

#: Characters the document uses that WinAnsi has no glyph for. Mapped rather than
#: dropped: the pipeline diagram *is* the architecture, and a diagram rendered as
#: rows of ``?`` is worse than a diagram rendered in ASCII.
TRANSLITERATION = {
    "─": "-", "│": "|", "┌": "+", "┐": "+",
    "└": "+", "┘": "+", "┬": "+", "┴": "+",
    "├": "+", "┤": "+", "┼": "+",
    "▶": ">", "▼": "v", "▲": "^", "◀": "<",
    "→": "->", "←": "<-", "⇒": "=>",
    "τ": "tau", "≈": "~=", "≫": ">>", "≥": ">=",
    "≤": "<=", "×": "x", "✓": "y", "✗": "n",
    "ā": "a", "ū": "u",
    # Spaces the prose uses for typographic reasons. NO-BREAK SPACE is in
    # cp1252 and would pass the codec check, but it is mapped anyway: a
    # justified line that cannot break where the author wrote nbsp is a
    # rendering decision, not a glyph problem.
    "\u2009": " ",  # THIN SPACE
    "\u00a0": " ",  # NO-BREAK SPACE
}

_FENCE = "```"
_BULLET_RE = re.compile(r"^- (.*)$")
_H1_RE = re.compile(r"^# (.+)$")
_H2_RE = re.compile(r"^## (.+)$")
_RULE_RE = re.compile(r"^-{3,}\s*$")
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_CODE_RE = re.compile(r"`([^`]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC_RE = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")


class UnsupportedMarkdownError(RuntimeError):
    """The document uses a construct this renderer does not implement.

    Raised rather than skipped. A skipped construct produces a PDF that is short
    by one section and still two pages long, which the page-count gate would
    happily pass.
    """


@dataclass(frozen=True)
class Block:
    """One renderable unit. ``kind`` selects the style, ``lines`` is its text."""

    kind: str  # h1 | h2 | para | bullet | code | rule
    lines: tuple[str, ...]


def mono_size(blocks: list[Block]) -> float:
    """The largest Courier size at which every code block fits the text column.

    Returns the body size when there is no code, so the caller never has to
    special-case an empty document.
    """
    widest = max(
        (len(line) for block in blocks if block.kind == "code" for line in block.lines),
        default=0,
    )
    if not widest:
        return BODY_SIZE
    column = PAGE_WIDTH - 2 * MARGIN_X
    return min(BODY_SIZE, column / (widest * _COURIER_ADVANCE))


def transliterate(text: str) -> str:
    """Map the document's non-WinAnsi characters to ASCII, or refuse.

    Membership is decided by ``cp1252`` — WinAnsi *is* cp1252, so the codec is
    the authority rather than a hand-kept list that would drift from the fonts.
    """
    out = []
    for char in text:
        replacement = TRANSLITERATION.get(char)
        if replacement is not None:
            out.append(replacement)
            continue
        try:
            char.encode("cp1252")
        except UnicodeEncodeError:
            raise UnsupportedMarkdownError(
                f"{SOURCE.name} contains U+{ord(char):04X} ({char!r}), which the 14 "
                f"standard PDF fonts cannot render. Add it to TRANSLITERATION with an "
                f"ASCII equivalent, or reword the sentence. It is not silently dropped "
                f"because a report that renders a character as '?' has published a "
                f"typo it did not write."
            ) from None
        out.append(char)
    return "".join(out)


def parse(text: str) -> list[Block]:
    """Split the Markdown into blocks. Unknown constructs raise.

    Bullet continuation lines are joined into their bullet, because Markdown
    treats an indented follow-on as the same list item and rendering it as a
    separate paragraph would break the indent.
    """
    blocks: list[Block] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.startswith(_FENCE):
            index += 1
            code: list[str] = []
            while index < len(lines) and not lines[index].startswith(_FENCE):
                code.append(lines[index])
                index += 1
            if index >= len(lines):
                raise UnsupportedMarkdownError(f"{SOURCE.name}: unclosed code fence")
            blocks.append(Block("code", tuple(code)))
            index += 1
            continue
        if _RULE_RE.match(line):
            blocks.append(Block("rule", ()))
            index += 1
            continue
        if match := _H2_RE.match(line):
            blocks.append(Block("h2", (match.group(1),)))
            index += 1
            continue
        if match := _H1_RE.match(line):
            blocks.append(Block("h1", (match.group(1),)))
            index += 1
            continue
        if line.startswith("#"):
            raise UnsupportedMarkdownError(
                f"{SOURCE.name}:{index + 1} uses a heading deeper than ##. Two "
                "levels is all this renderer styles; a third would be rendered as "
                "body text and read as a missing section."
            )
        if "|" in line and line.strip().startswith("|"):
            raise UnsupportedMarkdownError(
                f"{SOURCE.name}:{index + 1} looks like a table. Tables are not "
                "implemented — the two-page budget has no room for one, and a "
                "table flattened into paragraphs is unreadable."
            )
        if match := _BULLET_RE.match(line):
            item = [match.group(1)]
            index += 1
            while index < len(lines) and lines[index].startswith("  ") and lines[index].strip():
                item.append(lines[index].strip())
                index += 1
            blocks.append(Block("bullet", (" ".join(item),)))
            continue
        para = [line.strip()]
        index += 1
        while (
            index < len(lines)
            and lines[index].strip()
            and not lines[index].startswith(("#", "- ", _FENCE))
            and not _RULE_RE.match(lines[index])
        ):
            para.append(lines[index].strip())
            index += 1
        blocks.append(Block("para", (" ".join(para),)))
    return blocks


def inline(text: str) -> str:
    """Convert inline Markdown to ReportLab's mini-HTML.

    Code spans and link tags are lifted out into placeholders before the
    emphasis passes run, and restored afterwards. Without that, the ``*`` in
    ``reports/metrics/*.json`` pairs with the next literal asterisk in the
    paragraph and opens an ``<i>`` that closes inside a ``<font>`` — ReportLab
    rejects the whole paragraph, which is at least loud, but the correct reading
    is that emphasis markers inside code are not emphasis markers.

    Relative links render as their text alone. A clickable ``GAPS.md`` in a PDF
    resolves against nothing, and a footnote per link would cost more of the
    two-page budget than the links are worth; absolute URLs stay clickable
    because those do resolve.
    """
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    vault: list[str] = []

    def stash(markup: str) -> str:
        vault.append(markup)
        return f"\x00{len(vault) - 1}\x01"

    def link(match: re.Match[str]) -> str:
        label, target = match.group(1), match.group(2)
        if not target.startswith(("http://", "https://")):
            return label
        return stash(f'<link href="{target}" color="#1a4f8a">') + label + stash("</link>")

    out = _LINK_RE.sub(link, escaped)
    out = _CODE_RE.sub(
        lambda m: stash(
            f'<font face="{MONO_FONT}" size="{BODY_SIZE * INLINE_CODE_RATIO:.2f}">'
            f"{m.group(1)}</font>"
        ),
        out,
    )
    out = _BOLD_RE.sub(r"<b>\1</b>", out)
    out = _ITALIC_RE.sub(r"<i>\1</i>", out)
    return re.sub(r"\x00(\d+)\x01", lambda m: vault[int(m.group(1))], out)


def build_story(blocks: list[Block]) -> list[object]:
    """Turn blocks into ReportLab flowables."""
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_JUSTIFY
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import HRFlowable, Paragraph, Preformatted, Spacer

    size = mono_size(blocks)
    body = ParagraphStyle(
        "body", fontName=BODY_FONT, fontSize=BODY_SIZE, leading=BODY_LEADING,
        alignment=TA_JUSTIFY, spaceAfter=3.6,
    )
    bullet = ParagraphStyle(
        "bullet", parent=body, leftIndent=9.0, bulletIndent=1.0, spaceAfter=2.4,
    )
    h1 = ParagraphStyle(
        "h1", fontName=BOLD_FONT, fontSize=H1_SIZE, leading=H1_SIZE + 2.0,
        spaceAfter=4.0, textColor=HexColor("#12314f"),
    )
    h2 = ParagraphStyle(
        "h2", fontName=BOLD_FONT, fontSize=H2_SIZE, leading=H2_SIZE + 1.6,
        spaceBefore=6.4, spaceAfter=2.6, textColor=HexColor("#12314f"),
    )
    code = ParagraphStyle(
        "code", fontName=MONO_FONT, fontSize=size, leading=size * 1.17,
    )

    story: list[object] = []
    for block in blocks:
        if block.kind == "rule":
            story.append(Spacer(1, 2.4))
            story.append(HRFlowable(width="100%", thickness=0.4, color=HexColor("#9aa7b4")))
            story.append(Spacer(1, 3.6))
        elif block.kind == "h1":
            story.append(Paragraph(inline(block.lines[0]), h1))
        elif block.kind == "h2":
            story.append(Paragraph(inline(block.lines[0]), h2))
        elif block.kind == "bullet":
            story.append(Paragraph(inline(block.lines[0]), bullet, bulletText="•"))
        elif block.kind == "code":
            story.append(Spacer(1, 1.6))
            story.append(Preformatted("\n".join(block.lines), code))
            story.append(Spacer(1, 3.2))
        else:
            story.append(Paragraph(inline(block.lines[0]), body))
    return story


def render(destination: Path) -> tuple[int, float]:
    """Write the PDF. Returns ``(pages, last_page_fill)``.

    ``last_page_fill`` is the fraction of the final page's text column that is
    occupied, which is the number an author needs *before* the page count tips.
    """
    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate

    raw = transliterate(SOURCE.read_text(encoding=FILE_ENCODING))
    story = build_story(parse(raw))

    fills: list[float] = []
    frame_height = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM

    doc = BaseDocTemplate(
        str(destination),
        pagesize=(PAGE_WIDTH, PAGE_HEIGHT),
        title="PRAMAN — Architecture",
        author="PRAMAN",
        subject="SIH 2026 PS 26155 — architecture document (R10.3, 2 pages)",
        leftMargin=MARGIN_X, rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP, bottomMargin=MARGIN_BOTTOM,
    )
    frame = Frame(
        MARGIN_X, MARGIN_BOTTOM, PAGE_WIDTH - 2 * MARGIN_X, frame_height, id="text",
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )

    def on_page(canvas: object, document: object) -> None:
        remaining = getattr(frame, "_y", MARGIN_BOTTOM) - MARGIN_BOTTOM
        fills.append(max(0.0, min(1.0, 1.0 - remaining / frame_height)))

    doc.addPageTemplates([PageTemplate(id="page", frames=[frame], onPageEnd=on_page)])
    doc.build(story)
    return doc.page, (fills[-1] if fills else 0.0)


def page_text(path: Path) -> list[str]:
    """Extract each page's text, for the staleness comparison.

    ``pypdfium2`` is used because it is the PDF library this project already
    depends on (``requirements.lock.txt``). Extraction normalises whitespace: a
    justified line's inter-word spacing is a rendering detail, and comparing it
    would report drift that no author caused.
    """
    import pypdfium2

    document = pypdfium2.PdfDocument(str(path))
    try:
        return [
            " ".join(page.get_textpage().get_text_range().split())
            for page in document
        ]
    finally:
        document.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if stale or mis-paginated")
    args = parser.parse_args()

    import tempfile

    with tempfile.TemporaryDirectory() as work:
        fresh = Path(work) / "ARCHITECTURE.pdf"
        pages, fill = render(fresh)
        problems: list[str] = []
        if pages != PAGES:
            problems.append(
                f"renders to {pages} pages; R10.3 requires exactly {PAGES}. Adjust "
                f"{SOURCE.name}, not the font size — the limit is on the document."
            )
        if args.check:
            if not TARGET.exists():
                problems.append(f"{TARGET.name} has not been built")
            elif page_text(TARGET) != page_text(fresh):
                problems.append(
                    f"{TARGET.name} no longer matches {SOURCE.name}. Rebuild with: "
                    "python scripts/build_architecture_pdf.py"
                )
            for problem in problems:
                print(f"STALE {problem}")
            print(f"{pages} pages, page {pages} {fill:.0%} full.")
            return 1 if problems else 0

        for problem in problems:
            print(f"FAIL {problem}")
        if problems:
            return 1
        TARGET.write_bytes(fresh.read_bytes())
        print(
            f"wrote {TARGET.relative_to(PROJECT_ROOT).as_posix()} "
            f"({TARGET.stat().st_size // 1024} KB, {pages} pages, page {pages} {fill:.0%} full)"
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
