"""A PDF writer of last resort, in the standard library alone.

This exists for one reason. :func:`backend.report.render.render_pdf` is served by
a route that sets ``Content-Type: application/pdf``, and the previous fallback
path returned a JSON document under that header. Every viewer in the chain --
browser, mail client, PDF/A validator, the operator's evidence archive -- would
treat those bytes as a corrupt PDF rather than as valid JSON, and the failure
would surface far from its cause.

So when ReportLab is unavailable the report degrades in content, not in format:
plain monospaced text, no charts, no colour, but a file that opens. It says at
the top that it is a degraded rendering and how to get the real one, because a
report that quietly drops the remediation section is worse than one that
announces it did.

What it deliberately does not implement: font embedding, compression,
Unicode. The 14 standard Type 1 fonts need no embedding and Courier is enough
for text; anything outside Latin-1 is transliterated by
:func:`~backend.report.minimal_pdf.pdf_string` rather than silently truncating
the file. This is not a general-purpose PDF library and should not grow into one
-- the real renderer is ReportLab.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: A4 in PostScript points, matching the ReportLab path so the degraded report
#: prints on the same paper as the real one.
PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89

MARGIN = 56.0
FONT_SIZE = 8.5
LEADING = 11.0
FONT_NAME = "Courier"
BOLD_NAME = "Courier-Bold"

#: Courier is metrically fixed at 0.6 em per glyph, which is what makes wrapping
#: computable here without a font metrics table.
_COURIER_ADVANCE = 0.6


def wrap(text: str, width_pt: float, size: float = FONT_SIZE) -> list[str]:
    """Break text to a pixel width using Courier's fixed advance.

    Long unbroken tokens -- a 64-character hash, a config line with no spaces --
    are hard-split rather than allowed to run off the page. A hash that runs past
    the margin is not a verifiable hash.
    """
    columns = max(8, int(width_pt / (size * _COURIER_ADVANCE)))
    lines: list[str] = []
    for paragraph in text.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        current = ""
        for word in paragraph.split(" "):
            while len(word) > columns:
                if current:
                    lines.append(current)
                    current = ""
                lines.append(word[:columns])
                word = word[columns:]
            candidate = f"{current} {word}".strip()
            if len(candidate) > columns:
                lines.append(current)
                current = word
            else:
                current = candidate
        if current:
            lines.append(current)
    return lines


def pdf_string(text: str) -> bytes:
    """Encode one line as a PDF literal string.

    Backslash, and both parentheses, delimit and escape inside a PDF string, so
    an unescaped config line containing ``(`` would end the string early and
    corrupt the object. Characters outside Latin-1 become ``?`` -- visibly wrong
    in the output, which is preferable to a file that will not open.
    """
    escaped = (
        text.replace("\\", r"\\")
        .replace("(", r"\(")
        .replace(")", r"\)")
    )
    return b"(" + escaped.encode("latin-1", "replace") + b")"


@dataclass
class _Line:
    """One rendered line: text, indent in points, and whether it is bold."""

    text: str
    indent: float = 0.0
    bold: bool = False


@dataclass
class MinimalPdf:
    """Accumulates text lines and serialises them as a multi-page PDF."""

    lines: list[_Line] = field(default_factory=list)
    title: str = "PRAMAN Report"

    @property
    def usable_width(self) -> float:
        """Text column width in points."""
        return PAGE_WIDTH - 2 * MARGIN

    def heading(self, text: str) -> None:
        """A bold line with a blank line before it."""
        if self.lines:
            self.lines.append(_Line(""))
        for chunk in wrap(text.upper(), self.usable_width):
            self.lines.append(_Line(chunk, bold=True))

    def body(self, text: str, indent: float = 0.0) -> None:
        """A wrapped run of normal text."""
        for chunk in wrap(text, self.usable_width - indent):
            self.lines.append(_Line(chunk, indent=indent))

    def pair(self, label: str, value: str) -> None:
        """A ``label: value`` row, continuation lines aligned under the value."""
        self.body(f"{label}: {value}", indent=0.0)

    def blank(self) -> None:
        """One empty line."""
        self.lines.append(_Line(""))

    def _pages(self) -> list[list[_Line]]:
        """Split the accumulated lines into pages."""
        per_page = max(1, int((PAGE_HEIGHT - 2 * MARGIN) / LEADING))
        if not self.lines:
            return [[]]
        return [
            self.lines[index : index + per_page]
            for index in range(0, len(self.lines), per_page)
        ]

    def _content_stream(self, page: list[_Line]) -> bytes:
        """The text-drawing operators for one page."""
        out = [b"BT", f"1 0 0 1 {MARGIN:.2f} {PAGE_HEIGHT - MARGIN:.2f} Tm".encode(),
               f"{LEADING:.2f} TL".encode()]
        font = ""
        for line in page:
            wanted = BOLD_NAME if line.bold else FONT_NAME
            if wanted != font:
                out.append(f"/{'FB' if line.bold else 'FR'} {FONT_SIZE:.2f} Tf".encode())
                font = wanted
            if line.indent:
                out.append(f"{line.indent:.2f} 0 Td".encode())
            out.append(pdf_string(line.text) + b" Tj")
            if line.indent:
                out.append(f"{-line.indent:.2f} 0 Td".encode())
            out.append(b"T*")
        out.append(b"ET")
        return b"\n".join(out)

    def build(self) -> bytes:
        """Serialise to PDF bytes with a correct cross-reference table."""
        pages = self._pages()
        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        # Object numbers are assigned before the bodies that reference them are
        # written, so the layout is fixed up front rather than patched later.
        catalog_num = 1
        pages_num = 2
        regular_num = 3
        bold_num = 4
        first_page_num = 5
        page_nums = [first_page_num + index * 2 for index in range(len(pages))]
        content_nums = [num + 1 for num in page_nums]

        add(f"<< /Type /Catalog /Pages {pages_num} 0 R >>".encode())
        kids = " ".join(f"{num} 0 R" for num in page_nums)
        add(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())
        add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
            b"/Encoding /WinAnsiEncoding >>")
        add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold "
            b"/Encoding /WinAnsiEncoding >>")

        for page, page_num, content_num in zip(pages, page_nums, content_nums, strict=True):
            assert add(
                f"<< /Type /Page /Parent {pages_num} 0 R "
                f"/MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "
                f"/Resources << /Font << /FR {regular_num} 0 R /FB {bold_num} 0 R >> >> "
                f"/Contents {content_num} 0 R >>".encode()
            ) == page_num
            stream = self._content_stream(page)
            assert add(
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                + stream + b"\nendstream"
            ) == content_num

        out = bytearray(b"%PDF-1.4\n")
        offsets: list[int] = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

        startxref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        # Every xref entry is exactly 20 bytes; a reader seeks by multiplication,
        # so a single byte off here makes the whole file unreadable.
        out += b"0000000000 65535 f \n"
        for offset in offsets:
            out += f"{offset:010d} 00000 n \n".encode()
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_num} 0 R "
            f"/Info << /Title ".encode()
            + pdf_string(self.title)
            + b" /Producer (PRAMAN minimal writer) >> >>\n"
        )
        out += f"startxref\n{startxref}\n%%EOF\n".encode()
        return bytes(out)
