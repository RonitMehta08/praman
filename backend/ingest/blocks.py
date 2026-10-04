"""Block extent — pass 1 of the shared pattern parser.

Split out of :mod:`backend.ingest.generic`, which was doing two separable jobs:
deciding *where a block starts and stops* in a vendor's own syntax, and turning
the lines inside it into canonical facts. This module is the first job only. It
is pure lexical work over ``list[str]`` — it knows about indentation, ``end``
markers, braces and repeated keys, and nothing at all about canonical paths,
facts or devices.

The separation is worth having because the two jobs fail differently. A bug here
puts a real finding on the wrong interface; a bug in fact production gets the
value wrong on the right one. Keeping them in separate modules keeps that
distinction visible, and keeps each file readable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from backend.ingest.patterns import (
    SKIP,
    BlockMode,
    BlockPattern,
    PatternPack,
    coerce_value,
)


def indent_of(raw_line: str) -> int:
    """Return a line's leading-whitespace width, tabs counted as one column."""
    return len(raw_line) - len(raw_line.lstrip())


@dataclass
class BlockInstance:
    """One occurrence of a block in one configuration file."""

    block: BlockPattern
    #: String form of the anchor value, used for grouping and for labelling
    #: evidence ("GigabitEthernet0/1"). Always a string so it can be compared
    #: and displayed uniformly.
    key: str
    #: The anchor fact's actual value, which may be a bool or int. Kept separate
    #: from ``key`` so a block whose anchor means "this feature is on" emits a
    #: real boolean rather than the string "True".
    value: Any
    line_start: int
    line_end: int
    anchor_line: str
    depth: int = 0
    #: Child paths this instance actually matched, so child_defaults can fill gaps.
    matched_paths: set[str] = field(default_factory=set)

    def contains(self, line_no: int) -> bool:
        """Whether a line number falls inside this instance's span."""
        return self.line_start <= line_no <= self.line_end



class BlockScanner:
    """Finds every block instance in one configuration, with its exact span.

    Holds the pack's block patterns and comment prefixes; built once per adapter
    and reused for every parse, because neither changes between files.
    """

    def __init__(self, pack: PatternPack) -> None:
        self._blocks = pack.blocks
        self._comment_prefixes = pack.comment_prefixes

    def is_comment(self, stripped: str) -> bool:
        """Whether a stripped line is a comment for this platform."""
        return any(stripped.startswith(p) for p in self._comment_prefixes)

    def scan(self, lines: list[str]) -> list[BlockInstance]:
        """Locate every block instance and its exact line span.

        Returns instances sorted innermost-first for a given line, so
        ``_enclosing`` can resolve the tightest containing block in one pass.
        """
        instances: list[BlockInstance] = []
        run_blocks = [b for b in self._blocks if b.mode == BlockMode.RUN]
        stack_blocks = [b for b in self._blocks if b.mode != BlockMode.RUN]

        if stack_blocks:
            instances.extend(self._scan_nested(lines, stack_blocks, 1, len(lines), 0))
        for block in run_blocks:
            instances.extend(self._scan_runs(lines, block, 1, len(lines)))
        return instances

    def _scan_nested(
        self,
        lines: list[str],
        candidates: list[BlockPattern],
        first: int,
        last: int,
        depth: int,
    ) -> list[BlockInstance]:
        """Find instances of ``candidates`` between two line numbers, recursively."""
        found: list[BlockInstance] = []
        line_no = first
        while line_no <= last:
            raw_line = lines[line_no - 1]
            stripped = raw_line.strip()
            if not stripped or self.is_comment(stripped):
                line_no += 1
                continue
            block, match = self._match_block(candidates, stripped)
            if block is None or match is None:
                line_no += 1
                continue

            end = self._block_end(lines, block, line_no, last)
            key, value = self._instance_value(block, match, stripped)
            instance = BlockInstance(
                block=block,
                key=key,
                value=value,
                line_start=line_no,
                line_end=end,
                anchor_line=stripped,
                depth=depth,
            )
            found.append(instance)
            if block.blocks and end > line_no:
                nested = self._scan_nested(
                    lines, block.blocks, line_no + 1, end, depth + 1
                )
                found.extend(nested)
            line_no = end + 1
        return found

    def _scan_runs(
        self, lines: list[str], block: BlockPattern, first: int, last: int
    ) -> list[BlockInstance]:
        """Group consecutive lines sharing a captured key into one instance.

        Junos ``set`` and PAN-OS ``set`` output repeats the object name on every
        line: ``set interfaces ge-0/0/0 unit 0 ...``. Contiguity is the grouping
        signal because both platforms emit an object's lines together; a
        non-contiguous repeat of the same key becomes a second instance rather
        than being merged, which keeps the span honest.
        """
        found: list[BlockInstance] = []
        current: BlockInstance | None = None
        for line_no in range(first, last + 1):
            stripped = lines[line_no - 1].strip()
            if not stripped or self.is_comment(stripped):
                continue
            match = block.regex.match(stripped)
            if match is None:
                current = None
                continue
            key, value = self._instance_value(block, match, stripped)
            if current is not None and current.key == key:
                current.line_end = line_no
                continue
            current = BlockInstance(
                block=block,
                key=key,
                value=value,
                line_start=line_no,
                line_end=line_no,
                anchor_line=stripped,
            )
            found.append(current)
        return found

    def _block_end(
        self, lines: list[str], block: BlockPattern, anchor_line: int, limit: int
    ) -> int:
        """Return the last line number belonging to a block instance."""
        if block.mode == BlockMode.DELIMITED:
            return self._end_delimited(lines, block, anchor_line, limit)
        if block.mode == BlockMode.BRACE:
            return self._end_brace(lines, anchor_line, limit)
        return self._end_indent(lines, anchor_line, limit)

    def _end_indent(self, lines: list[str], anchor_line: int, limit: int) -> int:
        """Indentation-scoped extent: ends at the first line not indented further.

        A bare comment marker also terminates the stanza, which is how Cisco
        writes ``show running-config``. ``exit`` is deliberately *not* special-cased
        - it is more indented than its anchor, so indentation alone already keeps
        it inside the right block, and treating it as a terminator would close an
        outer block on an inner block's ``exit``.
        """
        anchor_indent = indent_of(lines[anchor_line - 1])
        end = anchor_line
        for line_no in range(anchor_line + 1, limit + 1):
            raw_line = lines[line_no - 1]
            stripped = raw_line.strip()
            if not stripped:
                continue
            if self.is_comment(stripped):
                break
            if indent_of(raw_line) <= anchor_indent:
                break
            end = line_no
        return end

    def _end_delimited(
        self, lines: list[str], block: BlockPattern, anchor_line: int, limit: int
    ) -> int:
        """Explicit-terminator extent, counting nested opens of the same block."""
        assert block.end_regex is not None  # guaranteed by the pack loader
        depth = 1
        for line_no in range(anchor_line + 1, limit + 1):
            stripped = lines[line_no - 1].strip()
            if not stripped:
                continue
            if block.regex.match(stripped):
                depth += 1
                continue
            if block.end_regex.match(stripped):
                depth -= 1
                if depth == 0:
                    return line_no
        return limit

    def _end_brace(self, lines: list[str], anchor_line: int, limit: int) -> int:
        """Curly-brace extent, depth-counted across lines (Junos)."""
        depth = 0
        for line_no in range(anchor_line, limit + 1):
            stripped = lines[line_no - 1].strip()
            if self.is_comment(stripped):
                continue
            depth += stripped.count("{") - stripped.count("}")
            if line_no > anchor_line and depth <= 0:
                return line_no
            if line_no == anchor_line and depth <= 0:
                return line_no  # single-line statement, no block opened
        return limit

    @staticmethod
    def _match_block(
        candidates: list[BlockPattern], stripped: str
    ) -> tuple[BlockPattern | None, re.Match[str] | None]:
        """Return the first candidate block whose anchor matches this line."""
        for block in candidates:
            match = block.regex.match(stripped)
            if match is not None:
                return block, match
        return None, None

    @staticmethod
    def _instance_value(
        block: BlockPattern, match: re.Match[str], stripped: str
    ) -> tuple[str, Any]:
        """Derive a block instance's grouping key and its anchor fact value."""
        value = coerce_value(
            block.anchor_coercion,
            match,
            stripped,
            block.anchor_group,
            literal=block.anchor_literal,
        )
        if value is SKIP:
            return stripped, stripped
        if isinstance(value, list):
            joined = " ".join(str(v) for v in value)
            return joined, value
        return str(value), value

    @staticmethod
    def enclosing(
        instances: list[BlockInstance], line_no: int
    ) -> list[BlockInstance]:
        """Return the instances containing a line, innermost first."""
        hits = [i for i in instances if i.contains(line_no)]
        hits.sort(key=lambda i: (-i.depth, i.line_end - i.line_start, i.line_start))
        return hits
