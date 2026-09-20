"""Abstract base class for vendor config parsers.

Every vendor adapter implements this ABC and writes ONLY to the Canonical Model
(Device + list[CanonicalFact]). No adapter imports or references any control ID,
framework, or rule — that would violate the decoupling boundary (SPINE §4).
"""

from __future__ import annotations

import abc
from typing import Any

from backend.canonical.models import CanonicalFact, Device, Vendor


class ParseResult:
    """Container for one parsed config file.

    Attributes:
        device: The Device record with identity fields populated.
        facts: Flat list of CanonicalFact records extracted from the config.
        unparsed_lines: Lines the parser could not map to a canonical path.
                        These feed the AI escalation ladder (§18).
    """

    __slots__ = ("device", "facts", "unparsed_lines")

    def __init__(
        self,
        device: Device,
        facts: list[CanonicalFact],
        unparsed_lines: list[dict[str, Any]] | None = None,
    ) -> None:
        self.device = device
        self.facts = facts
        self.unparsed_lines = unparsed_lines or []


class VendorAdapter(abc.ABC):
    """Abstract base class for vendor config parsers.

    Subclass contract:
        1. Implement vendor_id() → the Vendor enum value.
        2. Implement can_parse(raw_text, filename) → True if this adapter handles it.
        3. Implement parse(raw_text, source_file) → ParseResult.
        4. Every CanonicalFact MUST carry all six provenance fields.
        5. confidence = 1.0 for all deterministic parse results.
    """

    @abc.abstractmethod
    def vendor_id(self) -> Vendor:
        """Return the canonical Vendor enum for this adapter."""

    @abc.abstractmethod
    def can_parse(self, raw_text: str, filename: str) -> bool:
        """Return True if this adapter can handle the given config text.

        Heuristic detection — look for vendor-specific markers in the text.
        """

    @abc.abstractmethod
    def parse(self, raw_text: str, source_file: str) -> ParseResult:
        """Parse a config file into a Device + list of CanonicalFacts.

        Args:
            raw_text: The full config text (already decoded to UTF-8, NFKC-normalised).
            source_file: The original filename (for provenance).

        Returns:
            ParseResult containing the device record, facts, and any unparsed lines.

        Raises:
            ParseError: When the config cannot be parsed at all.
        """

    def _make_fact(
        self,
        path: str,
        value: Any,
        present: bool,
        source_file: str,
        line_start: int,
        line_end: int,
        raw_text: str,
    ) -> CanonicalFact:
        """Helper to build a CanonicalFact with full provenance and confidence=1.0."""
        return CanonicalFact(
            path=path,
            value=value,
            present=present,
            source_file=source_file,
            line_start=line_start,
            line_end=line_end,
            raw_text=raw_text,
            parser_id=self._parser_id(),
            confidence=1.0,
        )

    @abc.abstractmethod
    def _parser_id(self) -> str:
        """Return the parser_id string, e.g. 'netutils.cisco_ios@1.18.0'."""
