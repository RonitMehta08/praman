"""Fact index — the read side of the canonical model contract.

Rules never touch a raw ``list[CanonicalFact]``. They go through ``FactIndex``,
which gives them three things the raw list cannot:

* **Path lookup** in constant time, so a rule pack with 2000 rules over a config
  with 3000 facts stays linear rather than quadratic.
* **Tri-state absence**, distinguishing "the parser looked and the setting is
  off" from "the parser produced nothing for this path". The second case must
  never be reported as a pass (GLOBAL_RULESET R4.2).
* **Block grouping**, so a rule can ask "for each interface, does this interface
  also have an inbound ACL". Blocks are recovered from the six-field provenance
  already on every fact - a sub-fact's line falls inside its block fact's
  ``[line_start, line_end]`` span - so no field is added to the frozen canonical
  model to support it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from backend.canonical.models import CanonicalFact


def is_block_anchor(fact: CanonicalFact) -> bool:
    """True when a fact anchors a configuration block.

    Block-ness is read off the provenance rather than from a hardcoded list of
    paths, because a list would have to be edited in Python every time a pattern
    pack introduced a block type - exactly the "manual code modification" C5
    rules out. Two provenance fields identify an anchor between them:

    * a **multi-line span**, which only a block fact has: an ordinary line fact
      records ``line_start == line_end``;
    * **present=True**, which separates the anchor from the per-instance defaults
      that ``generic.py`` stamps with the same span so a report can still point
      at the right stanza. Without this second test, the defaulted
      ``interface.cdp_enabled`` on a port with no ``cdp`` line would masquerade
      as a block of its own.

    ``tests`` asserts this predicate recovers exactly the anchor paths each
    pattern pack declares, so the invariant is machine-checked rather than
    merely asserted here.
    """
    return fact.present and fact.line_end > fact.line_start


class FactBlock:
    """A configuration block and the facts that fall inside its line span."""

    __slots__ = ("anchor", "facts")

    def __init__(self, anchor: CanonicalFact) -> None:
        self.anchor = anchor
        self.facts: list[CanonicalFact] = [anchor]

    @property
    def label(self) -> str:
        """Human-readable block name, taken verbatim from the anchor's raw text."""
        return self.anchor.raw_text.splitlines()[0].strip() if self.anchor.raw_text else ""

    def get(self, path: str) -> list[CanonicalFact]:
        """Return the facts in this block at ``path``."""
        return [fact for fact in self.facts if fact.path == path]

    def has(self, path: str) -> bool:
        """True when the block contains at least one fact at ``path``."""
        return any(fact.path == path for fact in self.facts)


class FactIndex:
    """Indexed, read-only view over one device's canonical facts."""

    __slots__ = ("_blocks", "_by_path", "_facts")

    def __init__(self, facts: Iterable[CanonicalFact]) -> None:
        self._facts: list[CanonicalFact] = list(facts)
        by_path: dict[str, list[CanonicalFact]] = defaultdict(list)
        for fact in self._facts:
            by_path[fact.path].append(fact)
        self._by_path: dict[str, list[CanonicalFact]] = dict(by_path)
        self._blocks: dict[str, list[FactBlock]] | None = None

    @property
    def facts(self) -> list[CanonicalFact]:
        """Every fact, in parse order."""
        return self._facts

    @property
    def paths(self) -> frozenset[str]:
        """The set of paths this device produced at least one fact for."""
        return frozenset(self._by_path)

    def get(self, path: str) -> list[CanonicalFact]:
        """Return every fact at ``path``, or an empty list."""
        return self._by_path.get(path, [])

    def first(self, path: str) -> CanonicalFact | None:
        """Return the first fact at ``path``, or None when the parser saw none."""
        found = self._by_path.get(path)
        return found[0] if found else None

    def values(self, path: str) -> list[Any]:
        """Return every value observed at ``path``."""
        return [fact.value for fact in self._by_path.get(path, [])]

    def has(self, path: str) -> bool:
        """True when the parser produced at least one fact at ``path``.

        False means the evidence is *missing*, not that the setting is disabled.
        Callers must map False to UNKNOWN unless the rule explicitly treats
        absence as a verdict.
        """
        return path in self._by_path

    def blocks(self, block_path: str) -> list[FactBlock]:
        """Return the configuration blocks anchored at ``block_path``.

        Each returned block owns the facts whose line span falls inside the
        anchor's span. Nested facts are attributed to the innermost containing
        block so a VTY sub-command is not also claimed by an enclosing block.
        """
        if self._blocks is None:
            self._blocks = self._build_blocks()
        return self._blocks.get(block_path, [])

    def _build_blocks(self) -> dict[str, list[FactBlock]]:
        """Group facts into blocks using line-span containment."""
        anchors = [fact for fact in self._facts if is_block_anchor(fact)]
        # Innermost-first so a fact is attributed to the tightest enclosing block.
        anchors.sort(key=lambda f: (f.line_end - f.line_start, f.line_start))

        blocks = [FactBlock(anchor) for anchor in anchors]
        claimed: set[int] = {id(anchor) for anchor in anchors}
        for fact in self._facts:
            if id(fact) in claimed:
                continue
            for block in blocks:
                if block.anchor.line_start <= fact.line_start <= block.anchor.line_end:
                    block.facts.append(fact)
                    claimed.add(id(fact))
                    break

        grouped: dict[str, list[FactBlock]] = defaultdict(list)
        for block in blocks:
            block.facts.sort(key=lambda f: (f.line_start, f.path))
            grouped[block.anchor.path].append(block)
        for block_list in grouped.values():
            block_list.sort(key=lambda b: b.anchor.line_start)
        return dict(grouped)
