"""Directive polarity — the check that a ``no``-prefixed command means what the path says.

``negated_bool`` answers one question: *was this command prefixed with ``no``?*
For the directive it was written for that is the same question as "is the feature
on", because the directive names the feature — ``logging on`` emits
``logging.on``, ``ip routing`` emits ``routing.ip_routing``, and 71 patterns
across the library are built that way and are correct.

It is the wrong question for a directive that *disables*. ``shutdown`` turns a
thing off by being present, so ``negated_bool`` on it returns True for the
hardened state. Whether that is a bug depends entirely on what the path is named
after:

* ``vlan.shutdown`` is named after the directive. True means "shutdown is set",
  which is what the fact says and what a rule reading it expects. Correct.
* ``mgmt.telnet.enabled`` is named after the service. True means "telnet is
  running" — the opposite of what a bare ``shutdown`` line establishes. Inverted.

That second case shipped. Three packs carried it, and on Arista it reached a
verdict: DISA NDM control V-255952 asks for ``mgmt.telnet.enabled == false``, and
the fixture's shut-down telnet stanza was read as ``true``, so a hardened switch
was reported non-compliant — and a switch actually running telnet (``no
shutdown`` → ``false``) would have been reported clean. The visible half was the
harmless direction, so the wrong verdict was read as a true finding and written
into the mapping pack's header as one. The dangerous half was never exercised,
because no fixture ran telnet.

The other two sites were latent rather than live: ``mgmt.restconf.enabled`` on
EOS, and ``interface.admin_state`` on EOS, ASA and NX-OS. No rule reads either
path today, so neither produced a wrong verdict — but ``interface.admin_state``
was also emitting a bool onto a path whose vocabulary everywhere else, including
its own pack's ``child_defaults``, is the string ``shutdown``/``no-shutdown``. A
rule written against either representation would have silently missed the ports
that used the other.

This lives in its own module rather than in ``test_pattern_packs.py`` because
that file is already over the 500-line budget and the ratchet in
``tests/test_deliverable_limits.py`` does not let an over-budget file grow.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from backend.ingest.patterns import (
    PATTERNS_DIR,
    Coercion,
    Emission,
    LinePattern,
    PatternPack,
    load_pattern_pack,
    walk_blocks,
)

#: Directives whose *presence* turns a feature off. Add one here if a pack starts
#: parsing it — the gate is only as wide as this tuple.
_INVERTING_DIRECTIVES = ("shutdown",)


def _pack_files() -> list[Path]:
    """Every pattern pack on disk, in a stable order."""
    return sorted(PATTERNS_DIR.glob("*.yaml"))


def _pack_ids() -> list[str]:
    return [path.stem for path in _pack_files()]


def _inverted_negated_bools(pack: PatternPack) -> list[str]:
    """Every ``negated_bool`` whose directive and path disagree about polarity.

    Matching is behavioural — the compiled regex is asked whether it accepts the
    bare directive — rather than textual. That is deliberate: the compiled regex
    is the thing that actually runs, and picking the literal back out of a
    pattern carrying an optional ``(?P<neg>no\\s+)?`` group would be its own
    source of error, in a check whose whole job is catching authoring mistakes.
    """
    problems: list[str] = []

    def check(pattern: LinePattern, context: str) -> None:
        for directive in _INVERTING_DIRECTIVES:
            if not pattern.regex.match(directive):
                continue
            for emission in pattern.emits:
                if emission.coercion != Coercion.NEGATED_BOOL:
                    continue
                if emission.path.rsplit(".", 1)[-1] == directive:
                    continue
                problems.append(
                    f"{context}:{pattern.id} reads '{directive}' with "
                    f"'negated_bool' onto '{emission.path}'. A bare "
                    f"'{directive}' emits True, which reports the feature as ON "
                    f"when that line turns it OFF. Split the directive and its "
                    f"'no' form into two patterns with explicit 'value: true' "
                    f"and 'value: false'."
                )

    for pattern in pack.patterns:
        check(pattern, "top-level")
    for block in walk_blocks(pack.blocks):
        for child in block.children:
            check(child, block.id)
    return problems


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_negated_bool_is_not_used_on_an_inverting_directive(path: Path) -> None:
    """A disabling directive must not be read with ``negated_bool``.

    The module docstring records the three sites where this shipped and what each
    one cost. The 71 other ``negated_bool`` uses in the library are correctly
    polarised because their directive names the feature being enabled; those are
    the ones this gate must leave alone, and
    ``test_the_gate_is_discriminating_not_merely_loud`` is what proves it does.
    """
    pack = load_pattern_pack(path)
    problems = _inverted_negated_bools(pack)
    assert not problems, f"{path.name}: " + "; ".join(problems)


def test_the_gate_is_discriminating_not_merely_loud() -> None:
    """Proof the gate has teeth, on the exact pattern that shipped broken.

    A gate that only ever passes is indistinguishable from one that cannot fail,
    and this one now passes against the whole library by construction. So it is
    re-run here against the original authoring, and against the two neighbours
    that must stay clean — the directive-named path and the enabling directive —
    because a check that flagged those would be worse than no check: it would
    push someone to "fix" 71 correct patterns.
    """
    broken = LinePattern(
        id="eos_telnet_shutdown",
        regex=re.compile(r"^(?P<neg>no\s+)?shutdown\s*$"),
        emits=(Emission(path="mgmt.telnet.enabled", coercion=Coercion.NEGATED_BOOL),),
    )
    named_for_the_directive = LinePattern(
        id="vlan_shutdown",
        regex=re.compile(r"^(?P<neg>no\s+)?shutdown\s*$"),
        emits=(Emission(path="vlan.shutdown", coercion=Coercion.NEGATED_BOOL),),
    )
    enabling_directive = LinePattern(
        id="logging_on",
        regex=re.compile(r"^(?P<neg>no\s+)?logging on\s*$"),
        emits=(Emission(path="logging.on", coercion=Coercion.NEGATED_BOOL),),
    )
    template = load_pattern_pack(_pack_files()[0])

    def problems_for(pattern: LinePattern) -> list[str]:
        return _inverted_negated_bools(replace(template, patterns=(pattern,), blocks=()))

    assert len(problems_for(broken)) == 1, (
        "the gate no longer catches the defect it was written for"
    )
    assert "mgmt.telnet.enabled" in problems_for(broken)[0]
    assert not problems_for(named_for_the_directive), (
        "vlan.shutdown is named after the directive, so negated_bool is correct "
        "there and the gate must not flag it"
    )
    assert not problems_for(enabling_directive), (
        "'logging on' enables the feature it names, which is the polarity "
        "negated_bool exists for"
    )


def test_the_shutdown_directive_is_parsed_somewhere() -> None:
    """The gate is only meaningful while some pack still parses ``shutdown``.

    If every pack stopped emitting it, this module would pass forever without
    inspecting anything, and the next pack to reintroduce the pairing would land
    against a green suite that had quietly stopped looking.
    """
    parsing = []
    for path in _pack_files():
        pack = load_pattern_pack(path)
        patterns = list(pack.patterns)
        for block in walk_blocks(pack.blocks):
            patterns.extend(block.children)
        if any(p.regex.match("shutdown") for p in patterns):
            parsing.append(path.stem)
    assert parsing, (
        "no pack parses a bare 'shutdown' line any more, so "
        "test_negated_bool_is_not_used_on_an_inverting_directive inspects "
        "nothing. Either the directive moved, or this module should be retired."
    )
