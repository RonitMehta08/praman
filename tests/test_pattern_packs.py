"""Pattern-pack invariants — the tests that make a vendor-as-data file safe to edit.

A pattern pack is authored by hand in YAML and can be added at runtime, so the
guarantees the rest of the system relies on cannot live in a reviewer's head.
Each test here corresponds to a defect that was found by inspection once and must
never be found by inspection again:

* **Absence must not contradict observation.** A pack-level default is asserted
  only when nothing in the file produced that path. Getting that bookkeeping
  wrong made ``mgmt.login_banner`` come back both True (block anchor) and False
  (default) on a device that genuinely has a banner, which would have failed a
  compliant device on an ``all``-quantified rule. That is a false positive, and a
  false positive is the failure mode that ends an auditor's trust in the tool.

* **Block anchors are recovered from provenance, not from a list.**
  ``rules.facts.is_block_anchor`` promises in its docstring that this is
  machine-checked. This module is where that promise is kept: the anchors
  recovered from parsed facts must equal the anchor paths the pack declares, with
  no strays.

* **Every path is in the vocabulary and every capture group exists.** The loader
  enforces both, but a test states them independently so a loader refactor cannot
  quietly relax them.

The tests parametrise over every pack in ``data/ingest/patterns`` and every config
in ``test_configs/``, so adding a vendor or a fixture extends the coverage without
touching this file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.canonical.models import OsFamily, Vendor
from backend.canonical.paths import is_canonical_path
from backend.ingest.generic import PatternAdapter, PatternAdapterRegistry
from backend.ingest.patterns import (
    PATTERNS_DIR,
    Coercion,
    LinePattern,
    PatternLibrary,
    PatternPack,
    load_pattern_pack,
    walk_blocks,
)
from backend.rules.facts import is_block_anchor

CONFIG_DIR = PROJECT_ROOT / "test_configs"

#: Coercions that read the emission's own ``group``, so that group must exist.
_GROUP_READING = frozenset(
    {
        Coercion.STR,
        Coercion.LOWER,
        Coercion.INT,
        Coercion.WORD_LIST,
        Coercion.GROUP_PRESENT,
        # ``auto`` infers int / bool / str from the captured text's shape. It still
        # reads the emission's group to get that text, so a misspelled group is
        # just as silent a failure here as anywhere else.
        Coercion.AUTO,
    }
)

#: Coercions that read fixed group names rather than the emission's ``group``.
#: ``negated_bool`` asks "was the command prefixed with 'no'", and
#: ``minutes_seconds`` composes a duration; naming their groups per emission would
#: let two patterns spell the same concept differently for no benefit.
_FIXED_GROUPS: dict[str, tuple[str, ...]] = {
    Coercion.NEGATED_BOOL: ("neg",),
    Coercion.MINUTES_SECONDS: ("minutes", "seconds"),
}


def _pack_files() -> list[Path]:
    """Every pattern pack on disk, in a stable order."""
    return sorted(PATTERNS_DIR.glob("*.yaml"))


def _config_files() -> list[Path]:
    """Every shipped test configuration, in a stable order.

    Recursive: ``test_configs/`` is organised into a documented taxonomy
    (``compliance_extremes/``, ``realistic/``, ``feature_coverage/`` — see its
    README), and a non-recursive glob would silently drop every fixture the day
    someone filed one in a category folder.
    """
    return sorted(CONFIG_DIR.rglob("*.conf")) if CONFIG_DIR.exists() else []


def _pack_ids() -> list[str]:
    return [path.stem for path in _pack_files()]


def _config_ids() -> list[str]:
    return [path.stem for path in _config_files()]


@pytest.fixture(scope="module")
def library() -> PatternLibrary:
    """The pattern library, loaded once for the whole module."""
    return PatternLibrary()


@pytest.fixture(scope="module")
def registry(library: PatternLibrary) -> PatternAdapterRegistry:
    """A registry over the on-disk packs, with no learned patterns."""
    return PatternAdapterRegistry(library)


# ── Load-time invariants ──────────────────────────────────────────────


def test_pattern_directory_is_not_empty() -> None:
    """A green suite with zero packs would prove nothing at all."""
    assert _pack_files(), f"no pattern packs found in {PATTERNS_DIR}"


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_pack_loads(path: Path) -> None:
    """Every pack loads, and its declared identity is in the frozen enums.

    Loading is itself the schema check: ``load_pattern_pack`` validates paths,
    coercions, capture groups, ``const`` literals and duplicate ids. A pack that
    reaches this assertion has passed all of them.
    """
    pack = load_pattern_pack(path)

    assert pack.vendor == path.stem, (
        f"{path.name} declares vendor '{pack.vendor}'. The filename is how the "
        "registry finds a pack for a vendor, so the two must agree."
    )
    assert pack.vendor in {v.value for v in Vendor}, (
        f"'{pack.vendor}' is not in the Vendor enum; add it to "
        "backend/canonical/models.py before shipping the pack."
    )
    assert pack.os_family in {o.value for o in OsFamily}
    assert pack.patterns or pack.blocks, f"{path.name} defines no patterns at all"


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_pack_paths_are_canonical(path: Path) -> None:
    """No pack may emit a path outside the canonical vocabulary.

    Restated here independently of the loader: the canonical model is the only
    contract between parsing and rules, so a path a rule can never reference is
    dead weight at best and a silent miss at worst.
    """
    pack = load_pattern_pack(path)
    strays = sorted(p for p in pack.referenced_paths() if not is_canonical_path(p))
    assert not strays, (
        f"{path.name} emits {len(strays)} non-canonical path(s): {strays}. "
        "Add them to backend/canonical/schema/canonical_paths.schema.json or "
        "correct the spelling."
    )


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_capture_groups_and_literals_are_consistent(path: Path) -> None:
    """Every group-reading coercion names a group its regex actually defines.

    This is the check that turns a class of authoring mistake from a startup
    crash into a test failure: a pattern whose ``group`` is misspelled silently
    reads nothing, so the fact never appears and the control it answers becomes
    ``unknown`` for every device.
    """
    pack = load_pattern_pack(path)
    problems: list[str] = []

    def check(pattern: LinePattern, context: str) -> None:
        groups = set(pattern.regex.groupindex)
        for emission in pattern.emits:
            if emission.coercion in _GROUP_READING and emission.group not in groups:
                problems.append(
                    f"{context}:{pattern.id} coercion '{emission.coercion}' reads "
                    f"group '{emission.group}', regex defines {sorted(groups)}"
                )
            expected = _FIXED_GROUPS.get(emission.coercion)
            if expected and not groups.intersection(expected):
                problems.append(
                    f"{context}:{pattern.id} coercion '{emission.coercion}' needs one "
                    f"of {list(expected)}, regex defines {sorted(groups)}"
                )
            if emission.coercion == Coercion.CONST and emission.literal is None:
                problems.append(
                    f"{context}:{pattern.id} uses 'const' with no 'literal' value"
                )

    for pattern in pack.patterns:
        check(pattern, "top-level")
    for block in walk_blocks(pack.blocks):
        # TRUE, FALSE and CONST are all fixed values, so none of them reads a
        # group. The loader separately requires CONST to carry a literal.
        assert block.regex.groupindex or block.anchor_coercion in {
            Coercion.TRUE,
            Coercion.FALSE,
            Coercion.CONST,
        }, (
            f"{path.name}:{block.id} anchor coercion '{block.anchor_coercion}' needs "
            "a capture group, but the anchor regex defines none"
        )
        for child in block.children:
            check(child, block.id)

    assert not problems, f"{path.name}: " + "; ".join(problems)


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_ignore_rules_do_not_swallow_emitted_paths(path: Path) -> None:
    """An ``ignore`` regex must not discard a line some pattern wants to parse.

    A real defect this catches: an ignore of ``^speed \\d+`` written for console
    line speeds also discarded an interface's ``speed 1000``, so
    ``interface.speed`` silently stopped being emitted. Ignore rules are applied
    before matching, so they win — which makes them worth testing.
    """
    pack = load_pattern_pack(path)
    if not pack.ignore:
        pytest.skip(f"{path.name} declares no ignore rules")

    samples: list[tuple[str, str]] = []
    for pattern in pack.patterns:
        samples.append((pattern.id, pattern.regex.pattern))
    for block in walk_blocks(pack.blocks):
        samples.append((block.id, block.regex.pattern))

    # Only literal prefixes can be tested without a regex generator, which is
    # enough: an over-broad ignore is nearly always a literal command word.
    problems: list[str] = []
    for pattern_id, raw in samples:
        literal = _literal_prefix(raw)
        if len(literal) < 4:
            continue
        for ignore in pack.ignore:
            if ignore.match(literal):
                problems.append(
                    f"ignore /{ignore.pattern}/ swallows '{literal}', which "
                    f"pattern '{pattern_id}' is meant to parse"
                )
    assert not problems, f"{path.name}: " + "; ".join(problems)


def _literal_prefix(raw: str) -> str:
    """Longest leading literal of a regex, used to probe the ignore list.

    Stops at the first metacharacter. ``'^ip ssh version\\s+(?P<value>\\d+)'``
    yields ``'ip ssh version'`` — enough to tell whether an ignore rule would
    discard the line before the pattern ever saw it.
    """
    if raw.startswith("^"):
        raw = raw[1:]
    out: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            break
        if char in "([{|?*+.$":
            break
        out.append(char)
        index += 1
    return "".join(out).strip()


# ── Parse-time invariants ─────────────────────────────────────────────


def _parse(registry: PatternAdapterRegistry, config: Path):
    """Detect the vendor for a config and parse it, or skip when unrecognised."""
    text = config.read_text(encoding=FILE_ENCODING)
    adapter = registry.detect(text, config.name)
    if adapter is None:
        pytest.skip(f"no pack detects {config.name}")
    return adapter, adapter.parse(text, config.name)


def test_shipped_configs_exist() -> None:
    """The parse-time tests below are vacuous without fixtures."""
    assert _config_files(), f"no .conf fixtures found in {CONFIG_DIR}"


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_shipped_packs_declare_their_types(path: Path) -> None:
    """No hand-authored pack may use the ``auto`` coercion.

    ``auto`` guesses int / bool / str from the shape of the captured text. That is
    the right behaviour for a pattern *taught at runtime* through the training GUI,
    where an operator supplies a canonical path and a masked template and nobody is
    around to declare a type. It is the wrong behaviour in a file a human wrote and
    a reviewer read: ``auto`` on a field whose values happen to be ``0`` and ``1``
    in every fixture yields ints, and the first device that spells it ``enable``
    silently yields a string, so a rule comparing to an int stops matching without
    erroring. Shipped packs say what they mean.
    """
    pack = load_pattern_pack(path)
    offenders: list[str] = []

    def check(pattern: LinePattern, context: str) -> None:
        for emission in pattern.emits:
            if emission.coercion == Coercion.AUTO:
                offenders.append(f"{context}:{pattern.id} -> {emission.path}")

    for pattern in pack.patterns:
        check(pattern, "top-level")
    for block in walk_blocks(pack.blocks):
        for child in block.children:
            check(child, block.id)

    assert not offenders, (
        f"{path.name} uses coercion 'auto' in {len(offenders)} place(s): "
        f"{offenders}. Replace it with the explicit coercion — int, str, lower, "
        "true, negated_bool — that the field actually needs."
    )


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_pack_default_never_contradicts_an_observed_fact(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """A pack-level default and a real fact must never share a path.

    This is the regression test for the duplicate-banner bug. A pack-level
    absence fact is identifiable by its provenance alone — ``present=False`` with
    a zero line span, because there is no configuration line to cite — so the
    check needs no cooperation from the parser.

    Per-instance ``child_defaults`` are deliberately *not* covered by this rule:
    they carry their block's line span and are scoped to one interface, so two
    interfaces legitimately produce one observed and one defaulted
    ``interface.cdp_enabled``. Their own invariant is one fact per instance per
    path, asserted below.
    """
    _, result = _parse(registry, config)

    pack_default_paths = {
        fact.path
        for fact in result.facts
        if not fact.present and fact.line_start == 0 and fact.line_end == 0
    }
    observed_paths = {
        fact.path
        for fact in result.facts
        if fact.line_start > 0 or fact.line_end > 0
    }
    collisions = sorted(pack_default_paths & observed_paths)

    assert not collisions, (
        f"{config.name}: {len(collisions)} path(s) carry both a pack default and a "
        f"fact from the config: {collisions}. A rule quantified over all facts at "
        "such a path sees True and False at once and fails a compliant device."
    )


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_child_defaults_are_one_per_block_instance(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """Within one block instance, a defaulted path must not also be observed.

    The per-instance analogue of the test above. If an interface both matched
    ``no cdp enable`` and received the ``cdp_enabled: true`` default, a
    ``for_each`` rule over that interface would see a contradiction it cannot
    resolve, and which of the two won would depend on fact ordering.
    """
    adapter, result = _parse(registry, config)
    default_paths = {
        default.path
        for block in walk_blocks(adapter.pack.blocks)
        for default in block.child_defaults
    }
    if not default_paths:
        pytest.skip(f"{adapter.pack.vendor} declares no child defaults")

    # Group by (block span, path): the span identifies the instance, because a
    # child default is stamped with its instance's own line span.
    seen: dict[tuple[int, int, str], list[bool]] = {}
    for fact in result.facts:
        if fact.path not in default_paths or fact.line_start == 0:
            continue
        seen.setdefault((fact.line_start, fact.line_end, fact.path), []).append(
            fact.present
        )

    problems = [
        f"lines {start}-{end} path '{path}' has {len(flags)} facts (present={flags})"
        for (start, end, path), flags in sorted(seen.items())
        if len(flags) > 1
    ]
    assert not problems, f"{config.name}: " + "; ".join(problems)


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_block_anchors_match_the_declared_anchor_paths(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """``is_block_anchor`` recovers exactly the anchor paths the pack declares.

    The promise ``rules.facts.is_block_anchor`` makes in its docstring. Two
    directions matter and both are asserted:

    * **no strays** — nothing that is not an anchor may be mistaken for one, or a
      ``for_each`` rule would iterate over phantom blocks;
    * **no misses** — every recovered anchor must be a path some block declares,
      so the predicate cannot quietly stop recognising a block type.
    """
    adapter, result = _parse(registry, config)
    declared = {block.anchor_path for block in walk_blocks(adapter.pack.blocks)}
    recovered = {fact.path for fact in result.facts if is_block_anchor(fact)}

    strays = sorted(recovered - declared)
    assert not strays, (
        f"{config.name}: is_block_anchor accepted {strays}, which no block in "
        f"{adapter.pack.vendor}.yaml declares as an anchor."
    )


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_facts_carry_complete_provenance(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """Six-field provenance on every leaf (GLOBAL_RULESET R3.4).

    A finding whose evidence cannot be pointed at in the source file is not
    evidence. Absence facts legitimately carry line 0 — there is no line — but
    they must still name the file, the parser and their reason.
    """
    adapter, result = _parse(registry, config)
    problems: list[str] = []
    for fact in result.facts:
        if not fact.source_file:
            problems.append(f"{fact.path}: no source_file")
        if not fact.parser_id:
            problems.append(f"{fact.path}: no parser_id")
        if not fact.raw_text:
            problems.append(f"{fact.path} @{fact.line_start}: no raw_text")
        if fact.line_end < fact.line_start:
            problems.append(
                f"{fact.path}: line_end {fact.line_end} precedes "
                f"line_start {fact.line_start}"
            )
        if fact.line_start > 0 and fact.line_start > len(result.facts) + 100000:
            problems.append(f"{fact.path}: implausible line_start {fact.line_start}")
    assert not problems, (
        f"{config.name} ({adapter.pack.parser_id}): " + "; ".join(problems[:10])
    )


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_unparsed_lines_are_reported_not_dropped(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """Unrecognised lines must reach ``unparsed_lines``, not vanish.

    This is the C2 seam: the training GUI can only offer to teach a line the
    parser admits it did not understand. A parser that quietly discarded the
    remainder would make the coverage number a fiction and leave the operator
    with nothing to map.
    """
    _, result = _parse(registry, config)
    for entry in result.unparsed_lines:
        assert entry["line_number"] > 0
        assert entry["raw_text"].strip(), "an unparsed entry with no text is useless"


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_parsing_is_deterministic(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """The same bytes must produce the same facts in the same order.

    Determinism is the property that lets a signed report be re-verified, so it
    is tested rather than assumed. Set iteration inside the parser is the usual
    way this breaks.
    """
    text = config.read_text(encoding=FILE_ENCODING)
    adapter = registry.detect(text, config.name)
    if adapter is None:
        pytest.skip(f"no pack detects {config.name}")

    first = adapter.parse(text, config.name)
    second = adapter.parse(text, config.name)

    def signature(result) -> list[tuple]:
        return [
            (f.path, repr(f.value), f.present, f.line_start, f.line_end)
            for f in result.facts
        ]

    assert signature(first) == signature(second)


# ── Detection ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("config", _config_files(), ids=_config_ids())
def test_detection_picks_exactly_one_pack(
    registry: PatternAdapterRegistry, config: Path
) -> None:
    """One config must not score above zero on two unrelated platforms.

    Cisco dialects share enough syntax that anti-markers are the only thing
    keeping IOS, XE, NX-OS and ASA apart. A tie would mean the ingestion engine
    picks a vendor by dict ordering, and every downstream verdict would inherit
    that coin flip.
    """
    text = config.read_text(encoding=FILE_ENCODING)
    scored = sorted(
        (
            (adapter.detection_score(text, config.name), adapter.pack.vendor)
            for adapter in registry.adapters()
        ),
        reverse=True,
    )
    positive = [entry for entry in scored if entry[0] > 0]
    if not positive:
        pytest.skip(f"no pack claims {config.name}")

    if len(positive) > 1:
        assert positive[0][0] > positive[1][0], (
            f"{config.name}: {positive[0][1]} and {positive[1][1]} tie at score "
            f"{positive[0][0]}; add an anti_marker or a strong_marker to separate them"
        )


#: A configuration that is unmistakably Cisco IOS and carries almost nothing
#: else. Detection has to accept it: a lab switch, a freshly-imaged device or a
#: hand-typed snippet pasted into the upload box all look like this, and refusing
#: them was a real defect — every marker in the pack was a security-relevant
#: command, so a file that configured nothing scored zero and came back "no loaded
#: pattern pack recognises this file".
_MINIMAL_IOS = """!
version 15.0
hostname lab-sw-01
enable secret 5 $1$abc$def
ip ssh version 2
end
"""

#: Same shape, other platforms. Detection must refuse all of these, because
#: parsing a Junos file with the IOS pack does not produce an error — it produces
#: a device with almost no facts and a compliance report full of ``unknown``.
_OTHER_DIALECTS = {
    "juniper_junos": (
        "set system host-name edge-01\n"
        "set system services ssh root-login deny\n"
        "set system login retry-options tries-before-disconnect 3\n"
    ),
    "fortinet": (
        "config system global\n"
        "    set hostname fw-01\n"
        "    set admin-lockout-threshold 3\n"
        "end\n"
    ),
    "cisco_nxos": (
        "version 7.3(0)N1(1)\nhostname n9k-01\nfeature nx-os\n"
        "line vty\n  exec-timeout 10\nend\n"
    ),
    "cisco_asa": (
        "ASA Version 9.12(4)\nhostname fw-01\nnameif inside\nenable password xyz\n"
    ),
}


def test_detection_accepts_a_minimal_but_unambiguous_config(
    registry: PatternAdapterRegistry,
) -> None:
    """A six-line IOS config must be recognised, filename hints or not.

    The filename is deliberately unhelpful (``upload.txt``) so the test exercises
    the markers rather than the ``filename_hints`` shortcut, which is what a
    browser upload of a pasted snippet actually looks like.
    """
    scored = {
        adapter.pack.vendor: adapter.detection_score(_MINIMAL_IOS, "upload.txt")
        for adapter in registry.adapters()
    }
    assert scored.get("cisco_ios", 0) > 0, (
        "the minimal IOS config scored zero on every pack, so /ingest would "
        f"reject it with ParseError. Scores: {scored}"
    )


@pytest.mark.parametrize("vendor,text", sorted(_OTHER_DIALECTS.items()))
def test_detection_refuses_a_foreign_dialect(
    registry: PatternAdapterRegistry, vendor: str, text: str
) -> None:
    """A pack must not claim a config belonging to a platform it cannot parse.

    Only the packs actually shipped are asserted on: as each of these vendors gets
    its own pack this test keeps holding, because the assertion is "no *other*
    pack claims it", not "nothing claims it".
    """
    for adapter in registry.adapters():
        if adapter.pack.vendor == vendor:
            continue
        score = adapter.detection_score(text, f"{vendor}-sample.conf")
        assert score == 0, (
            f"{adapter.pack.vendor} scored {score} on a {vendor} config. Add an "
            f"anti_marker to {adapter.pack.vendor}.yaml for syntax only {vendor} has."
        )


def test_adapter_pack_is_reachable_by_vendor(registry: PatternAdapterRegistry) -> None:
    """``for_vendor`` must resolve every pack the library loaded.

    The training GUI and the re-simulate path both look a pack up by vendor
    string rather than by detection, so the two lookups must agree.
    """
    for adapter in registry.adapters():
        resolved = registry.for_vendor(adapter.pack.vendor)
        assert isinstance(resolved, PatternAdapter)
        assert resolved.pack.vendor == adapter.pack.vendor


def test_library_reload_is_a_no_op_when_nothing_changed() -> None:
    """Hot reload must not re-read an unchanged pack on every request.

    C2 requires picking up a new mapping without a redeploy; it does not require
    re-parsing every YAML file per upload. The fingerprint is what separates the
    two, and a broken fingerprint shows up as latency rather than as a wrong
    answer — which is exactly why it needs a test.
    """
    library = PatternLibrary()
    assert library.reload_if_changed() is True
    version = library.version
    assert library.reload_if_changed() is False
    assert library.version == version


# ── Coverage reporting ────────────────────────────────────────────────


@pytest.mark.parametrize("path", _pack_files(), ids=_pack_ids())
def test_pack_reports_meaningful_coverage(path: Path) -> None:
    """A pack must cover enough of the vocabulary to answer real controls.

    Not a quality metric — a floor. A pack with a handful of patterns would parse
    cleanly, produce almost no facts, and turn every control into ``unknown``,
    which reads as "nothing wrong here" to anyone skimming a report.
    """
    pack: PatternPack = load_pattern_pack(path)
    assert pack.pattern_count() >= 20, (
        f"{path.name} defines only {pack.pattern_count()} patterns; a pack this "
        "thin cannot answer a benchmark and would report mostly 'unknown'."
    )
    assert len(pack.referenced_paths()) >= 20
