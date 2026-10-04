"""Pattern-driven parsing engine — a vendor is a data file, not a Python module.

PRAMAN supports adding new vendors, OS versions and standards without
manual code modification. A hand-written adapter per vendor cannot deliver that:
every new platform is a new Python file, a code review and a redeploy. So the
parsing logic lives in data instead.

``data/ingest/patterns/<vendor>.yaml`` declares, for one platform:

* how to *recognise* a config of that platform (markers, anti-markers);
* a flat list of line patterns, each a regex plus the canonical paths its capture
  groups map to;
* a list of block definitions - ``line vty 0 4``, ``interface Gi0/1`` - each with
  an anchor pattern and its own child patterns, so a sub-command is attributed to
  the block that contains it;
* the vendor defaults that make *absence* of a line meaningful.

Everything else - provenance stamping, tri-state, ordering, unparsed-line
collection - is ``backend/ingest/generic.py``, once, for every vendor.

One regex may emit several facts. ``username admin privilege 15 secret 5 $1$..``
is one line carrying three separate compliance-relevant facts, and splitting it
into three regexes over the same line would make their agreement accidental. So a
pattern declares an ``emits`` list, each entry naming the capture group it reads:

    - id: local_user
      regex: '^username\\s+(?P<name>\\S+)(?:\\s+privilege\\s+(?P<priv>\\d+))?'
      emits:
        - {path: mgmt.local_user.name, value: str, group: name}
        - {path: mgmt.local_user.privilege, value: int, group: priv}

An emission whose group did not participate in the match is skipped, not
defaulted, which is how an optional clause stays absent rather than becoming a
guess. A group named in ``emits`` but missing from the regex is a load-time
error, so a typo surfaces at startup instead of silently producing no facts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from backend.app.config import DATA_DIR, FILE_ENCODING
from backend.canonical.paths import is_canonical_path
from backend.core_errors import ParseError

PATTERNS_DIR = DATA_DIR / "ingest" / "patterns"

#: The capture group an emission reads when it names none.
DEFAULT_GROUP = "value"


class Coercion:
    """Value coercions a pattern may name. Each is a pure function of the match."""

    #: The line's presence means the setting is on; the capture group is ignored.
    TRUE = "true"
    #: The line's presence means the setting is off (``no service pad``).
    FALSE = "false"
    #: A leading ``no`` flips the value; needs a ``(?P<neg>no\\s+)?`` group.
    NEGATED_BOOL = "negated_bool"
    #: The capture group, whitespace-stripped.
    STR = "str"
    #: The capture group, lower-cased. Use for enum-like values so a rule can
    #: compare without worrying about how the operator typed it.
    LOWER = "lower"
    #: The capture group as an integer.
    INT = "int"
    #: ``exec-timeout <min> <sec>`` to total seconds; needs ``minutes``/``seconds``.
    MINUTES_SECONDS = "minutes_seconds"
    #: A whitespace/comma separated group to a sorted list of tokens.
    WORD_LIST = "word_list"
    #: The whole matched line, stripped. For facts whose value is the command.
    LINE = "line"
    #: The capture group is present -> True. Distinguishes "clause appeared" from
    #: "line appeared" when one regex covers several optional clauses.
    GROUP_PRESENT = "group_present"
    #: A literal value from the pattern's ``literal:`` key, ignoring the match.
    #: For commands that carry no operand but set a definite value:
    #: ``no exec-timeout`` means a timeout of 0 seconds, not "false".
    CONST = "const"
    #: Infer the value's type from the captured text: an integer if it reads as
    #: one, a bool for ``true``/``false``, otherwise the stripped string.
    #:
    #: Reserved for patterns taught through the training GUI (C2). A pack author
    #: knows whether ``mgmt.ssh.version`` is an integer and says so; an operator
    #: mapping a line in the browser has no field in which to say it, and a
    #: taught fact whose value arrived as ``"2"`` would silently fail every rule
    #: comparing it with ``2``. Inference is narrow and total - it never returns
    #: SKIP for a group that matched - so a taught fact is still a deterministic
    #: function of the line. Shipped packs must not use it: there the type is
    #: known at authoring time and declaring it makes a wrong regex a load error
    #: instead of a surprising value.
    AUTO = "auto"


#: Coercions that read a capture group and therefore require one to exist.
_GROUP_COERCIONS = frozenset(
    {
        Coercion.STR,
        Coercion.LOWER,
        Coercion.INT,
        Coercion.WORD_LIST,
        Coercion.GROUP_PRESENT,
        Coercion.AUTO,
    }
)

_ALL_COERCIONS = _GROUP_COERCIONS | frozenset(
    {
        Coercion.TRUE,
        Coercion.FALSE,
        Coercion.NEGATED_BOOL,
        Coercion.MINUTES_SECONDS,
        Coercion.LINE,
        Coercion.CONST,
    }
)

#: Sentinel meaning "this emission does not apply to this match".
SKIP = object()


def coerce_value(
    coercion: str,
    match: re.Match[str],
    line: str,
    group: str = DEFAULT_GROUP,
    literal: Any = None,
) -> Any:
    """Turn a regex match into a canonical fact value.

    Args:
        coercion: One of the ``Coercion`` constants.
        match: The successful match.
        line: The stripped configuration line, for ``Coercion.LINE``.
        group: The named capture group to read.
        literal: The value returned by ``Coercion.CONST``.

    Returns:
        The coerced value, or ``SKIP`` when the emission's capture group did not
        participate in this match.

    Raises:
        ParseError: When the coercion is unknown or the captured text cannot be
            coerced (a non-numeric value for ``int``).
    """
    groups = match.groupdict()

    if coercion == Coercion.TRUE:
        return True
    if coercion == Coercion.FALSE:
        return False
    if coercion == Coercion.CONST:
        return literal
    if coercion == Coercion.LINE:
        return line.strip()
    if coercion == Coercion.NEGATED_BOOL:
        return not bool(groups.get("neg"))
    if coercion == Coercion.MINUTES_SECONDS:
        if groups.get("minutes") is None and groups.get("seconds") is None:
            return SKIP
        return int(groups.get("minutes") or 0) * 60 + int(groups.get("seconds") or 0)

    raw = groups.get(group)
    if coercion == Coercion.GROUP_PRESENT:
        return raw is not None
    if raw is None:
        return SKIP
    if coercion == Coercion.STR:
        return raw.strip()
    if coercion == Coercion.LOWER:
        return raw.strip().lower()
    if coercion == Coercion.INT:
        try:
            return int(raw.strip())
        except ValueError as exc:
            raise ParseError(f"expected an integer, got {raw!r}") from exc
    if coercion == Coercion.WORD_LIST:
        return sorted(token for token in re.split(r"[,\s]+", raw.strip()) if token)
    if coercion == Coercion.AUTO:
        return _infer_value(raw)

    raise ParseError(
        f"unknown coercion '{coercion}'; expected one of {sorted(_ALL_COERCIONS)}"
    )


def _infer_value(raw: str) -> Any:
    """Type a captured token without an author to declare its type.

    Only three shapes are recognised, and the fallback is the string itself. A
    wider inference - floats, IP addresses, comma lists - would make the same
    taught pattern produce different value *types* on different devices, and a
    rule comparing that path would then pass or fail depending on how the
    operator happened to write the line.
    """
    text = raw.strip()
    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    return text


@dataclass(frozen=True)
class Emission:
    """One canonical fact a pattern produces from one capture group."""

    path: str
    coercion: str = Coercion.TRUE
    group: str = DEFAULT_GROUP
    #: The value returned by ``Coercion.CONST``; ignored by every other coercion.
    literal: Any = None


@dataclass
class LinePattern:
    """One regex bound to the canonical facts it produces."""

    id: str
    regex: re.Pattern[str]
    emits: tuple[Emission, ...]
    #: Emitted only when this pattern matched nowhere in the config. Lets a pack
    #: state "no `ip ssh version 2` line means version 1 is in effect".
    absent_path: str | None = None
    absent_value: Any = None
    note: str = ""

    @property
    def path(self) -> str:
        """The primary path, used in messages and coverage reporting."""
        return self.emits[0].path if self.emits else ""

    @property
    def paths(self) -> tuple[str, ...]:
        """Every path this pattern can produce."""
        return tuple(e.path for e in self.emits)

    def match(self, line: str) -> re.Match[str] | None:
        """Match the pattern against a stripped configuration line."""
        return self.regex.match(line)


class BlockMode:
    """How a block's extent is determined in the raw text.

    Vendors delimit blocks in genuinely different ways, and getting the extent
    wrong misattributes a child command to the wrong interface - which would put
    a real finding on the wrong port. So the mode is declared per block rather
    than guessed.
    """

    #: Cisco / Arista / NX-OS: children are indented under the anchor and the
    #: block ends at the first line indented no further than the anchor.
    INDENT = "indent"
    #: FortiGate ``config ... end`` and ``edit ... next``: an explicit terminator.
    DELIMITED = "delimited"
    #: Junos curly-brace format: depth-counted ``{`` / ``}``.
    BRACE = "brace"
    #: Junos / PAN-OS ``set`` format: the anchor repeats on every member line and
    #: a run of consecutive lines sharing the same captured key is one instance.
    RUN = "run"


_ALL_BLOCK_MODES = frozenset(
    {BlockMode.INDENT, BlockMode.DELIMITED, BlockMode.BRACE, BlockMode.RUN}
)


@dataclass
class BlockPattern:
    """A configuration block, its anchor fact, and the patterns valid inside it."""

    id: str
    anchor_path: str
    regex: re.Pattern[str]
    anchor_coercion: str = Coercion.STR
    anchor_group: str = DEFAULT_GROUP
    #: The value returned by ``Coercion.CONST``, from the block's ``literal:``
    #: key. A block whose anchor line names the platform's spelling of a thing
    #: rather than the canonical one needs this: Junos opens ``tacplus-server
    #: {``, and every other pack files that protocol as ``tacacs+``.
    anchor_literal: Any = None
    mode: str = BlockMode.INDENT
    #: Required by BlockMode.DELIMITED; ignored otherwise.
    end_regex: re.Pattern[str] | None = None
    children: tuple[LinePattern, ...] = ()
    #: Nested sub-blocks, e.g. ``address-family`` inside ``router bgp``.
    blocks: tuple[BlockPattern, ...] = ()
    #: Facts asserted per instance when a child pattern never matched in it.
    child_defaults: tuple[Default, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Default:
    """A fact that follows from a line being absent, with the reason recorded.

    The reason is written into the fact's ``raw_text``, because a fact with no
    configuration line behind it still owes the reader an explanation of where
    its value came from.
    """

    path: str
    value: Any
    reason: str = "platform default"


@dataclass
class Detector:
    """How to recognise a config as belonging to this platform."""

    markers: tuple[str, ...] = ()
    min_hits: int = 3
    anti_markers: tuple[str, ...] = ()
    filename_hints: tuple[str, ...] = ()
    #: Added to the score when every one of these appears. Use for syntax only
    #: this platform has, so a shared-dialect sibling cannot outscore it.
    strong_markers: tuple[str, ...] = ()
    strong_bonus: int = 10

    def score(self, lowered_text: str, filename: str) -> int:
        """Return a detection score; higher wins, 0 means "not this platform"."""
        if any(anti.lower() in lowered_text for anti in self.anti_markers):
            return 0
        hits = sum(1 for marker in self.markers if marker.lower() in lowered_text)
        if hits < self.min_hits:
            return 0
        score = hits
        if self.strong_markers and all(
            marker.lower() in lowered_text for marker in self.strong_markers
        ):
            score += self.strong_bonus
        lowered_name = filename.lower()
        if any(hint.lower() in lowered_name for hint in self.filename_hints):
            score += 5
        return score


@dataclass
class PatternPack:
    """Everything needed to parse one platform's configuration."""

    vendor: str
    os_family: str
    parser_id: str
    detect: Detector
    comment_prefixes: tuple[str, ...] = ("!", "#")
    patterns: tuple[LinePattern, ...] = ()
    blocks: tuple[BlockPattern, ...] = ()
    #: Facts asserted when no pattern in the file produced the named path.
    defaults: tuple[Default, ...] = ()
    #: Lines matching these are structural noise, not unparsed content.
    ignore: tuple[re.Pattern[str], ...] = ()
    #: Optional overrides for where the Device record reads its identity from.
    identity: dict[str, str] = field(default_factory=dict)
    source_file: str = ""
    description: str = ""

    def referenced_paths(self) -> set[str]:
        """Every canonical path this pack can emit.

        Used by the coverage test that asserts parsers and rules share one
        vocabulary, and by ``bench_parse_coverage.py``.
        """
        paths: set[str] = set()
        for pattern in self.patterns:
            paths.update(pattern.paths)
            if pattern.absent_path:
                paths.add(pattern.absent_path)
        paths |= {d.path for d in self.defaults}
        for block in walk_blocks(self.blocks):
            paths.add(block.anchor_path)
            for child in block.children:
                paths.update(child.paths)
                if child.absent_path:
                    paths.add(child.absent_path)
            paths |= {d.path for d in block.child_defaults}
        return paths

    def pattern_count(self) -> int:
        """Total patterns, top-level plus every block's children."""
        return len(self.patterns) + sum(
            len(block.children) for block in walk_blocks(self.blocks)
        )


def walk_blocks(blocks: Iterable[BlockPattern]) -> list[BlockPattern]:
    """Flatten nested block definitions, outermost first."""
    out: list[BlockPattern] = []
    for block in blocks:
        out.append(block)
        out.extend(walk_blocks(block.blocks))
    return out


# ── Loading ───────────────────────────────────────────────────────────


def _compile(pattern_id: str, raw: str, flags: int) -> re.Pattern[str]:
    """Compile a pattern regex, naming the offending pattern on failure."""
    try:
        return re.compile(raw, flags)
    except re.error as exc:
        raise ParseError(f"pattern '{pattern_id}': invalid regex {raw!r}: {exc}") from exc


def _check_path(pattern_id: str, path: str, what: str = "path") -> str:
    """Reject a path that is not in the canonical vocabulary."""
    if not is_canonical_path(path):
        raise ParseError(
            f"pattern '{pattern_id}' {what} '{path}' is not in the canonical "
            "vocabulary. Add it to backend/canonical/schema/"
            "canonical_paths.schema.json first, then teach a parser to emit it."
        )
    return path


def _coercion_name(raw: Any) -> str:
    """Normalise a YAML coercion token to its ``Coercion`` spelling.

    ``value: true`` is the documented spelling, but YAML resolves an unquoted
    ``true`` to a Python bool, so a naive ``str()`` would produce ``"True"`` and
    the loader would reject the very spelling its error message recommends.
    Lower-casing also makes ``STR`` and ``Int`` work, which costs nothing and
    removes a class of pointless startup failure.
    """
    return str(raw).strip().lower()


def _check_coercion(pattern_id: str, coercion: str) -> str:
    """Reject an unknown coercion name."""
    if coercion not in _ALL_COERCIONS:
        raise ParseError(
            f"pattern '{pattern_id}' names unknown coercion '{coercion}'; "
            f"expected one of {sorted(_ALL_COERCIONS)}"
        )
    return coercion


def _check_group(
    pattern_id: str, regex: re.Pattern[str], coercion: str, group: str
) -> None:
    """Reject an emission reading a capture group the regex never defines."""
    if coercion in _GROUP_COERCIONS and group not in regex.groupindex:
        raise ParseError(
            f"pattern '{pattern_id}' coercion '{coercion}' reads group "
            f"'{group}', but the regex defines {sorted(regex.groupindex)}"
        )
    if coercion == Coercion.NEGATED_BOOL and "neg" not in regex.groupindex:
        raise ParseError(
            f"pattern '{pattern_id}' uses 'negated_bool' but the regex has no "
            "'(?P<neg>no\\s+)?' group"
        )
    if coercion == Coercion.MINUTES_SECONDS and not (
        "minutes" in regex.groupindex or "seconds" in regex.groupindex
    ):
        raise ParseError(
            f"pattern '{pattern_id}' uses 'minutes_seconds' but the regex "
            "defines neither a 'minutes' nor a 'seconds' group"
        )


def _build_emissions(
    raw: dict[str, Any], pattern_id: str, regex: re.Pattern[str]
) -> tuple[Emission, ...]:
    """Build the emission list, accepting the single-fact shorthand."""
    declared = raw.get("emits")
    if declared is None:
        if "path" not in raw:
            raise ParseError(f"pattern '{pattern_id}' declares neither 'path' nor 'emits'")
        shorthand: dict[str, Any] = {
            "path": raw["path"],
            "value": raw.get("value", Coercion.TRUE),
            "group": raw.get("group", DEFAULT_GROUP),
        }
        if "literal" in raw:
            shorthand["literal"] = raw["literal"]
        declared = [shorthand]
    if not declared:
        raise ParseError(f"pattern '{pattern_id}' has an empty 'emits' list")

    emissions: list[Emission] = []
    for entry in declared:
        path = _check_path(pattern_id, str(entry.get("path", "")))
        coercion = _check_coercion(
            pattern_id, _coercion_name(entry.get("value", Coercion.TRUE))
        )
        group = str(entry.get("group", DEFAULT_GROUP))
        _check_group(pattern_id, regex, coercion, group)
        if coercion == Coercion.CONST and "literal" not in entry:
            raise ParseError(
                f"pattern '{pattern_id}' emission '{path}' uses coercion 'const' "
                "but declares no 'literal:' value; a constant with no value "
                "asserts nothing"
            )
        emissions.append(
            Emission(
                path=path,
                coercion=coercion,
                group=group,
                literal=entry.get("literal"),
            )
        )
    return tuple(emissions)


def _build_line_pattern(raw: dict[str, Any], flags: int, context: str) -> LinePattern:
    """Build one LinePattern from its YAML mapping."""
    pattern_id = str(raw.get("id") or f"{context}:{raw.get('path', '?')}")
    if "regex" not in raw:
        raise ParseError(f"pattern '{pattern_id}' has no 'regex'")
    regex = _compile(pattern_id, str(raw["regex"]), flags)
    emissions = _build_emissions(raw, pattern_id, regex)

    absent_path = raw.get("absent_path")
    if absent_path:
        _check_path(pattern_id, str(absent_path), "absent_path")
        if "absent_value" not in raw:
            raise ParseError(
                f"pattern '{pattern_id}' sets absent_path but no absent_value; "
                "an absence with no stated value asserts nothing"
            )
    return LinePattern(
        id=pattern_id,
        regex=regex,
        emits=emissions,
        absent_path=str(absent_path) if absent_path else None,
        absent_value=raw.get("absent_value"),
        note=str(raw.get("note", "")),
    )


def _build_defaults(raw: Any, context: str) -> tuple[Default, ...]:
    """Build the default list, accepting ``path: value`` or a full mapping."""
    if not raw:
        return ()
    defaults: list[Default] = []
    if isinstance(raw, dict):
        items: Iterable[tuple[str, Any]] = sorted(raw.items())
        for path, value in items:
            if isinstance(value, dict):
                defaults.append(
                    Default(
                        path=_check_path(context, str(path)),
                        value=value.get("value"),
                        reason=str(value.get("reason", "platform default")),
                    )
                )
            else:
                defaults.append(Default(path=_check_path(context, str(path)), value=value))
        return tuple(defaults)
    for entry in raw:
        defaults.append(
            Default(
                path=_check_path(context, str(entry.get("path", ""))),
                value=entry.get("value"),
                reason=str(entry.get("reason", "platform default")),
            )
        )
    return tuple(defaults)


def _build_block(raw: dict[str, Any], flags: int) -> BlockPattern:
    """Build one BlockPattern, recursing into nested blocks."""
    block_id = str(raw.get("id") or raw.get("anchor_path", "block"))
    anchor_path = _check_path(block_id, str(raw.get("anchor_path", "")), "anchor_path")
    if "regex" not in raw:
        raise ParseError(f"block '{block_id}' has no 'regex'")
    regex = _compile(block_id, str(raw["regex"]), flags)

    mode = str(raw.get("mode", BlockMode.INDENT))
    if mode not in _ALL_BLOCK_MODES:
        raise ParseError(
            f"block '{block_id}' names unknown mode '{mode}'; "
            f"expected one of {sorted(_ALL_BLOCK_MODES)}"
        )
    end_raw = raw.get("end_regex")
    if mode == BlockMode.DELIMITED and not end_raw:
        raise ParseError(f"block '{block_id}' uses mode 'delimited' but has no end_regex")

    anchor_coercion = _check_coercion(
        block_id, _coercion_name(raw.get("anchor_value", Coercion.STR))
    )
    anchor_literal = raw.get("literal")
    if anchor_coercion == Coercion.CONST:
        if "literal" not in raw:
            raise ParseError(
                f"block '{block_id}' uses anchor_value 'const' but declares no "
                "'literal:' value; a constant with no value would return nothing. "
                "Use 'true' for a singleton block, or a group coercion to key "
                "instances."
            )
        if mode == BlockMode.RUN:
            raise ParseError(
                f"block '{block_id}' uses anchor_value 'const' with mode 'run'. "
                "A run block groups consecutive lines by their anchor value, and "
                "a constant makes every line one instance, so unrelated objects "
                "would be merged. Key a run block by a capture group."
            )
    anchor_group = str(raw.get("anchor_group", DEFAULT_GROUP))
    _check_group(block_id, regex, anchor_coercion, anchor_group)

    return BlockPattern(
        id=block_id,
        anchor_path=anchor_path,
        regex=regex,
        anchor_coercion=anchor_coercion,
        anchor_group=anchor_group,
        anchor_literal=anchor_literal,
        mode=mode,
        end_regex=_compile(f"{block_id}:end", str(end_raw), flags) if end_raw else None,
        children=tuple(
            _build_line_pattern(child, flags, block_id)
            for child in raw.get("children", [])
        ),
        blocks=tuple(_build_block(nested, flags) for nested in raw.get("blocks", [])),
        child_defaults=_build_defaults(raw.get("child_defaults"), block_id),
        note=str(raw.get("note", "")),
    )


def load_pattern_pack(path: Path) -> PatternPack:
    """Load and validate one vendor pattern file.

    Raises:
        ParseError: With the file name and the specific pattern at fault, so a
            malformed pack names its own bug instead of failing at parse time.
    """
    try:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding=FILE_ENCODING)) or {}
    except yaml.YAMLError as exc:
        raise ParseError(f"{path.name}: not valid YAML: {exc}") from exc

    for required in ("vendor", "os_family", "parser_id"):
        if not raw.get(required):
            raise ParseError(f"{path.name}: missing required key '{required}'")

    flags = re.IGNORECASE if raw.get("case_insensitive", True) else 0
    detect_raw = raw.get("detect", {}) or {}

    try:
        pack = PatternPack(
            vendor=str(raw["vendor"]),
            os_family=str(raw["os_family"]),
            parser_id=str(raw["parser_id"]),
            detect=Detector(
                markers=tuple(str(m) for m in detect_raw.get("markers", [])),
                min_hits=int(detect_raw.get("min_hits", 3)),
                anti_markers=tuple(str(m) for m in detect_raw.get("anti_markers", [])),
                filename_hints=tuple(str(m) for m in detect_raw.get("filename_hints", [])),
                strong_markers=tuple(str(m) for m in detect_raw.get("strong_markers", [])),
                strong_bonus=int(detect_raw.get("strong_bonus", 10)),
            ),
            comment_prefixes=tuple(str(c) for c in raw.get("comment_prefixes", ["!", "#"])),
            patterns=tuple(
                _build_line_pattern(p, flags, path.stem) for p in raw.get("patterns", [])
            ),
            blocks=tuple(_build_block(b, flags) for b in raw.get("blocks", [])),
            defaults=_build_defaults(raw.get("defaults"), path.stem),
            ignore=tuple(
                _compile(f"{path.stem}:ignore", str(r), flags)
                for r in raw.get("ignore", [])
            ),
            identity={str(k): str(v) for k, v in (raw.get("identity") or {}).items()},
            source_file=path.name,
            description=str(raw.get("description", "")),
        )
    except ParseError as exc:
        raise ParseError(f"{path.name}: {exc}") from exc

    _reject_duplicate_ids(path.name, pack)
    return pack


def _reject_duplicate_ids(filename: str, pack: PatternPack) -> None:
    """Reject a pack with two patterns sharing an id.

    Ids appear in unparsed-line diagnostics and in the coverage bench, so a
    duplicate would make a coverage figure impossible to attribute.
    """
    seen: set[str] = set()
    duplicates: set[str] = set()
    everything = list(pack.patterns)
    for block in walk_blocks(pack.blocks):
        everything.extend(block.children)
    for pattern in everything:
        if pattern.id in seen:
            duplicates.add(pattern.id)
        seen.add(pattern.id)
    if duplicates:
        raise ParseError(
            f"{filename}: duplicate pattern id(s): {sorted(duplicates)}"
        )


class PatternLibrary:
    """Loads every vendor pattern pack and reloads when the directory changes."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or PATTERNS_DIR
        self._packs: dict[str, PatternPack] = {}
        self._fingerprint: tuple = ()
        self.version = 0

    def _current_fingerprint(self) -> tuple:
        """Cheap change signal: path, size and mtime of every pack file."""
        if not self.directory.exists():
            return ()
        return tuple(
            (str(p), p.stat().st_size, int(p.stat().st_mtime_ns))
            for p in sorted(self.directory.glob("*.y*ml"))
        )

    def packs(self) -> dict[str, PatternPack]:
        """Return every loaded pack, keyed by vendor."""
        if not self._packs:
            self.reload_if_changed()
        return self._packs

    def reload_if_changed(self) -> bool:
        """Reload pattern packs when the directory has changed on disk.

        Returns:
            True when a reload happened, so a caller can log the new version.
        """
        fingerprint = self._current_fingerprint()
        if fingerprint == self._fingerprint and self._packs:
            return False
        packs: dict[str, PatternPack] = {}
        if self.directory.exists():
            for path in sorted(self.directory.glob("*.y*ml")):
                pack = load_pattern_pack(path)
                if pack.vendor in packs:
                    raise ParseError(
                        f"{path.name}: vendor '{pack.vendor}' is already declared by "
                        f"{packs[pack.vendor].source_file}"
                    )
                packs[pack.vendor] = pack
        self._packs = packs
        self._fingerprint = fingerprint
        self.version += 1
        return True
