"""PatternAdapter — the one parser every vendor shares.

``backend/ingest/patterns.py`` defines what a pattern pack *is*; this module is
what *runs* it. One class parses Cisco IOS, NX-OS, ASA, Junos, EOS, FortiGate and
PAN-OS, because the vendor-specific part is the YAML, not the Python.

Parsing happens in four passes, in this order, because each depends on the last:

1. **Block extent.** Find every block instance and its exact line span. A child
   command must be attributed to the block that contains it - putting
   ``shutdown`` on the wrong interface would put a real finding on the wrong
   port - so the span is computed from the vendor's own delimiters
   (indentation, ``end``, braces, or a repeated key) rather than guessed.
2. **Line matching.** Walk the lines once. For each, try the innermost enclosing
   block's children first, then outward, then the top-level patterns. The first
   pattern that matches wins, so a specific pattern placed above a general one
   in the YAML takes precedence.
3. **Absence.** A security check often turns on a line that *is not there*:
   ``no ip http server`` absent means the HTTP server is on. Passes 1-2 can only
   see what is present, so absence is asserted here, from ``defaults`` and
   ``absent_path``, with ``present=False`` and a line span of 0.
4. **Identity.** Read the ``device.*`` facts back out to fill the Device record,
   including the serial numbers and hardware PS 26155 C4 requires on the report.

Everything the parser could not place lands in ``ParseResult.unparsed_lines``.
That list is not debug output - it is the input to the AI escalation ladder and
the training queue (C2), so a line is only dropped from it when the pack
explicitly declares it structural noise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from backend.canonical.models import (
    VENDOR_TO_OS_FAMILY,
    CanonicalFact,
    Device,
    OsFamily,
    Vendor,
    compute_config_hash,
    utc_now_iso,
)
from backend.core_errors import ParseError
from backend.ingest.base import ParseResult, VendorAdapter
from backend.ingest.patterns import (
    SKIP,
    BlockMode,
    BlockPattern,
    LinePattern,
    PatternLibrary,
    PatternPack,
    coerce_value,
)

# Canonical paths the Device record is built from. A pack populates these with
# ordinary patterns; nothing here is vendor-specific.
IDENTITY_HOSTNAME = "device.hostname"
IDENTITY_OS_VERSION = "device.os_version"
IDENTITY_SERIALS = "device.serials"
IDENTITY_HARDWARE = "device.hardware"
IDENTITY_MODEL = "device.model"

# A device_id must be a stable filesystem- and URL-safe slug.
_SLUG_STRIP = re.compile(r"[^a-z0-9._-]+")


def slugify(value: str, fallback: str = "device") -> str:
    """Turn a hostname or filename into a stable device_id slug."""
    slug = _SLUG_STRIP.sub("-", value.strip().lower()).strip("-._")
    return slug or fallback


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


class PatternAdapter(VendorAdapter):
    """Runs one pattern pack against one configuration file."""

    def __init__(
        self, pack: PatternPack, learned: list[LinePattern] | None = None
    ) -> None:
        """Build an adapter for one platform.

        Args:
            pack: The vendor pattern pack, already loaded and validated.
            learned: Extra patterns taught through the training GUI. They are
                tried *after* the shipped patterns so an operator's mapping can
                never silently override a vetted one, and they carry their own
                parser_id so a taught fact is distinguishable on the report.
        """
        self.pack = pack
        self.learned = learned or []
        try:
            self._vendor = Vendor(pack.vendor)
        except ValueError as exc:
            raise ParseError(
                f"{pack.source_file}: vendor '{pack.vendor}' is not a canonical "
                f"Vendor value ({[v.value for v in Vendor]})"
            ) from exc
        try:
            self._os_family = OsFamily(pack.os_family)
        except ValueError as exc:
            raise ParseError(
                f"{pack.source_file}: os_family '{pack.os_family}' is not a "
                f"canonical OsFamily value"
            ) from exc
        expected = VENDOR_TO_OS_FAMILY[self._vendor]
        if self._os_family is not expected:
            raise ParseError(
                f"{pack.source_file}: vendor '{pack.vendor}' maps to os_family "
                f"'{expected.value}', but the pack declares '{pack.os_family}'"
            )
        self._learned_ids = {p.id for p in self.learned}

    # ── VendorAdapter contract ────────────────────────────────────────

    def vendor_id(self) -> Vendor:
        """Return the canonical Vendor enum for this pack."""
        return self._vendor

    def can_parse(self, raw_text: str, filename: str) -> bool:
        """Whether this pack's detector recognises the text."""
        return self.pack.detect.score(raw_text.lower(), filename) > 0

    def detection_score(self, raw_text: str, filename: str) -> int:
        """Expose the detector score so a registry can pick the best pack."""
        return self.pack.detect.score(raw_text.lower(), filename)

    def _parser_id(self) -> str:
        """Return the pinned parser id declared by the pack."""
        return self.pack.parser_id

    # ── Parsing ───────────────────────────────────────────────────────

    def parse(self, raw_text: str, source_file: str) -> ParseResult:
        """Parse a configuration into a Device and canonical facts.

        Args:
            raw_text: Decoded, NFKC-normalised configuration text.
            source_file: Original filename, recorded in every fact's provenance.

        Returns:
            ParseResult with facts, unparsed lines, and the Device record.
        """
        lines = raw_text.splitlines()
        instances = self._scan_blocks(lines)

        facts: list[CanonicalFact] = []
        unparsed: list[dict[str, Any]] = []
        matched_paths: set[str] = set()
        matched_patterns: set[str] = set()

        anchor_lines = {i.line_start for i in instances}

        for offset, raw_line in enumerate(lines):
            line_no = offset + 1
            stripped = raw_line.strip()
            if not stripped or self._is_comment(stripped) or self._is_ignored(stripped):
                continue
            if line_no in anchor_lines:
                continue  # the anchor fact is emitted from the instance itself

            enclosing = self._enclosing(instances, line_no)
            produced = self._match_line(stripped, line_no, source_file, enclosing)
            if produced is not None:
                pattern, new_facts = produced
                matched_patterns.add(pattern.id)
                matched_paths.update(f.path for f in new_facts)
                facts.extend(new_facts)
                continue
            unparsed.append(
                {
                    "line_number": line_no,
                    "raw_text": stripped,
                    # The anchor *line*, not the anchor key: a block whose anchor
                    # value is a boolean has key "True", and "an unmapped line
                    # inside True" tells the operator staring at the training GUI
                    # nothing. "router rip" tells them what to map it against.
                    "block": enclosing[0].anchor_line.strip() if enclosing else "",
                    "block_path": enclosing[0].block.anchor_path if enclosing else "",
                }
            )

        # A block anchor and a per-instance child default both produce real facts,
        # so both must silence the pack-level default for their path. Feeding only
        # _match_line's output into matched_paths would let a device that *has* a
        # login banner carry mgmt.login_banner as True (from the block anchor) and
        # False (from the default) at once, and a rule quantified over all facts at
        # that path would then fail a compliant device.
        derived = self._anchor_facts(instances, source_file)
        derived += self._child_default_facts(instances, source_file)
        facts.extend(derived)
        matched_paths.update(fact.path for fact in derived)
        facts.extend(
            self._absence_facts(matched_paths, matched_patterns, source_file)
        )

        facts.sort(key=lambda f: (f.line_start, f.path, str(f.value)))
        device = self._build_device(facts, raw_text, source_file)
        return ParseResult(device=device, facts=facts, unparsed_lines=unparsed)

    # ── Pass 1: block extents ─────────────────────────────────────────

    def _scan_blocks(self, lines: list[str]) -> list[BlockInstance]:
        """Locate every block instance and its exact line span.

        Returns instances sorted innermost-first for a given line, so
        ``_enclosing`` can resolve the tightest containing block in one pass.
        """
        instances: list[BlockInstance] = []
        run_blocks = [b for b in self.pack.blocks if b.mode == BlockMode.RUN]
        stack_blocks = [b for b in self.pack.blocks if b.mode != BlockMode.RUN]

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
            if not stripped or self._is_comment(stripped):
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
            if not stripped or self._is_comment(stripped):
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
        anchor_indent = _indent_of(lines[anchor_line - 1])
        end = anchor_line
        for line_no in range(anchor_line + 1, limit + 1):
            raw_line = lines[line_no - 1]
            stripped = raw_line.strip()
            if not stripped:
                continue
            if self._is_comment(stripped):
                break
            if _indent_of(raw_line) <= anchor_indent:
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
            if self._is_comment(stripped):
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
    def _enclosing(
        instances: list[BlockInstance], line_no: int
    ) -> list[BlockInstance]:
        """Return the instances containing a line, innermost first."""
        hits = [i for i in instances if i.contains(line_no)]
        hits.sort(key=lambda i: (-i.depth, i.line_end - i.line_start, i.line_start))
        return hits

    # ── Pass 2: line matching ─────────────────────────────────────────

    def _match_line(
        self,
        stripped: str,
        line_no: int,
        source_file: str,
        enclosing: list[BlockInstance],
    ) -> tuple[LinePattern, list[CanonicalFact]] | None:
        """Match one line against block children, then top-level, then taught.

        The first pattern that matches wins, so a specific pattern placed above a
        general one in the YAML takes precedence. Taught patterns are tried last
        so an operator's mapping can never shadow a vetted one.

        Returns:
            The winning pattern and the facts it produced, or None when nothing
            matched - in which case the caller records the line as unparsed.
        """
        for instance in enclosing:
            for pattern in instance.block.children:
                match = pattern.match(stripped)
                if match is None:
                    continue
                facts = self._facts_from(pattern, match, stripped, line_no, source_file)
                instance.matched_paths.update(f.path for f in facts)
                return pattern, facts

        for group in (self.pack.patterns, self.learned):
            for pattern in group:
                match = pattern.match(stripped)
                if match is not None:
                    return pattern, self._facts_from(
                        pattern, match, stripped, line_no, source_file
                    )
        return None

    def _facts_from(
        self,
        pattern: LinePattern,
        match: re.Match[str],
        raw_text: str,
        line_no: int,
        source_file: str,
    ) -> list[CanonicalFact]:
        """Build every fact a matched pattern emits, with six-field provenance.

        An emission whose capture group did not participate produces nothing:
        ``username bob secret 5 $1$..`` has no ``privilege`` clause, and inventing
        a default privilege there would be a fabricated fact.
        """
        # A taught mapping is deterministic once approved - it is a regex, not an
        # inference - but it carries its own parser_id so an auditor can see which
        # facts came from an operator-supplied pattern.
        parser_id = (
            f"{self.pack.parser_id}+taught"
            if pattern.id in self._learned_ids
            else self.pack.parser_id
        )
        facts: list[CanonicalFact] = []
        for emission in pattern.emits:
            try:
                value = coerce_value(
                    emission.coercion,
                    match,
                    raw_text,
                    emission.group,
                    emission.literal,
                )
            except ParseError as exc:
                raise ParseError(
                    f"{self.pack.source_file}: pattern '{pattern.id}' failed on "
                    f"{source_file}:{line_no}: {exc}"
                ) from exc
            if value is SKIP:
                continue
            facts.append(
                CanonicalFact(
                    path=emission.path,
                    value=value,
                    present=True,
                    source_file=source_file,
                    line_start=line_no,
                    line_end=line_no,
                    raw_text=raw_text,
                    parser_id=parser_id,
                    confidence=1.0,
                )
            )
        return facts

    def _anchor_facts(
        self, instances: list[BlockInstance], source_file: str
    ) -> list[CanonicalFact]:
        """Emit one anchor fact per block instance, spanning the whole instance.

        The span matters: ``FactIndex`` recovers block membership from line-span
        containment, so an anchor whose span covered only its own line would
        orphan every child fact.
        """
        return [
            CanonicalFact(
                path=instance.block.anchor_path,
                value=instance.value,
                present=True,
                source_file=source_file,
                line_start=instance.line_start,
                line_end=instance.line_end,
                raw_text=instance.anchor_line,
                parser_id=self.pack.parser_id,
                confidence=1.0,
            )
            for instance in instances
        ]

    def _child_default_facts(
        self, instances: list[BlockInstance], source_file: str
    ) -> list[CanonicalFact]:
        """Assert per-instance defaults for children that never matched.

        ``interface`` blocks are the motivating case: a port with no
        ``switchport port-security`` line has port security off, and a rule must
        be able to see that as a definite ``False`` rather than as missing
        evidence. The fact is anchored to the block's own line span so the report
        still points the reader at the right stanza, and ``present=False`` keeps
        it distinguishable from a value the operator actually typed.
        """
        facts: list[CanonicalFact] = []
        for instance in instances:
            for default in instance.block.child_defaults:
                if default.path in instance.matched_paths:
                    continue
                facts.append(
                    CanonicalFact(
                        path=default.path,
                        value=default.value,
                        present=False,
                        source_file=source_file,
                        line_start=instance.line_start,
                        line_end=instance.line_end,
                        raw_text=f"{instance.anchor_line} <no explicit setting: "
                        f"{default.reason}>",
                        parser_id=self.pack.parser_id,
                        confidence=1.0,
                    )
                )
        return facts

    # ── Pass 3: absence ───────────────────────────────────────────────

    def _absence_facts(
        self, matched_paths: set[str], matched_patterns: set[str], source_file: str
    ) -> list[CanonicalFact]:
        """Assert the facts that follow from a line being absent.

        ``present=False`` and a zero line span are the honest provenance for a
        fact derived from absence: there is no configuration line to cite. Rules
        that must not treat absence as compliance use ``on_missing`` instead;
        this pass is for the narrower case where the platform's documented
        default is known and the pack states it, with its reason.
        """
        facts: list[CanonicalFact] = []
        asserted: set[str] = set()

        for pattern in self.pack.patterns:
            if not pattern.absent_path or pattern.id in matched_patterns:
                continue
            if pattern.absent_path in matched_paths or pattern.absent_path in asserted:
                continue
            asserted.add(pattern.absent_path)
            facts.append(
                self._absent_fact(
                    pattern.absent_path,
                    pattern.absent_value,
                    source_file,
                    pattern.note or f"no line matched '{pattern.id}'",
                )
            )

        for default in self.pack.defaults:
            if default.path in matched_paths or default.path in asserted:
                continue
            asserted.add(default.path)
            facts.append(
                self._absent_fact(
                    default.path, default.value, source_file, default.reason
                )
            )
        return facts

    def _absent_fact(
        self, path: str, value: Any, source_file: str, note: str
    ) -> CanonicalFact:
        """Build a present=False fact for something the config never stated."""
        return CanonicalFact(
            path=path,
            value=value,
            present=False,
            source_file=source_file,
            line_start=0,
            line_end=0,
            raw_text=f"<not configured> {note}".strip(),
            parser_id=self.pack.parser_id,
            confidence=1.0,
        )

    # ── Pass 4: device identity ───────────────────────────────────────

    def _build_device(
        self, facts: list[CanonicalFact], raw_text: str, source_file: str
    ) -> Device:
        """Assemble the Device record from the identity facts.

        Serial numbers and hardware models are what PS 26155 C4 asks the report
        to identify the device by. They are not in a running-config, so they are
        parsed from any ``show version`` / ``show inventory`` output included in
        the upload. When the upload is config-only both stay ``[]``, and the
        report says so rather than inventing an identifier.
        """
        identity = self.pack.identity

        def values_at(default_path: str, key: str) -> list[str]:
            path = str(identity.get(key, default_path))
            out: list[str] = []
            for fact in facts:
                if fact.path != path or not fact.present:
                    continue
                if isinstance(fact.value, list):
                    out.extend(str(v) for v in fact.value)
                elif fact.value not in (None, "", True, False):
                    out.append(str(fact.value))
            # Deduplicate while keeping first-seen order: a stacked chassis lists
            # its members in a meaningful sequence.
            seen: set[str] = set()
            return [v for v in out if not (v in seen or seen.add(v))]

        hostnames = values_at(IDENTITY_HOSTNAME, "hostname")
        versions = values_at(IDENTITY_OS_VERSION, "os_version")
        hardware = values_at(IDENTITY_HARDWARE, "hardware")
        hardware += [m for m in values_at(IDENTITY_MODEL, "model") if m not in hardware]

        hostname = hostnames[0] if hostnames else None
        device_id = slugify(hostname or _stem(source_file), fallback="device")

        return Device(
            device_id=device_id,
            vendor=self._vendor,
            os_family=self._os_family,
            hostname=hostname,
            serials=values_at(IDENTITY_SERIALS, "serials"),
            hardware=hardware,
            os_version=versions[0] if versions else None,
            source_file=source_file,
            config_hash=compute_config_hash(raw_text.encode("utf-8")),
            ingested_at=utc_now_iso(),
        )

    # ── Helpers ───────────────────────────────────────────────────────

    def _is_comment(self, stripped: str) -> bool:
        """Whether a stripped line is a comment for this platform."""
        return any(stripped.startswith(prefix) for prefix in self.pack.comment_prefixes)

    def _is_ignored(self, stripped: str) -> bool:
        """Whether the pack declares this line structural noise."""
        return any(pattern.match(stripped) for pattern in self.pack.ignore)


def _indent_of(raw_line: str) -> int:
    """Return a line's leading-whitespace width, tabs counted as one column."""
    return len(raw_line) - len(raw_line.lstrip())


def _stem(source_file: str) -> str:
    """Filename without directories or extension, for device_id fallback."""
    name = source_file.replace("\\", "/").rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[0] if "." in name else name


class PatternAdapterRegistry:
    """Chooses the pattern adapter for an uploaded configuration.

    Detection is by score, not by first match, so a Cisco IOS-XE config is not
    claimed by the IOS pack merely because it shares most of its syntax. The
    library reloads when the pattern directory changes, which is what lets a new
    vendor be onboarded without restarting the service (C5).
    """

    def __init__(self, library: PatternLibrary | None = None) -> None:
        self.library = library or PatternLibrary()
        self._learned_provider = None

    def set_learned_provider(self, provider) -> None:
        """Register a callable returning taught patterns for a vendor.

        Wired to ``backend/ai/mapping_store.py`` at startup. Kept as a callable
        rather than a direct import so the parser has no dependency on the
        database, and so tests can inject patterns without one.
        """
        self._learned_provider = provider

    def adapters(self) -> list[PatternAdapter]:
        """Build an adapter per loaded pattern pack."""
        self.library.reload_if_changed()
        return [
            PatternAdapter(pack, self._learned_for(pack.vendor))
            for pack in self.library.packs().values()
        ]

    def _learned_for(self, vendor: str) -> list[LinePattern]:
        """Fetch taught patterns for one vendor, tolerating an absent store."""
        if self._learned_provider is None:
            return []
        return list(self._learned_provider(vendor) or [])

    def detect(self, raw_text: str, filename: str) -> PatternAdapter | None:
        """Return the best-scoring adapter for this configuration, if any."""
        scored = [
            (adapter.detection_score(raw_text, filename), adapter.pack.vendor, adapter)
            for adapter in self.adapters()
        ]
        best = max(
            (entry for entry in scored if entry[0] > 0),
            key=lambda entry: (entry[0], entry[1]),
            default=None,
        )
        return best[2] if best else None

    def for_vendor(self, vendor: str) -> PatternAdapter:
        """Return the adapter for an explicitly named vendor."""
        self.library.reload_if_changed()
        pack = self.library.packs().get(vendor)
        if pack is None:
            known = sorted(self.library.packs())
            raise ParseError(
                f"no pattern pack for vendor '{vendor}'. Loaded: {known or 'none'}. "
                f"Add data/ingest/patterns/{vendor}.yaml to onboard it."
            )
        return PatternAdapter(pack, self._learned_for(vendor))
