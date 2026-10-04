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
from backend.ingest.blocks import BlockInstance, BlockScanner
from backend.ingest.patterns import (
    SKIP,
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
        self._scanner = BlockScanner(pack)
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
        instances = self._scanner.scan(lines)

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

            enclosing = self._scanner.enclosing(instances, line_no)
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
        return self._scanner.is_comment(stripped)

    def _is_ignored(self, stripped: str) -> bool:
        """Whether the pack declares this line structural noise."""
        return any(pattern.match(stripped) for pattern in self.pack.ignore)


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
        packs = self.library.packs().values()
        learned = self._learned_for_all([pack.vendor for pack in packs])
        return [PatternAdapter(pack, learned.get(pack.vendor, [])) for pack in packs]

    def _learned_for_all(self, vendors: list[str]) -> dict[str, list[LinePattern]]:
        """Fetch taught patterns for every pack in one sweep, if the store allows.

        Asked once per pack per parse, so the per-vendor form reconnected to the
        database seven times per config — see ``docs/GAPS.md`` §6. The one-vendor
        path stays because the provider is a plain callable by design, which is
        what lets tests inject patterns with no database at all.
        """
        if self._learned_provider is None:
            return {}
        bulk = getattr(self._learned_provider, "load_many", None)
        if callable(bulk):
            return {
                vendor: list(result.patterns) for vendor, result in bulk(vendors).items()
            }
        return {vendor: self._learned_for(vendor) for vendor in vendors}

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
