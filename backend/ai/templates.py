"""Line templating — the grouping key that makes the training module usable.

An unparsed configuration line is not interesting on its own. A 400-device
estate produces the same unmapped command 400 times with a different address on
each one, and a training queue that lists all 400 is a queue nobody works
through. So every unparsed line is reduced to a *template*: the command with its
variable operands masked.

    logging host 10.0.0.1        ─┐
    logging host 10.0.0.2         ├─  logging host <*>      cluster_size = 3
    logging host 192.168.44.7    ─┘

The operator maps the template once and every line that shares it is mapped.

**Why this is not drain3.** drain3 is installed and is used offline by
``scripts/build_template_index.py`` to mine templates from the corpus. It is a
poor fit for the request path for one reason: it is stateful. Its parse tree
adapts as lines arrive, so the template a line yields depends on which lines
were seen before it. That would make the mapping-store key - and therefore
whether a taught mapping still matches - a function of ingestion order. Here the
masker is a pure function of the line, so the same line always produces the same
template, on any machine, in any order, forever. That property is what lets the
template be a database key.

Masking is deliberately narrow. Only these shapes are variable:

* an address (IPv4/IPv6, optionally with a prefix length). A dotted subnet mask
  is a *second* operand and is masked as one, not folded into the address;
* a dotted or colon-separated numeric identifier that is not an address — an
  IS-IS NET, a dotted MAC, a version number;
* a bare number;
* an interface-style name — letters followed by digits **carrying a separator**,
  as in ``GigabitEthernet0/0/1``. The separator is what distinguishes an
  interface from a keyword that merely ends in a digit;
* a secret (``$9$…``, or a long hex/base64 blob).

Everything else stays literal, because a mask that eats a keyword merges two
different commands into one template, and the operator then teaches a mapping
that fires on a line they never saw. Under-masking costs a longer queue;
over-masking costs a wrong fact.

Two invariants on the mask list are stated at :data:`_MASKS` and enforced by
``tests/test_templates.py``: a mask may not consume whitespace (or the compiled
regex cannot match the line the template came from), and a mask may not eat a
keyword (or two commands share one template).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from backend.ingest.patterns import Coercion, Emission, LinePattern

#: The mask token. Same spelling drain3 uses, so templates mined offline by
#: ``scripts/build_template_index.py`` and templates masked here are comparable.
WILDCARD = "<*>"

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_IPV6 = r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"

#: Applied in order. The first match wins for a given token, so the address
#: patterns must precede the bare-number one or ``10.0.0.1`` would be masked
#: one octet at a time.
#:
#: Two invariants constrain what may be added here, and both were violated by the
#: first version of this list:
#:
#: 1. **A mask must round-trip.** ``<*>`` compiles to :data:`_OPERAND`, so a mask
#:    may only consume text that ``_OPERAND`` can match back — whitespace-free, or
#:    a quoted run. A mask for ``IPv4 IPv4`` (address plus dotted mask) turned
#:    ``network 10.20.0.0 0.0.0.3`` into ``network <*>``, whose regex cannot match
#:    the very line the template was mined from: the operator teaches the mapping,
#:    the store accepts it, and it produces zero facts forever. That failure is
#:    silent at every step, which is why ``tests/test_templates.py`` asserts the
#:    round trip over every line the shipped fixtures leave unparsed.
#: 2. **A mask must not eat a keyword.** ``integrity sha512`` and ``integrity
#:    md5`` are different answers to a STIG control on IKEv2 integrity; a mask
#:    that reduces both to ``integrity <*>`` merges them into one template, and a
#:    mapping taught on the compliant line then fires on the non-compliant one.
_MASKS: tuple[re.Pattern[str], ...] = (
    # A quoted string: its contents are data, however it is spelled. This is the
    # one operand that legitimately contains spaces — banners, interface
    # descriptions, `snmp-server location` — which is why _OPERAND below accepts a
    # quoted run as well as a whitespace-free one.
    re.compile(r'"[^"]*"'),
    re.compile(r"'[^']*'"),
    # An IOS/NX-OS type-N secret, and the long hex/base64 blobs.
    re.compile(r"\$\d+\$\S+"),
    re.compile(r"\b[0-9A-Fa-f]{16,}\b"),
    # Addresses, with an optional prefix length. An address and its dotted mask
    # are two operands and are masked as two: see invariant 1 above.
    re.compile(rf"\b{_IPV4}/\d{{1,2}}\b"),
    re.compile(rf"\b{_IPV4}\b"),
    re.compile(rf"\b{_IPV6}(?:/\d{{1,3}})?"),
    # Interface- and instance-style names: letters, then digits carrying a
    # separator. GigabitEthernet0/0/1, Te1/0/1, ge-0/0/1, Serial0/0/0:0.
    #
    # The separator is required, which is narrower than it looks and deliberately
    # so. Without it the pattern also matched every keyword that ends in a digit —
    # `md5`, `sha512`, `aes256`, `ipv4`, `ipv6`, `v3` — and merged
    # `address-family ipv4 unicast` with its IPv6 counterpart. The cost is that a
    # separator-less name like `Vlan100` is not masked, so an operator teaching
    # unhandled interface lines maps one template per interface. That is the
    # documented trade: under-masking costs a longer queue, over-masking costs a
    # wrong fact.
    #
    # Ordered before the dotted-identifier mask, which would otherwise claim the
    # `0:0` tail of `Serial0/0/0:0` and leave `<*>/<*>`.
    re.compile(r"\b[A-Za-z][A-Za-z-]*\d\d*(?:[/.:]\d+)+\b"),
    # A dotted or colon-separated numeric string that is not an address: an IS-IS
    # NET (49.0001.0000.0000.0001.00), a dotted MAC (0011.2233.4455), a version
    # (15.0). Runs after the address masks so it cannot pre-empt them, and before
    # the bare-number mask, which would otherwise shred one identifier into six.
    re.compile(r"\b\d\d*(?:[.:][0-9A-Fa-f]+)+\b"),
    # A numeric range is one operand, not two. `switchport trunk allowed vlan
    # 10-20` names a range; masking the ends separately would leave `vlan <*>-20`,
    # which is both unreadable and wrong about where the operand boundary is.
    re.compile(r"\b\d+-\d+\b"),
    # A bare number, last, so it cannot pre-empt anything above.
    #
    # The lookbehind keeps the mask off a number that is the tail of a hyphenated
    # keyword. `aes-cbc-256` and `aes-cbc-128` are different cipher strengths and
    # a STIG control distinguishes them; `hmac-sha1-96` is one algorithm name;
    # `level-2-only` is one IS-IS keyword, not a keyword with an operand. All three
    # were being masked, merging commands whose difference is the whole point of
    # the control that reads them. The class is ``\w`` rather than ``[A-Za-z]``
    # because the character before the hyphen is itself often a digit — the `1` of
    # `sha1` — and that is still a keyword, not an operand boundary.
    re.compile(r"(?<!\w-)\b\d+\b"),
)

#: What a single masked operand may match when a template is compiled back to a
#: regex. Whitespace-free by default, plus the two quoted forms, which are
#: self-delimiting and so cannot swallow a following operand: ``logging host <*>``
#: still refuses ``logging host 10.0.0.1 transport tcp``.
_OPERAND = r'"[^"]*"|\'[^\']*\'|\S+'


def mine_template(line: str) -> str:
    """Reduce one configuration line to its template.

    Args:
        line: A raw configuration line. Leading and trailing whitespace and
            interior whitespace runs are normalised, because a template that
            differs only in indentation would split one cluster into two.

    Returns:
        The line with every variable operand replaced by ``<*>``.
    """
    text = re.sub(r"\s+", " ", line.strip())
    for mask in _MASKS:
        text = mask.sub(WILDCARD, text)
    # Two adjacent masked operands (``ip route <*> <*> <*>``) stay separate
    # tokens, but a mask that consumed a separator can leave ``<*><*>``.
    return re.sub(r"(?:<\*>){2,}", WILDCARD, text)


def template_id(template: str) -> str:
    """A short stable id for a template, used as a pattern id and queue key."""
    digest = hashlib.sha256(template.encode("utf-8")).hexdigest()
    return f"taught:{digest[:12]}"


def wildcard_count(template: str) -> int:
    """How many operands the template masks. Zero means a bare command."""
    return template.count(WILDCARD)


@dataclass(frozen=True)
class TemplateCluster:
    """One template and the lines that produced it, in first-seen order."""

    template: str
    template_id: str
    lines: tuple[dict, ...]

    @property
    def cluster_size(self) -> int:
        """How many raw lines this template stands for."""
        return len(self.lines)

    @property
    def example(self) -> dict:
        """The first line seen, shown to the operator as the concrete case."""
        return self.lines[0]


def cluster_lines(unparsed: list[dict]) -> list[TemplateCluster]:
    """Group unparsed lines by template, preserving first-seen order.

    Args:
        unparsed: ``ParseResult.unparsed_lines`` entries. Each is a dict with
            ``line_number``, ``raw_text`` and the enclosing block, so the
            cluster keeps every occurrence's provenance rather than collapsing
            to a count.

    Returns:
        One cluster per distinct template, ordered by the line number of the
        first occurrence so the queue reads in file order.
    """
    order: list[str] = []
    grouped: dict[str, list[dict]] = {}
    for entry in unparsed:
        raw = str(entry.get("raw_text", "")).strip()
        if not raw:
            continue
        template = mine_template(raw)
        if template not in grouped:
            grouped[template] = []
            order.append(template)
        grouped[template].append(entry)
    return [
        TemplateCluster(
            template=template,
            template_id=template_id(template),
            lines=tuple(grouped[template]),
        )
        for template in order
    ]


def template_to_regex(template: str, value_index: int = 0) -> str:
    """Turn a template back into an anchored regex with one capture group.

    Args:
        template: A template as produced by :func:`mine_template`.
        value_index: Which masked operand carries the fact's value. The others
            are matched but not captured.

    Returns:
        A regex source string, anchored at both ends.

    Raises:
        ValueError: When ``value_index`` names an operand the template does not
            have. Silently falling back to operand 0 would teach a mapping that
            reads the wrong field, which is worse than refusing the mapping.

    The anchoring is the safety property. ``<*>`` becomes :data:`_OPERAND` — a
    whitespace-free run, or a quoted string — rather than ``.*``, and the regex
    must match the whole line, so a taught pattern for ``logging host <*>`` cannot
    also claim ``logging host 10.0.0.1 transport tcp``, a line that means
    something different and deserves its own mapping.
    """
    total = wildcard_count(template)
    if total and not 0 <= value_index < total:
        raise ValueError(
            f"value_index {value_index} is out of range: the template "
            f"{template!r} masks {total} operand(s)"
        )

    parts = template.split(WILDCARD)
    pieces: list[str] = []
    for position, literal in enumerate(parts):
        pieces.append(_literal_to_regex(literal))
        if position < len(parts) - 1:
            pieces.append(
                f"(?P<value>{_OPERAND})"
                if position == value_index
                else f"(?:{_OPERAND})"
            )
    return r"^\s*" + "".join(pieces) + r"\s*$"


def _literal_to_regex(literal: str) -> str:
    """Escape a literal template segment, letting whitespace match any run.

    Whitespace in the template stands for whitespace of any width in the config:
    ``line vty  0 4`` and ``line vty 0 4`` are the same command, and a taught
    mapping that missed the second because the operator's example was
    double-spaced would be a silent false negative.
    """
    return r"\s+".join(re.escape(chunk) for chunk in literal.split(" "))


def build_learned_pattern(
    template: str,
    canonical_path: str,
    value_index: int = 0,
) -> LinePattern:
    """Compile one taught mapping into a pattern the parser can run.

    A mapping with no masked operand emits ``true``: the fact is that the
    command is present. A mapping with operands emits the captured one under
    :data:`~backend.ingest.patterns.Coercion.AUTO`, because the operator had no
    field in which to declare whether they were looking at a number or a name.

    Raises:
        ValueError: When ``value_index`` is out of range for the template.
    """
    source = template_to_regex(template, value_index)
    coercion = Coercion.AUTO if wildcard_count(template) else Coercion.TRUE
    return LinePattern(
        id=template_id(template),
        regex=re.compile(source, re.IGNORECASE),
        emits=(Emission(path=canonical_path, coercion=coercion),),
        note=f"taught mapping for template {template!r}",
    )
