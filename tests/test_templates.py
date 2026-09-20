"""Template masking — the properties that let a template be a database key.

``backend/ai/templates.py`` is the grouping key for the C2 training queue and the
primary key of the mapping store. Three properties have to hold for that to be
safe, and each one has a section below:

* **Purity.** The same line always yields the same template, on any machine, in
  any order. This is the whole reason the module exists instead of calling drain3
  on the request path — drain3's parse tree adapts as lines arrive, so its
  template for a line is a function of ingestion history. A key that changes when
  a different file is uploaded first is not a key.

* **Narrow masking.** A mask that eats a keyword merges two different commands
  into one template, and the operator then teaches a mapping that fires on a line
  they never saw. The tests state which shapes are variable and, more
  importantly, which are not.

* **No over-claiming.** A compiled taught pattern must match the lines the
  operator meant and refuse the ones they did not. ``logging host <*>`` must not
  claim ``logging host 10.0.0.1 transport tcp``, which is a different command with
  a different meaning.

The failure mode being defended against throughout is a *silent wrong fact*: a
taught mapping that matches too much produces a canonical fact with the wrong
value, a rule then reaches a verdict from it, and the report says PASS with a
line number attached. There is no error anywhere in that chain.
"""

from __future__ import annotations

import re

import pytest

from backend.ai.templates import (
    WILDCARD,
    build_learned_pattern,
    cluster_lines,
    mine_template,
    template_id,
    template_to_regex,
    wildcard_count,
)
from backend.ingest.patterns import Coercion

# ── Purity and stability ──────────────────────────────────────────────


def test_masking_is_pure() -> None:
    """Repeated calls, and calls in different orders, agree.

    Deliberately interleaved: if the masker held any state, mining B between two
    minings of A would show up here and nowhere else.
    """
    a = "logging host 10.0.0.1"
    b = "ntp server 192.168.1.1 key 7"
    first_a = mine_template(a)
    mine_template(b)
    assert mine_template(a) == first_a
    assert mine_template(b) == mine_template(b)


def test_template_id_is_stable_and_scoped() -> None:
    """The id is a pure function of the template text and is namespaced.

    The ``taught:`` prefix is load-bearing: template ids become ``LinePattern.id``
    values, which share a namespace with the ids a hand-authored pack declares. A
    collision there would make a taught pattern indistinguishable from a shipped
    one in every log line and every provenance record.
    """
    template = mine_template("snmp-server community public RO")
    assert template_id(template) == template_id(template)
    assert template_id(template).startswith("taught:")
    assert template_id(template) != template_id(template + " extra")


@pytest.mark.parametrize(
    "spelling",
    [
        "logging host 10.0.0.1",
        "  logging host 10.0.0.1",
        "logging host 10.0.0.1  ",
        "logging  host   10.0.0.1",
        "\tlogging host 10.0.0.1\t",
    ],
)
def test_whitespace_does_not_split_a_cluster(spelling: str) -> None:
    """Indentation and interior whitespace runs are normalised away.

    Configs arrive from ``show running-config``, from TFTP archives and from
    copy-paste, and the three indent differently. A queue that listed the same
    command three times because of leading tabs is a queue an operator stops
    trusting.
    """
    assert mine_template(spelling) == "logging host <*>"


# ── What is masked, and what is not ───────────────────────────────────


@pytest.mark.parametrize(
    "line,expected",
    [
        # Addresses, in each shape the CLI accepts.
        ("logging host 10.0.0.1", "logging host <*>"),
        ("ip route 0.0.0.0 0.0.0.0 10.1.1.1", "ip route <*> <*> <*>"),
        ("ip address 10.0.0.1/24", "ip address <*>"),
        ("ntp server 2001:db8::1", "ntp server <*>"),
        # Bare numbers.
        ("ip ssh version 2", "ip ssh version <*>"),
        ("exec-timeout 5 0", "exec-timeout <*> <*>"),
        # A numeric range is one operand.
        ("switchport trunk allowed vlan 10-20", "switchport trunk allowed vlan <*>"),
        # Interface- and instance-style names.
        ("interface GigabitEthernet0/0/1", "interface <*>"),
        ("switchport access vlan 20", "switchport access vlan <*>"),
        # Secrets: recorded as variable, never as literal.
        ("enable secret 5 $1$abc$defghi", "enable secret <*> <*>"),
        ("username admin secret 9 $9$abcdefghijklmnop", "username admin secret <*> <*>"),
        # Quoted strings are data however they are spelled.
        ('banner motd "Authorised users only"', "banner motd <*>"),
    ],
)
def test_variable_operands_are_masked(line: str, expected: str) -> None:
    """The four variable shapes the module documents, one case each."""
    assert mine_template(line) == expected


@pytest.mark.parametrize(
    "line,must_keep",
    [
        # Keywords that merely contain digits are not operands. Masking these
        # would merge distinct commands: 'address-family ipv4 unicast' and its
        # IPv6 counterpart are not the same command.
        ("encapsulation dot1q 100", "dot1q"),
        ("address-family ipv4 unicast", "ipv4"),
        ("address-family ipv6 unicast", "ipv6"),
        # Crypto strength is the compliance-relevant part of the line. 'integrity
        # sha512' passes a STIG control that 'integrity md5' fails, so a template
        # that covers both is a template that answers neither.
        ("integrity sha512", "sha512"),
        ("integrity md5", "md5"),
        ("encryption aes-cbc-256", "aes-cbc-256"),
        ("authentication hmac-sha1-96", "hmac-sha1-96"),
        # A hyphenated keyword whose tail happens to be a number is still one
        # keyword: 'level-2-only' is not 'level-<n>-only'.
        ("is-type level-2-only", "level-2-only"),
        # Protocol version words are part of the command, not its argument.
        ("snmp-server group ADMIN v3 priv", "v3"),
        ("snmp-server host 10.0.0.1 version 2c public", "2c"),
        # A keyword ending in a digit that is still a keyword.
        ("ip http secure-server", "secure-server"),
    ],
)
def test_keywords_are_not_masked(line: str, must_keep: str) -> None:
    """Under-masking costs a longer queue; over-masking costs a wrong fact.

    So the bias is explicit and tested: anything that could be a keyword stays
    literal, and the operator maps two templates instead of one.
    """
    template = mine_template(line)
    assert must_keep in template, (
        f"{line!r} masked the keyword {must_keep!r} into {template!r}. Two "
        "different commands now share one template, so a mapping taught on one "
        "would silently fire on the other."
    )


@pytest.mark.parametrize(
    "name",
    [
        "GigabitEthernet0/0/1",
        "TenGigabitEthernet1/0/24",
        "Serial0/0/0:0",
        "ge-0/0/1",
        "Eth1/1",
    ],
)
def test_interface_names_with_separators_are_masked(name: str) -> None:
    """A separator is what makes a letters-then-digits token an interface name.

    Every form a running-config actually writes carries one, because IOS, NX-OS,
    EOS and Junos all expand abbreviations on output.
    """
    assert mine_template(f"interface {name}") == "interface <*>"


@pytest.mark.parametrize("name", ["Vlan100", "Loopback0", "Port-channel10"])
def test_separatorless_interface_names_are_left_literal(name: str) -> None:
    """The documented cost of requiring a separator, stated as a test.

    ``Vlan100`` is indistinguishable in shape from ``sha512``, and no amount of
    regex resolves that without a vendor-specific name list inside a
    vendor-agnostic masker. So these are left literal and the operator maps one
    template per interface — a longer queue, never a wrong fact. This test exists
    so the trade-off is visible rather than surprising, and so that a future change
    to widen the mask has to come here and argue with it.
    """
    assert name in mine_template(f"interface {name}")


def test_dotted_identifiers_mask_as_one_operand() -> None:
    """An IS-IS NET is one identifier, not six numbers.

    Before the dotted-identifier mask, the bare-number mask shredded
    ``49.0001.0000.0000.0001.00`` into ``net <*>.<*>.<*>.<*>.<*>.<*>`` — a
    template no operator would recognise as the line they uploaded.
    """
    assert mine_template("net 49.0001.0000.0000.0001.00") == "net <*>"
    assert mine_template("clns net 0011.2233.4455") == "clns net <*>"
    assert mine_template("version 15.0") == "version <*>"


def test_an_address_and_its_mask_are_two_operands() -> None:
    """The regression that made a whole class of taught mapping never fire.

    A combined ``IPv4 IPv4`` mask folded address and dotted mask into one ``<*>``.
    Two things broke at once: ``network 10.20.0.0 0.0.0.3`` became
    indistinguishable from a bare ``network 10.20.0.0``, and the compiled regex
    could no longer match the line the template was mined from, because a single
    operand cannot span a space.
    """
    assert mine_template("network 10.20.0.0 0.0.0.3") == "network <*> <*>"
    assert mine_template("network 10.20.0.0") == "network <*>"
    assert mine_template("network 10.20.0.0") != mine_template(
        "network 10.20.0.0 0.0.0.3"
    )


def test_a_quoted_operand_round_trips_despite_its_spaces() -> None:
    """The one operand that may contain whitespace, and why that is safe.

    Banners, interface descriptions and ``snmp-server location`` are quoted runs
    with spaces in them, so the compiled operand accepts a quoted string as well
    as a whitespace-free token. Quoting is self-delimiting, which is what keeps the
    widening from costing the no-over-claiming property — asserted on the last two
    lines.
    """
    template = mine_template('banner motd "Authorised users only"')
    assert template == "banner motd <*>"

    regex = re.compile(template_to_regex(template), re.IGNORECASE)
    match = regex.match('banner motd "Authorised users only"')
    assert match is not None
    assert match.group("value") == '"Authorised users only"'

    unquoted = re.compile(template_to_regex("logging host <*>"), re.IGNORECASE)
    assert unquoted.match("logging host 10.0.0.1")
    assert not unquoted.match("logging host 10.0.0.1 transport tcp")


def _fixture_unparsed_lines() -> list[str]:
    """Every distinct line the shipped fixtures leave unparsed.

    Collected at import time from the real parser rather than hand-listed, so the
    round-trip property below is asserted against what the ingestion engine
    actually produces today. Add a fixture or widen a pack and this corpus follows
    without anyone remembering to update it.
    """
    from backend.app.config import FILE_ENCODING, PROJECT_ROOT
    from backend.ingest.generic import PatternAdapterRegistry

    config_dir = PROJECT_ROOT / "test_configs"
    if not config_dir.exists():
        return []

    registry = PatternAdapterRegistry()
    seen: dict[str, str] = {}
    for config in sorted(config_dir.rglob("*.conf")):
        text = config.read_text(encoding=FILE_ENCODING)
        adapter = registry.detect(text, config.name)
        if adapter is None:
            continue
        for entry in adapter.parse(text, config.name).unparsed_lines:
            raw = str(entry.get("raw_text", "")).strip()
            if raw:
                seen.setdefault(mine_template(raw), raw)
    return sorted(seen.values())


@pytest.mark.parametrize(
    "line",
    [
        "logging host 10.0.0.1",
        "network 10.20.0.0 0.0.0.3",
        "network 10.100.0.0 mask 255.255.0.0",
        "ip route 0.0.0.0 0.0.0.0 10.1.1.1",
        "ip prefix-list INTERNAL seq 5 permit 10.100.0.0/16 le 32",
        "net 49.0001.0000.0000.0001.00",
        "neighbor 10.20.0.2 remote-as 65002",
        "interface GigabitEthernet0/0/1",
        "enable secret 5 $1$abc$defghi",
        "integrity sha512",
        "no auto-summary",
        "snmp-server ifindex persist",
        "is-type level-2-only",
        'banner motd "Authorised users only"',
        "ntp server 2001:db8::1",
        *_fixture_unparsed_lines(),
    ],
)
def test_every_template_matches_the_line_it_came_from(line: str) -> None:
    """The round trip — the single most important property in the module.

    The chain the C2 training module runs is: mine a template from an unparsed
    line, show it to the operator, compile it back to a regex, and match it against
    future configs. If the compiled regex does not match the line the template was
    mined from, the operator's mapping is accepted and then silently matches
    nothing — no error, no fact, no finding, and a queue entry that never clears.

    The hand-written cases pin the shapes that have broken before. The rest are
    generated from :func:`_fixture_unparsed_lines`, so the property is checked
    against every line the shipped configs actually leave for the training module
    rather than against a list someone curated once.
    """
    template = mine_template(line)
    regex = re.compile(template_to_regex(template), re.IGNORECASE)
    assert regex.match(line), (
        f"{line!r} mined to {template!r}, whose regex "
        f"{template_to_regex(template)!r} does not match the original line."
    )


def test_the_fixture_corpus_is_not_empty() -> None:
    """The generated half of the round-trip test must not be vacuous.

    If the packs ever parse everything, this test is the thing that says so out
    loud instead of letting the parametrised list quietly shrink to the
    hand-written cases.
    """
    assert _fixture_unparsed_lines(), (
        "no fixture leaves any line unparsed, so the round-trip property is only "
        "being checked against hand-written examples. Either a pack widened (good "
        "— retire this assertion) or the fixtures stopped loading (bad)."
    )


def test_a_bare_command_masks_nothing() -> None:
    """A command with no operands is its own template, with zero wildcards.

    This is the case that decides the coercion in
    :func:`build_learned_pattern`: no operand means the fact is presence, so the
    pattern emits ``true`` rather than trying to capture a value.
    """
    template = mine_template("service password-encryption")
    assert template == "service password-encryption"
    assert wildcard_count(template) == 0


def test_adjacent_masks_collapse_but_separated_ones_do_not() -> None:
    """``<*><*>`` cannot appear, but ``<*> <*>`` must.

    ``ip route 10.0.0.0 255.0.0.0 192.168.1.1`` masks three operands and the
    operator has to be able to choose which one carries the value, so the
    operands must remain individually addressable by ``value_index``.
    """
    template = mine_template("ip route 10.0.0.0 255.255.255.0 192.168.1.1")
    assert f"{WILDCARD}{WILDCARD}" not in template
    assert wildcard_count(template) == 3


# ── Clustering ────────────────────────────────────────────────────────


def test_cluster_lines_groups_by_template_in_file_order() -> None:
    """One cluster per template, ordered by first occurrence, provenance kept.

    File order matters because the operator reads the queue against the config
    open beside it. Keeping every occurrence rather than a count matters because
    the training GUI shows a concrete example line, and a count cannot be clicked
    through to a source line.
    """
    unparsed = [
        {"line_number": 10, "raw_text": "logging host 10.0.0.1", "block": ""},
        {"line_number": 12, "raw_text": "custom-widget enable", "block": ""},
        {"line_number": 14, "raw_text": "logging host 10.0.0.2", "block": ""},
        {"line_number": 16, "raw_text": "logging host 192.168.44.7", "block": ""},
    ]
    clusters = cluster_lines(unparsed)

    assert [c.template for c in clusters] == [
        "logging host <*>",
        "custom-widget enable",
    ]
    assert clusters[0].cluster_size == 3
    assert clusters[1].cluster_size == 1
    assert clusters[0].example["line_number"] == 10
    assert [line["line_number"] for line in clusters[0].lines] == [10, 14, 16]


def test_cluster_lines_drops_blank_entries() -> None:
    """A whitespace-only unparsed entry is noise, not something to teach."""
    clusters = cluster_lines(
        [
            {"line_number": 1, "raw_text": "   ", "block": ""},
            {"line_number": 2, "raw_text": "", "block": ""},
            {"line_number": 3, "raw_text": "real-command here", "block": ""},
        ]
    )
    assert [c.template for c in clusters] == ["real-command here"]


# ── Compilation: the no-over-claiming property ────────────────────────


def test_compiled_pattern_is_anchored_at_both_ends() -> None:
    """The regex must describe a whole line, not a prefix of one."""
    source = template_to_regex("logging host <*>")
    assert source.startswith("^")
    assert source.endswith("$")


def test_compiled_pattern_does_not_claim_a_longer_command() -> None:
    """The property that keeps a taught mapping from producing a wrong fact.

    ``logging host <*>`` sends syslog over UDP to a host. ``logging host <*>
    transport tcp`` is a different configuration with different compliance
    consequences. A pattern that matched both would attach the first mapping's
    canonical path to the second command's line, and the resulting fact would be
    wrong with a citation.
    """
    regex = re.compile(template_to_regex("logging host <*>"), re.IGNORECASE)

    assert regex.match("logging host 10.0.0.1")
    assert regex.match("  logging  host   10.0.0.1  "), "whitespace-tolerant"
    assert regex.match("LOGGING HOST 10.0.0.1"), "case-insensitive"
    assert not regex.match("logging host 10.0.0.1 transport tcp")
    assert not regex.match("no logging host 10.0.0.1")
    assert not regex.match("logging trap informational")


def test_value_index_selects_which_operand_is_captured() -> None:
    """Each operand is reachable, and the captured text is the chosen one."""
    template = mine_template("ip route 10.0.0.0 255.255.255.0 192.168.1.1")
    line = "ip route 10.0.0.0 255.255.255.0 192.168.1.1"

    captured = []
    for index in range(wildcard_count(template)):
        match = re.match(template_to_regex(template, index), line)
        assert match is not None, f"operand {index} regex stopped matching the line"
        captured.append(match.group("value"))

    assert captured == ["10.0.0.0", "255.255.255.0", "192.168.1.1"]


@pytest.mark.parametrize("bad_index", [1, 2, 99, -1])
def test_out_of_range_value_index_is_refused(bad_index: int) -> None:
    """Refusing beats falling back to operand 0.

    A silent fallback would compile a pattern that reads a different field from
    the one the operator selected in the GUI — the mapping would look accepted and
    produce a wrong value on every device it matched.
    """
    with pytest.raises(ValueError, match="value_index"):
        template_to_regex("ip ssh version <*>", value_index=bad_index)


def test_build_learned_pattern_picks_coercion_from_the_template() -> None:
    """Operands present → capture and infer; none → assert presence.

    ``auto`` is acceptable here and nowhere else: the operator supplied a
    canonical path and a masked line, and had no field in which to declare a
    type. ``tests/test_pattern_packs.py`` asserts the complementary half — that no
    hand-authored pack uses ``auto``.
    """
    with_value = build_learned_pattern("ip ssh version <*>", "mgmt.ssh.version")
    assert with_value.emits[0].coercion == Coercion.AUTO
    assert with_value.emits[0].path == "mgmt.ssh.version"

    presence = build_learned_pattern(
        "service password-encryption", "service.password_encryption"
    )
    assert presence.emits[0].coercion == Coercion.TRUE


def test_build_learned_pattern_id_matches_the_template_id() -> None:
    """The pattern id and the store's primary key must be the same string.

    They are joined on in ``mapping_store``: a taught fact's provenance carries
    the pattern id, and the only way back from a fact to the mapping that produced
    it — the audit question "who taught this, and when" — is that equality.
    """
    template = "ip ssh version <*>"
    pattern = build_learned_pattern(template, "mgmt.ssh.version")
    assert pattern.id == template_id(template)


def test_build_learned_pattern_rejects_a_bad_value_index() -> None:
    """Compilation, not first use, is where a bad mapping is caught.

    ``upsert_mapping`` compiles before it writes for exactly this reason: a
    mapping that cannot compile must never reach the database, because it would
    then fail on every parse for every device until someone noticed.
    """
    with pytest.raises(ValueError):
        build_learned_pattern("ip ssh version <*>", "mgmt.ssh.version", value_index=3)
