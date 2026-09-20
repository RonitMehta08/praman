"""Test: redaction removes credentials without changing what the auditor sees.

Redaction has two obligations that pull against each other, and the interesting
tests are the ones that hold both at once:

* no credential reaches a response, the fact store, a PDF, the ledger or the C2
  training queue;
* every *non*-credential field on a redacted line still parses, and every verdict
  is the verdict the unredacted config would have produced.

The second obligation is the one that was broken, and silently. Redaction used to
run as a pre-parse text filter whose replacement token contained spaces; because
every pattern in every pack reads whitespace-delimited fields, a one-token secret
becoming three tokens shifted the rest of the line and the line stopped matching
entirely. That lost 58 facts and changed 31 verdicts across the ten shipped
fixtures — including ``insecure_minimal``, a fixture built to be insecure, which
started reporting PASS on two SNMP controls because the mangled community line no
longer produced ``snmp.enabled`` at all.

So the two headline tests here are whole-estate differentials:
:class:`TestRedactionPreservesFacts` and :class:`TestRedactionPreservesVerdicts`
parse every fixture twice, once redacted and once not, and compare. A pattern that
over-reaches fails them even if every unit test below still passes.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path
from typing import ClassVar

import pytest

from backend.app.main import STATE
from backend.ingest.redact import (
    REDACTED,
    SECRET_VALUE_PATHS,
    WELL_KNOWN_COMMUNITIES,
    redact_fact_value,
    redact_parse_result,
    redact_secrets,
)
from backend.rules.evaluator import RulesEvaluator

FIXTURE_DIR = Path(__file__).parent.parent / "test_configs"

SAMPLE_CONFIG = """!
hostname test-sw-01
!
enable secret 0 cleartext_password
enable secret 5 $1$abcd$xyz
!
snmp-server community public RO
snmp-server community secret123 RW SNMP-ACL
!
username admin password 0 mypassword
username admin2 privilege 15 password 5 $1$xyz$abc
username auditor privilege 5 secret 9 $9$scrypthash
!
tacacs-server host 10.0.0.1 key mysecretkey
radius-server host 10.0.0.2 auth-port 1812 acct-port 1813 key 7 encodedkey
!
ntp authentication-key 1 md5 ntpkey123
!
"""


def _fixtures() -> list[Path]:
    """Every shipped fixture. Recursive — test_configs/ is a category taxonomy."""
    return sorted(FIXTURE_DIR.rglob("*.conf"))


def _parse(text: str, name: str):
    """Parse without redacting — the control arm of the differential tests."""
    adapter = STATE.detect(text, name)
    assert adapter is not None, f"no adapter claimed {name}; see _synthetic()"
    return adapter.parse(text, name)


def _synthetic(body: str) -> str:
    """Wrap a snippet in the minimum an IOS config needs to be detected as one.

    ``version 15.2`` is the marker vendor detection keys on. Without it
    ``STATE.detect`` returns None and the snippet is never parsed, which would
    make a redaction assertion pass by never running.
    """
    return f"!\nversion 15.2\nhostname r1\n!\n{body}!\nend\n"


def _fixture_text(path: Path) -> str:
    """Read as the endpoints do, NFKC-normalised."""
    return unicodedata.normalize("NFKC", path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def evaluator() -> RulesEvaluator:
    """One evaluator for the module — construction loads 42 catalogs from disk."""
    return RulesEvaluator()


def _result_of(finding) -> str:
    """``Finding.result`` is an enum or a plain str depending on call path."""
    return str(getattr(finding.result, "value", finding.result))


def _framework_of(finding) -> str:
    return str(getattr(finding.framework, "value", finding.framework))


# ─────────────────────────────────────────────────────────────────────────
# Function contract
# ─────────────────────────────────────────────────────────────────────────


class TestRedactionPurity:
    def test_pure_function(self) -> None:
        assert redact_secrets(SAMPLE_CONFIG) == redact_secrets(SAMPLE_CONFIG)

    def test_idempotent(self) -> None:
        once = redact_secrets(SAMPLE_CONFIG)
        assert redact_secrets(once) == once

    def test_idempotent_on_every_fixture(self) -> None:
        """The conditional patterns make this worth checking on real input.

        A pattern that decides based on the captured value must not re-inspect a
        token it has already replaced — ``REDACTED`` is not a well-known community,
        so a second pass over an already-redacted community line would be a
        different decision if the line were not skipped outright.
        """
        for path in _fixtures():
            once = redact_secrets(_fixture_text(path))
            assert redact_secrets(once) == once, f"not idempotent: {path.name}"

    def test_replacement_token_has_no_whitespace(self) -> None:
        """The bug, pinned as a test.

        Every pattern in every pack splits on whitespace. A replacement containing
        a space occupies more field positions than the secret it replaced, which
        shifts every field after it and stops the line matching. Nothing else in
        this file would catch a regression here as directly.
        """
        assert REDACTED.split() == [REDACTED]

    def test_line_and_field_count_are_preserved(self) -> None:
        """Structure-preserving, stated at the level the packs care about."""
        redacted = redact_secrets(SAMPLE_CONFIG)
        original_lines = SAMPLE_CONFIG.splitlines()
        redacted_lines = redacted.splitlines()
        assert len(original_lines) == len(redacted_lines)
        for before, after in zip(original_lines, redacted_lines, strict=True):
            assert len(before.split()) == len(after.split()), (
                f"field count changed: {before!r} -> {after!r}"
            )


# ─────────────────────────────────────────────────────────────────────────
# What gets replaced
# ─────────────────────────────────────────────────────────────────────────


class TestCredentialsAreRemoved:
    """One case per credential form the packs can encounter."""

    @pytest.mark.parametrize(
        ("line", "secret"),
        [
            # Line-initial forms.
            ("enable secret 0 cleartext_password", "cleartext_password"),
            ("enable secret 5 $1$abcd$xyz", "$1$abcd$xyz"),
            ("enable secret 9 $9$scrypthash", "$9$scrypthash"),
            ("enable password 7 05080F1C2243", "05080F1C2243"),
            ("enable secret level 15 0 levelpw", "levelpw"),
            ("username admin password 0 mypassword", "mypassword"),
            ("username a privilege 15 password 5 $1$xyz$abc", "$1$xyz$abc"),
            ("username b privilege 5 secret 9 $9$scrypt", "$9$scrypt"),
            ("username c view ALLVIEW secret 0 viewpw", "viewpw"),
            (" password 7 05080F1C2243", "05080F1C2243"),
            (" password cleartextvty", "cleartextvty"),
            ("tacacs-server host 10.0.0.1 key mysecretkey", "mysecretkey"),
            ("tacacs-server key MyTacacsSecret", "MyTacacsSecret"),
            ("key-string 7 070C285F4D061A33", "070C285F4D061A33"),
            (" key-string TheActualSecret", "TheActualSecret"),
            ("ip ospf authentication key ospfsecret", "ospfsecret"),
            ("ip ospf message-digest-key 1 md5 7 070C285F", "070C285F"),
            ("crypto isakmp key MyPreSharedKey address 10.0.0.1", "MyPreSharedKey"),
            ("ntp authentication-key 1 md5 ntpkey123", "ntpkey123"),
            # Mid-line forms — the credential is not the first thing on the line,
            # so a ^-anchored pattern misses it. All four were real leaks.
            (" server-private 10.10.10.11 key 7 070C285F4D061A33", "070C285F4D061A33"),
            (" server-private 10.0.0.1 key MySharedSecret", "MySharedSecret"),
            (" neighbor 10.20.0.2 password 7 070C285F4D061A33", "070C285F4D061A33"),
            (
                "radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key RadiusK3y!",
                "RadiusK3y!",
            ),
            # SNMPv3 keys. Two on one line, and the pack captures the algorithm
            # names either side of them rather than the keys themselves.
            (
                "snmp-server user auditor RO v3 auth sha AuthK3y priv aes 128 PrivK3y",
                "AuthK3y",
            ),
            (
                "snmp-server user auditor RO v3 auth sha AuthK3y priv aes 128 PrivK3y",
                "PrivK3y",
            ),
            # A community repeated on a trap-host line.
            ("snmp-server host 10.0.0.9 version 2c EntMonitor2026", "EntMonitor2026"),
            ("snmp-server community secret123 RW", "secret123"),
        ],
    )
    def test_credential_is_replaced(self, line: str, secret: str) -> None:
        out = redact_secrets(line)
        assert secret not in out, f"{secret!r} survived in {out!r}"
        assert REDACTED in out

    def test_a_password_may_contain_an_exclamation_mark(self) -> None:
        """``!`` starts an IOS comment only after whitespace.

        The credential class used to be ``[^\\s!]+``, meant to avoid swallowing a
        trailing comment. It does not do that — ``\\S+`` already stops at the space
        before a comment — but it did truncate any credential containing ``!``.

        The line below is the one that isolates the difference: it has no
        line-initial credential keyword and no type digit, so the *only* pattern
        that can match it is the end-of-line-anchored mid-line one. With the old
        class that pattern matched ``MySecret``, the ``(\\s*)$`` anchor then failed
        on the leftover ``!``, and the whole line went unredacted.

        A line the specific patterns also cover, such as ``radius-server host X key
        RadiusK3y!``, would not prove this: there the old class still redacted the
        credential and merely left a stray ``!`` behind, so the test would pass
        either way.
        """
        out = redact_secrets(" server-private 10.0.0.1 key MySecret!")
        assert "MySecret" not in out
        assert out == f" server-private 10.0.0.1 key {REDACTED}"

    def test_radius_key_after_open_ended_clauses(self) -> None:
        """The real cause of the ``RadiusK3y!`` leak, separated from the class fix.

        ``radius-server host <ip> auth-port 1812 acct-port 1813 key <secret>`` is
        the ordinary shape. A pattern that only allowed ``host <ip>`` between
        ``radius-server`` and ``key`` did not match the line at all.
        """
        out = redact_secrets(
            "radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key RadiusK3y!"
        )
        assert out == (
            f"radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key {REDACTED}"
        )

    def test_a_trailing_comment_is_not_swallowed(self) -> None:
        """The other half of the same decision."""
        out = redact_secrets("enable secret 5 $1$abcd$xyz ! set by ops 2026-01")
        assert out == f"enable secret 5 {REDACTED} ! set by ops 2026-01"


class TestMetadataIsPreserved:
    """The fields a rule reads on a credential-bearing line are not secrets."""

    def test_hash_type_digit_survives(self) -> None:
        """CIS 1.4.1 reads ``mgmt.enable_secret.hash_type``.

        The old ``enable secret`` pattern could not match a non-zero type digit, so
        for ``enable secret 9 $9$hash`` it captured ``9`` as the secret — redacting
        the one field the module existed to preserve and leaving the hash itself in
        the clear. It flipped CIS 1.4.1 from PASS to FAIL on five fixtures.
        """
        assert redact_secrets("enable secret 9 $9$hash") == f"enable secret 9 {REDACTED}"
        assert redact_secrets("enable secret 5 $1$ab$cd") == f"enable secret 5 {REDACTED}"

    def test_snmp_access_and_acl_survive(self) -> None:
        """CIS 1.5.4 reads the RO/RW keyword; the ACL controls read the ACL name."""
        out = redact_secrets("snmp-server community Secret1 RW SNMP-ACL")
        assert out == f"snmp-server community {REDACTED} RW SNMP-ACL"

    def test_snmpv3_algorithms_survive(self) -> None:
        """``snmp.v3_auth`` / ``snmp.v3_priv`` are algorithm names, not keys."""
        out = redact_secrets(
            "snmp-server user auditor RO v3 auth sha AuthK3y priv aes 128 PrivK3y"
        )
        assert "sha" in out
        assert "aes 128" in out

    def test_hostname_and_structure_survive(self) -> None:
        out = redact_secrets(SAMPLE_CONFIG)
        assert "hostname test-sw-01" in out

    @pytest.mark.parametrize(
        "line",
        [
            # 'key'/'password' as a sub-command, not a credential slot. Each of
            # these is a line the generic mid-line patterns must decline.
            "key chain EIGRP-CHAIN",
            " key 1",
            "service password-encryption",
            "no service password-encryption",
            "password encryption aes",
            "crypto key generate rsa modulus 2048",
            "crypto key zeroize rsa",
            "key config-key password-encrypt",
            "ip ssh pubkey-chain",
            "radius-server timeout 5",
            "radius-server retransmit 3",
            "ntp server 10.0.0.1 key 1",
            # A v3 trap host names a user, not a community.
            "snmp-server host 10.1.1.1 version 3 priv auditor",
            # An SNMP view name is a label the rules read.
            "snmp-server group SENTINEL-RO v3 priv read SENTINEL-VIEW",
            "snmp-server view SENTINEL-VIEW iso included",
        ],
    )
    def test_non_credential_line_is_untouched(self, line: str) -> None:
        assert redact_secrets(line) == line


class TestWellKnownCommunitiesStayVisible:
    """Why a default community is kept, and the coupling that keeps it correct."""

    @pytest.mark.parametrize("community", ["public", "private", "PUBLIC", "Private"])
    def test_default_community_is_not_replaced(self, community: str) -> None:
        """Replacing it would turn a real FAIL into a PASS.

        CIS 1.5.2 and 1.5.3 are ``ne private`` / ``ne public`` against
        ``snmp.community``. An opaque placeholder satisfies ``ne`` and the control
        reports PASS on a device running the default community — a false positive
        in the direction that matters. A default community is public knowledge by
        definition; there is no secret to protect and its presence is the finding.
        """
        line = f"snmp-server community {community} RO"
        assert redact_secrets(line) == line

    def test_custom_community_is_replaced(self) -> None:
        out = redact_secrets("snmp-server community NotADefault RO")
        assert "NotADefault" not in out

    def test_every_literal_the_rules_compare_is_covered(
        self, evaluator: RulesEvaluator
    ) -> None:
        """Derived from the loaded packs, so the coupling polices itself.

        ``WELL_KNOWN_COMMUNITIES`` is only sound as long as it is a superset of the
        literals some rule compares a secret-valued path against. If a new pack
        starts checking for ``cisco`` or ``monitor`` and the set does not list it,
        that control silently becomes a false PASS — no exception, no log line,
        just a wrong verdict. Asserting the containment against the real rule set
        turns that into a test failure at the moment the pack is added.

        List-valued expectations are decomposed rather than stringified. ``in`` and
        ``not_in`` take a list, so ``expected`` for the multi-vendor packs is
        ``['public', 'private', 'juniper', ...]`` — and ``str()`` of that is never
        a member of the set, so the check would fail for the *wrong reason* and,
        worse, could be "fixed" by adding the stringified list, which would leave
        every literal inside it unchecked forever. Comparing element by element is
        what makes the assertion mean what its name says.
        """

        def walk(condition):
            yield condition
            for child in getattr(condition, "conditions", []) or []:
                yield from walk(child)
            inner = getattr(condition, "condition", None)
            if inner is not None:
                yield from walk(inner)

        compared: dict[str, set[str]] = {}
        for rule in evaluator.rules:
            for condition in walk(rule.condition):
                path = getattr(condition, "path", None)
                expected = getattr(condition, "expected", None)
                if path in SECRET_VALUE_PATHS and expected is not None:
                    literals = (
                        expected
                        if isinstance(expected, (list, tuple, set, frozenset))
                        else [expected]
                    )
                    compared.setdefault(path, set()).update(
                        str(literal) for literal in literals
                    )

        assert compared, (
            "no rule compares a secret-valued path against a literal — either "
            "SECRET_VALUE_PATHS or the rule packs moved, and the reasoning behind "
            "WELL_KNOWN_COMMUNITIES needs re-reading"
        )
        uncovered = {
            (path, literal)
            for path, literals in compared.items()
            for literal in literals
            if literal.lower() not in WELL_KNOWN_COMMUNITIES
        }
        assert not uncovered, (
            f"rules compare secret-valued paths against literals that redaction "
            f"would replace, which makes those controls report a false PASS: "
            f"{sorted(uncovered)}. Add them to WELL_KNOWN_COMMUNITIES."
        )


# ─────────────────────────────────────────────────────────────────────────
# Fact-level API
# ─────────────────────────────────────────────────────────────────────────


class TestRedactFactValue:
    def test_non_secret_path_is_returned_unchanged(self) -> None:
        assert redact_fact_value("mgmt.enable_secret.hash_type", "9") == "9"
        assert redact_fact_value("snmp.community_access", "rw") == "rw"

    def test_secret_path_with_custom_value_is_replaced(self) -> None:
        assert redact_fact_value("snmp.community", "EntMonitor2026") == REDACTED

    def test_secret_path_with_default_value_is_kept(self) -> None:
        assert redact_fact_value("snmp.community", "public") == "public"

    def test_booleans_and_none_survive(self) -> None:
        """A presence fact on a secret path carries no material to leak.

        Checked explicitly because ``True`` would otherwise be replaced by a
        string, which changes the *type* a rule compares and could fail an
        ``eq true`` check on a path that has nothing to hide.
        """
        assert redact_fact_value("snmp.community", True) is True
        assert redact_fact_value("snmp.community", False) is False
        assert redact_fact_value("snmp.community", None) is None


class TestRedactParseResult:
    """The single call site: everything downstream reads a redacted result."""

    def test_provenance_lines_are_redacted(self) -> None:
        text = _synthetic("snmp-server community EntMonitor2026 RO\n")
        result = redact_parse_result(_parse(text, "t.conf"))
        for fact in result.facts:
            assert "EntMonitor2026" not in fact.raw_text

    def test_secret_fact_values_are_redacted(self) -> None:
        text = _synthetic("snmp-server community EntMonitor2026 RO\n")
        result = redact_parse_result(_parse(text, "t.conf"))
        communities = [f.value for f in result.facts if f.path == "snmp.community"]
        assert communities == [REDACTED]

    def test_unparsed_lines_are_redacted(self) -> None:
        """The training queue is a storage surface, and an easy one to forget.

        Unparsed lines are persisted verbatim for C2 and shown in the training
        GUI, so an unrecognised credential-bearing directive would sit in the
        database in the clear. This uses a directive no pack matches on purpose.
        """
        text = _synthetic("frobnicate-server 10.0.0.1 key MyLeakedSecret\n")
        result = redact_parse_result(_parse(text, "t.conf"))
        assert result.unparsed_lines, "fixture must produce an unparsed line"
        blob = "\n".join(str(e.get("raw_text", "")) for e in result.unparsed_lines)
        assert "MyLeakedSecret" not in blob

    def test_returns_the_same_object(self) -> None:
        """In-place, and returned only so the call site reads as one expression."""
        parsed = _parse(_synthetic(""), "t.conf")
        assert redact_parse_result(parsed) is parsed


# ─────────────────────────────────────────────────────────────────────────
# Whole-estate differentials — the tests that caught the original bug
# ─────────────────────────────────────────────────────────────────────────


class TestRedactionPreservesFacts:
    """Redaction must not cost a single fact, on any fixture.

    Compared as ``(path, line_start)`` rather than by count: an equal count could
    still mean one fact was lost and another gained, and comparing values would
    fail on the redacted community, which is the one value that is *meant* to
    differ.
    """

    @pytest.mark.parametrize("fixture", _fixtures(), ids=lambda p: p.stem)
    def test_no_fact_is_lost(self, fixture: Path) -> None:
        text = _fixture_text(fixture)
        truth = _parse(text, fixture.name)
        redacted = redact_parse_result(_parse(text, fixture.name))

        before = {(f.path, f.line_start) for f in truth.facts}
        after = {(f.path, f.line_start) for f in redacted.facts}
        assert before == after, (
            f"redaction changed which facts were observed on {fixture.name}: "
            f"lost {sorted(before - after)}, gained {sorted(after - before)}"
        )

    @pytest.mark.parametrize("fixture", _fixtures(), ids=lambda p: p.stem)
    def test_only_secret_valued_paths_change_value(self, fixture: Path) -> None:
        text = _fixture_text(fixture)
        truth = _parse(text, fixture.name)
        redacted = redact_parse_result(_parse(text, fixture.name))

        by_key = {(f.path, f.line_start): f.value for f in truth.facts}
        for fact in redacted.facts:
            original = by_key[(fact.path, fact.line_start)]
            if fact.value != original:
                assert fact.path in SECRET_VALUE_PATHS, (
                    f"{fixture.name}: redaction changed {fact.path} from "
                    f"{original!r} to {fact.value!r}, but that path is not "
                    "declared as carrying secret material"
                )
                assert fact.value == REDACTED


class TestRedactionPreservesVerdicts:
    """The compliance-relevant statement: no verdict depends on redaction.

    This is what makes it sound to redact *before* evaluation, which in turn is
    what lets the whole thing happen at one call site instead of four.
    """

    @pytest.mark.parametrize("fixture", _fixtures(), ids=lambda p: p.stem)
    def test_verdicts_are_identical(
        self, fixture: Path, evaluator: RulesEvaluator
    ) -> None:
        text = _fixture_text(fixture)
        truth = _parse(text, fixture.name)
        redacted = redact_parse_result(_parse(text, fixture.name))

        def verdicts(result) -> dict[tuple[str, str], str]:
            findings = evaluator.evaluate(
                result.facts,
                result.device.vendor.value,
                result.device.os_family.value,
                os_version=result.device.os_version,
            )
            return {
                (_framework_of(f), f.control_id): _result_of(f) for f in findings
            }

        before, after = verdicts(truth), verdicts(redacted)
        changed = {k: (before[k], after.get(k)) for k in before if before[k] != after.get(k)}
        assert not changed, (
            f"redaction changed {len(changed)} verdict(s) on {fixture.name}: "
            f"{dict(list(changed.items())[:10])}"
        )


class TestNoCredentialSurvivesTheEstate:
    """End-to-end: harvest the fixtures' own credentials, then look for them.

    The parametrised cases above test the patterns that exist. This test looks for
    credentials the patterns might not cover, by taking them from the fixtures
    rather than from a hand-written list — which is how the ``RadiusK3y!`` and
    SNMPv3-key leaks were found after the unit tests were already green.
    """

    #: Every credential in the fixtures, as (fixture stem, literal). Kept as a
    #: literal list rather than re-derived at runtime: a harvesting regex is a
    #: second implementation of the thing under test, and if it drifts the test
    #: gets quietly weaker. A new fixture with a new credential form is expected
    #: to fail here until it is added — that failure is the notification.
    #:
    #: Excludes ``public``, ``private`` and ``cisco``, which are kept on purpose —
    #: see TestWellKnownCommunitiesStayVisible. Excludes short literals like
    #: ``cisco123`` only where they also occur in unrelated text; where they do
    #: not, they are listed.
    KNOWN_CREDENTIALS: ClassVar[list[tuple[str, str]]] = [
        # Type 5 / type 9 hashes. Redacted despite being hashed: type 5 is MD5 and
        # offline-crackable, and a hash is still a credential-equivalent for an
        # offline attacker holding the config.
        ("fully_hardened", "$1$Kd7f$q0N8sTvHhZ2mXbEwR3aLu."),
        ("fully_hardened", "$1$Rp2m$8LxQeN4vTgYbHcWzA9sKj/"),
        # fully_hardened once carried a third type 5 hash on a second local
        # account. DISA CISC-ND-000490 (V-215679) requires exactly one local
        # account — the account of last resort — so the positive pole cannot hold
        # two and still be the positive pole. The 'username ... secret 5' pattern
        # is still exercised by the account above, and 'enable secret 5' by the
        # line before it, so removing the third instance costs no pattern coverage.
        ("partial_compliance", "$1$mixed$hashvalue1234"),
        ("enterprise_complex", "$1$Ent3r$hashedvaluehere12345"),
        ("secure_baseline", "$9$securescrypthash"),
        ("router_with_show_version", "$9$branchrtrhash"),
        ("stacked_switch_with_inventory", "$9$stackswitchhash"),
        # Type 7 material. Reversible by design, so "already encoded" is no
        # protection at all. This literal appears in four positions in
        # fully_hardened — an NTP key, an AAA server-private key, a BGP neighbour
        # password and both SNMPv3 keys — and three of them were missed by the
        # line-anchored patterns.
        ("fully_hardened", "070C285F4D061A33"),
        ("fully_noncompliant", "070C285F4D061A33"),
        ("router_with_show_version", "0745B1F0A5"),
        # Cleartext. Several contain '!' mid-token, which the old credential
        # character class truncated at.
        ("fully_hardened", "S3nt1nelR0"),
        ("insecure_minimal", "cisco123"),
        ("telnet_exposed", "AdminPass2026!"),
        ("secure_baseline", "SecureStr1ng!2026"),
        ("secure_baseline", "NtpK3y!Secure"),
        ("enterprise_complex", "EntMonitor2026"),
        ("enterprise_complex", "AuthK3y!"),
        ("enterprise_complex", "PrivK3y!"),
        ("enterprise_complex", "NtpEntK3y!"),
        ("enterprise_complex", "NtpBkupK3y!"),
        ("enterprise_complex", "RadiusK3y!"),
    ]

    @pytest.mark.parametrize("fixture", _fixtures(), ids=lambda p: p.stem)
    def test_no_known_credential_reaches_any_output_surface(
        self, fixture: Path
    ) -> None:
        expected = [
            literal for stem, literal in self.KNOWN_CREDENTIALS if stem == fixture.stem
        ]
        text = _fixture_text(fixture)
        present = [literal for literal in expected if literal in text]

        result = redact_parse_result(_parse(text, fixture.name))
        surfaces = (
            [str(f.value) for f in result.facts]
            + [f.raw_text for f in result.facts]
            + [str(e.get("raw_text", "")) for e in result.unparsed_lines]
        )
        blob = "\n".join(surfaces)

        leaked = [literal for literal in present if literal in blob]
        assert not leaked, (
            f"{fixture.name} leaks {leaked} into facts, provenance or the "
            "training queue"
        )

    def test_the_known_credential_list_is_not_stale(self) -> None:
        """A literal that no longer appears in its fixture proves nothing.

        Without this, deleting a credential from a fixture would leave a test that
        passes because it checks for a string that cannot occur.
        """
        stems = {p.stem: _fixture_text(p) for p in _fixtures()}
        for stem, literal in self.KNOWN_CREDENTIALS:
            assert stem in stems, f"KNOWN_CREDENTIALS names a missing fixture: {stem}"
            assert literal in stems[stem], (
                f"{literal!r} is no longer in {stem}.conf — remove it from "
                "KNOWN_CREDENTIALS or restore the fixture"
            )
