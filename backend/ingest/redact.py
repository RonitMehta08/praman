"""Secret redaction.

Credentials must not reach a response, the fact store, a PDF, the audit ledger
or the C2 training queue. This module is the single place that decides what
counts as a credential and what replaces it.

Where it runs, and why that changed
-----------------------------------
Redaction used to be a pre-filter: the config text was rewritten and the
*rewritten* text was handed to the parser. That is wrong, and not marginally.
The pattern packs read whitespace-delimited fields, so replacing a secret with a
token that contains spaces shifted every field after it and the whole line
stopped matching — taking with it every fact the line would have produced, secret
or not. Measured over the ten fixtures in ``test_configs/``: **58 facts lost
across 11 canonical paths, and 31 verdicts changed.** The directions were all
bad. ``insecure_minimal`` had CIS 1.5.7 and 1.5.8 flip FAIL → PASS, because
``snmp.enabled`` is only observed from a community/group/user/host line and the
mangled community line no longer produced it — a deliberately insecure fixture
reported compliant. Thirteen real FAILs degraded to ``notapplicable``. CIS 1.4.1
flipped PASS → FAIL on five fixtures, because the ``enable secret`` pattern
captured the *hash-type digit* as the secret: ``enable secret 9 $9$hash`` became
``enable secret <token> $9$hash``, which redacted the metadata the module
existed to preserve and left the hash itself in the clear.

So redaction now runs *after* the parse, over the parse result, and the pre-parse
call sites are gone. This is also the only ordering under which some controls are
answerable at all — see the note on ``WELL_KNOWN_COMMUNITIES``.

What is actually secret, and what only looks it
----------------------------------------------
The pattern packs were already written to keep credentials out of the canonical
model, and they say so where they do it: ``enable_secret_typed`` notes "the hash
itself is never emitted", ``con_password`` notes "presence only; the credential
is never emitted as a value", ``ntp_authentication_key`` records the digest
algorithm and "the key material is not". Auditing every credential-shaped path
in the vocabulary against what ``cisco_ios.yaml`` emits leaves exactly one whose
*value* is real secret material: ``snmp.community``. The other thirty are a
boolean, a type digit, an algorithm name, a key id, a username or a bit count.

That is why the pre-filter bought nothing it could not have got here: the values
were never the leak. The leak is ``CanonicalFact.raw_text``, which is the
verbatim line by contract, and the unparsed lines, which are stored verbatim in
the training queue. Both are redacted below.

Scope boundary: this covers the credential forms the shipped packs parse, across
all seven vendors. A new vendor pack that introduces a new credential syntax
needs a pattern here as well — there is no way to derive one from the pack,
because the pack's job is to *not* capture the secret.

Indented forms and stripped evidence
------------------------------------
``CanonicalFact.raw_text`` holds the *stripped* line, not the line as it appears
in the file. That is invisible until you look, and it silently disabled a third
of this module: every pattern anchored on leading whitespace (``^\\s+password``)
or on a whitespace lookbehind (``(?<=\\s)key 7 …``) matched the config text and
then failed on the very surface that reaches a report. Measured over the sixteen
shipped fixtures, five credentials survived into ``Finding.evidence`` for that
reason alone — an indented ``line con 0`` password, a NX-OS BGP ``password 3``,
an ASA TACACS ``key``. Those patterns now accept start-of-string as well as a
preceding space, and the tokens that follow ``password`` in a *policy* command
(``password strength-check``) are listed in :data:`_KEY_KEYWORDS` so widening the
anchor cannot turn a policy line into a redaction.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from backend.canonical.models import CanonicalFact
    from backend.ingest.base import ParseResult

#: The replacement token. Deliberately free of whitespace.
#:
#: The previous value was ``"*** REDACTED ***"``, and the spaces were the bug:
#: every pattern in every pack splits on whitespace, so a three-token
#: replacement for a one-token secret shifted the fields after it and the line
#: stopped matching. A single opaque token occupies exactly one field position,
#: so a redacted line still parses into the same facts — the RO/RW keyword, the
#: ACL name and the view name after a community string are not secrets, and they
#: are precisely what CIS 1.5.4 and the SNMP ACL controls read.
REDACTED = "***REDACTED***"

#: Community strings that are kept verbatim, because they are findings rather
#: than secrets.
#:
#: This set is what makes redaction verdict-preserving. ``snmp.community`` is the
#: one secret-valued path in the canonical model, and CIS 1.5.2 and 1.5.3 are
#: literal comparisons against it (``ne private``, ``ne public``). That leaves
#: three possibilities and only one of them is honest:
#:
#:   * drop the fact — the control reports ``notapplicable`` on a device running
#:     the default community. This is what the pre-filter did, and it is a false
#:     negative wearing the label "not applicable".
#:   * emit the fact with an opaque value — ``REDACTED != public`` is true, so the
#:     control reports PASS. A false positive, which is strictly worse.
#:   * emit the fact with its real value *when that value is a documented
#:     default*. A default community is public knowledge by definition; there is
#:     no secret to protect, and its presence is the entire finding.
#:
#: So a community is replaced only when it differs from every literal a rule
#: could compare it against, which makes the substitution
#: comparison-equivalent and the verdict unchanged. ``tests/test_redaction.py``
#: derives the required literals from the loaded rule packs and asserts this set
#: covers them, so a rule that starts checking a new default name fails the test
#: rather than silently turning into a false PASS.
#:
#: Every entry here is a value that will be printed verbatim in a report, so each
#: one has to be *earned* by a rule that needs it — a name added "for symmetry"
#: with the others is a real credential that stops being redacted. ``juniper``
#: was added when the CIS Juniper OS pack landed, because that benchmark names it
#: among the default communities and the rule compares against it; the other
#: vendor names in this corpus (``fortinet``, ``panos``, ``arista``) are
#: deliberately absent, since no rule compares them and their absence keeps a
#: community that happens to be named after the vendor redacted.
WELL_KNOWN_COMMUNITIES = frozenset(
    {
        "public",
        "private",
        "cisco",
        "juniper",
        "snmp",
        "community",
        "admin",
        "default",
        "monitor",
        "manager",
        "read",
        "write",
        "ro",
        "rw",
    }
)

#: Canonical paths whose *value* is credential material and must be replaced.
#:
#: Exactly one entry, and that is a property of the packs rather than an
#: oversight — see the module docstring. Keep it a set anyway: a future vendor
#: pack that has to emit a credential value to answer a control would be added
#: here, and a one-element set makes that a data change instead of a code change.
SECRET_VALUE_PATHS = frozenset({"snmp.community"})


#: Tokens that follow ``key`` or ``password`` in a command that carries no
#: credential. The end-of-line anchor on the untyped pattern already excludes
#: most of these — ``key chain NAME`` has a token after ``chain``, so the anchor
#: fails — but two classes need naming explicitly.
#:
#: The truncated forms (``crypto key generate`` with no algorithm) are cheap to
#: exclude and the list documents which commands were considered. The
#: *policy* forms are load-bearing: once the untyped pattern was widened to fire
#: at start-of-string, so that it works on the stripped evidence line, a bare
#: ``password strength-check`` (NX-OS) or ``password secure-mode`` looked exactly
#: like ``password MySecret`` — one token after ``password``, nothing following.
#: Redacting those would have destroyed ``mgmt.password_policy.complexity``,
#: which is the fact the line exists to state. Multi-token policy commands
#: (``password minimum length 15``) are already excluded by the anchor.
_KEY_KEYWORDS = frozenset(
    {
        "chain",
        "config-key",
        "decrypt",
        "encryption",
        "generate",
        "mypubkey",
        "pubkey-chain",
        "zeroize",
        # Password-policy commands whose single argument is a mode, not a secret.
        "strength-check",
        "secure-mode",
        "prompt",
        "encryption-key",
        "complexity",
        "history",
        "lifetime",
        "max-age",
        "minimum",
        "reuse",
    }
)


def _redact_community(match: re.Match[str]) -> str:
    """Replace a community string unless it is a documented default."""
    if match.group(2).lower() in WELL_KNOWN_COMMUNITIES:
        return match.group(0)
    return f"{match.group(1)}{REDACTED}{match.group(3)}"


def _redact_untyped_key(match: re.Match[str]) -> str:
    """Replace a trailing, untyped ``key|password <value>`` unless it is an id.

    Two unrelated commands share this shape and only one carries a secret::

        tacacs server FOO      key chain EIGRP-CHAIN
         key MySharedSecret     key 1
                                 key-string TheActualSecret

    A line-level pattern cannot see which block it is in, so the value decides:
    a bare integer is a key-chain identifier, anything else is key material.
    Getting this wrong in the cautious direction would destroy
    ``routing.eigrp.key_chain``; in the other direction it would leak a shared
    secret whose value is a single small integer, which is not a secret worth
    protecting.

    An already-redacted value is left alone, and that guard is what lets the
    hash-marker pattern and this one coexist. ``phash $5$salt$digest`` is first
    rewritten to ``phash $5$***REDACTED***`` so the ``$5$`` survives for
    ``mgmt.local_user.hash_type``; this pattern then sees ``phash`` followed by a
    single trailing token and, without the guard, would replace the whole thing —
    undoing the metadata the first pattern went out of its way to keep.
    """
    if REDACTED in match.group(2):
        return match.group(0)
    if match.group(2).isdigit() or match.group(2).lower() in _KEY_KEYWORDS:
        return match.group(0)
    return f"{match.group(1)}{REDACTED}{match.group(3)}"


# --- Pattern definitions ---
#
# Each entry is (compiled pattern, replacement), where the replacement is either
# a template string or a callable, so a pattern whose decision depends on the
# captured value can make it.
#
# Shared shape: group 1 is the command prefix *including any type digit*, group 2
# is the credential, group 3 is the remainder of the line. Keeping the type digit
# in the prefix is what preserves mgmt.enable_secret.hash_type and
# mgmt.local_user.hash_type — CIS 1.4.1 and the STIG hash-strength checks read
# them, and they are metadata, not credentials. The credential itself is replaced
# regardless of type: type 7 is reversible by design and type 5 is offline-
# crackable, so "already hashed, therefore safe to publish" is not true for
# either. (A prior version of this module carried an `is_type_hashed` helper
# asserting the opposite policy. It was never called by anything, so the policy
# was documented but not implemented; the honest version is implemented here.)
#
# Order matters twice. The two SNMPv3 patterns must run auth-then-priv, because
# the priv pattern scans forward to the last 'priv' on the line. And the generic
# mid-line patterns run after the specific ones, so they only ever re-match text
# a specific pattern has already replaced, which is a no-op.
#
# The credential is matched as \S+, not [^\s!]+. Excluding '!' was an attempt to
# avoid swallowing a trailing IOS comment, but it does not do that — IOS requires
# whitespace before a comment marker, so \S+ already stops at the space. What the
# exclusion did instead was truncate any credential containing '!', which left
# 'key RadiusK3y!' unredacted: the class matched 'RadiusK3y', and the end-of-line
# anchor then failed on the leftover '!'. A password may legally contain '!'.
_PATTERNS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    # SNMP community strings — conditional, see _redact_community.
    (
        re.compile(
            r"^(\s*snmp-server\s+community\s+)(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        _redact_community,
    ),
    # A trap destination repeats the community string, so redacting only the
    # 'snmp-server community' line leaves it in the clear one line later.
    #
    # The negative lookahead is load-bearing: on 'version 3' the optional version
    # clause does not match, and without the guard group 2 would capture the
    # literal word 'version'. A v3 trap host names a *user*, not a secret, so
    # declining to match that form is correct rather than merely safe.
    (
        re.compile(
            r"^(\s*snmp-server\s+host\s+\S+(?:\s+vrf\s+\S+)?"
            r"(?:\s+(?:informs?|traps?))?(?:\s+version\s+(?:1|2c))?\s+)"
            r"(?!version\b|vrf\b|informs?\b|traps?\b)(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        _redact_community,
    ),
    # snmp-server user ... auth <algorithm> <key> — the algorithm is the fact
    # (snmp.v3_auth), the token after it is the credential.
    #
    # Three vendors write this three ways and only one of them says 'v3':
    #
    #     snmp-server user u GRP v3 auth sha <key>                (IOS, EOS)
    #     snmp-server user u GRP v3 encrypted auth sha256 <key>   (ASA)
    #     snmp-server user u network-operator auth sha <key>      (NX-OS)
    #
    # Requiring the 'v3' token therefore leaked both the ASA key (an 'encrypted'
    # clause sits between the group and 'auth') and the NX-OS key (there is no
    # version token at all — the role name stands where the group would be).
    # Anchoring on 'auth' alone is what makes this vendor-agnostic. The '.*?' is
    # non-greedy so the FIRST 'auth' wins: a v3 user can carry both keys on one
    # line, and a greedy run would skip past the auth key to the priv one and
    # leave the first secret in the clear.
    (
        re.compile(
            r"^(\s*snmp-server\s+user\s+.*?\bauth\s+\S+\s+)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # ... priv <algorithm> [bits] <key>. Separate pattern because a v3 user can
    # carry both keys on one line and 'priv aes 128 <key>' puts a key length
    # between the algorithm and the credential.
    (
        re.compile(
            r"^(\s*snmp-server\s+user\s+.*\bpriv\s+\S+\s+(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # enable secret | enable password, with optional 'level N' and type digit.
    (
        re.compile(
            r"^(\s*enable\s+(?:secret|password)\s+"
            r"(?:level\s+\d+\s+)?(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # username ... secret|password [type] <credential>
    #
    # 'secret' was missing here, so 'username admin secret 0 cleartext' was not
    # redacted at all. The clause order mirrors local_user_secret in
    # cisco_ios.yaml, including the 'view' clause, so redaction and parsing agree
    # on where the credential starts.
    (
        re.compile(
            r"^(\s*username\s+\S+(?:\s+privilege\s+\d+)?(?:\s+view\s+\S+)?"
            r"\s+(?:secret|password)\s+(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # An indented, bare 'password [type] <credential>' — the line con/vty/aux
    # form, which produces line.console.password / line.vty.password /
    # line.aux.password. Indentation is required: it is what distinguishes a
    # line-block child from a global command. 'password' must be followed by
    # whitespace, so 'password-policy' is left alone, and 'encryption' is
    # excluded so the global 'password encryption aes' cannot be mistaken for a
    # credential if it ever appears indented.
    (
        re.compile(
            r"^(\s+password\s+(?:\d+\s+)?)(?!encryption\b)(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # tacacs-server / radius-server key, legacy global form.
    #
    # The greedy '.*' before 'key' is there because the clauses in between are
    # open-ended: 'radius-server host 10.0.0.1 auth-port 1812 acct-port 1813 key
    # <secret>' is the normal shape, and a pattern that only allowed 'host <ip>'
    # missed it — a real leak the fixtures caught. Greedy also means the *last*
    # 'key' on the line wins, which is the credential-bearing one.
    (
        re.compile(
            r"^(\s*(?:tacacs|radius)-server\s+(?:.*\s)?key\s+(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # 'key-string [type] <material>' inside a key chain.
    (
        re.compile(
            r"^(\s*key-string\s+(?:\d+\s+)?)(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # ip ospf|eigrp|rip authentication key[-string]
    (
        re.compile(
            r"^(\s*(?:ip\s+)?(?:ospf|eigrp|rip)\s+authentication\s+key(?:-string)?\s+"
            r"(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # ip ospf message-digest-key <id> <algorithm> [type] <material>
    (
        re.compile(
            r"^(\s*(?:ip\s+)?ospf\s+message-digest-key\s+\d+\s+\S+\s+(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # crypto isakmp key / crypto ipsec pre-shared-key
    (
        re.compile(
            r"^(\s*crypto\s+\S+\s+(?:pre-shared-)?key\s+(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # ntp authentication-key <id> <algorithm> <material>
    (
        re.compile(
            r"^(\s*ntp\s+authentication-key\s+\d+\s+\S+\s+(?:\d+\s+)?)"
            r"(\S+)(.*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # Mid-line typed credential: '<anything> key 7 <material>' or
    # '<anything> password 7 <material>'. This is the catch-all for credentials
    # that are not the first thing on the line — 'server-private 10.0.0.1 key 7
    # <hex>' inside an AAA server group, and 'neighbor 10.0.0.2 password 7 <hex>'
    # inside a BGP process, both of which the line-anchored patterns above miss.
    #
    # The type digit makes it unambiguous, which is why this can be generic: no
    # non-credential command has the shape 'key <digits> <token>'. The lookbehind
    # on whitespace rather than \b is deliberate — \b would match inside
    # 'authentication-key' and 'pubkey-chain'.
    #
    # Start-of-line is an accepted anchor alongside the lookbehind because this
    # module also runs over ``CanonicalFact.raw_text``, which is *stripped*. The
    # NX-OS BGP peer key is written as an indented 'password 3 <hex>' and reached
    # the fact store as 'password 3 <hex>' with nothing before it, so a pattern
    # that insisted on a preceding space redacted the config file and not the
    # evidence in the report.
    (
        re.compile(
            r"(?:(?<=\s)|^)((?:key|password)\s+\d+\s+)(\S+)",
            re.IGNORECASE | re.MULTILINE,
        ),
        rf"\g<1>{REDACTED}",
    ),
    # Mid-line untyped credential, and only as the last token on the line —
    # 'server-private 10.0.0.1 key MySharedSecret', or the ASA's indented
    # 'key <secret>' inside an aaa-server host block. Anchoring at end of line is
    # what makes this safe: every 'key <keyword> ...' command has a token after
    # the keyword, so the anchor rejects it before _redact_untyped_key is
    # consulted.
    #
    # Start-of-line is accepted here for the same stripped-evidence reason as
    # above, and it is why _KEY_KEYWORDS had to grow: once a bare 'password
    # <token>' at the start of a line can match, the NX-OS policy command
    # 'password strength-check' is indistinguishable from a credential by shape
    # alone, and redacting it would silently delete
    # mgmt.password_policy.complexity from every NX-OS report.
    (
        re.compile(
            r"(?:(?<=\s)|^)((?:key|password)\s+)(\S+)(\s*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        _redact_untyped_key,
    ),
    # Any '$<type>$<salt>$<digest>' blob, wherever it appears, keeping the type
    # marker and destroying everything after it.
    #
    # This is the one pattern that is genuinely vendor-independent, because the
    # modular crypt format is. It is what covers the hashes the command-shaped
    # patterns above cannot reach:
    #
    #     aaa root secret sha512 $6$<salt>$<hash>                (EOS)
    #     username admin ... role network-admin secret sha512 $6$…   (EOS)
    #     encrypted-password "$6$<salt>$<hash>"; ## SECRET-DATA  (Junos)
    #     authentication-key "$9$<blob>"; ## SECRET-DATA         (Junos)
    #     set mgt-config users admin phash $5$<salt>$<hash>      (PAN-OS)
    #
    # The EOS forms are the reason a command-shaped pattern is not enough: the
    # 'role <name>' clause sits between the username and the credential, so the
    # 'username ... secret' pattern above does not match, and no amount of adding
    # optional clauses would keep up with seven vendors.
    #
    # Keeping the '$N$' prefix is deliberate, not laziness. Five packs read the
    # digits as mgmt.enable_secret.hash_type or mgmt.local_user.hash_type, and
    # that fact is how a CIS or STIG control tells a type-7 reversible cipher
    # from a type-9 scrypt hash. Redacting the marker along with the digest would
    # trade a leak for a false verdict. The character class excludes quotes,
    # semicolons and commas so Junos's trailing '"; ## SECRET-DATA' survives —
    # arista_eos.yaml and juniper_junos.yaml both parse structure around it.
    (
        re.compile(r"(\$[0-9a-z]{1,6}\$)([^\"'\s;,]+)", re.IGNORECASE),
        rf"\g<1>{REDACTED}",
    ),
    # FortiOS 'set <field> ENC <blob>'. One line shape carries every encrypted
    # value in a FortiGate configuration — admin passwords, the NTP key, RADIUS
    # and HA secrets — so one pattern retires six leaks at once. The 'ENC' token
    # is FortiOS's own marker that what follows is ciphertext, which makes this
    # precise rather than merely broad.
    #
    # fortinet.yaml reads the marker, never the blob: fgt_admin_password_hash
    # emits a const 'enc' and its unused '(?P<value>\S{4})' group still matches
    # the first four characters of the replacement.
    (
        re.compile(r"^(\s*set\s+\S+\s+ENC\s+)(\S+)(.*)$", re.IGNORECASE | re.MULTILINE),
        rf"\g<1>{REDACTED}\g<3>",
    ),
    # A credential keyword whose value is the last token on the line, for the
    # keywords that are not 'key' or 'password'. PAN-OS drives this one:
    #
    #     ... server TAC-1 secret -AQ==<blob>
    #     ... users snmpv3-monitor authpwd <secret>
    #     ... users snmpv3-monitor privpwd <secret>
    #     ... authentication-type symmetric-key algorithm sha1 authentication-key <secret>
    #
    # End-of-line anchoring does the same work here as it does for 'key': every
    # non-credential use of these words has a token after it, so 'set secret ENC
    # <blob>' and Junos's 'authentication-key 7 type sha256 value "…"' are both
    # rejected by the anchor and handled by the two patterns above instead.
    #
    # 'phash' is deliberately absent. PAN-OS hashes are '$5$<salt>$<digest>' and
    # the modular-crypt pattern has already rewritten them to '$5$***REDACTED***';
    # matching 'phash' here would replace that with a bare marker-less redaction
    # and destroy mgmt.local_user.hash_type. _redact_untyped_key's
    # already-redacted guard makes that safe either way, but not listing the
    # keyword states the intent.
    (
        re.compile(
            r"(?:(?<=\s)|^)((?:authentication-key|authpwd|privpwd|secret"
            r"|bind-password|pre-shared-key|psksecret|passphrase)\s+)(\S+)(\s*)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        _redact_untyped_key,
    ),
]


def redact_secrets(config_text: str) -> str:
    """Replace credential material in config text, leaving structure intact.

    Pure and idempotent: ``redact_secrets(x) == redact_secrets(redact_secrets(x))``.
    Line and field positions are preserved, so the result still parses — that is
    a contract, not a coincidence, and ``tests/test_redaction.py`` asserts it
    fact-for-fact against every shipped fixture.

    Args:
        config_text: Config text or a single provenance line, already decoded.

    Returns:
        The same text with credentials replaced by :data:`REDACTED`.
    """
    lines = config_text.splitlines(keepends=True)
    result_lines: list[str] = []

    for line in lines:
        # An already-redacted line is left alone. Re-running the patterns over it
        # would be harmless for the template forms but would let a conditional
        # pattern re-inspect a token that is no longer the original value.
        if REDACTED in line:
            result_lines.append(line)
            continue

        modified = line
        for pattern, replacement in _PATTERNS:
            modified = pattern.sub(replacement, modified)
        result_lines.append(modified)

    return "".join(result_lines)


def redact_fact_value(path: str, value: Any) -> Any:
    """Replace a fact value if the path carries credential material.

    Values that a rule compares against a literal are preserved when they equal
    one of those literals — see :data:`WELL_KNOWN_COMMUNITIES` for why that is
    the difference between a correct verdict and a false PASS.
    """
    if path not in SECRET_VALUE_PATHS:
        return value
    if isinstance(value, str) and value.lower() in WELL_KNOWN_COMMUNITIES:
        return value
    if value is None or value is True or value is False:
        return value
    return REDACTED


def redact_fact(fact: CanonicalFact) -> None:
    """Redact one fact in place: its provenance line and, if secret, its value."""
    fact.raw_text = redact_secrets(fact.raw_text)
    fact.value = redact_fact_value(fact.path, fact.value)


def redact_parse_result(result: ParseResult) -> ParseResult:
    """Redact a parse result in place, and return it for call-site readability.

    Call this immediately after ``adapter.parse`` and before anything else —
    evaluation, storage, serialisation, clustering. Doing it here rather than at
    each of those points means there is one ordering to get right instead of
    four, and no dependence on whether ``Finding.evidence`` aliases these fact
    objects or copies them.

    Evaluating *after* this is safe because the substitution is
    comparison-equivalent: a value is only replaced when it differs from every
    literal the rules compare it against.

    Unparsed lines are redacted too, and that surface matters more than it
    looks. They are stored verbatim in the training queue for C2, so an
    unrecognised ``snmp-server community <secret> RO`` would otherwise sit in the
    database in the clear, waiting to be shown in the training GUI.
    """
    for fact in result.facts:
        redact_fact(fact)
    for entry in result.unparsed_lines:
        raw = entry.get("raw_text")
        if isinstance(raw, str):
            entry["raw_text"] = redact_secrets(raw)
    return result
