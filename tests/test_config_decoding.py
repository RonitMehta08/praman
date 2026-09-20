"""The same configuration must audit identically however its bytes arrived.

What this file is for
---------------------
A configuration reaches PRAMAN three ways — an ``/ingest`` upload, an archive
member, and ``backend/cli.py`` reading a path — and for a while they did not agree
about what the bytes meant. The API decoded through a candidate list starting at
``utf-8-sig``; the CLI called ``Path.read_text(encoding="utf-8")``. Two measured
consequences, both on inputs that are ordinary rather than exotic:

* **A UTF-8 BOM** (Notepad, PowerShell ``Out-File``, several TFTP collectors) came
  through the CLI as a leading ``\\ufeff`` glued to whatever command was on line 1.
  With ``hostname`` first, ``device.hostname`` came back ``None`` — the per-device
  report could not say which device it described. C4 asks for exactly that.
* **A cp1252 byte** (a smart quote in an interface description, routine on
  Windows) raised ``UnicodeDecodeError`` out of the CLI as an unhandled traceback,
  while the identical bytes uploaded to ``/ingest`` parsed fine.

Both are now one policy in ``backend/ingest/decode.py``. These tests hold it there.

Why invariance rather than a hostile fixture
--------------------------------------------
The obvious alternative was a ``test_configs/adversarial/`` file full of BOMs,
CRLFs and tabs. It was rejected: a static hostile file can only assert *does not
crash*, and "did not crash" is compatible with silently losing half the facts —
which is the failure that actually happened here. Mangling the **real** fixtures
and asserting the fact set is *unchanged* is a strictly stronger claim, and it
scales automatically: a new fixture is covered the day it lands, with no table to
update and no coverage metric to renumber.

The mutations are the ones that occur in practice, not a fuzzer's: BOM, CRLF line
endings, tab indentation, and a missing final newline. Each is a thing a real
collection script does.
"""

from __future__ import annotations

import pytest

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.ingest.decode import (
    DECODINGS,
    decode_config,
    decode_config_file,
    normalise,
)
from backend.ingest.generic import PatternAdapterRegistry
from backend.rules.loader import load_all_rules
from backend.rules.models import (
    CountCondition,
    ForEachCondition,
    LeafCondition,
    PresenceCondition,
)

CONFIG_DIR = PROJECT_ROOT / "test_configs"

#: Byte-level mutations that leave the *configuration* identical. Each is
#: something a real collection path does, named by what does it.
#:
#: ``tabs`` replaces the single leading space IOS uses for block children with a
#: tab. It is the mutation most likely to break a pattern pack, because block
#: nesting is expressed through indentation and a pack that matched ``^ ``
#: literally would lose every child line — a silent, total loss of interface and
#: line-block facts, reported as a clean parse.
MUTATIONS = {
    "bom": lambda text: "﻿" + text,
    "crlf": lambda text: text.replace("\n", "\r\n"),
    "tabs": lambda text: text.replace("\n ", "\n\t"),
    "no_final_newline": lambda text: text.rstrip("\r\n"),
    "bom_and_crlf": lambda text: "﻿" + text.replace("\n", "\r\n"),
}

FIXTURES = sorted(CONFIG_DIR.rglob("*.conf"))


def _facts(text: str, name: str) -> dict[str, object]:
    """Parse and return ``{path: value}``, or fail loudly if detection declined."""
    adapter = PatternAdapterRegistry().detect(text, name)
    assert adapter is not None, f"vendor detection declined {name}"
    return {fact.path: fact.value for fact in adapter.parse(text, name).facts}


def _split_paths_by_use(
    condition: object, compared: set[str], structural: set[str]
) -> None:
    """Partition a condition tree's paths by whether the *value* is read.

    ``Rule.referenced_paths`` deliberately does not make this distinction — it
    exists for coverage reporting, where "the pack reads this path" is the
    question. Encoding safety asks a narrower one, so the walk is local to this
    file rather than pushed into the model: only ``fact_check`` puts a fact's text
    on one side of a comparison. ``presence`` and ``count`` ask whether the fact
    is there and how many there are, and mangled text is still text.

    ``for_each``'s block anchor is counted as compared, not structural, because
    its value both selects the blocks to iterate and labels the resulting finding.
    """
    if isinstance(condition, LeafCondition):
        compared.add(condition.path)
    elif isinstance(condition, (PresenceCondition, CountCondition)):
        structural.add(condition.path)
    elif isinstance(condition, ForEachCondition):
        compared.add(condition.block)
        _split_paths_by_use(condition.condition, compared, structural)
    else:
        for child in getattr(condition, "conditions", ()) or ():
            _split_paths_by_use(child, compared, structural)


class TestTheDecoderIsTotal:
    """It must never refuse a file. A 500 on a stray byte is a tool nobody runs."""

    def test_every_byte_value_decodes(self) -> None:
        """The terminator is ``latin-1``, which maps all 256 byte values.

        Asserted against actual bytes rather than by reading the tuple, because
        the property that matters is "does not raise", and a future reordering
        that put a strict codec last would still look correct in the tuple.
        """
        assert decode_config(bytes(range(256)))  # must not raise

    def test_empty_input_is_empty_output(self) -> None:
        """An empty upload is a parse failure downstream, not a decode failure."""
        assert decode_config(b"") == ""

    def test_decoding_is_idempotent(self) -> None:
        """Re-decoding already-decoded text must not strip or normalise further.

        Matters because ``/simulate`` normalises a JSON string that the HTTP layer
        already decoded, so ``normalise`` runs on text that may or may not have
        been through ``decode_config``. Both orders must agree.
        """
        raw = "hostname R1\n!\nend\n".encode("utf-8-sig")
        once = decode_config(raw)
        assert once == decode_config(once.encode("utf-8"))
        assert once == normalise(once)

    def test_the_last_candidate_cannot_raise(self) -> None:
        """Documents *why* the function is total, so a reorder fails here.

        ``latin-1`` last is the entire basis of the totality claim. If someone
        appends a stricter codec after it, the guarantee is gone and the loop can
        fall through — this names that invariant rather than leaving it implicit
        in a comment.
        """
        assert DECODINGS[-1] == "latin-1"


class TestByteOrderMark:
    """The specific defect: a BOM stuck to the first command."""

    def test_the_mark_is_stripped(self) -> None:
        assert decode_config("﻿hostname R1\n".encode()) == "hostname R1\n"

    def test_a_hostname_on_line_one_survives_a_bom(self) -> None:
        """The regression, stated as the thing an operator would notice.

        Not asserted as "no ``\\ufeff`` in the output" — that is the mechanism. The
        consequence was ``device.hostname is None``, which is a report that cannot
        name its own subject, and this asserts the consequence.
        """
        config = "hostname R-BOM\n!\nip ssh version 2\nno ip http server\n!\nend\n"
        facts = _facts(decode_config(config.encode("utf-8-sig")), "bom.conf")
        assert facts.get("device.hostname") == "R-BOM"

    def test_reading_a_file_matches_decoding_its_bytes(self, tmp_path) -> None:
        """``decode_config_file`` must be exactly ``decode_config(read_bytes())``.

        A separate implementation for the disk path is how the two entry points
        diverged the first time.
        """
        path = tmp_path / "bom.conf"
        raw = "hostname R1\n!\nend\n".encode("utf-8-sig")
        path.write_bytes(raw)
        assert decode_config_file(path) == decode_config(raw)


class TestWindowsCodepageBytes:
    """A smart quote in a description used to crash the CLI and not the API.

    These tests also pin the documented *limit* of the decoder. ``decode.py`` says
    plainly that it does not repair mojibake, and that this is acceptable because
    the damage is confined to free text. That is a load-bearing claim — it is the
    reason the module is allowed to guess — so it is asserted here rather than
    left as a comment, by checking the damaged paths against what the rules
    actually read.
    """

    def test_a_cp1252_byte_does_not_raise(self) -> None:
        """0x92 is a valid cp1252 right single quote and invalid UTF-8.

        This is the byte that came out of the CLI as a traceback. It appears in
        configs edited in Word or Outlook, which is how descriptions get written.
        """
        assert decode_config(b"hostname R1\n description Bob\x92s uplink\n")

    def test_a_cp1252_byte_costs_no_facts(self) -> None:
        """The count and the set of paths must survive; only values may shift."""
        real = (CONFIG_DIR / "realistic" / "secure_baseline.conf").read_bytes()
        clean = _facts(decode_config(real), "secure_baseline.conf")
        mangled = _facts(
            decode_config(real.replace(b"description ", b"description Bob\x92s ", 1)),
            "secure_baseline.conf",
        )
        assert set(mangled) == set(clean)

    def test_nothing_a_rule_reads_is_damaged(self) -> None:
        """The documented limitation, asserted against the rule packs.

        Injecting one cp1252 byte pushes the *whole file* past ``utf-8``, so a
        UTF-8 em-dash elsewhere in the same config decodes as ``â€”``. That is the
        mojibake ``decode.py`` declines to repair. The claim that makes it
        tolerable is narrow and checkable: no damaged path is one any rule
        evaluates, so no verdict moves.

        Asserted against the real loaded packs rather than against a hand-written
        list of free-text paths, because a hand-written list would go stale
        exactly when a new pack starts reading a description — which is the case
        where this test needs to fail.

        "Reads" is narrowed to *compares the value*, and the distinction is the
        whole point rather than a convenience. Mojibake changes a fact's text; it
        does not change whether the fact exists. So a ``presence`` or ``count``
        condition on a damaged path cannot move a verdict — ``description Bob's
        uplink`` and ``description Bobâ€™s uplink`` are both a description being
        present, and both are one fact. A ``fact_check`` on the same path is a
        different matter: it puts the mangled text on one side of a comparison,
        and then the verdict really does depend on the encoding.

        CIS Juniper OS 3.4 is the case that forced this to be stated. It requires
        a description on every interface and is written as a ``presence`` check
        inside a ``for_each``, so it reads ``interface.description`` without ever
        reading the text. Deleting that rule to keep a coarser assertion green
        would have traded a real control for a test that was easier to satisfy;
        sharpening the assertion instead keeps both, and keeps failing for the
        case that matters. ``for_each``'s block anchor counts as value-compared:
        the anchor's value decides which blocks exist and what each finding is
        named, so damage there is not structural.
        """
        real = (CONFIG_DIR / "realistic" / "secure_baseline.conf").read_bytes()
        clean = _facts(decode_config(real), "secure_baseline.conf")
        mangled = _facts(
            decode_config(real.replace(b"description ", b"description Bob\x92s ", 1)),
            "secure_baseline.conf",
        )

        damaged = {path for path in clean if clean[path] != mangled.get(path)}
        assert damaged, (
            "expected the em-dash in this fixture to be mangled; if the fixture "
            "lost its non-ASCII text this test is no longer proving anything"
        )

        compared: set[str] = set()
        structural: set[str] = set()
        for rule in load_all_rules():
            _split_paths_by_use(rule.condition, compared, structural)

        assert compared, (
            "no rule compares any fact value, so this test would pass no matter "
            "what decode.py did — the condition walk below has gone stale"
        )
        assert not damaged & compared, (
            f"mojibake reached a path whose value a rule compares: "
            f"{sorted(damaged & compared)}. A verdict can now depend on which "
            f"encoding the config arrived in, which is the whole thing "
            f"backend/ingest/decode.py exists to prevent."
        )


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.stem)
@pytest.mark.parametrize("mutation", sorted(MUTATIONS), ids=lambda k: k)
class TestByteLevelMutationsChangeNothing:
    """Every shipped fixture, under every mutation, must yield the same facts.

    This is the load-bearing test in the file. It is parametrised over the
    fixtures rather than over a copy of them, so it cannot fall behind: adding a
    fixture adds five assertions about it automatically.
    """

    def test_the_fact_set_is_identical(self, fixture, mutation: str) -> None:
        original = fixture.read_text(encoding=FILE_ENCODING)
        baseline = _facts(original, fixture.name)
        mutated = _facts(normalise(MUTATIONS[mutation](original)), fixture.name)

        assert mutated == baseline, (
            f"{mutation} changed what {fixture.name} parses to. "
            f"Lost: {sorted(set(baseline) - set(mutated))}. "
            f"Gained: {sorted(set(mutated) - set(baseline))}. "
            f"Changed: "
            f"{sorted(k for k in set(baseline) & set(mutated) if baseline[k] != mutated[k])}."
        )


class TestBannerTextIsNotConfiguration:
    """A ``banner motd`` body contains lines that look exactly like commands.

    This is the most dangerous shape in the whole input space, because getting it
    wrong produces a *wrong verdict* rather than a missing one: a login banner
    reading "this device does not run ip http server" would set
    ``mgmt.http.server_enabled`` from display text. The parser handles it — these
    tests are here so it keeps doing so, since nothing else in the suite covers a
    delimited multi-line block whose contents must be ignored.
    """

    BANNER_LAST = (
        "hostname R-LEAK\n!\nip ssh version 2\nno ip http server\n!\n"
        "banner motd ^C\nip ssh version 1\nip http server\n^C\n!\nend\n"
    )

    def test_banner_contents_do_not_become_facts(self) -> None:
        """Deliberately ordered banner-*after*-command.

        With the banner first, a last-value-wins parser would look correct for
        the wrong reason: the real command would overwrite the leaked one. Putting
        the contradicting text last means a leak actually changes the answer.
        """
        facts = _facts(self.BANNER_LAST, "leak.conf")
        assert facts.get("mgmt.ssh.version") == 2, "banner text overrode a real command"
        assert facts.get("mgmt.http.server_enabled") is False, (
            "banner text overrode a real command"
        )

    def test_a_banner_survives_the_mutations_too(self) -> None:
        """CRLF changes where the ``^C`` delimiter sits relative to the newline."""
        baseline = _facts(self.BANNER_LAST, "leak.conf")
        for name, mutate in MUTATIONS.items():
            mutated = _facts(normalise(mutate(self.BANNER_LAST)), "leak.conf")
            assert mutated == baseline, f"{name} changed how the banner is handled"
