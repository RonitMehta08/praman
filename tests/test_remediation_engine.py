"""Remediation resolution — where the commands come from, and what they must not claim.

A remediation block is the one part of a compliance report that an operator
*executes*. Everything else is read. That asymmetry sets the bar for these tests:
a wrong verdict costs a re-audit, and a wrong command costs an outage.

So three properties are checked harder than the rest.

**Provenance.** Every command must trace to a published document and control. The
architecture forbids model-authored CLI outright (R3), and the test that enforces
it is structural — the module may not import the AI package at all — because a
docstring promising "no LLM" is not a constraint.

**Honest absence.** 65% of catalog controls describe their fix in prose. Those must
come back labelled ``manual`` with the prose attached, never as an empty block: a
blank remediation section reads as "nothing to do" to anyone skimming, which is
the same failure as rendering missing evidence as PASS.

**Nothing presented as runnable that isn't.** 195 controls carry commands
containing ``<interface_name>``-style placeholders. Printing those as
copy-pasteable is how an operator ends up pasting a literal angle bracket into a
config prompt.

The corpus-coverage tests at the end assert against the real built catalogs rather
than fixtures. They are the ones that would catch a regression in the extractor —
a subtly narrowed regex still passes every hand-written case while quietly
reclassifying hundreds of controls as prose-only, and only a count notices.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.frameworks.catalog import load_catalogs
from backend.remediation.engine import (
    KIND_CLI,
    KIND_MANUAL,
    KIND_NONE,
    MODE_EXEC,
    Remediation,
    _prose,
    extract_steps,
    reset_catalog_cache,
    resolve_remediation,
    strip_markup,
)

DEVICE = {"device_id": "dev-r1", "hostname": "core-rtr-01", "vendor": "cisco_ios"}

CIS_IOS = {
    "framework": "CIS",
    "benchmark": "CIS Cisco IOS 15",
    "benchmark_version": "v4.1.1",
    "references": {"catalog_id": "cis_cisco_ios_15_v4_1_1"},
}


def _finding(control_id: str, **extra) -> dict:
    return {**CIS_IOS, "control_id": control_id, **extra}


@pytest.fixture(scope="module")
def catalogs():
    """The real built catalogs. Skip rather than fail if none have been built."""
    built = load_catalogs()
    if not built:
        pytest.skip("no catalogs built; run scripts/build_catalog.py")
    return built


# ── Provenance: where a command is allowed to come from ───────────────


def test_the_engine_cannot_reach_the_ai_package() -> None:
    """R3 as a structural fact, not a promise in prose.

    A model that writes ``no ip http server`` into a remediation block has authored
    a configuration change for a production device on the strength of a probability
    distribution. The operator pastes it into an enable prompt. So the import is
    the thing to forbid: a docstring saying "no LLM" survives any refactor that
    adds one.
    """
    source = Path("backend/remediation/engine.py").read_text(encoding="utf-8")
    for forbidden in ("backend.ai", "llama", "llm_", "generate("):
        assert forbidden not in source, f"remediation reached for {forbidden}"


def test_every_command_carries_a_citation(catalogs) -> None:
    """A command with no source is indistinguishable from a guess.

    The citation is what lets an operator check the instruction against the
    benchmark before running it, and what lets an auditor confirm the report did
    not invent the fix.
    """
    remediation = resolve_remediation(_finding("1.1.1"), DEVICE)
    assert remediation.is_actionable
    assert "CIS Cisco IOS 15" in remediation.source
    assert "v4.1.1" in remediation.source
    assert "1.1.1" in remediation.source
    assert remediation.source.endswith(".pdf"), "the document itself must be named"


def test_the_publishers_own_command_is_what_gets_extracted(catalogs) -> None:
    """``aaa new-model`` because CIS wrote ``aaa new-model``, not because we know it."""
    steps = resolve_remediation(_finding("1.1.1"), DEVICE).steps
    assert [step.command for step in steps] == ["aaa new-model"]
    assert steps[0].mode == "config"


# ── Device-specific: the C4 word that does the work ───────────────────


def test_the_prompt_carries_this_device_not_the_publishers_placeholder() -> None:
    """Publishers write ``SW1(config)#``; the operator has a ``core-rtr-01``.

    Nineteen different stand-in hostnames appear across the corpus. Rewriting the
    prompt is what makes the output device-specific rather than a benchmark excerpt
    pasted into a report.
    """
    steps = extract_steps("SW1(config)#no ip proxy-arp", "core-rtr-01")
    assert steps[0].prompt == "core-rtr-01(config)#no ip proxy-arp"
    assert steps[0].command == "no ip proxy-arp"


def test_a_device_with_no_hostname_still_gets_a_prompt() -> None:
    """Falls back to the device id, then to a literal.

    A config-only upload may carry no hostname at all, and an empty prompt
    (``(config)#aaa new-model``) reads as a syntax error rather than as a command.
    """
    assert resolve_remediation(
        _finding("1.1.1"), {"device_id": "dev-r1", "vendor": "cisco_ios"}
    ).steps[0].prompt.startswith("dev-r1(config)#")
    assert resolve_remediation(_finding("1.1.1"), {}).steps[0].prompt.startswith(
        "device(config)#"
    )


def test_the_mode_is_preserved_so_the_operator_knows_where_a_command_goes() -> None:
    """``transport input ssh`` typed at the wrong prompt is a different command."""
    steps = extract_steps(
        "R1(config)#line vty 0 15\nR1(config-line)#transport input ssh", "rtr"
    )
    assert [step.mode for step in steps] == ["config", "config-line"]
    assert steps[1].prompt == "rtr(config-line)#transport input ssh"


def test_an_exec_prompt_has_no_mode_suffix() -> None:
    """``show`` commands run from exec, and a fake ``(exec)`` suffix is not a prompt."""
    steps = extract_steps("hostname#show running-config", "rtr")
    assert steps[0].mode == MODE_EXEC
    assert steps[0].prompt == "rtr#show running-config"


# ── The corpus's own quirks ───────────────────────────────────────────


def test_a_space_before_the_mode_is_still_a_prompt(catalogs) -> None:
    """The bug the corpus found.

    CIS writes ``hostname (config)#ip domain-name`` for control 2.1.1.1.2 — with a
    space. The first version of the pattern required none, silently classified that
    control as prose-only, and would have gone on doing so for every publisher who
    formats prompts that way.
    """
    steps = extract_steps("hostname (config)#ip domain-name example.com", "rtr")
    assert len(steps) == 1
    assert steps[0].mode == "config"
    assert resolve_remediation(_finding("2.1.1.1.2"), DEVICE).kind == KIND_CLI


def test_markup_that_leaked_out_of_the_publisher_pdf_is_stripped() -> None:
    """``<em>`` appears inside 69 command lines in the built catalogs.

    Left in place it corrupts the command *and* gets counted as an operator
    placeholder, so a perfectly runnable command would be flagged as a template.
    """
    assert strip_markup("ip domain-name {<em>domain-name</em>}") == (
        "ip domain-name {domain-name}"
    )
    steps = extract_steps("hostname (config)#ip domain-name {<em>d-name</em>}", "rtr")
    assert steps[0].command == "ip domain-name {d-name}"
    assert steps[0].placeholders == ("{d-name}",)


def test_the_brace_form_of_the_same_leak_is_stripped_too() -> None:
    """``{em}`` instead of ``<em>``, and it is the worse of the two.

    CIS Cisco IOS 15 and IOS XE 17 both write control 1.4.3's fix as
    ``username {{em}LOCAL_USERNAME{/em}} secret``, where the *outer* braces are the
    publisher's real placeholder delimiters and the inner ``{em}`` is the leaked
    tag. A stripper that only knew the angle form left the command corrupted and
    reported the placeholders as ``{{em}`` and ``{/em}`` — two tokens that do not
    exist anywhere — while hiding ``LOCAL_USERNAME``, the one value the operator
    actually has to supply. The operator is then told to substitute nonsense and
    not told to substitute the username.
    """
    assert strip_markup("username {{em}LOCAL_USERNAME{/em}} secret") == (
        "username {LOCAL_USERNAME} secret"
    )
    steps = extract_steps("R1(config)#username {{em}LOCAL_USERNAME{/em}} secret", "rtr")
    assert steps[0].command == "username {LOCAL_USERNAME} secret"
    assert steps[0].placeholders == ("{LOCAL_USERNAME}",)
    assert steps[0].is_runnable is False


def test_the_two_controls_that_carry_the_brace_leak_come_out_clean(catalogs) -> None:
    """Asserted against the corpus, because the fixture above cannot regress with it.

    Control 1.4.3 of the two CIS Cisco catalogs is where this leak actually lives.
    Pinning the real controls means a future extractor change that reintroduces the
    tag is caught here rather than in a report.
    """
    checked = 0
    for catalog in catalogs:
        for control in catalog.controls:
            if control.control_id != "1.4.3" or "{em}" not in (control.fix_text or ""):
                continue
            checked += 1
            steps = extract_steps(control.fix_text, "rtr")
            assert steps, f"{catalog.catalog_id} 1.4.3 yielded no command"
            for step in steps:
                assert "{em}" not in step.command
                assert "{/em}" not in step.command
                assert not any("em}" in token for token in step.placeholders), (
                    f"{catalog.catalog_id}: markup counted as a placeholder"
                )
    if not checked:
        pytest.skip("no built catalog carries the brace-form leak")


def test_html_entities_are_unescaped() -> None:
    """Publisher extraction produces ``&gt;`` where the command needs ``>``."""
    assert strip_markup("logging trap &gt;level&lt;") == "logging trap >level<"


def test_prose_that_merely_contains_a_hash_is_not_read_as_a_command() -> None:
    """A false positive here puts a fragment of a sentence in front of an operator."""
    assert extract_steps("Refer to section 3.2: see the note (below).", "rtr") == ()
    assert extract_steps("This is prose with no prompt at all.", "rtr") == ()


# ── Templates are not commands ────────────────────────────────────────


def test_a_placeholder_makes_a_step_not_runnable() -> None:
    """195 controls in the corpus ship commands with placeholders.

    Presenting ``username <LOCAL_USERNAME> privilege 1`` as copy-pasteable is how
    an operator ends up putting a literal angle bracket into a config prompt.
    """
    steps = extract_steps("hostname(config)#username <LOCAL_USERNAME> privilege 1", "r")
    assert steps[0].placeholders == ("<LOCAL_USERNAME>",)
    assert steps[0].is_runnable is False


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("snmp-server group <group_name> v3 priv", ("<group_name>",)),
        ("ip domain-name {domain-name}", ("{domain-name}",)),
        ("clear line [ending_line_number]", ("[ending_line_number]",)),
        ("aaa new-model", ()),
    ],
)
def test_all_three_placeholder_shapes_are_recognised(command, expected) -> None:
    """Publishers use angle brackets, braces and square brackets interchangeably."""
    steps = extract_steps(f"R1(config)#{command}", "rtr")
    assert steps[0].placeholders == expected


def test_substitution_is_announced_before_the_commands(catalogs) -> None:
    """The warning has to be the first note, because notes get truncated.

    A report that prints three notes and shows two has to show the one that stops
    the operator pasting a template.
    """
    remediation = resolve_remediation(_finding("1.2.1"), DEVICE)
    assert remediation.requires_substitution is True
    assert "templates, not ready to paste" in remediation.notes[0]
    assert "<LOCAL_USERNAME>" in remediation.notes[0]


def test_a_clean_command_is_not_warned_about(catalogs) -> None:
    """Warning on everything trains the reader to skip warnings."""
    remediation = resolve_remediation(_finding("1.1.1"), DEVICE)
    assert remediation.requires_substitution is False
    assert not any("ready to paste" in note for note in remediation.notes)


# ── The guidance is the why, not the commands again ───────────────────


def test_the_guidance_does_not_repeat_the_commands(catalogs) -> None:
    """Found by rendering a report, not by reading the code.

    The guidance paragraph and the steps table are both built from ``fix_text``.
    Before ``_prose`` existed the paragraph carried the publisher's raw line
    (``hostname (config)#ip domain-name {domain-name}``) and the table carried the
    same command rewritten for this device — so the report showed one command
    twice, once with a hostname that is not the audited device's. An operator
    scanning for something to paste has no way to tell which of the two is meant
    for them.
    """
    remediation = resolve_remediation(_finding("2.1.1.1.2"), DEVICE)
    assert remediation.kind == KIND_CLI
    assert remediation.steps, "2.1.1.1.2 is the space-before-mode control"
    for step in remediation.steps:
        assert step.command not in remediation.guidance, (
            f"guidance repeats the command {step.command!r}"
        )
    # And the publisher's stand-in hostname must not survive into the prose.
    assert "hostname (config)#" not in remediation.guidance


def test_the_guidance_keeps_the_reason(catalogs) -> None:
    """Stripping commands must not strip the sentence that explains them.

    ``_prose`` removing too much would be worse than removing nothing: an
    operator would be handed CLI with no statement of what it is for, which is
    the definition of following instructions rather than making a decision.
    """
    remediation = resolve_remediation(_finding("2.1.1.1.2"), DEVICE)
    assert "domain name" in remediation.guidance.lower()


def test_a_prose_only_fix_keeps_all_of_its_prose() -> None:
    """No command lines means nothing to strip."""
    text = "Navigate to Device > Setup > Management and enable the setting."
    assert _prose(text) == text


# ── Honest absence ────────────────────────────────────────────────────


def test_prose_only_fixes_come_back_labelled_manual_with_the_prose() -> None:
    """65% of catalog controls are prose. That is an answer, not a parse failure.

    Returning an empty block would read as "nothing to do", which is the
    remediation-side version of rendering missing evidence as PASS.
    """
    remediation = resolve_remediation(
        {
            "control_id": "1.1.1",
            "framework": "CIS",
            "benchmark": "CIS Palo Alto Firewall 11",
            "benchmark_version": "v1.2.0",
        },
        DEVICE,
    )
    if remediation.kind == KIND_MANUAL:
        assert remediation.guidance, "the prose must survive"
        assert "prose" in remediation.notes[0]
        assert "by hand" in remediation.notes[0]
        assert remediation.steps == ()


def test_an_unknown_control_says_so_rather_than_going_blank() -> None:
    """A coverage gap must be reported as a gap.

    The sentence has to distinguish "PRAMAN has no fix for this" from "this needs
    no action" — a reader who conflates them closes a real finding.
    """
    remediation = resolve_remediation(_finding("99.99.99"), DEVICE)
    assert remediation.kind == KIND_NONE
    assert remediation.steps == ()
    note = remediation.notes[0]
    assert "gap in PRAMAN's coverage" in note
    assert "not a statement that the finding needs no action" in note
    assert remediation.is_actionable is False


def test_a_mode_nobody_showed_how_to_reach_is_flagged_not_invented() -> None:
    """``config-if`` without an ``interface`` line is the common case.

    Picking an interface would be authoring configuration by another route — the
    engine would be choosing which port to change. Naming the gap leaves the
    decision where it belongs.
    """
    remediation = resolve_remediation(
        _finding("1.1.1", remediation_ref=None), DEVICE
    )
    steps = extract_steps("SW1(config-if)#no ip proxy-arp", "rtr")
    assert steps[0].mode == "config-if"
    assert all("interface" not in step.command for step in steps), (
        "the engine must not fabricate the mode-entry command"
    )
    assert isinstance(remediation, Remediation)


def test_the_mode_warning_names_the_mode_and_appears_once() -> None:
    """One note per mode, or a long fix produces a wall of identical warnings."""
    from backend.remediation.engine import _mode_notes

    steps = extract_steps(
        "R1(config-if)#no ip proxy-arp\nR1(config-if)#no ip redirects\n"
        "R1(config-line)#transport input ssh",
        "rtr",
    )
    notes = _mode_notes(steps)
    assert len(notes) == 2, notes
    assert "config-if" in notes[0]
    assert "config-line" in notes[1]
    assert "select the correct target" in notes[0]


# ── Precedence between the two sources ────────────────────────────────


def test_the_catalog_supplies_commands_and_the_playbook_supplies_verification(
    catalogs,
) -> None:
    """Each source contributes what it actually has.

    The catalog is the publisher's own text and is citable; the playbook is
    hand-authored but carries the two things no catalog does — a command that shows
    whether the fix took, and a rollback. Taking commands from the playbook when a
    catalog entry exists would trade a citation for nothing.
    """
    remediation = resolve_remediation(
        _finding("1.1.1", remediation_ref="stig-ndm-v220140-remediation"), DEVICE
    )
    assert [step.command for step in remediation.steps] == ["aaa new-model"]
    assert "CIS Cisco IOS 15" in remediation.source
    assert remediation.verification == "show aaa | include method"
    assert remediation.rollback == "no aaa new-model"
    assert remediation.risk == "high"


def test_the_playbook_is_the_fallback_when_no_catalog_carries_the_control() -> None:
    """STIG controls have no built catalog yet, and must still produce a fix."""
    remediation = resolve_remediation(
        {
            "control_id": "V-215844",
            "framework": "DISA_STIG",
            "benchmark": "unbuilt",
            "benchmark_version": "v3r8",
            "remediation_ref": "stig-ndm-v215844-remediation",
        },
        DEVICE,
    )
    assert remediation.kind == KIND_CLI
    assert [step.command for step in remediation.steps] == [
        "ip ssh version 2",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
    ]
    assert "hand-authored" in remediation.source
    assert "no built catalog carries this control" in remediation.notes[0]
    assert remediation.steps[0].prompt == "core-rtr-01(config)#ip ssh version 2"


def test_command_order_is_the_publishers_order() -> None:
    """``line vty 0 15`` before ``transport input ssh``, or neither works.

    Sorting or de-duplicating these would silently produce a sequence that does
    not apply.
    """
    steps = extract_steps(
        "R1(config)#line vty 0 15\n"
        "R1(config-line)#transport input ssh\n"
        "R1(config-line)#exec-timeout 10 0",
        "rtr",
    )
    assert [step.command for step in steps] == [
        "line vty 0 15",
        "transport input ssh",
        "exec-timeout 10 0",
    ]


def test_risk_is_unknown_rather_than_low_when_nobody_said() -> None:
    """Defaulting an unrated fix to "low" invites an operator to skip a change window.

    ``aaa new-model`` is the example that matters: CIS calls it "significantly
    disruptive", and a report that guessed "low" would be actively dangerous.
    """
    remediation = resolve_remediation(_finding("1.1.1"), DEVICE)
    assert remediation.risk == "unknown"
    assert any("impact" in note.lower() for note in remediation.notes), (
        "the publisher's own impact statement must reach the reader"
    )


# ── The cache ─────────────────────────────────────────────────────────


def test_the_catalog_index_is_cached(catalogs) -> None:
    """3,366 controls across 42 files, ~0.23 s. Fine once, fatal per finding.

    A 71-finding device would spend 16 seconds re-reading the same JSON, and the
    report route would look like a performance bug rather than a missing cache.
    """
    from backend.remediation.engine import _catalog_index

    reset_catalog_cache()
    first = _catalog_index()
    assert _catalog_index() is first, "the index was rebuilt"
    info = _catalog_index.cache_info()
    assert info.hits >= 1


def test_the_cache_can_be_dropped_for_a_rebuilt_catalog(catalogs) -> None:
    """C5 promises new standards without a redeploy.

    Catalogs are rebuilt by a script while the server runs. A process that never
    re-read the index would keep serving remediation from the set it booted with,
    and the new standard would appear in the rules and not in the fixes.
    """
    from backend.remediation.engine import _catalog_index

    before = _catalog_index()
    reset_catalog_cache()
    assert _catalog_index() is not before


# ── Against the real corpus ───────────────────────────────────────────


def test_every_cis_cisco_ios_control_yields_a_command(catalogs) -> None:
    """The demo path, asserted as a number.

    All 90 controls in CIS Cisco IOS 15 — which includes every one of the 71
    automated rules — produce extractable CLI. A narrowed regex would still pass
    every hand-written case above while quietly reclassifying dozens of these as
    prose-only, and only a count notices.
    """
    catalog = next(
        (c for c in catalogs if c.catalog_id == "cis_cisco_ios_15_v4_1_1"), None
    )
    if catalog is None:
        pytest.skip("CIS Cisco IOS 15 catalog not built")

    kinds = [
        resolve_remediation(
            {
                "control_id": control.control_id,
                "framework": catalog.framework,
                "benchmark": catalog.benchmark,
                "benchmark_version": catalog.benchmark_version,
                "references": {"catalog_id": catalog.catalog_id},
            },
            DEVICE,
        ).kind
        for control in catalog.controls
    ]
    assert kinds.count(KIND_NONE) == 0, "a built control with no remediation at all"
    assert kinds.count(KIND_CLI) == len(catalog.controls), (
        f"only {kinds.count(KIND_CLI)} of {len(catalog.controls)} yielded CLI"
    )


def test_no_control_in_any_built_catalog_resolves_to_nothing(catalogs) -> None:
    """Every catalog control carries publisher fix text, so ``none`` means a bug.

    ``KIND_NONE`` is reserved for controls no catalog knows about. Seeing it for a
    control that *is* in a catalog means the lookup keys drifted — the exact
    failure that would make remediation vanish from reports without any error.
    """
    misses = [
        (catalog.catalog_id, control.control_id)
        for catalog in catalogs
        for control in catalog.controls
        if resolve_remediation(
            {
                "control_id": control.control_id,
                "framework": catalog.framework,
                "benchmark": catalog.benchmark,
                "benchmark_version": catalog.benchmark_version,
                "references": {"catalog_id": catalog.catalog_id},
            },
            DEVICE,
        ).kind
        == KIND_NONE
    ]
    assert misses == [], f"{len(misses)} catalog controls resolved to nothing"


def test_lookup_works_without_a_catalog_id_on_the_finding(catalogs) -> None:
    """Projected NIST and ISO findings carry a benchmark, not a catalog id.

    They are derived by crosswalk rather than by a mapping rule, so the exact key
    is unavailable and the benchmark triple is the only way in. Without this
    fallback every projected finding would report a coverage gap.
    """
    remediation = resolve_remediation(
        {
            "control_id": "1.1.1",
            "framework": "CIS",
            "benchmark": "CIS Cisco IOS 15",
            "benchmark_version": "v4.1.1",
        },
        DEVICE,
    )
    assert remediation.kind == KIND_CLI
    assert [step.command for step in remediation.steps] == ["aaa new-model"]


# ── A verdict older than the installed benchmark ──────────────────────


def test_a_fix_is_not_served_across_benchmark_versions(catalogs) -> None:
    """The refusal itself, asserted — it is a safety property, not an oversight.

    DISA renumbers and rewords controls between STIG releases. ``V-215832`` exists
    in the installed V3R7 catalog, but a verdict issued against V3R5 was about
    whatever V3R5 called ``V-215832``, and handing over V3R7's fix would describe a
    requirement the operator was never assessed on. So the lookup must miss.
    """
    catalog = next(
        (
            c
            for c in catalogs
            if c.framework == "DISA_STIG" and c.controls
        ),
        None,
    )
    if catalog is None:
        pytest.skip("no DISA STIG catalog built")

    remediation = resolve_remediation(
        {
            "control_id": catalog.controls[0].control_id,
            "framework": catalog.framework,
            "benchmark": catalog.benchmark,
            # A version that is certainly not installed.
            "benchmark_version": "V0R0",
            "references": {},
        },
        DEVICE,
    )
    assert remediation.kind == KIND_NONE
    assert remediation.steps == ()


def test_a_version_mismatch_says_so_instead_of_claiming_no_fix_exists(catalogs) -> None:
    """The note has to name the real reason, or it is a false statement.

    "No published remediation is available for this control in the built catalogs"
    is what this used to say, about a control the catalogs plainly carry. An
    operator reading it goes looking for a benchmark document, when the thing that
    would actually resolve it is a re-audit against the installed edition. Same
    verdict, different next action — which is the whole value of the sentence.
    """
    catalog = next(
        (c for c in catalogs if c.framework == "DISA_STIG" and c.controls), None
    )
    if catalog is None:
        pytest.skip("no DISA STIG catalog built")

    control_id = catalog.controls[0].control_id
    remediation = resolve_remediation(
        {
            "control_id": control_id,
            "framework": catalog.framework,
            "benchmark": catalog.benchmark,
            "benchmark_version": "V0R0",
            "references": {},
        },
        DEVICE,
    )
    note = remediation.notes[0]
    assert "V0R0" in note, "the note must name the version the verdict cited"
    assert catalog.benchmark_version in note, "and the version that is installed"
    assert "re-audit" in note.lower(), "and what to do about it"
    assert "No published remediation is available" not in note


def test_a_control_no_catalog_carries_still_reports_a_coverage_gap() -> None:
    """The original message is still correct for its original case.

    Broadening the note must not swallow it: a genuinely unknown control is a gap
    in PRAMAN's coverage, and saying so is how that gap gets closed.
    """
    remediation = resolve_remediation(
        {
            "control_id": "NOT-A-REAL-CONTROL-999",
            "framework": "CIS",
            "benchmark": "CIS Cisco IOS 15",
            "benchmark_version": "v4.1.1",
            "references": {},
        },
        DEVICE,
    )
    assert remediation.kind == KIND_NONE
    assert "gap in PRAMAN's coverage" in remediation.notes[0]
