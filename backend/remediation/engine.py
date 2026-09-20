"""Remediation resolution — the publisher's own fix text, made device-specific.

C4 asks for "device-specific step-by-step remediation CLI". Two things could
supply it, and only one of them is allowed to.

The forbidden one is a language model. An LLM that writes ``no ip http server``
into a remediation block has authored a configuration change for a production
device on the strength of a probability distribution, and a plausible-but-wrong
command here is worse than no command: the operator pastes it into an enable
prompt. R3's rule is absolute — remediation comes from a hier_config delta or a
template, never from generation.

The permitted one is what this module does: every control in every built catalog
carries the publisher's own ``fix_text``, and 53% of those contain prompt-prefixed
CLI written by CIS or DISA themselves. Extracting it is citable — each command
traces to a named document and control — and it needs no model at all. The
remaining 47% are prose, and prose is returned *as* prose, marked
:data:`KIND_MANUAL`. That distinction is the same tri-state discipline the verdict
path uses: "no command could be extracted" must never render as "nothing to do".

What makes the output device-specific is the prompt. Publishers write
``SW1(config)#``, ``R1(config-if)#``, ``hostname(config)#`` — nineteen different
placeholder hostnames across the corpus. The reconstructed prompt carries the
device's actual hostname and the mode the publisher put the command in, so the
operator can see where each line belongs instead of inferring it.

Two things this module deliberately does not do:

* **It does not invent mode-entry commands.** If the publisher shows a
  ``config-if`` command without the ``interface`` line that reaches that mode, the
  mode is reported as a label and the missing step is not fabricated. Guessing
  which interface would be authoring CLI by another route.
* **It does not present a template as runnable.** ``username <LOCAL_USERNAME>
  privilege 1`` is not a command, and 229 command lines in the corpus contain
  placeholders. Those tokens are extracted, counted and surfaced, so the report
  can say "substitute these first" rather than implying copy-paste safety.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from backend.frameworks.catalog import ControlCatalog, load_catalogs
from backend.remediation.playbook import get_commands_for_vendor, get_remediation

#: How a remediation was arrived at.
KIND_CLI = "cli"
"""Executable steps were extracted from the publisher's fix text or the playbook."""

KIND_MANUAL = "manual"
"""The publisher describes the fix in prose only. A human has to perform it."""

KIND_NONE = "none"
"""Neither source has anything for this control. Reported, never silently blank."""

#: A prompt-prefixed command line, e.g. ``SW1(config-if)#no ip proxy-arp``.
#: The optional whitespace before ``(mode)`` is not cosmetic — the corpus contains
#: ``hostname (config)#ip domain-name``, and a pattern without it silently
#: classified that control as prose-only.
_PROMPT = re.compile(
    r"^\s*(?P<host>[A-Za-z][\w\-]*)\s*"
    r"(?:\((?P<mode>[\w\-]+)\))?\s*"
    r"(?P<sep>[#>])\s*"
    r"(?P<command>\S.*?)\s*$"
)

#: Markup that leaked out of the publisher PDFs during catalog extraction.
#: ``<em>`` appears in 69 command lines; left in place it both corrupts the
#: command and gets miscounted as an operator placeholder.
#:
#: The brace form is the same leak in a different costume, and it is worse. Two
#: controls carry ``username {{em}LOCAL_USERNAME{/em}} secret``, where the outer
#: braces are the publisher's real placeholder delimiters and the inner ``{em}``
#: is the tag. Matching only the angle form left the command corrupted *and* told
#: the operator to substitute ``{{em}`` and ``{/em}`` — two tokens that do not
#: exist — while hiding the one placeholder that does. Stripping both forms
#: recovers ``username {LOCAL_USERNAME} secret``.
_MARKUP = re.compile(
    r"</?(?:em|i|b|strong|span|code|tt|sub|sup)\s*/?>"
    r"|\{/?(?:em|i|b|strong|span|code|tt|sub|sup)\}",
    re.IGNORECASE,
)

#: Tokens the operator must replace before running anything. Three shapes,
#: because the publishers use all three: ``<interface_name>``, ``{group_name}``,
#: ``[ending_line_number]``.
_PLACEHOLDER = re.compile(r"<[A-Za-z_][\w\- ]*>|\{[^}]{1,60}\}|\[[^\]]{1,60}\]")

#: Prompt hostnames the publishers use as stand-ins. Not used for matching —
#: :data:`_PROMPT` accepts any hostname — but kept because a line whose "hostname"
#: is one of these is certainly a prompt and not prose that happens to contain a
#: ``#``.
KNOWN_PROMPT_HOSTS = frozenset({
    "hostname", "host", "switch", "router", "device", "asa", "firewall",
    "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
    "sw1", "sw2", "sw3", "sw4", "leaf-1a", "spine-1a",
})

#: ``exec`` for a ``>`` or bare ``#`` prompt: the publisher showed a command with
#: no configuration mode, so it runs from the exec prompt.
MODE_EXEC = "exec"


@dataclass(frozen=True)
class RemediationStep:
    """One command, with the context needed to run it and the caveats not to.

    Attributes:
        mode: The configuration mode the publisher put this command in
            (``config``, ``config-if``, ``config-line``, …) or :data:`MODE_EXEC`.
        command: The command text, markup stripped.
        prompt: The command as the operator will see it on *their* device,
            hostname substituted. This is the device-specific part of C4.
        placeholders: Tokens that must be replaced before running. Non-empty means
            this line is a template, not a command.
    """

    mode: str
    command: str
    prompt: str
    placeholders: tuple[str, ...] = ()

    @property
    def is_runnable(self) -> bool:
        """False when the operator still has to fill something in."""
        return not self.placeholders


@dataclass(frozen=True)
class Remediation:
    """Everything the report needs to print a remediation block honestly.

    Attributes:
        control_id: The control this fixes.
        kind: One of :data:`KIND_CLI`, :data:`KIND_MANUAL`, :data:`KIND_NONE`.
        steps: Ordered commands. Empty unless ``kind`` is :data:`KIND_CLI`.
        guidance: The publisher's prose, markup stripped. Present for every kind —
            it is the *why*, and an operator running commands without it is
            following instructions rather than making a decision.
        source: Citation for the text above: document and control. What separates
            this from generated advice.
        verification: A command that shows whether the fix took. Only the
            hand-authored playbook carries these; catalogs do not.
        rollback: How to undo it.
        risk: ``low`` / ``medium`` / ``high`` where known, else ``unknown``.
        notes: Caveats the report must show — missing mode-entry steps,
            placeholders, prose-only status.
    """

    control_id: str
    kind: str
    steps: tuple[RemediationStep, ...] = ()
    guidance: str = ""
    source: str = ""
    verification: str = ""
    rollback: str = ""
    risk: str = "unknown"
    notes: tuple[str, ...] = ()

    @property
    def requires_substitution(self) -> bool:
        """True when any step still contains an operator placeholder."""
        return any(step.placeholders for step in self.steps)

    @property
    def is_actionable(self) -> bool:
        """True when there is at least one command to run."""
        return self.kind == KIND_CLI and bool(self.steps)


def strip_markup(text: str) -> str:
    """Remove leaked HTML tags and unescape entities from publisher text."""
    return html.unescape(_MARKUP.sub("", text))


def _prose(fix_text: str) -> str:
    """The publisher's fix text, minus its command lines.

    :func:`extract_steps` lifts the commands out; this returns what is left, so
    a report prints each publisher command once -- on the operator's own prompt,
    in the steps table -- and not again verbatim with the publisher's placeholder
    hostname in the guidance paragraph. A line counts as a command line exactly
    when :data:`_PROMPT` accepts it, which is the same gate ``extract_steps``
    uses: the two halves must agree about what a command is, or the command
    reappears in the prose.
    """
    kept = [
        raw_line
        for raw_line in fix_text.splitlines()
        if not _PROMPT.match(strip_markup(raw_line))
    ]
    return "\n".join(strip_markup(line) for line in kept).strip()


def extract_steps(fix_text: str, hostname: str) -> tuple[RemediationStep, ...]:
    """Pull the prompt-prefixed command lines out of a publisher's fix text.

    Args:
        fix_text: The publisher's remediation text, as the catalog stores it.
        hostname: The audited device's hostname, used to rebuild each prompt so
            the operator sees their own device rather than ``SW1``.

    Returns:
        The commands in the order the publisher wrote them. Empty when the fix is
        described in prose only — which is 47% of the corpus and a legitimate
        answer, not a parse failure.
    """
    steps: list[RemediationStep] = []
    for raw_line in fix_text.splitlines():
        line = strip_markup(raw_line)
        match = _PROMPT.match(line)
        if not match:
            continue
        command = match.group("command").strip()
        if not command:
            continue
        # A prose line ending in a colon then a URL fragment can look like a
        # prompt; requiring the command not to start with a lone bracket or
        # punctuation removes the bulk of those without a hostname allow-list.
        if command[0] in "(),.;:":
            continue
        mode = match.group("mode") or MODE_EXEC
        placeholders = tuple(
            dict.fromkeys(token.strip() for token in _PLACEHOLDER.findall(command))
        )
        suffix = "" if mode == MODE_EXEC else f"({mode})"
        steps.append(
            RemediationStep(
                mode=mode,
                command=command,
                prompt=f"{hostname}{suffix}{match.group('sep')}{command}",
                placeholders=placeholders,
            )
        )
    return tuple(steps)


@lru_cache(maxsize=1)
def _catalog_index() -> tuple[dict, dict, dict]:
    """Index every built catalog control by the keys a finding can offer.

    Cached for the process: ``load_catalogs()`` reads 42 files and 3,366 controls
    in about a quarter of a second, which is fine once and unacceptable per
    report — a 71-finding device would spend 16 seconds re-reading the same JSON.

    Returns:
        ``(by_catalog_id, by_benchmark, versions_by_control)``. The first key is
        exact and comes from the mapping rule's own ``catalog: {catalog_id,
        control_id}`` reference, surfaced on the finding as
        ``references["catalog_id"]``. The second is the fallback for projected NIST
        and ISO findings, which are derived by crosswalk and carry a benchmark
        rather than a catalog id. The third records which *versions* of a benchmark
        publish a given control, so a lookup that misses can say whether it missed
        because the control is unknown or because the audit cites an edition that
        is no longer installed.
    """
    by_catalog: dict[tuple[str, str], tuple[ControlCatalog, Any]] = {}
    by_benchmark: dict[tuple[str, str, str, str], tuple[ControlCatalog, Any]] = {}
    versions: dict[tuple[str, str, str], set[str]] = {}
    for catalog in load_catalogs():
        for control in catalog.controls:
            by_catalog[(catalog.catalog_id, control.control_id)] = (catalog, control)
            key = (
                catalog.framework,
                catalog.benchmark,
                catalog.benchmark_version,
                control.control_id,
            )
            by_benchmark.setdefault(key, (catalog, control))
            versions.setdefault(
                (catalog.framework, catalog.benchmark, control.control_id), set()
            ).add(catalog.benchmark_version)
    return by_catalog, by_benchmark, versions


def reset_catalog_cache() -> None:
    """Drop the cached index.

    Catalogs are rebuilt by ``scripts/build_catalog.py`` while the server may be
    running, and C5 promises new standards without a redeploy. A long-lived
    process that never re-read the index would keep serving remediation from the
    catalog set it booted with.
    """
    _catalog_index.cache_clear()


def _lookup(finding: dict[str, Any]) -> tuple[ControlCatalog, Any] | None:
    """Find the catalog control behind a finding, by exact id then by benchmark."""
    by_catalog, by_benchmark, _versions = _catalog_index()
    control_id = str(finding.get("control_id") or "")
    if not control_id:
        return None

    references = finding.get("references") or {}
    if isinstance(references, dict):
        catalog_id = references.get("catalog_id")
        if catalog_id:
            hit = by_catalog.get((str(catalog_id), control_id))
            if hit:
                return hit

    return by_benchmark.get((
        str(finding.get("framework") or ""),
        str(finding.get("benchmark") or ""),
        str(finding.get("benchmark_version") or ""),
        control_id,
    ))


def _version_skew_note(finding: dict[str, Any]) -> str:
    """Why a lookup missed, when the control exists at another edition.

    Refusing to serve a fix across benchmark versions is deliberate: DISA
    renumbers and rewords controls between releases, so V3R7's remediation for
    ``V-215832`` is not necessarily the fix for the control that verdict was
    issued against. But "no published remediation is available" is then a false
    statement about a control the catalogs plainly carry, and it sends the
    operator looking for a document rather than for the re-audit that would
    actually resolve it.

    Returns:
        A sentence naming the installed editions, or ``""`` when the control is
        genuinely absent.
    """
    _by_catalog, _by_benchmark, versions = _catalog_index()
    framework = str(finding.get("framework") or "")
    benchmark = str(finding.get("benchmark") or "")
    control_id = str(finding.get("control_id") or "")
    cited = str(finding.get("benchmark_version") or "")

    installed = versions.get((framework, benchmark, control_id))
    if not installed or cited in installed:
        return ""
    return (
        f"This verdict cites {benchmark} {cited or '(no version recorded)'}, which "
        f"is not among the installed editions of that benchmark "
        f"({', '.join(sorted(installed))}). The control does exist there, but "
        f"publishers renumber and reword controls between releases, so serving "
        f"that edition's fix here could describe a different requirement. "
        f"Re-audit this device to get remediation against the installed edition."
    )


def _mode_notes(steps: tuple[RemediationStep, ...]) -> list[str]:
    """Warn when a command needs a mode the publisher never showed how to reach.

    ``config-if`` without an ``interface`` line is the common case. Naming the gap
    is the honest move; picking an interface would be authoring configuration.
    """
    notes: list[str] = []
    reached = {MODE_EXEC, "config"}
    for step in steps:
        if step.mode in reached:
            continue
        reached.add(step.mode)
        notes.append(
            f"One or more commands run in {step.mode} mode. The published fix does "
            f"not include the command that enters it, so select the correct target "
            f"(interface, line or instance) for this device before applying them."
        )
    return notes


def resolve_remediation(
    finding: dict[str, Any],
    device: dict[str, Any],
) -> Remediation:
    """Build the remediation block for one finding.

    Args:
        finding: A finding dict as the API and the report see it.
        device: The device record, for the hostname and vendor.

    Returns:
        A :class:`Remediation`, always. A control with no published fix returns
        :data:`KIND_NONE` with a sentence saying so, because a blank remediation
        section reads as "compliant" to anyone skimming.

    Precedence is catalog first, playbook second. The catalog's text is what the
    publisher actually wrote and is citable to a document and control; the
    playbook is hand-authored and exists to add the two things catalogs do not
    carry — a verification command and a rollback. So when both are available the
    commands come from the catalog and the verification from the playbook.
    """
    control_id = str(finding.get("control_id") or "")
    hostname = str(device.get("hostname") or device.get("device_id") or "device")
    vendor = str(device.get("vendor") or "")
    playbook = get_remediation(finding.get("remediation_ref"))

    verification = str(playbook.get("verification", "")) if playbook else ""
    rollback = str(playbook.get("rollback", "")) if playbook else ""
    risk = str(playbook.get("risk_of_fix", "unknown")) if playbook else "unknown"

    found = _lookup(finding)
    if found is not None:
        catalog, control = found
        guidance = _prose(control.fix_text)
        source = (
            f"{catalog.benchmark} {catalog.benchmark_version}, control "
            f"{control.control_id} — {catalog.source_document}"
        )
        steps = extract_steps(control.fix_text, hostname)
        notes = list(_mode_notes(steps))
        if control.impact.strip():
            notes.append(f"Publisher's stated impact: {strip_markup(control.impact).strip()}")

        if steps:
            substitutions = sorted({
                token for step in steps for token in step.placeholders
            })
            if substitutions:
                notes.insert(0, (
                    "These commands are templates, not ready to paste: replace "
                    + ", ".join(substitutions)
                    + " with values for this device first."
                ))
            return Remediation(
                control_id=control_id,
                kind=KIND_CLI,
                steps=steps,
                guidance=guidance,
                source=source,
                verification=verification,
                rollback=rollback,
                risk=risk,
                notes=tuple(notes),
            )

        # Prose-only: 47% of the corpus. Returned as guidance, labelled manual.
        return Remediation(
            control_id=control_id,
            kind=KIND_MANUAL,
            guidance=guidance,
            source=source,
            verification=verification,
            rollback=rollback,
            risk=risk,
            notes=(
                "The published fix for this control is described in prose and "
                "contains no command line to extract. Apply it by hand.",
                *notes,
            ),
        )

    # No catalog control matched. The playbook is the only remaining source.
    skew = _version_skew_note(finding)
    if playbook:
        commands = get_commands_for_vendor(finding.get("remediation_ref"), vendor)
        steps = tuple(
            RemediationStep(
                mode="config",
                command=command.strip(),
                prompt=f"{hostname}(config)#{command.strip()}",
                placeholders=tuple(
                    dict.fromkeys(t.strip() for t in _PLACEHOLDER.findall(command))
                ),
            )
            for command in commands
            if command.strip()
        )
        return Remediation(
            control_id=control_id,
            kind=KIND_CLI if steps else KIND_MANUAL,
            steps=steps,
            guidance=str(playbook.get("description", "")),
            source="PRAMAN remediation playbook (hand-authored)",
            verification=verification,
            rollback=rollback,
            risk=risk,
            notes=(
                "Sourced from the built-in playbook rather than a published "
                "benchmark, because no built catalog carries this control.",
                *([skew] if skew else []),
            ),
        )

    return Remediation(
        control_id=control_id,
        kind=KIND_NONE,
        guidance="",
        source="",
        notes=(
            skew
            or (
                "No published remediation is available for this control in the "
                "built catalogs, and the playbook has no entry for it. Consult the "
                "benchmark document directly. This is a gap in PRAMAN's coverage, "
                "not a statement that the finding needs no action."
            ),
        ),
    )
