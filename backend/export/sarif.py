"""SARIF v2.1.0 output — the compliance audit as a CI gate artifact.

The OSCAL export answers "what did this signed audit conclude?". SARIF answers a
different question: "should this configuration change be allowed to land?". Its
home is a pipeline — a static-analysis viewer, a pull-request annotation, a
`sarif` upload step — where the useful output is a list of things that are wrong,
attached to the exact lines that make them wrong.

That difference drives three decisions worth stating up front.

**Built from a simulation, not from the ledger.** A gate has to run *before* the
config is committed to anything, so :func:`to_sarif` takes a device and its
findings straight out of ``POST /simulate``. Nothing here reads or writes the
ledger. The document therefore carries no ledger hash and makes no claim to be
verifiable evidence; that is what the OSCAL export and the signed PDF are for.

**No timestamps, no invocation block.** ``/simulate`` is documented as idempotent
— the same bytes produce the same verdicts — and this export preserves that
property exactly: the output is a pure function of the configuration and the loaded
rules. Two runs over an unchanged config produce byte-identical SARIF, so a diff in
CI means the configuration drifted, never that the clock moved. ``invocations``,
``columnKind`` and every timestamp are omitted for that reason, not by oversight.

**Remediation goes in ``rules[].help``, never in ``result.fixes``.** A SARIF
``fix`` describes an edit a tool may apply. PRAMAN's remediation text is a set of
CLI commands for a human to run on a live device after reading them; presenting
that as an applicable patch would invite a viewer to offer a one-click "fix" for a
change that can drop management access to a router.

Field names, ``required`` lists and enum values were read out of
``sarif-schema-2.1.0.json`` as published by OASIS (115,632 bytes). Two of them
shaped the code rather than merely validating it: ``region.startLine`` carries
``minimum: 1``, so a fact with no line number gets a location without a region
instead of ``startLine: 0``; and ``propertyBag`` is ``additionalProperties: true``,
which is what makes the ``praman*`` bookkeeping keys below legal rather than
tolerated.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from backend.app.config import APP_VERSION
from backend.canonical.findings import Finding, Result
from backend.core_errors import ExportError
from backend.export.ids import deterministic_uuid
from backend.export.oscal_mapping import as_finding, result_value
from backend.remediation.playbook import get_remediation

#: The only value the root schema's ``version`` enum accepts.
SARIF_VERSION = "2.1.0"

#: Where the schema was fetched from, and what goes into ``$schema``. The document
#: served at this URL declares its own ``$id`` as a ``raw.githubusercontent.com``
#: path; the OASIS Standard URL is used here because it is the citable published
#: location. Noted so the mismatch does not look like a mistake to be corrected.
SARIF_SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
)

#: XCCDF result → ``result.kind``. Enum verified:
#: ``notApplicable|pass|fail|review|open|informational``, default ``fail``.
#:
#: ``error`` maps to ``open`` rather than ``fail``: the rule did not establish that
#: the device is non-compliant, it failed to reach a conclusion, and ``open`` is
#: SARIF's word for a result needing a human. ``unknown`` maps to ``review`` for the
#: same reason from the other direction — PRAMAN saw a line no pattern pack
#: recognised, which is a question for the operator, not a verdict on the device.
#:
#: All nine values are present so that adding a tenth breaks
#: ``tests/test_export_sarif.py`` instead of exporting as a silent default.
RESULT_KIND: dict[str, str] = {
    Result.PASS.value: "pass",
    Result.FAIL.value: "fail",
    Result.FIXED.value: "pass",
    Result.ERROR.value: "open",
    Result.UNKNOWN.value: "review",
    Result.INFORMATIONAL.value: "informational",
    Result.NOTAPPLICABLE.value: "notApplicable",
    Result.NOTCHECKED.value: "notApplicable",
    Result.NOTSELECTED.value: "notApplicable",
}

#: The three results that get counted but not emitted as SARIF results.
#:
#: A single device typically produces a few hundred ``notchecked`` controls — every
#: control in the loaded benchmarks that PRAMAN has no deterministic rule for. Those
#: are the honest majority of any real audit and the PDF and OSCAL exports report
#: every one of them. Streaming them into a pull-request annotator would bury the
#: handful of results a reviewer can act on under hundreds that say "not evaluated".
#:
#: So they are omitted from ``results`` and their exact counts are published in
#: ``run.properties``, which keeps the omission arithmetic rather than editorial:
#: the per-result counts sum to the finding total, so a reader can confirm nothing
#: was quietly dropped.
OMITTED_RESULTS: tuple[str, ...] = (
    Result.NOTCHECKED.value,
    Result.NOTSELECTED.value,
    Result.NOTAPPLICABLE.value,
)

#: PRAMAN severity → ``result.level``. Enum verified ``none|note|warning|error``.
SEVERITY_LEVEL: dict[str, str] = {"high": "error", "medium": "warning", "low": "note"}

#: The schema's own default for ``level``, used for a severity outside the three.
DEFAULT_LEVEL = "warning"

#: ``partialFingerprints`` key. The ``name/vN`` shape is SARIF's convention for a
#: versioned fingerprint, so a future change to what the hash covers can ship as
#: ``/v2`` without silently re-identifying every existing alert.
FINGERPRINT_KEY = "pramanControlFingerprint/v1"

#: Device columns the exporter reads, checked up front so a missing one names
#: itself rather than surfacing as a KeyError inside a comprehension.
DEVICE_FIELDS = ("device_id", "vendor", "config_hash", "source_file")


def _rule_id(finding: Finding) -> str:
    """The SARIF rule id for `finding`'s control.

    ``framework/control_id`` rather than the bare control id, because SARIF groups
    results by ``ruleId`` and a bare ``1.1.4`` is ambiguous across frameworks.
    Unlike OSCAL's ``target-id``, SARIF puts no lexical constraint on an id, so the
    publisher's id travels verbatim on the right-hand side — no tokenising here.

    The benchmark version is deliberately not in the key: it would change every
    rule id on a benchmark update and break the historical grouping that makes a
    code-scanning UI useful. The version is published per rule in ``properties``.
    """
    return f"{finding.framework}/{finding.control_id}"


def _help_text(finding: Finding, vendor: str) -> str | None:
    """Remediation guidance for `finding`, or ``None`` when there is none.

    Only ever the guidance recorded for **this** device's vendor, and that is a
    whole-entry decision rather than a per-field one. ``get_commands_for_vendor``
    falls back to the ``cisco_ios`` list for an unknown vendor, which is right for a
    UI that labels what it is showing and wrong here: IOS syntax presented as the
    fix for a FortiGate is worse than no fix text at all, because a reader in a
    hurry will paste it.

    The playbook's ``verification`` and ``rollback`` strings are CLI too — ``show ip
    ssh | include SSH``, ``no ip ssh version 2`` — so they are held back with the
    commands. Emitting them beside a "no commands for your vendor" line would leak
    exactly what that line promised not to.
    """
    playbook = get_remediation(finding.remediation_ref)
    if playbook is None:
        return None
    lines = [str(playbook.get("title") or finding.title), ""]
    description = playbook.get("description")
    if description:
        lines += [str(description), ""]
    commands = (playbook.get("commands") or {}).get(vendor)
    if not commands:
        lines += [
            f"PRAMAN has no {vendor} command sequence recorded for this control. "
            "Apply the vendor's own documented equivalent. The commands, "
            "verification and rollback steps PRAMAN holds for this control are for "
            "other platforms and are deliberately not shown here."
        ]
        return "\n".join(lines).rstrip()
    lines += [f"Configuration commands ({vendor}):", "", "```"]
    lines += [str(command) for command in commands]
    lines += ["```", ""]
    for label, field in (("Verify with", "verification"), ("Roll back with", "rollback")):
        value = playbook.get(field)
        if value:
            lines += [f"{label}: `{value}`"]
    risk = playbook.get("risk_of_fix")
    if risk:
        lines += [
            f"Risk of applying this change: {risk}. Applying it on a live device "
            "can affect management reachability; review it before use."
        ]
    return "\n".join(lines).rstrip()


def _descriptor(rule_id: str, findings: list[Finding], vendor: str) -> dict[str, Any]:
    """One ``reportingDescriptor``. ``required: ["id"]``, everything else optional.

    `findings` are every finding sharing `rule_id` — normally one, but a device
    evaluated against two benchmarks of the same framework can produce more, so the
    benchmarks it covers are published rather than the first one winning silently.
    """
    first = findings[0]
    help_text = _help_text(first, vendor)
    benchmarks = sorted({f"{f.benchmark} {f.benchmark_version}" for f in findings})
    descriptor: dict[str, Any] = {
        "id": rule_id,
        "name": first.control_id,
        "shortDescription": {"text": first.title},
        # ``level`` here is the rule's default severity; each result restates it
        # only when it is a failure. Enum and default verified.
        "defaultConfiguration": {
            "level": SEVERITY_LEVEL.get(first.severity, DEFAULT_LEVEL)
        },
        "properties": {
            "pramanControlId": first.control_id,
            "pramanFramework": first.framework,
            "pramanBenchmarks": benchmarks,
            "pramanSeverity": first.severity,
        },
    }
    if first.remediation_ref:
        descriptor["properties"]["pramanRemediationRef"] = first.remediation_ref
    # ``helpUri`` is omitted throughout: PRAMAN ships no public documentation URL,
    # and a benchmark URL guessed from a control id would 404 on the air-gapped
    # machine this tool is built for.
    if help_text:
        descriptor["help"] = {"text": help_text}
    return descriptor


def _locations(finding: Finding, source_file: str) -> list[dict[str, Any]]:
    """`finding`'s evidence as SARIF locations — the config lines themselves.

    ``region`` is emitted only when there is a real line number, because
    ``region.startLine`` carries ``minimum: 1`` in the schema and a fact with no
    recorded span would otherwise produce an invalid document.

    The snippet is ``CanonicalFact.raw_text``, which has already been through
    ``redact_parse_result`` — SARIF's usual destination is an external
    code-scanning service, so the fact that these lines are post-redaction is a
    precondition of this function rather than a detail.
    """
    locations: list[dict[str, Any]] = []
    for fact in finding.evidence:
        uri = fact.source_file or source_file
        artifact: dict[str, Any] = {"uri": uri}
        if uri == source_file:
            # Index into ``run.artifacts``, which holds exactly the analysed
            # config. Set only when the uri really is that artifact.
            artifact["index"] = 0
        physical: dict[str, Any] = {"artifactLocation": artifact}
        if fact.line_start and fact.line_start >= 1:
            region: dict[str, Any] = {"startLine": fact.line_start}
            if fact.line_end and fact.line_end >= fact.line_start:
                region["endLine"] = fact.line_end
            if fact.raw_text:
                region["snippet"] = {"text": fact.raw_text}
            physical["region"] = region
        locations.append(
            {
                "physicalLocation": physical,
                "message": {
                    "text": f"{fact.path} = {fact.value!r} (present={fact.present})"
                },
            }
        )
    if not locations:
        # A control decided on the *absence* of a line has no line to point at. The
        # result still belongs somewhere, so it attaches to the file as a whole.
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source_file, "index": 0}
                },
                "message": {
                    "text": (
                        "No canonical fact was recorded for this control; the "
                        "verdict rests on the absence of a configuration line."
                    )
                },
            }
        )
    return locations


def _fingerprint(finding: Finding, device_id: str) -> str:
    """A stable identity for "this control, on this device", across config edits.

    Deliberately excludes the config hash. A fingerprint's job is to let a viewer
    recognise an alert it has seen before; including the config hash would mint a
    new alert on every unrelated edit and make suppressions and age tracking
    useless. Joined with ``\\x1f`` so no combination of ids can collide with a
    different one by containing the separator.
    """
    key = "\x1f".join((device_id, finding.framework, finding.benchmark, finding.control_id))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _sarif_result(
    finding: Finding,
    value: str,
    *,
    rule_id: str,
    rule_index: int,
    device_id: str,
    source_file: str,
) -> dict[str, Any]:
    """One ``result``. ``required: ["message"]``; everything else earns its place."""
    kind = RESULT_KIND[value]
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "kind": kind,
        "message": {"text": f"{finding.control_id} — {finding.title}: {finding.rationale}"},
        "locations": _locations(finding, source_file),
        "partialFingerprints": {FINGERPRINT_KEY: _fingerprint(finding, device_id)},
        "properties": {
            "pramanResult": value,
            "pramanControlId": finding.control_id,
            "pramanFramework": finding.framework,
            "pramanBenchmark": f"{finding.benchmark} {finding.benchmark_version}",
            "pramanSeverity": finding.severity,
            "pramanDeviceId": device_id,
        },
    }
    # ``level`` is only meaningful for a failure — the schema notes it is ignored
    # for other kinds, and setting it on a pass would show a green control at
    # "error" severity in any viewer that reads level first.
    if kind == "fail":
        result["level"] = SEVERITY_LEVEL.get(finding.severity, DEFAULT_LEVEL)
    return result


def _sort_key(finding: Finding) -> tuple[str, str, str, str]:
    """Total order over findings, so the output does not depend on rule-load order."""
    return (finding.framework, finding.benchmark, finding.benchmark_version, finding.control_id)


def to_sarif(
    device: dict[str, Any],
    findings: Sequence[Finding | dict[str, Any]],
) -> dict[str, Any]:
    """A SARIF v2.1.0 log for one simulated device.

    `device` is a ``Device.model_dump()`` or the equivalent ``devices`` row;
    `findings` are that device's findings, as models or as dict projections.

    An empty `findings` list is a valid document, unlike in the OSCAL export: the
    root schema puts ``minItems: 0`` on ``runs`` and ``results`` is optional, and a
    config for which no rule was applicable is a real outcome that a CI gate should
    see as "nothing to report" rather than as an error.
    """
    missing = [field for field in DEVICE_FIELDS if not device.get(field)]
    if missing:
        raise ExportError(
            "device record is missing " + ", ".join(missing) + ". SARIF locations "
            "and the run's automation id are built from these, so a partial record "
            "would produce results that point nowhere."
        )
    device_id = str(device["device_id"])
    vendor = str(device["vendor"])
    config_hash = str(device["config_hash"])
    source_file = str(device["source_file"])

    typed = sorted((as_finding(item) for item in findings), key=_sort_key)
    counts: dict[str, int] = {}
    grouped: dict[str, list[Finding]] = {}
    for finding in typed:
        value = result_value(finding)
        counts[value] = counts.get(value, 0) + 1
        if value not in OMITTED_RESULTS:
            grouped.setdefault(_rule_id(finding), []).append(finding)

    rule_ids = list(grouped)
    rules = [_descriptor(rule_id, grouped[rule_id], vendor) for rule_id in rule_ids]
    index_of = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    results = [
        _sarif_result(
            finding,
            result_value(finding),
            rule_id=_rule_id(finding),
            rule_index=index_of[_rule_id(finding)],
            device_id=device_id,
            source_file=source_file,
        )
        for finding in typed
        if result_value(finding) not in OMITTED_RESULTS
    ]

    omitted = {value: counts.get(value, 0) for value in OMITTED_RESULTS}
    run_properties: dict[str, Any] = {
        "pramanDeviceId": device_id,
        "pramanVendor": vendor,
        "pramanConfigHash": config_hash,
        "pramanFindingsTotal": len(typed),
        # Sorted so the JSON is byte-identical for identical input.
        "pramanResultCounts": {value: counts[value] for value in sorted(counts)},
        "pramanResultsOmitted": omitted,
        "pramanResultsOmittedTotal": sum(omitted.values()),
        "pramanOmissionRationale": (
            "notchecked, notselected and notapplicable results are counted here "
            "rather than emitted as SARIF results: they carry no verdict and would "
            "outnumber the actionable results by an order of magnitude in a "
            "pull-request view. pramanResultCounts sums to pramanFindingsTotal, so "
            "the omission is verifiable. The OSCAL export and the PDF report every "
            "result."
        ),
    }
    for name in ("os_family", "os_version", "hostname"):
        value = device.get(name)
        if value:
            run_properties["praman" + name.title().replace("_", "")] = str(value)

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PRAMAN",
                        "fullName": (
                            f"PRAMAN {APP_VERSION} — offline multi-vendor network "
                            "device compliance auditor"
                        ),
                        "version": APP_VERSION,
                        "semanticVersion": APP_VERSION,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": f"praman/simulate/{device_id}",
                    # A GUID over the config hash, so two runs of the same bytes
                    # are one run and an edited config is a new one. uuid5 writes
                    # the version and variant nibbles this field's pattern wants.
                    "guid": deterministic_uuid("sarif-run", device_id, config_hash),
                    "description": {
                        "text": (
                            f"Stateless compliance simulation of {source_file} for "
                            f"device '{device_id}'. No ledger record was written."
                        )
                    },
                },
                "artifacts": [
                    {
                        "location": {"uri": source_file},
                        "roles": ["analysisTarget"],
                        "mimeType": "text/plain",
                        # The config hash goes in ``properties`` and not in
                        # ``hashes``, even though its algorithm is known: PRAMAN
                        # hashes the *normalised* config bytes, so the value is not
                        # the digest of the file sitting at ``uri``. Putting it in
                        # ``hashes`` would invite a consumer to hash the file and
                        # report a mismatch that is not one.
                        "properties": {
                            "pramanConfigHash": config_hash,
                            "pramanDeviceId": device_id,
                            "pramanVendor": vendor,
                        },
                    }
                ],
                "results": results,
                "properties": run_properties,
            }
        ],
    }
