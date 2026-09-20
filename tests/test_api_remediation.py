"""``GET /devices/{id}/remediation`` — the half of C4 that was only ever in the PDF.

C4 asks for "device-specific step-by-step remediation CLI". The renderer had it;
nothing else did. The UI could tell an operator that control 1.1.1 failed and had
no way to tell them what to type, because ``resolve_remediation()`` was called
from exactly one place — ``backend/report/render.py`` — and no route exposed it.
So the capability existed in the artefact that leaves the building and not in the
tool the operator actually works in.

These tests hold the route to the same bar the report is held to, which is higher
than the bar for a read endpoint: an operator *executes* this response. Three
properties get checked hardest.

**It is device-specific, not generic.** The prompt on every step must carry this
device's hostname. A plan that prints ``SW1(config)#`` is the publisher's
document, not a plan for the device in front of you.

**Nothing is presented as runnable that isn't.** A step carrying a placeholder
must say so, through the API and not merely inside the engine. This is the
property whose failure mode is an operator pasting ``<LOCAL_USERNAME>`` into a
config prompt.

**The summary agrees with the body.** ``counts`` is what the UI puts in a header
before anyone scrolls. A count that disagrees with the plan it summarises is worse
than no count, because it is trusted.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.remediation.engine import KIND_CLI, KIND_MANUAL, KIND_NONE

#: Deliberately non-compliant, so there are failures to remediate. A fixture that
#: passed everything would exercise the route and assert nothing about a plan.
FAILING_CONFIG = """\
!
version 15.0
hostname remediation-api-rtr
enable password cisco123
no aaa new-model
ip http server
line con 0
 exec-timeout 0 0
line vty 0 4
 transport input telnet
 no login authentication
snmp-server community public RO
end
"""

#: Ingested but never committed, for the no-ledger-record path.
UNCOMMITTED_CONFIG = FAILING_CONFIG.replace(
    "remediation-api-rtr", "remediation-api-uncommitted"
)


@pytest.fixture(scope="module")
def committed() -> tuple[TestClient, str, dict]:
    """A device with one committed audit, and its remediation plan."""
    client = TestClient(app)
    ingest = client.post(
        "/ingest",
        files={"file": ("remediation-api.conf", FAILING_CONFIG.encode(), "text/plain")},
    )
    assert ingest.status_code == 200, ingest.text
    device_id = ingest.json()["device_id"]

    commit = client.post("/audit/commit", json={"device_id": device_id})
    assert commit.status_code == 200, commit.text

    response = client.get(f"/devices/{device_id}/remediation")
    assert response.status_code == 200, response.text
    return client, device_id, response.json()


# ── The plan exists and is about the failures ─────────────────────────


def test_the_plan_covers_the_failures_and_nothing_else(committed) -> None:
    """Default scope is ``fail``, because that is the set that needs work.

    Returning every verdict would bury 23 actionable controls under 1,391
    ``notchecked`` ones, which is how a fix list becomes unusable.
    """
    _client, _device_id, body = committed
    assert body["plan"], "a config this bad must produce failures to remediate"
    assert {entry["result"] for entry in body["plan"]} == {"fail"}


def test_every_entry_names_the_control_it_fixes(committed) -> None:
    """A command without its control is advice; with it, it is evidence."""
    _client, _device_id, body = committed
    for entry in body["plan"]:
        assert entry["control_id"], "an unnamed control cannot be cited"
        assert entry["framework"], entry["control_id"]
        assert entry["title"], entry["control_id"]
        assert entry["severity"], entry["control_id"]


def test_the_kind_is_always_one_of_the_three(committed) -> None:
    """The tri-state, through the API.

    ``manual`` and ``none`` are answers, not failures — 47% of the corpus
    describes its fix in prose. What must never happen is a blank ``kind``, which
    a UI would render as an empty block and a reader would take for "nothing to
    do".
    """
    _client, _device_id, body = committed
    for entry in body["plan"]:
        assert entry["kind"] in {KIND_CLI, KIND_MANUAL, KIND_NONE}, entry["control_id"]
        if entry["kind"] == KIND_CLI:
            assert entry["steps"], f"{entry['control_id']} claims CLI with no steps"
        else:
            assert entry["guidance"] or entry["notes"], (
                f"{entry['control_id']} is {entry['kind']} with nothing to show"
            )


# ── Device-specific, which is the word the PS uses ────────────────────


def test_every_prompt_carries_this_devices_hostname(committed) -> None:
    """The one thing that makes this a plan rather than a citation.

    ``resolve_remediation`` rebuilds each prompt against the audited device, and
    the publishers use nineteen different stand-in hostnames. If any of those
    reach the operator, the route is echoing a PDF.
    """
    _client, _device_id, body = committed
    hostname = body["hostname"]
    assert hostname, "the device has no hostname to substitute"

    stand_ins = ("SW1(", "R1(", "hostname(", "Router(", "Switch(")
    for entry in body["plan"]:
        for step in entry["steps"]:
            assert step["prompt"].startswith(hostname), (
                f"{entry['control_id']}: prompt {step['prompt']!r} is not this device"
            )
            assert not step["prompt"].startswith(stand_ins), step["prompt"]


def test_the_command_and_the_prompt_agree(committed) -> None:
    """The prompt is the command plus context, not a second rendering of it.

    A UI shows the prompt and a copy button copies the command. If they drift, the
    operator copies something other than what they read.
    """
    _client, _device_id, body = committed
    for entry in body["plan"]:
        for step in entry["steps"]:
            assert step["command"] in step["prompt"], entry["control_id"]


# ── Nothing presented as runnable that isn't ──────────────────────────


def test_a_step_with_a_placeholder_is_not_marked_runnable(committed) -> None:
    """The property whose failure mode is a literal angle bracket in a config.

    Checked through the API rather than only in the engine, because the route
    projects the dataclass by hand and a dropped field here would be silent.
    """
    _client, _device_id, body = committed
    for entry in body["plan"]:
        for step in entry["steps"]:
            assert step["is_runnable"] == (not step["placeholders"]), (
                f"{entry['control_id']}: {step['command']!r} claims "
                f"is_runnable={step['is_runnable']} with "
                f"placeholders={step['placeholders']}"
            )


def test_substitution_is_announced_on_the_entry_not_just_the_step(committed) -> None:
    """An operator scanning entry headers must see it without expanding steps."""
    _client, _device_id, body = committed
    for entry in body["plan"]:
        expected = any(step["placeholders"] for step in entry["steps"])
        assert entry["requires_substitution"] == expected, entry["control_id"]


def test_no_leaked_publisher_markup_reaches_a_command(committed) -> None:
    """``<em>`` and ``{em}`` both leaked out of the source PDFs.

    Either one corrupts the command *and* gets counted as a placeholder, so this
    is the same defect as the test above wearing a different hat.
    """
    _client, _device_id, body = committed
    for entry in body["plan"]:
        for step in entry["steps"]:
            for tag in ("<em>", "</em>", "{em}", "{/em}"):
                assert tag not in step["command"], (
                    f"{entry['control_id']}: markup in {step['command']!r}"
                )
            assert not any("em}" in token for token in step["placeholders"]), (
                f"{entry['control_id']}: markup counted as a placeholder"
            )


# ── Provenance ────────────────────────────────────────────────────────


def test_an_actionable_entry_cites_where_its_commands_came_from(committed) -> None:
    """R3: remediation is published text or a template, never generated.

    An uncited command is indistinguishable from one a model wrote, so the
    citation is the enforcement mechanism and not decoration.
    """
    _client, _device_id, body = committed
    actionable = [entry for entry in body["plan"] if entry["is_actionable"]]
    assert actionable, "nothing actionable, so provenance was not exercised"
    for entry in actionable:
        assert entry["source"], f"{entry['control_id']} has commands with no source"


def test_risk_is_reported_rather_than_assumed(committed) -> None:
    """``unknown`` where nobody rated it. Defaulting to "low" invites a skipped
    change window on a fix CIS itself calls significantly disruptive.
    """
    _client, _device_id, body = committed
    for entry in body["plan"]:
        assert entry["risk"] in {"low", "medium", "high", "unknown"}, entry["risk"]


# ── Ordering and counts ───────────────────────────────────────────────


def test_the_plan_is_ordered_worst_first(committed) -> None:
    """A fix list read top-to-bottom should close the high-risk gaps first.

    ``control_id`` order would interleave a high-severity telnet finding with a
    low-severity banner one, and an operator working down the list would spend
    their change window on the wrong end.
    """
    _client, _device_id, body = committed
    rank = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    ranks = [rank[entry["severity"]] for entry in body["plan"]]
    assert ranks == sorted(ranks), "severities are not in worst-first order"


def test_the_counts_agree_with_the_plan_they_summarise(committed) -> None:
    """The header the UI shows before anyone scrolls."""
    _client, _device_id, body = committed
    plan, counts = body["plan"], body["counts"]

    assert counts["controls"] == len(plan)
    assert counts["cli"] == sum(1 for e in plan if e["kind"] == KIND_CLI)
    assert counts["manual"] == sum(1 for e in plan if e["kind"] == KIND_MANUAL)
    assert counts["none"] == sum(1 for e in plan if e["kind"] == KIND_NONE)
    assert counts["cli"] + counts["manual"] + counts["none"] == counts["controls"]
    assert counts["commands"] == sum(len(e["steps"]) for e in plan)
    assert counts["commands_runnable"] == sum(
        1 for e in plan for s in e["steps"] if s["is_runnable"]
    )
    assert counts["commands_runnable"] <= counts["commands"]
    assert counts["requires_substitution"] == sum(
        1 for e in plan if e["requires_substitution"]
    )


# ── Which verdicts the plan is about ──────────────────────────────────


def test_the_plan_cites_the_ledger_record_it_came_from(committed) -> None:
    """A plan and a report about the same device must name the same audit.

    Without the audit id the operator cannot tell whether they are looking at a
    fix list for the verdicts they read in the PDF or for a later re-evaluation.
    """
    _client, _device_id, body = committed
    assert body["audit_id"], "a committed device's plan must cite its audit"
    assert isinstance(body["seq"], int)
    assert body["audit_id"] in body["basis"]


def test_a_device_with_no_committed_audit_still_gets_a_plan() -> None:
    """Requiring a commit first would be friction with no integrity benefit.

    The commands come from the catalogs, not from the ledger, so nothing here
    needs a signature to be true. What the response must not do is imply the plan
    is about a committed audit — so ``audit_id`` is null and ``basis`` says which
    verdicts were used.
    """
    client = TestClient(app)
    ingest = client.post(
        "/ingest",
        files={
            "file": (
                "remediation-uncommitted.conf",
                UNCOMMITTED_CONFIG.encode(),
                "text/plain",
            )
        },
    )
    assert ingest.status_code == 200, ingest.text

    body = client.get(f"/devices/{ingest.json()['device_id']}/remediation").json()
    assert body["audit_id"] is None
    assert body["seq"] is None
    assert "no committed audit" in body["basis"]
    assert body["plan"], "an uncommitted device with failures still needs a fix list"


# ── Filters ───────────────────────────────────────────────────────────


def test_results_all_widens_the_scope(committed) -> None:
    """An operator may want the published fix for a control that passed.

    Useful as a reference — "what is the command we are already compliant with" —
    so ``all`` is supported, and must return strictly more than the default.
    """
    client, device_id, body = committed
    widened = client.get(f"/devices/{device_id}/remediation?results=all").json()
    assert widened["counts"]["controls"] > body["counts"]["controls"]
    assert len({entry["result"] for entry in widened["plan"]}) > 1


def test_control_id_narrows_to_one_entry(committed) -> None:
    """The UI's expand-one-finding interaction, which must not fetch 23 plans."""
    client, device_id, body = committed
    target = body["plan"][0]["control_id"]
    narrowed = client.get(
        f"/devices/{device_id}/remediation?control_id={target}"
    ).json()
    assert [entry["control_id"] for entry in narrowed["plan"]] == [target]
    assert narrowed["counts"]["controls"] == 1


def test_an_unknown_result_value_is_rejected_rather_than_ignored(committed) -> None:
    """Silently returning an empty plan for ``results=failed`` reads as compliant.

    The XCCDF value is ``fail``. A caller who typoes it must be told, because the
    alternative is a UI that shows "no remediation needed" for a device with 23
    failures.
    """
    client, device_id, _body = committed
    response = client.get(f"/devices/{device_id}/remediation?results=failed")
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "failed" in detail
    assert "fail" in detail, "the message must name the valid values"


def test_an_unknown_device_is_a_404(committed) -> None:
    client, _device_id, _body = committed
    response = client.get("/devices/no-such-device/remediation")
    assert response.status_code == 404
    assert "no-such-device" in response.json()["detail"]


def test_an_audit_that_is_not_this_devices_is_a_404(committed) -> None:
    """Guessing an audit id must not hand over another device's verdicts."""
    client, device_id, _body = committed
    response = client.get(
        f"/devices/{device_id}/remediation?audit_id=00000000-0000-0000-0000-000000000000"
    )
    assert response.status_code == 404


# ── The plan and the report tell the same story ───────────────────────


def test_the_plan_matches_the_pdf_for_the_same_audit(committed) -> None:
    """Two artefacts, one audit. A divergence here is the worse kind of bug.

    An operator reads the PDF, works from the UI, and has no way to notice that
    the two disagree about which controls failed. Both read the committed findings
    through ``finding_from_row``, and this asserts they still do — against the
    rendered text a reader actually sees, not against the raw bytes, whose content
    streams are compressed and would make any substring search vacuously pass.
    """
    pdfplumber = pytest.importorskip("pdfplumber")

    client, device_id, body = committed
    report = client.get(f"/devices/{device_id}/report.pdf?audit_id={body['audit_id']}")
    assert report.status_code == 200, report.text
    assert report.headers["X-PRAMAN-Audit-Id"] == body["audit_id"]

    with pdfplumber.open(BytesIO(report.content)) as pdf:
        text = "\n".join(page.extract_text() or "" for page in pdf.pages)

    # The report abbreviates long rosters, so not every id is guaranteed to be
    # printed. What must hold is that the high-severity failures the plan leads
    # with are the ones the report leads with too: a wholesale divergence between
    # the two readers of the same audit shows up immediately here.
    leading = [entry["control_id"] for entry in body["plan"][:5]]
    found = [control_id for control_id in leading if control_id in text]
    assert found == leading, (
        f"the plan's top failures {leading} are not all in the report for the same "
        f"audit; only {found} appear"
    )


def test_the_engine_is_never_asked_to_generate(committed) -> None:
    """R3 as a structural assertion, not a docstring.

    The remediation module may not import the AI package at all. A plausible but
    wrong command is worse than no command, because the operator pastes it.
    """
    source = Path("backend/remediation/engine.py").read_text(encoding="utf-8")
    for forbidden in ("backend.ai", "llama", "openai", "transformers"):
        assert forbidden not in source, f"remediation imports {forbidden}"
