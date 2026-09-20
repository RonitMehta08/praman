"""Drive every fixture in test_configs/ through the live /simulate API.

This is the end-to-end counterpart to the pytest suite. pytest exercises the
parser and evaluator in-process; this script goes over HTTP against a running
server, so it also covers request validation, JSON serialisation of the canonical
model, and the AI-status envelope the frontend reads. A response shape that
pydantic accepts but the browser cannot use fails here and nowhere else.

Usage:
    1. Start the backend:  python -m uvicorn backend.app.main:app --port 8000
    2. Run this script:    python scripts/run_frontend_tests.py

    Set PRAMAN_API to point at a different origin, e.g.
    PRAMAN_API=http://127.0.0.1:8012 python scripts/run_frontend_tests.py

Fixtures are discovered by walking test_configs/, so adding one is enough to have
it exercised. Add it to EXPECTATIONS as well — an unlisted fixture is still run,
but only against the generic assertions, which is how the three fixtures added
after the original five went a while without a real check.

Exit code 0 = all tests passed, 1 = failures detected.
"""
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

API = os.environ.get("PRAMAN_API", "http://127.0.0.1:8000").rstrip("/")
TEST_DIR = Path(__file__).parent.parent / "test_configs"

#: Ceiling on a single /simulate call, and a deliberately generous one.
#:
#: This exists because a latency regression already hid here once. The AI ladder
#: used to construct a fresh classifier per unparsed line, so joblib re-unpickled
#: the TF-IDF pipeline from disk every time — 1.77 s per line, which took
#: enterprise_complex (20 unparsed) to 32 s. That exceeded the request timeout,
#: so the harness reported "API call failed" and the real problem looked like a
#: broken endpoint rather than a slow one. Both numbers below are the fix: the
#: timeout is high enough that a slow response is still a response, and this
#: ceiling turns slowness into its own named failure.
#:
#: 15 s against a measured ~1.6 s is about 10x headroom, so it will not flake on a
#: slower machine or a cold first call, but it does catch a 20x regression.
MAX_SIMULATE_SECONDS = 15.0

#: Well above MAX_SIMULATE_SECONDS on purpose — see above. A timeout here reports
#: as a transport error and loses the measurement.
REQUEST_TIMEOUT_SECONDS = 120

REQUIRED_DEVICE_FIELDS = {"device_id", "vendor", "os_family", "hostname", "config_hash"}
REQUIRED_FINDING_FIELDS = {"control_id", "framework", "title", "result", "severity"}
VALID_FRAMEWORKS = {"CIS", "NIST_800_53", "DISA_STIG", "ISO_27001"}
XCCDF_RESULTS = {
    "pass", "fail", "error", "unknown", "notapplicable",
    "notchecked", "notselected", "informational", "fixed",
}

# What each fixture is for, and the property that would break if it regressed.
#
# Keys are fixture stems. Recognised expectations:
#   min_findings    — floor on the number of findings
#   has_hostname    — the device must have a non-empty hostname
#   expect_fails    — at least one FAIL (a fixture built to be non-compliant)
#   expect_passes   — at least one PASS (a fixture built to be compliant)
#   expect_mixed    — both a PASS and a FAIL/UNKNOWN
#   expect_serials  — exact device.serials, in order (C4 identity)
#   expect_hardware — substrings that must appear in device.hardware
#   max_unparsed    — ceiling on unparsed_count, guarding the pack's ignore list
EXPECTATIONS: dict[str, dict] = {
    # ── realistic/ — configs shaped like something an operator would hand over
    "enterprise_complex": {
        "min_findings": 5,
        "has_hostname": True,
        "expect_mixed": True,
    },
    "insecure_minimal": {
        "min_findings": 3,
        "expect_fails": True,
        "has_hostname": True,
    },
    "partial_compliance": {
        "min_findings": 3,
        "expect_mixed": True,
        "has_hostname": True,
    },
    "secure_baseline": {
        "min_findings": 3,
        "has_hostname": True,
        "expect_passes": True,
    },
    "telnet_exposed": {
        "min_findings": 3,
        "expect_fails": True,
        "has_hostname": True,
    },
    # ── compliance_extremes/ — the ends of the score range, so the gauge and the
    # score denominator are exercised at both bounds rather than only in the middle.
    "fully_hardened": {
        "min_findings": 5,
        "has_hostname": True,
        "expect_passes": True,
    },
    "fully_noncompliant": {
        "min_findings": 5,
        "has_hostname": True,
        "expect_fails": True,
    },
    # ── feature_coverage/ — feature-conditional controls. The point of this one is
    # that crypto and ISIS controls become applicable at all; on every other
    # fixture they are notapplicable, so their rules are never really run.
    "crypto_ipsec_isis": {
        "min_findings": 3,
        "has_hostname": True,
    },
    # ── device_identity/ — PS 26155 C4. Serial and hardware come from bundled
    # 'show version' / 'show inventory' text, not from the config, so these are the
    # only two fixtures where device.serials is non-empty. Asserted exactly:
    # a stack has one serial per member and no board serials, and the ceiling on
    # unparsed_count is what keeps ~60 lines of build metadata out of the C2
    # training queue. See tests/test_device_identity.py for the reasoning.
    "stacked_switch_with_inventory": {
        "min_findings": 3,
        "has_hostname": True,
        "expect_serials": [
            "FDO1732H0KL", "FDO1801J1AB", "FDO1902K2CD", "FDO1834M7QP",
        ],
        "expect_hardware": ["WS-C3750X-48P-S", "WS-C3750X-24P-S"],
        "max_unparsed": 8,
    },
    "router_with_show_version": {
        "min_findings": 3,
        "has_hostname": True,
        "expect_serials": ["FTX1840ALBE"],
        "expect_hardware": ["CISCO2921/K9"],
        "max_unparsed": 8,
    },
}


class TestResult:
    """Track pass/fail assertions for a single test config."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.passed: list[str] = []
        self.failed: list[str] = []

    def check(self, condition: bool, description: str) -> None:
        if condition:
            self.passed.append(description)
        else:
            self.failed.append(description)

    @property
    def ok(self) -> bool:
        return len(self.failed) == 0


def run_simulate(config_text: str, source_file: str) -> tuple[dict, float]:
    """POST /simulate and return (JSON response, elapsed seconds)."""
    payload = json.dumps({"config_text": config_text, "source_file": source_file}).encode()
    req = urllib.request.Request(
        f"{API}/simulate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        body = json.loads(resp.read().decode())
    return body, time.perf_counter() - started


def validate_config(name: str, data: dict, elapsed: float | None = None) -> TestResult:
    """Run all assertions on a /simulate response."""
    tr = TestResult(name)
    expect = EXPECTATIONS.get(name, {})

    # A fixture nobody described is a fixture nobody is really testing: it still
    # runs, but only against the generic shape assertions below, which pass for
    # any well-formed response. Naming it here is the cheap way to notice.
    tr.check(bool(expect), f"'{name}' has an entry in EXPECTATIONS")

    # ── Device fields ──────────────────────────────────────
    device = data.get("device", {})
    for field in REQUIRED_DEVICE_FIELDS:
        tr.check(field in device, f"device.{field} present")
    tr.check(bool(device.get("device_id")), "device_id is non-empty")
    tr.check(bool(device.get("config_hash")), "config_hash is non-empty")

    if expect.get("has_hostname"):
        tr.check(bool(device.get("hostname")), "hostname is non-empty")

    # ── Device identity (PS 26155 C4) ──────────────────────
    # Exact equality on serials, not containment: a superset would pass while the
    # parser also swallowed a motherboard or power-supply serial, which is the
    # regression this guards. Only the device_identity/ fixtures declare these.
    if "expect_serials" in expect:
        serials = device.get("serials") or []
        tr.check(
            serials == expect["expect_serials"],
            f"device.serials == {expect['expect_serials']} (got {serials})",
        )
    if "expect_hardware" in expect:
        hardware = device.get("hardware") or []
        for model in expect["expect_hardware"]:
            tr.check(model in hardware, f"device.hardware includes '{model}'")
        tr.check(
            len(hardware) == len(set(hardware)),
            f"device.hardware is deduplicated (got {hardware})",
        )
    else:
        # Every other fixture is config-only, and a config carries no serial. A
        # non-empty list here means something invented one, which is worse in a
        # compliance report than an empty field: it is traceable to nothing.
        tr.check(
            not (device.get("serials") or []),
            f"config-only fixture has no serials (got {device.get('serials')})",
        )

    # ── Findings ───────────────────────────────────────────
    findings = data.get("findings", [])
    min_findings = expect.get("min_findings", 1)
    tr.check(len(findings) >= min_findings, f"findings count >= {min_findings} (got {len(findings)})")

    for i, f in enumerate(findings):
        missing = REQUIRED_FINDING_FIELDS - set(f.keys())
        tr.check(not missing, f"finding[{i}] has required fields (missing: {missing or 'none'})")

        fw = f.get("framework", "")
        tr.check(fw in VALID_FRAMEWORKS, f"finding[{i}].framework '{fw}' is valid")

        result = f.get("result", "")
        if isinstance(result, dict):
            result = result.get("value", str(result))
        tr.check(str(result).lower() in XCCDF_RESULTS, f"finding[{i}].result '{result}' is XCCDF enum")

    # ── Pass/Fail expectations ─────────────────────────────
    results_list = []
    for f in findings:
        r = f.get("result", "")
        if isinstance(r, dict):
            r = r.get("value", str(r))
        results_list.append(str(r).lower())

    if expect.get("expect_fails"):
        tr.check("fail" in results_list, "at least one FAIL finding expected")

    if expect.get("expect_passes"):
        tr.check("pass" in results_list, "at least one PASS finding expected")

    if expect.get("expect_mixed"):
        tr.check("pass" in results_list, "at least one PASS in mixed config")
        tr.check("fail" in results_list or "unknown" in results_list, "at least one FAIL/UNKNOWN in mixed config")

    # ── Unparsed ceiling ───────────────────────────────────
    # Guards the pattern pack's ignore list. The device_identity fixtures bundle
    # ~30 lines of 'show version' build metadata each; every one that leaks
    # becomes an entry in the C2 training queue, which is ordered by occurrences
    # and so does not bury once-per-device noise below the real work.
    if "max_unparsed" in expect:
        unparsed = data.get("unparsed_count", 0)
        tr.check(
            unparsed <= expect["max_unparsed"],
            f"unparsed_count {unparsed} <= {expect['max_unparsed']}",
        )

    # ── Summary ────────────────────────────────────────────
    summary = data.get("summary", {})
    tr.check("total" in summary, "summary.total present")
    tr.check("by_result" in summary, "summary.by_result present")
    tr.check(summary.get("total", 0) > 0, "summary.total > 0")

    # ── AI fields (MUST exist in response) ─────────────────
    tr.check("ai_classifications" in data, "ai_classifications field present")
    tr.check("ai_status" in data, "ai_status field present")
    tr.check("unparsed_count" in data, "unparsed_count field present")

    ai_status = data.get("ai_status", {})
    tr.check("tiers" in ai_status, "ai_status.tiers present")
    tr.check("ai_backend" in ai_status, "ai_status.ai_backend present")

    tiers = ai_status.get("tiers", {})
    for tier_name in ["tier1_tfidf", "tier2_setfit", "tier3_llm"]:
        tr.check(tier_name in tiers, f"ai_status.tiers.{tier_name} present")

    ai_classifications = data.get("ai_classifications", [])
    tr.check(isinstance(ai_classifications, list), "ai_classifications is a list")

    # ── Latency ────────────────────────────────────────────
    # Asserted here rather than left to the eye because the cost scaled with the
    # number of unparsed lines, which is exactly the axis no fixture was chosen to
    # stress — so the slowest fixture was the most realistic one.
    if elapsed is not None:
        tr.check(
            elapsed <= MAX_SIMULATE_SECONDS,
            f"/simulate returned in {elapsed:.2f}s (ceiling {MAX_SIMULATE_SECONDS:.0f}s)",
        )

    return tr


def main() -> int:
    # ── Health check ───────────────────────────────────────
    print("Checking API health...\n")
    try:
        req = urllib.request.Request(f"{API}/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            health = json.loads(resp.read().decode())
        print(f"  API: {health.get('app', '?')} v{health.get('version', '?')} — OK\n")
    except Exception as e:
        print(f"  ERROR: Cannot reach API at {API} — {e}")
        print("  Start the backend first: python -m uvicorn backend.app.main:app --port 8000")
        return 1

    # ── Run each test config ───────────────────────────────
    all_results: list[TestResult] = []
    config_data: dict[str, dict] = {}
    timings: dict[str, float] = {}

    # Recursive: test_configs/ is organised into a taxonomy of category folders
    # (see test_configs/README.md), so a flat glob would find nothing.
    for conf_file in sorted(TEST_DIR.rglob("*.conf")):
        name = conf_file.stem
        text = conf_file.read_text(encoding="utf-8")

        print(f"{'=' * 60}")
        print(f"  TEST: {name}")
        print(f"{'=' * 60}")

        try:
            data, elapsed = run_simulate(text, conf_file.name)
            config_data[name] = data
            timings[name] = elapsed
            tr = validate_config(name, data, elapsed)
            all_results.append(tr)

            # Print device info
            dev = data["device"]
            summary = data.get("summary", {})
            by_result = summary.get("by_result", {})

            print(f"  Device:     {dev.get('hostname', '?')} ({dev.get('vendor', '?')} / {dev.get('os_family', '?')})")
            print(f"  Findings:   {summary.get('total', 0)} total")
            print(f"  Pass/Fail:  {by_result.get('pass', 0)} / {by_result.get('fail', 0)}")
            print(f"  Unparsed:   {data.get('unparsed_count', 0)}")
            print(f"  AI Classes: {len(data.get('ai_classifications', []))}")
            print(f"  Latency:    {elapsed:.2f}s")

            ai_tiers = data.get("ai_status", {}).get("tiers", {})
            active = sum(1 for v in ai_tiers.values() if v)
            print(f"  AI Tiers:   {active}/3 active")

            # Print assertion results
            print(f"\n  Assertions: {len(tr.passed)} passed, {len(tr.failed)} failed")
            if tr.failed:
                for msg in tr.failed:
                    print(f"    ✗ {msg}")
            print()

        except Exception as e:
            print(f"  ERROR: {e}\n")
            tr = TestResult(name)
            tr.failed.append(f"API call failed: {e}")
            all_results.append(tr)

    # ── Summary Table ──────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("  RESULTS SUMMARY")
    print(f"{'=' * 60}")
    print(f"  {'Config':<25} | {'Findings':>8} | {'Pass':>5} | {'Fail':>5} | {'Unparsed':>8} | {'Time':>7} | {'Status':>8}")
    print(f"  {'-' * 85}")

    for tr in all_results:
        data = config_data.get(tr.name, {})
        s = data.get("summary", {})
        br = s.get("by_result", {})
        status = "✓ PASS" if tr.ok else "✗ FAIL"
        secs = timings.get(tr.name)
        shown = f"{secs:.2f}s" if secs is not None else "—"
        print(f"  {tr.name:<25} | {s.get('total', 0):>8} | {br.get('pass', 0):>5} | {br.get('fail', 0):>5} | {data.get('unparsed_count', 0):>8} | {shown:>7} | {status:>8}")

    total_passed = sum(1 for tr in all_results if tr.ok)
    total_configs = len(all_results)
    total_assertions = sum(len(tr.passed) + len(tr.failed) for tr in all_results)
    total_assertion_pass = sum(len(tr.passed) for tr in all_results)

    print(f"\n  Configs: {total_passed}/{total_configs} passed")
    print(f"  Assertions: {total_assertion_pass}/{total_assertions} passed")

    # Reported together because the failure they guard against is a per-device
    # cost that only shows up at scale: a bulk upload is this number times the
    # device count, and 1.6s vs 32s per device is the difference between a
    # 50-device estate auditing in a minute and in half an hour.
    if timings:
        slowest = max(timings, key=lambda k: timings[k])
        print(
            f"  Latency: {sum(timings.values()) / len(timings):.2f}s mean, "
            f"{timings[slowest]:.2f}s worst ({slowest})"
        )

    if total_passed == total_configs:
        print("\n  ✓ ALL FRONTEND TESTS PASSED")
        return 0
    else:
        print(f"\n  ✗ {total_configs - total_passed} CONFIG(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
