"""Test: the frontend's assumptions about the backend must hold.

`frontend/js/views/dashboard.js` names this file as the guard on the one piece of
backend arithmetic the frontend reimplements. It grew to cover the rest of the
contract, because the frontend is a separate artefact in a language the Python
test suite otherwise never reads, and every assumption it makes is invisible to
`pytest` until a user hits it.

Four classes of assumption are checked:

  * **Arithmetic.** `scoreFromSummary()` in the dashboard recomputes the score
    from a ledger row's stored summary, because re-reading every past audit's
    findings to plot a trend would be a table scan per point. Two implementations
    of one number is exactly the drift R9.1 exists to prevent.
  * **Routes.** Every path `api.js` calls must exist on the app with the method it
    uses. A renamed route is a 404 the frontend reports as "Request failed", and
    nothing in the Python suite notices.
  * **Vocabulary.** Result and severity values the frontend switches on must be
    values the backend can actually emit.
  * **Deployment.** `deploy/nginx/praman.conf` restates three things the
    application also decides — the upload limit, the port, and which inline
    scripts exist. All three break only behind the proxy, which is the one place
    no developer is looking.

The score check is a port, not a re-derivation: the JS body is extracted from the
source file and its behaviour asserted against `score_from_counts` over a table
of cases including the ones that decide the design — an empty denominator, and
counts where the excluded results dominate.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import MAX_UPLOAD_BYTES
from backend.app.main import app
from backend.canonical.findings import Result
from backend.frameworks.catalog import load_catalogs
from backend.rules.evaluator import DEFAULT_SEVERITY, SCORE_BASIS, score_from_counts

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND = PROJECT_ROOT / "frontend"
API_JS = FRONTEND / "js" / "api.js"
DASHBOARD_JS = FRONTEND / "js" / "views" / "dashboard.js"


# ── The score the frontend recomputes ────────────────────────────────────


def _score_from_summary_js(summary: dict) -> float | None:
    """A faithful transcription of `scoreFromSummary` in dashboard.js.

    Kept beside a test that asserts the real source still says this, so the
    transcription cannot quietly go stale.
    """
    by_result = summary.get("by_result") or {}
    passed = float(by_result.get("pass") or 0)
    failed = float(by_result.get("fail") or 0)
    if passed + failed == 0:
        return None
    return (passed / (passed + failed)) * 100


def test_dashboard_score_source_is_unchanged() -> None:
    """The JS still computes what the transcription above says it does.

    Whitespace-insensitive, so reformatting does not fail the build; any change to
    the operands or the guard does.
    """
    source = DASHBOARD_JS.read_text(encoding="utf-8")
    match = re.search(r"function scoreFromSummary\(summary\)\s*\{(.*?)\n\}", source, re.DOTALL)
    assert match, "dashboard.js no longer defines scoreFromSummary()"
    body = re.sub(r"\s+", " ", match.group(1)).strip()
    expected = (
        "const byResult = summary?.by_result || {}; "
        "const passed = Number(byResult.pass || 0); "
        "const failed = Number(byResult.fail || 0); "
        "if (passed + failed === 0) return null; "
        "return (passed / (passed + failed)) * 100;"
    )
    assert body == expected, (
        "scoreFromSummary() has changed. Update the transcription in this test "
        "and re-check it against backend.rules.evaluator.score_from_counts.\n"
        f"  now: {body}"
    )


# Cases chosen for what they decide, not for coverage. The excluded-results rows
# are the ones that would differ under any other definition of the score.
SCORE_CASES = [
    pytest.param({"pass": 7, "fail": 45}, id="the live sample fixture"),
    pytest.param({"pass": 0, "fail": 0}, id="nothing decided"),
    pytest.param({"pass": 3, "fail": 0}, id="all pass"),
    pytest.param({"pass": 0, "fail": 3}, id="all fail"),
    pytest.param({"pass": 1, "fail": 2, "notchecked": 1391}, id="notchecked dominates"),
    pytest.param({"pass": 1, "fail": 1, "notapplicable": 18, "unknown": 1}, id="excluded results"),
    pytest.param({"notchecked": 40}, id="nothing but coverage states"),
    pytest.param({"pass": 1, "fail": 2}, id="a repeating decimal"),
]


@pytest.mark.parametrize("counts", SCORE_CASES)
def test_frontend_score_matches_backend(counts: dict[str, int]) -> None:
    """Same inputs, same number — to the one decimal place the backend rounds to.

    The two implementations legitimately differ in how they say "no score": the
    backend returns `0.0` because its callers put the value straight into a
    report, the frontend returns `null` because a gauge showing 0% for "we have
    not decided anything yet" would be a lie. The rounding also differs — the
    frontend rounds at the point of display. What must not differ is the value.
    """
    backend_score = score_from_counts(counts)
    frontend_score = _score_from_summary_js({"by_result": counts})

    decided = counts.get("pass", 0) + counts.get("fail", 0)
    if decided == 0:
        assert frontend_score is None, "the gauge must show 'no score', not 0%"
        assert backend_score == 0.0
        return

    assert frontend_score is not None
    assert round(frontend_score, 1) == backend_score


def test_score_basis_is_stated_in_the_ui() -> None:
    """The sentence that defines the score must appear where the score appears.

    `SCORE_BASIS` says the ratio excludes notchecked, notapplicable and unknown.
    A compliance score is a PRAMAN convention rather than a published metric, so
    a number shown without that sentence is a number a reader will assume means
    something standard.
    """
    haystack = "\n".join(
        path.read_text(encoding="utf-8")
        for path in FRONTEND.rglob("*.js")
    )
    # Not a substring match on the whole sentence — it is wrapped for display —
    # but the two claims that make it honest must both be on screen.
    assert "pass / (pass + fail)" in haystack, (
        f"no UI text states the score formula; the backend's is: {SCORE_BASIS}"
    )
    for excluded in ("notchecked", "notapplicable"):
        assert excluded in haystack, f"the UI never mentions that {excluded} is excluded"


# ── Routes the frontend calls ────────────────────────────────────────────


def _declared_routes() -> set[tuple[str, str]]:
    """`(method, path)` for every route the app serves."""
    declared = set()
    for route in app.routes:
        for method in getattr(route, "methods", None) or []:
            declared.add((method, getattr(route, "path", "")))
    return declared


def _called_paths() -> list[tuple[str, str]]:
    """`(method, path-template)` for every call site in api.js.

    Template literals are normalised back to a FastAPI-style path parameter, so
    `/devices/${encodeURIComponent(deviceId)}` compares against
    `/devices/{device_id}`. Query strings are stripped — `query()` builds those
    and a route does not declare them.
    """
    source = API_JS.read_text(encoding="utf-8")
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)

    calls: list[tuple[str, str]] = []
    for helper, method in (("getJson", "GET"), ("postJson", "POST")):
        for raw in re.findall(rf"{helper}\(\s*[`']([^`']+)[`']", source):
            calls.append((method, raw))
    # `request()` is used directly for the two multipart uploads.
    for raw, opts in re.findall(r"request\(\s*'([^']+)'\s*,\s*\{([^}]*)\}", source):
        match = re.search(r"method:\s*'(\w+)'", opts)
        calls.append((match.group(1) if match else "GET", raw))

    normalised = []
    for method, raw in calls:
        # `${query(opts)}` interpolates a query string, not a path segment; a route
        # does not declare its query parameters in its path.
        path = re.sub(r"\$\{query\([^}]*\)\}", "", raw)
        path = re.sub(r"\$\{[^}]*\}", "{param}", path)
        path = path.split("?")[0].rstrip("/") or "/"
        normalised.append((method, path))
    return normalised


def _matches(called: str, declared: str) -> bool:
    """Path-template equality, treating any parameter name as equal."""
    normalise = lambda p: re.sub(r"\{[^}]*\}", "{param}", p).rstrip("/") or "/"  # noqa: E731
    return normalise(called) == normalise(declared)


def test_every_frontend_call_hits_a_real_route() -> None:
    """No call site points at a path the app does not serve.

    The failure mode this catches is a renamed route: the frontend reports it as
    "Request failed (HTTP 404)" from a screen nobody re-tests, and the Python
    suite is entirely happy.
    """
    declared = _declared_routes()
    missing = []
    for method, path in _called_paths():
        if not any(m == method and _matches(path, p) for m, p in declared):
            missing.append(f"{method} {path}")
    assert not missing, f"api.js calls routes that do not exist: {sorted(set(missing))}"


def test_api_client_calls_no_absolute_url() -> None:
    """Every request is same-origin and relative.

    The previous client hardcoded `http://127.0.0.1:8000`, so opening the UI on
    any other host or port broke every screen and made every request needlessly
    cross-origin. The backend serves this page itself; there is nothing to
    configure and nothing that should look configurable.
    """
    source = API_JS.read_text(encoding="utf-8")
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", "", source)
    absolute = re.findall(r"https?://[^\s'\"`)]+", source)
    assert not absolute, f"api.js contains an absolute URL: {absolute}"


def test_pdf_and_export_are_hrefs_not_fetches() -> None:
    """The two binary/bulk downloads are built as URLs for the browser to follow.

    Fetching a multi-megabyte signed PDF into a blob to trigger the same download
    buffers the whole report in memory and loses the download shelf.
    """
    source = API_JS.read_text(encoding="utf-8")
    for name in ("reportUrl", "trainingExportUrl"):
        match = re.search(rf"export const {name} = [^;]+;", source, re.DOTALL)
        assert match, f"api.js no longer exports {name}"
        assert "getJson" not in match.group(0) and "request(" not in match.group(0), (
            f"{name} should build a URL, not perform a request"
        )


# ── Vocabulary the frontend switches on ──────────────────────────────────


def test_frontend_result_vocabulary_is_the_backend_vocabulary() -> None:
    """Result strings the UI names must be values `Result` can hold.

    Checked against the palette's key set, which the drift test already pins to
    the enum — so this is really asserting that the *views* have not invented a
    tenth value like "warning" that would silently fall through to grey.
    """
    from tests.test_frontend_palette import _js_literal, _strip_comments

    palette_js = _strip_comments((FRONTEND / "js" / "palette.js").read_text(encoding="utf-8"))
    order = _js_literal("RESULT_ORDER", palette_js)
    assert set(order) == {member.value for member in Result}


def test_frontend_severity_vocabulary_matches_the_evaluator() -> None:
    """The UI orders severities worst-first over the evaluator's folded set.

    `evaluator.py` folds CAT I/II/III and critical/important/informational down to
    high/medium/low and uses `unknown` for unrated. A UI listing `critical` would
    be listing a bucket no finding is ever in.
    """
    from tests.test_frontend_palette import _js_literal, _strip_comments

    palette_js = _strip_comments((FRONTEND / "js" / "palette.js").read_text(encoding="utf-8"))
    assert _js_literal("SEVERITY_ORDER", palette_js) == [
        "high",
        "medium",
        "low",
        DEFAULT_SEVERITY,
    ]


def test_every_cis_benchmark_section_has_a_name_in_the_heatmap_axis() -> None:
    """`BENCHMARK_SECTIONS` must name every section the loaded catalogs can reach.

    The heatmap's family axis is the only place in the UI that says what a group of
    controls *is*, and `controlFamily` falls back to a bare `CIS 4` for anything
    unnamed. The fallback is deliberate — an invented name would be worse than a
    number — but it is also silent, so without this test a new benchmark ships with
    an axis of numbers and nobody finds out from a red run.

    Keyed on the benchmark, not the section number, because that distinction is the
    bug this test was written after. A flat section map was correct while Cisco IOS
    was the only mapped benchmark and false as soon as six more shipped: CIS Palo
    Alto section 3 is High Availability and CIS FortiGate section 1 is DNS and
    WAN-side service exposure, both of which were rendering under a column headed
    "Data plane". A wrong label on a compliance chart is worse than no label,
    because the reader has no way to tell it is wrong.

    Only CIS is checked. DISA ids carry no hierarchy and group under their
    framework, and NIST/ISO are projected rather than evaluated.
    """
    from tests.test_frontend_palette import _strip_comments

    source = _strip_comments((FRONTEND / "js" / "charts.js").read_text(encoding="utf-8"))
    start = source.index("const BENCHMARK_SECTIONS")
    body = source[start : source.index("\n};", start)]

    # Parsed with a regex rather than by executing the JS: the whole point is to
    # read what ships, and a test that evaluated the file could pass against a
    # definition the browser never sees.
    named: dict[str, set[str]] = {}
    for block in re.finditer(
        r"'([^']+)':\s*\{\s*short:\s*'[^']*',\s*sections:\s*\{([^}]*)\}", body
    ):
        named[block.group(1)] = set(re.findall(r"(\d+)\s*:", block.group(2)))

    assert named, "BENCHMARK_SECTIONS parsed as empty, so this test proves nothing"

    missing: list[str] = []
    for catalog in load_catalogs():
        if catalog.framework != "CIS":
            continue
        sections = {c.control_id.split(".")[0] for c in catalog.controls}
        if catalog.benchmark not in named:
            missing.append(f"{catalog.benchmark}: whole benchmark, sections {sorted(sections)}")
            continue
        gap = sections - named[catalog.benchmark]
        if gap:
            missing.append(f"{catalog.benchmark}: sections {sorted(gap)}")

    assert not missing, (
        "the heatmap axis would render a bare section number for:\n  "
        + "\n  ".join(missing)
        + "\nAdd the name to BENCHMARK_SECTIONS in frontend/js/charts.js, derived "
        "from the titles of the controls that section actually contains."
    )


# ── The page the server actually serves ──────────────────────────────────


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def test_index_references_only_assets_that_exist(client: TestClient) -> None:
    """Every local asset `index.html` names is served.

    A 404 on the stylesheet renders the app unstyled but working, which is the
    kind of break that survives a demo and is noticed by the audience.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:href|src)="(/[^"]+)"', html)
    assert refs, "index.html references no local assets — has it been replaced?"
    for ref in refs:
        response = client.get(ref)
        assert response.status_code == 200, f"{ref} → HTTP {response.status_code}"


def test_frontend_loads_nothing_from_another_origin() -> None:
    """Offline-first, enforced rather than intended.

    PRAMAN is expected to run on air-gapped estates. A CDN font or script does
    not fail fast there — it hangs until the request times out, blocking first
    paint. The previous `index.html` preconnected to two Google origins.
    """
    # Two URL-shaped strings are not fetches and must not be flagged.
    #   * `http://www.w3.org/2000/svg` is the SVG namespace *identifier* passed to
    #     `createElementNS`. It is compared, never requested; changing it would
    #     break every chart.
    #   * `http://127.0.0.1:8000/` appears inside the boot watchdog's error text,
    #     as prose telling a user who opened the page over `file://` what to type.
    allowed = {"http://www.w3.org/2000/svg", "http://127.0.0.1:8000/"}

    offenders = []
    for path in list(FRONTEND.rglob("*.js")) + list(FRONTEND.rglob("*.css")) + [
        FRONTEND / "index.html"
    ]:
        text = path.read_text(encoding="utf-8")
        # Comments in these files discuss the CDN problem by name, so strip them
        # before looking for an actual reference.
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        text = re.sub(r"^\s*//[^\n]*", "", text, flags=re.MULTILINE)
        for url in re.findall(r"https?://[^\s'\"`)>]+", text):
            if url.rstrip(".,") in allowed:
                continue
            offenders.append(f"{path.relative_to(PROJECT_ROOT)} → {url}")
    assert not offenders, f"frontend loads from another origin: {offenders}"


def test_no_absolute_url_in_a_loading_position() -> None:
    """The same property again, by syntax rather than by allowlist.

    The check above can be defeated by adding a URL to its allowlist without
    thinking. This one cannot: it looks only at the positions a browser actually
    fetches from — `href`, `src`, `url()`, an `@import`, a bare `import … from`,
    and `fetch()` — and no entry in that list has a legitimate absolute URL in an
    offline-first application.
    """
    patterns = [
        r'(?:href|src)\s*=\s*["\']https?://',
        r"url\(\s*['\"]?https?://",
        r"@import\s+['\"]https?://",
        r"from\s+['\"]https?://",
        r"fetch\(\s*['\"`]https?://",
    ]
    offenders = []
    for path in list(FRONTEND.rglob("*.js")) + list(FRONTEND.rglob("*.css")) + [
        FRONTEND / "index.html"
    ]:
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            for hit in re.findall(pattern, text):
                offenders.append(f"{path.relative_to(PROJECT_ROOT)} → {hit}")
    assert not offenders, f"cross-origin resource reference: {offenders}"


def test_no_reference_to_the_retired_dashboard_files() -> None:
    """`dashboard.css` and the old top-level `dashboard.js` are gone.

    Their replacement lives at `js/views/dashboard.js`. A stale `<script>` tag
    pointing at the deleted path is a 404 the browser reports only in the console.
    """
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert not re.search(r'["\'/]dashboard\.(js|css)', html)
    assert not (FRONTEND / "dashboard.js").exists()
    assert not (FRONTEND / "dashboard.css").exists()


# ── Text the operator actually reads ─────────────────────────────────────


def _view_sources() -> list[Path]:
    """Every frontend module, views and shared alike."""
    return sorted((FRONTEND / "js").rglob("*.js"))


def test_no_count_is_rendered_as_thing_parenthesis_s() -> None:
    """`10 device(s)` is not a plural, it is a note to the reader that nobody looked.

    Every count in this UI once read that way — `1 vendor(s)`, `42 catalog(s)`,
    `1 record(s), hashes, links, Merkle roots and signatures all check out`. It is
    a small thing repeated on every screen, which is most of what "feels rough"
    is made of. `dom.js:count()` and `dom.js:agree()` replaced all 23 sites.

    `dom.js` itself is exempt because its docstrings quote the old form to explain
    what the helpers are for, and an arrow-function parameter named `s` is not a
    plural.
    """
    offenders = []
    for path in _view_sources():
        if path.name == "dom.js":
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\(s\)", text):
            # `filter((s) => ...)` — a parameter list, not a noun.
            if "((s)" in text[max(0, match.start() - 4) : match.end()]:
                continue
            line = text[: match.start()].count("\n") + 1
            offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{line}")

    assert not offenders, (
        f"count rendered as 'thing(s)' at {offenders}. Use count(n, 'thing') from "
        f"dom.js, and agree(n, ...) for any verb or pronoun downstream of it."
    )


def test_every_helper_a_view_calls_is_imported() -> None:
    """A missing named import is a `ReferenceError` at render time, not at load.

    ES modules resolve names lazily inside function bodies, so a view that calls
    `count()` without importing it loads fine, passes every static check, and
    throws only when a user opens that screen — and only on the branch that builds
    that particular hint. Two views shipped in exactly that state while this was
    being written, which is why it is a test rather than a habit.
    """
    helpers = ("count", "agree", "pluralise", "num", "pct", "when", "shortHash")
    offenders = []
    for path in _view_sources():
        if path.name == "dom.js":
            continue
        text = path.read_text(encoding="utf-8")
        imported = " ".join(re.findall(r"import \{([^}]*)\} from", text, re.S))
        for helper in helpers:
            called = re.search(rf"(?<![\w.]){helper}\(", text)
            if called and not re.search(rf"\b{helper}\b", imported):
                line = text[: called.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{line} calls {helper}()")

    assert not offenders, f"helper called without being imported: {offenders}"


def test_no_frontend_source_contains_a_raw_control_byte() -> None:
    """A literal NUL in a `.js` file makes it binary to every text tool.

    `topology.js` used one as a join delimiter — `[a, b].sort().join('\\0')` —
    written as the byte rather than the escape. The delimiter choice is right, but
    the encoding meant `grep`, `git diff` and this file's own checks all reported
    the file as binary and skipped its contents, which is how three `device(s)`
    strings in it survived a project-wide sweep that found the other twenty.
    """
    offenders = []
    for path in [*_view_sources(), FRONTEND / "index.html", FRONTEND / "app.css"]:
        raw = path.read_bytes()
        bad = {byte for byte in raw if byte < 0x09 or 0x0E <= byte < 0x20}
        if bad:
            offenders.append(
                f"{path.relative_to(PROJECT_ROOT)} contains {sorted(hex(b) for b in bad)}"
            )

    assert not offenders, (
        f"raw control byte in a source file: {offenders}. Write it as an escape "
        f"(\\u0000) so the file stays text and tools can read it."
    )



# ── The deployed Content-Security-Policy ─────────────────────────────────


#: Hashes are computed over the exact bytes between `<script>` and `</script>`,
#: with no `src` attribute. Matched on bytes rather than on decoded text because
#: that is what the browser hashes: a checkout that rewrote LF to CRLF would
#: change every hash, and comparing decoded text would hide it.
_INLINE_SCRIPT_RE = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL)

NGINX_CONF = PROJECT_ROOT / "deploy" / "nginx" / "praman.conf"


def _inline_script_hashes() -> list[str]:
    raw = (FRONTEND / "index.html").read_bytes()
    return [
        "sha256-" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        for body in _INLINE_SCRIPT_RE.findall(raw)
    ]


def test_the_deployed_csp_lists_exactly_the_inline_scripts_that_exist() -> None:
    """A CSP hash that has gone stale breaks the page only in production.

    `deploy/nginx/praman.conf` ships `script-src 'self' 'sha256-…'` rather than
    `unsafe-inline`, and a browser ignores `unsafe-inline` once any hash is
    present — so a stale hash is not a degraded policy, it is a script that
    silently stops running behind the proxy while every developer machine, which
    has no proxy, looks fine. Recomputing it here is what makes shipping a hash a
    reasonable thing to do.

    Both directions are asserted. A missing hash is the break above; an extra one
    is a hash left behind by an edit, which quietly re-permits a script nobody is
    still reviewing.
    """
    conf = NGINX_CONF.read_text(encoding="utf-8")
    listed = set(re.findall(r"'(sha256-[A-Za-z0-9+/=]+)'", conf))
    actual = set(_inline_script_hashes())

    assert actual, (
        "index.html has no inline script. If the boot watchdog was moved to a "
        "file, drop the hash from the CSP in deploy/nginx/praman.conf and delete "
        "this test — do not leave an unused hash in a shipped policy."
    )
    missing = actual - listed
    assert not missing, (
        f"inline script in index.html is not permitted by the deployed CSP: "
        f"{sorted(missing)}. Add it to script-src in "
        f"{NGINX_CONF.relative_to(PROJECT_ROOT)}, or move the script to a file "
        f"under frontend/js/ so 'self' covers it."
    )
    stale = listed - actual
    assert not stale, (
        f"the deployed CSP permits an inline script that no longer exists: "
        f"{sorted(stale)}. Remove it from "
        f"{NGINX_CONF.relative_to(PROJECT_ROOT)}."
    )


def test_the_deployed_csp_does_not_undo_itself() -> None:
    """`unsafe-inline` and `unsafe-eval` must not appear in the shipped policy.

    The first is ignored by a browser when a hash is present, so its only effect
    would be to make the policy read as permissive to a reviewer while behaving
    strictly — or, if the hashes were ever removed, to become live silently. The
    second has no legitimate use here: `dom.js` refuses to set `innerHTML` and
    nothing in the frontend calls `eval` or `new Function`.
    """
    conf = NGINX_CONF.read_text(encoding="utf-8")
    policy = "".join(
        line for line in conf.splitlines() if "Content-Security-Policy" in line
    )
    # The directive is a multi-line continuation, so scan the whole file for the
    # tokens rather than one line of it.
    for token in ("'unsafe-inline'", "'unsafe-eval'"):
        assert token not in conf, (
            f"{token} appears in {NGINX_CONF.relative_to(PROJECT_ROOT)}. See "
            "test_the_deployed_csp_lists_exactly_the_inline_scripts_that_exist "
            "for why a hash is used instead."
        )
    assert policy, "no Content-Security-Policy header in the shipped nginx config"


def test_the_client_upload_limit_matches_the_application_limit() -> None:
    """`client_max_body_size` smaller than MAX_UPLOAD_BYTES refuses a legal upload.

    And larger makes the proxy's limit decorative. Either way the operator sees a
    413 from a component that cannot tell them which limit they hit, so the two
    numbers are pinned to each other here.
    """
    conf = NGINX_CONF.read_text(encoding="utf-8")
    match = re.search(r"client_max_body_size\s+(\d+)m\s*;", conf)
    assert match, "deploy/nginx/praman.conf sets no client_max_body_size"
    assert int(match.group(1)) * 1024 * 1024 == MAX_UPLOAD_BYTES, (
        f"nginx accepts {match.group(1)} MiB but the application accepts "
        f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MiB (MAX_UPLOAD_BYTES in "
        "backend/app/config.py). Keep them equal."
    )


def test_the_proxy_points_at_the_port_the_launcher_binds() -> None:
    """A proxy aimed at the wrong port is a 502 with nothing wrong anywhere else."""
    conf = NGINX_CONF.read_text(encoding="utf-8")
    serve = (PROJECT_ROOT / "scripts" / "serve.py").read_text(encoding="utf-8")
    default_port = re.search(r'os\.environ\.get\("PORT",\s*"(\d+)"\)', serve)
    assert default_port, "scripts/serve.py no longer has a literal default port"
    assert f"server 127.0.0.1:{default_port.group(1)};" in conf, (
        f"deploy/nginx/praman.conf does not proxy to 127.0.0.1:"
        f"{default_port.group(1)}, which is what scripts/serve.py binds by default."
    )
