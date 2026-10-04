"""Test: the deployed proxy config must agree with the application it fronts.

Split out of :mod:`tests.test_frontend_contract`, which checked it because the
frontend is what breaks when the proxy is wrong. But the subject here is not the
frontend — it is ``deploy/nginx/praman.conf``, which restates three things the
application also decides: which inline scripts may run, how large an upload may
be, and which port to reach. All three break only *behind the proxy*, which is
the one place no developer is looking, and none of them involve reading a line
of frontend JavaScript.

Each test pins the shipped config to the thing it duplicates, so raising a limit
or moving a script fails here rather than in production.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from backend.app.config import MAX_UPLOAD_BYTES

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND = PROJECT_ROOT / "frontend"
NGINX_CONF = PROJECT_ROOT / "deploy" / "nginx" / "praman.conf"

#: Hashes are computed over the exact bytes between `<script>` and `</script>`,
#: with no `src` attribute. Matched on bytes rather than on decoded text because
#: that is what the browser hashes: a checkout that rewrote LF to CRLF would
#: change every hash, and comparing decoded text would hide it.
_INLINE_SCRIPT_RE = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL)


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
