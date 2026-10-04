# Deployment

PRAMAN's application code implements no TLS, no per-request rate limiting and no
IP allowlisting, and it is not going to. `docs/SECURITY.md` §2 and §4 name those
as the reverse proxy's job; this directory holds the other half of that sentence.

| File | What it is |
|---|---|
| [`nginx/praman.conf`](nginx/praman.conf) | A complete server block: TLS 1.2 floor, HSTS, CSP, rate limits, `/docs` refused, `/health` restricted by address |
| [`ONLINE.md`](ONLINE.md) | Hosted-demo deployment using a managed Python web service, HTTPS termination, and optional persistent storage |

Nothing here is executed by the application or by the test suite's fixtures, so a
deployment that ignores it still runs. Three of its numbers are not free-floating,
though — `tests/test_deploy_config.py` asserts that the config's
`client_max_body_size` equals `MAX_UPLOAD_BYTES`, that its upstream port is the
one `scripts/serve.py` binds, and that its CSP hash matches the single inline
script in `frontend/index.html`. A proxy config that has drifted from the
application breaks only behind the proxy, which is the one environment nobody
develops in.

## The single-operator case

None of this is needed to run PRAMAN the way it is designed to be run: one
assessor, one laptop, `python scripts/serve.py`, loopback only. The proxy becomes
necessary the moment a second person needs to reach it, because that is the moment
the bearer token starts crossing a network.

## What a proxy still does not fix

- The signing key remains on the same disk as the database it signs
  (`docs/SECURITY.md` §3).
- The access log remains editable by anyone who can write to `data/praman.db`
  (§5).
- There is still no multi-tenancy: one SQLite file, no tenant column. Two
  business units under separate assessors cannot share a deployment, whatever
  sits in front of it.

## Hosted demonstrations

`ONLINE.md` describes the second, intentionally narrower profile: a managed web
service can expose the same app at a live HTTPS URL for a hackathon, while the
offline profile remains the correct place for real sensitive configurations. The
hosted profile disables optional AI inference, uses the provider's TLS, and can
use `PRAMAN_DATABASE_PATH` for a mounted SQLite volume.
