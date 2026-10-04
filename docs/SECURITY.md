# Security

What PRAMAN defends against, what it does not, and which of those are decisions
versus debts.

A tool that reads network device configurations holds, by definition, a map of
the estate's weaknesses. The threat model has to be written down or the honest
version of it never gets said.

## What the tool holds

| Asset | Where | Sensitivity |
|---|---|---|
| Device configurations | `data/praman.db`, `facts` table | **High** — a list of every misconfiguration on the device |
| Findings and scores | `findings`, `audit_records` | High — an attacker's prioritised target list |
| Ledger signing key | `data/private/ed25519_signing.key` | **Critical** — forges audit provenance |
| Operator credentials | `users.password_hash` (PBKDF2, 600k iterations) | High — but not replayable; see §1 |
| Live session tokens | `sessions.token_hash` (SHA-256 of the token) | Medium — the digest cannot be presented as a credential |
| Access log | `access_log` | Medium — who examined which device, which is itself intelligence |
| Catalog content | `data/frameworks/` | Public (published benchmarks) |

The finding set is the part people underrate. A PRAMAN database is more useful
to an attacker than the configurations themselves, because it is the
configurations already sorted by exploitability.

## Hardened, with the test that says so

**Operator identity and authorisation.** Every route except four is behind a role
gate: `/health`, `POST /auth/login`, `/` and `/{asset:path}` (the static
frontend). Three ordered roles — `viewer` reads, `auditor` hands the system a
configuration, `approver` commits to the ledger and teaches parser mappings — and
the operator's name is written into `AuditRecord.actor`, which is inside
`RECORD_HASH_FIELDS` and therefore under the Ed25519 signature. Passwords are
PBKDF2-HMAC-SHA256 at 600,000 iterations with a per-user salt; sessions are
`secrets.token_urlsafe(32)` bearer tokens of which only the SHA-256 is stored,
with a 12-hour TTL and server-side revocation. There is no default account and no
bootstrap endpoint — the first operator is created out of band with
`scripts/manage_users.py`, and until one exists every protected route answers 401
naming that script. `tests/test_auth.py` asserts the gate by walking `app.routes`
rather than a hand-maintained inventory, so a new endpoint that forgets
authorisation fails the suite.

**Read auditing.** An HTTP middleware appends every API request to `access_log`
— method, path, status, duration, client, and the resolved actor — reads
included, and `GET /devices/{id}/report.pdf` in particular. Unauthenticated
attempts are logged too, with an empty actor, because a burst of those is the
signature of somebody probing the appliance. Static assets and `/health` are
excluded so the one line that matters is not buried under thousands that do not.
`GET /audit/access` exposes it to approvers only: the log answers "who looked at
the core router's findings", so a viewer-readable copy would make the reviewer's
work visible to the reviewed. Asserted in
`tests/test_api_surface.py::test_the_access_log_records_a_read_and_is_readable`
and `::test_static_assets_are_not_written_to_the_access_log`.

**Credential redaction.** `backend/ingest/redact.py` strips secrets before a
fact is stored — enable secrets, local passwords, SNMP communities, pre-shared
keys, TACACS/RADIUS keys. Redaction happens at ingest, so a secret never reaches
the database, the PDF or a log line. A new vendor pack that introduces new
credential syntax **must** add a pattern here; this is the one part of adding a
vendor that is not purely additive.

**Archive handling.** `/ingest/bulk` treats the archive as hostile: member count
(2,000), per-member uncompressed size (8 MB), total uncompressed size (512 MB)
and upload size (64 MB) are all enforced, and the total is checked against the
*declared* sizes in the central directory before any member is read — so a zip
bomb is refused for the cost of parsing a header. Member names that traverse
(`../`, absolute, drive-letter, backslash variants) are rejected even though
nothing is written to disk, because the name is stored as provenance and
rendered in the UI. Asserted in
`tests/test_api_surface.py::TestArchiveGuards`, including with a genuine
crafted archive that declares 600 MB in 127 bytes on the wire.

**Static asset traversal.** The frontend is served by name from `frontend/` only.
The candidate path is resolved and then checked with `relative_to()`, so
percent-encoding does not help. There is deliberately **no SPA catch-all**: a
fallback that returns `index.html` for every unknown path turns an API typo into
a 200 with HTML in it. Asserted in `TestStaticAssetGuards`, against markers from
inside each target file rather than against the 404 text.

**Ledger integrity.** Append-only, `prev_hash`-chained, Merkle-committed,
Ed25519-signed. `/audit/verify` re-checks five independent links per record —
Merkle root, record hash, chain link, signature, and whether the recorded actor
resolves to a principal this deployment knows — and reads the rows back from
SQLite rather than trusting the writing process. Tampering with record *n*
invalidates every record after it. The actor check is tri-state: it can only
contribute a pass or a not-known, never silently succeed, so a record naming an
unknown operator makes the standalone verifier report INCOMPLETE and exit 2
instead of reporting a pass.

**Encoding confusion.** Configurations are decoded through
`("utf-8-sig", "utf-8", "cp1252", "latin-1")` and then NFKC-normalised, so two
visually identical commands hash identically and cannot be used to smuggle a
duplicate device past the config-hash dedup.

**Determinism.** The same bytes produce the same findings — asserted, not
assumed. A compliance tool whose output varies between runs cannot be used as
evidence.

## Not hardened — the honest list

### 1. Identity exists; these parts of it do not

The framing that drove the design stands, and is now met: *a ledger that proves
what was decided but not who decided it is only half an audit trail.* Every
protected route resolves an authenticated operator, authorisation separates who
may upload from who may commit, and the operator's name is inside the signed
record. What is **not** built:

- **No TLS**, so the bearer token crosses the network in clear text on any
  deployment that is not loopback. This is the one that makes the rest
  conditional, and it is §2 below. Until a proxy terminates TLS, treat
  `HOST=0.0.0.0` as equivalent to publishing the token.
- **No per-request rate limiter.** `POST /auth/login` has a per-username,
  in-process lockout (10 failures, 900 s) on top of a 0.209 s key derivation,
  which makes online password guessing pointless. It is not a rate limiter, it is
  cleared by a restart, and each worker would hold its own copy. §4 below.
- **No MFA, no password expiry, no SSO/LDAP/OIDC.** A single factor, rotated by
  an administrator running `scripts/manage_users.py passwd`. For a tool whose own
  rule packs fail devices for single-factor administrative access, that is worth
  stating plainly rather than leaving to be noticed.
- **No self-service anything.** No registration, no password reset, no admin UI.
  Every account operation needs filesystem access to the deployment. That is a
  deliberate trade — it makes taking privilege require more than an HTTP path —
  but it means a locked-out operator waits for somebody with a shell.
- **Session storage is a table in the same SQLite file as the findings.** An
  attacker with read access to `data/praman.db` gets the estate's findings, which
  is worse than the sessions; the token digests specifically are not replayable.

**Mitigation today:** `scripts/serve.py` binds `127.0.0.1` by default and prints
a warning when `HOST=0.0.0.0` is set. With identity in place that is no longer
the only control, but it is still the reason the missing TLS has not yet been
exploitable.

A hardcoded credential would have been worse than the visible absence this
section used to describe, and an open bootstrap route is the same mistake wearing
a different hat. Neither was added: the first operator is created out of band, and
`POST /auth/login` answers 503 while none exists, naming
`scripts/manage_users.py` and MANUAL_COMMANDS.md Step 13 in the detail.

### 2. Transport is plain HTTP

No TLS in the application, and there will not be. Configurations, findings and the
bearer token itself cross the network in clear text on anything but loopback.

`deploy/nginx/praman.conf` is the configuration rather than an implementation —
TLS 1.2 floor, HSTS, a CSP that matches what the frontend actually loads, the
per-request rate limiter §4 lists as missing, `/docs` refused, `/health`
restricted by address, and `client_max_body_size` pinned to `MAX_UPLOAD_BYTES`.
Three of those numbers are asserted against the application by
`tests/test_deploy_config.py`, because a proxy config that has drifted from
the app breaks only in the one environment nobody develops in.

Two details in it are easy to get wrong and are worth repeating here:

- **The upstream must stay on loopback.** If nginx terminates TLS while uvicorn
  also listens on `0.0.0.0:8012`, an attacker talks to 8012 directly and the proxy
  has bought nothing. `scripts/serve.py` binds `127.0.0.1` by default for this
  reason and warns when `HOST=0.0.0.0` overrides it.
- **The proxy adds `Secure` to the session cookie**
  (`proxy_cookie_flags praman_session httponly secure samesite=strict`, nginx
  1.19.3+). The application deliberately does not set that flag: it cannot know
  whether it is behind TLS, and a `Secure` cookie sent over plain HTTP to a LAN
  address is dropped silently by the browser — which would break PDF downloads
  with no error visible anywhere. The component that knows the answer sets it.

### 3. The signing key is a local file

`data/private/ed25519_signing.key` sits on the same disk as the database it
signs. An attacker with filesystem access can rewrite history and re-sign it, and
`/audit/verify` will report the forged chain as valid — this is inherent to
holding both halves in one place. Real non-repudiation needs the key somewhere
the application cannot read at rest (HSM, KMS, or an external timestamping
authority). What the current design *does* buy is detection of tampering by
anyone without key access, which covers the accidental and the semi-privileged
cases.

Absence is handled honestly: with no key, reports are still produced and
`X-PRAMAN-Signature` says `unsigned`. It never silently claims a signature it
does not have.

### 4. No rate limiting, no request size accounting beyond upload limits

A single authenticated client can drive CPU with repeated large uploads. Single-process and
synchronous, so this is a denial of service against a tool, not a path to data.
The login lockout in §1 is the only throttle anywhere in the app and covers one
route; it is not this. A reverse proxy is the right place for the general case,
which is another reason §2's proxy is not optional in a real deployment.

### 5. The access log is a log, not evidence

Reads are now recorded — see *Read auditing* above — which closes the gap this
section used to describe. What the `access_log` table is not:

- **Not tamper-evident.** No hash chain, no signature. Anyone who can write to
  `data/praman.db` can edit or truncate it, unlike the ledger sitting in the same
  file. Chaining it was considered and not done: the log takes a row per request,
  and a chain over that volume buys detection of an attacker who already has write
  access to the database the log is trying to protect.
- **Not exported.** No syslog, no SIEM egress, no append-only sink outside the
  application. A log that only exists on the box being audited is a log the box's
  owner controls.
- **Unbounded, with no retention policy.** It grows for the life of the
  deployment; nothing rotates or prunes it.
- **Best-effort.** A write failure is swallowed, deliberately: the response has
  already been produced, and turning a full table into a 500 would deny service
  to protect an audit trail. So the log records what it could, not provably
  everything that happened.

### 6. LLM tier prompt injection

The tier-3 classifier is a local quantised model reading **configuration text**,
which is attacker-influenced input. Its output is constrained to a canonical path
suggestion and is **always confirmed by a human** in the Training GUI before it
affects parsing, so the blast radius is a bad suggestion rather than a bad
verdict. The abstention-over-guessing design is what keeps this true; an
auto-accept mode would remove the control entirely and should not be added
without a schema-constrained decoder and a review queue.

## Reporting

Pre-production research project. No production deployments, so no disclosure
process. Findings against the tool itself belong in the issue tracker alongside
`docs/GAPS.md`, which is the equivalent document for compliance coverage.
