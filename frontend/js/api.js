/**
 * The API surface, as functions.
 *
 * Two things this fixes about the old client. It hardcoded
 * `const API_BASE = 'http://127.0.0.1:8000'` even though the backend serves this
 * page itself — so opening the UI on any other host or port broke every request,
 * and every request was cross-origin for no reason. And it reported failures with
 * `alert()`, which threw away the `detail` string FastAPI sends. The new
 * remediation route returns a 400 whose detail names the valid values; losing that
 * turns a fixable mistake into a mystery.
 *
 * Requests are same-origin and relative. The backend declares its asset routes
 * last precisely so nothing shadows an API path, so a relative fetch is both
 * correct and one less thing to configure.
 */

/** An HTTP failure with the server's own explanation attached. */
export class ApiError extends Error {
  constructor(status, detail, path) {
    super(detail || `${path} failed with HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
    this.path = path;
  }
}

/** The network never reached the server — a different problem from a 4xx, and one
 * that usually means the backend is not running. Worth saying so explicitly
 * rather than showing "Failed to fetch". */
export class OfflineError extends Error {
  constructor(path, cause) {
    super(`Could not reach the PRAMAN backend (${path}). Is uvicorn running?`);
    this.name = 'OfflineError';
    this.path = path;
    this.cause = cause;
  }
}

async function readDetail(response, path) {
  // FastAPI sends {"detail": ...}; a crash inside a route may send HTML. Try the
  // structured form, fall back to text, never let the parse failure mask the
  // status code the caller needs.
  let detail = '';
  try {
    const body = await response.json();
    detail = typeof body?.detail === 'string' ? body.detail : JSON.stringify(body?.detail ?? body);
  } catch {
    try {
      detail = (await response.text()).slice(0, 600);
    } catch {
      detail = '';
    }
  }
  return new ApiError(response.status, detail, path);
}

/**
 * The bearer token for every request, held in one variable.
 *
 * `auth.js` owns the policy — where the token is stored, when it is asked for,
 * what the modal says. This module owns only the header. The dependency runs one
 * way (`auth.js` imports this file, never the reverse), which is why the token
 * arrives through a setter instead of this module reading storage itself: an
 * import cycle between the transport and the login flow is the kind of thing that
 * works until a bundler or a load order changes.
 */
let authToken = '';

export function setAuthToken(token) {
  authToken = token || '';
}

let unauthorizedHandler = null;

/** Register the one callback that runs when the server rejects our session.
 *
 * A 401 on any route after boot means the session ended mid-shift — expiry, a
 * password change, a disabled account. The failing request still throws, so the
 * view reports its own problem; the callback exists so something can put the
 * sign-in modal back rather than leaving the operator clicking a dead page. */
export function onUnauthorized(handler) {
  unauthorizedHandler = handler;
}

/** The one route where a 401 is an answer rather than a session failure. */
const LOGIN_PATH = '/auth/login';

async function request(path, options = {}) {
  // `Headers` rather than object spread: `postJson` passes a Content-Type and a
  // caller could pass a differently-cased key, and two `content-type` entries is
  // a bug that only shows up on some servers.
  const headers = new Headers(options.headers || {});
  if (authToken) headers.set('Authorization', `Bearer ${authToken}`);

  let response;
  try {
    // `same-origin` is the default, stated because the HttpOnly session cookie
    // rides on it — that cookie is how a PDF link can be a plain navigation.
    response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  } catch (cause) {
    throw new OfflineError(path, cause);
  }
  if (!response.ok) {
    const error = await readDetail(response, path);
    if (response.status === 401 && path !== LOGIN_PATH && unauthorizedHandler) {
      unauthorizedHandler(error);
    }
    throw error;
  }
  return response;
}

async function getJson(path) {
  return (await request(path)).json();
}

async function postJson(path, body) {
  const response = await request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return response.json();
}

function query(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== '') search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

// ── Runtime ──────────────────────────────────────────────────────────

/** `/health` carries `runtime` and `ai.tiers` already.
 *
 * The old client did a `POST /simulate` with a throwaway `_status_probe.conf`
 * purely to learn which AI tiers were up — a full parse, rule evaluation and
 * drain3 pass per page load, which also pushed the probe's own unknown lines into
 * the training queue an admin then had to dismiss. The information was one GET
 * away the whole time. */
export const health = () => getJson('/health');

export const vendors = () => getJson('/vendors');

export const canonicalPaths = () => getJson('/canonical/paths');

// ── Ingestion (C1) ───────────────────────────────────────────────────

/** Single-file upload. */
export async function ingest(file) {
  const form = new FormData();
  form.append('file', file, file.name);
  return (await request('/ingest', { method: 'POST', body: form })).json();
}

/** Bulk upload — the half of C1 the old UI had no control for at all.
 *
 * The route takes one field, `file`, holding a **ZIP archive**; it is not a
 * repeated file field. One member failing does not fail the archive, so the
 * response separates `results` from `errors` and the UI must show both — a bulk
 * import that silently drops two of 400 devices is worse than one that refuses.
 *
 * This is the background form. The archive ceilings are 2,000 members and
 * 512 MB expanded, which is more than any browser or reverse proxy will hold a
 * connection open for, so the request returns `202` with a job to poll and the
 * UI shows progress instead of a spinner that becomes a gateway timeout. The
 * server still offers the synchronous form (`POST /ingest/bulk` with no
 * `background` flag) for scripts and for compatibility; the UI has no use for
 * it, so there is no wrapper here.
 *
 * Validation happens before the `202`: a file that is not a ZIP fails here and
 * now, rather than becoming a job the operator has to poll to discover it was
 * never going to work. */
export async function ingestBulkBackground(zipFile) {
  const form = new FormData();
  form.append('file', zipFile, zipFile.name);
  return (await request('/ingest/bulk?background=true', { method: 'POST', body: form })).json();
}

/** Poll one job. 404s once the job has aged out of the in-process history. */
export const job = (jobId) => getJson(`/jobs/${encodeURIComponent(jobId)}`);

/** Ask a running job to stop. Work already committed stays committed. */
export const cancelJob = (jobId) =>
  postJson(`/jobs/${encodeURIComponent(jobId)}/cancel`, {});

// ── Simulate (stateless, no ledger write) ────────────────────────────

export const simulate = (configText, sourceFile = 'inline.conf') =>
  postJson('/simulate', { config_text: configText, source_file: sourceFile });

// ── Devices ──────────────────────────────────────────────────────────

export const devices = () => getJson('/devices');

export const device = (deviceId) => getJson(`/devices/${encodeURIComponent(deviceId)}`);

/** The remediation plan (C4). Defaults match the route's: failures only, latest
 * committed audit. */
export const remediation = (deviceId, opts = {}) =>
  getJson(`/devices/${encodeURIComponent(deviceId)}/remediation${query(opts)}`);

/** The signed PDF's URL, for an anchor rather than a fetch.
 *
 * Letting the browser navigate means the download shows in the download shelf and
 * streams straight to disk. Fetching it into a blob would buffer a multi-megabyte
 * report in memory to achieve the same thing. */
export const reportUrl = (deviceId, opts = {}) =>
  `/devices/${encodeURIComponent(deviceId)}/report.pdf${query(opts)}`;

/** The committed machine-readable assessment, streamed as a browser download. */
export const oscalUrl = (deviceId, opts = {}) =>
  `/devices/${encodeURIComponent(deviceId)}/oscal.json${query(opts)}`;

/** Render a stateless simulation as a deterministic SARIF download. */
export async function simulateSarif(configText, sourceFile = 'inline.conf') {
  return request('/simulate/sarif', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ config_text: configText, source_file: sourceFile }),
  });
}

// ── Identity ─────────────────────────────────────────────────────────

/** Exchange a password for a bearer token.
 *
 * The response also sets an `HttpOnly; SameSite=Strict` cookie which the server
 * accepts on GET and HEAD only. That is what makes `reportUrl` work as an anchor:
 * a navigation cannot carry an Authorization header, and putting the token in the
 * query string would have written a live credential into the access log. */
export const login = (username, password) => postJson('/auth/login', { username, password });

/** Revoke this token on the server. Not the same as forgetting it locally — a
 * token the client drops is still valid to anyone who captured it. */
export const logout = () => postJson('/auth/logout', {});

/** Who the server thinks we are, and what it will let us do. The permission flags
 * are computed server-side on purpose, so the UI cannot disagree with the
 * authorization rule it is describing. */
export const whoami = () => getJson('/auth/whoami');

/** The access log, newest first. Approver-only: it is a map of who is
 * investigating what. */
export const accessLog = (opts = {}) => getJson(`/audit/access${query(opts)}`);

// ── Ledger ───────────────────────────────────────────────────────────

export const commit = (deviceId) => postJson('/audit/commit', { device_id: deviceId });

export const auditRecords = () => getJson('/audit/records');

export const auditVerify = () => getJson('/audit/verify');

// ── Training (C2) ────────────────────────────────────────────────────

/** The queue, busiest template first — one entry per template across the estate,
 * so mapping `logging host <*>` once clears it everywhere. */
export const trainingQueue = (opts = {}) => getJson(`/training/queue${query(opts)}`);

export const trainingMappings = (opts = {}) => getJson(`/training/mappings${query(opts)}`);

/** Teach a template. Takes effect without a redeploy, which is the capability
 * C2 is actually asking for.
 *
 * `vendor` scopes the mapping to one pattern pack (`*` means every pack) and
 * `value_index` says which masked operand carries the value — both are real
 * fields on `MapRequest` with real defaults, and both are exposed in the UI
 * because a mapping applied to the wrong operand produces a confidently wrong
 * fact, which is the failure mode this whole ladder exists to avoid.
 *
 * There is no `admin_id` here any more. The route used to take the mapper's name
 * as a string the client chose, which recorded whatever was typed; it now records
 * the authenticated principal and ignores the field. Sending a self-declared
 * identity alongside a real one would only invite the two to disagree. */
export const trainingMap = ({ template, canonicalPath, note, vendor, valueIndex }) =>
  postJson('/training/map', {
    drain3_template: template,
    canonical_path: canonicalPath,
    note: note || '',
    ...(vendor ? { vendor } : {}),
    ...(Number.isInteger(valueIndex) ? { value_index: valueIndex } : {}),
  });

export const trainingRetire = (template) =>
  postJson('/training/retire', { drain3_template: template });

export const trainingExportUrl = () => '/training/export';
