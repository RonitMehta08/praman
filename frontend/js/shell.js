/**
 * The shell: routing, shared state, toasts, theme.
 *
 * Small on purpose. The old dashboard kept everything in module-level `let`s and
 * refetched `/health` and `/devices` on every view switch; here a view asks the
 * store for what it needs and the store decides whether that means a request.
 */

import { el, byId, render, clear, errorPanel, spinner } from './dom.js';
import { ApiError, OfflineError } from './api.js';
import * as api from './api.js';

// ── Toasts ───────────────────────────────────────────────────────────

let toastHost = null;

function host() {
  if (!toastHost) {
    toastHost = el('div', { class: 'toast-host', 'aria-live': 'polite', 'aria-atomic': 'false' });
    document.body.appendChild(toastHost);
  }
  return toastHost;
}

/**
 * A non-blocking notification.
 *
 * Replaces `alert()`, which blocked the page, could not show the `detail` string
 * the API sends, and — for the new remediation route's 400, whose detail names the
 * valid result values — threw away the only part of the response that told the
 * caller what to do instead.
 */
export function toast(message, kind = 'info', detail = null) {
  const node = el(
    'div',
    { class: `toast toast-${kind}`, role: kind === 'error' ? 'alert' : 'status' },
    el('div', { class: 'toast-message', text: message }),
    detail ? el('pre', { class: 'toast-detail', text: String(detail).slice(0, 400) }) : null,
    el('button', {
      class: 'toast-close',
      type: 'button',
      'aria-label': 'Dismiss',
      text: '×',
      onclick: () => node.remove(),
    })
  );
  host().appendChild(node);
  // Errors persist: they carry a detail string worth reading, and a message that
  // vanishes after four seconds is a message nobody read.
  if (kind !== 'error') setTimeout(() => node.remove(), 4200);
  return node;
}

/** Turn a thrown error into a sentence that names the cause. */
export function describeError(error) {
  if (error instanceof OfflineError) {
    return {
      message: 'Cannot reach the backend.',
      detail: 'The page loaded but the API did not answer. If uvicorn was restarted, reload.',
    };
  }
  if (error instanceof ApiError) {
    return { message: `Request failed (HTTP ${error.status})`, detail: error.detail || error.path };
  }
  return { message: error?.message || 'Something went wrong.', detail: error?.stack || null };
}

export function reportError(error) {
  const { message, detail } = describeError(error);
  toast(message, 'error', detail);
  return errorPanel(message, detail);
}

// ── Theme ────────────────────────────────────────────────────────────

const THEME_KEY = 'praman.theme';

export function initTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem(THEME_KEY);
  } catch {
    // Private-mode storage denial is not worth a message; fall through to the
    // system preference.
  }
  const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches;
  document.documentElement.dataset.theme = stored || (prefersDark ? 'dark' : 'light');
}

export function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    /* not fatal */
  }
  // Charts bake their colours into attributes at build time, so a theme flip has
  // to redraw rather than restyle. Cheaper than threading CSS variables through
  // every fill, and it keeps the PDF and the screen sharing one palette module.
  window.dispatchEvent(new CustomEvent('praman:theme'));
  return next;
}

// ── Shared state ─────────────────────────────────────────────────────

/**
 * A tiny cache over the read-only endpoints.
 *
 * `/health` and `/canonical/paths` change only when a pack is reloaded or a
 * mapping is taught; `/devices` changes on ingest. Views declare what they need
 * and mutating actions invalidate by name, which is less machinery than it sounds
 * and removes the four redundant `/health` calls the old page made per navigation.
 */
const cache = new Map();
const inflight = new Map();

function cached(key, loader) {
  if (cache.has(key)) return Promise.resolve(cache.get(key));
  if (inflight.has(key)) return inflight.get(key);
  const promise = loader()
    .then((value) => {
      cache.set(key, value);
      inflight.delete(key);
      return value;
    })
    .catch((error) => {
      inflight.delete(key);
      throw error;
    });
  inflight.set(key, promise);
  return promise;
}

export const store = {
  health: () => cached('health', api.health),
  vendors: () => cached('vendors', api.vendors),
  canonicalPaths: () => cached('canonical', api.canonicalPaths),
  devices: () => cached('devices', api.devices),
  auditRecords: () => cached('records', api.auditRecords),

  /** Drop cached entries. Called by anything that writes. */
  invalidate(...keys) {
    if (keys.length === 0) {
      cache.clear();
      return;
    }
    for (const key of keys) cache.delete(key);
  },

  /** After an ingest or a commit, the device roster and the ledger have both
   * moved, and `/health` counters may have too. */
  invalidateAfterWrite() {
    this.invalidate('devices', 'records', 'health');
  },
};

// ── Routing ──────────────────────────────────────────────────────────

/**
 * Hash routing, because the backend deliberately has no SPA catch-all.
 *
 * `main.py` declines to serve `index.html` for unknown paths on the grounds that
 * doing so turns an API typo into a silent 200 with HTML in it — a decision worth
 * keeping. So the router lives entirely after the `#`, which means a deep link
 * survives a refresh without the server needing to know any route names.
 */
const routes = new Map();
let currentCleanup = null;
let currentRoute = null;

export function route(name, handler) {
  routes.set(name, handler);
}

/** Parse `#/devices/abc123?tab=remediation` into name, params, and query. */
function parseHash() {
  const raw = window.location.hash.replace(/^#\/?/, '');
  const [pathPart, queryPart] = raw.split('?');
  const segments = pathPart.split('/').filter(Boolean).map(decodeURIComponent);
  const query = Object.fromEntries(new URLSearchParams(queryPart || ''));
  return { name: segments[0] || 'dashboard', params: segments.slice(1), query };
}

export function navigate(name, params = [], query = {}) {
  const search = new URLSearchParams(query).toString();
  const path = [name, ...params.map(encodeURIComponent)].join('/');
  window.location.hash = `#/${path}${search ? `?${search}` : ''}`;
}

export function currentView() {
  return currentRoute;
}

async function dispatch() {
  const { name, params, query } = parseHash();
  const handler = routes.get(name) || routes.get('dashboard');
  const outlet = byId('view-outlet');

  if (currentCleanup) {
    try {
      currentCleanup();
    } catch {
      /* a view failing to tear down must not block the next one */
    }
    currentCleanup = null;
  }

  const routeChanged = currentRoute !== name;
  currentRoute = name;
  outlet.dataset.route = name;
  const navName = name === 'device' || name === 'remediation' ? 'devices' : name;
  document.querySelectorAll('[data-nav]').forEach((link) => {
    const active = link.dataset.nav === navName;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });

  render(outlet, spinner('Loading…'));
  try {
    const cleanup = await handler({ params, query, outlet });
    currentCleanup = typeof cleanup === 'function' ? cleanup : null;
    const title = outlet.querySelector('.page-title')?.textContent || 'Workspace';
    const location = document.getElementById('workspace-location');
    if (location) location.textContent = title;
    document.title = `${title} — PRAMAN`;
    if (routeChanged) window.scrollTo({ top: 0, behavior: 'instant' });
  } catch (error) {
    render(outlet, reportError(error));
  }
}

/** Re-run the active route.
 *
 * `navigate()` to the hash you are already on fires no `hashchange`, so a write
 * that should refresh the page it happened on needs this rather than a synthetic
 * event. Committing an audit from a device page is the case that matters: the
 * history table, the PDF link and the trend all have to move.
 */
export function refresh() {
  return dispatch();
}

export function startRouter() {
  window.addEventListener('hashchange', dispatch);
  window.addEventListener('praman:theme', () => {
    // Redraw the active view so charts pick up the new surface.
    dispatch();
  });
  dispatch();
}

// ── View helpers ─────────────────────────────────────────────────────

/** A page with a title, an optional action bar, and body sections. */
export function page(title, subtitle, actions, ...sections) {
  return el(
    'div',
    { class: 'page' },
    el(
      'header',
      { class: 'page-header' },
      el(
        'div',
        {},
        // `h1`, not `h2`. The route title is the top-level heading of the
        // document — there is nothing above it — and a page whose outline starts
        // at `h2` gives a screen reader no landmark to jump to.
        el('h1', { class: 'page-title', text: title }),
        subtitle ? el('p', { class: 'page-subtitle', text: subtitle }) : null
      ),
      actions ? el('div', { class: 'page-actions' }, ...[].concat(actions)) : null
    ),
    ...sections.flat(Infinity).filter(Boolean)
  );
}

/** A bordered panel. */
export function panel(title, ...children) {
  return el(
    'section',
    { class: 'panel' },
    title ? el('h2', { class: 'panel-title', text: title }) : null,
    ...children.flat(Infinity).filter(Boolean)
  );
}

/** A button. */
export function button(label, onClick, opts = {}) {
  return el('button', {
    class: `btn ${opts.class || ''}`.trim(),
    type: 'button',
    onclick: onClick,
    disabled: opts.disabled || false,
    title: opts.title || null,
  }, label);
}

/** A link styled as a button, for real navigations like the PDF download. */
export function linkButton(label, href, opts = {}) {
  return el('a', {
    class: `btn ${opts.class || ''}`.trim(),
    href,
    download: opts.download || null,
    target: opts.target || null,
    rel: opts.target ? 'noopener' : null,
    text: label,
  });
}

/** A labelled `<select>`. */
export function select(label, options, value, onChange, opts = {}) {
  const node = el(
    'select',
    { class: 'field-input', onchange: (event) => onChange(event.target.value) },
    ...options.map(([optValue, optLabel]) =>
      el('option', { value: optValue, selected: optValue === value ? true : null }, optLabel)
    )
  );
  return el(
    'label',
    { class: `field ${opts.class || ''}`.trim() },
    el('span', { class: 'field-label', text: label }),
    node
  );
}

/** A labelled text input. */
export function textField(label, value, onInput, opts = {}) {
  const node = el('input', {
    class: 'field-input',
    type: opts.type || 'text',
    value: value || '',
    placeholder: opts.placeholder || '',
    list: opts.list || null,
    oninput: (event) => onInput(event.target.value),
  });
  const field = el(
    'label',
    { class: `field ${opts.class || ''}`.trim() },
    el('span', { class: 'field-label', text: label }),
    node,
    opts.hint ? el('span', { class: 'field-hint', text: opts.hint }) : null
  );
  field.input = node;
  return field;
}

/** Swap a container's contents for a spinner while `work` runs. */
export async function withSpinner(container, label, work) {
  render(container, spinner(label));
  try {
    const result = await work();
    return result;
  } catch (error) {
    render(container, reportError(error));
    throw error;
  }
}

export { clear, render };
