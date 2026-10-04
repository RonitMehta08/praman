/**
 * Who the operator is, and the modal that asks.
 *
 * The server gained roles before the UI had a way to log in, which left the
 * frontend in the worst possible state: every route answering 401 and the page
 * rendering eleven copies of the same error. This module closes that, and it is
 * the only place in the frontend that holds a credential.
 *
 * Three decisions worth stating, because each has a more obvious alternative:
 *
 * 1. **The token lives in `sessionStorage`, not `localStorage`.** Both are equally
 *    readable by injected script, so that is not the axis; persistence is. A
 *    bearer token in `localStorage` survives closing the browser, which on a
 *    shared assessment laptop means the next person to open the tool inherits the
 *    previous assessor's identity — and the ledger would sign their name onto it.
 *    `sessionStorage` dies with the tab. It is kept at all so that a reload does
 *    not throw away a live session, because the alternative is worse than either:
 *    the `HttpOnly` cookie the server also sets would keep every GET working while
 *    every write failed, and a UI that reads but cannot write looks broken rather
 *    than logged out.
 * 2. **Permissions come from `/auth/whoami`, never from the role string here.**
 *    Recomputing "approver means may_commit" in JavaScript would be one line and
 *    would be a second copy of the authorization rule, free to drift from the one
 *    that matters. So login is followed by a `whoami`, one extra round trip on a
 *    once-per-session path.
 * 3. **What the UI disables is a courtesy; the 403 is the control.** Nothing here
 *    is a security boundary. Greying out a commit button a viewer cannot use saves
 *    them a pointless click and an error toast — it does not stop anyone, and it
 *    is not asked to.
 */

import { el } from './dom.js';
import { evidenceCore, icon } from './experience.js';
import {
  ApiError,
  login as apiLogin,
  logout as apiLogout,
  onUnauthorized,
  setAuthToken,
  whoami,
} from './api.js';

/** Per-tab, deliberately. See the module note. */
const STORAGE_KEY = 'praman.session.token';

/** `{username, role, may_ingest, may_commit}` once known, `null` when signed out. */
let identityState = null;

/** The overlay node while it is on screen, `null` otherwise. */
let overlay = null;

/** One gate promise shared by every caller waiting for a sign-in, so a 401 storm
 * from several in-flight requests produces one modal and one wait, not five. */
let gatePromise = null;
let resolveGate = null;

// ── Token storage ────────────────────────────────────────────────────

function readStoredToken() {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY) || '';
  } catch {
    // Storage can throw rather than return null: a locked-down profile, or
    // Safari's private mode historically. A session that works until the next
    // reload beats a page that will not boot.
    return '';
  }
}

function writeStoredToken(token) {
  try {
    if (token) window.sessionStorage.setItem(STORAGE_KEY, token);
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* see readStoredToken */
  }
}

// ── State ────────────────────────────────────────────────────────────

/** The current identity, or `null`. Do not cache the result: it changes. */
export function identity() {
  return identityState;
}

export function isSignedIn() {
  return identityState !== null;
}

/** May this operator upload and simulate? Server-computed. */
export function mayIngest() {
  return Boolean(identityState?.may_ingest);
}

/** May this operator commit to the ledger and teach the parser? Server-computed. */
export function mayCommit() {
  return Boolean(identityState?.may_commit);
}

/**
 * A sentence for the `title` of a control this role cannot use.
 *
 * Written as one function so every disabled control in the UI explains itself the
 * same way, and so the explanation names the role needed rather than saying
 * "not permitted" — an operator who reads "needs the approver role" knows what to
 * ask for, and an operator who reads "denied" opens a support call.
 */
export function needsRole(role, action) {
  const who = identityState ? `You are signed in as ${identityState.role}.` : 'You are signed out.';
  return `${who} ${action} needs the ${role} role.`;
}

function announce() {
  window.dispatchEvent(new CustomEvent('praman:identity', { detail: identityState }));
}

function adopt(snapshot) {
  identityState = snapshot;
  announce();
}

// ── The gate ─────────────────────────────────────────────────────────

/**
 * Resolve to `true` once an operator is signed in, or `false` if the backend
 * cannot be reached at all.
 *
 * Called once at boot, before the router starts. A signed-out session that
 * rendered the dashboard first would fire a dozen requests the server is bound to
 * refuse, and the operator would read a dozen errors instead of a password field.
 *
 * The offline case deliberately does *not* show the modal. A password box in front
 * of a backend that is not running cannot succeed, and it hides the footer line
 * that says how to start uvicorn.
 */
export async function requireIdentity() {
  const token = readStoredToken();
  if (token) {
    setAuthToken(token);
    try {
      adopt(await whoami());
      return true;
    } catch (error) {
      if (!(error instanceof ApiError)) return false; // offline: let the shell say so
      // 401 here is the ordinary case — a stale token from a previous session, or
      // one revoked by a password change. Not worth a message.
      forgetToken();
    }
  }
  return openGate(null);
}

function forgetToken() {
  writeStoredToken('');
  setAuthToken('');
  if (identityState !== null) adopt(null);
}

function openGate(message) {
  if (!gatePromise) {
    gatePromise = new Promise((resolve) => {
      resolveGate = resolve;
    });
  }
  showOverlay(message);
  return gatePromise;
}

function closeGate(result) {
  if (overlay) {
    overlay.remove();
    overlay = null;
  }
  const app = document.getElementById('app');
  if (app) app.inert = false;
  document.getElementById('view-outlet')?.focus({ preventScroll: true });
  const resolve = resolveGate;
  gatePromise = null;
  resolveGate = null;
  if (resolve) resolve(result);
}

/**
 * Sign out: revoke the token on the server, then ask for a new sign-in.
 *
 * The revocation is the point. Clearing storage alone would leave a live
 * credential valid for the rest of its twelve hours in whatever captured it, so a
 * failed logout call is reported rather than swallowed — but the local state is
 * cleared either way, because refusing to sign out of a UI whose backend just went
 * down would be absurd.
 */
export async function signOut() {
  let failure = null;
  try {
    await apiLogout();
  } catch (error) {
    failure = error;
  }
  forgetToken();
  openGate(
    failure
      ? 'Signed out here, but the server did not confirm it. The old session may still be valid.'
      : 'Signed out. The previous session was revoked on the server.'
  );
  return failure === null;
}

/**
 * A 401 on any request after boot means the session ended under us — the twelve
 * hour lifetime ran out, an administrator changed the password, or the account was
 * disabled mid-shift. The request that hit it still throws, so the view reports
 * its own failure; this puts the modal back so the next attempt can work.
 */
onUnauthorized(() => {
  if (overlay) return; // already asking
  const had = identityState !== null;
  forgetToken();
  if (had) {
    openGate(
      'Your session ended. That happens after twelve hours, or when an ' +
        'administrator changes your password or disables the account.'
    );
  }
});

// ── The modal ────────────────────────────────────────────────────────

function fieldRow(id, label, type, autocomplete) {
  const input = el('input', {
    class: 'field-input',
    id,
    name: id,
    type,
    autocomplete,
    required: true,
    spellcheck: 'false',
  });
  return {
    input,
    node: el(
      'label',
      { class: 'field', for: id },
      el('span', { class: 'field-label', text: label }),
      input
    ),
  };
}

function showOverlay(message) {
  if (overlay) {
    if (message) setStatus(overlay.querySelector('.auth-status'), message, 'note');
    return;
  }

  const user = fieldRow('auth-username', 'Operator name', 'text', 'username');
  const pass = fieldRow('auth-password', 'Password', 'password', 'current-password');
  const status = el('p', { class: 'auth-status', role: 'status', 'aria-live': 'polite' });
  const submit = el('button', { class: 'btn auth-submit', type: 'submit', text: 'Sign in' });

  const form = el(
    'form',
    { class: 'auth-form', novalidate: true },
    user.node,
    pass.node,
    submit
  );

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    attempt(user.input, pass.input, submit, status);
  });

  overlay = el(
    'div',
    { class: 'auth-overlay', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'auth-title' },
    el('div', { class: 'auth-layout' },
    el('section', { class: 'auth-story', 'aria-label': 'About PRAMAN' },
      el('div', { class: 'auth-brand' }, icon('shield', 26), el('span', { text: 'PRAMAN' })),
      el('p', { class: 'eyebrow', text: 'THE EVIDENCE-FIRST WORKSPACE' }),
      el('h2', { class: 'auth-statement' }, 'Confidence,', el('br'), 'with proof.'),
      el('p', { class: 'auth-story-note', text: 'Bring clarity to network compliance. Every finding traceable. Every committed audit verifiable.' }),
      evidenceCore(),
      el('p', { class: 'auth-local' }, icon('shield', 16), 'Offline-first · Private by design')),
    el(
      'div',
      { class: 'auth-card' },
      el('span', { class: 'auth-mark' }, icon('shield', 28)),
      el('p', { class: 'eyebrow', text: 'YOUR SECURE WORKSPACE' }),
      el('h1', { class: 'auth-title', id: 'auth-title', text: 'Welcome to PRAMAN' }),
      el('p', {
        class: 'auth-sub',
        text: 'Sign in. Every audit committed to the ledger is signed with the name you use here.',
      }),
      form,
      status,
      el('p', {
        class: 'auth-foot',
        text:
          'There is no default account. The first one is created on the server ' +
          'with scripts/manage_users.py, which is Step 13 of MANUAL_COMMANDS.md.',
      })
    ))
  );

  // The role=dialog overlay must behave as a modal for keyboard users too.
  overlay.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    const focusable = [...overlay.querySelectorAll('input:not(:disabled), button:not(:disabled)')];
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  const app = document.getElementById('app');
  if (app) app.inert = true;
  document.body.appendChild(overlay);
  if (message) setStatus(status, message, 'note');
  // After the append, or the node is not focusable yet.
  user.input.focus();
}

function setStatus(status, text, kind) {
  status.replaceChildren(el('span', { class: `auth-${kind}`, text }));
}

/**
 * One sign-in attempt.
 *
 * Failures are shown verbatim from the server's `detail`, which is a deliberate
 * choice rather than laziness. The three interesting answers are already written
 * for the person at the keyboard: 401 says only "invalid credentials" because
 * distinguishing an unknown name from a wrong password would hand out a user
 * roster; 429 names the seconds left on the lockout; and 503 explains that the
 * deployment has no account yet and gives the command that creates one.
 * Paraphrasing any of them here would put a second, staler copy of that reasoning
 * in the client.
 */
async function attempt(userInput, passInput, submit, status) {
  const username = userInput.value.trim();
  const password = passInput.value;
  if (!username || !password) {
    setStatus(status, 'Both the operator name and the password are needed.', 'bad');
    (username ? passInput : userInput).focus();
    return;
  }

  submit.disabled = true;
  submit.textContent = 'Signing in…';
  setStatus(status, 'Checking. Key derivation takes about a fifth of a second.', 'note');

  try {
    const session = await apiLogin(username, password);
    setAuthToken(session.token);
    writeStoredToken(session.token);
    // Ask the server what this identity may do rather than deciding from the role
    // string it just returned. See note 2 in the module docstring.
    adopt(await whoami());
    passInput.value = '';
    closeGate(true);
  } catch (error) {
    setAuthToken('');
    writeStoredToken('');
    submit.disabled = false;
    submit.textContent = 'Sign in';
    setStatus(status, error.detail || error.message, 'bad');
    passInput.value = '';
    passInput.focus();
  }
}
