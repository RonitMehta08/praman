/**
 * Application entry point.
 *
 * A zero-build native ES-module SPA. §24 of the master prompt specifies Vite +
 * React + Tailwind + shadcn + Monaco + xyflow; this build deliberately does not
 * use them, and the reasoning is worth stating where a reader will find it:
 *
 * 1. That stack needs an `npm install` of several hundred megabytes. The standing
 *    constraint on this project is that heavy downloads are handed to the operator
 *    as a documented command, not executed here.
 * 2. The tool is offline-first by requirement. A build step that resolves packages
 *    from a registry is a network dependency in the development loop, and a CDN
 *    font or script is one at runtime — the old `index.html` had exactly that, and
 *    the page rendered with fallback metrics on an air-gapped machine.
 * 3. `main.py` already serves `.js` and `.mjs` with the right content type and
 *    already serves nested asset paths, so native modules work the instant uvicorn
 *    starts. No watcher, no dist directory, no source maps to keep in sync.
 *
 * The two substitutions that cost the most are honest about what they are:
 * `configview.js` implements §24.1's Monarch tokenizer rules directly rather than
 * loading Monaco, and `charts.js`'s `topologyMap` lays out nodes deterministically
 * rather than pulling in xyflow and dagre. Both are documented as deviations in the
 * architecture notes rather than passed off as the specified components.
 */

import { el, byId } from './dom.js';
import {
  initTheme, toggleTheme, route, startRouter, navigate, refresh, store, toast,
} from './shell.js';
import { identity, requireIdentity, signOut } from './auth.js';
import { dashboardView } from './views/dashboard.js';
import { uploadView } from './views/upload.js';
import { simulateView } from './views/simulate.js';
import { devicesView } from './views/devices.js';
import { deviceView } from './views/device.js';
import { findingsView } from './views/findings.js';
import { trainingView } from './views/training.js';
import { topologyView } from './views/topology.js';
import { ledgerView } from './views/ledger.js';
import { remediationView } from './views/remediation.js';

const NAV = [
  ['dashboard', 'Overview'],
  ['upload', 'Upload'],
  ['simulate', 'Simulate'],
  ['devices', 'Devices'],
  ['findings', 'Findings'],
  ['training', 'Training'],
  ['topology', 'Topology'],
  ['ledger', 'Ledger'],
];

route('dashboard', dashboardView);
route('upload', uploadView);
route('simulate', simulateView);
route('devices', devicesView);
route('device', deviceView);
route('findings', findingsView);
route('training', trainingView);
route('topology', topologyView);
route('ledger', ledgerView);
route('remediation', remediationView);

function buildNav() {
  return el(
    'nav',
    { class: 'nav', 'aria-label': 'Main' },
    ...NAV.map(([name, label]) =>
      el('a', {
        class: 'nav-link',
        href: `#/${name}`,
        dataset: { nav: name },
        text: label,
      })
    )
  );
}

/** The signed-in operator, their role, and the way out.
 *
 * The role is on screen at all times deliberately. A viewer who has forgotten
 * which account they are on reads a greyed-out Commit button as a broken build;
 * the same button next to the word "viewer" explains itself.
 */
function buildIdentitySlot() {
  const slot = el('div', { class: 'who' });

  function render() {
    const who = identity();
    if (!who) {
      slot.replaceChildren();
      return;
    }
    slot.replaceChildren(
      el(
        'span',
        { class: 'who-text', title: `Signed in as ${who.username}` },
        el('span', { class: 'who-name', text: who.username }),
        el('span', { class: `who-role who-role-${who.role}`, text: who.role })
      ),
      el('button', {
        class: 'btn btn-quiet btn-tiny',
        type: 'button',
        text: 'Sign out',
        title: 'Revoke this session on the server, not just in this browser',
        onclick: async (event) => {
          const btn = event.currentTarget;
          btn.disabled = true;
          btn.textContent = 'Signing out…';
          const clean = await signOut();
          if (!clean) {
            toast(
              'Signed out here, but the server did not confirm it.',
              'warn',
              'The old token may still be valid. If the backend is up, sign in and out again.'
            );
          }
        },
      })
    );
  }

  render();
  window.addEventListener('praman:identity', render);
  return slot;
}

function buildChrome() {
  const themeButton = el('button', {
    class: 'btn btn-quiet btn-icon',
    type: 'button',
    title: 'Switch between light and dark',
    'aria-label': 'Switch between light and dark',
    text: '◐',
    onclick: () => toggleTheme(),
  });

  const badge = el('span', { class: 'brand-badge', text: 'offline' });

  return el(
    'header',
    { class: 'topbar' },
    el(
      'a',
      { class: 'brand', href: '#/dashboard' },
      el('span', { class: 'brand-mark', 'aria-hidden': 'true', text: '◈' }),
      el(
        'span',
        { class: 'brand-text' },
        el('span', { class: 'brand-name', text: 'PRAMAN' }),
        el('span', { class: 'brand-sub', text: 'Network configuration compliance auditor' })
      ),
      badge
    ),
    buildNav(),
    el('div', { class: 'topbar-actions' }, buildIdentitySlot(), themeButton)
  );
}

/** Fill in the version and runtime facts once `/health` answers.
 *
 * Deliberately after the first render: a chrome that waits for a request shows an
 * empty page if the backend is down, when the useful thing to show is the shell
 * plus an error the user can act on.
 */
async function stampFooter(footer) {
  try {
    const health = await store.health();
    footer.replaceChildren(
      el('span', { text: `${health.app} ${health.version}` }),
      el('span', { class: 'footer-sep', text: '·' }),
      el('span', { text: `${health.problem_statement.id} · ${health.problem_statement.org}` }),
      el('span', { class: 'footer-sep', text: '·' }),
      el('span', {
        text: `${health.runtime.rules_loaded} rules · ${health.runtime.controls_total} controls · ${health.runtime.catalogs_loaded} catalogs`,
      }),
      el('span', { class: 'footer-sep', text: '·' }),
      el('span', { text: `pattern library ${health.runtime.pattern_library_version}` }),
      el('span', { class: 'footer-sep', text: '·' }),
      el('span', {
        text: 'No telemetry. No outbound network calls. Verdicts are deterministic — no model is in the decision path.',
      })
    );
  } catch {
    footer.replaceChildren(
      el('span', {
        class: 'footer-bad',
        text: 'The backend is not answering. Start it with: .venv/Scripts/python.exe -m uvicorn backend.app.main:app --port 8000',
      })
    );
  }
}

async function boot() {
  initTheme();

  const root = byId('app');
  const outlet = el('main', { class: 'view', id: 'view-outlet', tabindex: '-1' });
  const footer = el('footer', { class: 'footer' }, el('span', { text: 'Loading runtime information…' }));

  root.replaceChildren(
    // A skip link, but a button rather than `href="#view-outlet"` — the router
    // owns the fragment, and an anchor would rewrite it to a route name that does
    // not exist and bounce the user to the dashboard.
    el('button', {
      class: 'skip-link',
      type: 'button',
      text: 'Skip to content',
      onclick: () => outlet.focus(),
    }),
    buildChrome(),
    outlet,
    footer
  );

  // An unhandled rejection anywhere in a view is a bug, and a silent one is a
  // support call. Surfacing it as a toast costs nothing and turns "the page did
  // nothing" into a message with a cause in it.
  window.addEventListener('unhandledrejection', (event) => {
    toast('Something failed in the background.', 'error', String(event.reason?.message || event.reason || ''));
  });

  if (!window.location.hash) navigate('dashboard');

  // Before the gate, not after. `/health` is one of the three unauthenticated
  // routes, so the runtime facts and — more usefully — the "backend is not
  // answering" line are both available while the sign-in modal is still up. A
  // footer that said "Loading runtime information…" behind a password box would be
  // hiding the one message that explains the case where signing in cannot work.
  stampFooter(footer);

  // Identity before the router. Every route reads something the server refuses
  // without a session, so starting the router first would paint one 401 per panel
  // and bury the password field the operator actually needs. The shell is already
  // on screen at this point, which is what keeps the boot watchdog in index.html
  // quiet.
  await requireIdentity();
  startRouter();

  // A later sign-out clears the screen rather than leaving one operator's findings
  // up for the next, and drops the caches with it. A later sign-in re-renders the
  // route that was showing, now with the new identity's permissions applied.
  window.addEventListener('praman:identity', () => {
    store.invalidate();
    if (identity()) refresh();
    else outlet.replaceChildren();
  });
}

// `boot` is async because identity has to settle before the router runs. The
// catch is not decoration: a rejection here happens before the toast host exists,
// so without it the page would sit on the boot placeholder with the reason only in
// the console.
boot().catch((error) => {
  const root = byId('app');
  if (root) {
    root.replaceChildren(
      el(
        'div',
        { class: 'boot-error' },
        el('p', { text: 'PRAMAN could not start.' }),
        el('p', { text: String(error?.message || error) })
      )
    );
  }
});
