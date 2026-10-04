/** Local-only presentation primitives. No API state, dependencies or verdict logic. */
import { el, svg } from './dom.js';

const PATHS = {
  dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  upload: 'M12 16V3 m-5 5 5-5 5 5 M4 15v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5',
  simulate: 'm9 4 12 8-12 8z M3 4v16',
  devices: 'M3 3h18v6H3z M3 15h18v6H3z M7 6h.01 M7 18h.01 M12 9v6',
  findings: 'm12 3 10 18H2z M12 9v5 M12 17h.01',
  training: 'M9 3 7 7 3 9l4 2 2 4 2-4 4-2-4-2z M17 13l-2 3-3 2 3 2 2 3 2-3 3-2-3-2z',
  topology: 'M9 2h6v6H9z M2 16h6v6H2z M16 16h6v6h-6z M12 8v4 M5 16v-4h14v4',
  ledger: 'M4 3h16v18H4z M8 7h8 M8 11h8 m-8 5 2 2 5-4',
  access: 'M5 20v-1a7 7 0 0 1 14 0v1 M12 13a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  shield: 'm12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6z m-5 10 3 3 7-7',
  search: 'M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15 M16 16l5 5',
  theme: 'M12 3a9 9 0 1 0 9 9A9 9 0 0 1 12 3z',
  arrow: 'M4 12h16 m-6-6 6 6-6 6',
  menu: 'M4 6h16 M4 12h16 M4 18h16',
  close: 'm6 6 12 12 M6 18 18 6',
  motion: 'M8 4v16 M16 4v16',
  up: 'M12 20V4 m-7 7 7-7 7 7',
};

export function icon(name, size = 20) {
  return svg('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: 'ui-icon', 'aria-hidden': 'true', focusable: 'false' },
    svg('path', { d: PATHS[name] || PATHS.shield }));
}

/** A sculptural evidence stack, deliberately not a chart or a verification badge.
 * CSS planes retain their depth with motion disabled; no GPU canvas or asset fetch.
 */
export function evidenceCore() {
  return el('div', { class: 'evidence-scene', 'aria-hidden': 'true' },
    el('div', { class: 'scene-orbit orbit-one' }),
    el('div', { class: 'scene-orbit orbit-two' }),
    el('div', { class: 'scene-floor' }),
    el('div', { class: 'evidence-float' },
      el('div', { class: 'evidence-core' },
        ...[0, 1, 2, 3].map((layer) => el('div', { class: `core-plane plane-${layer}` },
          el('span', { class: 'plane-corner corner-a' }),
          el('span', { class: 'plane-corner corner-b' }),
          layer === 3 ? icon('shield', 72) : el('span', { class: 'plane-circuit' })
        ))
      )
    ),
    el('span', { class: 'scene-label label-top', text: 'CONFIGURATION → FACTS' }),
    el('span', { class: 'scene-label label-bottom', text: 'RULES → SIGNED EVIDENCE' })
  );
}

export function overviewHero() {
  return el('section', { class: 'overview-hero', 'aria-labelledby': 'hero-title' },
    el('div', { class: 'hero-copy' },
      el('p', { class: 'eyebrow', text: 'CLARITY. WITHOUT COMPROMISE.' }),
      el('h2', { id: 'hero-title', class: 'hero-title' }, 'Every configuration.', el('br'), el('span', { text: 'A verifiable answer.' })),
      el('p', { class: 'hero-description', text: 'From multi-vendor configurations to traceable findings. Your entire audit workflow, in one private workspace.' }),
      el('div', { class: 'hero-links' },
        el('a', { href: '#/simulate', class: 'hero-cta' }, icon('simulate', 16), 'Try a simulation', icon('arrow', 16)),
        el('span', { class: 'hero-local' }, icon('shield', 15), 'Local by design')
      )
    ),
    evidenceCore(),
    el('div', { class: 'hero-frameworks' }, el('span', { text: 'FRAMEWORK LIBRARY' }),
      ...['CIS Benchmarks', 'NIST SP 800-53', 'DISA STIG', 'ISO 27001'].map((name) => el('span', { text: name })))
  );
}

export function workflowLinks() {
  return el('nav', { class: 'workflow-links', 'aria-label': 'Audit workflow' },
    ...[
      ['01', 'upload', 'Bring your configurations', 'A file, a folder, an entire estate.'],
      ['02', 'findings', 'Understand the gaps', 'Trace each finding to its evidence.'],
      ['03', 'ledger', 'Verify what was signed', 'Inspect the chain, not just a badge.'],
    ].map(([step, route, title, note]) => el('a', { class: 'workflow-link', href: `#/${route}` },
      el('span', { class: 'workflow-number', text: step }),
      el('span', {}, el('strong', { text: title }), el('span', { class: 'workflow-note', text: note })), icon('arrow', 18)))
  );
}

/** Native dialog handles focus trapping, Escape, and return-to-trigger focus. */
export function openWorkspaceSearch(items) {
  if (document.querySelector('.workspace-search[open]') || document.querySelector('.auth-overlay')) return;
  const input = el('input', { class: 'command-input', type: 'search', placeholder: 'Where would you like to go?', 'aria-label': 'Find a workspace', autocomplete: 'off' });
  const results = el('div', { class: 'command-results' });
  const dialog = el('dialog', { class: 'workspace-search', 'aria-labelledby': 'command-title' },
    el('div', { class: 'command-heading' }, el('h2', { id: 'command-title', text: 'Jump to workspace' }),
      el('button', { class: 'btn btn-quiet btn-icon', type: 'button', 'aria-label': 'Close workspace search', onclick: () => dialog.close() }, icon('close'))),
    el('div', { class: 'command-field' }, icon('search'), input), results,
    el('p', { class: 'command-hint', text: '↑ ↓ to move · Enter to open · Esc to close' }));
  function draw() {
    const query = input.value.trim().toLowerCase();
    const approverLink = document.querySelector('[data-role-link="approver"]');
    const visibleItems = items.filter(([name]) => name !== 'access' || !approverLink || !approverLink.hidden);
    const matches = visibleItems.filter(([name, label]) => `${name} ${label}`.toLowerCase().includes(query));
    results.replaceChildren(...matches.map(([name, label]) => el('a', { href: `#/${name}`, class: 'command-result', onclick: () => dialog.close() }, icon(name), el('span', { text: label }), icon('arrow', 16))));
    if (!matches.length) results.appendChild(el('p', { class: 'command-empty', role: 'status', text: 'No matching workspace. Try “devices” or “training”.' }));
  }
  input.addEventListener('input', draw);
  dialog.addEventListener('keydown', (event) => {
    const links = [...results.querySelectorAll('a')];
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!links.length) return;
      const index = links.indexOf(document.activeElement);
      links[(index + (event.key === 'ArrowDown' ? 1 : links.length - 1) + links.length) % links.length].focus();
    } else if (event.key === 'Enter' && document.activeElement === input) {
      event.preventDefault();
      links[0]?.click();
    }
  });
  dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
  dialog.addEventListener('close', () => dialog.remove(), { once: true });
  draw();
  document.body.appendChild(dialog);
  dialog.showModal();
  input.focus();
}

export function initExperience(items) {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  let paused = false;
  try { paused = localStorage.getItem('praman.motion') === 'paused'; } catch { /* optional preference */ }
  const motionButton = document.querySelector('[data-motion-toggle]');
  function updateMotion() {
    const off = reduced.matches || paused;
    document.documentElement.dataset.motion = off ? 'paused' : 'full';
    motionButton?.setAttribute('aria-pressed', String(off));
    if (motionButton) motionButton.title = reduced.matches ? 'Motion disabled by your system preference' : off ? 'Resume decorative motion' : 'Pause decorative motion';
  }
  motionButton?.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('praman.motion', paused ? 'paused' : 'full'); } catch { /* optional preference */ }
    updateMotion();
  });
  reduced.addEventListener('change', updateMotion);
  updateMotion();

  const toggle = document.querySelector('[data-menu-toggle]');
  const sidebar = document.querySelector('.workspace-sidebar');
  const scrim = document.querySelector('.sidebar-scrim');
  const mobile = window.matchMedia('(max-width: 1000px)');
  function setMenu(open) {
    document.body.classList.toggle('menu-open', open);
    toggle?.setAttribute('aria-expanded', String(open));
    if (sidebar) sidebar.inert = mobile.matches && !open;
  }
  toggle?.addEventListener('click', () => setMenu(!document.body.classList.contains('menu-open')));
  scrim?.addEventListener('click', () => setMenu(false));
  mobile.addEventListener('change', () => setMenu(false));
  setMenu(false);
  window.addEventListener('hashchange', () => {
    const focusWasInSidebar = sidebar?.contains(document.activeElement);
    setMenu(false);
    if (focusWasInSidebar && mobile.matches) toggle?.focus();
  });
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && document.body.classList.contains('menu-open')) {
      setMenu(false);
      toggle?.focus();
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openWorkspaceSearch(items);
    }
  });

  const top = document.querySelector('.back-to-top');
  let scheduled = false;
  let lastScrollY = window.scrollY;
  const syncScroll = () => {
    scheduled = false;
    const y = Math.max(0, window.scrollY);
    const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const progress = Math.min(1, y / max);
    const delta = y - lastScrollY;
    document.documentElement.style.setProperty('--scroll-y', `${y}px`);
    document.documentElement.style.setProperty('--scroll-progress', progress.toFixed(4));
    document.documentElement.style.setProperty('--scroll-percent', `${(progress * 100).toFixed(2)}%`);
    document.documentElement.style.setProperty('--scroll-shift', `${Math.min(32, y * 0.06).toFixed(2)}px`);
    document.documentElement.style.setProperty('--scroll-inverse-shift', `${Math.max(-32, -y * 0.06).toFixed(2)}px`);
    document.documentElement.style.setProperty('--scroll-scale', (1 + progress * 0.25).toFixed(4));
    document.documentElement.style.setProperty('--scroll-direction', delta >= 0 ? '1' : '-1');
    document.documentElement.dataset.scrollBand = y > 720 ? 'deep' : y > 160 ? 'middle' : 'top';
    top.hidden = y < 600;
    lastScrollY = y;
  };
  window.addEventListener('scroll', () => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(syncScroll);
  }, { passive: true });

  // Reveal the interface in measured beats as it enters the viewport. A mutation
  // observer is intentional: routes are rendered after the shell boots and again
  // after every hash navigation, so a one-time query would only animate Overview.
  const view = document.querySelector('.view');
  const reveal = 'scroll-reveal';
  const observer = 'IntersectionObserver' in window
    ? new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      }, { rootMargin: '0px 0px -8% 0px', threshold: 0.04 })
    : null;
  const markRevealables = () => {
    if (!view) return;
    observer?.disconnect();
    view.querySelectorAll('.page-header, .page > .panel, .stat, .chart, .workflow-link').forEach((node) => {
      if (!node.classList.contains(reveal)) node.classList.add(reveal);
      if (node.classList.contains('is-visible')) return;
      observer?.observe(node);
      if (!observer) node.classList.add('is-visible');
    });
    syncScroll();
  };
  markRevealables();
  const mutations = view ? new MutationObserver(markRevealables) : null;
  mutations?.observe(view, { childList: true, subtree: true });
  syncScroll();
}
