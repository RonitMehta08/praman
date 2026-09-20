/**
 * Element construction without `innerHTML`.
 *
 * The old dashboard built every row by string concatenation into `innerHTML`,
 * with device hostnames, config lines, and drain3 templates interpolated raw.
 * That is an injection in a tool whose entire input is untrusted text: a config
 * file containing `hostname <img src=x onerror=...>` is a perfectly ordinary
 * thing for an auditor to be handed, and the whole point of PRAMAN is to accept
 * files nobody vetted.
 *
 * Everything here goes through `textContent` or `setAttribute`, so a payload in a
 * config renders as the characters it is. There is no escaping function to
 * remember to call, because there is no path that would need one.
 */

/** SVG needs its own namespace or the browser builds inert HTMLUnknownElements. */
const SVG_NS = 'http://www.w3.org/2000/svg';

function applyProps(node, props) {
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;

    if (key === 'class' || key === 'className') {
      node.setAttribute('class', String(value));
    } else if (key === 'text') {
      node.textContent = String(value);
    } else if (key === 'html') {
      // Deliberately not supported. Reaching for it means a caller is about to
      // paste data into markup; throwing here is cheaper than the audit later.
      throw new Error('dom.js does not set innerHTML — build child nodes instead');
    } else if (key === 'dataset') {
      for (const [dataKey, dataValue] of Object.entries(value)) {
        if (dataValue !== null && dataValue !== undefined) {
          node.dataset[dataKey] = String(dataValue);
        }
      }
    } else if (key === 'style' && typeof value === 'object') {
      for (const [prop, val] of Object.entries(value)) {
        if (val !== null && val !== undefined) node.style.setProperty(prop, String(val));
      }
    } else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
}

function appendChildren(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/**
 * Build an HTML element.
 *
 * @param {string} tag
 * @param {object} [props] Attributes. `text` sets textContent, `dataset` sets
 *   data-* keys, `on*` functions become listeners, `style` accepts an object.
 * @param {...(Node|string|Array|null|false)} children
 */
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  applyProps(node, props);
  appendChildren(node, children);
  return node;
}

/** Build an SVG element. Same signature as `el`, correct namespace. */
export function svg(tag, props = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'text') {
      node.textContent = String(value);
    } else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === 'dataset') {
      for (const [dataKey, dataValue] of Object.entries(value)) {
        if (dataValue !== null && dataValue !== undefined) node.dataset[dataKey] = String(dataValue);
      }
    } else {
      node.setAttribute(key, String(value));
    }
  }
  appendChildren(node, children);
  return node;
}

/** A document fragment, for returning several siblings without a wrapper div. */
export function frag(...children) {
  const fragment = document.createDocumentFragment();
  appendChildren(fragment, children);
  return fragment;
}

/** Empty a node. `textContent = ''` beats `innerHTML = ''` — no parser involved. */
export function clear(node) {
  node.textContent = '';
  return node;
}

/** Replace a node's contents in one operation. */
export function render(node, ...children) {
  clear(node);
  appendChildren(node, children);
  return node;
}

/** `document.getElementById`, throwing on a typo instead of returning null.
 *
 * A missing id used to surface three calls later as "cannot set textContent of
 * null", pointing at the wrong line. */
export function byId(id) {
  const node = document.getElementById(id);
  if (!node) throw new Error(`no element with id "${id}"`);
  return node;
}

export function qs(selector, root = document) {
  return root.querySelector(selector);
}

export function qsa(selector, root = document) {
  return Array.from(root.querySelectorAll(selector));
}

// ── Small composites the views all need ──────────────────────────────

/**
 * A table built from headers and row-producing data.
 *
 * @param {string[]} headers
 * @param {Array<Array<Node|string>>} rows
 * @param {object} [opts] `caption` for an accessible description, `empty` for
 *   the message shown instead of a zero-row body.
 */
export function table(headers, rows, opts = {}) {
  const head = el(
    'thead',
    {},
    el('tr', {}, ...headers.map((h) => el('th', { scope: 'col', text: h })))
  );

  const body = el('tbody');
  if (rows.length === 0) {
    body.appendChild(
      el(
        'tr',
        {},
        el('td', {
          colspan: String(headers.length),
          class: 'table-empty',
          text: opts.empty || 'Nothing to show.',
        })
      )
    );
  } else {
    for (const row of rows) {
      body.appendChild(
        el('tr', row.__props || {}, ...row.map((cell) => (cell instanceof Node && cell.tagName === 'TD' ? cell : el('td', {}, cell))))
      );
    }
  }

  const node = el('table', { class: opts.class || 'data-table' });
  if (opts.caption) node.appendChild(el('caption', { text: opts.caption }));
  node.appendChild(head);
  node.appendChild(body);
  return node;
}

/** A `<td>` with attributes, for rows that need per-cell classes. */
export function td(props, ...children) {
  return el('td', props, ...children);
}

/** A coloured pill. Used for results and severities, where the colour carries
 * meaning and must therefore also be stated in text (R11.4: colour is never the
 * only channel). */
export function pill(text, color, extraClass = '') {
  return el('span', {
    class: `pill ${extraClass}`.trim(),
    text,
    style: { '--pill-color': color },
  });
}

/** A labelled statistic. */
export function stat(label, value, opts = {}) {
  return el(
    'div',
    { class: `stat ${opts.class || ''}`.trim(), title: opts.title || null },
    el('div', { class: 'stat-label', text: label }),
    el('div', { class: 'stat-value', text: String(value) }),
    opts.hint ? el('div', { class: 'stat-hint', text: opts.hint }) : null
  );
}

/** `<code>` for a single command, with a copy button.
 *
 * The button is the reason remediation is worth showing in a UI at all — an
 * operator retyping a 60-command plan will make a typo in a config prompt. */
export function code(text, opts = {}) {
  const node = el('code', { class: `mono ${opts.class || ''}`.trim(), text });
  if (!opts.copy) return node;

  const button = el('button', {
    class: 'copy-btn',
    type: 'button',
    title: 'Copy to clipboard',
    'aria-label': `Copy: ${text}`,
    text: 'Copy',
    onclick: async (event) => {
      const btn = event.currentTarget;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = 'Copied';
      } catch {
        // Clipboard access is blocked over plain http on some browsers. Select
        // the text instead so the operator can copy it by hand rather than being
        // told nothing happened.
        const range = document.createRange();
        range.selectNodeContents(node);
        window.getSelection()?.removeAllRanges();
        window.getSelection()?.addRange(range);
        btn.textContent = 'Selected';
      }
      setTimeout(() => {
        btn.textContent = 'Copy';
      }, 1400);
    },
  });
  return el('span', { class: 'code-row' }, node, button);
}

/** A `<details>` block. Collapsed by default, because these views carry hundreds
 * of findings and an expanded-by-default list is a wall. */
export function details(summaryChildren, bodyChildren, opts = {}) {
  return el(
    'details',
    { class: opts.class || '', open: opts.open || false },
    el('summary', {}, ...[].concat(summaryChildren)),
    el('div', { class: 'details-body' }, ...[].concat(bodyChildren))
  );
}

/** Section heading plus optional subtitle. */
export function heading(title, subtitle = null, level = 'h3') {
  return el(
    'div',
    { class: 'section-heading' },
    el(level, { text: title }),
    subtitle ? el('p', { class: 'section-subtitle', text: subtitle }) : null
  );
}

/** The empty state. Says what would fill it, which the old dashboard's bare
 * "No data" never did. */
export function emptyState(message, hint = null) {
  return el(
    'div',
    { class: 'empty-state' },
    el('p', { text: message }),
    hint ? el('p', { class: 'empty-hint', text: hint }) : null
  );
}

/** A spinner with a label, so a slow fetch looks like work rather than a hang. */
export function spinner(label = 'Loading…') {
  return el(
    'div',
    { class: 'spinner-row', role: 'status', 'aria-live': 'polite' },
    el('span', { class: 'spinner', 'aria-hidden': 'true' }),
    el('span', { text: label })
  );
}

/** An inline error panel. Replaces `alert()`, which blocked the page, lost the
 * detail the API sent, and could not be styled or dismissed. */
export function errorPanel(message, detail = null) {
  return el(
    'div',
    { class: 'error-panel', role: 'alert' },
    el('strong', { text: message }),
    detail ? el('pre', { class: 'error-detail', text: detail }) : null
  );
}

/** Format a number with thin thousands separators. */
export function num(value) {
  return Number(value ?? 0).toLocaleString('en-US');
}

/** Format a 0..1 ratio as a percentage string. */
export function pct(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  return `${(Number(value) * 100).toFixed(digits)}%`;
}

/**
 * A number and its noun, agreeing.
 *
 * Every count in this UI used to read `10 device(s)`, `1 vendor(s)`, `42
 * catalog(s)`. That parenthesis is small and it is everywhere, and it is the
 * clearest possible signal that nobody read the screen back — an auditor being
 * told `1 record(s), hashes, links, Merkle roots and signatures all check out`
 * is reading a sentence written for the convenience of the code.
 *
 * Handles the regular English cases so a caller normally passes only the
 * singular: `-y` → `-ies` (`policy` → `policies`), sibilants → `-es` (`match` →
 * `matches`), otherwise `-s`. Anything irregular takes an explicit second
 * argument rather than growing a dictionary here.
 *
 * @param {number} value
 * @param {string} singular The noun as it appears after `1`.
 * @param {string} [plural] Override, for nouns the rules above get wrong.
 * @returns {string} e.g. `1 device`, `10 devices`, `1,311 controls`
 */
export function count(value, singular, plural = null) {
  const n = Number(value ?? 0);
  return `${num(n)} ${n === 1 ? singular : plural ?? pluralise(singular)}`;
}

/** The plural of an English noun, by the regular rules only. */
export function pluralise(singular) {
  const word = String(singular);
  // `-y` after a consonant inflects to `-ies`; after a vowel it does not
  // ("key" → "keys", not "kies"), which matters here because `key chain` is
  // real IOS configuration this UI displays.
  if (/[^aeiou]y$/i.test(word)) return `${word.slice(0, -1)}ies`;
  if (/(s|x|z|ch|sh)$/i.test(word)) return `${word}es`;
  return `${word}s`;
}

/**
 * Pick the form that agrees with a count.
 *
 * `count()` fixes the noun; this fixes everything downstream of it. Several of
 * these hints are whole sentences — "N findings rest on a setting being absent,
 * so they have no line to mark" — and pluralising only the noun leaves "1
 * finding rest on ... so they have", which reads worse than the `(s)` it
 * replaced. English verb agreement is irregular enough (is/are, has/have,
 * contains/contain) that both forms have to be written out.
 *
 * @param {number} value
 * @param {string} singular Form used when the count is exactly 1.
 * @param {string} plural Form used otherwise, including for 0.
 */
export function agree(value, singular, plural) {
  return Number(value ?? 0) === 1 ? singular : plural;
}

/** An ISO timestamp as something a person can read, falling back to the raw
 * string rather than printing "Invalid Date". */
export function when(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return date.toLocaleString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Shorten a hash for display while keeping both ends, so two different hashes
 * never look identical. */
export function shortHash(hash, head = 10, tail = 6) {
  const text = String(hash || '');
  if (text.length <= head + tail + 1) return text || '—';
  return `${text.slice(0, head)}…${text.slice(-tail)}`;
}
