/**
 * The configuration viewer — line-numbered, tokenised, and addressable by line.
 *
 * §24.1 specifies Monaco with a custom Cisco Monarch grammar. Monaco is a ~4 MB
 * npm dependency that has to be bundled, and this project ships without a build
 * step so it works the moment uvicorn starts (the deviation and its rationale are
 * recorded in the architecture doc). What the screen actually has to do is
 * narrower than what an editor does: show the config, colour it enough that
 * structure is visible, and open at `source_file:line_start` with the offending
 * line marked. That is a tokeniser and an anchor, not an editor.
 *
 * The token rules are the eight verified Cisco IOS patterns from §24.1, applied in
 * the same order Monarch would apply them, so the two implementations agree about
 * what a token is. Case-insensitive throughout, matching `ignoreCase: true`.
 *
 * Nothing is highlighted by string substitution into markup. Each token becomes a
 * `<span>` with `textContent`, which is the only reason it is safe to render a
 * file we did not write.
 */

import { el, svg, clear } from './dom.js';

/**
 * Ordered token rules. First match at a position wins, exactly as Monarch
 * resolves its `tokenizer.root` array.
 *
 * The secret rules come before the generic ones because `password 7 08…` must be
 * recognised as a secret with a type digit, not as a keyword followed by a number.
 * Anchors are stripped relative to the scan position rather than the line start,
 * so `^` in the source spec becomes "at the cursor".
 */
const RULES = [
  // A comment or a bang divider — the whole rest of the line.
  { type: 'comment', re: /^\s*!.*$/i },
  // Banner delimiters introduce free text that is not configuration.
  { type: 'banner', re: /^(banner)(\s+)(motd|login|exec|incoming)/i },
  // `password 7 <hash>` / `secret 5 <hash>` — keyword, type digit, then the value.
  { type: 'secret', re: /^\b(password|secret|key|md5)(\s+)(\d)(\s+)(\S+)/i },
  // Type-0 (cleartext) secrets. Called out separately because a cleartext secret
  // is itself a finding, and it should not look like an encrypted one.
  { type: 'secret-clear', re: /^\b(password|secret)(\s+)(0\s+)?([^\s!]+)$/i },
  // Interfaces, ethernet family first so `GigabitEthernet0/1` does not fall
  // through to the generic rule and lose its unit path.
  {
    type: 'interface',
    re: /^\b((?:Ten|Forty|Hundred)?GigabitEthernet|FastEthernet|Ethernet|TwentyFiveGigE|FortyGigE|HundredGigE)(\s*)([\d/.:]+)/i,
  },
  { type: 'interface', re: /^\b(Loopback|Vlan|Port-channel|Tunnel|Serial|Dialer|BVI|Management)(\s*)([\d/.:]+)/i },
  // IPv4 addresses and prefixes.
  { type: 'address', re: /^\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/i },
  // Everything else that is word-shaped.
  { type: 'keyword', re: /^\b(no|ip|ipv6|line|interface|router|aaa|snmp-server|logging|ntp|crypto|access-list|username|enable|service|hostname|version|end|exit|vty|con|aux|transport|login|exec-timeout|authentication|authorization|accounting|new-model|http|https|server|community|host|source-interface|key|chain|key-string|description|shutdown|switchport|spanning-tree|vlan|standby|tacacs|radius|domain|name-server|route|banner|privilege|secret|password|encryption|tcp|udp|permit|deny|any|log|in|out)\b/i },
  { type: 'number', re: /^\b\d+\b/i },
  { type: 'string', re: /^"[^"]*"/i },
];

/** Split one line into typed tokens. */
function tokenise(line) {
  const tokens = [];
  let rest = line;
  let guard = 0;

  while (rest.length > 0 && guard++ < 400) {
    let matched = null;
    for (const rule of RULES) {
      const match = rule.re.exec(rest);
      if (match && match[0].length > 0) {
        matched = { type: rule.type, text: match[0] };
        break;
      }
    }
    if (matched) {
      tokens.push(matched);
      rest = rest.slice(matched.text.length);
      continue;
    }
    // No rule applied. Consume one run of non-word characters or one word so the
    // loop always advances — `defaultToken` is non-empty in the Monarch spec for
    // the same reason: an unmatched character must still be emitted, not dropped.
    const plain = /^(\s+|[^\s\w]+|\w+)/.exec(rest);
    const text = plain ? plain[0] : rest[0];
    tokens.push({ type: 'plain', text });
    rest = rest.slice(text.length);
  }
  if (rest.length) tokens.push({ type: 'plain', text: rest });
  return tokens;
}

function lineNode(text, lineNumber, marks) {
  const mark = marks.get(lineNumber);
  const row = el('div', {
    class: `cfg-line ${mark ? `cfg-mark cfg-mark-${mark.kind}` : ''}`.trim(),
    id: `cfg-line-${lineNumber}`,
    dataset: { line: String(lineNumber) },
  });

  row.appendChild(el('span', { class: 'cfg-gutter', 'aria-hidden': 'true', text: String(lineNumber) }));

  const content = el('span', { class: 'cfg-text' });
  if (text.length === 0) {
    content.appendChild(document.createTextNode('​'));
  } else {
    for (const token of tokenise(text)) {
      content.appendChild(
        token.type === 'plain'
          ? document.createTextNode(token.text)
          : el('span', { class: `tok tok-${token.type}`, text: token.text })
      );
    }
  }
  row.appendChild(content);

  if (mark) {
    row.appendChild(
      el('span', {
        class: `cfg-badge cfg-badge-${mark.kind}`,
        text: mark.label,
        title: mark.title || mark.label,
      })
    );
  }
  return row;
}

/**
 * Build a viewer.
 *
 * @param {string} text The configuration.
 * @param {object} [opts]
 *   `marks`: `Map<lineNumber, {kind, label, title}>` — the offending lines.
 *   `focusLine`: scroll to and flash this line once mounted.
 *   `sourceFile`: shown in the header, since a finding cites `file:line`.
 *   `redacted`: note that secrets were replaced before storage.
 */
export function configViewer(text, opts = {}) {
  const marks = opts.marks || new Map();
  const lines = String(text ?? '').replace(/\r\n?/g, '\n').split('\n');

  const body = el('div', { class: 'cfg-body', role: 'group', 'aria-label': 'Configuration text' });
  lines.forEach((line, index) => body.appendChild(lineNode(line, index + 1, marks)));

  const markCount = marks.size;
  const header = el(
    'div',
    { class: 'cfg-header' },
    el('span', { class: 'cfg-file mono', text: opts.sourceFile || 'configuration' }),
    el('span', { class: 'cfg-meta', text: `${lines.length} line${lines.length === 1 ? '' : 's'}` }),
    markCount
      ? el('span', { class: 'cfg-meta cfg-meta-bad', text: `${markCount} flagged line${markCount === 1 ? '' : 's'}` })
      : null,
    opts.redacted
      ? el('span', {
          class: 'cfg-meta',
          text: 'secrets redacted at ingest',
          title: 'Passwords and keys were replaced before this text was stored, so the value shown is not the value configured.',
        })
      : null
  );

  const wrapper = el('div', { class: 'cfg-viewer' }, header, body);

  /** Scroll a line into view and flash it. */
  wrapper.focusLine = (lineNumber) => {
    const target = body.querySelector(`#cfg-line-${lineNumber}`);
    if (!target) return false;
    target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    target.classList.add('cfg-flash');
    setTimeout(() => target.classList.remove('cfg-flash'), 1600);
    return true;
  };

  if (opts.focusLine) {
    // After paint, or `scrollIntoView` runs against a zero-height container.
    requestAnimationFrame(() => wrapper.focusLine(Number(opts.focusLine)));
  }

  return wrapper;
}

/**
 * Build the mark map from findings and the facts they cite.
 *
 * A finding does not carry a line number; its evidence does. So the mapping is
 * finding → evidence → `line_start`, which is also why a finding whose evidence is
 * an absent fact cannot be marked: there is no line to point at, because the
 * problem is that the line is missing. Those are collected separately rather than
 * quietly discarded, since "nothing to highlight" and "the absence is the finding"
 * are different statements.
 */
export function marksFromFindings(findings, opts = {}) {
  const marks = new Map();
  const absent = [];

  for (const finding of findings) {
    const result = String(finding.result || '').toLowerCase();
    if (opts.only && !opts.only.includes(result)) continue;

    const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
    const located = evidence.filter((item) => Number(item?.line_start) > 0);

    if (located.length === 0) {
      absent.push(finding);
      continue;
    }

    for (const item of located) {
      const line = Number(item.line_start);
      const kind = result === 'fail' ? 'fail' : result === 'pass' ? 'pass' : 'other';
      const existing = marks.get(line);
      // A failure outranks a pass on the same line: if one control is unhappy
      // with a line, that is the thing the operator needs to see.
      if (!existing || (kind === 'fail' && existing.kind !== 'fail')) {
        marks.set(line, {
          kind,
          label: finding.control_id || result,
          title: `${finding.control_id || ''} ${finding.title || ''} — ${result}`.trim(),
        });
      }
    }
  }

  return { marks, absent };
}

/** A legend for the mark colours, since a coloured stripe alone is not a label. */
export function viewerLegend() {
  return el(
    'ul',
    { class: 'chart-legend cfg-legend' },
    el('li', {}, el('span', { class: 'legend-swatch swatch-fail', 'aria-hidden': 'true' }), el('span', { text: 'a control failed on this line' })),
    el('li', {}, el('span', { class: 'legend-swatch swatch-pass', 'aria-hidden': 'true' }), el('span', { text: 'a control passed on this line' })),
    el('li', {}, el('span', { class: 'legend-swatch swatch-other', 'aria-hidden': 'true' }), el('span', { text: 'cited by a non-verdict result' }))
  );
}

export { clear, svg };
