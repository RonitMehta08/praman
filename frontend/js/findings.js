/**
 * The findings table (§24 screen 3), reused by the device report (screen 4).
 *
 * Filterable by framework, severity and result, with the columns §24 asks for:
 * control_id, framework, benchmark_version, title, result, severity. Two things
 * beyond the spec earn their place.
 *
 * **Evidence drills down to `source_file:line_start`.** The old table rendered
 * evidence as `e.path || e.raw_text` — the canonical path, which tells an auditor
 * which field was examined but not where it came from. Six-field provenance is a
 * hard requirement precisely so a verdict can be traced to a line in a file, and
 * throwing away five of the six fields at the last hop wastes the whole chain.
 *
 * **Remediation is fetched, not promised.** The old table printed "Click to see
 * fix commands in the Training view remediation database", which was a pointer to
 * a feature that did not exist — the Training view has no such thing and there was
 * no endpoint to build one from. `GET /devices/{id}/remediation` now exists, so
 * expanding a failing control loads the real published fix for that control on
 * that device.
 *
 * Rendering is windowed. The shipped sample commits 1,462 findings; building 1,462
 * rows with an expandable panel each is a visible freeze, and an operator scrolls
 * the first thirty.
 */

import { el, table, td, pill, code, num, clear, emptyState, spinner } from './dom.js';
import { resultColor, severityColor, frameworkColor, RESULT_ORDER, SEVERITY_ORDER } from './palette.js';
import { button, select, textField, toast, describeError, navigate } from './shell.js';
import * as api from './api.js';

const PAGE_SIZE = 40;

function resultPill(result) {
  const value = String(result || 'unknown').toLowerCase();
  return pill(value, resultColor(value), `pill-result pill-${value}`);
}

function severityPill(severity) {
  const value = String(severity || 'unknown').toLowerCase();
  // `unknown` is deliberately not styled like a severity rung — it means nobody
  // rated this control, and dressing it as "low" would be an invented rating.
  return pill(value, severityColor(value), value === 'unknown' ? 'pill-muted' : 'pill-severity');
}

/** One evidence item, with its full provenance.
 *
 * `present: false` is rendered as an explicit statement rather than an empty cell.
 * Absence of evidence is the single most dangerous thing to render ambiguously
 * here: a blank row reads as "fine", when what it means is "the setting was not
 * found", which is usually why the control failed.
 */
function evidenceRow(item, onJump) {
  const present = item.present !== false;
  const location =
    item.source_file && Number(item.line_start) > 0
      ? `${item.source_file}:${item.line_start}${item.line_end && item.line_end !== item.line_start ? `-${item.line_end}` : ''}`
      : item.source_file || '—';

  return el(
    'div',
    { class: `evidence ${present ? '' : 'evidence-absent'}`.trim() },
    el(
      'div',
      { class: 'evidence-head' },
      el('code', { class: 'mono evidence-path', text: item.path || '(no canonical path)' }),
      present
        ? pill('found', resultColor('pass'), 'pill-tiny')
        : pill('not present', resultColor('unknown'), 'pill-tiny')
    ),
    present
      ? el(
          'div',
          { class: 'evidence-value' },
          el('span', { class: 'evidence-label', text: 'Value' }),
          el('code', { class: 'mono', text: item.value === null || item.value === undefined ? '(null)' : String(item.value) })
        )
      : el('p', {
          class: 'evidence-note',
          text: 'This setting was not found in the configuration. The control was decided on its absence.',
        }),
    item.raw_text
      ? el(
          'div',
          { class: 'evidence-value' },
          el('span', { class: 'evidence-label', text: 'Line' }),
          el('code', { class: 'mono', text: item.raw_text })
        )
      : null,
    el(
      'div',
      { class: 'evidence-provenance' },
      onJump && Number(item.line_start) > 0
        ? el('button', {
            class: 'link-btn mono',
            type: 'button',
            text: location,
            title: 'Open the configuration at this line',
            onclick: () => onJump(Number(item.line_start)),
          })
        : el('span', { class: 'mono', text: location }),
      el('span', { class: 'evidence-sep', text: '·' }),
      el('span', { text: `parser ${item.parser_id || 'unknown'}` }),
      el('span', { class: 'evidence-sep', text: '·' }),
      el('span', {
        text: `confidence ${item.confidence === undefined || item.confidence === null ? '—' : Number(item.confidence).toFixed(2)}`,
      })
    )
  );
}

/** The remediation block for one control, loaded on demand. */
function remediationBlock(entry) {
  if (!entry) return emptyState('No remediation entry was returned for this control.');

  const header = el(
    'div',
    { class: 'fix-header' },
    pill(entry.kind, entry.kind === 'cli' ? resultColor('fixed') : resultColor('informational'), 'pill-tiny'),
    entry.risk && entry.risk !== 'unknown'
      ? pill(`risk: ${entry.risk}`, severityColor(entry.risk), 'pill-tiny')
      : pill('risk: not rated', resultColor('unknown'), 'pill-tiny pill-muted'),
    entry.requires_substitution
      ? pill('needs your values', resultColor('unknown'), 'pill-tiny')
      : null
  );

  const steps = entry.steps?.length
    ? el(
        'ol',
        { class: 'fix-steps' },
        ...entry.steps.map((step) =>
          el(
            'li',
            { class: step.is_runnable ? 'fix-step' : 'fix-step fix-step-manual' },
            code(step.command, { copy: true }),
            el('div', { class: 'fix-prompt mono', text: step.prompt }),
            step.placeholders?.length
              ? el(
                  'p',
                  { class: 'fix-warn' },
                  'Substitute before running: ',
                  ...step.placeholders.flatMap((placeholder, index) => [
                    index ? el('span', { text: ', ' }) : null,
                    el('code', { class: 'mono', text: placeholder }),
                  ]).filter(Boolean)
                )
              : null
          )
        )
      )
    : null;

  return el(
    'div',
    { class: 'fix-block' },
    header,
    entry.guidance ? el('p', { class: 'fix-guidance', text: entry.guidance }) : null,
    steps,
    entry.verification
      ? el(
          'div',
          { class: 'fix-aside' },
          el('span', { class: 'fix-aside-label', text: 'Verify' }),
          code(entry.verification, { copy: true })
        )
      : null,
    entry.rollback
      ? el(
          'div',
          { class: 'fix-aside' },
          el('span', { class: 'fix-aside-label', text: 'Roll back' }),
          code(entry.rollback, { copy: true })
        )
      : null,
    entry.source ? el('p', { class: 'fix-source', text: `Source: ${entry.source}` }) : null,
    entry.notes?.length ? el('ul', { class: 'fix-notes' }, ...entry.notes.map((note) => el('li', { text: note }))) : null,
    entry.kind === 'cli'
      ? el('p', {
          class: 'fix-provenance',
          text: 'These commands are extracted from the benchmark publisher’s own fix text and rewritten for this device’s prompt. Nothing here is model-generated.',
        })
      : null
  );
}

/**
 * The table.
 *
 * @param {object} opts
 *   `findings` — the array.
 *   `deviceId` — enables remediation lookup; omit for `/simulate` output, which
 *     has no device row to resolve a plan against.
 *   `auditId` — pins remediation to a committed audit.
 *   `onJump(line)` — jump to the configuration viewer.
 *   `initial` — `{result, severity, framework, q}` starting filter.
 */
export function findingsTable(opts = {}) {
  const all = opts.findings || [];
  const filters = {
    result: opts.initial?.result || '',
    severity: opts.initial?.severity || '',
    framework: opts.initial?.framework || '',
    q: opts.initial?.q || '',
  };
  let limit = PAGE_SIZE;

  const host = el('div', { class: 'findings' });
  const tableHost = el('div', { class: 'findings-body' });
  const countHost = el('div', { class: 'findings-count' });

  const frameworks = [...new Set(all.map((f) => f.framework).filter(Boolean))].sort();
  const results = RESULT_ORDER.filter((value) =>
    all.some((f) => String(f.result || '').toLowerCase() === value)
  );
  const severities = SEVERITY_ORDER.filter((value) =>
    all.some((f) => String(f.severity || '').toLowerCase() === value)
  );

  function matching() {
    const needle = filters.q.trim().toLowerCase();
    return all.filter((finding) => {
      if (filters.result && String(finding.result || '').toLowerCase() !== filters.result) return false;
      if (filters.severity && String(finding.severity || '').toLowerCase() !== filters.severity) return false;
      if (filters.framework && finding.framework !== filters.framework) return false;
      if (needle) {
        const haystack = `${finding.control_id || ''} ${finding.title || ''} ${finding.rationale || ''} ${finding.benchmark || ''}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }

  /** Expandable detail for one finding: rationale, evidence, remediation. */
  function detailPanel(finding) {
    const body = el('div', { class: 'finding-detail' });

    if (finding.rationale) {
      body.appendChild(
        el(
          'div',
          { class: 'finding-section' },
          el('h5', { text: 'Why this verdict' }),
          el('p', { text: finding.rationale })
        )
      );
    }

    const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
    body.appendChild(
      el(
        'div',
        { class: 'finding-section' },
        el('h5', { text: `Evidence (${num(evidence.length)})` }),
        evidence.length
          ? el('div', { class: 'evidence-list' }, ...evidence.map((item) => evidenceRow(item, opts.onJump)))
          : el('p', {
              class: 'evidence-note',
              text:
                'No evidence was recorded for this finding. That is itself worth noting — a verdict with no ' +
                'evidence cannot be audited, and controls in this state are reported as notchecked rather than as passing.',
            })
      )
    );

    if (finding.references?.length) {
      body.appendChild(
        el(
          'div',
          { class: 'finding-section' },
          el('h5', { text: 'References' }),
          el('ul', { class: 'ref-list' }, ...finding.references.map((ref) => el('li', { class: 'mono', text: String(ref) })))
        )
      );
    }

    // Remediation, only where it means something: a failing control on a real
    // device. `/simulate` output has no device row, and a passing control's fix
    // text is reference material rather than an action.
    const result = String(finding.result || '').toLowerCase();
    if (opts.deviceId && result === 'fail') {
      const fixHost = el('div', { class: 'finding-section' }, el('h5', { text: 'Remediation' }), spinner('Resolving the published fix…'));
      body.appendChild(fixHost);

      api
        .remediation(opts.deviceId, {
          control_id: finding.control_id,
          results: 'all',
          ...(opts.auditId ? { audit_id: opts.auditId } : {}),
        })
        .then((plan) => {
          clear(fixHost);
          fixHost.appendChild(el('h5', { text: 'Remediation' }));
          const entry = (plan.plan || []).find((item) => item.control_id === finding.control_id) || plan.plan?.[0];
          fixHost.appendChild(remediationBlock(entry));
        })
        .catch((error) => {
          const { message, detail } = describeError(error);
          clear(fixHost);
          fixHost.appendChild(el('h5', { text: 'Remediation' }));
          fixHost.appendChild(el('p', { class: 'evidence-note', text: `${message} ${detail || ''}`.trim() }));
        });
    } else if (opts.deviceId && result !== 'fail') {
      body.appendChild(
        el(
          'div',
          { class: 'finding-section' },
          el('h5', { text: 'Remediation' }),
          el('p', {
            class: 'evidence-note',
            text: `This control is "${result}", so there is nothing to remediate. Open the device’s full remediation plan to see the published fix text anyway.`,
          }),
          button('Open the full plan', () => navigate('remediation', [opts.deviceId]), { class: 'btn-quiet' })
        )
      );
    }

    return body;
  }

  function draw() {
    const rows = matching();
    const shown = rows.slice(0, limit);

    clear(countHost);
    countHost.appendChild(
      el('span', {
        text:
          rows.length === all.length
            ? `${num(all.length)} finding${all.length === 1 ? '' : 's'}`
            : `${num(rows.length)} of ${num(all.length)} findings match`,
      })
    );

    clear(tableHost);
    if (rows.length === 0) {
      tableHost.appendChild(
        emptyState(
          'No findings match these filters.',
          all.length ? 'Clear a filter to widen the search.' : 'This device has no findings yet.'
        )
      );
      return;
    }

    const cells = shown.map((finding) => [
      el('code', { class: 'mono', text: finding.control_id || '—' }),
      pill((finding.framework || 'other').replace(/_/g, ' '), frameworkColor(finding.framework), 'pill-tiny'),
      el('span', { class: 'mono dim', text: finding.benchmark_version || '—' }),
      el('span', { class: 'finding-title', text: finding.title || '(untitled control)' }),
      resultPill(finding.result),
      severityPill(finding.severity),
    ]);

    const node = table(
      ['Control', 'Framework', 'Version', 'Title', 'Result', 'Severity'],
      cells,
      { class: 'data-table findings-table' }
    );

    // Each row gets an expandable sibling rather than a nested table, so the
    // detail can be as tall as it needs without breaking column alignment.
    const body = node.querySelector('tbody');
    Array.from(body.children).forEach((tr, index) => {
      const finding = shown[index];
      tr.classList.add('row-expandable');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-expanded', 'false');
      tr.setAttribute('aria-label', `${finding.control_id || ''} ${finding.title || ''} — ${finding.result}. Activate for evidence and remediation.`);

      const detailRow = el(
        'tr',
        { class: 'detail-row', hidden: true },
        td({ colspan: '6' })
      );
      let built = false;

      const toggle = () => {
        const open = detailRow.hidden;
        detailRow.hidden = !open;
        tr.setAttribute('aria-expanded', String(open));
        tr.classList.toggle('row-open', open);
        if (open && !built) {
          built = true;
          detailRow.firstChild.appendChild(detailPanel(finding));
        }
      };

      tr.addEventListener('click', toggle);
      tr.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggle();
        }
      });
      tr.after(detailRow);
    });

    tableHost.appendChild(node);

    if (rows.length > limit) {
      tableHost.appendChild(
        el(
          'div',
          { class: 'button-row' },
          button(`Show ${num(Math.min(PAGE_SIZE, rows.length - limit))} more`, () => {
            limit += PAGE_SIZE;
            draw();
          }),
          button(`Show all ${num(rows.length)}`, () => {
            limit = rows.length;
            draw();
          }, { class: 'btn-quiet' })
        )
      );
    }
  }

  const search = textField('Search', filters.q, (value) => {
    filters.q = value;
    limit = PAGE_SIZE;
    draw();
  }, { placeholder: 'control id, title or rationale', class: 'field-wide' });

  const bar = el(
    'div',
    { class: 'filter-bar' },
    search,
    select(
      'Result',
      [['', `all results (${num(all.length)})`], ...results.map((value) => [value, `${value} (${num(all.filter((f) => String(f.result).toLowerCase() === value).length)})`])],
      filters.result,
      (value) => {
        filters.result = value;
        limit = PAGE_SIZE;
        draw();
      }
    ),
    select(
      'Severity',
      [['', 'any severity'], ...severities.map((value) => [value, value])],
      filters.severity,
      (value) => {
        filters.severity = value;
        limit = PAGE_SIZE;
        draw();
      }
    ),
    select(
      'Framework',
      [['', 'all frameworks'], ...frameworks.map((value) => [value, value.replace(/_/g, ' ')])],
      filters.framework,
      (value) => {
        filters.framework = value;
        limit = PAGE_SIZE;
        draw();
      }
    ),
    button('Only failures', () => {
      filters.result = 'fail';
      filters.severity = '';
      filters.framework = '';
      filters.q = '';
      search.input.value = '';
      limit = PAGE_SIZE;
      redrawBar();
      draw();
    }, { class: 'btn-quiet' }),
    button('Clear', () => {
      filters.result = '';
      filters.severity = '';
      filters.framework = '';
      filters.q = '';
      search.input.value = '';
      limit = PAGE_SIZE;
      redrawBar();
      draw();
    }, { class: 'btn-quiet' })
  );

  function redrawBar() {
    // The selects are uncontrolled; after a programmatic filter change their
    // displayed value would otherwise disagree with the table.
    const selects = bar.querySelectorAll('select');
    selects[0].value = filters.result;
    selects[1].value = filters.severity;
    selects[2].value = filters.framework;
  }

  host.appendChild(bar);
  host.appendChild(countHost);
  host.appendChild(tableHost);
  draw();

  host.setFilter = (next) => {
    Object.assign(filters, next);
    limit = PAGE_SIZE;
    redrawBar();
    draw();
  };

  return host;
}

export { remediationBlock };
