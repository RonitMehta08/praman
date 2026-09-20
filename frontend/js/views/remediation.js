/**
 * The remediation plan — C4's "device-specific step-by-step remediation CLI".
 *
 * Until `GET /devices/{id}/remediation` existed this screen was impossible: the
 * only place remediation appeared was inside the PDF, so the UI could tell an
 * operator that a control failed and had no way to tell them what to type.
 *
 * The screen is built around three honesty properties the route enforces, because
 * an operator *executes* what is on this page:
 *
 * **Nothing is presented as runnable that isn't.** A command carrying a
 * placeholder is marked, its placeholders are listed, and the copy button still
 * copies the real text — because silently substituting a guess is how
 * `<LOCAL_USERNAME>` ends up in a running config.
 *
 * **Every command is cited.** `source` names the publisher's fix text it came
 * from. An uncited command is indistinguishable from one a model wrote, and R3
 * forbids model-authored CLI outright.
 *
 * **`manual` and `none` are answers.** Roughly two thirds of the corpus describes
 * its fix in prose, and a control nobody published a fix for says so rather than
 * rendering as an empty block a reader would take for "nothing to do".
 */

import { el, table, num, pct, when, pill, code, emptyState, shortHash, clear, count, agree } from '../dom.js';
import { page, panel, button, linkButton, navigate, select, toast, describeError } from '../shell.js';
import { resultColor, severityColor } from '../palette.js';
import * as api from '../api.js';

function kindPill(kind) {
  if (kind === 'cli') return pill('CLI', resultColor('fixed'), 'pill-tiny');
  if (kind === 'manual') return pill('manual steps', resultColor('informational'), 'pill-tiny');
  return pill('no published fix', resultColor('unknown'), 'pill-tiny pill-muted');
}

function entryCard(entry, index) {
  const runnable = (entry.steps || []).filter((step) => step.is_runnable).length;

  const head = el(
    'header',
    { class: 'fix-card-head' },
    el(
      'div',
      { class: 'fix-card-title' },
      el('span', { class: 'fix-index', text: String(index + 1) }),
      el(
        'div',
        {},
        el(
          'div',
          { class: 'fix-ids' },
          el('code', { class: 'mono', text: entry.control_id }),
          pill((entry.framework || '').replace(/_/g, ' '), resultColor('informational'), 'pill-tiny'),
          el('span', { class: 'mono dim', text: `${entry.benchmark || ''} ${entry.benchmark_version || ''}`.trim() })
        ),
        el('h4', { class: 'fix-title', text: entry.title || '(untitled control)' })
      )
    ),
    el(
      'div',
      { class: 'fix-card-badges' },
      pill(entry.severity || 'unknown', severityColor(entry.severity), entry.severity === 'unknown' ? 'pill-tiny pill-muted' : 'pill-tiny'),
      kindPill(entry.kind),
      entry.requires_substitution ? pill('needs your values', resultColor('unknown'), 'pill-tiny') : null,
      entry.risk && entry.risk !== 'unknown'
        ? pill(`risk: ${entry.risk}`, severityColor(entry.risk), 'pill-tiny')
        : pill('risk: not rated', resultColor('unknown'), 'pill-tiny pill-muted')
    )
  );

  const steps = (entry.steps || []).length
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
                  'Replace before running: ',
                  ...step.placeholders
                    .flatMap((placeholder, position) => [
                      position ? el('span', { text: ', ' }) : null,
                      el('code', { class: 'mono', text: placeholder }),
                    ])
                    .filter(Boolean)
                )
              : null
          )
        )
      )
    : null;

  const copyAll =
    runnable > 0
      ? button(
          `Copy ${num(runnable)} runnable command${runnable === 1 ? '' : 's'}`,
          async (event) => {
            const text = entry.steps
              .filter((step) => step.is_runnable)
              .map((step) => step.command)
              .join('\n');
            try {
              await navigator.clipboard.writeText(text);
              event.currentTarget.textContent = 'Copied';
              setTimeout(() => {
                event.currentTarget.textContent = `Copy ${num(runnable)} runnable command${runnable === 1 ? '' : 's'}`;
              }, 1500);
            } catch {
              toast('The browser blocked clipboard access.', 'warn', 'Select the commands and copy them by hand.');
            }
          },
          { class: 'btn-tiny btn-quiet' }
        )
      : null;

  return el(
    'article',
    { class: `fix-card fix-card-${entry.kind}` },
    head,
    entry.guidance ? el('p', { class: 'fix-guidance', text: entry.guidance }) : null,
    steps,
    copyAll ? el('div', { class: 'button-row' }, copyAll) : null,
    entry.verification
      ? el('div', { class: 'fix-aside' }, el('span', { class: 'fix-aside-label', text: 'Verify' }), code(entry.verification, { copy: true }))
      : null,
    entry.rollback
      ? el('div', { class: 'fix-aside' }, el('span', { class: 'fix-aside-label', text: 'Roll back' }), code(entry.rollback, { copy: true }))
      : null,
    entry.source ? el('p', { class: 'fix-source', text: `Source: ${entry.source}` }) : null,
    entry.notes?.length ? el('ul', { class: 'fix-notes' }, ...entry.notes.map((note) => el('li', { text: note }))) : null
  );
}

export async function remediationView({ outlet, params, query }) {
  const deviceId = params[0];
  if (!deviceId) {
    navigate('devices');
    return;
  }

  let scope = query?.results || 'fail';
  const auditId = query?.audit_id || null;

  const planHost = el('div', { class: 'fix-list' });
  const summaryHost = el('div', {});

  async function load() {
    clear(planHost);
    planHost.appendChild(el('div', { class: 'spinner-row' }, el('span', { class: 'spinner' }), el('span', { text: 'Resolving published fixes…' })));

    let body;
    try {
      body = await api.remediation(deviceId, { results: scope, ...(auditId ? { audit_id: auditId } : {}) });
    } catch (error) {
      const { message, detail } = describeError(error);
      clear(planHost);
      planHost.appendChild(el('div', { class: 'error-panel', role: 'alert' }, el('strong', { text: message }), detail ? el('pre', { class: 'error-detail', text: detail }) : null));
      return;
    }

    const counts = body.counts || {};
    clear(summaryHost);
    summaryHost.appendChild(
      panel(
        'Plan summary',
        el(
          'div',
          { class: 'stat-grid stat-grid-tight' },
          el('div', { class: 'stat' }, el('div', { class: 'stat-label', text: 'Controls' }), el('div', { class: 'stat-value', text: num(counts.controls) })),
          el('div', { class: 'stat' }, el('div', { class: 'stat-label', text: 'With CLI' }), el('div', { class: 'stat-value', text: num(counts.cli) })),
          el('div', { class: 'stat' }, el('div', { class: 'stat-label', text: 'Manual only' }), el('div', { class: 'stat-value', text: num(counts.manual) })),
          el('div', { class: 'stat' }, el('div', { class: 'stat-label', text: 'No published fix' }), el('div', { class: 'stat-value', text: num(counts.none) })),
          el('div', { class: 'stat' }, el('div', { class: 'stat-label', text: 'Commands' }), el('div', { class: 'stat-value', text: num(counts.commands) })),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Runnable as-is' }),
            el('div', { class: 'stat-value', text: num(counts.commands_runnable) }),
            el('div', {
              class: 'stat-hint',
              text: counts.commands
                ? `${pct(counts.commands_runnable / counts.commands, 0)} of the commands; the rest need a value from you`
                : '',
            })
          )
        ),
        el('p', { class: 'panel-note', text: `Basis: ${body.basis || '—'}` }),
        body.audit_id
          ? el('p', {
              class: 'panel-note',
              text: `Audit ${body.audit_id} (seq #${body.seq}), committed ${when(body.created_at)}. The same verdicts the PDF for this record renders.`,
            })
          : el('p', {
              class: 'panel-note',
              text: 'This device has no committed audit, so the plan is built from verdicts recomputed just now. The commands come from the published catalogs either way — nothing here needs a signature to be true.',
            }),
        counts.requires_substitution
          ? el('p', {
              class: 'panel-note panel-warn',
              text: `${count(counts.requires_substitution, 'control')} ${agree(counts.requires_substitution, 'contains', 'contain')} a placeholder you must replace with a value for this estate — a server address, a key name, an ACL number. ${agree(counts.requires_substitution, 'It is', 'They are')} marked in place and ${agree(counts.requires_substitution, 'is', 'are')} never counted as runnable.`,
            })
          : null
      )
    );

    clear(planHost);
    const plan = body.plan || [];
    if (plan.length === 0) {
      planHost.appendChild(
        emptyState(
          scope === 'fail' ? 'No failing controls on this device.' : 'No controls match this scope.',
          scope === 'fail'
            ? 'Every control a rule could decide passed. Widen the scope to see the published fix text for controls that already pass.'
            : null
        )
      );
      return;
    }
    plan.forEach((entry, index) => planHost.appendChild(entryCard(entry, index)));
  }

  const scopeSelect = select(
    'Scope',
    [
      ['fail', 'failing controls only'],
      ['all', 'every control, including those that pass'],
      ['fail,error,unknown', 'failing, errored and undetermined'],
    ],
    scope,
    (value) => {
      scope = value;
      load();
    }
  );

  await load();

  return void outlet.replaceChildren(
    page(
      'Remediation plan',
      'Device-specific fix commands, taken from the benchmark publishers’ own text',
      [
        linkButton('Signed PDF', api.reportUrl(deviceId, auditId ? { audit_id: auditId } : {}), { class: 'btn-quiet' }),
        button('Back to device', () => navigate('device', [deviceId]), { class: 'btn-quiet' }),
      ],
      panel(null, el('div', { class: 'filter-bar' }, scopeSelect)),
      summaryHost,
      planHost,
      panel(
        'How to read this',
        el(
          'ul',
          { class: 'note-list' },
          el('li', {
            text:
              'Commands are extracted from the benchmark publisher’s fix text and re-prompted for this device’s hostname. None of them is generated by a model — that is a hard architectural rule, because a plausible but wrong command is worse than no command when an operator pastes it.',
          }),
          el('li', {
            text:
              'A command shown in muted type carries a placeholder. Its copy button still copies the literal text, placeholder included, so nothing is silently guessed on your behalf.',
          }),
          el('li', {
            text:
              '"Manual steps" means the publisher wrote prose rather than commands for that control. "No published fix" means neither the catalogs nor the built-in playbook carries one — a gap in PRAMAN’s coverage, not a statement that the finding needs no action.',
          }),
          el('li', {
            text:
              'The order is worst severity first, so working top-to-bottom closes the high-risk gaps first rather than following control-id order.',
          }),
          el('li', {
            text:
              'Risk is reported as the publisher rated it, and "not rated" is shown as such. Some of these changes are disruptive; a fix CIS itself calls significant should not arrive labelled low.',
          })
        )
      )
    )
  );
}
