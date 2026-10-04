/** The approver-only access log.
 *
 * Reads are an audited capability too: the log answers who opened sensitive
 * device evidence, not only who changed the ledger. It lives as a first-class
 * workspace screen so the API surface is not hidden behind database tooling.
 */

import { el, table, num, count, when } from '../dom.js';
import { page, panel, button, textField, navigate, toast, describeError } from '../shell.js';
import * as api from '../api.js';

function statusClass(status) {
  const code = Number(status);
  return code >= 500 ? 'pill-bad' : code >= 400 ? 'pill-warn' : 'pill-ok';
}

export async function accessView({ outlet }) {
  let actor = '';
  let filterTimer = null;
  let requestSerial = 0;
  let body = { entries: [], count: 0, total: 0 };
  const host = el('div', {});
  const filter = textField('Filter by operator', '', (value) => {
    window.clearTimeout(filterTimer);
    filterTimer = window.setTimeout(() => {
      actor = value.trim();
      load();
    }, 220);
  }, { placeholder: 'username (optional)', class: 'field-narrow' });

  filter.input.setAttribute('aria-describedby', 'access-filter-note');

  async function load() {
    const serial = ++requestSerial;
    host.replaceChildren(el('div', { class: 'spinner-row', role: 'status' }, el('span', { class: 'spinner' }), el('span', { text: 'Reading access events…' })));
    try {
      const next = await api.accessLog(actor ? { actor } : {});
      if (serial !== requestSerial) return;
      body = next;
      draw();
    } catch (error) {
      if (serial !== requestSerial) return;
      const { message, detail } = describeError(error);
      toast(message, 'error', detail);
      host.replaceChildren(el('div', { class: 'error-panel', role: 'alert' }, el('strong', { text: message }), detail ? el('pre', { class: 'error-detail', text: detail }) : null));
    }
  }

  function draw() {
    const entries = body.entries || [];
    const rows = entries.map((entry) => [
      el('span', { class: 'mono', text: entry.actor || 'anonymous' }),
      el('span', { class: 'mono', text: `${entry.method || '—'} ${entry.path || '—'}` }),
      el('span', { class: `pill ${statusClass(entry.status)}`, text: String(entry.status ?? '—') }),
      el('span', { text: `${num(entry.duration_ms || 0)} ms` }),
      el('span', { class: 'dim', text: when(entry.at) }),
      el('span', { class: 'mono dim', text: entry.client || '—' }),
    ]);
    host.replaceChildren(
      panel(
        `Recent activity — ${count(entries.length, 'event')}`,
        table(['Operator', 'Request', 'Status', 'Duration', 'When', 'Client'], rows, {
          caption: `${num(body.total || 0)} total access events. Newest first.`,
          class: 'data-table access-table',
          empty: 'No access events match this operator filter.',
        }),
        el('p', { class: 'panel-note', text: 'Protected reads and writes are recorded server-side. This view is itself approver-only.' })
      )
    );
  }

  await load();
  return void outlet.replaceChildren(
    page(
      'Access log',
      'A review trail for who read or changed protected evidence',
      [button('Refresh', load), button('Ledger', () => navigate('ledger'), { class: 'btn-quiet' })],
      panel(
        null,
        el('div', { class: 'filter-bar' }, filter),
        el('p', { class: 'panel-note', id: 'access-filter-note', text: 'Filter is applied on the server. The log is retained separately from the signed ledger, because looking is not the same act as committing.' })
      ),
      host
    )
  );
}
