/**
 * The device roster.
 *
 * Sortable, searchable, and honest about what has not been committed. A device
 * with facts but no ledger record is a different thing from an audited device, and
 * the column says so rather than leaving the reader to infer it from a blank.
 */

import { el, table, num, when, pill, emptyState, shortHash, count, agree } from '../dom.js';
import { store, page, panel, button, navigate, linkButton, textField, toast, describeError } from '../shell.js';
import { mayCommit, needsRole } from '../auth.js';
import { resultColor } from '../palette.js';
import * as api from '../api.js';

export async function devicesView({ outlet }) {
  const body = await store.devices();
  const devices = body.devices || [];

  let filter = '';
  let sortKey = 'ingested_at';
  let sortDesc = true;

  const tableHost = el('div', {});

  function sorted() {
    const needle = filter.trim().toLowerCase();
    const rows = devices.filter((device) => {
      if (!needle) return true;
      return `${device.hostname || ''} ${device.device_id} ${device.vendor || ''} ${device.os_family || ''} ${device.source_file || ''}`
        .toLowerCase()
        .includes(needle);
    });
    rows.sort((a, b) => {
      const left = a[sortKey] ?? '';
      const right = b[sortKey] ?? '';
      const cmp = typeof left === 'number' && typeof right === 'number' ? left - right : String(left).localeCompare(String(right));
      return sortDesc ? -cmp : cmp;
    });
    return rows;
  }

  async function commit(deviceId, btn) {
    btn.disabled = true;
    btn.textContent = 'Committing…';
    try {
      const result = await api.commit(deviceId);
      store.invalidateAfterWrite();
      toast(
        `Committed as seq #${result.seq}.`,
        'success',
        `${num(result.findings_count)} findings, Merkle root ${shortHash(result.merkle_root)}. The record is signed and chained to its predecessor.`
      );
      navigate('device', [deviceId]);
    } catch (error) {
      const { message, detail } = describeError(error);
      toast(message, 'error', detail);
      btn.disabled = false;
      btn.textContent = 'Commit audit';
    }
  }

  function draw() {
    const rows = sorted().map((device) => {
      const audited = Boolean(device.latest_audit_id);
      return [
        el('button', {
          class: 'link-btn',
          type: 'button',
          text: device.hostname || '(no hostname)',
          onclick: () => navigate('device', [device.device_id]),
        }),
        el('span', { text: `${device.vendor || '—'}${device.os_family ? ` / ${device.os_family}` : ''}` }),
        el('span', { class: 'mono dim', text: device.os_version || '—' }),
        el('span', { text: num(device.facts_count) }),
        audited
          ? pill(`seq #${device.latest_seq}`, resultColor('pass'), 'pill-tiny')
          : pill('not committed', resultColor('notchecked'), 'pill-tiny pill-muted'),
        el('span', { class: 'dim', text: when(device.ingested_at) }),
        el(
          'div',
          { class: 'row-actions' },
          audited
            ? linkButton('PDF', api.reportUrl(device.device_id), { class: 'btn-tiny', download: `${device.hostname || device.device_id}.pdf` })
            : null,
          el('button', {
            class: 'btn btn-tiny',
            type: 'button',
            text: audited ? 'Re-commit' : 'Commit audit',
            disabled: !mayCommit(),
            title: !mayCommit()
              ? needsRole('approver', 'Committing an audit')
              : audited
                ? 'Evaluate the stored facts against the current rules and append a new ledger record'
                : 'Write the first immutable audit record for this device',
            onclick: (event) => commit(device.device_id, event.currentTarget),
          })
        ),
      ];
    });

    tableHost.replaceChildren(
      rows.length
        ? table(
            ['Hostname', 'Vendor', 'OS version', 'Facts', 'Latest audit', 'Ingested', ''],
            rows,
            { caption: `${num(rows.length)} of ${num(devices.length)} devices.` }
          )
        : emptyState('No device matches that search.')
    );
  }

  const search = textField('Filter', '', (value) => {
    filter = value;
    draw();
  }, { placeholder: 'hostname, vendor, or source file', class: 'field-wide' });

  draw();

  const uncommitted = devices.filter((device) => !device.latest_audit_id);

  return void outlet.replaceChildren(
    page(
      'Devices',
      `${num(devices.length)} ingested`,
      [button('Upload more', () => navigate('upload'))],
      devices.length === 0
        ? panel(
            null,
            emptyState(
              'No devices yet.',
              'Upload a configuration from the Upload view. Sample configurations ship under test_configs/, and the Simulate view has three inline samples you can run without storing anything.'
            )
          )
        : panel(
            null,
            el('div', { class: 'filter-bar' }, search, ...sortControls()),
            tableHost,
            uncommitted.length
              ? el('p', {
                  class: 'panel-note',
                  text: `${count(uncommitted.length, 'device')} ${agree(uncommitted.length, 'has', 'have')} facts stored but no committed audit. Ingesting is not auditing — until you commit, there is no signed record and no PDF.`,
                })
              : null
          )
    )
  );

  function sortControls() {
    const keys = [
      ['ingested_at', 'ingested'],
      ['hostname', 'hostname'],
      ['vendor', 'vendor'],
      ['facts_count', 'facts'],
      ['latest_seq', 'latest audit'],
    ];
    return [
      el(
        'div',
        { class: 'field' },
        el('span', { class: 'field-label', text: 'Sort by' }),
        el(
          'div',
          { class: 'button-row' },
          ...keys.map(([key, label]) =>
            el('button', {
              class: `btn btn-tiny ${sortKey === key ? 'btn-active' : 'btn-quiet'}`,
              type: 'button',
              text: sortKey === key ? `${label} ${sortDesc ? '↓' : '↑'}` : label,
              onclick: (event) => {
                if (sortKey === key) sortDesc = !sortDesc;
                else {
                  sortKey = key;
                  sortDesc = true;
                }
                draw();
                event.currentTarget.closest('.filter-bar').replaceChildren(search, ...sortControls());
              },
            })
          )
        )
      ),
    ];
  }
}
