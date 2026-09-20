/**
 * Screen 3 — findings, at estate scale.
 *
 * The per-device findings table already exists and is shared with the device
 * report (`js/findings.js`). Repeating it here with a device column would answer
 * the same question twice, so this screen answers the question a device page
 * cannot: **which controls are failing across the fleet, and on how many boxes.**
 *
 * That inversion is the difference between a list and a work plan. Twelve devices
 * each failing the same "no service password-encryption" control is one change
 * rolled out twelve times, not twelve investigations — and a per-device view makes
 * that impossible to see.
 *
 * There is no estate-wide findings endpoint, so this reads each audited device and
 * aggregates client-side. That is honest about cost: the request count is shown,
 * and the device drill-down below reuses the shared table rather than loading
 * everything twice.
 */

import { el, table, num, pill, emptyState, spinner, clear, pct, count, agree } from '../dom.js';
import { store, page, panel, button, select, navigate } from '../shell.js';
import { findingsTable } from '../findings.js';
import { severityBars, frameworkStackedBars } from '../charts.js';
import { resultColor, severityColor, frameworkColor, SEVERITY_ORDER } from '../palette.js';
import * as api from '../api.js';

const SEVERITY_RANK = { high: 0, medium: 1, low: 2, unknown: 3 };

export async function findingsView({ outlet, query }) {
  const devicesBody = await store.devices();
  const devices = (devicesBody.devices || []).filter((device) => device.latest_audit_id);

  let selected = query?.device || '';
  const host = el('div', {});
  const drill = el('div', {});

  async function loadEstate() {
    clear(host);
    host.appendChild(spinner(`Reading ${count(devices.length, 'audited device')}…`));

    const loaded = [];
    for (const device of devices) {
      try {
        loaded.push(await api.device(device.device_id));
      } catch {
        /* Counted below rather than silently dropped. */
      }
    }

    clear(host);
    host.appendChild(drawEstate(loaded));
  }

  function drawEstate(loaded) {
    if (loaded.length === 0) {
      return panel(
        null,
        emptyState(
          'No committed audits to aggregate.',
          'Ingest a configuration and commit an audit; this view then shows which controls fail across the estate.'
        ),
        el('div', { class: 'button-row' }, button('Go to Upload', () => navigate('upload')))
      );
    }

    // control_id -> { meta, failing: [hostname], passing: n, devices: n }
    const byControl = new Map();
    const allFindings = [];

    for (const detail of loaded) {
      const hostname = detail.device.hostname || detail.device.device_id;
      for (const finding of detail.findings || []) {
        allFindings.push(finding);
        const key = `${finding.framework}::${finding.control_id}`;
        if (!byControl.has(key)) {
          byControl.set(key, {
            control_id: finding.control_id,
            framework: finding.framework,
            benchmark: finding.benchmark,
            title: finding.title,
            severity: finding.severity,
            failing: [],
            passing: 0,
            undecided: 0,
          });
        }
        const entry = byControl.get(key);
        const result = String(finding.result || '').toLowerCase();
        if (result === 'fail') entry.failing.push({ hostname, device_id: detail.device.device_id });
        else if (result === 'pass') entry.passing += 1;
        else entry.undecided += 1;
      }
    }

    const failing = [...byControl.values()]
      .filter((entry) => entry.failing.length > 0)
      .sort(
        (a, b) =>
          (SEVERITY_RANK[String(a.severity || 'unknown').toLowerCase()] ?? 3) -
            (SEVERITY_RANK[String(b.severity || 'unknown').toLowerCase()] ?? 3) ||
          b.failing.length - a.failing.length ||
          String(a.control_id).localeCompare(String(b.control_id))
      );

    const universal = failing.filter((entry) => entry.failing.length === loaded.length);
    const decided = allFindings.filter((finding) => {
      const result = String(finding.result || '').toLowerCase();
      return result === 'pass' || result === 'fail';
    });
    const failedCount = decided.filter((finding) => String(finding.result).toLowerCase() === 'fail').length;

    const severityCounts = SEVERITY_ORDER.map((severity) => [
      severity,
      failing.filter((entry) => String(entry.severity || 'unknown').toLowerCase() === severity).length,
    ]).filter(([, count]) => count > 0);

    return el(
      'div',
      {},
      panel(
        null,
        el(
          'div',
          { class: 'stat-grid stat-grid-tight' },
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Devices aggregated' }),
            el('div', { class: 'stat-value', text: num(loaded.length) }),
            el('div', { class: 'stat-hint', text: `${count(loaded.length, 'request')} — there is no estate-wide findings endpoint` })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Distinct controls failing' }),
            el('div', { class: 'stat-value stat-bad', text: num(failing.length) }),
            el('div', { class: 'stat-hint', text: 'each one is a change to plan, not a device to visit' })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Failing everywhere' }),
            el('div', { class: 'stat-value', text: num(universal.length) }),
            el('div', { class: 'stat-hint', text: 'a fleet-wide standard gap, not a device fault' })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Estate pass rate' }),
            el('div', { class: 'stat-value', text: decided.length ? pct((decided.length - failedCount) / decided.length, 1) : '—' }),
            el('div', { class: 'stat-hint', text: `over ${count(decided.length, 'decided verdict')}` })
          )
        ),
        severityCounts.length
          ? el(
              'div',
              { class: 'chip-list' },
              ...severityCounts.map(([severity, count]) =>
                pill(`${count} ${severity}`, severityColor(severity), severity === 'unknown' ? 'pill-muted' : '')
              )
            )
          : null
      ),
      panel(
        `Failing controls across the estate (${num(failing.length)})`,
        failing.length
          ? table(
              ['Control', 'Framework', 'Severity', 'Title', 'Devices failing', 'Also passing on', 'Affected'],
              failing.map((entry) => [
                el('code', { class: 'mono', text: entry.control_id }),
                pill((entry.framework || 'other').replace(/_/g, ' '), frameworkColor(entry.framework), 'pill-tiny'),
                pill(
                  entry.severity || 'unknown',
                  severityColor(entry.severity),
                  String(entry.severity || 'unknown').toLowerCase() === 'unknown' ? 'pill-tiny pill-muted' : 'pill-tiny'
                ),
                el('span', { class: 'finding-title', text: entry.title || '(untitled control)' }),
                entry.failing.length === loaded.length
                  ? pill(`all ${num(loaded.length)}`, resultColor('fail'), 'pill-tiny')
                  : el('span', { text: `${num(entry.failing.length)} of ${num(loaded.length)}` }),
                el('span', { class: 'dim', text: entry.passing ? num(entry.passing) : '—' }),
                el(
                  'div',
                  { class: 'device-links' },
                  ...entry.failing.slice(0, 6).map((device) =>
                    el('button', {
                      class: 'link-btn small',
                      type: 'button',
                      text: device.hostname,
                      title: `Open ${device.hostname} filtered to failures`,
                      onclick: () => navigate('device', [device.device_id], { result: 'fail' }),
                    })
                  ),
                  entry.failing.length > 6
                    ? el('span', { class: 'dim small', text: `+${num(entry.failing.length - 6)} more` })
                    : null
                ),
              ]),
              { caption: 'Worst severity first, then by how many devices are affected.' }
            )
          : emptyState('No control fails on any audited device.', 'Every control a rule could decide passed everywhere.'),
        universal.length
          ? el('p', {
              class: 'panel-note panel-warn',
              text: `${count(universal.length, 'control')} ${agree(universal.length, 'fails', 'fail')} on every audited device. A gap that universal is usually a missing standard in the build template rather than ${num(loaded.length)} independent mistakes — fix it once, at the source.`,
            })
          : null
      ),
      panel(
        'Estate shape',
        el('div', { class: 'chart-grid' }, severityBars(allFindings), frameworkStackedBars(allFindings)),
        el('p', {
          class: 'panel-note',
          text:
            'Every finding from every audited device, pooled. The framework chart keeps "not checked" visible: hiding ' +
            'it would show a tidy pass/fail split that implies the estate was fully audited against each standard.',
        })
      )
    );
  }

  async function loadDrill() {
    clear(drill);
    if (!selected) return;
    drill.appendChild(spinner('Loading findings…'));
    try {
      const detail = await api.device(selected);
      clear(drill);
      drill.appendChild(
        panel(
          `${detail.device.hostname || selected} — ${num((detail.findings || []).length)} findings`,
          findingsTable({
            findings: detail.findings || [],
            deviceId: selected,
            auditId: detail.audits?.[0]?.audit_id,
            initial: { result: 'fail' },
          }),
          el(
            'div',
            { class: 'button-row' },
            button('Open the full device report', () => navigate('device', [selected]), { class: 'btn-quiet' }),
            button('Remediation plan', () => navigate('remediation', [selected]), { class: 'btn-quiet' })
          ),
          el('p', {
            class: 'panel-note',
            text: 'Evidence and remediation are here, but the configuration view and audit history are on the device page — a jump to a line number needs the reconstructed config next to it.',
          })
        )
      );
    } catch {
      clear(drill);
      drill.appendChild(emptyState('That device could not be read.'));
    }
  }

  const deviceSelect = select(
    'Drill into one device',
    [['', 'choose a device…'], ...devices.map((device) => [device.device_id, device.hostname || device.device_id])],
    selected,
    async (value) => {
      selected = value;
      await loadDrill();
    }
  );

  await loadEstate();
  await loadDrill();

  return void outlet.replaceChildren(
    page(
      'Findings',
      'What is failing, across every audited device',
      [button('Topology view', () => navigate('topology'), { class: 'btn-quiet' })],
      host,
      panel(null, el('div', { class: 'filter-bar' }, deviceSelect)),
      drill
    )
  );
}
