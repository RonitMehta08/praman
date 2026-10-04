/**
 * Screen 4 — the device report, and screen 8's configuration view.
 *
 * The cover block carries device identity because C4 asks for it by name:
 * hostname, vendor, OS version, **serial numbers and hardware**. Two of those are
 * empty on every device PRAMAN has ingested, and the panel says so in as many
 * words. A running-config does not contain a chassis serial — that comes from
 * `show version` / `show inventory` — so a blank field here is a missing capture,
 * not a missing feature, and rendering it as an empty cell would let a reader
 * assume the device has no serial.
 *
 * The configuration panel is a reconstruction, and labelled as one. The original
 * file is deliberately not retained: only its hash, plus the `raw_text` and line
 * span of each line that produced a fact. So what can be shown is every line the
 * parser understood, at its real line number, with the gaps marked — which is
 * enough to open at `source_file:line_start` and see the offending line in
 * context, and is not the same thing as showing the file.
 *
 * Verdicts on this screen are **recomputed from the stored facts**, which is the
 * right answer to "where do I stand" and the wrong answer to "what did we conclude
 * in March". The audit history is there for the second question, and each row
 * links to the PDF of that record.
 */

import {
  el, table, num, pct, when, pill, emptyState, shortHash, count, agree,
} from '../dom.js';
import {
  store, page, panel, button, linkButton, navigate, refresh, toast, describeError,
} from '../shell.js';
import { mayCommit, needsRole } from '../auth.js';
import { findingsTable } from '../findings.js';
import { configViewer, marksFromFindings, viewerLegend } from '../configview.js';
import {
  complianceGauge, resultDistribution, severityBars, frameworkStackedBars, trendLine,
} from '../charts.js';
import { resultColor } from '../palette.js';
import * as api from '../api.js';

/** Rebuild a viewable configuration from the facts that came out of it.
 *
 * Facts can share a line and can span several, so lines are collected into a map
 * first and the widest `raw_text` for a line wins — a fact spanning three lines
 * carries all three in its `raw_text`, and that is more of the file than a
 * single-line fact from the same block.
 */
function reconstruct(facts) {
  const lines = new Map();
  for (const fact of facts) {
    const start = Number(fact.line_start);
    if (!(start > 0) || !fact.raw_text) continue;
    const text = String(fact.raw_text);
    const pieces = text.replace(/\r\n?/g, '\n').split('\n');
    pieces.forEach((piece, offset) => {
      const lineNumber = start + offset;
      const existing = lines.get(lineNumber);
      if (existing === undefined || piece.length > existing.length) lines.set(lineNumber, piece);
    });
  }

  if (lines.size === 0) return { text: '', firstLine: 1, coverage: 0, gaps: 0 };

  const numbers = [...lines.keys()].sort((a, b) => a - b);
  const last = numbers[numbers.length - 1];
  const out = [];
  let gaps = 0;
  for (let line = 1; line <= last; line += 1) {
    if (lines.has(line)) {
      out.push(lines.get(line));
    } else {
      out.push('');
      gaps += 1;
    }
  }
  return { text: out.join('\n'), firstLine: numbers[0], coverage: lines.size / last, gaps };
}

function identityRow(label, value, missingNote) {
  const empty = value === null || value === undefined || value === '' || (Array.isArray(value) && value.length === 0);
  return [
    label,
    empty
      ? el('span', { class: 'dim', text: missingNote || 'not captured' })
      : el('span', { class: 'mono', text: Array.isArray(value) ? value.join(', ') : String(value) }),
  ];
}

export async function deviceView({ outlet, params, query }) {
  const deviceId = params[0];
  if (!deviceId) {
    navigate('devices');
    return;
  }

  const detail = await api.device(deviceId);
  const device = detail.device || {};
  const findings = detail.findings || [];
  const facts = detail.facts || [];
  const audits = detail.audits || [];
  const latest = audits[0];

  const rebuilt = reconstruct(facts);
  const { marks, absent } = marksFromFindings(findings, { only: ['fail', 'pass', 'error', 'unknown'] });

  const viewer = configViewer(rebuilt.text, {
    marks,
    sourceFile: device.source_file || 'configuration',
    redacted: true,
    focusLine: query?.line ? Number(query.line) : null,
  });

  const jump = (line) => {
    viewer.focusLine(line);
    viewer.scrollIntoView({ block: 'center', behavior: 'smooth' });
  };

  const findingsHost = findingsTable({
    findings,
    deviceId,
    auditId: latest?.audit_id,
    onJump: jump,
    initial: { result: query?.result || 'fail' },
  });

  const identity = table(
    ['Field', 'Value'],
    [
      identityRow('Hostname', device.hostname),
      identityRow('Device id', device.device_id),
      identityRow('Vendor', device.vendor),
      identityRow('OS family', device.os_family),
      identityRow('OS version', device.os_version),
      identityRow(
        'Serial numbers',
        device.serials,
        'not in a running-config — needs a `show version` or `show inventory` capture'
      ),
      identityRow(
        'Hardware',
        device.hardware,
        'not in a running-config — needs a `show version` or `show inventory` capture'
      ),
      identityRow('Source file', device.source_file),
      ['Config hash', el('code', { class: 'mono', text: shortHash(device.config_hash, 16, 8) })],
      identityRow('Ingested', when(device.ingested_at)),
      ['Canonical facts', el('span', { text: num(facts.length) })],
    ],
    { class: 'data-table compact' }
  );

  const commitButton = el('button', {
    class: 'btn',
    type: 'button',
    text: audits.length ? 'Commit a new audit' : 'Commit audit',
    disabled: !mayCommit(),
    // A greyed-out button is a courtesy; the 403 on the route is the control.
    title: mayCommit()
      ? 'Evaluate the stored facts and append a signed, chained record to the ledger'
      : needsRole('approver', 'Committing an audit'),
    onclick: async (event) => {
      const btn = event.currentTarget;
      btn.disabled = true;
      btn.textContent = 'Committing…';
      try {
        const result = await api.commit(deviceId);
        store.invalidateAfterWrite();
        toast(
          `Committed as seq #${result.seq}.`,
          'success',
          `${num(result.findings_count)} findings sealed under Merkle root ${shortHash(result.merkle_root)}.`
        );
        // Re-run the route so the history table, the PDF link and the trend all
        // reflect the new record rather than being patched in place. `navigate`
        // alone would be a no-op — the hash has not changed.
        await refresh();
      } catch (error) {
        const { message, detail: reason } = describeError(error);
        toast(message, 'error', reason);
        btn.disabled = false;
        btn.textContent = 'Commit audit';
      }
    },
  });

  const taught = detail.taught_facts || [];

  const trendPoints = audits
    .map((audit) => {
      const byResult = audit.summary?.by_result || {};
      const passed = Number(byResult.pass || 0);
      const failed = Number(byResult.fail || 0);
      return passed + failed === 0
        ? null
        : { seq: audit.seq, score: (passed / (passed + failed)) * 100, hostname: device.hostname, passed, failed };
    })
    .filter(Boolean);

  return void outlet.replaceChildren(
    page(
      device.hostname || deviceId,
      `${device.vendor || 'unknown vendor'}${device.os_family ? ` / ${device.os_family}` : ''}${device.os_version ? ` ${device.os_version}` : ''}`,
      [
        latest
          ? linkButton('Download signed PDF', api.reportUrl(deviceId, { audit_id: latest.audit_id }), {
              download: `${device.hostname || deviceId}-audit-${latest.seq}.pdf`,
            })
          : null,
        latest
          ? linkButton('Export OSCAL', api.oscalUrl(deviceId, { audit_id: latest.audit_id }), {
              class: 'btn-quiet',
              download: `praman-${device.hostname || deviceId}-seq${latest.seq}.oscal.json`,
            })
          : null,
        button('Remediation plan', () => navigate('remediation', [deviceId])),
        commitButton,
      ].filter(Boolean),

      latest
        ? null
        : panel(
            null,
            el(
              'div',
              { class: 'notice' },
              el('strong', { text: 'This device has no committed audit.' }),
              el('p', {
                text:
                  'The verdicts below are computed from the stored facts against the rules loaded right now. ' +
                  'They are real, but nothing has been signed or written to the ledger, so there is no PDF and ' +
                  'nothing an auditor could later verify. Commit an audit to create that record.',
              })
            )
          ),

      panel(
        'Compliance',
        el(
          'div',
          { class: 'chart-grid' },
          complianceGauge(detail.score || {}),
          resultDistribution(detail.summary || {}),
          severityBars(findings),
          frameworkStackedBars(findings)
        ),
        el('p', {
          class: 'panel-note',
          text:
            'Computed from the current facts and the currently loaded rules — not read back from the ledger. ' +
            'This is the right answer to "where do I stand today"; for what was concluded at a point in time, ' +
            'open the record in the audit history below.',
        })
      ),

      panel('Device identity', identity),

      panel(`Findings (${num(findings.length)})`, findingsHost),

      panel(
        'Configuration',
        el('p', {
          class: 'panel-note',
          text:
            'Reconstructed from the lines that produced canonical facts. The original file is not retained — only ' +
            `its hash — so lines the parser did not recognise are blank here. ${count(facts.length, 'fact')} ${agree(facts.length, 'covers', 'cover')} ` +
            `${pct(rebuilt.coverage)} of the line range${rebuilt.gaps ? `, leaving ${count(rebuilt.gaps, 'unrecognised or blank line')}` : ''}.`,
        }),
        viewerLegend(),
        rebuilt.text ? viewer : emptyState('No fact carries a line number, so nothing can be reconstructed.'),
        absent.length
          ? el('p', {
              class: 'panel-note',
              text:
                `${count(absent.length, 'finding')} ${agree(absent.length, 'rests', 'rest')} on a setting being absent, so ${agree(absent.length, 'it has', 'they have')} no line to mark.`,
            })
          : null
      ),

      taught.length
        ? panel(
            `Facts from taught mappings (${num(taught.length)})`,
            el('p', {
              class: 'panel-note',
              text:
                'These facts exist because an admin mapped a line format in the Training view. They were produced ' +
                'without a code change or a redeploy — the parser picked the mapping up on the next parse.',
            }),
            table(
              ['Canonical path', 'Value', 'Line', 'Parser'],
              taught.map((fact) => [
                el('code', { class: 'mono', text: fact.path }),
                el('code', { class: 'mono', text: fact.value === null ? '(null)' : String(fact.value) }),
                el('button', {
                  class: 'link-btn mono',
                  type: 'button',
                  text: `${fact.source_file}:${fact.line_start}`,
                  onclick: () => jump(Number(fact.line_start)),
                }),
                el('span', { class: 'mono dim', text: fact.parser_id }),
              ]),
              { class: 'data-table compact' }
            )
          )
        : null,

      audits.length
        ? panel(
            `Audit history (${num(audits.length)})`,
            trendPoints.length >= 2 ? trendLine(trendPoints) : null,
            table(
              ['Seq', 'Committed', 'Approved by', 'Findings', 'Fail', 'Record hash', 'Merkle root', ''],
              audits.map((audit) => {
                const byResult = audit.summary?.by_result || {};
                return [
                  el('code', { class: 'mono', text: `#${audit.seq}` }),
                  el('span', { class: 'dim', text: when(audit.created_at) }),
                  // `actor` is inside the signed, hashed record, so this is not a
                  // label beside the evidence — it is part of it. A record whose
                  // actor no longer resolves to an operator row makes the
                  // standalone verifier report INCOMPLETE rather than pass.
                  el('span', { class: 'mono dim', text: audit.actor || 'unattributed' }),
                  el('span', { text: num(audit.summary?.total ?? 0) }),
                  Number(byResult.fail || 0) > 0
                    ? pill(num(byResult.fail), resultColor('fail'), 'pill-tiny')
                    : pill('0', resultColor('pass'), 'pill-tiny'),
                  el('code', { class: 'mono dim', text: shortHash(audit.record_hash) }),
                  el('code', { class: 'mono dim', text: shortHash(audit.merkle_root) }),
                  el(
                    'div',
                    { class: 'row-actions' },
                    linkButton('PDF', api.reportUrl(deviceId, { audit_id: audit.audit_id }), {
                      class: 'btn-tiny',
                      download: `${device.hostname || deviceId}-audit-${audit.seq}.pdf`,
                    }),
                    linkButton('OSCAL', api.oscalUrl(deviceId, { audit_id: audit.audit_id }), {
                      class: 'btn-tiny btn-quiet',
                      download: `praman-${device.hostname || deviceId}-seq${audit.seq}.oscal.json`,
                    }),
                    button('Plan', () => navigate('remediation', [deviceId], { audit_id: audit.audit_id }), {
                      class: 'btn-tiny btn-quiet',
                    })
                  ),
                ];
              }),
              {
                caption:
                  'Newest first. Each record is signed and chained to the one before it, and the approver named ' +
                  'here is covered by that signature.',
              }
            ),
            el('p', {
              class: 'panel-note',
              text:
                'The PDF for a given record renders the verdicts as they were committed, not as they would be ' +
                'computed today. That is what makes it evidence.',
            })
          )
        : null
    )
  );
}
