/**
 * Screen 7 — the ledger.
 *
 * The whole value of an append-only hash-chained ledger is that someone other
 * than the tool can check it, so this screen's job is to show the *result of a
 * check*, not a reassuring green badge. Four links are verified independently and
 * reported independently, because they fail for different reasons and conflating
 * them destroys the diagnostic value:
 *
 * - `merkle_valid` — the findings still hash to the committed root. The only link
 *   that covers the verdicts themselves.
 * - `hash_valid` — the record's own fields hash to its stored hash.
 * - `chain_valid` — `prev_hash` matches the previous record. Catches a removed,
 *   reordered or spliced record.
 * - `signature_valid` — Ed25519 over the record hash.
 *
 * `/audit/verify` returns a fifth check that is *not* a link in that chain, and
 * this screen renders it on the same terms:
 *
 * - `actor_valid` — the recorded operator resolves to somebody this deployment
 *   issued. The chain already stops an actor being edited; only the roster can
 *   say the name means anything.
 *
 * Rendering four of five was this screen's own defect, not a backend gap. The
 * payload carried `actor_valid` and the table had no column for it, so a record
 * that failed *only* its actor check was listed under "do not verify" with an
 * empty "What failed" cell — the page reported a failure and then declined to
 * say what it was, which is worse than not checking.
 *
 * `merkle_valid: null` is rendered as "not checked", never as a tick. An
 * unchecked link displayed as sound is the exact failure the ledger exists to
 * prevent.
 *
 * A failing record is also not automatically evidence of tampering, and the page
 * says so: a record committed under an earlier hash definition cannot verify under
 * the current one. That is a migration problem, and quietly presenting it as
 * "tampered" would cost an operator a day.
 */

import { el, table, num, when, pill, emptyState, spinner, clear, shortHash, code, count } from '../dom.js';
import { store, page, panel, button, navigate, toast, describeError } from '../shell.js';
import { trendLine } from '../charts.js';
import { resultColor, NODE_STATUS_COLORS } from '../palette.js';
import * as api from '../api.js';

/** A tri-state check cell: true, false, or "not checked". */
function checkPill(value, labels) {
  if (value === true) return pill(labels[0], resultColor('pass'), 'pill-tiny');
  if (value === false) return pill(labels[1], resultColor('fail'), 'pill-tiny');
  return pill('not checked', resultColor('notchecked'), 'pill-tiny pill-muted');
}

/** The actor check, whose label is the operator's own name.
 *
 * One column rather than two, because "who committed this" and "is that a real
 * operator" are not separately actionable: a name that resolves to nobody is not
 * a weaker attribution, it is a different finding. Carrying the name inside the
 * pill also keeps this column scannable beside the four link checks instead of
 * adding an eleventh.
 *
 * An empty actor is spelled out rather than shown as a blank red pill. It means
 * the record predates operator identity, which is a migration to run and not a
 * person to go looking for.
 */
function actorPill(value, actor) {
  if (value === true) return pill(actor, resultColor('pass'), 'pill-tiny');
  if (value === false) {
    return pill(actor || 'no actor', resultColor('fail'), 'pill-tiny');
  }
  return pill(actor || 'not checked', resultColor('notchecked'), 'pill-tiny pill-muted');
}

/** The chain as a strip of linked blocks — the shape is the point.
 *
 * Not a chart: there is no quantity here, only sequence and adjacency. Each block
 * shows its seq and the head of its hash, and the connector between two blocks is
 * coloured by whether that specific link verified, so a break is visible at the
 * link rather than only in a table row.
 */
function chainStrip(records, byseq) {
  if (records.length === 0) return null;

  const blocks = [];
  records.forEach((record, index) => {
    const check = byseq.get(record.seq) || {};
    const broken = check.all_valid === false;

    if (index > 0) {
      const linkOk = check.chain_valid !== false;
      blocks.push(
        el('span', {
          class: `chain-link ${linkOk ? '' : 'chain-link-broken'}`.trim(),
          title: linkOk
            ? `prev_hash of #${record.seq} matches #${records[index - 1].seq}`
            : `prev_hash of #${record.seq} does not match #${records[index - 1].seq} — a record may have been removed, reordered or spliced in`,
          text: linkOk ? '→' : '⇸',
        })
      );
    }

    blocks.push(
      el(
        'span',
        {
          class: `chain-block ${broken ? 'chain-block-broken' : ''}`.trim(),
          style: { '--block-color': broken ? NODE_STATUS_COLORS.red : NODE_STATUS_COLORS.green },
          title: `${check.detail || 'verified'}\n${record.record_hash}`,
          tabindex: '0',
          role: 'listitem',
        },
        el('span', { class: 'chain-seq', text: `#${record.seq}` }),
        el('span', { class: 'chain-hash mono', text: shortHash(record.record_hash, 6, 4) })
      )
    );
  });

  return el(
    'div',
    { class: 'chain-strip', role: 'list', 'aria-label': 'The audit chain, oldest first' },
    ...blocks
  );
}

export async function ledgerView({ outlet }) {
  const bannerHost = el('div', {});
  const bodyHost = el('div', {});

  async function load() {
    clear(bodyHost);
    bodyHost.appendChild(spinner('Recomputing every hash, Merkle root and signature…'));

    const [recordBody, devicesBody] = await Promise.all([api.auditRecords(), store.devices()]);
    let verification = null;
    let verifyError = null;
    try {
      verification = await api.auditVerify();
    } catch (error) {
      verifyError = error;
    }

    const records = recordBody.records || [];
    const hostnames = new Map((devicesBody.devices || []).map((device) => [device.device_id, device.hostname]));
    const byseq = new Map((verification?.results || []).map((entry) => [entry.seq, entry]));

    drawBanner(records, verification, verifyError);
    drawBody(records, verification, verifyError, hostnames, byseq);
  }

  function drawBanner(records, verification, verifyError) {
    clear(bannerHost);

    if (verifyError) {
      const { message, detail } = describeError(verifyError);
      bannerHost.appendChild(
        panel(
          null,
          el(
            'div',
            { class: 'notice notice-bad', role: 'alert' },
            el('strong', { text: 'The ledger could not be verified.' }),
            el('p', { text: `${message} ${detail || ''}`.trim() }),
            el('p', {
              text: 'Treat this as unverified, not as verified. Nothing below should be relied on as evidence until the check completes.',
            })
          )
        )
      );
      return;
    }

    const broken = (verification.results || []).filter((entry) => entry.all_valid === false);
    // Any link the backend declined to check, not just the Merkle root. Counting
    // only `merkle_valid` here would let an unresolved actor — a ledger with no
    // `users` table — read as fully checked, which is the same overclaim the
    // tri-state pills exist to avoid.
    const unchecked = (verification.results || []).filter(
      (entry) => entry.merkle_valid === null || entry.actor_valid === null
    );
    const intact = verification.all_valid === true && records.length > 0;

    bannerHost.appendChild(
      panel(
        null,
        el(
          'div',
          { class: `notice ${intact ? 'notice-good' : broken.length ? 'notice-bad' : ''}`.trim(), role: 'status' },
          el('strong', {
            text: records.length === 0
              ? 'The ledger is empty.'
              : intact
                ? `All ${num(verification.chain_length)} records verify.`
                : `${num(broken.length)} of ${num(verification.chain_length)} records do not verify.`,
          }),
          el('p', {
            text: records.length === 0
              ? 'No audit has been committed yet. Commit one from a device view to write the first record.'
              : intact
                ? 'Every record hash, chain link, Ed25519 signature and Merkle root over the findings was recomputed just now and matches what was committed, and every recorded operator resolves to somebody this deployment issued. Nothing has been altered since it was written.'
                : 'The failures are listed below with the specific link that broke. Read the note on superseded hash definitions before concluding that anything was tampered with.',
          }),
          unchecked.length
            ? el('p', {
                text: `${count(unchecked.length, 'record')} had a link this check could not recompute — findings missing for a Merkle root, or no operator roster to resolve the actor against — so that link is reported as unchecked rather than as sound.`,
              })
            : null
        )
      )
    );
  }

  function drawBody(records, verification, verifyError, hostnames, byseq) {
    clear(bodyHost);

    if (records.length === 0) {
      bodyHost.appendChild(
        panel(
          null,
          emptyState(
            'Nothing in the ledger yet.',
            'Upload a configuration, then commit an audit. Each commit appends one signed record chained to the one before it.'
          ),
          el('div', { class: 'button-row' }, button('Go to Upload', () => navigate('upload')))
        )
      );
      return;
    }

    const trendPoints = records
      .map((record) => {
        const byResult = record.summary?.by_result || {};
        const passed = Number(byResult.pass || 0);
        const failed = Number(byResult.fail || 0);
        if (passed + failed === 0) return null;
        return {
          seq: record.seq,
          score: (passed / (passed + failed)) * 100,
          hostname: hostnames.get(record.device_id) || record.device_id,
          passed,
          failed,
        };
      })
      .filter(Boolean);

    const rows = records
      .slice()
      .reverse()
      .map((record) => {
        const check = byseq.get(record.seq) || {};
        const byResult = record.summary?.by_result || {};
        return [
          el('code', { class: 'mono', text: `#${record.seq}` }),
          el('button', {
            class: 'link-btn',
            type: 'button',
            text: hostnames.get(record.device_id) || record.device_id,
            onclick: () => navigate('device', [record.device_id]),
          }),
          el('span', { class: 'dim', text: when(record.created_at) }),
          el('span', { text: num(record.summary?.total ?? 0) }),
          Number(byResult.fail || 0) > 0
            ? pill(num(byResult.fail), resultColor('fail'), 'pill-tiny')
            : pill('0', resultColor('pass'), 'pill-tiny'),
          checkPill(check.merkle_valid, ['findings intact', 'findings altered']),
          checkPill(check.hash_valid, ['hash ok', 'hash mismatch']),
          checkPill(check.chain_valid, ['linked', 'link broken']),
          checkPill(check.signature_valid, ['signed', 'bad signature']),
          actorPill(check.actor_valid, check.actor ?? record.actor ?? ''),
          el('code', { class: 'mono dim', title: record.record_hash, text: shortHash(record.record_hash) }),
        ];
      });

    const failing = (verification?.results || []).filter((entry) => entry.all_valid === false);

    bodyHost.appendChild(
      panel(
        'The chain',
        el('p', {
          class: 'panel-note',
          text:
            'Oldest first. Each block carries the head of its own record hash; each connector is the previous ' +
            'record’s hash stored inside the next one. Removing or reordering a record breaks the connector, which is ' +
            'what makes the ledger append-only in practice rather than by policy.',
        }),
        chainStrip(records, byseq)
      )
    );

    if (failing.length) {
      bodyHost.appendChild(
        panel(
          `Records that do not verify (${num(failing.length)})`,
          table(
            ['Seq', 'What failed', 'Detail'],
            failing.map((entry) => [
              el('code', { class: 'mono', text: `#${entry.seq}` }),
              el(
                'div',
                { class: 'check-set' },
                entry.merkle_valid === false ? pill('findings', resultColor('fail'), 'pill-tiny') : null,
                entry.hash_valid === false ? pill('record hash', resultColor('fail'), 'pill-tiny') : null,
                entry.chain_valid === false ? pill('chain link', resultColor('fail'), 'pill-tiny') : null,
                entry.signature_valid === false ? pill('signature', resultColor('fail'), 'pill-tiny') : null,
                entry.actor_valid === false ? pill('actor', resultColor('fail'), 'pill-tiny') : null
              ),
              el('span', { text: entry.detail || '' }),
            ]),
            { class: 'data-table compact' }
          ),
          el('p', {
            class: 'panel-note panel-warn',
            text:
              'A failing record is not by itself proof of tampering. The most common cause in a development database ' +
              'is a record committed under an earlier definition of the record hash: the bytes are original, but the ' +
              'current definition hashes them differently, so it cannot match. Re-seeding the demo ledger clears ' +
              'those; MANUAL_COMMANDS.md carries the step, and it is destructive, so it is deliberately not automatic.',
          })
        )
      );
    }

    bodyHost.appendChild(
      panel(
        `Records (${num(records.length)})`,
        table(
          ['Seq', 'Device', 'Committed', 'Findings', 'Fail', 'Findings hash', 'Record hash', 'Chain', 'Signature', 'Actor', 'Hash head'],
          rows,
          { caption: 'Newest first. Every check was recomputed by this request, not read from a stored flag.' }
        )
      )
    );

    if (trendPoints.length >= 2) {
      bodyHost.appendChild(
        panel(
          'Score across the ledger',
          trendLine(trendPoints, { title: 'Score over audits' }),
          el('p', {
            class: 'panel-note',
            text:
              'One point per committed record, in ledger order — so this is the estate’s history across devices, not ' +
              'one device improving. Per-device history is on the device page.',
          })
        )
      );
    }

    bodyHost.appendChild(
      panel(
        'What is actually signed',
        el(
          'ul',
          { class: 'note-list' },
          el('li', { text: 'The findings of an audit are hashed into a Merkle tree, and only the root goes into the record. So the verdicts are covered by the chain without the ledger having to store them twice — and altering one finding changes the root.' }),
          el('li', { text: 'The record hash covers the audit id, device id, config hash, timestamp, committing operator, summary, sequence number, previous hash and Merkle root. Altering a timestamp or a count breaks it.' }),
          el('li', { text: 'The operator’s name is one of those nine fields, so who committed an audit is covered by the same signature as the verdicts rather than sitting beside them in a table anyone could edit. The chain cannot say the name means anything, though, so it is separately resolved against the operator roster — that is the fifth check, and it is not a link in the chain.' }),
          el('li', { text: 'The signature is Ed25519 over the record hash. It proves the record was written by the holder of the signing key, which in this build is a key file on disk — a real deployment would hold it in an HSM or a KMS, and that gap is documented rather than hidden.' }),
          el('li', { text: 'Verification here runs inside the same process that wrote the records, which is convenient and is not independent. A verifier that reads the SQLite file and the public key with no PRAMAN code in the loop is the honest form of this check.' })
        )
      )
    );
  }

  await load();

  return void outlet.replaceChildren(
    page(
      'Ledger',
      'Append-only, hash-chained, signed — and re-verified on every visit',
      [
        button('Re-verify now', async (event) => {
          const btn = event.currentTarget;
          btn.disabled = true;
          btn.textContent = 'Verifying…';
          try {
            store.invalidate('records');
            await load();
            toast('Re-verified.', 'success');
          } catch (error) {
            const { message, detail } = describeError(error);
            toast(message, 'error', detail);
          } finally {
            btn.disabled = false;
            btn.textContent = 'Re-verify now';
          }
        }),
      ],
      bannerHost,
      bodyHost
    )
  );
}
