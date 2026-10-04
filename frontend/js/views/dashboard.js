/**
 * The overview.
 *
 * Three things on the old dashboard were not merely rough, they were false. The
 * pass-rate tile was hardcoded to `'—'` and never computed. The chain-integrity
 * tile was hardcoded to `'—'` while `/audit/verify` sat there returning a real
 * verdict. And `#framework-bars` was an empty div that no code ever filled, so the
 * page had a labelled space where a chart was supposed to be. All three now read
 * from the API.
 *
 * The AI tile also stops lying. The old code set "AI: Online" from the mere fact
 * that a request succeeded, then separately issued a `POST /simulate` carrying a
 * fake `_status_probe.conf` to discover which tiers were up — a full parse, rule
 * evaluation and drain3 pass on every page load, whose unknown lines then landed
 * in the training queue for an admin to dismiss. `/health` has carried
 * `ai.tiers` the whole time.
 */

import { el, table, num, pct, when, emptyState, stat, shortHash, count } from '../dom.js';
import { store, page, panel, button, navigate, toast } from '../shell.js';
import { frameworkStackedBars, resultDistribution, trendLine, severityBars } from '../charts.js';
import * as api from '../api.js';
import { overviewHero, workflowLinks } from '../experience.js';

/** Score from a ledger record's summary.
 *
 * Mirrors `score_from_counts` in `backend/rules/evaluator.py`: pass over
 * pass-plus-fail, with everything undecided excluded. Recomputed here rather than
 * stored per record so the trend cannot disagree with the gauge; if the backend
 * definition ever changes, `tests/test_frontend_contract.py` fails.
 */
function scoreFromSummary(summary) {
  const byResult = summary?.by_result || {};
  const passed = Number(byResult.pass || 0);
  const failed = Number(byResult.fail || 0);
  if (passed + failed === 0) return null;
  return (passed / (passed + failed)) * 100;
}

/** One tier row. `note` is the tier's constant; `state` overrides "loaded".
 *
 * Tier 3 is the only one whose answer can be stale — the other three are a file
 * that either exists or does not, checked on the spot. Tier 3 is a running server
 * behind a cached probe with a 30 s TTL while it is down, so a red dot there can
 * mean "we last looked 28 seconds ago". Showing the age turns the one transition
 * an operator makes deliberately — starting llama-server, MANUAL_COMMANDS.md
 * Step 6 — from "Step 6 did not work" into "wait, or reload". */
function tierRow(label, up, note, state) {
  return el(
    'li',
    { class: `tier ${up ? 'tier-up' : 'tier-down'}` },
    el('span', { class: 'tier-dot', 'aria-hidden': 'true' }),
    el('span', { class: 'tier-name', text: label }),
    el('span', { class: 'tier-state', text: state || (up ? 'loaded' : 'not loaded') }),
    note ? el('span', { class: 'tier-note', text: note }) : null
  );
}

/** "not reachable · checked 12s ago", or the plain state if there is no age.
 *
 * Absent rather than zero when the field is missing: an older backend that does
 * not send it should read as "no freshness information", not as "checked just
 * now", which would be a claim the response never made.
 *
 * `weights` separates the two reasons tier 3 can be down, because they are two
 * different jobs for the operator: a 2.4 GB download, or starting a server whose
 * model is already on disk. A single "not loaded" badge sends someone who has
 * finished the download back to the download. */
function llmState(up, ageSeconds, weights) {
  const base = up ? 'reachable' : weights === false ? 'no weights on disk' : 'not reachable';
  if (up === false && weights === false) return base;
  if (typeof ageSeconds !== 'number' || !Number.isFinite(ageSeconds)) return base;
  const age = ageSeconds < 1 ? 'just now' : `${Math.round(ageSeconds)}s ago`;
  return `${base} · checked ${age}`;
}

export async function dashboardView({ outlet }) {
  // Fired together: they are independent, and serialising four round trips is how
  // a local dashboard ends up feeling slow.
  const [health, devicesBody, recordsBody, verify] = await Promise.all([
    store.health(),
    store.devices(),
    store.auditRecords(),
    api.auditVerify().catch((error) => ({ __error: error })),
  ]);

  const devices = devicesBody.devices || [];
  const records = recordsBody.records || [];
  const runtime = health.runtime || {};
  const tiers = health.ai?.tiers || {};

  // Estate posture comes from the committed ledger, not from re-evaluating every
  // device: the ledger is what was signed, and it is one request instead of N.
  const estate = { pass: 0, fail: 0, total: 0 };
  // Severity of *failures* only. Older ledger records predate the field, so a
  // missing `by_severity_failing` leaves this empty and the chart is simply
  // absent — the alternative, falling back to the summary's `by_severity`, would
  // silently restore the bug this field exists to fix. That field counts every
  // finding including passes and the `notchecked` majority, and charting it
  // reported 16,082 "failing controls" on an estate with 372 failures.
  const failingSeverity = {};
  for (const record of records) {
    const byResult = record.summary?.by_result || {};
    estate.pass += Number(byResult.pass || 0);
    estate.fail += Number(byResult.fail || 0);
    estate.total += Number(record.summary?.total || 0);
    for (const [severity, count] of Object.entries(record.summary?.by_severity_failing || {})) {
      failingSeverity[severity] = (failingSeverity[severity] || 0) + Number(count);
    }
  }
  const decided = estate.pass + estate.fail;
  const estateScore = decided ? (estate.pass / decided) * 100 : null;

  const chainOk = verify.__error ? null : verify.all_valid;
  const chainBroken = verify.__error
    ? null
    : (verify.results || []).filter((entry) => !entry.all_valid).length;

  const tiles = el(
    'div',
    { class: 'stat-grid' },
    stat('Devices ingested', num(devices.length), {
      hint: devices.length ? count(new Set(devices.map((d) => d.vendor)).size, 'vendor') : 'Upload a config to begin',
    }),
    stat('Committed audits', num(records.length), {
      hint: records.length ? `latest seq #${records[records.length - 1].seq}` : 'Nothing signed yet',
    }),
    stat('Estate pass rate', estateScore === null ? '—' : `${estateScore.toFixed(1)}%`, {
      class: 'stat-score',
      hint: decided
        ? `${num(estate.pass)} pass / ${num(estate.fail)} fail over ${num(decided)} decided`
        : 'No verdict has been committed yet',
      title: 'pass / (pass + fail) across every committed audit. A PRAMAN ratio, not a published metric.',
    }),
    stat(
      'Ledger integrity',
      chainOk === null ? 'unknown' : chainOk ? 'verified' : `${num(chainBroken)} broken`,
      {
        class: chainOk === null ? '' : chainOk ? 'stat-ok' : 'stat-bad',
        hint:
          chainOk === null
            ? 'The verifier could not be reached'
            : chainOk
              ? `${count(verify.chain_length, 'record')}, hashes, links, Merkle roots and signatures all check out`
              : 'Open the Ledger view for the per-record detail',
      }
    ),
    stat('Controls loaded', num(runtime.controls_total), {
      hint: `${count(runtime.rules_loaded, 'automated check')} across ${count(runtime.catalogs_loaded, 'catalog')}`,
    }),
    stat('Automation coverage', runtime.controls_total ? pct(runtime.rules_loaded / runtime.controls_total) : '—', {
      hint: 'Share of loaded controls a deterministic rule can decide',
      title:
        'Everything outside this share is reported as notchecked, never as pass. That is why the ' +
        'result distribution below is worth reading next to the score.',
    })
  );

  const aiPanel = panel(
    'AI escalation ladder',
    el('p', { class: 'panel-note', text: health.ai?.note || '' }),
    el(
      'ul',
      { class: 'tier-list' },
      tierRow('Tier 0 — deterministic patterns', tiers.tier0_deterministic, 'Always on; the only tier in the verdict path'),
      tierRow('Tier 1 — TF-IDF char n-gram', tiers.tier1_tfidf, 'τ = 0.85'),
      tierRow('Tier 2 — SetFit', tiers.tier2_setfit, 'τ = 0.80'),
      tierRow(
        'Tier 3 — local Qwen3-4B',
        tiers.tier3_llm,
        'τ = 0.70, grammar-constrained',
        llmState(tiers.tier3_llm, health.ai?.tier3_checked_age_s, health.ai?.tier3_weights_present)
      )
    ),
    el('p', {
      class: 'panel-note',
      text:
        'The ladder classifies unrecognised configuration lines so an admin can map them. ' +
        'It never issues a verdict — compliance results come only from deterministic rules, ' +
        'so a tier being unavailable narrows what PRAMAN can suggest and cannot change what it concludes.',
    }),
    el('p', {
      class: 'panel-note',
      text: `Backend: ${health.ai?.ai_backend || 'unknown'}. A line no tier can place above its threshold abstains and goes to the training queue.`,
    })
  );

  const trendPoints = records
    .map((record) => ({
      seq: record.seq,
      score: scoreFromSummary(record.summary),
      device_id: record.device_id,
      hostname: devices.find((d) => d.device_id === record.device_id)?.hostname,
      passed: record.summary?.by_result?.pass ?? 0,
      failed: record.summary?.by_result?.fail ?? 0,
    }))
    .filter((point) => point.score !== null);

  // The findings themselves are not in `/audit/records`, so the framework split is
  // built from the newest device's detail rather than the estate. One request for a
  // real chart beats an empty div with a caption.
  let frameworkChart = null;
  let latestSummary = null;
  const newest = devices.filter((d) => d.latest_audit_id).sort((a, b) => (b.latest_seq || 0) - (a.latest_seq || 0))[0];
  if (newest) {
    try {
      const detail = await api.device(newest.device_id);
      frameworkChart = frameworkStackedBars(detail.findings || []);
      latestSummary = detail.summary;
    } catch (error) {
      toast('Could not load the latest device for the framework chart.', 'warn', error.detail);
    }
  }

  const charts = el(
    'div',
    { class: 'chart-grid' },
    frameworkChart,
    latestSummary ? resultDistribution(latestSummary) : null,
    Object.keys(failingSeverity).length
      ? severityBars(
          // `severityBars` counts failing findings, and `by_severity_failing` is
          // the ledger summary field that already restricts to them. Reconstructed
          // as synthetic failing findings so one chart implementation serves both
          // callers rather than a second near-copy drifting from the first.
          //
          // Deliberately NOT `by_severity`: that field counts every finding,
          // including passes and the `notchecked` majority, so charting it
          // reported 16,082 "failing controls" on an estate with 372 failures.
          Object.entries(failingSeverity).flatMap(([severity, count]) =>
            Array.from({ length: Number(count) }, () => ({ result: 'fail', severity }))
          )
        )
      : null,
    trendLine(trendPoints)
  );

  const recentRows = records
    .slice(-8)
    .reverse()
    .map((record) => {
      const score = scoreFromSummary(record.summary);
      const device = devices.find((d) => d.device_id === record.device_id);
      return [
        `#${record.seq}`,
        device?.hostname || record.device_id,
        score === null ? '—' : `${score.toFixed(1)}%`,
        num(record.summary?.by_result?.fail ?? 0),
        when(record.created_at),
        shortHash(record.record_hash),
      ];
    });

  return void outlet.replaceChildren(
    page(
      'Overview',
      `${health.app || 'PRAMAN'} ${health.version || ''} — ${health.problem_statement?.title || ''}`.trim(),
      [
        button('Upload configs', () => navigate('upload')),
        button('Verify ledger', () => navigate('ledger'), { class: 'btn-quiet' }),
      ],
      overviewHero(),
      tiles,
      workflowLinks(),
      devices.length === 0
        ? panel(
            null,
            emptyState(
              'No devices have been ingested yet.',
              'Upload a configuration file, or drop a ZIP of an estate, from the Upload view. ' +
                'Sample configs ship under test_configs/.'
            )
          )
        : null,
      trendPoints.length === 1
        ? panel(
            'Trend',
            el('p', {
              class: 'panel-note',
              text: `One committed audit so far, at ${trendPoints[0].score.toFixed(1)}%. A second commit will start the trend line — a chart of a single point would only restate the number above.`,
            })
          )
        : null,
      charts.childElementCount ? charts : null,
      aiPanel,
      records.length
        ? panel(
            'Recent commits',
            table(['Seq', 'Device', 'Score', 'Fail', 'Committed', 'Record hash'], recentRows, {
              caption: 'The most recent entries in the append-only ledger.',
            })
          )
        : null,
      panel(
        'Loaded runtime',
        table(
          ['Component', 'Version / count'],
          [
            ['Pattern library', runtime.pattern_library_version || '—'],
            ['Pattern packs', num(runtime.pattern_packs)],
            ['Vendors recognised', (runtime.vendors || []).join(', ') || '—'],
            ['Rule pack', runtime.rule_pack_version || '—'],
            ['Rules loaded', num(runtime.rules_loaded)],
            ['Catalogs loaded', num(runtime.catalogs_loaded)],
            ['Controls total', num(runtime.controls_total)],
          ],
          { class: 'data-table compact' }
        ),
        el('p', {
          class: 'panel-note',
          text:
            'These counters move when a pattern pack is dropped in or a mapping is taught, ' +
            'which is how a hot reload is observable rather than a claim.',
        })
      )
    )
  );
}
