/**
 * Screen 2 — the live linter.
 *
 * `POST /simulate` is stateless, idempotent, and writes nothing: no device row, no
 * ledger record. That property is the whole point of the screen and it is stated
 * on the screen, because an auditor pasting a production config into a tool needs
 * to know before they paste, not after.
 *
 * The samples are inline rather than fetched. They make the screen testable the
 * moment the server starts — paste nothing, click one button, see a real verdict
 * with real evidence — and the frontend has no filesystem access to read
 * `test_configs/` from. They are short on purpose; the full fixture library lives
 * under `test_configs/` for the pytest suite and the bulk-ingest path.
 */

import { el, num, pct, clear, emptyState, table, pill, spinner, count, agree } from '../dom.js';
import { page, panel, button, toast, describeError, navigate, store } from '../shell.js';
import { mayIngest, needsRole } from '../auth.js';
import { findingsTable } from '../findings.js';
import { configViewer, marksFromFindings, viewerLegend } from '../configview.js';
import { complianceGauge, resultDistribution, severityBars, frameworkStackedBars } from '../charts.js';
import { resultColor } from '../palette.js';
import * as api from '../api.js';

/** The escalation ladder's own vocabulary, mirrored from `backend/ai/escalation.py`.
 *
 * The endpoint reports tiers as integers and `-1` for both "abstained" and
 * "disabled" — printing the raw number tells a reader nothing, and `0` is a real
 * tier that a falsy check would erase. `parser_id` is what separates the two `-1`
 * cases (`ai.abstain` vs `ai.disabled`). */
const TIER_ORDER = ['tier0_deterministic', 'tier1_tfidf', 'tier2_setfit', 'tier3_llm'];
const TIER_LABELS = {
  tier0_deterministic: 'Tier 0 · deterministic patterns',
  tier1_tfidf: 'Tier 1 · TF-IDF',
  tier2_setfit: 'Tier 2 · SetFit',
  tier3_llm: 'Tier 3 · local LLM',
};
const CLASSIFIER_TIERS = {
  '-1': 'none',
  0: 'Tier 0 · pattern',
  1: 'Tier 1 · TF-IDF',
  2: 'Tier 2 · SetFit',
  3: 'Tier 3 · LLM',
};

function tierName(tier) {
  if (tier === null || tier === undefined) return '—';
  return CLASSIFIER_TIERS[String(tier)] ?? `tier ${tier}`;
}


const SAMPLES = {
  'Insecure router': `!
version 15.2
hostname edge-rtr-01
!
enable password cisco123
no service password-encryption
!
no aaa new-model
!
ip http server
ip http secure-server
!
interface GigabitEthernet0/0
 description UPLINK
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
line con 0
 exec-timeout 0 0
 no login
line vty 0 4
 exec-timeout 0 0
 transport input telnet
 no login
!
snmp-server community public RO
snmp-server community private RW
!
no logging on
!
end
`,
  'Hardened router': `!
version 15.2
hostname core-rtr-01
!
service password-encryption
enable secret 5 $1$abcd$0123456789abcdefghijkl
!
aaa new-model
aaa authentication login default local
aaa authorization exec default local
aaa accounting exec default start-stop group tacacs+
!
no ip http server
no ip http secure-server
!
login block-for 120 attempts 3 within 60
!
banner motd ^C Authorised access only. Activity is monitored. ^C
!
interface GigabitEthernet0/0
 description UPLINK to core
 ip address 10.0.0.1 255.255.255.0
 no ip proxy-arp
 no shutdown
!
line con 0
 exec-timeout 5 0
 login authentication default
line vty 0 4
 exec-timeout 5 0
 transport input ssh
 login authentication default
!
ip ssh version 2
!
logging on
logging host 10.0.0.250
logging trap informational
!
ntp authenticate
ntp server 10.0.0.251
!
end
`,
  'Unknown vendor lines': `!
hostname mystery-box-01
!
set system services ssh protocol-version v2
set system login retry-options tries-before-disconnect 3
set snmp community secret-community authorization read-only
proprietary-hardening-profile level strict
custom-audit-mode enable timeout 300
!
end
`,
};

export async function simulateView({ outlet, query }) {
  const health = await store.health();

  const editor = el('textarea', {
    class: 'config-input mono',
    id: 'simulate-input',
    rows: '16',
    spellcheck: 'false',
    placeholder: 'Paste a device configuration here, or load one of the samples below.',
    'aria-label': 'Configuration to check',
  });

  const sourceName = el('input', {
    class: 'field-input mono',
    type: 'text',
    value: 'inline.conf',
    'aria-label': 'Source file name recorded in the evidence',
  });

  const resultsHost = el('div', { class: 'simulate-results' });
  let lastConfig = '';

  function reset() {
    clear(resultsHost);
  }

  async function run() {
    const text = editor.value;
    if (!text.trim()) {
      toast('Nothing to check.', 'warn', 'Paste a configuration, or load one of the samples.');
      return;
    }
    lastConfig = text;
    clear(resultsHost);
    resultsHost.appendChild(spinner('Parsing, evaluating rules, and classifying unknown lines…'));

    try {
      const body = await api.simulate(text, sourceName.value.trim() || 'inline.conf');
      clear(resultsHost);
      resultsHost.appendChild(renderRun(body));
      resultsHost.scrollIntoView({ block: 'start', behavior: 'smooth' });
    } catch (error) {
      const { message, detail } = describeError(error);
      clear(resultsHost);
      resultsHost.appendChild(el('div', { class: 'error-panel', role: 'alert' }, el('strong', { text: message }), detail ? el('pre', { class: 'error-detail', text: detail }) : null));
      toast(message, 'error', detail);
    }
  }

  function renderRun(body) {
    const findings = body.findings || [];
    const stats = body.stats || {};
    const device = body.device || {};
    const classifications = body.ai_classifications || [];
    const { marks, absent } = marksFromFindings(findings, { only: ['fail', 'pass', 'error', 'unknown'] });

    const viewer = configViewer(lastConfig, {
      marks,
      sourceFile: sourceName.value.trim() || 'inline.conf',
    });

    const findingsHost = findingsTable({
      findings,
      onJump: (line) => {
        viewer.focusLine(line);
        viewer.scrollIntoView({ block: 'center', behavior: 'smooth' });
      },
      initial: { result: 'fail' },
    });

    const scopeTable = table(
      ['Selection', 'Count'],
      [
        ['Catalogs selected for this device', num(stats.catalogs_selected)],
        ['Catalogs skipped (different vendor or OS)', num(stats.catalogs_skipped)],
        ['Controls in the selected catalogs', num(stats.controls_total)],
        ['Controls a rule can decide automatically', num(stats.controls_automated)],
        ['Rules loaded', num(stats.rules_loaded)],
        ['Rules inapplicable to this device', num(stats.rules_inapplicable)],
        ['Automation coverage', pct(stats.automation_coverage)],
      ],
      { class: 'data-table compact' }
    );

    return el(
      'div',
      {},
      panel(
        'Result',
        el(
          'div',
          { class: 'sim-headline' },
          el(
            'div',
            {},
            el('h4', { class: 'sim-host', text: device.hostname || '(no hostname in this config)' }),
            el('p', {
              class: 'panel-note',
              text: `Detected as ${device.vendor || 'unknown vendor'}${device.os_family ? ` / ${device.os_family}` : ''}${device.os_version ? ` ${device.os_version}` : ''}. Nothing was stored — this run wrote no device row and no ledger record.`,
            })
          ),
          el(
            'div',
            { class: 'button-row' },
            button('Ingest this config for real', async (event) => {
              const btn = event.currentTarget;
              btn.disabled = true;
              try {
                const file = new File([lastConfig], sourceName.value.trim() || 'inline.conf', { type: 'text/plain' });
                const ingested = await api.ingest(file);
                store.invalidateAfterWrite();
                toast('Ingested.', 'success', `${num(ingested.facts_count)} facts stored. Commit an audit from the device view to write it to the ledger.`);
                navigate('device', [ingested.device_id]);
              } catch (error) {
                const { message, detail } = describeError(error);
                toast(message, 'error', detail);
                btn.disabled = false;
              }
            }, {
              disabled: !mayIngest(),
              title: mayIngest() ? null : needsRole('auditor', 'Storing a configuration'),
            })
          )
        ),
        el(
          'div',
          { class: 'chart-grid' },
          complianceGauge(body.score || {}),
          resultDistribution(body.summary || {}),
          severityBars(findings),
          frameworkStackedBars(findings)
        )
      ),
      panel(
        'Coverage of the standard',
        el('p', {
          class: 'panel-note',
          text:
            'The score above is computed over the controls a rule could decide. Everything else is reported as ' +
            'notchecked, never as a pass — so these two numbers have to be read together.',
        }),
        scopeTable
      ),
      panel(`Findings (${num(findings.length)})`, findingsHost),
      panel(
        'Configuration',
        viewerLegend(),
        viewer,
        absent.length
          ? el('p', {
              class: 'panel-note',
              text: `${count(absent.length, 'finding')} ${agree(absent.length, 'cites', 'cite')} a setting that is absent from this configuration, so ${agree(absent.length, 'it has', 'they have')} no line to point at. ${agree(absent.length, 'Its', 'Their')} verdict rests on the absence itself.`,
            })
          : null
      ),
      panel(
        `Unrecognised lines (${num(body.unparsed_count || 0)})`,
        (body.unparsed_count || 0) === 0
          ? el('p', { class: 'panel-note', text: 'Every line was matched by a deterministic pattern.' })
          : el(
              'div',
              {},
              el('p', {
                class: 'panel-note',
                text:
                  'These lines produced no canonical fact. The classifier proposes a canonical path for each; a ' +
                  'proposal is a suggestion for an admin to approve, never a verdict. Anything below the tier ' +
                  'threshold abstains rather than guessing.',
              }),
              classifications.length
                ? renderClassifications(classifications)
                : emptyState('No classifications were returned for these lines.', 'They will still appear in the training queue once this config is ingested.'),
              el(
                'div',
                { class: 'button-row' },
                button('Open the training queue', () => navigate('training'), { class: 'btn-quiet' })
              )
            )
      ),
      panel('AI tier status for this run', ...aiStatusPanel(body.ai_status))
    );
  }

  /**
   * The escalation ladder, as it stood for this run.
   *
   * `ai_status` is `{ai_backend, tiers: {tier0_deterministic: bool, …}, note}` — a
   * nested object, so mapping its top-level entries to chips (as this did) printed
   * `tiers: [object Object]` and crammed the note paragraph into a chip. The
   * booleans that decide what actually ran are one level down.
   */
  function aiStatusPanel(status) {
    if (!status) return [el('p', { class: 'panel-note', text: 'The run returned no tier status.' })];
    const tiers = status.tiers || {};
    const chips = TIER_ORDER.filter((key) => key in tiers).map((key) =>
      el(
        'li',
        { class: `chip ${tiers[key] ? 'chip-on' : 'chip-off'}` },
        el('span', { class: 'chip-label', text: TIER_LABELS[key] }),
        // The word, not just the colour — R11.4. "off" here means the tier is not
        // installed on this machine, which is a supported state, not a fault.
        el('span', { class: 'chip-state', text: tiers[key] ? 'available' : 'not installed' })
      )
    );
    return [
      el('ul', { class: 'chip-list' }, ...chips),
      el(
        'p',
        { class: 'panel-note' },
        el('span', { text: 'Backend: ' }),
        el('code', { class: 'mono', text: status.ai_backend || 'unknown' }),
        status.note ? el('span', { text: ` — ${status.note}` }) : null
      ),
    ];
  }

  function renderClassifications(items) {
    const rows = items.map((item) => [
      el('code', { class: 'mono', text: item.line_number ? `${item.line_number}` : '—' }),
      el('code', { class: 'mono', text: item.line || item.template || '' }),
      item.abstained
        ? pill('abstained', resultColor('unknown'), 'pill-tiny')
        : el('code', { class: 'mono', text: item.suggested_path || '—' }),
      el('span', { text: tierName(item.tier) }),
      el('span', { text: item.confidence === null || item.confidence === undefined ? '—' : Number(item.confidence).toFixed(2) }),
      el('span', { class: 'dim', text: item.block || '' }),
    ]);

    const abstained = items.filter((item) => item.abstained).length;
    return el(
      'div',
      {},
      table(['Line', 'Text', 'Proposed path', 'Tier', 'Confidence', 'Block'], rows, {
        class: 'data-table compact',
        caption: 'Classifier proposals for lines no pattern matched.',
      }),
      abstained
        ? el('p', {
            class: 'panel-note',
            text: `${count(abstained, 'line')} abstained — no tier was confident enough to propose a path. That is the designed outcome, not a failure: a wrong mapping produces a confidently wrong fact.`,
          })
        : null
    );
  }

  const sampleButtons = el(
    'div',
    { class: 'button-row' },
    ...Object.entries(SAMPLES).map(([name, text]) =>
      button(
        name,
        () => {
          editor.value = text;
          sourceName.value = `${name.toLowerCase().replace(/\s+/g, '-')}.conf`;
          reset();
          toast(`Loaded the "${name}" sample.`, 'info', 'Click Check to run it.');
        },
        { class: 'btn-quiet' }
      )
    )
  );

  if (query?.sample && SAMPLES[query.sample]) {
    editor.value = SAMPLES[query.sample];
  }

  return void outlet.replaceChildren(
    page(
      'Simulate',
      'Paste a configuration and see the verdicts — nothing is stored',
      [
        button('Check', run, {
          disabled: !mayIngest(),
          title: mayIngest() ? null : needsRole('auditor', 'Running a simulation'),
        }),
        button('Clear', () => {
          editor.value = '';
          reset();
        }, { class: 'btn-quiet' }),
      ],
      panel(
        null,
        el(
          'div',
          { class: 'sim-toolbar' },
          el('label', { class: 'field field-narrow' }, el('span', { class: 'field-label', text: 'Recorded as' }), sourceName),
          el('div', { class: 'sim-samples' }, el('span', { class: 'field-label', text: 'Load a sample' }), sampleButtons)
        ),
        editor,
        el('p', {
          class: 'panel-note',
          text:
            'This endpoint is stateless and idempotent. It creates no device, writes no ledger record, and ' +
            'leaves no trace you have to clean up — so it is safe to paste a production configuration into. ' +
            'Secrets are redacted server-side before parsing.',
        }),
        el('p', {
          class: 'panel-note',
          text: `${num(health.runtime?.rules_loaded)} deterministic rules across ${num(health.runtime?.catalogs_loaded)} catalogs are available. Only rules whose catalog matches the detected vendor and OS will be applied.`,
        })
      ),
      resultsHost
    )
  );
}
