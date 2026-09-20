/**
 * Screen 5 — the training GUI. C2: "teach the system an unseen vendor format
 * through the GUI, with no backend redeploy."
 *
 * This screen was the largest functional hole in the old frontend. Its
 * `loadTrainingQueue()` read `q.raw_line`, `q.status`, `q.drain3_template` and
 * `q.device_id` — four field names `GET /training/queue` does not return. The
 * queue therefore always rendered as empty, and the capability the problem
 * statement calls for could not be exercised at all. The route returns
 * `{template_id, template, vendor, occurrences, devices, example, source_file,
 * line_start, block, operands}` per item, and `counts:{pending, mapped}` for the
 * whole queue — there is no per-item status, because the queue *is* the pending
 * set.
 *
 * Three design decisions worth stating:
 *
 * **The operand is chosen explicitly.** A template like `ntp server <*> key <*>`
 * has two masked operands and a mapping that grabs the wrong one produces a
 * confidently wrong fact — the exact failure this project treats as worse than no
 * fact at all. So `value_index` is a first-class control with a live preview of
 * what would be extracted from the example line, not a hidden default.
 *
 * **The queue is per template, not per line.** One entry can stand for hundreds
 * of lines across dozens of devices, which is what makes teaching finite work.
 * The impact — occurrences and device count — is on the row, so an operator
 * spends their attention where it buys the most parsing coverage.
 *
 * **Mapping does not retroactively create facts.** The mapping is in force for
 * the next parse; configs already ingested keep the facts they had. The screen
 * says so and offers the re-ingest path, because "I mapped it and nothing
 * happened" is otherwise the obvious wrong conclusion.
 */

import {
  el, table, num, when, pill, emptyState, spinner, clear, code, count,
} from '../dom.js';
import {
  store, page, panel, button, linkButton, select, textField, navigate, toast, describeError,
} from '../shell.js';
import { identity, mayCommit, needsRole } from '../auth.js';
import { resultColor } from '../palette.js';
import * as api from '../api.js';

const PATH_LIST_ID = 'canonical-path-list';

/** Split a Drain3 template into literal and wildcard segments. */
function segments(template) {
  const parts = String(template || '').split('<*>');
  const out = [];
  parts.forEach((literal, index) => {
    if (literal) out.push({ kind: 'literal', text: literal });
    if (index < parts.length - 1) out.push({ kind: 'operand', index: out.filter((s) => s.kind === 'operand').length });
  });
  return out;
}

/** Guess what each operand would capture, by matching the template's literals
 * against the example line.
 *
 * This mirrors what `build_learned_pattern` does server-side closely enough to be
 * a useful preview, and it is labelled as a preview rather than as the stored
 * result — the authoritative extraction happens in the parser, and the operator
 * confirms it by re-ingesting. Guessing here and being slightly wrong is fine;
 * guessing here and presenting it as fact would not be.
 */
function previewOperands(template, example) {
  const line = String(example || '');
  const parts = String(template || '').split('<*>');
  if (parts.length === 1) return [];
  const values = [];
  let cursor = 0;

  for (let index = 0; index < parts.length; index += 1) {
    const literal = parts[index];
    if (literal) {
      const at = line.indexOf(literal, cursor);
      if (at === -1) return null; // The example does not match this template.
      if (index > 0) values.push(line.slice(cursor, at).trim());
      cursor = at + literal.length;
    } else if (index > 0) {
      values.push(line.slice(cursor).trim());
      cursor = line.length;
    }
  }
  if (parts[parts.length - 1] === '') values.push(line.slice(cursor).trim());
  return values.filter((_, index) => index < parts.length - 1);
}

/** The template with its operands numbered, so `value_index` means something. */
function templateNode(template, activeIndex) {
  return el(
    'code',
    { class: 'mono template' },
    ...segments(template).map((part) =>
      part.kind === 'literal'
        ? el('span', { text: part.text })
        : el('span', {
            class: `template-operand${part.index === activeIndex ? ' template-operand-active' : ''}`,
            text: `<${part.index}>`,
            title: `Operand ${part.index}`,
          })
    )
  );
}

export async function trainingView({ outlet, query }) {
  let vendorFilter = query?.vendor || '';

  const [paths, vendorBody] = await Promise.all([store.canonicalPaths(), store.vendors()]);
  const allPaths = paths.paths || [];
  const vendorNames = [...new Set((vendorBody.vendors || []).map((entry) => entry.vendor))].sort();

  // One datalist for the whole screen; three hundred-odd options duplicated per
  // row would be tens of thousands of nodes for no gain.
  const pathList = el(
    'datalist',
    { id: PATH_LIST_ID },
    ...allPaths.map((path) => el('option', { value: path }))
  );

  const statsHost = el('div', {});
  const queueHost = el('div', {});
  const mappingsHost = el('div', {});
  const brokenHost = el('div', {});

  async function reload() {
    clear(queueHost);
    queueHost.appendChild(spinner('Loading the queue…'));

    const [queueBody, mappingBody] = await Promise.all([
      api.trainingQueue(vendorFilter ? { vendor: vendorFilter } : {}),
      api.trainingMappings(vendorFilter ? { vendor: vendorFilter } : {}),
    ]);

    drawStats(queueBody, mappingBody);
    drawQueue(queueBody);
    drawMappings(mappingBody);
    drawBroken(mappingBody);
  }

  function drawStats(queueBody, mappingBody) {
    const counts = queueBody.counts || {};
    clear(statsHost);
    statsHost.appendChild(
      el(
        'div',
        { class: 'stat-grid stat-grid-tight' },
        el(
          'div',
          { class: 'stat' },
          el('div', { class: 'stat-label', text: 'Templates awaiting a mapping' }),
          el('div', { class: 'stat-value', text: num(counts.pending) }),
          el('div', { class: 'stat-hint', text: 'one decision each, however many devices they appear on' })
        ),
        el(
          'div',
          { class: 'stat' },
          el('div', { class: 'stat-label', text: 'Templates already mapped' }),
          el('div', { class: 'stat-value', text: num(counts.mapped) })
        ),
        el(
          'div',
          { class: 'stat' },
          el('div', { class: 'stat-label', text: 'Mappings stored' }),
          el('div', { class: 'stat-value', text: num(mappingBody.count) })
        ),
        el(
          'div',
          { class: 'stat' },
          el('div', { class: 'stat-label', text: 'Patterns in force' }),
          el('div', { class: 'stat-value', text: num(mappingBody.in_force) }),
          el('div', { class: 'stat-hint', text: 'compiled and live in this running process' })
        ),
        el(
          'div',
          { class: 'stat' },
          el('div', { class: 'stat-label', text: 'Not in force' }),
          el('div', {
            class: `stat-value ${(mappingBody.not_in_force || []).length ? 'stat-bad' : ''}`.trim(),
            text: num((mappingBody.not_in_force || []).length),
          }),
          el('div', { class: 'stat-hint', text: 'stored but failing to compile — silent loss of coverage' })
        ),
        el(
          'div',
          { class: 'stat' },
          el('div', { class: 'stat-label', text: 'Canonical paths available' }),
          el('div', { class: 'stat-value', text: num(allPaths.length) }),
          el('div', { class: 'stat-hint', text: 'the vocabulary a mapping may target' })
        )
      )
    );
  }

  /** The teach form for one queue item. Built on demand, on expand. */
  function teachForm(item, onDone) {
    let canonicalPath = '';
    let valueIndex = 0;
    let note = '';

    const preview = el('div', { class: 'teach-preview' });
    const templateHost = el('div', { class: 'teach-template' });

    function drawTemplate() {
      clear(templateHost);
      templateHost.appendChild(templateNode(item.template, item.operands > 0 ? valueIndex : -1));
    }

    function drawPreview() {
      clear(preview);
      const extracted = previewOperands(item.template, item.example);

      if (item.operands === 0) {
        preview.appendChild(
          el('p', {
            class: 'panel-note',
            text:
              'This template has no masked operand, so the mapping records the presence of the line rather than a ' +
              'value. That is the right shape for a flag like "logging on" and the wrong shape for anything carrying ' +
              'an address or a name.',
          })
        );
        return;
      }

      if (extracted === null) {
        preview.appendChild(
          el('p', {
            class: 'panel-note panel-warn',
            text: 'The example line does not line up with this template, so no preview can be shown. The server will still extract the operand correctly — this preview is a convenience, not the parser.',
          })
        );
        return;
      }

      preview.appendChild(
        table(
          ['Operand', 'Would capture', ''],
          extracted.map((value, index) => [
            el('code', { class: 'mono', text: `<${index}>` }),
            el('code', { class: 'mono', text: value === '' ? '(empty)' : value }),
            index === valueIndex
              ? pill('this one', resultColor('pass'), 'pill-tiny')
              : el('span', { class: 'dim', text: '' }),
          ]),
          { class: 'data-table compact', caption: 'Predicted from the example line. The parser is authoritative.' }
        )
      );

      if (canonicalPath) {
        const captured = extracted[valueIndex];
        preview.appendChild(
          el(
            'p',
            { class: 'teach-outcome' },
            el('span', { text: 'Next parse would produce ' }),
            el('code', { class: 'mono', text: `${canonicalPath} = ${captured === '' ? '(empty)' : captured}` })
          )
        );
      }
    }

    const pathField = textField(
      'Canonical path',
      '',
      (value) => {
        canonicalPath = value.trim();
        drawPreview();
        pathField.input.setAttribute('aria-invalid', canonicalPath && !allPaths.includes(canonicalPath) ? 'true' : 'false');
        pathHint.textContent =
          canonicalPath && !allPaths.includes(canonicalPath)
            ? 'Not a published canonical path — the server will reject this.'
            : `${num(allPaths.length)} paths published by the schema.`;
      },
      {
        placeholder: 'e.g. time.ntp.servers',
        list: PATH_LIST_ID,
        class: 'field-wide',
      }
    );
    const pathHint = el('span', { class: 'field-hint', text: `${num(allPaths.length)} paths published by the schema.` });
    pathField.appendChild(pathHint);

    const operandField =
      item.operands > 1
        ? select(
            'Which operand carries the value',
            Array.from({ length: item.operands }, (_, index) => [String(index), `operand <${index}>`]),
            '0',
            (value) => {
              valueIndex = Number(value);
              drawTemplate();
              drawPreview();
            }
          )
        : null;

    // Not a field any more. The route records the authenticated operator and
    // ignores whatever the client sends, so a "your admin id" box would be a
    // second identity free to disagree with the one the mapping is stored under.
    const whoRow = el(
      'div',
      { class: 'field' },
      el('span', { class: 'field-label', text: 'Recorded as' }),
      el('span', { class: 'teach-actor mono', text: identity()?.username || 'not signed in' }),
      el('span', {
        class: 'field-hint',
        text: 'Taken from your session, not typed. It is stored with the mapping.',
      })
    );

    const noteField = textField('Why (optional)', '', (value) => {
      note = value;
    }, { placeholder: 'carried onto the audit report', class: 'field-wide' });

    const teachable = mayCommit();
    const submit = button('Teach this mapping', async (event) => {
      const btn = event.currentTarget;
      if (!canonicalPath) {
        toast('Pick a canonical path first.', 'warn', `Start typing to search the ${num(allPaths.length)} published paths.`);
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Teaching…';
      try {
        const result = await api.trainingMap({
          template: item.template,
          canonicalPath,
          note,
          vendor: item.vendor || undefined,
          valueIndex,
        });
        toast(
          'Mapping is in force.',
          'success',
          `${result.mapping.template} → ${result.mapping.canonical_path} (version ${result.mapping.version}). No redeploy, no restart.`
        );
        store.invalidate('canonicalPaths');
        await onDone();
      } catch (error) {
        const { message, detail } = describeError(error);
        toast(message, 'error', detail);
        btn.disabled = false;
        btn.textContent = 'Teach this mapping';
      }
    }, {
      disabled: !teachable,
      title: teachable ? null : needsRole('approver', 'Teaching a mapping'),
    });

    drawTemplate();
    drawPreview();

    return el(
      'div',
      { class: 'teach' },
      el(
        'div',
        { class: 'teach-context' },
        el('div', { class: 'teach-row' }, el('span', { class: 'teach-label', text: 'Template' }), templateHost),
        el(
          'div',
          { class: 'teach-row' },
          el('span', { class: 'teach-label', text: 'Example' }),
          el('code', { class: 'mono', text: item.example || '(none recorded)' })
        ),
        el(
          'div',
          { class: 'teach-row' },
          el('span', { class: 'teach-label', text: 'Seen at' }),
          el('span', {
            class: 'mono dim',
            text: `${item.source_file || '—'}:${item.line_start || '—'}${item.block ? `  · block: ${item.block}` : ''}`,
          })
        ),
        el(
          'div',
          { class: 'teach-row' },
          el('span', { class: 'teach-label', text: 'Impact' }),
          el('span', {
            text: `${count(item.occurrences, 'line')} across ${count(item.devices, 'device')} would start producing a fact.`,
          })
        )
      ),
      el('div', { class: 'teach-fields' }, pathField, operandField, whoRow, noteField),
      preview,
      el('div', { class: 'button-row' }, submit),
      teachable
        ? null
        : el('p', {
            class: 'panel-note panel-warn',
            text: `${needsRole('approver', 'Teaching a mapping')} A mapping changes how every future ` +
              'configuration of this platform is read, so it is not an auditor-level action.',
          }),
      el('p', {
        class: 'panel-note',
        text:
          'The mapping applies from the next parse onwards. Configurations already ingested keep the facts they had — ' +
          're-upload one to see the new fact appear, which is also the honest demonstration that nothing was redeployed.',
      })
    );
  }

  function drawQueue(body) {
    const items = body.queue || [];
    clear(queueHost);

    if (items.length === 0) {
      queueHost.appendChild(
        emptyState(
          vendorFilter ? `Nothing pending for ${vendorFilter}.` : 'The queue is empty.',
          'Every line of every ingested configuration matched a pattern. Upload a configuration from an unsupported vendor, or run the "Unknown vendor lines" sample in the Simulate view, to put something here.'
        )
      );
      return;
    }

    const node = table(
      ['Template', 'Vendor', 'Lines', 'Devices', 'Operands', 'First seen at'],
      items.map((item) => [
        templateNode(item.template, -1),
        el('span', { text: item.vendor || '—' }),
        el('span', { text: num(item.occurrences) }),
        el('span', { text: num(item.devices) }),
        item.operands === 0
          ? pill('flag only', resultColor('informational'), 'pill-tiny')
          : el('span', { text: num(item.operands) }),
        el('span', { class: 'mono dim', text: `${item.source_file || '—'}:${item.line_start || '—'}` }),
      ]),
      { class: 'data-table', caption: 'Busiest first — mapping the top row unblocks the most facts.' }
    );

    const rows = Array.from(node.querySelector('tbody').children);
    rows.forEach((tr, index) => {
      const item = items[index];
      tr.classList.add('row-expandable');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-expanded', 'false');
      tr.setAttribute('aria-label', `Teach a mapping for ${item.template}`);

      const detailRow = el('tr', { class: 'detail-row', hidden: true }, el('td', { colspan: '6' }));
      let mounted = false;

      const toggle = () => {
        const open = detailRow.hidden;
        detailRow.hidden = !open;
        tr.setAttribute('aria-expanded', String(open));
        tr.classList.toggle('row-open', open);
        if (open && !mounted) {
          mounted = true;
          detailRow.firstChild.appendChild(teachForm(item, reload));
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

    queueHost.appendChild(node);
  }

  function drawMappings(body) {
    const mappings = body.mappings || [];
    clear(mappingsHost);

    if (mappings.length === 0) {
      mappingsHost.appendChild(emptyState('No mappings have been taught yet.'));
      return;
    }

    mappingsHost.appendChild(
      table(
        ['Template', 'Canonical path', 'Operand', 'Vendor', 'Taught by', 'Version', 'Updated', ''],
        mappings.map((mapping) => [
          templateNode(mapping.template, mapping.value_index),
          el('code', { class: 'mono', text: mapping.canonical_path }),
          el('span', { class: 'mono', text: mapping.operands ? `<${mapping.value_index}>` : '—' }),
          el('span', { text: mapping.vendor === '*' ? 'all vendors' : mapping.vendor }),
          el(
            'span',
            {},
            el('span', { text: mapping.admin_id || '—' }),
            mapping.note ? el('div', { class: 'dim small', text: mapping.note }) : null
          ),
          el('span', { class: 'mono', text: `v${mapping.version}` }),
          el('span', { class: 'dim', text: when(mapping.updated_at) }),
          el('button', {
            class: 'btn btn-tiny btn-quiet',
            type: 'button',
            text: 'Retire',
            disabled: !mayCommit(),
            title: mayCommit()
              ? 'Withdraw the mapping. The record that it once applied is kept.'
              : needsRole('approver', 'Retiring a mapping'),
            onclick: async (event) => {
              const btn = event.currentTarget;
              btn.disabled = true;
              btn.textContent = 'Retiring…';
              try {
                await api.trainingRetire(mapping.template);
                toast('Retired.', 'success', 'The pattern is out of force from the next parse onwards. Facts already stored are untouched.');
                await reload();
              } catch (error) {
                const { message, detail } = describeError(error);
                toast(message, 'error', detail);
                btn.disabled = false;
                btn.textContent = 'Retire';
              }
            },
          }),
        ]),
        { caption: `${count(mappings.length, 'mapping')}, newest first. ${num(body.in_force)} compiled into live patterns.` }
      )
    );
  }

  function drawBroken(body) {
    const broken = body.not_in_force || [];
    clear(brokenHost);
    if (broken.length === 0) return;

    brokenHost.appendChild(
      panel(
        `Mappings that are not in force (${num(broken.length)})`,
        el('p', {
          class: 'panel-note panel-warn',
          text:
            'These mappings are stored but do not compile, so they produce no facts. This is a silent loss of parsing ' +
            'coverage — the operator who taught the mapping is the only person who can fix it, which is why it is on ' +
            'screen instead of in a log file.',
        }),
        table(
          ['Template', 'Target path', 'Why it is not in force'],
          broken.map((entry) => [
            el('code', { class: 'mono', text: entry.template }),
            el('code', { class: 'mono', text: entry.canonical_path }),
            el('span', { text: entry.reason }),
          ]),
          { class: 'data-table compact' }
        )
      )
    );
  }

  const vendorSelect = select(
    'Vendor',
    [['', 'all vendors'], ...vendorNames.map((name) => [name, name])],
    vendorFilter,
    async (value) => {
      vendorFilter = value;
      await reload();
    }
  );

  await reload();

  return void outlet.replaceChildren(
    page(
      'Training',
      'Teach PRAMAN a line format it has never seen — without touching the code',
      [
        linkButton('Export as a pattern pack', api.trainingExportUrl(), {
          class: 'btn-quiet',
          download: 'taught-patterns.yaml',
        }),
        button('Upload a config', () => navigate('upload'), { class: 'btn-quiet' }),
      ],
      pathList,
      panel(null, el('div', { class: 'filter-bar' }, vendorSelect), statsHost),
      panel(
        'Queue — unrecognised line formats',
        el('p', {
          class: 'panel-note',
          text:
            'One row per line format, aggregated across the estate: mapping "logging host <*>" once resolves it on ' +
            'every device that has it. Expand a row to teach it. Nothing here was dropped — a line the parser did ' +
            'not understand is queued, never silently discarded, because a discarded line is an invisible gap in the audit.',
        }),
        queueHost
      ),
      panel('Mappings in force', mappingsHost),
      brokenHost,
      panel(
        'How this satisfies "no redeploy"',
        el(
          'ol',
          { class: 'note-list' },
          el('li', { text: 'A mapping is validated on the way in: the canonical path must exist in the schema, the template must compile, and the operand you picked must be present. All three fail loudly here rather than producing a broken parser later.' }),
          el('li', { text: 'It is stored as a row, not as code. The pattern registry fingerprints the mapping table and recompiles when it moves, so the very next parse in this same process uses it.' }),
          el('li', { text: 'Facts produced by a taught mapping carry a parser id ending in "+taught", so a report never conflates a vendor-supplied pattern with one an operator wrote.' }),
          el('li', { text: 'Export writes the mappings out as pattern-pack YAML. The store is a working surface; a reviewed pack under data/ingest/patterns/ is what ships. Without that step an estate’s real parsing knowledge would accumulate in a SQLite table nobody reads.' })
        ),
        el('p', {
          class: 'panel-note panel-warn',
          text:
            'Teaching is approver-only and the mapping is stored under the authenticated operator, not under a ' +
            'name the client chose. What is still missing is transport security: the API speaks plain HTTP, so on ' +
            'a management network it belongs behind a reverse proxy terminating TLS. See docs/SECURITY.md.',
        })
      )
    )
  );
}
