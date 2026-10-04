/**
 * Screen 1 — ingestion (C1).
 *
 * C1 is "single **and bulk** upload, any vendor". The old page had one file input
 * and no bulk control at all, so half the capability had no UI.
 *
 * Two paths, because the backend offers two and they suit different situations.
 * A `.zip` goes to `POST /ingest/bulk`, which enforces the archive limits and
 * returns per-member status in one response. Loose files — including a whole
 * folder, which browsers will hand over via `webkitdirectory` — go to
 * `POST /ingest` one at a time with bounded concurrency, because that is the only
 * way to show progress per file and because asking an auditor to zip a directory
 * before they can upload it is friction we can absorb instead.
 *
 * Failures are per-file and stay visible. A 40-device upload where two files are
 * Word documents must ingest 38 and name the two, which is what the bulk route
 * does server-side and what this mirrors for the loose-file path.
 */

import { el, table, num, clear, emptyState, pill, count, agree } from '../dom.js';
import { store, page, panel, button, navigate, toast, describeError } from '../shell.js';
import { mayIngest, needsRole } from '../auth.js';
import { resultColor } from '../palette.js';
import * as api from '../api.js';

/** Two at a time. Enough to hide latency, few enough that a 400-file drop does
 * not open 400 sockets and make the server's own parse queue the bottleneck. */
const CONCURRENCY = 2;

function statusPill(status) {
  return pill(status, status === 'ok' ? resultColor('pass') : resultColor('fail'));
}

export async function uploadView({ outlet }) {
  const health = await store.health();
  const knownVendors = health.runtime?.vendors || [];

  /** @type {Array<{file: string, state: string, detail: string, row: object}>} */
  let queue = [];
  let running = false;
  //: The job id of a background archive currently in flight, or null. Drives the
  //: cancel control, so it must be cleared on every exit path.
  let cancellableJob = null;

  const resultsHost = el('div', { class: 'upload-results' });
  const progressHost = el('div', { class: 'upload-progress' });

  function renderResults() {
    if (queue.length === 0) {
      clear(resultsHost);
      return;
    }
    const ok = queue.filter((item) => item.state === 'ok');
    const failed = queue.filter((item) => item.state === 'failed');
    const pending = queue.filter((item) => item.state === 'pending' || item.state === 'running');

    const rows = queue.map((item) => [
      item.file,
      statusPill(item.state === 'ok' ? 'ok' : item.state === 'failed' ? 'failed' : item.state),
      item.hostname || '—',
      item.vendor || '—',
      item.facts_count === undefined ? '—' : num(item.facts_count),
      item.unparsed_count === undefined ? '—' : num(item.unparsed_count),
      item.detail || '',
    ]);

    clear(resultsHost);
    resultsHost.appendChild(
      panel(
        `Ingest results — ${num(ok.length)} ok, ${num(failed.length)} failed${pending.length ? `, ${num(pending.length)} pending` : ''}`,
        table(
          ['File', 'Status', 'Hostname', 'Vendor', 'Facts', 'Unrecognised lines', 'Detail'],
          rows,
          { caption: 'One row per file. A failure here does not affect the others.' }
        ),
        // A cancel control only while a background archive is in flight. It stops
        // at the next member boundary, so the devices already in the table stay
        // ingested — which the label has to say, or "cancel" reads as "undo".
        cancellableJob
          ? el(
              'div',
              { class: 'button-row' },
              button(
                'Stop importing',
                () => cancelRunningJob(),
                {
                  class: 'btn-quiet',
                  title: 'Stops after the file being read. Devices already imported stay imported.',
                }
              )
            )
          : null,
        ok.length
          ? el(
              'div',
              { class: 'button-row' },
              button(`Review ${count(ok.length, 'ingested device')}`, () => navigate('devices')),
              ok.some((item) => item.unparsed_count > 0)
                ? button(
                    'Teach the unrecognised lines',
                    () => navigate('training'),
                    { class: 'btn-quiet', title: 'Open the training queue for the templates these files produced' }
                  )
                : null
            )
          : null,
        failed.length
          ? el('p', {
              class: 'panel-note',
              text:
                'A failed file was rejected before anything was stored — no partial device was created. ' +
                'The usual causes are a non-configuration file, a vendor with no pattern pack yet, or a size limit.',
            })
          : null
      )
    );
  }

  function setProgress(done, total) {
    clear(progressHost);
    if (total === 0 || done === total) return;
    progressHost.appendChild(
      el(
        'div',
        { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': String(total), 'aria-valuenow': String(done) },
        el('div', { class: 'progress-bar', style: { width: `${(done / total) * 100}%` } }),
        el('span', { class: 'progress-label', text: `${num(done)} of ${num(total)} uploaded` })
      )
    );
  }

  /** Run the loose-file queue with bounded concurrency. */
  async function drain(files) {
    running = true;
    let done = 0;
    setProgress(done, files.length);

    const cursor = { index: 0 };
    async function worker() {
      for (;;) {
        const index = cursor.index++;
        if (index >= files.length) return;
        const entry = queue[index];
        entry.state = 'running';
        renderResults();
        try {
          const body = await api.ingest(files[index]);
          Object.assign(entry, {
            state: 'ok',
            hostname: body.device_id,
            vendor: body.vendor,
            facts_count: body.facts_count,
            unparsed_count: body.unparsed_count,
            device_id: body.device_id,
            detail: body.queued_templates
              ? `${count(body.queued_templates, 'template')} queued for training`
              : '',
          });
        } catch (error) {
          const { detail } = describeError(error);
          entry.state = 'failed';
          entry.detail = detail || 'rejected';
        }
        done += 1;
        setProgress(done, files.length);
        renderResults();
      }
    }

    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, files.length) }, worker));
    running = false;
    setProgress(files.length, files.length);
    store.invalidateAfterWrite();

    const ok = queue.filter((item) => item.state === 'ok').length;
    const failed = queue.length - ok;
    toast(
      `Ingested ${num(ok)} of ${count(queue.length, 'file')}.`,
      failed ? 'warn' : 'success',
      failed
        ? `${count(failed, 'file')} ${agree(failed, 'was', 'were')} rejected — see the table for each reason.`
        : null
    );
  }

  /** Render one job poll into the results table.
   *
   * Results stream in as the worker walks the archive, so a 400-device import
   * fills the table device by device rather than showing nothing for a minute
   * and everything at once. */
  function renderJob(body, zipName) {
    const pending = Math.max(0, (body.total || 0) - (body.done || 0));
    queue = [
      ...(body.results || []).map((item) => ({
        file: item.file,
        state: 'ok',
        hostname: item.hostname,
        vendor: item.vendor,
        facts_count: item.facts_count,
        unparsed_count: item.unparsed_count,
        device_id: item.device_id,
        detail: item.queued_templates ? `${count(item.queued_templates, 'template')} queued` : '',
      })),
      ...(body.errors || []).map((item) => ({
        file: item.file,
        state: 'failed',
        detail: item.error,
      })),
    ];
    if (pending && body.state === 'running') {
      queue.push({
        file: zipName,
        state: 'running',
        detail: `${num(body.done)} of ${num(body.total)} — ${count(pending, 'file')} to go`,
      });
    }
    renderResults();
  }

  /** Ask the running import to stop. Failure here is not the operator's problem:
   * the job may simply have finished between the render and the click, which is
   * a race the backend answers with 409 and the poll loop resolves anyway. */
  async function cancelRunningJob() {
    const jobId = cancellableJob;
    if (!jobId) return;
    cancellableJob = null;
    renderResults();
    try {
      await api.cancelJob(jobId);
    } catch {
      // The poll loop reports the real outcome; nothing useful to add here.
    }
  }

  async function uploadArchive(zip) {
    queue = [{ file: zip.name, state: 'running', detail: 'expanding archive…' }];
    renderResults();
    try {
      // The archive limits allow far more than a request can be held open for,
      // so the archive goes on the job queue and this polls it. The POST still
      // rejects a malformed archive synchronously, which is why a bad zip lands
      // in the catch below rather than as a failed job.
      const started = await api.ingestBulkBackground(zip);
      cancellableJob = started.job_id;
      let body = started;
      while (body.state === 'queued' || body.state === 'running') {
        await new Promise((resolve) => setTimeout(resolve, 600));
        body = await api.job(started.job_id);
        renderJob(body, zip.name);
      }
      cancellableJob = null;
      renderJob(body, zip.name);
      store.invalidateAfterWrite();

      if (body.state === 'failed') {
        toast('Archive import failed.', 'error', body.error || '');
        return;
      }
      const verb = body.state === 'cancelled' ? 'Archive cancelled' : 'Archive expanded';
      toast(
        `${verb}: ${num(body.succeeded)} ingested, ${num(body.failed)} failed.`,
        body.failed || body.state === 'cancelled' ? 'warn' : 'success'
      );
    } catch (error) {
      cancellableJob = null;
      const { message, detail } = describeError(error);
      queue = [{ file: zip.name, state: 'failed', detail: detail || message }];
      renderResults();
      toast(message, 'error', detail);
    }
  }

  /** Route a drop or a picked set to the right endpoint. */
  async function accept(fileList) {
    const files = Array.from(fileList || []);
    if (files.length === 0) return;
    // One funnel for the picker, the folder picker and the drop target, so this is
    // the only place the role has to be checked. Saying so before the request is a
    // courtesy — the route answers 403 either way.
    if (!mayIngest()) {
      toast(
        'Uploading is not available to your role.',
        'warn',
        needsRole('auditor', 'Uploading a configuration')
      );
      return;
    }
    if (running) {
      toast('An upload is already running.', 'warn');
      return;
    }

    const archives = files.filter((file) => /\.zip$/i.test(file.name));
    if (archives.length === 1 && files.length === 1) {
      await uploadArchive(archives[0]);
      return;
    }
    if (archives.length) {
      toast(
        'Send one archive at a time.',
        'warn',
        'The bulk route takes a single ZIP so it can enforce the member and expansion limits across the whole archive. Loose configuration files can be dropped together.'
      );
      return;
    }

    queue = files.map((file) => ({ file: file.name, state: 'pending', detail: '' }));
    renderResults();
    await drain(files);
  }

  const fileInput = el('input', {
    type: 'file',
    id: 'upload-input',
    class: 'visually-hidden',
    multiple: true,
    onchange: (event) => {
      accept(event.target.files);
      event.target.value = '';
    },
  });

  const folderInput = el('input', {
    type: 'file',
    id: 'upload-folder-input',
    class: 'visually-hidden',
    multiple: true,
    onchange: (event) => {
      accept(event.target.files);
      event.target.value = '';
    },
  });
  // Not settable through setAttribute in every engine, and not in the HTML spec
  // proper — assigned directly so an unsupported browser simply gets a
  // multi-file picker instead of an error.
  folderInput.webkitdirectory = true;

  const dropZone = el(
    'div',
    {
      class: 'drop-zone',
      tabindex: '0',
      role: 'button',
      'aria-label': 'Choose configuration files to upload, or drop them here',
      onclick: () => fileInput.click(),
      onkeydown: (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          fileInput.click();
        }
      },
      ondragover: (event) => {
        event.preventDefault();
        dropZone.classList.add('drag-over');
      },
      ondragleave: () => dropZone.classList.remove('drag-over'),
      ondrop: (event) => {
        event.preventDefault();
        dropZone.classList.remove('drag-over');
        accept(event.dataTransfer?.files);
      },
    },
    el('p', { class: 'drop-title', text: 'Drop configuration files here' }),
    el('p', {
      class: 'drop-hint',
      text: 'One file, a whole folder, or a single .zip of an estate. Any supported vendor, mixed freely.',
    }),
    el(
      'div',
      { class: 'button-row' },
      button('Choose files', (event) => {
        event.stopPropagation();
        fileInput.click();
      }, {
        disabled: !mayIngest(),
        title: mayIngest() ? null : needsRole('auditor', 'Uploading a configuration'),
      }),
      button(
        'Choose a folder',
        (event) => {
          event.stopPropagation();
          folderInput.click();
        },
        {
          class: 'btn-quiet',
          disabled: !mayIngest(),
          title: mayIngest() ? null : needsRole('auditor', 'Uploading a configuration'),
        }
      )
    ),
    fileInput,
    folderInput
  );

  return void outlet.replaceChildren(
    page(
      'Upload',
      'Unified ingestion — single file, folder, or ZIP archive (C1)',
      null,
      panel(null, dropZone, progressHost),
      resultsHost,
      panel(
        'What happens to an uploaded file',
        el(
          'ol',
          { class: 'step-list' },
          el('li', {
            text:
              'Secrets are redacted before anything is stored. A password in a config never reaches the database or a report.',
          }),
          el('li', {
            text:
              'The vendor is detected and the matching pattern pack parses the text into canonical facts, each carrying its source file, line span, parser id and confidence.',
          }),
          el('li', {
            text:
              'Lines no pattern recognises are counted and their templates queued for the training module, rather than dropped silently.',
          }),
          el('li', {
            text:
              'Nothing is written to the ledger yet. Ingest is not an audit — you commit an audit explicitly, from the device view.',
          })
        )
      ),
      panel(
        'Vendors currently recognised',
        knownVendors.length
          ? el('ul', { class: 'chip-list' }, ...knownVendors.map((vendor) => el('li', { class: 'chip', text: vendor })))
          : emptyState('No pattern packs are loaded.'),
        el('p', {
          class: 'panel-note',
          text:
            'A vendor absent from this list is not a dead end: upload the config anyway, then map its unrecognised ' +
            'lines in the Training view. That takes effect immediately, with no redeploy.',
        }),
        el(
          'p',
          { class: 'panel-note' },
          'Limits are enforced server-side and reported per file: per-upload size, archive member count, ' +
            'per-member and total uncompressed size. The archive path is the zip-bomb guard, so a ' +
            'refusal there is the system working.'
        )
      )
    )
  );
}
