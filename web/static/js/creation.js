// The progress of a project creation (POST /api/projects): the
// NDJSON events of `sre start` (SRE/progress.py) shown like the Qt
// StartProgressDialog, the final "result" line, and the dialog of the Flavor form a lab may ask
// before starting (the Open page and the automatic starts of an exam).

import * as api from './api.js';
import {el} from './ui.js';
import {_, format} from './i18n.js';
import {Form} from './form.js';

// A label, a progress bar, the last plain line of stderr as detail, an error with a Retry button.
export class ProgressBox {
  constructor(element) {
    this.element = element;
    this.label = el('div', {class: 'label'});
    this.bar = el('progress');
    this.detail = el('div', {class: 'detail'});
    this.error = el('div', {class: 'error'});
    this.retry = el('div', {class: 'retry'});
    element.textContent = '';
    element.append(this.label, this.bar, this.detail, this.error, this.retry);
    element.hidden = true;
  }

  start(label) {
    this.element.hidden = false;
    this.label.textContent = label;
    this.bar.hidden = false;
    this.bar.removeAttribute('value');   // indeterminate until the first real event
    this.detail.textContent = '';
    this.error.textContent = '';
    this.retry.textContent = '';
  }

  hide() {
    this.element.hidden = true;
  }

  setProgress(value, max) {
    this.bar.max = Math.max(max, 1);
    this.bar.value = value;
  }

  // One event of the NDJSON stream.
  handleEvent(ev) {
    const phase = ev.phase;
    const status = ev.status;
    if (phase === 'pull') {
      if (status === 'start') {
        this.bar.removeAttribute('value');
        this.label.textContent = _('Downloading images…');
      } else if (status === 'downloading') {
        const pct = ev.overall_percent || 0;
        this.setProgress(pct, 100);
        this.label.textContent = format(_('Downloading images: {pct}%'), {pct});
      } else if (status === 'end') {
        this.setProgress(100, 100);
        this.label.textContent = _('Images ready.');
      }
    } else if (phase === 'deploy') {
      if (status === 'start') {
        const total = ev.total || 0;
        this.setProgress(0, total);
        this.label.textContent = format(_('Starting {n} machine(s)…'), {n: total});
      } else if (status === 'progress') {
        const current = ev.current || 0;
        const total = ev.total || 1;
        this.setProgress(current, total);
        this.label.textContent = format(_('Starting machines: {cur}/{tot}'), {cur: current, tot: total});
      } else if (status === 'end') {
        this.setProgress(this.bar.max, this.bar.max);
        this.label.textContent = _('All machines started.');
      }
    } else if (phase === 'message') {
      this.detail.textContent = ev.line || '';
    }
  }

  // Show an error; onRetry (optional) adds a Retry button, retryAfter (seconds) a countdown
  // before the button is enabled (429: wait before starting another project).
  showError(message, {onRetry = null, retryAfter = 0} = {}) {
    this.element.hidden = false;
    this.bar.hidden = true;
    this.error.textContent = message;
    this.retry.textContent = '';
    if (!onRetry) {
      return;
    }
    const button = el('button', {type: 'button'}, _('Retry'));
    this.retry.append(button);
    if (retryAfter > 0) {
      button.disabled = true;
      let remaining = Math.ceil(retryAfter);
      const tick = () => {
        if (remaining <= 0) {
          button.disabled = false;
          button.textContent = _('Retry');
          return;
        }
        button.textContent = format(_('Retry in {n} s'), {n: remaining});
        remaining -= 1;
        window.setTimeout(tick, 1000);
      };
      tick();
    }
    button.addEventListener('click', () => {
      this.retry.textContent = '';
      onRetry();
    });
  }
}

// Run a creation request and feed its events to the box.  Resolves with the final result event
// ({phase: "result", status: "created" | "flavor_form" | "flavor_error" | "error", ...}); the
// HTTP errors (no stream: 429, 503...) are turned into a result of status "error" carrying the
// status and retry_after of the answer, so that the callers handle one shape.
export async function runCreation(box, label, method, url, options) {
  box.start(label);
  let response;
  try {
    response = await api.fetchRaw(method, url, options);
  } catch (e) {
    return {phase: 'result', status: 'error', message: e.message || String(e), http_status: e.status || 0,
            retry_after: (e.data && e.data.retry_after) || 0};
  }
  let result = null;
  try {
    result = await api.readNdjson(response, (ev) => box.handleEvent(ev));
  } catch (e) {
    return {phase: 'result', status: 'error', message: e.message || String(e)};
  }
  if (!result) {
    return {phase: 'result', status: 'error', message: _('The connection was closed before the end.')};
  }
  return result;
}

// The page of a project just created.
export function projectUrl(host, runningLabName) {
  return `/projects/${encodeURIComponent(host)}/${encodeURIComponent(runningLabName)}`;
}

// The dialog of the Flavor form of a lab, built from a "flavor_form" result (its chunks and
// size): onSubmit(answers) when the form is submitted, onCancel() when the dialog is closed
// without.  The dialog stays in the page so that a refused flavor ("flavor_error") shows the
// same form again with its message and the values kept (setError); remove() drops it.
export function flavorDialog(result, {onSubmit, onCancel = () => {}}) {
  const error = el('div', {class: 'form-error'});
  const body = el('div', {class: 'form-body'});
  const cancel = el('button', {type: 'button'}, _('Cancel'));
  const dialog = el('dialog', {class: 'modal flavor'},
    el('h2', {}, _('Lab configuration')), error, body, el('div', {class: 'buttons'}, cancel));
  if (Array.isArray(result.form_size) && result.form_size.length === 2) {
    dialog.style.width = result.form_size[0] + 'px';
  }
  let submitted = false;
  const form = new Form(body, result.chunks || [], {
    allowSubmit: true,
    onSubmit: () => {
      submitted = true;
      dialog.close();
      onSubmit(form.getAnswers());
    },
  });
  cancel.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => {
    if (!submitted) {
      onCancel();
    }
  });
  document.body.append(dialog);
  return {
    dialog, form,
    setError(text) {
      error.textContent = text || '';
    },
    show() {
      submitted = false;
      dialog.showModal();
    },
    remove() {
      dialog.remove();
    },
  };
}
