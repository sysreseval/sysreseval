// The Open page: the lab tree (GET /api/labs), the start of a lab (POST /api/projects, an
// NDJSON stream of progress events), the Flavor form a lab may ask before starting and, for
// the instructors, the Host select (a host reserved for them, or the automatic placement).

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_} from './i18n.js';
import {el, clear} from './ui.js';
import {buildTree} from './tree.js';
import {Form} from './form.js';
import {ProgressBox, runCreation, projectUrl} from './creation.js';

const treeElement = document.getElementById('labs');
const selectedElement = document.getElementById('selected-lab');
const startButton = document.getElementById('start-button');
const progress = new ProgressBox(document.getElementById('progress'));

let selectedLab = null;
let starting = false;
let flavor = null;   // {lab, dialog, form, error} of the Flavor form being filled

function setBusy(busy) {
  starting = busy;
  startButton.disabled = busy || !selectedLab;
  for (const button of treeElement.querySelectorAll('button.lab')) {
    button.disabled = busy;
  }
}

// Show the Flavor form of a lab: the chunks of the result (first time), or the same form again
// with the error message of a refused flavor (the values are kept).
function showFlavorForm(lab, result) {
  if (!flavor || flavor.lab !== lab || result.status === 'flavor_form') {
    if (flavor) {
      flavor.dialog.remove();
    }
    const error = el('div', {class: 'form-error'});
    const body = el('div', {class: 'form-body'});
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const dialog = el('dialog', {class: 'flavor'},
      el('h2', {}, _('Lab configuration')), error, body, el('div', {class: 'buttons'}, cancel));
    if (Array.isArray(result.form_size) && result.form_size.length === 2) {
      dialog.style.width = result.form_size[0] + 'px';
    }
    const form = new Form(body, result.chunks || [], {
      allowSubmit: true,
      onSubmit: () => {
        dialog.close();
        start(lab, form.getAnswers());
      },
    });
    cancel.addEventListener('click', () => {
      dialog.close();
      progress.hide();
    });
    dialog.addEventListener('cancel', () => progress.hide());
    document.body.append(dialog);
    flavor = {lab, dialog, form, error};
  }
  flavor.error.textContent = result.status === 'flavor_error' ? (result.message || _('This flavor is not allowed.')) : '';
  flavor.dialog.showModal();
}

async function start(lab, flavorAnswers = null) {
  if (starting) {
    return;
  }
  setBusy(true);
  const body = flavorAnswers ? {lab, flavor: flavorAnswers} : {lab};
  const instructorBox = document.getElementById('instructor-mode');
  if (instructorBox && instructorBox.checked) {
    body.instructor_mode = true;   // an instructor's own project in instructor mode (privileged start)
  }
  const hostSelect = document.getElementById('host');
  if (hostSelect && hostSelect.value) {
    body.host = hostSelect.value;  // an instructor's choice: a host reserved for them
  }
  const result = await runCreation(progress, _('Starting…'), 'POST', '/api/projects', {json: body});
  setBusy(false);
  if (result.status === 'created') {
    progress.label.textContent = _('Project created, opening it…');
    window.location.href = projectUrl(result.host, result.running_lab_name);
  } else if (result.status === 'flavor_form' || result.status === 'flavor_error') {
    progress.hide();
    showFlavorForm(lab, result);
  } else {
    progress.showError(result.message || _('The start failed.'),
                       {onRetry: () => start(lab, flavorAnswers), retryAfter: result.retry_after || 0});
  }
}

// The Host select of the instructors (students have none): one option per host reserved for
// them (instructors_only), with its state and its projects, disabled when it is not up or is
// full; the label stays hidden when the pool has no such host.
async function fillHosts() {
  const select = document.getElementById('host');
  if (!select) {
    return;
  }
  let rows;
  try {
    rows = await api.get('/api/pool');
  } catch (e) {
    return;
  }
  let added = 0;
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row.instructors_only) {
      continue;
    }
    const detail = row.reachable ? `${row.state}, ${row.projects}/${row.max_projects}` : row.state;
    select.append(el('option', {value: row.name, disabled: row.state !== 'up' || row.projects >= row.max_projects},
                     `${row.name} (${detail})`));
    added += 1;
  }
  if (added) {
    document.getElementById('host-option').hidden = false;
  }
}

async function main() {
  await i18n.init();
  fillHosts();
  startButton.addEventListener('click', () => {
    if (selectedLab) {
      start(selectedLab);
    }
  });
  let labs;
  try {
    labs = await api.get('/api/labs');
  } catch (e) {
    clear(treeElement);
    treeElement.append(el('p', {class: 'error'}, e.message));
    return;
  }
  if (!labs.length) {
    clear(treeElement);
    treeElement.append(el('p', {class: 'muted'}, _('No lab is available.')));
    return;
  }
  buildTree(treeElement, labs, {
    onSelect: (name) => {
      selectedLab = name;
      selectedElement.textContent = name;
      startButton.disabled = starting;
    },
    onOpen: (name) => {
      selectedLab = name;
      selectedElement.textContent = name;
      start(name);
    },
  });
}

main();
