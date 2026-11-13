// The Open page: the lab tree (GET /api/labs; every lab of the host, the exam-only and draft
// ones included, while an instructor picks the debug mode: GET /api/labs?all=1), the start of a
// lab (POST /api/projects, an NDJSON stream of progress events), the Flavor form a lab may ask
// before starting and, for the instructors, the project mode (standard, instructor mode, debug
// mode) and the Host select (a host reserved for them, or the automatic placement).
// Under the tree, the README of the directory being browsed (README.md / README.<lang>.md of
// the lab directory, rendered by the agent: tree.js), hidden when that directory has none.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_} from './i18n.js';
import {el, clear} from './ui.js';
import {buildTree} from './tree.js';
import {ProgressBox, runCreation, projectUrl, flavorDialog} from './creation.js';

const treeElement = document.getElementById('labs');
const readmeElement = document.getElementById('lab-readme');
const selectedElement = document.getElementById('selected-lab');
const startButton = document.getElementById('start-button');
const progress = new ProgressBox(document.getElementById('progress'));

let selectedLab = null;
let starting = false;
let flavor = null;   // {lab, dialog} of the Flavor form being filled (creation.js flavorDialog)
let labsRequest = 0; // the number of the last request of the lab list: an older answer is dropped

// The project mode an instructor chose: 'standard', 'instructor' or 'debug' (the students have no
// radios: 'standard').
function currentMode() {
  const checked = document.querySelector('input[name="mode"]:checked');
  return checked ? checked.value : 'standard';
}

function setBusy(busy) {
  starting = busy;
  startButton.disabled = busy || !selectedLab;
  for (const button of treeElement.querySelectorAll('button.lab')) {
    button.disabled = busy;
  }
  for (const radio of document.querySelectorAll('input[name="mode"]')) {
    radio.disabled = busy;
  }
}

// Show the README of a directory of the tree (node.readme: html rendered by the agent from the
// lab markdown, like the Informations text of a project) under the tree, or hide the pane when
// the directory has none (node null: no tree).  The same text stays as it is, its scroll
// position too; a link opens in another tab, the page keeps its selection.
let shownReadme = '';
function showReadme(node) {
  const html = (node && node.readme) || '';
  if (!readmeElement || html === shownReadme) {
    return;
  }
  shownReadme = html;
  readmeElement.innerHTML = html;
  for (const link of readmeElement.querySelectorAll('a[href]')) {
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
  }
  readmeElement.hidden = !html;
  readmeElement.scrollTop = 0;
}

// Show the Flavor form of a lab: the chunks of the result (first time), or the same form again
// with the error message of a refused flavor (the values are kept).
function showFlavorForm(lab, result) {
  if (!flavor || flavor.lab !== lab || result.status === 'flavor_form') {
    if (flavor) {
      flavor.dialog.remove();
    }
    const dialog = flavorDialog(result, {
      onSubmit: (answers) => start(lab, answers),
      onCancel: () => progress.hide(),
    });
    flavor = {lab, dialog};
  }
  flavor.dialog.setError(result.status === 'flavor_error' ? (result.message || _('This flavor is not allowed.')) : '');
  flavor.dialog.show();
}

async function start(lab, flavorAnswers = null) {
  if (starting) {
    return;
  }
  setBusy(true);
  const body = flavorAnswers ? {lab, flavor: flavorAnswers} : {lab};
  const mode = currentMode();
  if (mode === 'instructor') {
    body.instructor_mode = true;   // an instructor's own project in instructor mode (privileged start)
  } else if (mode === 'debug') {
    body.debug_project = true;     // ... or in debug mode (sre start --debug-web-project)
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

// The lab tree: the student catalog, or every lab of the host (the exam-only and draft ones too)
// in debug mode; the lab selected stays selected when the new list holds it.
async function loadLabs() {
  const request = ++labsRequest;
  const all = currentMode() === 'debug';
  let labs;
  try {
    labs = await api.get(all ? '/api/labs?all=1' : '/api/labs');
  } catch (e) {
    if (request === labsRequest) {
      clear(treeElement);
      treeElement.append(el('p', {class: 'error'}, e.message));
      showReadme(null);
    }
    return;
  }
  if (request !== labsRequest) {
    return;   // a newer list is on its way
  }
  if (selectedLab && !labs.some((lab) => lab.name === selectedLab)) {
    selectedLab = null;
    selectedElement.textContent = '';
    startButton.disabled = true;
  }
  if (!labs.some((lab) => lab.name)) {   // nothing, or the README of the top directory alone
    clear(treeElement);
    treeElement.append(el('p', {class: 'muted'}, _('No lab is available.')));
    showReadme(null);
    return;
  }
  buildTree(treeElement, labs, {
    selected: selectedLab,
    onDirectory: showReadme,
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

async function main() {
  await i18n.init();
  fillHosts();
  startButton.addEventListener('click', () => {
    if (selectedLab) {
      start(selectedLab);
    }
  });
  // the list changes between the debug mode and the two others only
  let allLabs = currentMode() === 'debug';
  for (const radio of document.querySelectorAll('input[name="mode"]')) {
    radio.addEventListener('change', () => {
      const all = currentMode() === 'debug';
      if (all !== allLabs) {
        allLabs = all;
        loadLabs();
      }
    });
  }
  await loadLabs();
}

main();
