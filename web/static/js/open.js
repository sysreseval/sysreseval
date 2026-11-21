// The Open page: the lab tree (GET /api/labs; every lab of the host, the exam-only and draft
// ones included, while an instructor picks the debug mode: GET /api/labs?all=1), the start of a
// lab (POST /api/projects, an NDJSON stream of progress events), the Flavor form a lab may ask
// before starting and, for the instructors, the project mode (standard, instructor mode, debug
// mode) and the Host select (a host reserved for them, or the automatic placement).
// Under the tree, the README of the directory being browsed (README.md / README.<lang>.md of
// the lab directory, rendered by the agent: tree.js), hidden when that directory has none.
// The Lab costs button of the instructors (not pressed at first, and never remembered) shows
// beside each lab what one of its projects is counted for on a host: the columns of the Lab
// costs box of the Pool page (GET /api/pool/costs, asked while they are shown; lab_costs.js).

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_} from './i18n.js';
import {el, clear} from './ui.js';
import {buildTree} from './tree.js';
import {ProgressBox, runCreation, projectUrl, flavorDialog} from './creation.js';
import {costCells, costNote, costRowOf, NOTE_SEPARATOR} from './lab_costs.js';

const treeElement = document.getElementById('labs');
const readmeElement = document.getElementById('lab-readme');
const selectedElement = document.getElementById('selected-lab');
const startButton = document.getElementById('start-button');
const progress = new ProgressBox(document.getElementById('progress'));
// the lab costs: the three elements of an instructor's page (a student's has none)
const costsToggle = document.getElementById('costs-toggle');
const costsNoteElement = document.getElementById('lab-costs-note');
const costsHead = document.getElementById('lab-costs-head');   // a <template>: the titles of the columns

let selectedLab = null;
let starting = false;
let flavor = null;   // {lab, dialog} of the Flavor form being filled (creation.js flavorDialog)
let labsRequest = 0; // the number of the last request of the lab list: an older answer is dropped
// the costs beside the labs: shown or not, and the number of the last request of the costs (an
// older answer is dropped)
const costs = {shown: false, request: 0};

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
    // full: its max_projects, or no memory for one more project ([pool] project_memory_mb), or,
    // with [pool] capacity = "resources", no memory or no processor for one more
    const full = row.projects >= row.max_projects || row.memory_room === 0 || row.cpu_room === 0;
    select.append(el('option', {value: row.name, disabled: row.state !== 'up' || full},
                     `${row.name} (${detail})`));
    added += 1;
  }
  if (added) {
    document.getElementById('host-option').hidden = false;
  }
}

// Take the costs off the tree: the row of the titles and the cells of every lab.
function clearCosts() {
  for (const old of treeElement.querySelectorAll('.lab-costs-head, li.leaf > .lab-costs')) {
    old.remove();
  }
}

// Draw the answer of GET /api/pool/costs on the tree: the titles of the columns at its top (they
// stay there while it scrolls) and, after the button of each lab, the six cells of the Lab costs
// box of the Pool page.  A lab the pool knows nothing of has the default cost (costRowOf).
function drawCosts(data) {
  clearCosts();
  const leaves = treeElement.querySelectorAll('li.leaf');
  if (!leaves.length) {
    return;   // no tree: a message
  }
  treeElement.prepend(costsHead.content.firstElementChild.cloneNode(true));   // the row alone, not the blanks around it
  for (const leaf of leaves) {
    const button = leaf.querySelector('button.lab');
    const row = costRowOf(data, button ? button.dataset.lab : '');
    const cells = costCells(row);
    const source = cells.pop();
    leaf.append(el('span', {class: 'lab-costs'},
                   ...cells.map((text) => el('span', {class: 'num'}, text)),
                   el('span', {class: `source ${row.source || ''}`}, source)));
  }
}

// Ask the costs and draw them, while they are shown: when the button is pressed, and after
// every build of the tree (which drops the cells; and the lab list it was built from has just
// told the pool the weights of its labs).  Never drawn from an older answer.
async function refreshCosts() {
  if (!costs.shown) {
    return;
  }
  const request = ++costs.request;
  let data = null;
  let error = '';
  try {
    data = await api.get('/api/pool/costs');
  } catch (e) {
    error = e.message;
  }
  if (request !== costs.request || !costs.shown) {
    return;   // a newer request is on its way, or the costs were hidden meanwhile
  }
  costsNoteElement.className = error ? 'lab-costs-note error' : 'lab-costs-note muted';
  costsNoteElement.textContent = error || costNote(data).join(NOTE_SEPARATOR);
  if (error) {
    clearCosts();
  } else {
    drawCosts(data);
  }
}

// The Lab costs button of the instructors; a student's page has none, and never asks the costs.
function setupCosts() {
  if (!costsToggle || !costsNoteElement || !costsHead) {
    return;
  }
  costsToggle.addEventListener('click', () => {
    costs.shown = !costs.shown;
    costsToggle.setAttribute('aria-pressed', String(costs.shown));
    treeElement.classList.toggle('with-costs', costs.shown);
    costsNoteElement.hidden = !costs.shown;
    if (costs.shown) {
      costsNoteElement.textContent = '';
      refreshCosts();
    } else {
      clearCosts();
    }
  });
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
  refreshCosts();   // the new tree has no cell
}

async function main() {
  await i18n.init();
  fillHosts();
  setupCosts();
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
