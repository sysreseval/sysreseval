// The Projects page: the running projects of the user (GET /api/projects every 5 s), one card
// per project with its Open link and Close button; without a running project, the SRE logo in
// large (#no-project), as the Qt GUI shows it when no project is open. An instructor's cards say
// the mode of each project (Standard / Instructor mode / Debug mode: the words of the Project
// mode radios of the Open page), the two non-standard modes also as a suffix of the title.
//
// During an exam (exam.js: the `sre-exam` event and currentExam()) the portal lists the exam
// projects only, their cards have no Close button and no Open link before the exam starts, and
// the page starts the exam labs the student has no project of (one at a time, through the
// usual POST /api/projects: the progress in #exam-progress, the Flavor form when the lab asks
// one), from the pre-start instant of the countdown or as soon as the exam binds a student who
// logs in later; when the exam starts (or once the single exam project is created during it,
// or when time added after the end resumes the exam) the page opens it.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format, resolveText} from './i18n.js';
import {el, clear, toast, formatTimestamp} from './ui.js';
import {projectUrl, ProgressBox, runCreation, flavorDialog} from './creation.js';
import {currentExam, isBound, serverNow} from './exam.js';

const REFRESH_INTERVAL = 5000;
const START_RETRY = 15;         // s before a failed automatic start is tried again (without retry_after)
const START_JITTER = 5000;      // ms: the first automatic start waits a random part of it (the whole room at once)

const list = document.getElementById('projects');
const logo = document.getElementById('no-project');   // shown instead of the empty list
const examNote = document.getElementById('exam-note');
const examProgress = new ProgressBox(document.getElementById('exam-progress'));
const closing = new Set();   // running lab names whose close is in progress
const isInstructor = document.body.dataset.instructor === 'true';

let projects = [];           // the rows of the last GET /api/projects
let exam = null;             // the exam binding the student (the `exam` of exam.js's state), or null
let starting = false;        // an automatic start is in progress
let nextTry = 0;             // ms: no automatic start before this time
let jittered = false;        // the first automatic start waited its random delay
let wakeTimer = null;        // the timer waking the automatic start at the pre-start instant
let flavor = null;           // {lab, dialog} of the Flavor form of an automatic start
let openWhenActive = false;  // the exam just started: open its single project

function projectApi(project) {
  return `/api/projects/${encodeURIComponent(project.host)}/${encodeURIComponent(project.running_lab_name)}`;
}

function examActive() {
  return exam !== null && exam.phase === 'active';
}

// the mode a project was started in (the Project mode radios of the Open page): a debug project
// has everything an instructor-mode one has, so it is the mode shown when both flags are set
function modeOf(project) {
  if (project.debug_project) {
    return 'debug';
  }
  return project.instructor_mode ? 'instructor' : 'standard';
}

function modeLabel(mode) {
  if (mode === 'debug') {
    return _('Debug mode');
  }
  return mode === 'instructor' ? _('Instructor mode') : _('Standard');
}

function card(project) {
  const rln = project.running_lab_name;
  const title = resolveText(project.title) || project.lab_name;
  const examProject = Boolean(project.exam);
  const actions = el('div', {class: 'actions'});
  if (!examProject || examActive()) {
    actions.append(el('a', {class: 'button primary', href: projectUrl(project.host, rln)}, _('Open')));
  } else {
    actions.append(el('span', {class: 'muted'}, _('Available when the exam starts')));
  }
  if (!examProject) {
    const closeButton = el('button', {type: 'button', class: 'danger'}, _('Close Project'));
    if (closing.has(rln)) {
      closeButton.disabled = true;
      closeButton.textContent = _('closing in progress...');
    }
    closeButton.addEventListener('click', async () => {
      if (!window.confirm(_('Close this project? Its machines will be stopped.'))) {
        return;
      }
      closing.add(rln);
      closeButton.disabled = true;
      closeButton.textContent = _('closing in progress...');
      try {
        await api.del(projectApi(project));
      } catch (e) {
        toast(e.message, {error: true});
      } finally {
        closing.delete(rln);
      }
      refresh();
    });
    actions.append(closeButton);
  }
  const mode = modeOf(project);
  const heading = el('h2', {title: rln}, title);
  if (mode !== 'standard') {
    heading.append(el('span', {class: 'mode ' + mode}, ` (${mode === 'debug' ? _('debug') : _('instructor')})`));
  }
  const meta = el('div', {class: 'meta'}, el('div', {}, _('Lab: ') + project.lab_name));
  if (isInstructor) {    // a student's projects are all standard: the line would say nothing
    meta.append(el('div', {class: 'mode ' + mode}, _('Mode: ') + modeLabel(mode)));
  }
  meta.append(el('div', {}, _('Host: ') + project.host),
              el('div', {}, _('Started: ') + formatTimestamp(project.started_at)));
  if (examProject) {
    meta.prepend(el('div', {class: 'exam'}, _('Exam: ') + (resolveText(project.exam.title) || '')));
  }
  return el('div', {class: 'card' + (mode === 'standard' ? '' : ' ' + mode) + (examProject ? ' exam' : '')},
    heading,
    meta,
    actions);
}

function render() {
  clear(list);
  const bound = isBound(exam);
  const empty = !projects.length;
  logo.hidden = !empty || bound;
  list.hidden = empty;
  for (const project of projects) {
    list.append(card(project));
  }
  renderNote();
}

// the line above the cards while the exam binds the student
function renderNote() {
  if (!isBound(exam)) {
    examNote.hidden = true;
    return;
  }
  let text = '';
  if (exam.address_allowed === false) {
    text = _('The exam is reserved to the browsers of its rooms: no project is available from your address.');
  } else if (exam.phase === 'waiting') {
    text = typeof exam.prestart_at === 'number' && serverNow() < exam.prestart_at
      ? _('Your other projects are hidden until the end of the exam. Its projects will be prepared shortly before it starts.')
      : _('Your other projects are hidden until the end of the exam. Its projects are being prepared.');
  } else if (exam.phase === 'starting') {
    text = _('The exam has started: its projects are being prepared.');
  } else if (exam.phase === 'active') {
    text = _('The exam is in progress: only its projects are available.');
  } else {
    text = _('The exam is over.');
  }
  examNote.textContent = text;
  examNote.hidden = false;
}

async function refresh() {
  try {
    projects = await api.get('/api/projects');
  } catch (e) {
    clear(list);
    logo.hidden = true;
    list.hidden = false;
    list.append(el('p', {class: 'error'}, e.message));
    return;
  }
  projects = Array.isArray(projects) ? projects : [];
  render();
  autoOpen();
  autoStart();
}

// -- the exam --------------------------------------------------------------------------------

// the exam labs the student has no running project of
function missingLabs() {
  const running = new Set(projects.map((p) => p.lab_name));
  return (exam && Array.isArray(exam.labs) ? exam.labs : []).filter((lab) => !running.has(lab.lab_name));
}

// whether the automatic starts may run now: the exam binds the student, from the address it
// allows, after the pre-start instant of the countdown (or at once without one)
function mayStart() {
  if (!isBound(exam) || exam.address_allowed === false || exam.phase === 'ended') {
    return false;
  }
  if (exam.phase === 'waiting') {
    return typeof exam.prestart_at === 'number' && serverNow() >= exam.prestart_at;
  }
  return true;
}

// a timer waking the automatic start at the pre-start instant of a countdown
function armWake() {
  if (wakeTimer) {
    window.clearTimeout(wakeTimer);
    wakeTimer = null;
  }
  if (exam && exam.phase === 'waiting' && typeof exam.prestart_at === 'number') {
    const delay = (exam.prestart_at - serverNow()) * 1000;
    if (delay > 0) {
      wakeTimer = window.setTimeout(() => {
        wakeTimer = null;
        autoStart();
      }, delay + 500);
    }
  }
}

// start the first missing exam lab (the next ones follow on the refreshes: the portal spaces
// the starts of one user anyway); a 409 means another browser of the student did it
async function autoStart(flavorAnswers = null, chosenLab = null) {
  if (starting || !mayStart()) {
    return;
  }
  const missing = missingLabs();
  const lab = chosenLab || (missing.length ? missing[0] : null);
  if (!lab || Date.now() < nextTry) {
    return;
  }
  if (!jittered) {
    jittered = true;
    nextTry = Date.now() + Math.random() * START_JITTER;
    window.setTimeout(() => autoStart(), nextTry - Date.now() + 10);
    return;
  }
  starting = true;
  const body = flavorAnswers ? {lab: lab.lab, flavor: flavorAnswers} : {lab: lab.lab};
  const label = format(_('Starting {lab} for the exam…'), {lab: resolveText(lab.title) || lab.lab});
  const result = await runCreation(examProgress, label, 'POST', '/api/projects', {json: body});
  starting = false;
  if (result.status === 'created') {
    examProgress.hide();
    if (flavor) {
      flavor.dialog.remove();
      flavor = null;
    }
    if (examActive() && exam.labs.length === 1) {
      window.location.assign(projectUrl(result.host, result.running_lab_name));
      return;
    }
    await refresh();
  } else if (result.status === 'flavor_form' || result.status === 'flavor_error') {
    examProgress.hide();
    showFlavorForm(lab, result);
  } else if (result.http_status === 409) {
    examProgress.hide();       // another browser of the student started it: the next poll lists it
    nextTry = Date.now() + START_RETRY * 1000;
  } else {
    const wait = result.retry_after || START_RETRY;
    nextTry = Date.now() + wait * 1000;
    examProgress.showError(result.message || _('The start failed.'));
    examProgress.label.textContent = format(_('Next attempt in {n} s'), {n: Math.ceil(wait)});
  }
}

// the Flavor form a lab asks before starting: the chunks of the result (first time), or the
// same form again with the error message of a refused flavor (the values are kept)
function showFlavorForm(lab, result) {
  if (!flavor || flavor.lab !== lab.lab || result.status === 'flavor_form') {
    if (flavor) {
      flavor.dialog.remove();
    }
    const dialog = flavorDialog(result, {
      onSubmit: (answers) => autoStart(answers, lab),
      onCancel: () => {
        nextTry = Date.now() + START_RETRY * 1000;   // the form comes back at the next attempt
      },
    });
    flavor = {lab: lab.lab, dialog};
  }
  flavor.dialog.setError(result.status === 'flavor_error' ? (result.message || _('This flavor is not allowed.')) : '');
  flavor.dialog.show();
}

// the exam just started: its single project is opened (several: the cards stay)
function autoOpen() {
  if (!openWhenActive || !examActive()) {
    return;
  }
  const examProjects = projects.filter((p) => p.exam);
  if (exam.labs.length === 1 && examProjects.length === 1) {
    openWhenActive = false;
    window.location.assign(projectUrl(examProjects[0].host, examProjects[0].running_lab_name));
  } else if (examProjects.length) {
    openWhenActive = false;
  }
}

function applyExam(state) {
  const previous = exam;
  exam = state && isBound(state.exam) ? state.exam : null;
  const wasPreparing = previous !== null && (previous.phase === 'waiting' || previous.phase === 'starting');
  const resumed = previous !== null && previous.phase === 'ended';     // time added after the end
  if (exam && exam.phase === 'active' && (wasPreparing || resumed || previous === null)) {
    openWhenActive = true;
  }
  if (!exam) {
    examProgress.hide();
  }
  armWake();
  render();
  autoOpen();
  autoStart();
}

async function main() {
  await i18n.init();
  document.addEventListener('sre-exam', (ev) => applyExam(ev.detail));
  const known = currentExam();
  if (known) {
    exam = isBound(known.exam) ? known.exam : null;
    armWake();
  }
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
