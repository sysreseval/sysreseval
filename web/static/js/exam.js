// The exam a student is in, on every page of a logged-in user (set up by base.js): the state
// of GET /api/exam ({"now", "exam": null | {id, title, phase, start_at, prestart_at, end_at,
// lead, labs, address_allowed, address, dismissable}}), fetched at load, again on every
// {"t": "exam"} push of the presence socket (the `sre-exam-push` event base.js dispatches) and
// every minute as a fallback, is shown as a bar under the site bar (the countdown to the start
// while the exam is being prepared, the time left while it runs, the end, or the refusal of the
// browser's address) and, once the exam is over, as an overlay covering the page until the
// student presses Continue (POST /api/exam/{id}/dismiss).  The countdown is computed on the
// portal's clock (its `now` gives the offset of the browser's).  The pages learn the state
// through the `sre-exam` event on the document (projects.js starts the exam projects, project.js
// hides Close and ends the page); a page that is not the Projects page goes there when the exam
// starts.  Instructors are never bound by an exam: their pages get null.

import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format, resolveText} from './i18n.js';
import {el, toast} from './ui.js';

const REFRESH_INTERVAL = 60000;     // ms: the fallback poll of GET /api/exam
const PHASE_WAITING = 'waiting';
const PHASE_STARTING = 'starting';
const PHASE_ACTIVE = 'active';
const PHASE_ENDED = 'ended';
export const BOUND_PHASES = [PHASE_WAITING, PHASE_STARTING, PHASE_ACTIVE, PHASE_ENDED];

const body = document.body;
let state = null;           // {exam, now, offset}: offset = the browser's clock minus the portal's (seconds)
let bar = null;             // {element, title, text, countdown}
let overlay = null;         // the end overlay, while shown
let timer = null;           // the 1 s countdown
let refreshing = null;      // the GET in progress
let lastPhase = null;       // the phase last rendered (null: unbound)
let lastLabs = null;        // the lab names last rendered (a lab added: the Projects page starts it)
let crossed = false;        // the countdown reached zero: one refresh asked

// The state the page learnt last (null before the first answer): {exam, now, offset}.
export function currentExam() {
  return state;
}

// Whether the exam of a state binds the user (its projects are the only ones reachable).
export function isBound(exam) {
  return Boolean(exam) && BOUND_PHASES.includes(exam.phase);
}

// The portal's clock, in seconds.
export function serverNow() {
  return Date.now() / 1000 - (state ? state.offset : 0);
}

// the lab of a running lab name ("ts@@@sre@dhcp.py@@@alice"), in the form the exam labs carry (lab_name)
export function labOfRunningLabName(rln) {
  return String(rln || '').split('@@@')[1] || '';
}

function examLabNames(exam) {
  return (exam && Array.isArray(exam.labs) ? exam.labs : []).map((lab) => lab.lab_name);
}

// Fetch the state again (the pushes, the fallback poll, a page asking after an event of the agent).
export async function refreshExam() {
  if (refreshing) {
    return refreshing;
  }
  refreshing = (async () => {
    let data;
    try {
      data = await api.get('/api/exam');
    } catch (e) {
      return state;       // the last state stays (a transient failure, or a logged-out page)
    } finally {
      refreshing = null;
    }
    const now = typeof data.now === 'number' ? data.now : Date.now() / 1000;
    state = {exam: data.exam || null, now, offset: Date.now() / 1000 - now};
    crossed = false;
    render();
    document.dispatchEvent(new CustomEvent('sre-exam', {detail: state}));
    return state;
  })();
  return refreshing;
}

// -- the bar -----------------------------------------------------------------------------------

function ensureBar() {
  if (bar) {
    return bar;
  }
  const title = el('span', {class: 'exam-title'});
  const text = el('span', {class: 'exam-text'});
  const countdown = el('span', {class: 'countdown'});
  const element = el('div', {id: 'exam-bar', class: 'exam-bar'}, title, text, countdown);
  element.hidden = true;
  const topbar = document.querySelector('header.topbar');
  if (topbar) {
    topbar.after(element);
  } else {
    body.prepend(element);
  }
  bar = {element, title, text, countdown};
  return bar;
}

function countdownTarget(exam) {
  if (exam.phase === PHASE_WAITING) {
    return exam.start_at;
  }
  if (exam.phase === PHASE_ACTIVE) {
    return exam.end_at;
  }
  return null;
}

function tick() {
  const exam = state ? state.exam : null;
  if (!bar || !exam) {
    return;
  }
  const target = countdownTarget(exam);
  if (typeof target !== 'number') {
    bar.countdown.textContent = '';
    return;
  }
  const left = target - serverNow();
  bar.countdown.textContent = formatCountdown(Math.max(0, left));
  if (left <= 0 && !crossed) {
    crossed = true;         // the phase changed on the portal: ask (the push comes too)
    refreshExam();
  }
}

// HH:MM:SS, as the Qt GUI shows the countdowns
function formatCountdown(seconds) {
  const total = Math.max(0, Math.round(seconds));
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(Math.floor(total / 3600))}:${pad(Math.floor((total % 3600) / 60))}:${pad(total % 60)}`;
}

function renderBar(exam) {
  const b = ensureBar();
  if (!exam || !isBound(exam)) {
    b.element.hidden = true;
    b.element.classList.remove('denied');
    return;
  }
  const title = resolveText(exam.title) || '';
  b.title.textContent = format(_('Exam «{title}»'), {title});
  b.element.classList.toggle('denied', exam.address_allowed === false);
  b.countdown.textContent = '';
  if (exam.address_allowed === false) {
    b.text.textContent = format(_('your address {address} is not allowed for this exam.'), {address: exam.address || ''});
  } else if (exam.phase === PHASE_WAITING) {
    b.text.textContent = _('starts in') + ' ';
  } else if (exam.phase === PHASE_STARTING) {
    b.text.textContent = _('the exam is being prepared: its projects are starting…');
  } else if (exam.phase === PHASE_ACTIVE) {
    b.text.textContent = _('time left:') + ' ';
  } else {
    b.text.textContent = _('the exam is over.');
  }
  if (exam.phase === PHASE_WAITING && exam.address_allowed !== false) {
    b.text.append(el('span', {class: 'muted hint'}, ' — ' + _('your other projects are hidden until it ends')));
  }
  b.element.hidden = false;
  tick();
}

// -- the end overlay ---------------------------------------------------------------------------

function removeOverlay() {
  if (overlay) {
    overlay.remove();
    overlay = null;
    body.classList.remove('has-exam-ended');
  }
}

function showOverlay(exam) {
  if (overlay) {
    return;
  }
  for (const dialog of document.querySelectorAll('dialog[open]')) {
    dialog.close();      // a modal dialog lives in the top layer, above any z-index
  }
  const button = el('button', {type: 'button', class: 'primary'}, _('Continue'));
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await api.post(`/api/exam/${encodeURIComponent(exam.id)}/dismiss`);
    } catch (e) {
      if (e.status !== 409 && e.status !== 404) {    // already dismissed, or the exam is gone: go on
        toast(e.message, {error: true});
        button.disabled = false;
        return;
      }
    }
    window.location.assign('/projects');
  });
  overlay = el('div', {id: 'exam-ended', class: 'exam-ended'},
    el('img', {src: '/static/img/thats_all_folks.svg', alt: ''}),
    el('p', {class: 'exam-ended-title'}, format(_('The exam «{title}» is over.'), {title: resolveText(exam.title) || ''})),
    el('p', {class: 'muted'}, _('Your work has been evaluated. Press Continue to get back to your projects.')),
    button);
  body.append(overlay);
  body.classList.add('has-exam-ended');
  button.focus();
}

// -- the body and the navigation ---------------------------------------------------------------

function render() {
  const exam = state ? state.exam : null;
  const bound = isBound(exam);
  const phase = bound ? exam.phase : null;
  for (const name of Array.from(body.classList)) {
    if (name.startsWith('exam-')) {
      body.classList.remove(name);
    }
  }
  if (bound) {
    body.classList.add('exam-bound', `exam-${phase}`);
    if (exam.address_allowed === false) {
      body.classList.add('exam-denied');
    }
  }
  renderBar(exam);
  if (phase === PHASE_ENDED && exam.dismissable !== false && exam.address_allowed !== false) {
    showOverlay(exam);
  } else {
    removeOverlay();
  }
  if (bound && !timer) {
    timer = window.setInterval(tick, 1000);
  } else if (!bound && timer) {
    window.clearInterval(timer);
    timer = null;
  }
  navigate(exam, phase);
  lastPhase = phase;
}

// Where a page goes when the exam changes: the Projects page when the exam starts (it opens
// the exam project), when the user is bound while on the Open page, or when a lab is added to
// the exam while the page shows an exam project (the Projects page starts the new one); the
// project page of an exam project stays otherwise (project.js handles it).
function navigate(exam, phase) {
  const labs = phase ? examLabNames(exam) : null;
  const previousLabs = lastLabs;
  lastLabs = labs;
  if (!phase) {
    return;
  }
  const path = window.location.pathname;
  const onProjects = path === '/projects' || path === '/';
  const rln = body.dataset.rln || '';
  const onExamProject = Boolean(rln) && labs.includes(labOfRunningLabName(rln));
  if (phase === lastPhase) {
    const added = previousLabs !== null && labs.some((name) => !previousLabs.includes(name));
    if (added && onExamProject && (phase === PHASE_ACTIVE || phase === PHASE_STARTING)) {
      window.location.assign('/projects');
    }
    return;
  }
  const wasPreparing = lastPhase === PHASE_WAITING || lastPhase === PHASE_STARTING;
  if (phase === PHASE_ACTIVE && wasPreparing && !onProjects && !onExamProject) {
    window.location.assign('/projects');
  } else if (lastPhase === null && path === '/open') {
    window.location.assign('/projects');
  }
}

export function setupExam() {
  document.addEventListener('sre-exam-push', () => { refreshExam(); });
  i18n.init().then(() => refreshExam());
  window.setInterval(refreshExam, REFRESH_INTERVAL);
}
