// The Exams page of the instructors: the exams programmed on the portal (GET /api/exams every
// 5 s), one row per exam with its status (scheduled, running, past: the toggles, the past ones
// hidden at first), its times, its labs, its audience and its creator, sorted by any column and
// filtered by text (kept in the URL as ?q= and ?status=); New exam, Edit and Delete through the
// dialog of exams_form.js (POST / PUT / DELETE /api/exams…).  A click on a row (or Open) shows
// the detail of the exam (GET /api/exams/{id} every 5 s, ?id= in the URL): its members (login,
// name, group, connected, address, phase, start and end of their individual clock, extra
// minutes, labs, projects linked to the instructor's view of the project), a checkbox per
// member, and the actions during the exam: Start now (the start time set to now), End now
// (everybody), ± N minutes for all (the duration and the end-before time move) or for the
// selected members (extra minutes on their own clock), End for selected, Change labs of the
// selected members, Close the projects of the selection.  Every action replaces the summary
// and reloads the detail; nothing is optimistic.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast, formatDuration} from './ui.js';
import {projectUrl} from './creation.js';
import {createExamForm, labsDialog, labsText} from './exams_form.js';

const REFRESH_INTERVAL = 5000;
const STATUSES = ['scheduled', 'running', 'past'];
const STATUS_ORDER = {running: 0, scheduled: 1, past: 2};
const PHASE_ORDER = {active: 0, starting: 1, waiting: 2, ended: 3, done: 4, past: 5, scheduled: 6};
const NUMERIC = ['start', 'end', 'duration', 'members', 'started_at', 'end_at', 'extra_minutes'];

const table = document.getElementById('exams');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('exams-filter');
const statusButtons = Array.from(document.querySelectorAll('#exams-status button[data-status]'));
const countElement = document.getElementById('exams-count');
const newButton = document.getElementById('exams-new');
const notice = document.getElementById('exams-notice');
const detail = document.getElementById('exam-detail');
const detailTitle = document.getElementById('exam-detail-title');
const detailSummary = document.getElementById('exam-detail-summary');
const detailNotice = document.getElementById('exam-detail-notice');
const membersTable = document.getElementById('exam-members');
const membersBody = membersTable.querySelector('tbody');
const selectAll = document.getElementById('exam-select-all');
const minutesInput = document.getElementById('exam-minutes');
const groupSourcesEnabled = table.dataset.groupSources === 'true';
const databaseConfigured = table.dataset.database === 'true';
const available = table.dataset.available === 'true';

const buttons = {
  startNow: document.getElementById('exam-start-now'),
  endNow: document.getElementById('exam-end-now'),
  extendAll: document.getElementById('exam-extend-all'),
  reduceAll: document.getElementById('exam-reduce-all'),
  extendSelected: document.getElementById('exam-extend-selected'),
  reduceSelected: document.getElementById('exam-reduce-selected'),
  endSelected: document.getElementById('exam-end-selected'),
  labsSelected: document.getElementById('exam-labs-selected'),
  closeProjects: document.getElementById('exam-close-projects'),
  edit: document.getElementById('exam-edit'),
  delete: document.getElementById('exam-delete'),
  close: document.getElementById('exam-detail-close'),
};

// exams: the summaries of the API; now: the portal's clock at the last answer; statuses: shown
const state = {exams: [], now: 0, filter: '', statuses: new Set(['scheduled', 'running']), sortKey: 'start', sortAsc: true};
// the open detail: id, the data of GET /api/exams/{id}, the selected logins, the sort of the members
const open = {id: null, data: null, selected: new Set(), sortKey: 'login', sortAsc: true, timer: null};
let labsCache = null;      // the entries of GET /api/labs?all=1
let groupsCache = null;    // the groups of GET /api/groups

function examUrl(id, suffix = '') {
  return `/api/exams/${encodeURIComponent(id)}${suffix}`;
}

function columnCount(t) {
  return t.querySelectorAll('thead th:not([hidden])').length;
}

function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function dateText(epoch) {
  return isNumber(epoch) ? new Date(epoch * 1000).toLocaleString() : '';
}

function timeText(epoch) {
  return isNumber(epoch) ? new Date(epoch * 1000).toLocaleTimeString() : '';
}

function statusLabel(status) {
  const labels = {scheduled: _('scheduled'), running: _('running'), past: _('past')};
  return labels[status] || status || '';
}

function phaseLabel(phase) {
  const labels = {scheduled: _('not yet'), waiting: _('waiting'), starting: _('starting'), active: _('in progress'),
                  ended: _('ended'), done: _('ended'), past: _('did not take part')};
  return labels[phase] || phase || '';
}

// the Start cell of a summary: its start time, or how it starts
function startText(exam) {
  if (isNumber(exam.start_at)) {
    return dateText(exam.start_at);
  }
  return exam.start_after === null || exam.start_after === undefined ? _('when the student logs in') : dateText(exam.start_after);
}

// the End cell: the end-before time, or the end of the exam ended by hand
function endText(exam) {
  if (isNumber(exam.ended_at)) {
    return format(_('ended {date}'), {date: dateText(exam.ended_at)});
  }
  return isNumber(exam.end_before) ? dateText(exam.end_before) : '';
}

function durationText(exam) {
  return isNumber(exam.duration) ? formatDuration(exam.duration * 60) : '';
}

function audienceText(exam) {
  const audience = exam.audience || {};
  const parts = [];
  if ((audience.logins || []).length) {
    parts.push(format(_('{n} login(s)'), {n: audience.logins.length}));
  }
  for (const key of audience.groups || []) {
    parts.push(key);
  }
  return parts.join(', ');
}

// -- the URL ----------------------------------------------------------------------------------

function readUrl() {
  const params = new URLSearchParams(window.location.search);
  filterInput.value = params.get('q') || '';
  state.filter = filterInput.value.trim().toLowerCase();
  const statuses = (params.get('status') || '').split(',').map((s) => s.trim()).filter((s) => STATUSES.includes(s));
  if (statuses.length) {
    state.statuses = new Set(statuses);
  }
  open.id = params.get('id') || null;
}

function writeUrl() {
  const url = new URL(window.location.href);
  if (state.filter) {
    url.searchParams.set('q', filterInput.value.trim());
  } else {
    url.searchParams.delete('q');
  }
  const chosen = STATUSES.filter((s) => state.statuses.has(s));
  if (chosen.length === 2 && !state.statuses.has('past')) {
    url.searchParams.delete('status');
  } else {
    url.searchParams.set('status', chosen.join(','));
  }
  if (open.id) {
    url.searchParams.set('id', open.id);
  } else {
    url.searchParams.delete('id');
  }
  window.history.replaceState(null, '', url);
}

// -- the list ---------------------------------------------------------------------------------

function sortValue(exam, key) {
  switch (key) {
    case 'status': return STATUS_ORDER[exam.status] === undefined ? 9 : STATUS_ORDER[exam.status];
    case 'start': return isNumber(exam.start_at) ? exam.start_at : (isNumber(exam.start_after) ? exam.start_after : exam.created_at || 0);
    case 'end': return isNumber(exam.end_before) ? exam.end_before : Infinity;
    case 'duration': return isNumber(exam.duration) ? exam.duration : Infinity;
    case 'members': return exam.members || 0;
    default: return exam[key] || '';
  }
}

function compare(a, b) {
  const va = sortValue(a, state.sortKey);
  const vb = sortValue(b, state.sortKey);
  let result;
  if (typeof va === 'number' && typeof vb === 'number') {
    result = va - vb;
  } else {
    result = String(va).localeCompare(String(vb));
  }
  if (result === 0) {
    result = String(a.title || '').localeCompare(String(b.title || ''));
  }
  return state.sortAsc ? result : -result;
}

function matches(exam) {
  if (!state.statuses.has(exam.status)) {
    return false;
  }
  if (!state.filter) {
    return true;
  }
  const haystack = [exam.title, labsText(exam.labs), audienceText(exam), exam.created_by].join(' ').toLowerCase();
  return state.filter.split(/\s+/).every((word) => haystack.includes(word));
}

function render() {
  clear(body);
  const rows = state.exams.filter(matches).sort(compare);
  countElement.textContent = rows.length === state.exams.length
    ? format(_('{n} exam(s)'), {n: rows.length})
    : format(_('{n} of {total} exam(s)'), {n: rows.length, total: state.exams.length});
  for (const th of table.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === state.sortKey ? (state.sortAsc ? 'ascending' : 'descending') : 'none');
  }
  for (const button of statusButtons) {
    button.setAttribute('aria-pressed', state.statuses.has(button.dataset.status) ? 'true' : 'false');
  }
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: columnCount(table), class: 'muted'},
                                state.exams.length ? _('No exam matches the filter.') : _('No exam.'))));
    return;
  }
  for (const exam of rows) {
    body.append(renderRow(exam));
  }
}

function renderRow(exam) {
  const actions = [el('button', {type: 'button', class: 'primary', onclick: () => openDetail(exam.id)}, _('Open'))];
  if (databaseConfigured && available) {
    actions.push(el('button', {type: 'button', onclick: () => editExam(exam)}, _('Edit')));
    actions.push(el('button', {type: 'button', class: 'danger', onclick: () => deleteExam(exam)}, _('Delete')));
  }
  const tr = el('tr', {dataset: {id: String(exam.id)}, class: String(exam.id) === String(open.id) ? 'open' : ''},
    el('td', {class: 'title'}, exam.title || ''),
    el('td', {class: `status ${exam.status || ''}`}, statusLabel(exam.status)),
    el('td', {}, startText(exam)),
    el('td', {}, endText(exam)),
    el('td', {class: 'num'}, durationText(exam)),
    el('td', {class: 'labs', title: labsText(exam.labs)}, labsText(exam.labs)),
    el('td', {class: 'audience'}, audienceText(exam)),
    el('td', {class: 'num'}, String(exam.members || 0)),
    el('td', {}, exam.created_by || ''),
    el('td', {class: 'actions'}, ...actions));
  tr.addEventListener('click', (event) => {
    if (!event.target.closest('a, button')) {
      openDetail(exam.id);
    }
  });
  return tr;
}

function showNotice(text, {error = false} = {}) {
  notice.textContent = text;
  notice.hidden = !text;
  notice.classList.toggle('error', error);
}

function showError(e) {
  clear(body);
  body.append(el('tr', {}, el('td', {colspan: columnCount(table), class: 'error'}, e.message)));
  countElement.textContent = '';
  if (e.status === 409 || e.status === 503) {
    showNotice(e.message, {error: true});
  } else {
    toast(e.message, {error: true});
  }
}

async function refresh() {
  let data;
  try {
    data = await api.get('/api/exams');
  } catch (e) {
    showError(e);
    return;
  }
  state.exams = Array.isArray(data.exams) ? data.exams : [];
  state.now = isNumber(data.now) ? data.now : Date.now() / 1000;
  showNotice('');
  render();
}

// -- the catalogs of the form ----------------------------------------------------------------

async function getLabs() {
  if (labsCache === null) {
    try {
      const labs = await api.get('/api/labs?all=1');
      labsCache = Array.isArray(labs) ? labs : [];
    } catch (e) {
      toast(e.message, {error: true});
      return [];
    }
  }
  return labsCache;
}

async function getGroups() {
  if (groupsCache === null) {
    try {
      const data = await api.get('/api/groups');
      groupsCache = Array.isArray(data.groups) ? data.groups : [];
    } catch (e) {
      groupsCache = [];
    }
  }
  return groupsCache;
}

const form = createExamForm({table, getLabs, getGroups});

// -- create, edit, delete ---------------------------------------------------------------------

function newExam() {
  form.open(null, async (spec) => {
    const created = await api.post('/api/exams', spec);
    await refresh();
    if (created && created.id !== undefined) {
      openDetail(created.id);
    }
  });
}

function editExam(exam) {
  form.open(exam, async (spec) => {
    await api.put(examUrl(exam.id), spec);
    await refresh();
    if (String(open.id) === String(exam.id)) {
      await refreshDetail();
    }
  });
}

async function deleteExam(exam) {
  const closeToo = window.confirm(format(_('Delete the exam «{title}»? OK also closes its running projects; Cancel keeps everything.'),
                                         {title: exam.title}));
  if (!closeToo) {
    if (!window.confirm(format(_('Delete the exam «{title}» and leave its projects running?'), {title: exam.title}))) {
      return;
    }
  }
  try {
    const result = await api.del(api.withQuery(examUrl(exam.id), {close: closeToo ? '1' : ''}));
    if (result && isNumber(result.closed) && result.closed) {
      toast(format(_('{n} project(s) closed'), {n: result.closed}));
    }
  } catch (e) {
    if (e.status !== 404) {
      toast(e.message, {error: true});
      return;
    }
  }
  if (String(open.id) === String(exam.id)) {
    closeDetail();
  }
  await refresh();
}

// -- the detail -------------------------------------------------------------------------------

function openDetail(id) {
  if (String(open.id) !== String(id)) {
    open.selected.clear();
  }
  open.id = String(id);
  open.data = null;
  writeUrl();
  detail.hidden = false;
  detailTitle.textContent = _('Loading…');
  detailSummary.textContent = '';
  clear(membersBody);
  render();
  refreshDetail();
  if (!open.timer) {
    open.timer = window.setInterval(refreshDetail, REFRESH_INTERVAL);
  }
  detail.scrollIntoView({block: 'nearest'});
}

function closeDetail() {
  open.id = null;
  open.data = null;
  open.selected.clear();
  if (open.timer) {
    window.clearInterval(open.timer);
    open.timer = null;
  }
  detail.hidden = true;
  writeUrl();
  render();
}

async function refreshDetail() {
  const id = open.id;
  if (!id) {
    return;
  }
  let data;
  try {
    data = await api.get(examUrl(id));
  } catch (e) {
    if (open.id !== id) {
      return;
    }
    if (e.status === 404) {
      toast(_('The exam no longer exists.'), {error: true});
      closeDetail();
      refresh();
      return;
    }
    detailNotice.textContent = e.message;
    detailNotice.hidden = false;
    return;
  }
  if (open.id !== id) {
    return;
  }
  open.data = data;
  detailNotice.hidden = true;
  const known = new Set((data.members || []).map((m) => m.login));
  for (const login of Array.from(open.selected)) {
    if (!known.has(login)) {
      open.selected.delete(login);
    }
  }
  renderDetail();
}

// the line under the title of the detail
function summaryText(exam) {
  const parts = [statusLabel(exam.status)];
  parts.push(format(_('start: {text}'), {text: startText(exam)}));
  if (isNumber(exam.duration)) {
    parts.push(format(_('duration: {text}'), {text: durationText(exam)}));
  }
  if (isNumber(exam.end_before) || isNumber(exam.ended_at)) {
    parts.push(format(_('end: {text}'), {text: endText(exam)}));
  }
  parts.push(format(_('labs: {text}'), {text: labsText(exam.labs)}));
  parts.push(format(_('hidden {lead} min before, started {pre} min before, evaluated every {eval} s'),
                    {lead: exam.lead, pre: exam.pre_start, eval: exam.eval_interval}));
  if ((exam.networks || []).length) {
    parts.push(format(_('networks: {text}'), {text: exam.networks.join(', ')}));
  }
  return parts.join(' · ');
}

function memberSortValue(member, key) {
  switch (key) {
    case 'connected': return member.connected ? 0 : 1;
    case 'phase': return PHASE_ORDER[member.phase] === undefined ? 9 : PHASE_ORDER[member.phase];
    case 'started_at': case 'end_at': return isNumber(member[key]) ? member[key] : Infinity;
    case 'extra_minutes': return member.extra_minutes || 0;
    default: return member[key] || '';
  }
}

function compareMembers(a, b) {
  const va = memberSortValue(a, open.sortKey);
  const vb = memberSortValue(b, open.sortKey);
  let result;
  if (typeof va === 'number' && typeof vb === 'number') {
    result = va - vb;
  } else {
    result = String(va).localeCompare(String(vb));
  }
  if (result === 0) {
    result = String(a.login || '').localeCompare(String(b.login || ''));
  }
  return open.sortAsc ? result : -result;
}

function renderDetail() {
  const exam = open.data;
  if (!exam) {
    return;
  }
  detailTitle.textContent = exam.title || '';
  detailSummary.textContent = summaryText(exam);
  const running = exam.status === 'running';
  buttons.startNow.disabled = isNumber(exam.start_at) && exam.start_at <= state.now;
  buttons.startNow.hidden = exam.status === 'past';
  buttons.endNow.disabled = !running;
  buttons.edit.hidden = buttons.delete.hidden = !(databaseConfigured && available);
  clear(membersBody);
  for (const th of membersTable.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === open.sortKey ? (open.sortAsc ? 'ascending' : 'descending') : 'none');
  }
  const members = (exam.members || []).slice().sort(compareMembers);
  if (!members.length) {
    membersBody.append(el('tr', {}, el('td', {colspan: columnCount(membersTable), class: 'muted'}, _('No member.'))));
  }
  for (const member of members) {
    membersBody.append(renderMember(member));
  }
  renderSelection();
}

function renderMember(member) {
  const box = el('input', {type: 'checkbox', 'aria-label': member.login});
  box.checked = open.selected.has(member.login);
  box.addEventListener('change', () => {
    if (box.checked) {
      open.selected.add(member.login);
    } else {
      open.selected.delete(member.login);
    }
    renderSelection();
  });
  const projects = el('span', {class: 'projects'});
  for (const project of member.projects || []) {
    projects.append(el('a', {href: projectUrl(project.host, project.rln), title: project.rln}, project.lab || project.rln), ' ');
  }
  const extra = member.extra_minutes || 0;
  return el('tr', {dataset: {login: member.login}, class: `phase-${member.phase || ''}`},
    el('td', {class: 'select'}, box),
    el('td', {}, member.login || ''),
    el('td', {}, member.fullname || ''),
    el('td', {hidden: !groupSourcesEnabled}, member.group || ''),
    el('td', {class: 'connected'}, member.connected ? '✓' : ''),
    el('td', {}, member.address || ''),
    el('td', {class: `phase ${member.phase || ''}`}, phaseLabel(member.phase)),
    el('td', {title: dateText(member.started_at)}, timeText(member.started_at)),
    el('td', {title: dateText(member.end_at)}, timeText(member.end_at)),
    el('td', {class: 'num'}, extra ? (extra > 0 ? `+${extra}` : String(extra)) : ''),
    el('td', {class: 'labs', title: labsText(member.labs)}, member.labs && member.labs.length ? labsText(member.labs) : ''),
    el('td', {}, projects));
}

// the header checkbox and the buttons acting on the selection
function renderSelection() {
  const members = open.data ? open.data.members || [] : [];
  const count = open.selected.size;
  selectAll.disabled = !members.length;
  selectAll.checked = members.length > 0 && count === members.length;
  selectAll.indeterminate = count > 0 && count < members.length;
  const none = count === 0;
  const running = open.data && open.data.status === 'running';
  for (const button of [buttons.extendSelected, buttons.reduceSelected, buttons.endSelected, buttons.labsSelected]) {
    button.disabled = none || !running;
    button.title = none ? _('no member selected') : titles.get(button);   // the template's tooltip back
  }
  buttons.extendAll.disabled = buttons.reduceAll.disabled = !running;
}

const titles = new Map(Object.values(buttons).map((button) => [button, button.title]));   // the tooltips of the template

function minutes() {
  const n = Math.round(Number(minutesInput.value));
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function selection() {
  return {logins: [...open.selected].sort()};
}

// one action of the detail: the summary returned replaces the row, the detail is reloaded
async function act(button, call) {
  if (!open.data) {
    return;
  }
  const label = button.textContent;
  button.disabled = true;
  button.textContent = _('in progress…');
  try {
    const result = await call(open.data);
    if (result && result.id !== undefined && result.members !== undefined && Array.isArray(result.members)) {
      open.data = result;       // the detail itself
    } else if (result && result.id !== undefined) {
      state.exams = state.exams.map((e) => (String(e.id) === String(result.id) ? result : e));
    }
    if (result && isNumber(result.closed)) {
      toast(format(_('{n} project(s) closed'), {n: result.closed}));
    }
  } catch (e) {
    if (e.status === 404) {
      toast(_('The exam no longer exists.'), {error: true});
      closeDetail();
    } else {
      toast(e.message, {error: true});
    }
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
  await refresh();
  await refreshDetail();
}

function setupDetailControls() {
  buttons.close.addEventListener('click', closeDetail);
  buttons.startNow.addEventListener('click', () => act(buttons.startNow,     // the browser's clock: a few seconds off at most
    (exam) => api.put(examUrl(exam.id), {start_after: Math.floor(Date.now() / 1000)})));
  buttons.endNow.addEventListener('click', () => {
    if (window.confirm(_('End the exam now for everybody?'))) {
      act(buttons.endNow, (exam) => api.post(examUrl(exam.id, '/end'), {all: true}));
    }
  });
  buttons.extendAll.addEventListener('click', () => act(buttons.extendAll,
    (exam) => api.post(examUrl(exam.id, '/adjust'), {all: true, extra_minutes: minutes()})));
  buttons.reduceAll.addEventListener('click', () => act(buttons.reduceAll,
    (exam) => api.post(examUrl(exam.id, '/adjust'), {all: true, extra_minutes: -minutes()})));
  buttons.extendSelected.addEventListener('click', () => act(buttons.extendSelected,
    (exam) => api.post(examUrl(exam.id, '/adjust'), {...selection(), extra_minutes: minutes()})));
  buttons.reduceSelected.addEventListener('click', () => act(buttons.reduceSelected,
    (exam) => api.post(examUrl(exam.id, '/adjust'), {...selection(), extra_minutes: -minutes()})));
  buttons.endSelected.addEventListener('click', () => {
    if (window.confirm(format(_('End the exam now for {n} member(s)?'), {n: open.selected.size}))) {
      act(buttons.endSelected, (exam) => api.post(examUrl(exam.id, '/end'), selection()));
    }
  });
  buttons.labsSelected.addEventListener('click', async () => {
    if (!open.data) {
      return;
    }
    const labs = await getLabs();
    const first = open.data.members.find((m) => open.selected.has(m.login));
    const current = first && first.labs && first.labs.length ? first.labs : open.data.labs;
    const chosen = await labsDialog(labs, current, {title: format(_('Labs of {n} member(s)'), {n: open.selected.size})});
    if (chosen === null) {
      return;
    }
    act(buttons.labsSelected, (exam) => api.post(examUrl(exam.id, '/labs'), {...selection(), labs: chosen}));
  });
  buttons.closeProjects.addEventListener('click', () => {
    const all = open.selected.size === 0;
    const question = all ? _('Close the exam projects of every member? Their machines will be stopped.')
                         : format(_('Close the exam projects of {n} member(s)? Their machines will be stopped.'), {n: open.selected.size});
    if (window.confirm(question)) {
      act(buttons.closeProjects, (exam) => api.post(examUrl(exam.id, '/close-projects'), all ? {all: true} : selection()));
    }
  });
  buttons.edit.addEventListener('click', () => {
    if (open.data) {
      editExam(open.data);
    }
  });
  buttons.delete.addEventListener('click', () => {
    if (open.data) {
      deleteExam(open.data);
    }
  });
  selectAll.addEventListener('change', () => {
    const members = open.data ? open.data.members || [] : [];
    for (const member of members) {
      if (selectAll.checked) {
        open.selected.add(member.login);
      } else {
        open.selected.delete(member.login);
      }
    }
    renderDetail();
  });
  for (const th of membersTable.querySelectorAll('th.sortable')) {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (open.sortKey === key) {
        open.sortAsc = !open.sortAsc;
      } else {
        open.sortKey = key;
        open.sortAsc = !NUMERIC.includes(key);
      }
      renderDetail();
    });
  }
}

function setupControls() {
  for (const th of table.querySelectorAll('th.sortable')) {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortKey = key;
        state.sortAsc = !['end', 'duration', 'members'].includes(key);   // the counts descending first
      }
      render();
    });
  }
  filterInput.addEventListener('input', () => {
    state.filter = filterInput.value.trim().toLowerCase();
    writeUrl();
    render();
  });
  for (const button of statusButtons) {
    button.addEventListener('click', () => {
      const status = button.dataset.status;
      if (state.statuses.has(status)) {
        state.statuses.delete(status);
      } else {
        state.statuses.add(status);
      }
      writeUrl();
      render();
    });
  }
  newButton.addEventListener('click', newExam);
  setupDetailControls();
}

async function main() {
  await i18n.init();
  readUrl();
  setupControls();
  await refresh();
  if (open.id) {
    openDetail(open.id);
  }
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
