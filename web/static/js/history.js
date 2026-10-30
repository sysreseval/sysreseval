// The History page of the administrators: the connection log read from its database, in two
// views chosen by the buttons of the toolbar (the events view is kept in the URL as
// view=events; the page opens on the sessions).
//
// Sessions (GET /api/history/sessions, the default): one row per session of a login from one
// address, the sessions still open first (the portal's memory, green), then the closed ones
// from their session_close lines: login, name, address, start, end (the last request),
// duration, number of requests, the labs of the projects used, why it closed (logout, idle
// timeout, shutdown) and a link to the events of that session (the events view filtered on its
// login, address and time window).  Only the login, address and time filters apply (the time
// window bounds the time a session was closed); the open sessions are listed even without a
// database.
//
// Events (GET /api/history): newest first, one row per event with its time (shown in local
// time), event, login, client address, host, project, lab, status, duration and the other
// fields of the line.  The form filters by login and address (prefixes), event, host (exact),
// project and lab (substrings) and a time window.
//
// The filters and the view are kept in the URL (a filtered view reloads and can be shared).
// Older / Newer page through the rows with a cursor (the id of the oldest row shown).  A
// click on an event, login, address, host or project cell filters on that value.  Nothing is
// polled: the page shows what was asked, Search asks again.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';

const FILTER_KEYS = ['login', 'addr', 'event', 'host', 'rln', 'lab', 'since', 'until', 'limit'];
const EVENTS_ONLY_KEYS = ['event', 'host', 'rln', 'lab'];
const DEFAULT_LIMIT = '100';
const VIEWS = ['sessions', 'events'];
const DEFAULT_VIEW = 'sessions';
const ERROR_EVENTS = new Set(['denied', 'login_failed']);

const form = document.getElementById('history-filters');
const tables = {events: document.getElementById('history'), sessions: document.getElementById('history-sessions')};
const viewButtons = Array.from(document.querySelectorAll('.history-views button[data-view]'));
const notice = document.getElementById('history-notice');
const countElement = document.getElementById('history-count');
const newerButton = document.getElementById('history-newer');
const olderButton = document.getElementById('history-older');
const pageElement = document.getElementById('history-page');
const databaseConfigured = tables.events.dataset.database === 'true';

// view: events or sessions; rows: the rows of the page (events, or closed sessions); open: the
// open sessions (the first page of the sessions view); before: the cursor of the page shown
// (null = the newest rows); cursors: those of the previous pages, for Newer
const state = {view: DEFAULT_VIEW, rows: [], open: [], more: false, before: null, cursors: []};

function table() {
  return tables[state.view];
}

function body() {
  return table().querySelector('tbody');
}

function columnCount() {
  return table().querySelectorAll('thead th').length;
}

// the filters of the form as the query parameters of the API: the local times of the
// datetime-local inputs become seconds since the epoch; the sessions view sends its own keys only
function readForm() {
  const data = new FormData(form);
  const filters = {};
  for (const key of FILTER_KEYS) {
    if (state.view === 'sessions' && EVENTS_ONLY_KEYS.includes(key)) {
      continue;
    }
    const value = String(data.get(key) || '').trim();
    if (!value) {
      continue;
    }
    if (key === 'since' || key === 'until') {
      const ms = Date.parse(value);
      if (!Number.isNaN(ms)) {
        filters[key] = String(Math.floor(ms / 1000));
      }
    } else {
      filters[key] = value;
    }
  }
  return filters;
}

// the form values and the view in the URL (the raw values, so that the inputs are refilled on
// a reload; the default view is not written)
function writeUrl() {
  const url = new URL(window.location.href);
  const data = new FormData(form);
  for (const key of FILTER_KEYS) {
    const value = String(data.get(key) || '').trim();
    if (value && !(key === 'limit' && value === DEFAULT_LIMIT)) {
      url.searchParams.set(key, value);
    } else {
      url.searchParams.delete(key);
    }
  }
  if (state.view !== DEFAULT_VIEW) {
    url.searchParams.set('view', state.view);
  } else {
    url.searchParams.delete('view');
  }
  window.history.replaceState(null, '', url);
}

function fillForm() {
  const params = new URLSearchParams(window.location.search);
  for (const key of FILTER_KEYS) {
    const field = form.elements[key];
    if (field && params.has(key)) {
      field.value = params.get(key);
    }
  }
  const view = params.get('view');
  state.view = VIEWS.includes(view) ? view : DEFAULT_VIEW;
}

// the view chosen: the buttons, the table shown, the filters of the events view hidden
function applyView() {
  for (const button of viewButtons) {
    button.setAttribute('aria-pressed', String(button.dataset.view === state.view));
  }
  for (const [name, element] of Object.entries(tables)) {
    element.hidden = name !== state.view;
  }
  form.classList.toggle('sessions', state.view === 'sessions');
}

function valueText(value) {
  if (value === null || value === undefined || value === '') {
    return '-';
  }
  if (value === true) {
    return '1';
  }
  if (value === false) {
    return '0';
  }
  if (Array.isArray(value)) {
    return value.map(valueText).join(',');
  }
  if (typeof value === 'number') {
    return Number.isInteger(value) ? String(value) : value.toFixed(1);
  }
  return String(value);
}

// the other fields of the line, as the file shows them
function detailsText(details) {
  return Object.entries(details || {}).map(([key, value]) => `${key}=${valueText(value)}`).join(' ');
}

function rowClass(row) {
  const status = Number(row.status);
  const result = row.details ? row.details.result : '';
  return ERROR_EVENTS.has(row.event) || status >= 400 || result === 'error' ? 'row-errors' : '';
}

function timeText(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : '';
}

function timeCell(ts) {
  return el('td', {class: 'ts', title: ts ? new Date(ts * 1000).toISOString() : ''}, timeText(ts));
}

function durationText(duration) {
  if (duration === null || duration === undefined) {
    return '';
  }
  return (duration >= 10 ? String(Math.round(duration)) : duration.toFixed(1)) + ' s';
}

// the duration of a session: 42 s, 12 min 05 s, 1 h 02 min
function sessionDuration(seconds) {
  if (seconds === null || seconds === undefined) {
    return '';
  }
  const total = Math.max(0, Math.round(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const rest = total % 60;
  const pad = (n) => String(n).padStart(2, '0');
  if (hours) {
    return `${hours} h ${pad(minutes)} min`;
  }
  if (minutes) {
    return `${minutes} min ${pad(rest)} s`;
  }
  return `${rest} s`;
}

function filterCell(key, value) {
  const text = value || '';
  if (!text) {
    return el('td', {}, '');
  }
  return el('td', {class: 'link', title: _('Click to filter on this value'), onclick: () => setFilter(key, text)}, text);
}

function renderRow(row) {
  return el('tr', {class: rowClass(row), dataset: {id: String(row.id)}},
    timeCell(row.ts),
    filterCell('event', row.event),
    filterCell('login', row.login),
    filterCell('addr', row.addr),
    filterCell('host', row.host),
    filterCell('rln', row.rln),
    el('td', {}, row.lab || ''),
    el('td', {class: 'num'}, row.status || ''),
    el('td', {class: 'num'}, durationText(row.duration)),
    el('td', {class: 'details'}, detailsText(row.details)));
}

// -- the sessions view ------------------------------------------------------------------------

function isOpen(session) {
  return session.closed === null || session.closed === undefined;
}

// the lab of a running lab name (timestamp@@@lab@@@login)
function labOf(rln) {
  const parts = String(rln).split('@@@');
  return parts.length >= 2 ? parts[1] : String(rln);
}

function reasonText(session) {
  if (isOpen(session)) {
    return session.sockets > 0 ? format(_('Still open ({n} connection(s))'), {n: session.sockets}) : _('Still open');
  }
  const reasons = {logout: _('Logout'), idle: _('Idle'), shutdown: _('Shutdown')};
  return reasons[session.reason] || session.reason || '';
}

// the value of a datetime-local input for a time (local, to the minute)
function localInputValue(ts) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// the events view on the events of one session: its login and address, from the minute of its
// start to the minute after its closing line (an open session: until now)
function showEvents(session) {
  form.elements.login.value = session.login || '';
  form.elements.addr.value = session.addr || '';
  for (const key of EVENTS_ONLY_KEYS) {
    form.elements[key].value = '';
  }
  const start = session.start || Date.now() / 1000;
  const closed = isOpen(session) ? Date.now() / 1000 : session.closed;
  form.elements.since.value = localInputValue(Math.floor(start / 60) * 60);
  form.elements.until.value = localInputValue(Math.ceil((closed + 1) / 60) * 60);
  state.view = 'events';
  applyView();
  search();
}

function renderSession(session) {
  const open = isOpen(session);
  const projects = Array.isArray(session.projects) ? session.projects : [];
  return el('tr', {class: open ? 'row-open' : '', dataset: {id: session.id === null ? '' : String(session.id)}},
    filterCell('login', session.login),
    el('td', {title: session.role || ''}, session.name || ''),
    filterCell('addr', session.addr),
    timeCell(session.start),
    open ? el('td', {class: 'ts'}, '') : timeCell(session.end),
    el('td', {class: 'num'}, sessionDuration(session.duration)),
    el('td', {class: 'num'}, session.requests === null || session.requests === undefined ? '' : String(session.requests)),
    el('td', {title: projects.join('\n')}, projects.map(labOf).join(', ')),
    el('td', {title: open ? timeText(session.end) : ''}, reasonText(session)),
    el('td', {class: 'link', title: _('The events of this session'), onclick: () => showEvents(session)}, _('show')));
}

// -- the page -------------------------------------------------------------------------------

function countText() {
  const n = state.rows.length;
  if (state.view === 'sessions') {
    const parts = [state.more ? format(_('{n} session(s) shown, older ones exist'), {n})
                              : format(_('{n} session(s) shown'), {n})];
    if (state.open.length) {
      parts.push(format(_('{n} open'), {n: state.open.length}));
    }
    return parts.join(', ');
  }
  return state.more ? format(_('{n} event(s) shown, older ones exist'), {n}) : format(_('{n} event(s) shown'), {n});
}

function render() {
  const tbody = body();
  clear(tbody);
  const sessions = state.view === 'sessions';
  const rows = sessions ? [...state.open, ...state.rows] : state.rows;
  if (!rows.length) {
    const text = sessions ? _('No session matches the filters.') : _('No event matches the filters.');
    tbody.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'muted'}, text)));
  } else {
    for (const row of rows) {
      tbody.append(sessions ? renderSession(row) : renderRow(row));
    }
  }
  countElement.textContent = countText();
  olderButton.disabled = !state.more || !state.rows.length;
  newerButton.disabled = state.cursors.length === 0;
  pageElement.textContent = state.cursors.length ? format(_('page {n}'), {n: state.cursors.length + 1}) : '';
}

function showNotice(text, {error = false} = {}) {
  notice.textContent = text;
  notice.hidden = !text;
  notice.classList.toggle('error', error);
}

// the writer's state: while the server refuses the rows, the last events are not there yet
function showDatabase(status) {
  if (status && status.last_error) {
    showNotice(format(_('The last events may be missing: the database does not answer ({error}).'),
                      {error: status.last_error}), {error: true});
  } else {
    showNotice('');
  }
}

function showError(e) {
  const tbody = body();
  clear(tbody);
  tbody.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
  countElement.textContent = '';
  pageElement.textContent = '';
  if (e.status === 409 || e.status === 503) {
    showNotice(e.message, {error: true});
  } else {
    toast(e.message, {error: true});
  }
}

async function load() {
  if (!databaseConfigured && state.view === 'events') {
    clear(body());          // the notice of the page says what to configure
    countElement.textContent = '';
    pageElement.textContent = '';
    olderButton.disabled = true;
    newerButton.disabled = true;
    return;
  }
  const filters = readForm();
  if (state.before !== null) {
    filters.before = String(state.before);
  }
  olderButton.disabled = true;
  newerButton.disabled = true;
  let data;
  try {
    data = await api.get(api.withQuery(state.view === 'sessions' ? '/api/history/sessions' : '/api/history', filters));
  } catch (e) {
    showError(e);
    return;
  }
  state.rows = Array.isArray(data.rows) ? data.rows : [];
  state.open = state.view === 'sessions' && Array.isArray(data.open) ? data.open : [];
  state.more = Boolean(data.more);
  if (databaseConfigured) {     // without one the notice of the page stays
    showDatabase(data.database);
  }
  render();
}

function search() {
  state.before = null;
  state.cursors = [];
  writeUrl();
  load();
}

function setFilter(key, value) {
  const field = form.elements[key];
  if (!field) {
    return;
  }
  field.value = value;
  search();
}

function setupControls() {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    search();
  });
  document.getElementById('history-reset').addEventListener('click', () => {
    form.reset();
    search();
  });
  for (const button of viewButtons) {
    button.addEventListener('click', () => {
      if (button.dataset.view === state.view) {
        return;
      }
      state.view = VIEWS.includes(button.dataset.view) ? button.dataset.view : DEFAULT_VIEW;
      applyView();
      search();
    });
  }
  olderButton.addEventListener('click', () => {
    if (!state.rows.length) {
      return;
    }
    state.cursors.push(state.before);
    state.before = state.rows[state.rows.length - 1].id;
    load();
  });
  newerButton.addEventListener('click', () => {
    if (!state.cursors.length) {
      return;
    }
    state.before = state.cursors.pop();
    load();
  });
}

async function main() {
  await i18n.init();
  fillForm();
  applyView();
  setupControls();
  await load();
}

main();
