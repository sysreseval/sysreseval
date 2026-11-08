// The History page of the administrators: the connection log read from its database, in three
// views chosen by the buttons of the toolbar (the events and statistics views are kept in the
// URL as view=events / view=statistics; the page opens on the sessions).
//
// Sessions (GET /api/history/sessions, the default): one row per session of a login from one
// address, the sessions still open first (the portal's memory, green), then the closed ones
// from their session_close lines: login, name, student group (the column is hidden unless a
// group source is configured, like the Watch page's), address, start, end (the last request),
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
// Statistics (GET /api/history/statistics): who connected over a period and for how long,
// computed by the portal (history_stats.js draws the tables): the totals, the student groups,
// the users, the labs and the distribution of the students' time.  The period is the From / To
// window (the time of a session inside it alone counts); switching to the view with an empty
// From fills it with now minus 24 hours (the default period), To empty = now.  The login and
// address prefixes apply; the other filters, the row count and the pager are hidden.
//
// The Group select (shown when a source of user groups is configured, like the Watch page's)
// restricts the three views to the members of one group of any kind (groups_model.js: the
// departments, the directory groups and the custom groups of GET /api/groups, by kind): the
// portal resolves the group into the logins of its members and asks the database for their
// rows alone (the open sessions filtered the same way); a group nobody belongs to gives
// nothing, and the notice says so.  The department cell of a session filters on that
// department.
//
// The filters and the view are kept in the URL (a filtered view reloads and can be shared).
// Older / Newer page through the rows with a cursor (the id of the oldest row shown).  A
// click on an event, login, address, host or project cell filters on that value.  Nothing is
// polled: the page shows what was asked, Search asks again.
//
// The two tables are sorted by a click on their headers (table_sort.js, shared with the tables
// of the statistics): the rows shown, the page, not the whole log (Rows widens the page), one
// sort per view kept across the searches and the pages, not in the URL.  The default orders are
// the server's: the events by time, newest first; the sessions by end time, an open session
// being not ended yet, hence first, then the closed ones newest first.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast, formatDuration} from './ui.js';
import {createStatisticsView} from './history_stats.js';
import {sortRows, markSort, setupSort} from './table_sort.js';
import {KINDS, KIND_DEPARTMENT, groupKey, parseKey, normalizeKey, sortGroups, kindsLabel} from './groups_model.js';

const FILTER_KEYS = ['login', 'addr', 'group', 'event', 'host', 'rln', 'lab', 'since', 'until', 'limit'];
const EVENTS_ONLY_KEYS = ['event', 'host', 'rln', 'lab'];
const DEFAULT_LIMIT = '100';
const VIEWS = ['sessions', 'events', 'statistics'];
const DEFAULT_VIEW = 'sessions';
const DEFAULT_PERIOD_S = 86400;         // the statistics without a From: the last 24 hours
const ERROR_EVENTS = new Set(['denied', 'login_failed']);
// the columns of the two tables sorted descending on the first click (the times and numbers);
// the others, texts, ascending
const DESC_FIRST_KEYS = new Set(['ts', 'status', 'duration', 'start', 'end', 'requests']);

const form = document.getElementById('history-filters');
const tables = {events: document.getElementById('history'), sessions: document.getElementById('history-sessions')};
const statsRoot = document.getElementById('history-statistics');
const views = {...tables, statistics: statsRoot};
const viewButtons = Array.from(document.querySelectorAll('.history-views button[data-view]'));
const notice = document.getElementById('history-notice');
const countElement = document.getElementById('history-count');
const newerButton = document.getElementById('history-newer');
const olderButton = document.getElementById('history-older');
const pageElement = document.getElementById('history-page');
const pager = document.querySelector('.history-pager');
const databaseConfigured = tables.events.dataset.database === 'true';
const groupsEnabled = tables.sessions.dataset.groups === 'true';   // a department source is configured: Group column shown
const groupSourcesEnabled = form.dataset.groupSources === 'true';   // any group source: the Group select shown
const groupSelect = document.getElementById('history-group');
const stats = createStatisticsView(statsRoot, {groupsEnabled});
let catalog = [];              // the groups of GET /api/groups (every kind), read once per page load

// view: events, sessions or statistics; rows: the rows of the page (events, or closed
// sessions); open: the open sessions (the first page of the sessions view); loadedView: the
// view whose rows are in rows / open (null while nothing is loaded); before: the cursor of the
// page shown (null = the newest rows); cursors: those of the previous pages, for Newer; stats:
// the JSON of the statistics view; sort: the column and direction of each list table
const state = {view: DEFAULT_VIEW, rows: [], open: [], loadedView: null, more: false, before: null, cursors: [], stats: null,
               sort: {events: {key: 'ts', asc: false}, sessions: {key: 'end', asc: false}}};

function ascFirst(key) {
  return !DESC_FIRST_KEYS.has(key);
}

function numberOr(value, missing) {
  return value === null || value === undefined || value === '' ? missing : Number(value);
}

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
// datetime-local inputs become seconds since the epoch; the sessions and statistics views send
// their own keys only
function readForm() {
  const data = new FormData(form);
  const filters = {};
  for (const key of FILTER_KEYS) {
    if (state.view !== 'events' && EVENTS_ONLY_KEYS.includes(key)) {
      continue;
    }
    if ((state.view === 'statistics' && key === 'limit') || (key === 'group' && !groupSourcesEnabled)) {
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
    if (!field || !params.has(key)) {
      continue;
    }
    let value = params.get(key);
    if (key === 'group') {
      if (!groupSourcesEnabled) {
        continue;
      }
      value = value ? normalizeKey(value) : '';       // an old ?group=1A link: the department
      if (value) {
        ensureGroupOption(value);
      }
    }
    field.value = value;
  }
  const view = params.get('view');
  state.view = VIEWS.includes(view) ? view : DEFAULT_VIEW;
}

// -- the group select -------------------------------------------------------------------------

// the groups of every kind as optgroups by kind after the "All groups" entry: the catalog of
// GET /api/groups (the departments and directory groups of the directory, the custom groups of
// the database) plus *keep*, the key chosen, when the catalog does not list it (a custom group
// deleted since, a department nobody of the directory has any more): the filter still applies
function fillGroupSelect(groups, keep) {
  for (const child of [...groupSelect.children]) {
    if (child.tagName === 'OPTGROUP') {
      child.remove();
    }
  }
  const entries = new Map();
  for (const group of groups) {
    const key = normalizeKey(group.key);
    entries.set(key, {...group, key});
  }
  if (keep && !entries.has(keep)) {
    entries.set(keep, {key: keep, ...parseKey(keep)});
  }
  const sorted = sortGroups([...entries.values()]);
  for (const kind of KINDS) {
    const ofKind = sorted.filter((group) => group.kind === kind);
    if (!ofKind.length) {
      continue;
    }
    const optgroup = el('optgroup', {label: kindsLabel(kind)});
    for (const group of ofKind) {
      optgroup.append(el('option', {value: group.key}, group.name));
    }
    groupSelect.append(optgroup);
  }
}

// an option for *key* when the select has none (the URL, a click on a department cell)
function ensureGroupOption(key) {
  if (![...groupSelect.options].some((option) => option.value === key)) {
    fillGroupSelect(catalog, key);
  }
}

async function loadGroups() {
  try {
    const data = await api.get('/api/groups');
    catalog = Array.isArray(data.groups) ? data.groups : [];
  } catch (e) {
    catalog = [];
    toast(e.message, {error: true});
  }
  fillGroupSelect(catalog, groupSelect.value);
}

// the view chosen: the buttons, the table shown, the filters of the other views hidden, the
// pager hidden in the statistics view
function applyView() {
  for (const button of viewButtons) {
    button.setAttribute('aria-pressed', String(button.dataset.view === state.view));
  }
  for (const [name, element] of Object.entries(views)) {
    element.hidden = name !== state.view;
  }
  form.classList.toggle('sessions', state.view === 'sessions');
  form.classList.toggle('statistics', state.view === 'statistics');
  pager.hidden = state.view === 'statistics';
}

// the statistics view with an empty From: the last 24 hours (To empty = now)
function ensurePeriod() {
  if (state.view === 'statistics' && !form.elements.since.value) {
    form.elements.since.value = localInputValue(Date.now() / 1000 - DEFAULT_PERIOD_S);
  }
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

// the value a column of the events table sorts on: the time, status and duration as numbers (a
// missing one the smallest), the details as the cell shows them, the rest as text
function eventSortValue(row, key) {
  switch (key) {
    case 'ts': return numberOr(row.ts, -Infinity);
    case 'status': return numberOr(row.status, -Infinity);
    case 'duration': return numberOr(row.duration, -Infinity);
    case 'details': return detailsText(row.details);
    default: return row[key] || '';
  }
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

// the department of a session: a click filters on it as a group (when the select is shown)
function groupCell(group) {
  if (!group || !groupSourcesEnabled) {
    return el('td', {hidden: !groupsEnabled}, group || '');
  }
  return el('td', {hidden: !groupsEnabled, class: 'link', title: _('Click to filter on this group'),
                   onclick: () => setGroupFilter(groupKey(KIND_DEPARTMENT, group))}, group);
}

function renderSession(session) {
  const open = isOpen(session);
  const projects = Array.isArray(session.projects) ? session.projects : [];
  return el('tr', {class: open ? 'row-open' : '', dataset: {id: session.id === null ? '' : String(session.id)}},
    filterCell('login', session.login),
    el('td', {title: session.role || ''}, session.name || ''),
    groupCell(session.group),
    filterCell('addr', session.addr),
    timeCell(session.start),
    open ? el('td', {class: 'ts'}, '') : timeCell(session.end),
    el('td', {class: 'num'}, formatDuration(session.duration)),
    el('td', {class: 'num'}, session.requests === null || session.requests === undefined ? '' : String(session.requests)),
    el('td', {title: projects.join('\n')}, projects.map(labOf).join(', ')),
    el('td', {title: open ? timeText(session.end) : ''}, reasonText(session)),
    el('td', {class: 'link', title: _('The events of this session'), onclick: () => showEvents(session)}, _('show')));
}

// the value a column of the sessions table sorts on: the times and counts as numbers (a missing
// one the smallest), the end of an open session being "not yet", the greatest, so that the
// default order (end time, newest first) keeps the open sessions first; the projects and the
// reason as the cells show them, the rest as text
function sessionSortValue(session, key) {
  switch (key) {
    case 'start': return numberOr(session.start, -Infinity);
    case 'end': return isOpen(session) ? Infinity : numberOr(session.end, -Infinity);
    case 'duration': return numberOr(session.duration, -Infinity);
    case 'requests': return numberOr(session.requests, -Infinity);
    case 'projects': return (Array.isArray(session.projects) ? session.projects : []).map(labOf).join(', ');
    case 'reason': return reasonText(session);
    default: return session[key] || '';
  }
}

// -- the page -------------------------------------------------------------------------------

function countText() {
  const n = state.rows.length;
  if (state.view === 'statistics') {
    const totals = state.stats && state.stats.totals ? state.stats.totals : {};
    return format(_('{n} user(s) over the period'), {n: totals.users || 0});
  }
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
  if (state.view === 'statistics') {
    stats.render(state.stats || {});
    countElement.textContent = countText();
    pageElement.textContent = '';
    return;
  }
  const tbody = body();
  clear(tbody);
  const sessions = state.view === 'sessions';
  const sort = state.sort[state.view];
  markSort(table(), sort);
  const rows = sortRows(sessions ? [...state.open, ...state.rows] : state.rows, sort,
                        {value: sessions ? sessionSortValue : eventSortValue});
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

// a group filter whose group has no member known to the portal: the empty table is explained
// (the notice of the database, when there is one, comes first)
function showGroup(data) {
  if (data.group && data.group_members === 0 && notice.hidden) {
    showNotice(_('The group has no member known to the portal.'));
  }
}

function showError(e) {
  state.loadedView = null;
  if (state.view === 'statistics') {
    stats.clear();
  } else {
    const tbody = body();
    clear(tbody);
    tbody.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
  }
  countElement.textContent = '';
  pageElement.textContent = '';
  if (e.status === 409 || e.status === 503) {
    showNotice(e.message, {error: true});
  } else {
    toast(e.message, {error: true});
  }
}

const URLS = {sessions: '/api/history/sessions', events: '/api/history', statistics: '/api/history/statistics'};

async function load() {
  if (!databaseConfigured && state.view !== 'sessions') {
    state.loadedView = null;
    if (state.view === 'statistics') {
      stats.clear();        // the notice of the page says what to configure
    } else {
      clear(body());
    }
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
    data = await api.get(api.withQuery(URLS[state.view], filters));
  } catch (e) {
    showError(e);
    return;
  }
  if (state.view === 'statistics') {
    state.stats = data;
    if (databaseConfigured) {
      showDatabase(data.database);
    }
    if (data.truncated) {
      showNotice(format(_('The statistics are computed on the {n} newest rows only: narrow the period.'),
                        {n: data.limit}), {error: true});
    }
    showGroup(data);
    render();
    return;
  }
  state.rows = Array.isArray(data.rows) ? data.rows : [];
  state.open = state.view === 'sessions' && Array.isArray(data.open) ? data.open : [];
  state.loadedView = state.view;
  state.more = Boolean(data.more);
  if (databaseConfigured) {     // without one the notice of the page stays
    showDatabase(data.database);
  }
  showGroup(data);
  render();
}

function search() {
  state.before = null;
  state.cursors = [];
  ensurePeriod();
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

function setGroupFilter(key) {
  ensureGroupOption(key);
  setFilter('group', key);
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
  // the headers of the two tables sort the rows shown (drawn again only once they are those of
  // the view: a click during a load must not replace the Loading row nor draw the other view's)
  for (const name of ['events', 'sessions']) {
    setupSort(tables[name], state.sort[name], {ascFirst, onChange: () => {
      if (state.loadedView === state.view) {
        render();
      }
    }});
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
  if (groupSourcesEnabled) {
    await loadGroups();       // the options of the Group select, before the URL fills the form
  }
  fillForm();
  applyView();
  setupControls();
  ensurePeriod();           // ?view=statistics without a From: the last 24 hours
  await load();
}

main();
