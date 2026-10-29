// The History page of the administrators: the connection log read from its database
// (GET /api/history), newest first, one row per event with its time (shown in local time),
// event, login, client address, host, project, lab, status, duration and the other fields of
// the line.  The form filters by login and address (prefixes), event, host (exact), project and
// lab (substrings) and a time window; the filters are kept in the URL (a filtered view reloads
// and can be shared).  Older / Newer page through the rows with a cursor (the id of the oldest
// row shown).  A click on an event, login, address, host or project cell filters on that value.
// Nothing is polled: the page shows what was asked, Search asks again.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';

const FILTER_KEYS = ['login', 'addr', 'event', 'host', 'rln', 'lab', 'since', 'until', 'limit'];
const DEFAULT_LIMIT = '100';
const ERROR_EVENTS = new Set(['denied', 'login_failed']);

const form = document.getElementById('history-filters');
const table = document.getElementById('history');
const body = table.querySelector('tbody');
const notice = document.getElementById('history-notice');
const countElement = document.getElementById('history-count');
const newerButton = document.getElementById('history-newer');
const olderButton = document.getElementById('history-older');
const pageElement = document.getElementById('history-page');
const databaseConfigured = table.dataset.database === 'true';

// before: the cursor of the page shown (null = the newest rows); cursors: those of the
// previous pages, for Newer
const state = {rows: [], more: false, before: null, cursors: []};

function columnCount() {
  return table.querySelectorAll('thead th').length;
}

// the filters of the form as the query parameters of the API: the local times of the
// datetime-local inputs become seconds since the epoch
function readForm() {
  const data = new FormData(form);
  const filters = {};
  for (const key of FILTER_KEYS) {
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

// the form values in the URL (the raw values, so that the inputs are refilled on a reload)
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
    el('td', {class: 'ts', title: row.ts ? new Date(row.ts * 1000).toISOString() : ''}, timeText(row.ts)),
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

function render() {
  clear(body);
  const rows = state.rows;
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'muted'}, _('No event matches the filters.'))));
  } else {
    for (const row of rows) {
      body.append(renderRow(row));
    }
  }
  countElement.textContent = state.more
    ? format(_('{n} event(s) shown, older ones exist'), {n: rows.length})
    : format(_('{n} event(s) shown'), {n: rows.length});
  olderButton.disabled = !state.more || !rows.length;
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
  clear(body);
  body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
  countElement.textContent = '';
  pageElement.textContent = '';
  if (e.status === 409 || e.status === 503) {
    showNotice(e.message, {error: true});
  } else {
    toast(e.message, {error: true});
  }
}

async function load() {
  const filters = readForm();
  if (state.before !== null) {
    filters.before = String(state.before);
  }
  olderButton.disabled = true;
  newerButton.disabled = true;
  let data;
  try {
    data = await api.get(api.withQuery('/api/history', filters));
  } catch (e) {
    showError(e);
    return;
  }
  state.rows = Array.isArray(data.rows) ? data.rows : [];
  state.more = Boolean(data.more);
  showDatabase(data.database);
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
  setupControls();
  if (!databaseConfigured) {
    clear(body);          // the notice of the page says what to configure
    return;
  }
  await load();
}

main();
