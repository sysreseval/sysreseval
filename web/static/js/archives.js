// The Archives page of the instructors: the evaluations of the pool hosts collected into the
// database (every archive sre eval wrote: the self-evaluations, the periodic ones, the final
// one of a closing project), in two views chosen by the buttons of the toolbar (the summary is
// kept in the URL as view=summary; the page opens on the evaluations).
//
// Evaluations (GET /api/archives): newest first, one row per evaluation with its time (local
// time), the student (login, name, group when a group source is configured), the lab, the pool
// host, the start of the project, the grade, the mark, the errors / warnings counts, the number
// of self-evaluations the student had run and the exam flag.  The form filters by student (a
// login prefix or a part of a name), group (exact), lab (a part of the name), host (exact), a
// time window on the evaluation time and the exam flag, and chooses what to show: the last
// evaluation of each project (the default), the last of each student (per lab) or every one.
// A click on a row opens the evaluation (archive_detail.js); a click on a login, group, lab or
// host cell filters on that value.
//
// Summary (GET /api/archives/summary): the lab summary of the Watch page for the evaluations
// found by the same filters (a lab is required; the last evaluation of each student by default):
// one block per lab, the matrix of the students and the elements, then the elements table
// (watch_summary.js); a click on a matrix row opens the evaluation.
//
// The filters and the view are kept in the URL (a filtered view reloads and can be shared;
// ?open=<id> opens the evaluation of that id once the page is loaded: a link to one result).
// Older / Newer page through the rows with a cursor (the id of the oldest row shown).  Nothing
// is polled: the page shows what was asked, Search asks again.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format, resolveText} from './i18n.js';
import {el, clear, toast, formatNumber} from './ui.js';
import {renderSummaryTables} from './watch_summary.js';
import {createArchiveDialog, startOf} from './archive_detail.js';
import {inExoScope} from './evaluation_rows.js';

const FILTER_KEYS = ['student', 'group', 'lab', 'host', 'since', 'until', 'exam', 'show', 'limit'];
const DEFAULT_LIMIT = '100';
const DEFAULT_SHOW = 'project';
const SUMMARY_SHOW = 'student';
const VIEWS = ['evaluations', 'summary'];
const DEFAULT_VIEW = 'evaluations';

const form = document.getElementById('archives-filters');
const table = document.getElementById('archives');
const summaryRoot = document.getElementById('archives-summary');
const viewButtons = Array.from(document.querySelectorAll('.history-views button[data-view]'));
const notice = document.getElementById('archives-notice');
const countElement = document.getElementById('archives-count');
const newerButton = document.getElementById('archives-newer');
const olderButton = document.getElementById('archives-older');
const pageElement = document.getElementById('archives-page');
const pager = document.querySelector('.history-pager');
const databaseConfigured = table.dataset.database === 'true';
const groupsEnabled = table.dataset.groups === 'true';   // a group source is configured: Group column shown
const detail = createArchiveDialog();

// view: evaluations or summary; rows: the rows of the page (or of the summary); before: the
// cursor of the page shown (null = the newest rows); cursors: those of the previous pages, for
// Newer; truncated: the summary holds its newest rows only
const state = {view: DEFAULT_VIEW, rows: [], more: false, before: null, cursors: [], truncated: false};

function body() {
  return table.querySelector('tbody');
}

function columnCount() {
  return table.querySelectorAll('thead th').length;
}

// the filters of the form as the query parameters of the API: the local times of the
// datetime-local inputs become seconds since the epoch; the summary sends no row count
function readForm() {
  const data = new FormData(form);
  const filters = {};
  for (const key of FILTER_KEYS) {
    if (state.view === 'summary' && key === 'limit') {
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
// a reload; the defaults are not written)
function writeUrl() {
  const url = new URL(window.location.href);
  const data = new FormData(form);
  for (const key of FILTER_KEYS) {
    const value = String(data.get(key) || '').trim();
    const isDefault = (key === 'limit' && value === DEFAULT_LIMIT) || (key === 'show' && value === DEFAULT_SHOW);
    if (value && !isDefault) {
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

// the view chosen: the buttons, the table or the summary shown, the row count and the pager
// hidden in the summary view, which starts on the last evaluation of each student
function applyView() {
  for (const button of viewButtons) {
    button.setAttribute('aria-pressed', String(button.dataset.view === state.view));
  }
  const summary = state.view === 'summary';
  table.hidden = summary;
  summaryRoot.hidden = !summary;
  form.classList.toggle('statistics', summary);
  pager.hidden = summary;
  if (summary && form.elements.show.value === DEFAULT_SHOW) {
    form.elements.show.value = SUMMARY_SHOW;
  }
}

function timeText(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : '';
}

function timeCell(ts) {
  return el('td', {class: 'ts', title: ts ? new Date(ts * 1000).toISOString() : ''}, timeText(ts));
}

function filterCell(key, value, extra) {
  const text = value || '';
  if (!text) {
    return el('td', {...(extra || {})}, '');
  }
  return el('td', {class: 'link', title: _('Click to filter on this value'), onclick: () => setFilter(key, text), ...(extra || {})},
            text);
}

function gradeText(row) {
  return `${formatNumber(row.grade)} / ${formatNumber(row.max_grade)}`;
}

function markText(row) {
  if (row.mark === null || row.mark === undefined) {
    return '';
  }
  return row.maximum_mark === null || row.maximum_mark === undefined
    ? formatNumber(row.mark) : `${formatNumber(row.mark)} / ${formatNumber(row.maximum_mark)}`;
}

function errorsText(row) {
  return row.errors || row.warnings ? `${row.errors || 0} / ${row.warnings || 0}` : '';
}

function renderRow(row) {
  const tr = el('tr', {class: row.errors ? 'row-errors' : '', dataset: {id: String(row.id)}},
    timeCell(row.ts),
    filterCell('student', row.login),
    el('td', {}, row.fullname || ''),
    filterCell('group', row.group, {hidden: !groupsEnabled}),
    filterCell('lab', row.lab),
    filterCell('host', row.host),
    el('td', {class: 'ts', title: row.rln || ''}, startOf(row.rln)),
    el('td', {class: 'num'}, gradeText(row)),
    el('td', {class: 'num'}, markText(row)),
    el('td', {class: 'num', title: _('errors / warnings')}, errorsText(row)),
    el('td', {class: 'num'}, row.auto_eval_count === null || row.auto_eval_count === undefined ? '' : String(row.auto_eval_count)),
    el('td', {}, row.exam ? _('Yes') : ''));
  tr.addEventListener('click', (event) => {
    if (event.target.closest('td.link')) {
      return;
    }
    detail.open(row);
  });
  return tr;
}

// -- the summary view -------------------------------------------------------------------------

// a row of the summary as an entry of watch_summary.js: the stored elements with their labels
// resolved in the language of the page (the lab's language after it)
function entryOf(row) {
  const details = row.details || {};
  const language = details.language || 'en';
  const elements = (details.elements || []).filter(inExoScope).map((e) => ({
    key: e.key, label: resolveText(e.description, language) || resolveText(e.title, language),
    part: e.part || null, bonus: Boolean(e.bonus), grade: e.grade, max_grade: e.max_grade, grade_letter: e.grade_letter,
  }));
  const parts = (details.parts || []).map((p) => ({title: p.title, label: resolveText(p.description, language) || p.title}));
  return {id: row.id, owner: row.login, fullname: row.fullname, group: row.group, host: row.host,
          running_lab_name: row.rln, elements, parts, row,
          last_eval: {grade: row.grade, max_grade: row.max_grade, mark: row.mark, maximum_mark: row.maximum_mark,
                      archive: row.archive}};
}

function renderSummary() {
  clear(summaryRoot);
  if (!state.rows.length) {
    summaryRoot.append(el('p', {class: 'muted'}, _('No evaluation matches the filters.')));
    return;
  }
  const byLab = new Map();
  for (const row of state.rows) {
    const lab = row.lab || '';
    if (!byLab.has(lab)) {
      byLab.set(lab, []);
    }
    byLab.get(lab).push(entryOf(row));
  }
  for (const [lab, entries] of byLab) {
    summaryRoot.append(el('h2', {}, lab), el('p', {class: 'muted'}, format(_('{n} evaluation(s)'), {n: entries.length})));
    const tables = el('div', {class: 'watch-summary-tables'});
    renderSummaryTables(tables, entries, {onRow: (entry) => detail.open(entry.row)});
    summaryRoot.append(tables);
  }
}

// -- the page -------------------------------------------------------------------------------

function countText() {
  const n = state.rows.length;
  if (state.view === 'summary') {
    return format(_('{n} evaluation(s) in the summary'), {n});
  }
  return state.more ? format(_('{n} evaluation(s) shown, older ones exist'), {n}) : format(_('{n} evaluation(s) shown'), {n});
}

function render() {
  if (state.view === 'summary') {
    renderSummary();
    countElement.textContent = countText();
    pageElement.textContent = '';
    return;
  }
  const tbody = body();
  clear(tbody);
  if (!state.rows.length) {
    tbody.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'muted'}, _('No evaluation matches the filters.'))));
  } else {
    for (const row of state.rows) {
      tbody.append(renderRow(row));
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

// the writer's state: while the server refuses the rows, the last evaluations are not there yet
function showDatabase(status) {
  if (status && status.last_error) {
    showNotice(format(_('The last evaluations may be missing: the database does not answer ({error}).'),
                      {error: status.last_error}), {error: true});
  } else {
    showNotice('');
  }
}

function showError(e) {
  if (state.view === 'summary') {
    clear(summaryRoot);
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

const URLS = {evaluations: '/api/archives', summary: '/api/archives/summary'};

async function load() {
  if (!databaseConfigured) {
    clear(body());          // the notice of the page says what to configure
    clear(summaryRoot);
    countElement.textContent = '';
    pageElement.textContent = '';
    olderButton.disabled = true;
    newerButton.disabled = true;
    return;
  }
  const filters = readForm();
  if (state.view === 'summary' && !filters.lab) {
    clear(summaryRoot);
    summaryRoot.append(el('p', {class: 'muted'}, _('Give a lab to see its summary.')));
    countElement.textContent = '';
    return;
  }
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
  state.rows = Array.isArray(data.rows) ? data.rows : [];
  state.more = Boolean(data.more);
  state.truncated = Boolean(data.truncated);
  showDatabase(data.database);
  if (state.truncated) {
    showNotice(format(_('The summary shows the {n} newest evaluations only: narrow the filters.'), {n: data.limit}),
               {error: true});
  }
  render();
}

// the labs and groups the table knows, as suggestions of the filters
async function loadOptions() {
  if (!databaseConfigured) {
    return;
  }
  let options;
  try {
    options = await api.get('/api/archives/options');
  } catch (e) {
    return;         // the suggestions only
  }
  const fill = (id, values) => {
    const list = document.getElementById(id);
    clear(list);
    for (const value of Array.isArray(values) ? values : []) {
      list.append(el('option', {value}));
    }
  };
  fill('archives-labs', options.labs);
  fill('archives-groups', options.groups);
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
  document.getElementById('archives-reset').addEventListener('click', () => {
    form.reset();
    applyView();
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

// ?open=<id>: the evaluation of that id, with the fields of its row when the page shows it
function openFromUrl() {
  const id = new URLSearchParams(window.location.search).get('open');
  if (!id || !/^\d+$/.test(id) || !databaseConfigured) {
    return;
  }
  const row = state.rows.find((r) => String(r.id) === id);
  detail.open(row || {id: Number(id)});
}

async function main() {
  await i18n.init();
  fillForm();
  applyView();
  setupControls();
  loadOptions();
  await load();
  openFromUrl();
}

main();
