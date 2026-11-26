// The Watch page of the instructors: every running project of the pool (GET /api/watch every
// 5 s), one row per project with its owner (login and full name, and their student group when
// the site configures one), its lab, when it started, the last action of its owner (the age of
// the last key, click or scroll on its page, terminal input, answer, evaluation or state, as the
// agent keeps it; blank when it saw none), its last archived evaluation (age, grade,
// mark, errors), the number of self-evaluations the student has run (counted live by the agent
// from the project's auto_eval.log: the archives hold the count before their evaluation), its
// terminals and whether the web (or the Qt GUI) runs it.  The rows can be
// sorted by any column, filtered by text and restricted to one group (the select, by kind: the
// departments, the directory groups and the custom groups of GET /api/groups and of the rows,
// groups_model.js; kept in the URL as ?group=kind:name, a bare name being a department, and
// remembered by the browser (localStorage sreweb.watch): the page comes back with the group
// chosen last, through the Watch link of the header or in a new tab, until another one or All
// groups is chosen, a link with ?group= winning and being remembered); a row
// without a recent evaluation is amber, one whose last evaluation had
// errors is red.  Open goes to the project page (the instructor joins the student's terminals
// there), Close stops the project.  A click on a row opens the dialog of its last archived
// evaluation (watch_detail.js), a click on its lab cell the summary of that lab for the rows
// shown (the lab file really run, lab_key.js: the paths and symbolic links leading to one file
// are one lab), a click on its group cell the summary of that lab for the whole group (every project
// of the pool whose owner has that group, whatever the filter; watch_summary.js); all follow
// the polls.  The Clients column counts the clients of the owner on the project: their
// browsers showing its page and their local GUI on its host (blank for an older portal).  The
// Sharing column says whether the owner may share the project with other students and how many
// take part in it (the shared projects: `sharing` of the rows, sharing_model.js); a click on the
// cell opens the dialog of the project (watch_sharing.js: who is in it, Remove, Stop sharing, and
// the decision of the instructors for it).  A checkbox per row and the one of the header (the
// rows shown) fill a selection, which the bar above the table acts on: the sharing of the
// selected projects allowed, forbidden or back to the default of the site (POST
// /api/watch/sharing), and Close projects… (POST /api/watch/close after a confirmation listing
// them: a job of the portal closes them in the background, its rows greyed meanwhile, its
// outcome told by a toast when it ends — GET /api/watch/close).
//
// Two views, chosen by the Projects / Clients buttons of the toolbar (the buttons of the
// History page): the projects, where the page always lands, and the clients (?view=clients,
// never remembered), the users in a local GUI and the browsers connected to the portal
// (watch_clients.js, GET /api/watch/clients).  Only the view shown is polled; the text filter
// and the group select apply to both.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format, resolveText} from './i18n.js';
import {el, clear, toast, formatTimestamp, formatNumber} from './ui.js';
import {projectUrl} from './creation.js';
import {createDetailDialog} from './watch_detail.js';
import {createSummaryDialog} from './watch_summary.js';
import {createClientsView} from './watch_clients.js';
import {labKey} from './lab_key.js';
import {createSharingDialog, confirmClose} from './watch_sharing.js';
import {watchSharingText, watchSharingRank, watchSharingTitle, projectKey, POLICY_DEFAULT} from './sharing_model.js';
import {KINDS, KIND_DEPARTMENT, groupKey, parseKey, normalizeKey, rowGroupKeys, rowMatchesGroup, sortGroups,
        kindsLabel} from './groups_model.js';

const REFRESH_INTERVAL = 5000;
const STALE_AFTER_S = 900;     // without an evaluation younger than this (or 2 × the lab's interval): amber
const STORAGE_KEY = 'sreweb.watch';   // the group chosen last, remembered across the pages: {group: key}
const VIEWS = ['projects', 'clients'];
const DEFAULT_VIEW = 'projects';
const URLS = {projects: '/api/watch', clients: '/api/watch/clients'};

const table = document.getElementById('watch');
const titleElement = document.getElementById('watch-title');
const sections = {projects: document.getElementById('watch-projects'), clients: document.getElementById('watch-clients')};
const viewButtons = Array.from(document.querySelectorAll('.history-views button[data-view]'));
const body = table.querySelector('tbody');
const filterInput = document.getElementById('watch-filter');
const groupSelect = document.getElementById('watch-group');
const groupsEnabled = table.dataset.groups === 'true';   // a department source is configured: the Group column shown
const groupSourcesEnabled = table.dataset.groupSources === 'true';   // any group source: the select shown
const countElement = document.getElementById('watch-count');
const closing = new Set();     // running lab names whose close is in progress
// the selection: the keys (projectKey) of the rows ticked, the bar acting on them
const selected = new Set();
const selectAll = document.getElementById('watch-select-all');
const selectionBar = document.getElementById('watch-selection');
const selectedElement = document.getElementById('watch-selected');
const bulkButtons = selectionBar ? Array.from(selectionBar.querySelectorAll('button[data-action]')) : [];
const sharingEnabled = table.dataset.sharing === 'true';   // the site has the shared projects: the Sharing column shown
let closeJob = false;          // a bulk close of this instructor is running: its outcome is asked at each poll

// group: null = every group, '' = the rows without department, else the key of one group; shown:
// the rows after the filters, in the order of the table; view: the view shown
const state = {rows: [], shown: [], sortKey: 'started_at', sortAsc: false, filter: '', group: null,
               view: DEFAULT_VIEW};
// The template of a portal not restarted since the files were updated has no clients section
// (the scripts are read from the disk at every request, the templates when the portal starts):
// the page is then the projects table alone, as before.
const hasViews = Boolean(titleElement && sections.projects && sections.clients);
const clientsColumn = Boolean(table.querySelector('th[data-sort="clients"]'));
const clients = hasViews
  ? createClientsView(sections.clients, {groupsEnabled})
  : {render: () => ({shown: 0, total: 0}), setData: () => {}, showError: () => {}, rows: () => []};
const loaded = {projects: false, clients: false};   // the views the portal answered for at least once
let listedGroups = '';         // the groups the select offers, joined: rebuilt only when they change
let catalog = [];              // the groups of GET /api/groups (every kind), read once per page load

function columnCount() {
  return table.querySelectorAll('thead th:not([hidden])').length;
}

function projectApi(row) {
  return `/api/projects/${encodeURIComponent(row.host)}/${encodeURIComponent(row.running_lab_name)}`;
}

function title(row) {
  return resolveText(row.title) || row.lab_name || '';
}

function staleAfter(row) {
  return Math.max(STALE_AFTER_S, 2 * (Number(row.eval_interval) || 0));
}

function ageText(seconds) {
  if (seconds < 60) {
    return format(_('{n} s ago'), {n: seconds});
  }
  if (seconds < 3600) {
    return format(_('{n} min ago'), {n: Math.floor(seconds / 60)});
  }
  return format(_('{n} h ago'), {n: Math.floor(seconds / 3600)});
}

// The age in seconds of the last action of the owner on the project (a key, a click or a scroll
// on its page, terminal input, an answer, an evaluation, a state: the agent's `last_action`);
// null when the agent saw none (a project used from the Qt GUI only) or is older than the key.
function actionAge(row) {
  const action = row.last_action;
  return action && typeof action.age_s === 'number' ? action.age_s : null;
}

// the time of that action, in the words of the browser, for the tooltip of the cell
function actionTime(row) {
  const at = row.last_action ? new Date(row.last_action.at) : null;
  return at && !Number.isNaN(at.getTime()) ? at.toLocaleString() : '';
}

const detail = createDetailDialog({projectUrl: (row) => projectUrl(row.host, row.running_lab_name), projectApi, title});
const summary = createSummaryDialog();
const sharingDialog = createSharingDialog({title, onChanged: () => refresh()});

// the value a column sorts on
function sortValue(row, key) {
  const last = row.last_eval;
  switch (key) {
    case 'host': return row.host || '';
    case 'owner': return row.owner || '';
    case 'fullname': return (row.fullname || '').toLowerCase();
    case 'group': return row.group || '';
    case 'title': return title(row).toLowerCase();
    case 'started_at': return row.started_at || '';
    case 'last_action': return actionAge(row) === null ? -Infinity : -actionAge(row);
    case 'last_eval': return last ? -last.age_s : -Infinity;
    case 'grade': return last && last.max_grade ? last.grade / last.max_grade : -Infinity;
    case 'mark': return last && last.mark !== null && last.mark !== undefined ? last.mark : -Infinity;
    case 'errors': return last ? last.errors * 1000 + last.warnings : -1;
    case 'auto_eval_count': return typeof row.auto_eval_count === 'number' ? row.auto_eval_count : -1;
    case 'terminals': return Number(row.terminals) || 0;
    case 'clients': return typeof row.clients === 'number' ? row.clients : -1;
    case 'sharing': return watchSharingRank(row.sharing);
    case 'managed': return row.managed ? 1 : 0;
    default: return '';
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
    result = String(a.running_lab_name).localeCompare(String(b.running_lab_name));
  }
  return state.sortAsc ? result : -result;
}

function matchesGroup(row) {
  return rowMatchesGroup(row, state.group);
}

function matches(row) {
  if (!matchesGroup(row)) {
    return false;
  }
  if (!state.filter) {
    return true;
  }
  const names = [...rowGroupKeys(row)].map((key) => parseKey(key).name);
  const haystack = [row.host, row.owner, row.fullname, row.group, ...names, title(row), row.lab_name].join(' ').toLowerCase();
  return state.filter.split(/\s+/).every((word) => haystack.includes(word));
}

// the group select: its fixed entries (every group, no department) then, by kind, the groups of
// GET /api/groups and those of the rows (so an empty custom group can be chosen), plus the
// selected one while it is gone (the filter does not reset by itself)
function selectGroup() {
  const kind = state.group === null ? 'all' : (state.group === '' ? 'none' : 'group');
  for (const option of groupSelect.options) {
    option.selected = option.dataset.kind === kind && (kind !== 'group' || option.value === state.group);
  }
}

function fillGroups() {
  const entries = new Map();
  for (const group of catalog) {
    entries.set(group.key, group);
  }
  for (const row of [...state.rows, ...clients.rows()]) {
    for (const key of rowGroupKeys(row)) {
      if (!entries.has(key)) {
        entries.set(key, {key, ...parseKey(key)});
      }
    }
  }
  if (state.group && !entries.has(state.group)) {
    entries.set(state.group, {key: state.group, ...parseKey(state.group)});
  }
  const sorted = sortGroups([...entries.values()], {key: 'kind'});
  const joined = sorted.map((group) => group.key).join('\n');
  if (joined === listedGroups) {
    return;
  }
  listedGroups = joined;
  for (const child of [...groupSelect.children]) {
    if (child.tagName === 'OPTGROUP' || child.dataset.kind === 'group') {
      child.remove();
    }
  }
  for (const kind of KINDS) {
    const ofKind = sorted.filter((group) => group.kind === kind);
    if (!ofKind.length) {
      continue;
    }
    const optgroup = el('optgroup', {label: kindsLabel(kind)});
    for (const group of ofKind) {
      optgroup.append(el('option', {value: group.key, dataset: {kind: 'group'}}, group.name));
    }
    groupSelect.append(optgroup);
  }
  selectGroup();
}

// the groups of every kind, for the select (an empty group has no row to be found in)
async function loadCatalog() {
  try {
    const data = await api.get('/api/groups');
    catalog = Array.isArray(data.groups) ? data.groups : [];
  } catch (e) {
    catalog = [];
  }
  listedGroups = null;
  fillGroups();
}

function groupFromUrl() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has('group')) {
    return null;
  }
  const raw = params.get('group');
  return raw === '' ? '' : normalizeKey(raw);     // an old ?group=1A link: the department
}

function storeGroupInUrl() {
  const url = new URL(window.location.href);
  if (state.group === null) {
    url.searchParams.delete('group');
  } else {
    url.searchParams.set('group', state.group);
  }
  window.history.replaceState(null, '', url);
}

// the group the browser remembers: null when none (every group), '' (the rows without
// department) or the key of a group
function storedGroup() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || 'null');
    if (!stored || typeof stored !== 'object' || typeof stored.group !== 'string') {
      return null;
    }
    return stored.group === '' ? '' : normalizeKey(stored.group);
  } catch (e) {
    return null;       // private browsing, blocked storage or garbage
  }
}

function storeGroup() {
  try {
    if (state.group === null) {
      window.localStorage.removeItem(STORAGE_KEY);
    } else {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify({group: state.group}));
    }
  } catch (e) {
    // private browsing: the group lasts for the page only
  }
}

function rowClass(row) {
  const last = row.last_eval;
  if (last && last.errors > 0) {
    return 'row-errors';
  }
  if (!last || last.age_s > staleAfter(row)) {
    return 'row-stale';
  }
  return '';
}

// the view named by the URL (?view=clients), the projects without it or with anything else
function viewFromUrl() {
  const view = new URLSearchParams(window.location.search).get('view');
  return hasViews && VIEWS.includes(view) ? view : DEFAULT_VIEW;
}

function storeViewInUrl() {
  const url = new URL(window.location.href);
  if (state.view === DEFAULT_VIEW) {
    url.searchParams.delete('view');
  } else {
    url.searchParams.set('view', state.view);
  }
  window.history.replaceState(null, '', url);
}

// the buttons, the section and the texts of the view shown
function applyView() {
  if (!hasViews) {
    return;
  }
  for (const button of viewButtons) {
    button.setAttribute('aria-pressed', String(button.dataset.view === state.view));
  }
  for (const [name, section] of Object.entries(sections)) {
    section.hidden = name !== state.view;
  }
  const onClients = state.view === 'clients';
  titleElement.textContent = onClients ? _('Connected clients') : _('All running projects');
  filterInput.title = onClients ? _('Host, user, group, browser or page') : _('Host, owner, group or lab');
}

function renderClients() {
  if (groupSourcesEnabled) {
    fillGroups();
  }
  const {shown, total} = clients.render({filter: state.filter, group: state.group});
  countElement.textContent = shown === total
    ? format(_('{n} client(s)'), {n: shown})
    : format(_('{n} of {total} client(s)'), {n: shown, total});
}

function render() {
  if (state.view === 'clients') {
    renderClients();
    return;
  }
  clear(body);
  if (groupSourcesEnabled) {
    fillGroups();
  }
  const rows = state.rows.filter(matches).sort(compare);
  state.shown = rows;
  countElement.textContent = state.rows.length === rows.length
    ? format(_('{n} project(s)'), {n: rows.length})
    : format(_('{n} of {total} project(s)'), {n: rows.length, total: state.rows.length});
  for (const th of table.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === state.sortKey ? (state.sortAsc ? 'ascending' : 'descending') : 'none');
  }
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'muted'},
                                state.rows.length ? _('No project matches the filter.') : _('No project on the pool.'))));
    renderSelection();
    return;
  }
  for (const row of rows) {
    body.append(renderRow(row));
  }
  renderSelection();
}

// -- the selection and the bar acting on it ---------------------------------------------------------

// the checkbox of a row
function selectBox(row) {
  const key = projectKey(row);
  const box = el('input', {type: 'checkbox', 'aria-label': row.running_lab_name});
  box.checked = selected.has(key);
  box.addEventListener('change', () => {
    if (box.checked) {
      selected.add(key);
    } else {
      selected.delete(key);
    }
    renderSelection();
  });
  return box;
}

// the rows of the selection (those still running)
function selectedRows() {
  return state.rows.filter((row) => selected.has(projectKey(row)));
}

// what an action of the bar applies to: the close to every selected project not being closed,
// a decision about the sharing to those that can be shared at all
function targets(action) {
  const rows = selectedRows();
  if (action === 'close') {
    return rows.filter((row) => !row.closing && !closing.has(row.running_lab_name));
  }
  return rows.filter((row) => row.sharing && (row.sharing.available || row.sharing.shared || action === POLICY_DEFAULT));
}

// the header checkbox (the rows shown: all, some or none of them selected) and the bar: the
// count, and each button enabled when its action applies to a selected project
function renderSelection() {
  if (!selectAll || !selectionBar) {
    return;
  }
  const shown = state.shown;
  const shownSelected = shown.filter((row) => selected.has(projectKey(row))).length;
  const count = selectedRows().length;
  let text = format(_('{n} project(s) selected'), {n: count});
  if (count > shownSelected) {
    text += ' ' + format(_('({n} outside the rows shown)'), {n: count - shownSelected});
  }
  selectedElement.textContent = text;
  selectAll.disabled = !shown.length;
  selectAll.checked = shown.length > 0 && shownSelected === shown.length;
  selectAll.indeterminate = shownSelected > 0 && shownSelected < shown.length;
  for (const button of bulkButtons) {
    const n = targets(button.dataset.action).length;
    button.disabled = !n || (button.dataset.action === 'close' && closeJob);
    button.dataset.count = String(n);
  }
}

function selectionOf(rows) {
  return rows.map((row) => ({host: row.host, rln: row.running_lab_name}));
}

// one action of the bar on the selected projects
async function actMany(action) {
  const rows = targets(action);
  if (!rows.length) {
    return;
  }
  if (action === 'close') {
    if (!await confirmClose(rows, {title})) {
      return;
    }
    try {
      await api.post('/api/watch/close', {projects: selectionOf(rows)});
      closeJob = true;
    } catch (e) {
      toast(e.message, {error: true});
    }
    refresh();
    return;
  }
  try {
    const answer = await api.post('/api/watch/sharing', {projects: selectionOf(rows), policy: action});
    let text = format(_('{n} project(s) changed'), {n: answer.changed || 0});
    if (answer.skipped) {
      text += ' — ' + format(_('{n} on a host that cannot share'), {n: answer.skipped});
    }
    toast(text);
  } catch (e) {
    toast(e.message, {error: true});
  }
  refresh();
}

// the bulk close of this instructor, while it runs: its outcome when it ends
async function followCloseJob() {
  let job;
  try {
    job = (await api.get('/api/watch/close')).job;
  } catch (e) {
    return;
  }
  if (job && job.running) {
    closeJob = true;
    return;
  }
  if (closeJob && job) {
    let text = format(_('{n} project(s) closed'), {n: job.closed || 0});
    if (job.failed) {
      const first = (job.errors || [])[0];
      text += ' — ' + format(_('{n} could not be closed'), {n: job.failed}) + (first ? `: ${first.error}` : '');
    }
    toast(text, {error: Boolean(job.failed)});
  }
  closeJob = false;
}

function renderRow(row) {
  const last = row.last_eval;
  const rln = row.running_lab_name;
  const closeButton = el('button', {type: 'button', class: 'danger'}, _('Close'));
  if (closing.has(rln) || row.closing) {
    closeButton.disabled = true;
    closeButton.textContent = _('closing in progress...');
  }
  closeButton.addEventListener('click', async () => {
    if (!window.confirm(format(_('Close the project of {owner}? Its machines will be stopped.'), {owner: row.owner}))) {
      return;
    }
    closing.add(rln);
    closeButton.disabled = true;
    closeButton.textContent = _('closing in progress...');
    try {
      await api.del(projectApi(row));
    } catch (e) {
      toast(e.message, {error: true});
    } finally {
      closing.delete(rln);
    }
    refresh();
  });
  const errorsText = last ? (last.warnings ? `${last.errors} (${last.warnings} ~)` : String(last.errors)) : '';
  const shares = row.sharing && (row.sharing.available || row.sharing.shared);
  const tr = el('tr', {class: rowClass(row) + (row.closing ? ' row-closing' : ''), dataset: {rln}},
    el('td', {class: 'select'}, selectBox(row)),
    el('td', {}, row.host || ''),
    el('td', {}, row.owner || ''),
    el('td', {}, row.fullname || ''),
    el('td', {hidden: !groupsEnabled, class: row.group ? 'group' : null,
              title: row.group ? _('Summary of the lab for the students of the group') : null,
              onclick: row.group
                ? () => summary.open(labKey(row), title(row), () => state.rows, {group: groupKey(KIND_DEPARTMENT, row.group)})
                : null},
       row.group || ''),
    el('td', {class: 'lab', title: _('Summary of the lab for the projects shown'),
              onclick: () => summary.open(labKey(row), title(row), () => state.shown)}, title(row)),
    el('td', {title: rln}, formatTimestamp(row.started_at)),
    // blank when the agent saw no action of the owner
    el('td', {title: actionTime(row)}, actionAge(row) === null ? '' : ageText(actionAge(row))),
    el('td', {title: last ? last.eval_date : ''}, last ? ageText(last.age_s) : _('never')),
    el('td', {class: 'num'}, last ? `${formatNumber(last.grade)} / ${formatNumber(last.max_grade)}` : ''),
    el('td', {class: 'num'}, last && last.mark !== null && last.mark !== undefined
      ? `${formatNumber(last.mark)} / ${formatNumber(last.maximum_mark)}` : ''),
    el('td', {class: 'num'}, errorsText),
    // blank for the row of an agent older than the count
    el('td', {class: 'num'}, typeof row.auto_eval_count === 'number' ? String(row.auto_eval_count) : ''),
    el('td', {class: 'num'}, String(row.terminals || 0)),
    // blank for the row of a portal older than the count; no cell under a template without the column
    clientsColumn
      ? el('td', {class: 'num', title: row.client_local ? _('The local GUI of the owner is one of them') : null},
           typeof row.clients === 'number' ? String(row.clients) : '')
      : null,
    // blank for a project that cannot be shared, and for the row of a portal older than the key;
    // the cell of the others opens the dialog of the sharing of the project
    el('td', {class: shares ? 'sharing' : null, hidden: !sharingEnabled, title: watchSharingTitle(row.sharing),
              dataset: {policy: row.sharing ? row.sharing.policy : ''},
              onclick: shares ? () => sharingDialog.open(row) : null},
       watchSharingText(row.sharing)),
    el('td', {}, row.managed ? _('web') : _('local')),
    el('td', {class: 'actions'},
      el('a', {class: 'button primary', href: projectUrl(row.host, rln)}, _('Open')),
      closeButton));
  // the row itself: the last evaluation of the project (its buttons, its lab cell and its
  // group cell apart)
  tr.addEventListener('click', (event) => {
    if (!event.target.closest('a, button, input, td.select, td.lab, td.group, td.sharing')) {
      detail.open(row);
    }
  });
  return tr;
}

// asks the portal for the view shown; an answer that comes back after the view changed is dropped
async function refresh() {
  const view = state.view;
  let answer;
  try {
    answer = await api.get(URLS[view]);
  } catch (e) {
    if (view !== state.view) {
      return;
    }
    if (view === 'clients') {
      clients.showError(e.message);
    } else {
      clear(body);
      body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
    }
    return;
  }
  if (view !== state.view) {
    return;
  }
  loaded[view] = true;
  if (view === 'clients') {
    clients.setData(answer);
    render();
    return;
  }
  state.rows = Array.isArray(answer) ? answer : [];
  // a project closed since is out of the selection
  const running = new Set(state.rows.map(projectKey));
  for (const key of [...selected]) {
    if (!running.has(key)) {
      selected.delete(key);
    }
  }
  render();
  detail.update(state.rows);
  summary.update();
  sharingDialog.update(state.rows);
  if (closeJob || state.rows.some((row) => row.closing)) {
    await followCloseJob();
    renderSelection();
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
        state.sortAsc = !['last_action', 'last_eval', 'grade', 'mark', 'errors', 'auto_eval_count', 'terminals',
                          'clients', 'sharing', 'started_at'].includes(key);
      }
      render();
    });
  }
  for (const button of viewButtons) {
    button.addEventListener('click', () => {
      if (button.dataset.view === state.view) {
        return;
      }
      state.view = VIEWS.includes(button.dataset.view) ? button.dataset.view : DEFAULT_VIEW;
      storeViewInUrl();
      applyView();
      if (loaded[state.view]) {
        render();        // what the view held last, at once
      } else {
        countElement.textContent = '';
      }
      refresh();
    });
  }
  filterInput.addEventListener('input', () => {
    state.filter = filterInput.value.trim().toLowerCase();
    render();
  });
  if (selectAll) {
    // the rows shown, all of them in or out of the selection
    selectAll.addEventListener('change', () => {
      for (const row of state.shown) {
        if (selectAll.checked) {
          selected.add(projectKey(row));
        } else {
          selected.delete(projectKey(row));
        }
      }
      render();
    });
  }
  for (const button of bulkButtons) {
    button.addEventListener('click', () => actMany(button.dataset.action));
  }
  if (groupSourcesEnabled) {
    state.group = groupFromUrl();
    if (state.group === null) {
      // no ?group= in the URL (the Watch link of the header): the group chosen last
      state.group = storedGroup();
      if (state.group !== null) {
        storeGroupInUrl();
      }
    } else {
      storeGroup();    // a link with ?group= wins and is the remembered one from now on
    }
    selectGroup();
    groupSelect.addEventListener('change', () => {
      const option = groupSelect.selectedOptions[0];
      const kind = option ? option.dataset.kind : 'all';
      state.group = kind === 'all' ? null : (kind === 'none' ? '' : option.value);
      storeGroupInUrl();
      storeGroup();
      render();
    });
  }
}

async function main() {
  await i18n.init();
  state.view = viewFromUrl();
  applyView();
  setupControls();
  if (groupSourcesEnabled) {
    loadCatalog();
  }
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
