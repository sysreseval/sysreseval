// The Watch page of the instructors: every running project of the pool (GET /api/watch every
// 5 s), one row per project with its owner (login and full name, and their student group when
// the site configures one), its lab, when it started, its last archived evaluation (age, grade,
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
// the polls.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format, resolveText} from './i18n.js';
import {el, clear, toast, formatTimestamp, formatNumber} from './ui.js';
import {projectUrl} from './creation.js';
import {createDetailDialog} from './watch_detail.js';
import {createSummaryDialog} from './watch_summary.js';
import {labKey} from './lab_key.js';
import {KINDS, KIND_DEPARTMENT, groupKey, parseKey, normalizeKey, rowGroupKeys, rowMatchesGroup, sortGroups,
        kindsLabel} from './groups_model.js';

const REFRESH_INTERVAL = 5000;
const STALE_AFTER_S = 900;     // without an evaluation younger than this (or 2 × the lab's interval): amber
const STORAGE_KEY = 'sreweb.watch';   // the group chosen last, remembered across the pages: {group: key}

const table = document.getElementById('watch');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('watch-filter');
const groupSelect = document.getElementById('watch-group');
const groupsEnabled = table.dataset.groups === 'true';   // a department source is configured: the Group column shown
const groupSourcesEnabled = table.dataset.groupSources === 'true';   // any group source: the select shown
const countElement = document.getElementById('watch-count');
const closing = new Set();     // running lab names whose close is in progress

// group: null = every group, '' = the rows without department, else the key of one group; shown:
// the rows after the filters, in the order of the table
const state = {rows: [], shown: [], sortKey: 'started_at', sortAsc: false, filter: '', group: null};
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

const detail = createDetailDialog({projectUrl: (row) => projectUrl(row.host, row.running_lab_name), projectApi, title});
const summary = createSummaryDialog();

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
    case 'last_eval': return last ? -last.age_s : -Infinity;
    case 'grade': return last && last.max_grade ? last.grade / last.max_grade : -Infinity;
    case 'mark': return last && last.mark !== null && last.mark !== undefined ? last.mark : -Infinity;
    case 'errors': return last ? last.errors * 1000 + last.warnings : -1;
    case 'auto_eval_count': return typeof row.auto_eval_count === 'number' ? row.auto_eval_count : -1;
    case 'terminals': return Number(row.terminals) || 0;
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
  for (const row of state.rows) {
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

function render() {
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
    return;
  }
  for (const row of rows) {
    body.append(renderRow(row));
  }
}

function renderRow(row) {
  const last = row.last_eval;
  const rln = row.running_lab_name;
  const closeButton = el('button', {type: 'button', class: 'danger'}, _('Close'));
  if (closing.has(rln)) {
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
  const tr = el('tr', {class: rowClass(row), dataset: {rln}},
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
    el('td', {title: last ? last.eval_date : ''}, last ? ageText(last.age_s) : _('never')),
    el('td', {class: 'num'}, last ? `${formatNumber(last.grade)} / ${formatNumber(last.max_grade)}` : ''),
    el('td', {class: 'num'}, last && last.mark !== null && last.mark !== undefined
      ? `${formatNumber(last.mark)} / ${formatNumber(last.maximum_mark)}` : ''),
    el('td', {class: 'num'}, errorsText),
    // blank for the row of an agent older than the count
    el('td', {class: 'num'}, typeof row.auto_eval_count === 'number' ? String(row.auto_eval_count) : ''),
    el('td', {class: 'num'}, String(row.terminals || 0)),
    el('td', {}, row.managed ? _('web') : _('local')),
    el('td', {class: 'actions'},
      el('a', {class: 'button primary', href: projectUrl(row.host, rln)}, _('Open')),
      closeButton));
  // the row itself: the last evaluation of the project (its buttons, its lab cell and its
  // group cell apart)
  tr.addEventListener('click', (event) => {
    if (!event.target.closest('a, button, td.lab, td.group')) {
      detail.open(row);
    }
  });
  return tr;
}

async function refresh() {
  let rows;
  try {
    rows = await api.get('/api/watch');
  } catch (e) {
    clear(body);
    body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
    return;
  }
  state.rows = Array.isArray(rows) ? rows : [];
  render();
  detail.update(state.rows);
  summary.update();
}

function setupControls() {
  for (const th of table.querySelectorAll('th.sortable')) {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortKey = key;
        state.sortAsc = !['last_eval', 'grade', 'mark', 'errors', 'auto_eval_count', 'terminals', 'started_at'].includes(key);
      }
      render();
    });
  }
  filterInput.addEventListener('input', () => {
    state.filter = filterInput.value.trim().toLowerCase();
    render();
  });
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
  setupControls();
  if (groupSourcesEnabled) {
    loadCatalog();
  }
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
