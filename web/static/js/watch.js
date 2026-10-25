// The Watch page of the instructors: every running project of the pool (GET /api/watch every
// 5 s), one row per project with its owner, its lab, when it started, its last archived
// evaluation (age, grade, mark, errors), its terminals and whether the web (or the Qt GUI) runs
// it.  The rows can be sorted by any column and filtered by text; a row without a recent
// evaluation is amber, one whose last evaluation had errors is red.  Open goes to the project
// page (the instructor joins the student's terminals there), Close stops the project.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format, resolveText} from './i18n.js';
import {el, clear, toast, formatTimestamp} from './ui.js';
import {projectUrl} from './creation.js';

const REFRESH_INTERVAL = 5000;
const STALE_AFTER_S = 900;     // without an evaluation younger than this (or 2 × the lab's interval): amber

const table = document.getElementById('watch');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('watch-filter');
const countElement = document.getElementById('watch-count');
const closing = new Set();     // running lab names whose close is in progress

const state = {rows: [], sortKey: 'started_at', sortAsc: false, filter: ''};

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

function num(value, digits = 1) {
  if (value === null || value === undefined) {
    return '';
  }
  const n = Number(value);
  return Number.isInteger(n) ? String(n) : n.toFixed(digits);
}

// the value a column sorts on
function sortValue(row, key) {
  const last = row.last_eval;
  switch (key) {
    case 'host': return row.host || '';
    case 'owner': return row.owner || '';
    case 'title': return title(row).toLowerCase();
    case 'started_at': return row.started_at || '';
    case 'last_eval': return last ? -last.age_s : -Infinity;
    case 'grade': return last && last.max_grade ? last.grade / last.max_grade : -Infinity;
    case 'mark': return last && last.mark !== null && last.mark !== undefined ? last.mark : -Infinity;
    case 'errors': return last ? last.errors * 1000 + last.warnings : -1;
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

function matches(row) {
  if (!state.filter) {
    return true;
  }
  const haystack = [row.host, row.owner, row.fullname, title(row), row.lab_name].join(' ').toLowerCase();
  return state.filter.split(/\s+/).every((word) => haystack.includes(word));
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
  const rows = state.rows.filter(matches).sort(compare);
  countElement.textContent = state.rows.length === rows.length
    ? format(_('{n} project(s)'), {n: rows.length})
    : format(_('{n} of {total} project(s)'), {n: rows.length, total: state.rows.length});
  for (const th of table.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === state.sortKey ? (state.sortAsc ? 'ascending' : 'descending') : 'none');
  }
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: 11, class: 'muted'},
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
  return el('tr', {class: rowClass(row), dataset: {rln}},
    el('td', {}, row.host || ''),
    el('td', {title: row.fullname || ''}, row.owner || ''),
    el('td', {title: rln}, title(row)),
    el('td', {}, formatTimestamp(row.started_at)),
    el('td', {title: last ? last.eval_date : ''}, last ? ageText(last.age_s) : _('never')),
    el('td', {class: 'num'}, last ? `${num(last.grade)} / ${num(last.max_grade)}` : ''),
    el('td', {class: 'num'}, last && last.mark !== null && last.mark !== undefined
      ? `${num(last.mark)} / ${num(last.maximum_mark)}` : ''),
    el('td', {class: 'num'}, errorsText),
    el('td', {class: 'num'}, String(row.terminals || 0)),
    el('td', {}, row.managed ? _('web') : _('local')),
    el('td', {class: 'actions'},
      el('a', {class: 'button primary', href: projectUrl(row.host, rln)}, _('Open')),
      closeButton));
}

async function refresh() {
  let rows;
  try {
    rows = await api.get('/api/watch');
  } catch (e) {
    clear(body);
    body.append(el('tr', {}, el('td', {colspan: 11, class: 'error'}, e.message)));
    return;
  }
  state.rows = Array.isArray(rows) ? rows : [];
  render();
}

function setupControls() {
  for (const th of table.querySelectorAll('th.sortable')) {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortKey = key;
        state.sortAsc = !['last_eval', 'grade', 'mark', 'errors', 'terminals', 'started_at'].includes(key);
      }
      render();
    });
  }
  filterInput.addEventListener('input', () => {
    state.filter = filterInput.value.trim().toLowerCase();
    render();
  });
}

async function main() {
  await i18n.init();
  setupControls();
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
