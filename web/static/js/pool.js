// The Pool page of the instructors: every host of the pool (GET /api/pool and /api/pool/status
// every 5 s), one row per host with its state as `sre-web-tool list` shows it (the seconds and
// the failed attempts of a wake), its projects, terminals, load, who occupies it, its uptime,
// its flags (reserved for instructors, power, drain, power off sent), the agent's version and
// its last error, and the summary of `sre-web-tool status` above the table.  The rows can be
// sorted by any column and filtered by text.  The buttons are the commands of the tool (Enable /
// Disable, Wake, Drain, Power off, Restart: POST /api/pool/hosts/{name}/{action}; add and remove
// stay with the tool), each disabled with the reason as its tooltip when it does not apply; the
// answer of an action is the updated row, shown at once.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';

const REFRESH_INTERVAL = 5000;
const ERROR_WIDTH = 60;        // the Last error cell (the whole text in its tooltip), as the tool
const STATE_ORDER = ['up', 'occupied', 'exam', 'draining', 'waking', 'off', 'disabled'];   // the sort of the State column
const NUMERIC = ['projects', 'terminals', 'load1', 'uptime'];   // sorted descending first

const table = document.getElementById('pool');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('pool-filter');
const countElement = document.getElementById('pool-count');
const statusElement = document.getElementById('pool-status');
const pending = new Map();     // host name -> the action in progress: its buttons stay disabled across re-renders

const state = {rows: [], status: {}, sortKey: 'name', sortAsc: true, filter: ''};

function columnCount() {
  return table.querySelectorAll('thead th').length;
}

function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

// the translated state (the map is built here: the catalog is loaded by main, nothing at module level)
function stateLabel(raw) {
  const labels = {up: _('up'), off: _('off'), waking: _('waking'), occupied: _('occupied'), exam: _('exam'),
                  draining: _('draining'), disabled: _('disabled')};
  return labels[raw] || raw || '';
}

// the State cell, as the tool: "waking (30 s, 2 failed)"
function stateText(row) {
  const extra = [];
  if (isNumber(row.waking_for)) {
    extra.push(format(_('{n} s'), {n: row.waking_for}));
  }
  if (row.wake_failures) {
    extra.push(format(_('{n} failed'), {n: row.wake_failures}));
  }
  return stateLabel(row.state) + (extra.length ? ` (${extra.join(', ')})` : '');
}

function flagsText(row) {
  const flags = [];
  if (row.instructors_only) {
    flags.push(_('instructors'));
  }
  if (row.power) {
    flags.push(_('power'));
  }
  if (row.drain) {
    flags.push(_('drain'));
  }
  if (row.power_off_sent) {
    flags.push(_('power off sent'));
  }
  if (row.restart_sent) {
    flags.push(_('restart sent'));
  }
  return flags.join(', ');
}

function uptimeText(seconds) {   // 1h02, as the tool
  if (!isNumber(seconds)) {
    return '';
  }
  const minutes = Math.floor(seconds / 60);
  return `${Math.floor(minutes / 60)}h${String(minutes % 60).padStart(2, '0')}`;
}

function errorText(row) {
  const text = row.reachable ? '' : (row.error || '');
  return text.length <= ERROR_WIDTH ? text : text.slice(0, ERROR_WIDTH - 1) + '…';
}

// the value a column sorts on
function sortValue(row, key) {
  switch (key) {
    case 'state': {
      const index = STATE_ORDER.indexOf(row.state);
      return index < 0 ? STATE_ORDER.length : index;
    }
    case 'projects': return row.reachable ? Number(row.projects) || 0 : -1;
    case 'terminals': return row.reachable ? Number(row.terminals) || 0 : -1;
    case 'load1': return isNumber(row.load1) ? row.load1 : -1;
    case 'uptime': return isNumber(row.uptime) ? row.uptime : -1;
    case 'occupied_by': return (row.occupied_by || []).join(',');
    default: return row[key] || '';
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
    result = (a.name || '').localeCompare(b.name || '');
  }
  return state.sortAsc ? result : -result;
}

// every word of the filter in the name, host name, state, occupants or error of the row
function matches(row) {
  if (!state.filter) {
    return true;
  }
  const haystack = [row.name, row.hostname, row.state, stateLabel(row.state), (row.occupied_by || []).join(' '),
                    row.reachable ? '' : row.error].join(' ').toLowerCase();
  return state.filter.split(/\s+/).every((word) => haystack.includes(word));
}

// one action on a host: the row's buttons disabled meanwhile, the answer (the updated row) shown
// at once, then a refresh (the status line changes too)
async function act(row, action) {
  pending.set(row.name, action);
  render();
  try {
    const updated = await api.post(`/api/pool/hosts/${encodeURIComponent(row.name)}/${action}`);
    if (updated && updated.name) {
      state.rows = state.rows.map((r) => (r.name === updated.name ? updated : r));
    }
  } catch (e) {
    toast(e.message, {error: true});
  } finally {
    pending.delete(row.name);
  }
  render();
  await refresh();
}

// a button of the Actions cell: options.reason (a text) disables it with the reason as its tooltip,
// options.confirm is asked before the action, options.danger draws it red
function actionButton(row, action, label, options = {}) {
  const button = el('button', {type: 'button', class: options.danger ? 'danger' : undefined,
                               title: options.reason || undefined}, label);
  if (options.reason) {
    button.disabled = true;
  }
  if (pending.has(row.name)) {
    button.disabled = true;
    if (pending.get(row.name) === action) {
      button.textContent = _('in progress…');
    }
  }
  button.addEventListener('click', () => {
    if (options.confirm && !window.confirm(options.confirm)) {
      return;
    }
    act(row, action);
  });
  return button;
}

// the buttons of a row, always there (a stable layout), each with the reason it is disabled
function actions(row) {
  const unreachable = row.reachable ? '' : _('the host is not reachable');
  let wake = '';
  if (!row.can_wake) {
    wake = _('no MAC address nor wake command');
  } else if (row.reachable) {
    wake = _('the host is up');
  }
  let drain = unreachable;
  if (!drain && !row.enabled) {
    drain = _('the host is disabled');
  } else if (!drain && row.drain) {
    drain = _('already draining');
  }
  let poweroff = unreachable;
  if (!poweroff && !row.power_off_allowed) {
    poweroff = _('the agent does not allow it (allow_power_off)');
  } else if (!poweroff && row.power_off_sent) {
    poweroff = _('power off sent');
  }
  const question = format(_('Power off {name}? The agent refuses while a project runs or someone is logged in there.'),
                          {name: row.name});
  let restart = unreachable;
  if (!restart && !row.restart_allowed) {
    restart = _('the agent cannot restart itself (restart_command)');
  } else if (!restart && row.restart_sent) {
    restart = _('restart sent');
  }
  const restartQuestion = format(_('Restart the agent of {name}? The projects stay, the open terminals and desktops are lost.'),
                                 {name: row.name});
  return [
    row.enabled ? actionButton(row, 'disable', _('Disable'), {danger: true}) : actionButton(row, 'enable', _('Enable')),
    actionButton(row, 'wake', _('Wake'), {reason: wake}),
    actionButton(row, 'drain', _('Drain'), {reason: drain}),
    actionButton(row, 'poweroff', _('Power off'), {danger: true, reason: poweroff, confirm: question}),
    actionButton(row, 'restart', _('Restart'), {reason: restart, confirm: restartQuestion}),
  ];
}

// the line of `sre-web-tool status`
function renderStatus() {
  const s = state.status;
  if (!s || !('awake' in s)) {
    statusElement.textContent = '';
    return;
  }
  const waking = Array.isArray(s.waking) && s.waking.length ? s.waking.join(', ') : _('none');
  const pieces = [
    format(_('{awake} host(s) awake (floor {floor})'), {awake: s.awake, floor: s.min_hosts_up}),
    format(_('spare capacity: {spare} slot(s) (wanted: {wanted})'), {spare: s.spare_projects, wanted: s.wanted_spare}),
    format(_('waking: {names}'), {names: waking}),
  ];
  if (s.active_now === false) {
    pieces.push(_('outside the active hours'));
  }
  statusElement.textContent = pieces.join(' — ');
}

function render() {
  clear(body);
  renderStatus();
  const rows = state.rows.filter(matches).sort(compare);
  countElement.textContent = state.rows.length === rows.length
    ? format(_('{n} host(s)'), {n: rows.length})
    : format(_('{n} of {total} host(s)'), {n: rows.length, total: state.rows.length});
  for (const th of table.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === state.sortKey ? (state.sortAsc ? 'ascending' : 'descending') : 'none');
  }
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'muted'},
                                state.rows.length ? _('No host matches the filter.') : _('No host in the pool.'))));
    return;
  }
  for (const row of rows) {
    body.append(renderRow(row));
  }
}

function renderRow(row) {
  const nameTitle = [row.hostname, row.url].filter(Boolean).join(' — ');
  const idle = isNumber(row.idle_for) ? format(_('idle for {n} min'), {n: Math.floor(row.idle_for / 60)}) : '';
  return el('tr', {dataset: {host: row.name}},
    el('td', {title: nameTitle}, row.name || ''),
    el('td', {class: `state ${row.state || ''}`, title: idle}, stateText(row)),
    el('td', {class: 'num'}, row.reachable ? `${row.projects} / ${row.max_projects}` : ''),
    el('td', {class: 'num'}, row.reachable ? String(row.terminals) : ''),
    el('td', {class: 'num'}, isNumber(row.load1) ? row.load1.toFixed(2) : ''),
    el('td', {}, (row.occupied_by || []).join(', ')),
    el('td', {class: 'num'}, uptimeText(row.uptime)),
    el('td', {class: 'flags'}, flagsText(row)),
    el('td', {}, row.sre_version || ''),
    el('td', {class: 'error', title: row.reachable ? '' : (row.error || '')}, errorText(row)),
    el('td', {class: 'actions'}, ...actions(row)));
}

async function refresh() {
  let rows;
  let status;
  try {
    [rows, status] = await Promise.all([api.get('/api/pool'), api.get('/api/pool/status')]);
  } catch (e) {
    clear(body);
    body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
    return;
  }
  state.rows = Array.isArray(rows) ? rows : [];
  state.status = status && typeof status === 'object' ? status : {};
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
        state.sortAsc = !NUMERIC.includes(key);
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
