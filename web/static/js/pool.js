// The Pool page of the instructors: every host of the pool (GET /api/pool and /api/pool/status
// every 5 s), one row per host with its state as `sre-web-tool list` shows it (the seconds and
// the failed attempts of a wake), its projects, terminals, load, free memory, who occupies it, its
// uptime, the cores its projects are counted for and those they may use (CPU), its flags
// (reserved for instructors, power, drain, power off sent, restart sent, memory
// full with [pool] project_memory_mb, memory full / cpu full with [pool] capacity =
// "resources", and where the
// preload of the Docker images is: queued, preloading 2/5, failed), the agent's version and
// its last error, and the summary of `sre-web-tool status` above the table.  The rows can be
// sorted by any column and filtered by host name.  The buttons are the commands of the tool (Enable /
// Disable, Wake, Drain, Power off: POST /api/pool/hosts/{name}/{action}; add, remove and restart
// stay with the tool), each disabled with the reason as its tooltip when it does not apply; the
// answer of an action is the updated row, shown at once.  Enable also cancels a drain: the row of
// a draining host shows it in place of Drain, and the one of the bar applies to it (not once the
// power off is sent: the host is going down).  A checkbox per row (the header's one
// ticks the hosts shown) selects hosts for the buttons of the bar above the table, which run the
// same commands on every selected host the action applies to, one call per host; Preload images
// is one of them, in the bar only: the selected hosts wait for their turn to pull the images
// (`sre-web-tool preload`), the portal letting a few of them download at a time.  The Priority
// column is the priority of the host, group:order (a new project goes to the lowest group that
// has an available host and, in it, to the lowest order among the hosts without project; the
// lowest host is woken first, the highest one is powered off first when idle; `sre-web-tool
// priority`): its value opens a dialog to change the two numbers, and Priority… of the bar sets
// the group, the order or both on every selected host (POST /api/pool/hosts/{name}/priority
// with {priority: "group:order"}).

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';

const REFRESH_INTERVAL = 5000;
const ERROR_WIDTH = 60;        // the Last error cell (the whole text in its tooltip), as the tool
const STATE_ORDER = ['up', 'occupied', 'exam', 'draining', 'waking', 'off', 'disabled'];   // the sort of the State column
const NUMERIC = ['projects', 'terminals', 'load1', 'mem_available_mb', 'cpu_used', 'uptime'];   // sorted descending first
// the group and the order of a priority: integers from -9999 to 9999 (config.PRIORITY_LIMIT of the portal)
const PRIORITY_LIMIT = 9999;

const table = document.getElementById('pool');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('pool-filter');
const countElement = document.getElementById('pool-count');
const statusElement = document.getElementById('pool-status');
const selectAll = document.getElementById('pool-select-all');
const selectedElement = document.getElementById('pool-selected');
const bulkButtons = Array.from(document.querySelectorAll('#pool-selection button[data-action]'));
const pending = new Map();     // host name -> the action in progress: its buttons stay disabled across re-renders
const selected = new Set();    // the names of the selected hosts, kept across re-renders

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
  if (row.local_drain) {
    // asked on the host itself (sre set-drain there), not on this page
    flags.push(_('local drain'));
  } else {
    if (row.drain) {
      flags.push(_('drain'));
    }
    const localDrain = localDrainFlag(row);
    if (localDrain) {
      flags.push(localDrain);
    }
  }
  if (row.power_off_sent) {
    flags.push(_('power off sent'));
  }
  if (row.restart_sent) {
    flags.push(_('restart sent'));
  }
  if (row.exam_hold && row.state !== 'exam') {
    // a machine an exam of the Exams page is about to lock: no new project goes there
    flags.push(_('kept for an exam'));
  }
  if (row.memory_room === 0 && row.reachable) {
    // [pool] project_memory_mb: the free memory of the host holds no new project
    flags.push(_('memory full'));
  }
  if (row.cpu_room === 0 && row.reachable) {
    // [pool] capacity = "resources": the processors of the host hold no new project
    flags.push(_('cpu full'));
  }
  const preload = preloadFlag(row);
  if (preload) {
    flags.push(preload);
  }
  return flags.join(', ');
}

// whether the host may ask for its own drain (sre set-drain there): told when it may, and when it
// may not although its agent.toml allows it (forbidden from this page); nothing for a host that
// is not reachable or whose agent does not know the local drains (null)
function localDrainFlag(row) {
  if (!row.reachable || typeof row.local_drain_allowed !== 'boolean') {
    return '';
  }
  if (row.local_drain_allowed) {
    return _('local drain allowed');
  }
  return row.local_drain_default ? _('local drain forbidden') : '';
}

// the preload of the Docker images on the host: waiting for its turn, pulling (image 2 of 5), failed
function preloadFlag(row) {
  switch (row.preload) {
    case 'pending':
      return _('preload queued');
    case 'running':
      return row.preload_total
        ? format(_('preloading {current}/{total}'), {current: row.preload_current || 0, total: row.preload_total})
        : _('preloading');
    case 'failed':
      return _('preload failed');
    default:
      return '';
  }
}

// the tooltip of the Flags cell: the image being pulled, or why the preload failed, else where a
// local drain comes from
function flagsTitle(row) {
  if (row.preload === 'running') {
    return row.preload_image || '';
  }
  if (row.preload === 'failed') {
    return row.preload_error || '';
  }
  return row.local_drain ? _('drain asked on the host itself (sre set-drain)') : '';
}

function memoryText(row) {   // 12.3 GiB: the MemAvailable of the host (an older agent says nothing)
  return row.reachable && isNumber(row.mem_available_mb)
    ? format(_('{n} GiB'), {n: (row.mem_available_mb / 1024).toFixed(1)}) : '';
}

// 3.2 / 11.2: the cores the projects of the host are counted for, and those they may use (an
// older agent, or an older portal, says nothing)
function cpuText(row) {
  return row.reachable && isNumber(row.cpu_used) && isNumber(row.cpu_capacity)
    ? `${row.cpu_used.toFixed(1)} / ${row.cpu_capacity.toFixed(1)}` : '';
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

// the priority of a host, {group, order} (0:0 for a portal that says nothing; the single number
// of a portal of before the groups is that order in group 0)
function priorityOf(row) {
  const former = Number.isInteger(row.priority) ? row.priority : 0;
  return {group: Number(row.group) || 0, order: Number.isInteger(row.order) ? row.order : former};
}

// a priority as it is written and shown: "group:order"
function priorityText(priority) {
  return `${priority.group}:${priority.order}`;
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
    case 'mem_available_mb': return row.reachable && isNumber(row.mem_available_mb) ? row.mem_available_mb : -1;
    case 'cpu_used': return row.reachable && isNumber(row.cpu_used) ? row.cpu_used : -1;
    case 'uptime': return isNumber(row.uptime) ? row.uptime : -1;
    case 'occupied_by': return (row.occupied_by || []).join(',');
    case 'priority': {      // the group, then the order: one number
      const priority = priorityOf(row);
      return priority.group * (2 * PRIORITY_LIMIT + 2) + priority.order;
    }
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

// the filter on the host name only (the Host column): one or several words, a host whose name
// contains any of them ("a01 a02 h": those two and every h* host)
function matches(row) {
  if (!state.filter) {
    return true;
  }
  const name = (row.name || '').toLowerCase();
  return state.filter.split(/\s+/).some((word) => name.includes(word));
}

function shownRows() {
  return state.rows.filter(matches);
}

// why an action does not apply to a host ('' when it does): the tooltip of its disabled button,
// and what the bulk buttons skip
function actionReason(row, action) {
  const unreachable = row.reachable ? '' : _('the host is not reachable');
  switch (action) {
    case 'enable':
      if (!row.enabled) {
        return '';
      }
      if (!row.drain) {
        return _('the host is enabled');
      }
      // an enabled host that drains: Enable cancels the drain, unless the host is going down
      return row.power_off_sent ? _('power off sent') : '';
    case 'disable':
      return row.enabled ? '' : _('the host is disabled');
    case 'wake':
      if (!row.can_wake) {
        return _('no MAC address nor wake command');
      }
      return row.reachable ? _('the host is up') : '';
    case 'drain':
      if (unreachable) {
        return unreachable;
      }
      if (!row.enabled) {
        return _('the host is disabled');
      }
      return row.drain ? _('already draining') : '';
    case 'poweroff':
      if (unreachable) {
        return unreachable;
      }
      if (!row.power_off_allowed) {
        return _('the agent does not allow it (allow_power_off)');
      }
      return row.power_off_sent ? _('power off sent') : '';
    case 'preload':
      if (unreachable) {
        return unreachable;
      }
      if (!row.preload) {
        return _('the agent does not know the preload (older version)');
      }
      if (row.preload === 'pending') {
        return _('already queued');
      }
      return row.preload === 'running' ? _('already preloading') : '';
    case 'allow-local-drain':
    case 'forbid-local-drain':
      if (unreachable) {
        return unreachable;
      }
      if (typeof row.local_drain_allowed !== 'boolean') {
        return _('the agent does not know the local drains (older version)');
      }
      if (action === 'allow-local-drain') {
        return row.local_drain_allowed ? _('local drain is already allowed') : '';
      }
      return row.local_drain_allowed ? '' : _('local drain is already forbidden');
    default:
      return '';
  }
}

function powerOffQuestion(names) {
  return format(_('Power off {name}? The agent refuses while a project runs or someone is logged in there.'),
                {name: names.join(', ')});
}

// one call of the route (body: what the action takes, the priority alone has one); the answer
// (the updated row) replaces the row at once
async function postAction(row, action, body) {
  const updated = await api.post(`/api/pool/hosts/${encodeURIComponent(row.name)}/${action}`, body);
  if (updated && updated.name) {
    state.rows = state.rows.map((r) => (r.name === updated.name ? updated : r));
  }
}

// the dialog asking for a priority, group:order: a modal outside the table, whose rows are built
// anew at every poll (an input in a cell would lose its focus and what is typed).  value:
// {group, order}, the numbers shown first ('' for none).  With options.partial (several hosts) a
// field left empty leaves that number of each host as it is; without it both are required.
// Resolves with {group, order} (null for a number left empty), or null when the dialog is
// cancelled or asks for nothing.
function priorityDialog(title, value, options = {}) {
  return new Promise((resolve) => {
    let result = null;
    const field = (name, shown) => el('input', {type: 'number', name, required: !options.partial, step: '1',
                                              min: String(-PRIORITY_LIMIT), max: String(PRIORITY_LIMIT),
                                              value: String(shown)});
    const group = field('group', value.group);
    const order = field('order', value.order);
    // the number of a field: null when it is empty, undefined when it is no number of a priority
    const read = (input) => {
      const text = input.value.trim();
      const number = Number(text);
      if (text === '') {
        return null;
      }
      return Number.isInteger(number) && Math.abs(number) <= PRIORITY_LIMIT ? number : undefined;
    };
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const save = el('button', {type: 'submit', class: 'primary'}, _('Save'));
    const form = el('form', {},
      el('label', {}, _('Group'), group),
      el('label', {}, _('Order'), order),
      el('p', {class: 'muted'},
         _('A new project goes to the lowest group that has an available host, and in that group to the least loaded host, the lowest order first among the hosts without project. The hosts are woken in that order and powered off, when idle, in the reverse one. 0:0 by default; a negative number comes before.')),
      options.partial
        ? el('p', {class: 'muted'}, _('A field left empty leaves that number of each host as it is.')) : null,
      el('div', {class: 'buttons'}, cancel, el('span', {class: 'spacer'}), save));
    const dialog = el('dialog', {class: 'modal pool-priority'}, el('h2', {}, title), form);
    cancel.addEventListener('click', () => dialog.close());
    form.addEventListener('submit', (event) => {    // the browser checked the fields: whole numbers in the range
      event.preventDefault();
      const asked = {group: read(group), order: read(order)};
      if (asked.group === undefined || asked.order === undefined
          || (!options.partial && (asked.group === null || asked.order === null))) {
        return;
      }
      result = asked.group === null && asked.order === null ? null : asked;    // nothing asked: nothing to change
      dialog.close();
    });
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
    group.focus();
    group.select();
  });
}

// the priority of one host, asked in the dialog (the row is read again afterwards: the pool was
// polled meanwhile, the host may be gone or have got that priority)
async function editPriority(name) {
  const before = state.rows.find((row) => row.name === name);
  if (!before) {
    return;
  }
  const asked = await priorityDialog(format(_('Priority of {name}'), {name}), priorityOf(before));
  const row = state.rows.find((r) => r.name === name);
  if (asked === null || !row || pending.has(name) || priorityText(asked) === priorityText(priorityOf(row))) {
    return;
  }
  await act(row, 'priority', {priority: priorityText(asked)});
}

// the group and the order the hosts share, each '' when they do not have the same: what the
// dialog of the bar shows first
function commonPriority(rows) {
  const common = (key) => {
    const values = new Set(rows.map((row) => priorityOf(row)[key]));
    return values.size === 1 ? priorityOf(rows[0])[key] : '';
  };
  return {group: common('group'), order: common('order')};
}

// one action on a host: the row's buttons disabled meanwhile, the answer (the updated row) shown
// at once, then a refresh (the status line changes too)
async function act(row, action, body) {
  pending.set(row.name, action);
  render();
  try {
    await postAction(row, action, body);
  } catch (e) {
    toast(e.message, {error: true});
  } finally {
    pending.delete(row.name);
  }
  render();
  await refresh();
}

// the selected hosts an action applies to, those with an action in progress left out
function targets(action) {
  return state.rows.filter((row) => selected.has(row.name) && !pending.has(row.name) && !actionReason(row, action));
}

// one action on every selected host it applies to: one call per host, run together (one admin
// line of the connection log each), the rows' buttons disabled meanwhile, every answer shown at
// once, the failures in one message, then a refresh; the selection is kept.  The priority is
// asked first, in its dialog: a group, an order or both for all of them, each host keeping the
// number left empty (the targets are taken again afterwards, the pool was polled meanwhile).
async function actMany(action) {
  let rows = targets(action);
  if (!rows.length) {
    return;
  }
  if (action === 'poweroff' && !window.confirm(powerOffQuestion(rows.map((row) => row.name)))) {
    return;
  }
  let bodyOf = () => undefined;      // what the action takes, per host: the priority alone has a body
  if (action === 'priority') {
    const asked = await priorityDialog(format(_('Priority of the {n} selected host(s)'), {n: rows.length}),
                                       commonPriority(rows), {partial: true});
    rows = targets(action);
    if (asked === null || !rows.length) {
      return;
    }
    bodyOf = (row) => {
      const current = priorityOf(row);
      return {priority: priorityText({group: asked.group === null ? current.group : asked.group,
                                      order: asked.order === null ? current.order : asked.order})};
    };
  }
  for (const row of rows) {
    pending.set(row.name, action);
  }
  render();
  const failures = new Map();
  await Promise.all(rows.map(async (row) => {
    try {
      await postAction(row, action, bodyOf(row));
    } catch (e) {
      failures.set(row.name, e.message);
    } finally {
      pending.delete(row.name);
    }
  }));
  if (failures.size) {
    const details = rows.filter((row) => failures.has(row.name)).map((row) => `${row.name}: ${failures.get(row.name)}`);
    toast(format(_('{failed} of {total} action(s) failed: {details}'),
                 {failed: failures.size, total: rows.length, details: details.join('; ')}), {error: true});
  }
  render();
  await refresh();
}

// a button of the Actions cell: options.reason (a text) disables it with the reason as its tooltip,
// options.title is the tooltip of a button that applies, options.confirm is asked before the
// action, options.tone is its class: danger (red text), ok (green), ok-light (light green)
function actionButton(row, action, label, options = {}) {
  const button = el('button', {type: 'button', class: options.tone,
                               title: options.reason || options.title || undefined}, label);
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

// the buttons of a row, always there (a stable layout), each with the reason it is disabled; an
// enabled host that drains has Enable in place of Drain: it cancels the drain
function actions(row) {
  const cancelsDrain = row.enabled && row.drain;
  return [
    row.enabled ? actionButton(row, 'disable', _('Disable'), {tone: 'danger'}) : actionButton(row, 'enable', _('Enable'), {tone: 'ok'}),
    actionButton(row, 'wake', _('Wake'), {tone: 'ok-light', reason: actionReason(row, 'wake')}),
    cancelsDrain
      ? actionButton(row, 'enable', _('Enable'),
                     {tone: 'ok', reason: actionReason(row, 'enable'), title: _('cancels the drain')})
      : actionButton(row, 'drain', _('Drain'), {reason: actionReason(row, 'drain')}),
    actionButton(row, 'poweroff', _('Power off'),
                 {tone: 'danger', reason: actionReason(row, 'poweroff'), confirm: powerOffQuestion([row.name])}),
  ];
}

// the Priority cell: the value is a button opening the dialog that changes it (disabled while an
// action runs on the host, like the buttons of the row)
function priorityCell(row) {
  const button = el('button', {type: 'button',
                               title: _('Change the priority (group:order): the lowest group is used first, then the lowest order')},
                    priorityText(priorityOf(row)));
  button.disabled = pending.has(row.name);
  button.addEventListener('click', () => editPriority(row.name));
  return el('td', {class: 'num priority'}, button);
}

// the checkbox of a row
function selectBox(row) {
  const box = el('input', {type: 'checkbox', 'aria-label': row.name});
  box.checked = selected.has(row.name);
  box.addEventListener('change', () => {
    if (box.checked) {
      selected.add(row.name);
    } else {
      selected.delete(row.name);
    }
    renderSelection();
  });
  return box;
}

// the header checkbox (the hosts shown: all, some or none of them selected) and the bar above the
// table: the count of the selected hosts and the bulk buttons, each enabled when its action
// applies to at least one selected host, the tooltip saying how many
function renderSelection() {
  const shown = shownRows();
  const shownSelected = shown.filter((row) => selected.has(row.name)).length;
  const count = selected.size;
  let text = format(_('{n} host(s) selected'), {n: count});
  if (count > shownSelected) {
    text += ' ' + format(_('({n} not shown)'), {n: count - shownSelected});
  }
  selectedElement.textContent = text;
  selectAll.disabled = !shown.length;
  selectAll.checked = shown.length > 0 && shownSelected === shown.length;
  selectAll.indeterminate = shownSelected > 0 && shownSelected < shown.length;
  for (const button of bulkButtons) {
    const n = targets(button.dataset.action).length;
    let reason = '';
    if (!count) {
      reason = _('no host selected');
    } else if (!n) {
      reason = _('applies to none of the selected hosts');
    }
    button.disabled = Boolean(reason);
    button.title = reason || format(_('applies to {n} of the {total} selected host(s)'), {n, total: count});
  }
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
  if (Array.isArray(s.memory_full) && s.memory_full.length) {
    pieces.push(format(_('memory full: {names}'), {names: s.memory_full.join(', ')}));
  }
  if (Array.isArray(s.cpu_full) && s.cpu_full.length) {
    pieces.push(format(_('cpu full: {names}'), {names: s.cpu_full.join(', ')}));
  }
  // the preloads of the Docker images, when there is something to say
  const preloading = Array.isArray(s.preloading) ? s.preloading.length : 0;
  if (isNumber(s.max_preloads) && (preloading || s.preload_queued || s.preload_failed)) {
    pieces.push(format(_('image preloads: {running} running, {queued} queued, {failed} failed (at most {max} at a time)'),
                       {running: preloading, queued: s.preload_queued || 0, failed: s.preload_failed || 0,
                        max: s.max_preloads}));
  }
  // the state file of the portal cannot be written: a restart would undo what is changed here
  const unsaved = typeof s.state_error === 'string' && s.state_error !== '';
  if (unsaved) {
    pieces.push(format(_('the changes are NOT saved, a restart of the portal loses them: {error}'),
                       {error: s.state_error}));
  }
  statusElement.classList.toggle('unsaved', unsaved);
  statusElement.textContent = pieces.join(' — ');
}

function render() {
  clear(body);
  renderStatus();
  renderSelection();
  const rows = shownRows().sort(compare);
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
    el('td', {class: 'select'}, selectBox(row)),
    el('td', {title: nameTitle}, row.name || ''),
    el('td', {class: `state ${row.state || ''}`, title: idle}, stateText(row)),
    el('td', {class: 'num'}, row.reachable ? `${row.projects} / ${row.max_projects}` : ''),
    el('td', {class: 'num'}, row.reachable ? String(row.terminals) : ''),
    el('td', {class: 'num'}, isNumber(row.load1) ? row.load1.toFixed(2) : ''),
    el('td', {class: 'num memory'}, memoryText(row)),
    el('td', {class: 'num cpu'}, cpuText(row)),
    el('td', {}, (row.occupied_by || []).join(', ')),
    el('td', {class: 'num'}, uptimeText(row.uptime)),
    priorityCell(row),
    el('td', {class: 'flags', title: flagsTitle(row)}, flagsText(row)),
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
  const names = new Set(state.rows.map((row) => row.name));
  for (const name of Array.from(selected)) {   // the hosts removed from the pool
    if (!names.has(name)) {
      selected.delete(name);
    }
  }
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
  selectAll.addEventListener('change', () => {   // the hosts shown, selected or deselected together
    for (const row of shownRows()) {
      if (selectAll.checked) {
        selected.add(row.name);
      } else {
        selected.delete(row.name);
      }
    }
    render();
  });
  for (const button of bulkButtons) {
    button.addEventListener('click', () => actMany(button.dataset.action));
  }
}

async function main() {
  await i18n.init();
  setupControls();
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
