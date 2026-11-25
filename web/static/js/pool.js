// The Pool page of the instructors: every host of the pool (GET /api/pool and /api/pool/status
// every 5 s), one row per host with its state as `sre-web-tool list` shows it (the seconds and
// the failed attempts of a wake), its projects, terminals, load, free memory, who occupies it, its
// uptime, the cores its projects are counted for and those they may use (CPU), its flags
// (reserved for instructors, power, drain, power off sent, restart sent, memory
// full with [pool] project_memory_mb, memory full / cpu full with [pool] capacity =
// "resources", where the
// preload of the Docker images is: queued, preloading 2/5, failed, and saves unusable for a
// host whose agent.toml has a directory of the saved projects it cannot use), the agent's
// version and its last error (for a host with unusable saves, what its agent found: a volume
// that is not mounted, a marker never created), and the summary of `sre-web-tool status` above
// the table.  The rows can be
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
// with {priority: "group:order"}).  The Capacity column is what the whole host holds for
// projects (its memory less the reserve, its processors by the share projects may use), and the
// Usable capacity one the share of it the projects of this host may fill ([[hosts]]
// total_usable_capacity, a percentage; `sre-web-tool usable-capacity`): its value opens a dialog
// to change it, and Usable capacity… of the bar sets it on every selected host (POST
// /api/pool/hosts/{name}/usable-capacity with {total_usable_capacity: N}).  A priority or a share
// that is not the one of the configuration is in bold, its tooltip naming the configured value,
// and Reset to initial settings puts both back on every host (POST /api/pool/reset-settings)
// once its dialog, which lists what changes, is confirmed.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';

const REFRESH_INTERVAL = 5000;
const ERROR_WIDTH = 60;        // the Last error cell (the whole text in its tooltip), as the tool
const STATE_ORDER = ['up', 'occupied', 'exam', 'draining', 'waking', 'off', 'disabled'];   // the sort of the State column
const NUMERIC = ['projects', 'terminals', 'load1', 'mem_available_mb', 'cpu_used', 'capacity', 'uptime'];   // sorted descending first
// the group and the order of a priority: integers from -9999 to 9999 (config.PRIORITY_LIMIT of the portal)
const PRIORITY_LIMIT = 9999;
// total_usable_capacity of a host its projects may fill entirely (config.DEFAULT_USABLE_CAPACITY of the portal)
const WHOLE_HOST = 100;

const table = document.getElementById('pool');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('pool-filter');
const countElement = document.getElementById('pool-count');
const statusElement = document.getElementById('pool-status');
const selectAll = document.getElementById('pool-select-all');
const selectedElement = document.getElementById('pool-selected');
const bulkButtons = Array.from(document.querySelectorAll('#pool-selection button[data-action]'));
const resetButton = document.getElementById('pool-reset');
const pending = new Map();     // host name -> the action in progress: its buttons stay disabled across re-renders
const selected = new Set();    // the names of the selected hosts, kept across re-renders

const state = {rows: [], status: {}, sortKey: 'name', sortAsc: true, filter: '', resetting: false};

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
  if (savesUnusable(row)) {
    flags.push(_('saves unusable'));
  }
  return flags.join(', ');
}

// the host is meant to save and restore projects ([saves] dir of its agent.toml) and cannot: its
// volume is not mounted, the marker of the store was never created…  Never an unreachable host,
// nor one whose agent or portal is older than the key (as poolctl.saves_unusable() of the tool)
function savesUnusable(row) {
  return Boolean(row.reachable && row.saves_configured === true && !row.saves);
}

// what the agent of such a host found, as the Last error cell and the tooltips tell it
function savesError(row) {
  if (!savesUnusable(row)) {
    return '';
  }
  return row.saves_error ? format(_('saves: {reason}'), {reason: row.saves_error}) : _('saves unusable');
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

// the tooltip of the Flags cell, one line per flag that has more to say, in the order of the
// flags: where a local drain comes from, the image being pulled or why the preload failed, why
// the saves are unusable
function flagsTitle(row) {
  const lines = [];
  if (row.local_drain) {
    lines.push(_('drain asked on the host itself (sre set-drain)'));
  }
  if (row.preload === 'running') {
    lines.push(row.preload_image || '');
  } else if (row.preload === 'failed') {
    lines.push(row.preload_error || '');
  }
  lines.push(savesError(row));
  return lines.filter(Boolean).join('\n');
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

// "14.6 GiB · 9.8 cores": a memory in MiB and a number of cores
function capacityFigures(memoryMb, cores) {
  return format(_('{memory} GiB · {cores} cores'), {memory: (memoryMb / 1024).toFixed(1), cores: cores.toFixed(1)});
}

// what the whole host holds for projects, whatever its share (an unreachable host, an older
// agent or an older portal say nothing)
function capacityText(row) {
  return row.reachable && isNumber(row.full_mem_capacity_mb) && isNumber(row.full_cpu_capacity)
    ? capacityFigures(row.full_mem_capacity_mb, row.full_cpu_capacity) : '';
}

// the share of the capacity of a host its projects may fill, in percent (a portal that says
// nothing: the whole host)
function usableOf(row) {
  return Number.isInteger(row.total_usable_capacity) ? row.total_usable_capacity : WHOLE_HOST;
}

function percentText(percent) {
  return format(_('{percent} %'), {percent});
}

// the tooltip of the Capacity cell: the part of it the projects may fill, when it is not all of it
function capacityTitle(row) {
  const share = usableOf(row);
  if (!capacityText(row) || share === WHOLE_HOST) {
    return '';
  }
  return format(_('{percent} % usable: {figures}'),
                {percent: share, figures: capacityFigures(row.full_mem_capacity_mb * share / WHOLE_HOST,
                                                          row.full_cpu_capacity * share / WHOLE_HOST)});
}

function uptimeText(seconds) {   // 1h02, as the tool
  if (!isNumber(seconds)) {
    return '';
  }
  const minutes = Math.floor(seconds / 60);
  return `${Math.floor(minutes / 60)}h${String(minutes % 60).padStart(2, '0')}`;
}

// the Last error cell: why the host does not answer; for a host that does, why its saves are
// unusable (the cell is free then).  The whole text is the tooltip of the cell
function errorTitle(row) {
  return row.reachable ? savesError(row) : (row.error || '');
}

function errorText(row) {
  const text = errorTitle(row);
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

// the priority the configuration gives a host whose priority was set by hand (here, or with
// sre-web-tool); null when they are the same, or for a portal that does not tell the configured one
function configuredPriority(row) {
  const configured = row.priority_configured;
  return typeof configured === 'string' && configured !== priorityText(priorityOf(row)) ? configured : null;
}

// the same for the share of the host its projects may fill
function configuredUsable(row) {
  const configured = row.total_usable_capacity_configured;
  return Number.isInteger(configured) && configured !== usableOf(row) ? configured : null;
}

// what Reset to initial settings changes: the hosts whose priority or share is not the one of the
// configuration, each with the texts of its changes ("priority 1:0 → 0:0")
function resetChanges() {
  const hosts = [];
  for (const row of state.rows) {
    const changes = [];
    const priority = configuredPriority(row);
    if (priority !== null) {
      changes.push(format(_('priority {from} → {to}'), {from: priorityText(priorityOf(row)), to: priority}));
    }
    const usable = configuredUsable(row);
    if (usable !== null) {
      changes.push(format(_('usable capacity {from} → {to}'), {from: percentText(usableOf(row)), to: percentText(usable)}));
    }
    if (changes.length) {
      hosts.push({name: row.name, changes});
    }
  }
  return hosts.sort((a, b) => a.name.localeCompare(b.name));
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
    case 'capacity': return row.reachable && isNumber(row.full_mem_capacity_mb) ? row.full_mem_capacity_mb : -1;
    case 'total_usable_capacity': return usableOf(row);
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
      // a disabled host is never powered off, so a drain there would never end: unless its
      // agent says a drain powers it off all the same (allow_power_off_when_disabled)
      if (!row.enabled && row.power_off_when_disabled_allowed !== true) {
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

// the dialog asking for the share of a host its projects may fill, a percentage: built as the
// one of the priority.  value: the percentage shown first ('' for none: the selected hosts do
// not have the same).  Resolves with the percentage, or null when the dialog is cancelled.
function usableCapacityDialog(title, value) {
  return new Promise((resolve) => {
    let result = null;
    const percent = el('input', {type: 'number', name: 'percent', required: true, step: '1', min: '1',
                                 max: String(WHOLE_HOST), value: String(value)});
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const save = el('button', {type: 'submit', class: 'primary'}, _('Save'));
    const form = el('form', {},
      el('label', {}, _('Share (%)'), percent),
      el('p', {class: 'muted'},
         _('The share of the capacity of the host (its memory less the reserve, its processors) its projects may fill, from 1 to 100: at 50 the host counts as a machine half its size, and what is in use there counts against it. 100 by default: the whole host. It counts when the pool places the projects by the load of the hosts.')),
      el('div', {class: 'buttons'}, cancel, el('span', {class: 'spacer'}), save));
    const dialog = el('dialog', {class: 'modal pool-usable'}, el('h2', {}, title), form);
    cancel.addEventListener('click', () => dialog.close());
    form.addEventListener('submit', (event) => {    // the browser checked the field: a whole number in the range
      event.preventDefault();
      const number = Number(percent.value.trim());
      if (percent.value.trim() === '' || !Number.isInteger(number) || number < 1 || number > WHOLE_HOST) {
        return;
      }
      result = number;
      dialog.close();
    });
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
    percent.focus();
    percent.select();
  });
}

// the share of one host, asked in the dialog (the row is read again afterwards, as for a priority)
async function editUsableCapacity(name) {
  const before = state.rows.find((row) => row.name === name);
  if (!before) {
    return;
  }
  const asked = await usableCapacityDialog(format(_('Usable capacity of {name}'), {name}), usableOf(before));
  const row = state.rows.find((r) => r.name === name);
  if (asked === null || !row || pending.has(name) || asked === usableOf(row)) {
    return;
  }
  await act(row, 'usable-capacity', {total_usable_capacity: asked});
}

// the share the hosts have in common, '' when they do not have the same: what the dialog of the
// bar shows first
function commonUsable(rows) {
  const values = new Set(rows.map(usableOf));
  return values.size === 1 ? usableOf(rows[0]) : '';
}

// the confirmation of Reset to initial settings: the hosts that change and what changes on each.
// Resolves with true when it is confirmed.
function resetDialog(hosts) {
  return new Promise((resolve) => {
    let confirmed = false;
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const reset = el('button', {type: 'button', class: 'primary'}, _('Reset'));
    const dialog = el('dialog', {class: 'modal pool-reset'},
      el('h2', {}, _('Reset to initial settings')),
      el('p', {}, format(_('The priority and the usable capacity of {n} host(s) go back to the values of the configuration:'),
                         {n: hosts.length})),
      el('ul', {}, ...hosts.map((host) => el('li', {dataset: {host: host.name}},
                                             `${host.name}: ${host.changes.join(', ')}`))),
      el('div', {class: 'buttons'}, cancel, el('span', {class: 'spacer'}), reset));
    cancel.addEventListener('click', () => dialog.close());
    reset.addEventListener('click', () => {
      confirmed = true;
      dialog.close();
    });
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(confirmed);
    });
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}

// Reset to initial settings: the priority and the share of every host back to the values of the
// configuration, once the dialog is confirmed (one call for the whole pool)
async function resetSettings() {
  const hosts = resetChanges();
  if (!hosts.length || state.resetting || !(await resetDialog(hosts))) {
    return;
  }
  state.resetting = true;
  render();
  try {
    await api.post('/api/pool/reset-settings');
  } catch (e) {
    toast(e.message, {error: true});
  } finally {
    state.resetting = false;
  }
  await refresh();
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
// number left empty (the targets are taken again afterwards, the pool was polled meanwhile); the
// usable capacity too: one percentage for all of them.
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
  } else if (action === 'usable-capacity') {
    const asked = await usableCapacityDialog(format(_('Usable capacity of the {n} selected host(s)'), {n: rows.length}),
                                             commonUsable(rows));
    rows = targets(action);
    if (asked === null || !rows.length) {
      return;
    }
    bodyOf = () => ({total_usable_capacity: asked});
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
// enabled host that drains has Enable in place of Drain: it cancels the drain, as the Enable of
// a disabled host that drains does (its tooltip says so)
function actions(row) {
  const cancelsDrain = row.enabled && row.drain;
  return [
    row.enabled
      ? actionButton(row, 'disable', _('Disable'), {tone: 'danger'})
      : actionButton(row, 'enable', _('Enable'), {tone: 'ok', title: row.drain ? _('cancels the drain') : ''}),
    actionButton(row, 'wake', _('Wake'), {tone: 'ok-light', reason: actionReason(row, 'wake')}),
    cancelsDrain
      ? actionButton(row, 'enable', _('Enable'),
                     {tone: 'ok', reason: actionReason(row, 'enable'), title: _('cancels the drain')})
      : actionButton(row, 'drain', _('Drain'), {reason: actionReason(row, 'drain')}),
    actionButton(row, 'poweroff', _('Power off'),
                 {tone: 'danger', reason: actionReason(row, 'poweroff'), confirm: powerOffQuestion([row.name])}),
  ];
}

// the button of a setting of a host (its priority, its usable capacity): its value, opening the
// dialog that changes it (disabled while an action runs on the host, like the buttons of the
// row); configured: the value of the configuration when this one was set by hand (null
// otherwise), told in the tooltip, the value then in bold
function settingButton(row, text, title, configured) {
  const byHand = configured !== null;
  const button = el('button', {type: 'button', class: byHand ? 'by-hand' : undefined,
                               title: byHand ? `${title} — ${format(_('set by hand, the configuration says {value}'), {value: configured})}`
                                             : title},
                    text);
  button.disabled = pending.has(row.name);
  return button;
}

// the Priority cell
function priorityCell(row) {
  const button = settingButton(row, priorityText(priorityOf(row)),
                               _('Change the priority (group:order): the lowest group is used first, then the lowest order'),
                               configuredPriority(row));
  button.addEventListener('click', () => editPriority(row.name));
  return el('td', {class: 'num priority'}, button);
}

// the Usable capacity cell
function usableCell(row) {
  const configured = configuredUsable(row);
  const button = settingButton(row, percentText(usableOf(row)),
                               _('Change the share of the capacity of the host its projects may fill'),
                               configured === null ? null : percentText(configured));
  button.addEventListener('click', () => editUsableCapacity(row.name));
  return el('td', {class: 'num usable'}, button);
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

// the Reset to initial settings button: enabled when the priority or the share of a host is not
// the one of the configuration, its tooltip saying how many hosts
function renderReset() {
  const n = resetChanges().length;
  resetButton.disabled = !n || state.resetting;
  resetButton.title = n
    ? format(_('The priority or the usable capacity of {n} host(s) was changed: back to the values of the configuration'), {n})
    : _('Every host has the priority and the usable capacity of the configuration');
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
  renderReset();
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
    el('td', {class: 'num capacity', title: capacityTitle(row)}, capacityText(row)),
    usableCell(row),
    el('td', {}, (row.occupied_by || []).join(', ')),
    el('td', {class: 'num'}, uptimeText(row.uptime)),
    priorityCell(row),
    el('td', {class: 'flags', title: flagsTitle(row)}, flagsText(row)),
    el('td', {}, row.sre_version || ''),
    el('td', {class: 'error', title: errorTitle(row)}, errorText(row)),
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
  resetButton.addEventListener('click', resetSettings);
}

async function main() {
  await i18n.init();
  setupControls();
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
