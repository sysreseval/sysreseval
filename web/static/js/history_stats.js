// The Statistics view of the History page: the figures of GET /api/history/statistics drawn
// into the skeleton tables of history.html (their headers are in the template, translated by
// Jinja2): the totals of the period, the student groups (a click on a group row shows the
// users of that group alone, a second click every user again), the users and the labs (both
// sortable by their headers, the time first) and the distribution of the students' connection
// time.  Nothing is fetched here and nothing happens at module load: history.js creates the
// view and hands it the JSON.

import {el, clear, formatDuration} from './ui.js';
import {_, format} from './i18n.js';

const ROLE_INSTRUCTOR = 'instructor';
// the columns sorted ascending on the first click (the others, numbers and times, descending)
const TEXT_KEYS = new Set(['login', 'name', 'group', 'role', 'lab']);

function timeText(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : '';
}

function timeCell(ts) {
  return el('td', {class: 'ts', title: ts ? new Date(ts * 1000).toISOString() : ''}, timeText(ts));
}

function durationCell(seconds) {
  return el('td', {class: 'num'}, formatDuration(seconds));
}

function numCell(n) {
  return el('td', {class: 'num'}, n === null || n === undefined ? '' : String(n));
}

// the rows sorted on *key* (numbers numerically, the rest as text), the ties by *tieKey*
function sortRows(rows, {key, asc}, tieKey) {
  return rows.slice().sort((a, b) => {
    const va = a[key];
    const vb = b[key];
    let result;
    if (typeof va === 'number' && typeof vb === 'number') {
      result = va - vb;
    } else {
      const ta = va === null || va === undefined ? '' : String(va);
      const tb = vb === null || vb === undefined ? '' : String(vb);
      result = ta.localeCompare(tb);
    }
    if (result === 0) {
      result = String(a[tieKey]).localeCompare(String(b[tieKey]));
    }
    return asc ? result : -result;
  });
}

// the label of a bucket of the distribution (seconds; max null = no upper bound)
function bucketText(bucket) {
  if (bucket.max === null || bucket.max === undefined) {
    return format(_('more than {n} h'), {n: bucket.min / 3600});
  }
  if (bucket.max <= 3600) {
    return bucket.min === 0 ? format(_('less than {n} min'), {n: bucket.max / 60})
                            : format(_('{a} to {b} min'), {a: bucket.min / 60, b: bucket.max / 60});
  }
  return format(_('{a} to {b} h'), {a: bucket.min / 3600, b: bucket.max / 3600});
}

function roleText(role) {
  return role === ROLE_INSTRUCTOR ? _('instructor') : _('student');
}

// root: the #history-statistics container of history.html; groupsEnabled: a group source is
// configured (the Group column of the users and the Groups table are drawn)
export function createStatisticsView(root, {groupsEnabled = false} = {}) {
  const totals = root.querySelector('#stats-totals');
  const tables = {
    groups: root.querySelector('#stats-groups'),
    users: root.querySelector('#stats-users'),
    labs: root.querySelector('#stats-labs'),
    distribution: root.querySelector('#stats-distribution'),
  };
  // data: the JSON shown; group: the group whose users alone are listed (null = every user);
  // sort: the column and direction of the users and labs tables
  const state = {data: null, group: null, sort: {users: {key: 'time', asc: false}, labs: {key: 'time', asc: false}}};

  function body(name) {
    return tables[name].querySelector('tbody');
  }

  function columnCount(name) {
    return tables[name].querySelectorAll('thead th').length;
  }

  function emptyRow(name) {
    return el('tr', {}, el('td', {colspan: columnCount(name), class: 'muted'}, _('No session in the period.')));
  }

  function markSort(name) {
    const sort = state.sort[name];
    for (const th of tables[name].querySelectorAll('th.sortable')) {
      th.setAttribute('aria-sort', th.dataset.sort === sort.key ? (sort.asc ? 'ascending' : 'descending') : 'none');
    }
  }

  function fillTotals(data) {
    const t = data.totals || {};
    const peak = t.peak || {};
    const values = {
      period: `${timeText(data.since)} – ${timeText(data.until)}`,
      users: t.users,
      students: t.students,
      instructors: t.instructors,
      groups: t.groups,
      sessions: t.open ? `${t.sessions} (${format(_('{n} open'), {n: t.open})})` : t.sessions,
      addresses: t.addresses,
      time: formatDuration(t.time),
      average: formatDuration(t.average),
      median: formatDuration(t.median),
      longest: formatDuration(t.longest),
      peak: peak.users ? `${peak.users} (${timeText(peak.at)})` : '0',
      projects_started: t.projects_started,
      projects_used: t.projects_used,
      evaluations: t.evaluations,
      page_time: formatDuration(t.page_time),
    };
    for (const td of totals.querySelectorAll('td[data-key]')) {
      const value = values[td.dataset.key];
      td.textContent = value === null || value === undefined ? '' : String(value);
    }
  }

  function renderGroups() {
    const tbody = body('groups');
    clear(tbody);
    const groups = state.data && Array.isArray(state.data.groups) ? state.data.groups : [];
    if (!groups.length) {
      tbody.append(emptyRow('groups'));
      return;
    }
    for (const g of groups) {
      const selected = state.group === g.group;
      tbody.append(el('tr', {class: selected ? 'selected' : '',
                             title: _('Click to show the users of this group only (again: every user)'),
                             onclick: () => { state.group = selected ? null : g.group; renderGroups(); renderUsers(); }},
        el('td', {class: 'link'}, g.group || _('No group')),
        numCell(g.students),
        numCell(g.sessions),
        durationCell(g.time),
        durationCell(g.average),
        numCell(g.projects),
        numCell(g.evaluations)));
    }
  }

  function renderUsers() {
    const tbody = body('users');
    clear(tbody);
    markSort('users');
    let users = state.data && Array.isArray(state.data.users) ? state.data.users : [];
    if (state.group !== null) {
      users = users.filter((u) => u.group === state.group);
    }
    if (!users.length) {
      tbody.append(emptyRow('users'));
      return;
    }
    for (const u of sortRows(users, state.sort.users, 'login')) {
      tbody.append(el('tr', {class: u.open ? 'row-open' : ''},
        el('td', {}, u.login),
        el('td', {}, u.name || ''),
        el('td', {hidden: !groupsEnabled}, u.group || ''),
        el('td', {}, roleText(u.role)),
        numCell(u.sessions),
        durationCell(u.time),
        durationCell(u.page_time),
        timeCell(u.first),
        timeCell(u.last),
        numCell(u.addresses),
        numCell(u.projects),
        numCell(u.evaluations),
        numCell(u.requests)));
    }
  }

  function renderLabs() {
    const tbody = body('labs');
    clear(tbody);
    markSort('labs');
    const labs = state.data && Array.isArray(state.data.labs) ? state.data.labs : [];
    if (!labs.length) {
      tbody.append(emptyRow('labs'));
      return;
    }
    for (const l of sortRows(labs, state.sort.labs, 'lab')) {
      tbody.append(el('tr', {},
        el('td', {}, l.lab),
        numCell(l.projects),
        numCell(l.users),
        numCell(l.students),
        durationCell(l.time),
        durationCell(l.average),
        numCell(l.starts),
        numCell(l.evaluations)));
    }
  }

  function renderDistribution() {
    const tbody = body('distribution');
    clear(tbody);
    const buckets = state.data && Array.isArray(state.data.distribution) ? state.data.distribution : [];
    for (const bucket of buckets) {
      tbody.append(el('tr', {}, el('td', {}, bucketText(bucket)), numCell(bucket.users)));
    }
  }

  function setupSort(name, render) {
    for (const th of tables[name].querySelectorAll('th.sortable')) {
      th.addEventListener('click', () => {
        const key = th.dataset.sort;
        const sort = state.sort[name];
        if (sort.key === key) {
          sort.asc = !sort.asc;
        } else {
          sort.key = key;
          sort.asc = TEXT_KEYS.has(key);
        }
        render();
      });
    }
  }

  setupSort('users', renderUsers);
  setupSort('labs', renderLabs);

  return {
    // the JSON of GET /api/history/statistics
    render(data) {
      state.data = data;
      if (state.group !== null && !(data.groups || []).some((g) => g.group === state.group)) {
        state.group = null;
      }
      fillTotals(data);
      renderGroups();
      renderUsers();
      renderLabs();
      renderDistribution();
    },
    // nothing to show (an error, no database)
    clear() {
      state.data = null;
      for (const td of totals.querySelectorAll('td[data-key]')) {
        td.textContent = '';
      }
      for (const name of Object.keys(tables)) {
        clear(body(name));
      }
    },
  };
}
