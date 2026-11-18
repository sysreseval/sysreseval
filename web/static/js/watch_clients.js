// The Clients view of the Watch page: who is connected, and with what (GET /api/watch/clients,
// asked by watch.js while the view is shown).  Two tables:
// - Local GUI: the users with the Qt GUI running on a pool host (the agents report them), one
//   row per user and host, with the time the GUI started;
// - Web portal: the browsers connected to the portal, one row per browser (the tabs of one
//   browser are one row; another browser, another device or a private window is another row)
//   with the user, the kind of browser and its system, since when it is connected and the
//   pages it shows — a project page as a link to that project, any other page as its path.
//   The Address column (the client address) is for the administrators: the portal sends the
//   addresses to nobody else, and the column is hidden for the other instructors.
// The text filter and the group select of the page apply to both tables; each table is sorted
// by its headers (table_sort.js).  Nothing here asks the portal: watch.js hands the data.

import {_, format} from './i18n.js';
import {el, clear} from './ui.js';
import {projectUrl} from './creation.js';
import {sortRows, markSort, setupSort} from './table_sort.js';
import {parseKey, rowGroupKeys, rowMatchesGroup} from './groups_model.js';

const ROLE_INSTRUCTOR = 'instructor';

// What a page of a browser is called: the lab and the owner of a project page ("sre/dhcp.py
// (alice)", from its running lab name timestamp@@@lab@@@login), the path of any other page.
export function pageLabel(page) {
  if (!page || typeof page.rln !== 'string' || !page.host) {
    return page && typeof page.path === 'string' ? page.path : '';
  }
  const parts = page.rln.split('@@@');
  if (parts.length < 3) {
    return page.path || '';
  }
  return `${parts.slice(1, -1).join('@@@').replace(/@/g, '/')} (${parts[parts.length - 1]})`;
}

// "Firefox 131", "Firefox" without a version, '' for an unknown program
export function browserText(row) {
  if (!row.browser) {
    return '';
  }
  return row.version ? `${row.browser} ${row.version}` : row.browser;
}

// the words a row is searched by the text filter
export function clientHaystack(row) {
  const names = [...rowGroupKeys(row)].map((key) => parseKey(key).name);
  const pages = Array.isArray(row.pages) ? row.pages.map(pageLabel) : [];
  const addrs = Array.isArray(row.addrs) ? row.addrs : [];
  return [row.host, row.login, row.fullname, row.group, ...names, row.role, browserText(row), row.system,
          ...addrs, ...pages].filter(Boolean).join(' ').toLowerCase();
}

function timeText(seconds) {
  return typeof seconds === 'number' ? new Date(seconds * 1000).toLocaleString() : '';
}

function sortValue(row, key) {
  switch (key) {
    case 'fullname': return (row.fullname || '').toLowerCase();
    case 'since': return typeof row.since === 'number' ? row.since : -Infinity;
    case 'browser': return browserText(row);
    case 'addr': return Array.isArray(row.addrs) ? row.addrs.join(' ') : '';
    case 'pages': return Number(row.tabs) || 0;
    default: return row[key] || '';
  }
}

// root: the #watch-clients section; groupsEnabled: the Group columns are shown; the Address
// column is shown when the web table says data-addresses="true" (an administrator).
export function createClientsView(root, {groupsEnabled = false} = {}) {
  const tables = {local: root.querySelector('#watch-local'), web: root.querySelector('#watch-web')};
  const counts = {local: root.querySelector('#watch-local-count'), web: root.querySelector('#watch-web-count')};
  const addressesEnabled = tables.web.dataset.addresses === 'true';
  const sorts = {local: {key: 'host', asc: true}, web: {key: 'login', asc: true}};
  let data = {local: [], web: []};
  let filters = {filter: '', group: null};

  function columnCount(table) {
    return table.querySelectorAll('thead th:not([hidden])').length;
  }

  function matches(row) {
    if (!rowMatchesGroup(row, filters.group)) {
      return false;
    }
    if (!filters.filter) {
      return true;
    }
    const haystack = clientHaystack(row);
    return filters.filter.split(/\s+/).every((word) => haystack.includes(word));
  }

  function message(table, text, cls = 'muted') {
    const body = table.querySelector('tbody');
    clear(body);
    body.append(el('tr', {}, el('td', {colspan: columnCount(table), class: cls}, text)));
  }

  function roleText(role) {
    return role === ROLE_INSTRUCTOR ? _('instructor') : _('student');
  }

  function localRow(row) {
    return el('tr', {},
      el('td', {}, row.host || ''),
      el('td', {}, row.login || ''),
      el('td', {}, row.fullname || ''),
      el('td', {hidden: !groupsEnabled}, row.group || ''),
      el('td', {}, timeText(row.since)));
  }

  function pagesCell(row) {
    const pages = Array.isArray(row.pages) ? row.pages : [];
    const cell = el('td', {class: 'pages', title: format(_('{n} page(s) open'), {n: Number(row.tabs) || 0})});
    for (const page of pages) {
      // a link only to a project page, built from its host and name: never from the raw path,
      // which is what the browser said
      const label = pageLabel(page);
      cell.append(el('div', {}, page.host && page.rln
        ? el('a', {href: projectUrl(page.host, page.rln), title: page.host}, label)
        : label));
    }
    return cell;
  }

  function webRow(row) {
    const system = row.system ? (row.mobile ? format(_('{system} (mobile)'), {system: row.system}) : row.system) : '';
    return el('tr', {},
      el('td', {}, row.login || ''),
      el('td', {}, row.fullname || ''),
      el('td', {hidden: !groupsEnabled}, row.group || ''),
      el('td', {}, roleText(row.role)),
      el('td', {title: row.ua || null}, browserText(row) || _('unknown')),
      el('td', {}, system),
      el('td', {hidden: !addressesEnabled}, Array.isArray(row.addrs) ? row.addrs.join(', ') : ''),
      el('td', {}, timeText(row.since)),
      pagesCell(row));
  }

  function renderTable(name, renderRow, emptyText) {
    const table = tables[name];
    const all = data[name];
    const rows = sortRows(all.filter(matches), sorts[name], {value: sortValue, tieKey: 'login'});
    markSort(table, sorts[name]);
    counts[name].textContent = rows.length === all.length ? `(${rows.length})` : `(${rows.length} / ${all.length})`;
    if (!rows.length) {
      message(table, all.length ? _('No client matches the filter.') : emptyText);
    } else {
      const body = table.querySelector('tbody');
      clear(body);
      for (const row of rows) {
        body.append(renderRow(row));
      }
    }
    return rows.length;
  }

  // draws both tables for the filters {filter: lower-case words, group: null | '' | key};
  // returns how many clients are shown and how many there are
  function render(newFilters) {
    if (newFilters) {
      filters = newFilters;
    }
    const shown = renderTable('local', localRow, _('Nobody is in a local GUI.'))
      + renderTable('web', webRow, _('No browser is connected.'));
    return {shown, total: data.local.length + data.web.length};
  }

  function setData(answer) {
    data = {local: answer && Array.isArray(answer.local) ? answer.local : [],
            web: answer && Array.isArray(answer.web) ? answer.web : []};
  }

  function showError(text) {
    for (const name of ['local', 'web']) {
      counts[name].textContent = '';
      message(tables[name], text, 'error');
    }
  }

  // the rows as the portal gave them (the group select of the page lists their groups)
  function rows() {
    return [...data.local, ...data.web];
  }

  setupSort(tables.local, sorts.local, {ascFirst: (key) => key !== 'since', onChange: () => render()});
  setupSort(tables.web, sorts.web, {ascFirst: (key) => key !== 'since' && key !== 'pages', onChange: () => render()});

  return {render, setData, showError, rows};
}
