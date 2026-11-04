// The Groups page of the instructors: the user groups of three kinds (GET /api/groups), one row
// per group with its kind, its name, its size, and for a custom group its description, its
// creator and its creation time: the departments (the departmentNumber of the people of the
// directory), the directory groups (ou=groups) and the custom groups the instructors create here
// (in the database of the portal).  The rows can be sorted by any column, filtered by text and
// by kind (the toggles; kept in the URL as ?q= and ?kind=); Refresh reads the directory again
// (?refresh=1); New group, Edit and Delete manage the custom groups; Open (or a click on the
// row) shows the members of a group (group_members.js: the Add row and the Remove buttons of a
// custom group), kept in the URL as ?open=kind:name.  Every write reloads the page's data:
// nothing is optimistic, two instructors may edit at once.  The page says what is not
// configured (the hints), and whether the directory could be read and the database answers.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {KINDS, KIND_CUSTOM, parseKey, sortGroups, kindLabel} from './groups_model.js';
import {createMembersDialog, customUrl, isoText} from './group_members.js';

const table = document.getElementById('groups');
const body = table.querySelector('tbody');
const filterInput = document.getElementById('groups-filter');
const kindButtons = Array.from(document.querySelectorAll('#groups-kinds button[data-kind]'));
const countElement = document.getElementById('groups-count');
const refreshButton = document.getElementById('groups-refresh');
const newButton = document.getElementById('groups-new');
const notice = document.getElementById('groups-notice');
const statusElement = document.getElementById('groups-status');
const databaseConfigured = table.dataset.database === 'true';

// groups: every group of the API; directory / database: their status objects; kinds: the kinds shown
const state = {groups: [], directory: null, database: null, filter: '', kinds: new Set(KINDS),
               sortKey: 'kind', sortAsc: true};

const members = createMembersDialog({
  canEdit: databaseConfigured,
  getGroups: () => state.groups,
  onChanged: () => load(),
  onOpened: (key) => setOpenInUrl(key),
  onClosed: () => setOpenInUrl(null),
});

function columnCount() {
  return table.querySelectorAll('thead th:not([hidden])').length;
}

// -- the URL ----------------------------------------------------------------------------------

function readUrl() {
  const params = new URLSearchParams(window.location.search);
  filterInput.value = params.get('q') || '';
  state.filter = filterInput.value.trim().toLowerCase();
  const kinds = (params.get('kind') || '').split(',').map((k) => k.trim()).filter((k) => KINDS.includes(k));
  if (kinds.length) {
    state.kinds = new Set(kinds);
  }
}

function writeUrl() {
  const url = new URL(window.location.href);
  if (state.filter) {
    url.searchParams.set('q', filterInput.value.trim());
  } else {
    url.searchParams.delete('q');
  }
  if (state.kinds.size === KINDS.length) {
    url.searchParams.delete('kind');
  } else {
    url.searchParams.set('kind', KINDS.filter((k) => state.kinds.has(k)).join(','));
  }
  window.history.replaceState(null, '', url);
}

function setOpenInUrl(key) {
  const url = new URL(window.location.href);
  if (key) {
    url.searchParams.set('open', key);
  } else {
    url.searchParams.delete('open');
  }
  window.history.replaceState(null, '', url);
}

// -- the table ----------------------------------------------------------------------------------

function kindBadge(kind) {
  return el('span', {class: `kind kind-${kind}`}, kindLabel(kind));
}

function matches(group) {
  if (!state.kinds.has(group.kind)) {
    return false;
  }
  if (!state.filter) {
    return true;
  }
  const haystack = [group.name, group.description, group.created_by].join(' ').toLowerCase();
  return state.filter.split(/\s+/).every((word) => haystack.includes(word));
}

function render() {
  clear(body);
  const rows = sortGroups(state.groups.filter(matches), {key: state.sortKey, asc: state.sortAsc});
  countElement.textContent = rows.length === state.groups.length
    ? format(_('{n} group(s)'), {n: rows.length})
    : format(_('{n} of {total} group(s)'), {n: rows.length, total: state.groups.length});
  for (const th of table.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === state.sortKey ? (state.sortAsc ? 'ascending' : 'descending') : 'none');
  }
  for (const button of kindButtons) {
    button.setAttribute('aria-pressed', state.kinds.has(button.dataset.kind) ? 'true' : 'false');
  }
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'muted'},
                                state.groups.length ? _('No group matches the filter.') : _('No group.'))));
    return;
  }
  for (const group of rows) {
    body.append(renderRow(group));
  }
}

function renderRow(group) {
  const custom = group.kind === KIND_CUSTOM;
  const actions = [el('button', {type: 'button', class: 'primary', onclick: () => members.open(group)}, _('Open'))];
  if (custom && databaseConfigured) {
    actions.push(el('button', {type: 'button', onclick: () => openEditDialog(group)}, _('Edit')));
    actions.push(el('button', {type: 'button', class: 'danger', onclick: () => deleteGroup(group)}, _('Delete')));
  }
  const tr = el('tr', {dataset: {key: group.key}},
    el('td', {}, kindBadge(group.kind)),
    el('td', {}, group.name),
    el('td', {class: 'num'}, String(group.members)),
    el('td', {class: 'description', title: group.description || ''}, group.description || ''),
    el('td', {hidden: !databaseConfigured}, group.created_by || ''),
    el('td', {hidden: !databaseConfigured, title: group.created_at || ''}, isoText(group.created_at)),
    el('td', {class: 'actions'}, ...actions));
  tr.addEventListener('click', (event) => {
    if (!event.target.closest('a, button')) {
      members.open(group);
    }
  });
  return tr;
}

async function deleteGroup(group) {
  if (!window.confirm(format(_('Delete the group {name}? Its members are not affected.'), {name: group.name}))) {
    return;
  }
  try {
    await api.del(customUrl(group.name));
  } catch (e) {
    toast(e.message, {error: true});
  }
  await load();
}

// -- the notices ------------------------------------------------------------------------------

function showNotice(text, {error = false} = {}) {
  notice.textContent = text;
  notice.hidden = !text;
  notice.classList.toggle('error', error);
}

// the state of the directory read and of the database, after a load
function showStatus() {
  const directory = state.directory;
  const database = state.database;
  if (directory && directory.configured && directory.error) {     // not configured: the static hint says so
    showNotice(format(_('The directory could not be read: {error}'), {error: directory.error}), {error: true});
  } else if (database && database.last_error) {
    showNotice(format(_('The custom groups may be missing: the database does not answer ({error}).'),
                      {error: database.last_error}), {error: true});
  } else {
    showNotice('');
  }
  statusElement.textContent = directory && directory.configured && directory.loaded_at
    ? format(_('Directory read {date}: {n} people'), {date: isoText(directory.loaded_at), n: directory.people})
    : '';
}

function showError(e) {
  clear(body);
  body.append(el('tr', {}, el('td', {colspan: columnCount(), class: 'error'}, e.message)));
  countElement.textContent = '';
  if (e.status === 409 || e.status === 503) {
    showNotice(e.message, {error: true});
  } else {
    toast(e.message, {error: true});
  }
}

// -- the data -----------------------------------------------------------------------------------

async function load({refresh = false} = {}) {
  const label = refreshButton.textContent;
  refreshButton.disabled = true;
  if (refresh) {
    refreshButton.textContent = _('in progress…');
  }
  let data;
  try {
    data = await api.get(api.withQuery('/api/groups', {refresh: refresh ? '1' : ''}));
  } catch (e) {
    showError(e);
    return;
  } finally {
    refreshButton.disabled = false;
    refreshButton.textContent = label;
  }
  state.groups = Array.isArray(data.groups) ? data.groups : [];
  state.directory = data.directory || null;
  state.database = data.database || null;
  showStatus();
  render();
  members.update(state.groups);
}

// -- the dialog of a new or edited custom group ---------------------------------------------------

function openEditDialog(group) {
  const editing = Boolean(group);
  const nameInput = el('input', {type: 'text', name: 'name', required: true, maxlength: '64', pattern: '[^:/]+',
                                 title: _('1 to 64 characters, without ":" or "/"'), value: editing ? group.name : ''});
  const descriptionInput = el('textarea', {name: 'description', rows: '3', maxlength: '255'});
  descriptionInput.value = editing ? group.description || '' : '';
  const error = el('p', {class: 'form-error'});
  error.hidden = true;
  const cancel = el('button', {type: 'button'}, _('Cancel'));
  const submit = el('button', {type: 'submit', class: 'primary'}, editing ? _('Save') : _('Create'));
  const form = el('form', {},
    el('label', {}, _('Name'), nameInput),
    el('label', {}, _('Description'), descriptionInput),
    error,
    el('div', {class: 'buttons'}, cancel, el('span', {class: 'spacer'}), submit));
  const dialog = el('dialog', {class: 'modal group-edit'}, el('h2', {}, editing ? _('Edit the group') : _('New group')), form);
  cancel.addEventListener('click', () => dialog.close());
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const name = nameInput.value.trim();
    const description = descriptionInput.value.trim();
    submit.disabled = true;
    try {
      let result = null;
      if (editing) {
        const changes = {};
        if (name !== group.name) {
          changes.name = name;
        }
        if (description !== (group.description || '')) {
          changes.description = description;
        }
        if (Object.keys(changes).length) {
          result = await api.put(customUrl(group.name), changes);
        }
      } else {
        result = await api.post('/api/groups', {name, description});
      }
      dialog.close();
      await load();
      if (!editing && result && result.group) {
        members.open(result.group);      // fill the new group right away
      }
    } catch (e) {
      if (e.status === 404) {
        toast(_('The group no longer exists.'), {error: true});
        dialog.close();
        load();
      } else if (e.status === 400 || e.status === 409) {
        error.textContent = e.message;
        error.hidden = false;
      } else {
        toast(e.message, {error: true});
      }
    } finally {
      submit.disabled = false;
    }
  });
  dialog.addEventListener('close', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  nameInput.focus();
}

// ?open=kind:name after the first load: the dialog of that group (a vanished one gets its 404)
function openFromUrl() {
  const key = new URLSearchParams(window.location.search).get('open');
  if (!key) {
    return;
  }
  const group = state.groups.find((g) => g.key === key) || {...parseKey(key), key, members: 0, description: ''};
  members.open(group);
}

function setupControls() {
  for (const th of table.querySelectorAll('th.sortable')) {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortAsc = !state.sortAsc;
      } else {
        state.sortKey = key;
        state.sortAsc = !['members', 'created_at'].includes(key);
      }
      render();
    });
  }
  filterInput.addEventListener('input', () => {
    state.filter = filterInput.value.trim().toLowerCase();
    writeUrl();
    render();
  });
  for (const button of kindButtons) {
    button.addEventListener('click', () => {
      const kind = button.dataset.kind;
      if (state.kinds.has(kind)) {
        state.kinds.delete(kind);
      } else {
        state.kinds.add(kind);
      }
      writeUrl();
      render();
    });
  }
  refreshButton.addEventListener('click', () => load({refresh: true}));
  newButton.addEventListener('click', () => openEditDialog(null));
}

async function main() {
  await i18n.init();
  readUrl();
  setupControls();
  await load();
  openFromUrl();
}

main();
