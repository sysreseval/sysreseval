// The Saved projects page (GET /api/saves): the projects the user saved from their project
// pages (Restore, Share…, Delete; how many they may keep), those the members of their groups
// shared with them (Restore), and, for an instructor, a view of every saved project of the site
// (?all=1: a text filter, the free space of the directory, Restore, Share…, Delete).  A restore
// starts a new project of the user from the save (POST …/restore: the NDJSON stream of a start,
// shown like one, then the page of the new project); the saved project stays as it is.  Share…
// chooses the groups whose members may restore it (their own groups for a student, any group
// for an instructor) and edits its comment.  Nothing is polled: the page reads the list when it
// opens, after each change, and on Refresh.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {ProgressBox, runCreation, projectUrl} from './creation.js';
import {parseKey} from './groups_model.js';
import {isoText} from './group_members.js';
import {fillGroupsSelect} from './exams_form.js';
import {markSort, setupSort} from './table_sort.js';
import {saveUrl} from './save_dialog.js';
import {formatSize, formatSpace, labLabel, groupsLabel, ownerLabel, split, matches, sortSaves,
        quotaLabel} from './saves_model.js';

const isInstructor = document.body.dataset.instructor === 'true';
const notice = document.getElementById('saves-notice');
const quotaElement = document.getElementById('saves-quota');
const refreshButton = document.getElementById('saves-refresh');
const filterInput = document.getElementById('saves-filter');
const instructorMode = document.getElementById('saves-instructor-mode');
const viewButtons = Array.from(document.querySelectorAll('#saves-views button[data-view]'));
const progress = new ProgressBox(document.getElementById('progress'));

// one entry per table of the page: its box, its sort, the columns of a row
const TABLES = {
  mine: {box: 'saves-mine-box', table: 'saves-mine', sort: {key: 'saved_at', asc: false}},
  shared: {box: 'saves-shared-box', table: 'saves-shared', sort: {key: 'saved_at', asc: false}},
  all: {box: 'saves-all-box', table: 'saves-all', sort: {key: 'saved_at', asc: false}},
};
for (const entry of Object.values(TABLES)) {
  entry.box = document.getElementById(entry.box);
  entry.table = document.getElementById(entry.table);
}

// view: 'mine' (the user's saves and those shared with them) or 'all' (an instructor: every save)
const state = {view: 'mine', saves: [], quota: null, myGroups: [], space: {}, stale: false, filter: '',
               busy: false, allGroups: null};

// -- the URL ----------------------------------------------------------------------------------

function readUrl() {
  const params = new URLSearchParams(window.location.search);
  state.view = isInstructor && params.get('view') === 'all' ? 'all' : 'mine';
  state.filter = params.get('q') || '';
  if (filterInput) {
    filterInput.value = state.filter;
  }
}

function writeUrl() {
  const url = new URL(window.location.href);
  url.searchParams.delete('view');
  url.searchParams.delete('q');
  if (state.view === 'all') {
    url.searchParams.set('view', 'all');
    if (state.filter) {
      url.searchParams.set('q', state.filter);
    }
  }
  window.history.replaceState(null, '', url);
}

// -- the rows ---------------------------------------------------------------------------------

function mayChange(save) {
  return save.mine || isInstructor;
}

function actions(save) {
  const restoreButton = el('button', {type: 'button', class: 'primary', disabled: !save.lab_known || state.busy,
                                      title: save.lab_known ? '' : _('The lab of this saved project is not available any more.'),
                                      onclick: () => restore(save)}, _('Restore'));
  const buttons = [restoreButton];
  if (mayChange(save)) {
    buttons.push(el('button', {type: 'button', disabled: state.busy, onclick: () => shareDialog(save)}, _('Share…')));
    buttons.push(el('button', {type: 'button', class: 'danger', disabled: state.busy, onclick: () => remove(save)},
                    _('Delete')));
  }
  return el('td', {class: 'actions'}, ...buttons);
}

function labCell(save) {
  const flags = [];
  if (save.exam) {
    flags.push(_('exam'));
  }
  if (save.instructor_mode) {
    flags.push(_('instructor mode'));
  }
  if (save.debug_project) {
    flags.push(_('debug'));
  }
  return el('td', {title: save.lab}, labLabel(save),
            flags.length ? el('span', {class: 'save-flags'}, ` (${flags.join(', ')})`) : null);
}

const CELLS = {
  lab: labCell,
  comment: (save) => el('td', {class: 'description', title: save.comment || ''}, save.comment || ''),
  owner: (save) => el('td', {title: save.owner}, ownerLabel(save)),
  group: (save) => el('td', {}, save.group || ''),
  saved_at: (save) => el('td', {title: `${save.saved_at} — ${save.host}`}, isoText(save.saved_at)),
  size: (save) => el('td', {class: 'num'}, formatSize(save.size)),
  shared_with: (save) => el('td', {title: (save.shared_with || []).join('\n')}, groupsLabel(save)),
  actions,
};
const COLUMNS = {
  mine: ['lab', 'comment', 'saved_at', 'size', 'shared_with', 'actions'],
  shared: ['lab', 'comment', 'owner', 'saved_at', 'size', 'actions'],
  all: ['owner', 'group', 'lab', 'comment', 'saved_at', 'size', 'shared_with', 'actions'],
};

function fill(name, saves, emptyText) {
  const entry = TABLES[name];
  if (!entry.table) {
    return;
  }
  const body = entry.table.querySelector('tbody');
  clear(body);
  markSort(entry.table, entry.sort);
  const rows = sortSaves(saves, entry.sort);
  if (!rows.length) {
    body.append(el('tr', {}, el('td', {colspan: COLUMNS[name].length, class: 'muted'}, emptyText)));
    return;
  }
  for (const save of rows) {
    body.append(el('tr', {dataset: {id: save.id, owner: save.owner}}, ...COLUMNS[name].map((column) => CELLS[column](save))));
  }
}

function render() {
  for (const button of viewButtons) {
    button.setAttribute('aria-pressed', button.dataset.view === state.view ? 'true' : 'false');
  }
  const everything = state.view === 'all';
  if (filterInput) {
    filterInput.hidden = !everything;
  }
  quotaElement.textContent = quotaLabel(state.quota);
  notice.hidden = !state.stale;
  notice.textContent = state.stale
    ? _('No host with the saved projects answers: this is the list as it was a moment ago.') : '';
  const parts = split(state.saves);
  TABLES.mine.box.hidden = everything;
  TABLES.shared.box.hidden = everything || !parts.shared.length;
  if (TABLES.all.box) {
    TABLES.all.box.hidden = !everything;
  }
  if (everything) {
    const shown = state.saves.filter((save) => matches(save, state.filter));
    document.getElementById('saves-count').textContent = shown.length === state.saves.length
      ? format(_('({n})'), {n: shown.length})
      : format(_('({n} of {total})'), {n: shown.length, total: state.saves.length});
    document.getElementById('saves-space').textContent = state.space.total_mb
      ? format(_('Free space of the saved projects: {free} of {total}'),
               {free: formatSpace(state.space.free_mb), total: formatSpace(state.space.total_mb)})
      : '';
    fill('all', shown, state.saves.length ? _('No saved project matches the filter.') : _('No saved project.'));
    return;
  }
  fill('mine', parts.mine, _('You have no saved project.'));
  fill('shared', parts.shared, '');
}

// -- loading ----------------------------------------------------------------------------------

async function load({refresh = false} = {}) {
  const query = {};
  if (state.view === 'all') {
    query.all = '1';
  }
  if (refresh) {
    query.refresh = '1';
  }
  let data;
  try {
    data = await api.get(api.withQuery('/api/saves', query));
  } catch (e) {
    notice.hidden = false;
    notice.textContent = e.message;
    for (const name of Object.keys(TABLES)) {
      fill(name, [], '');
    }
    return;
  }
  state.saves = data.saves || [];
  state.quota = data.quota || null;
  state.myGroups = data.my_groups || [];
  state.space = {free_mb: data.free_mb, total_mb: data.total_mb};
  state.stale = Boolean(data.stale);
  render();
}

function setBusy(busy) {
  state.busy = busy;
  refreshButton.disabled = busy;
  render();
}

// -- restore ----------------------------------------------------------------------------------

async function restore(save) {
  const body = {};
  if (instructorMode && instructorMode.checked) {
    body.instructor_mode = true;
  }
  setBusy(true);
  const result = await runCreation(progress, format(_('Restoring {lab}…'), {lab: labLabel(save)}), 'POST',
                                   `${saveUrl(save)}/restore`, {json: body});
  if (result.status === 'created') {
    window.location.href = projectUrl(result.host, result.running_lab_name);
    return;
  }
  setBusy(false);
  progress.showError(result.message || _('The restore failed.'),
                     {onRetry: () => restore(save), retryAfter: result.retry_after || 0});
  if (result.http_status === 404 || result.http_status === 403) {
    await load({refresh: true});       // the save is gone, or not shared any more
  }
}

// -- delete -----------------------------------------------------------------------------------

async function remove(save) {
  const what = save.comment ? `${labLabel(save)} — ${save.comment}` : labLabel(save);
  if (!window.confirm(format(_('Delete the saved project "{name}" of {date}? It cannot be restored afterwards.'),
                             {name: what, date: isoText(save.saved_at)}))) {
    return;
  }
  try {
    await api.del(saveUrl(save));
  } catch (e) {
    toast(e.message, {error: true});
  }
  await load();
}

// -- share ------------------------------------------------------------------------------------

// the groups the dialog offers: every group for an instructor (GET /api/groups, read once), the
// user's own for a student; a group the save is already shared with stays in the list (it may
// have been added by an instructor, or the user left it)
async function groupChoices(save) {
  let groups;
  if (isInstructor) {
    if (state.allGroups === null) {
      try {
        state.allGroups = (await api.get('/api/groups')).groups || [];
      } catch (e) {
        state.allGroups = [];
        toast(e.message, {error: true});
      }
    }
    groups = state.allGroups.slice();
  } else {
    groups = state.myGroups.slice();
  }
  const known = new Set(groups.map((group) => group.key));
  for (const key of save.shared_with || []) {
    if (!known.has(key)) {
      groups.push({key, ...parseKey(key)});
    }
  }
  return groups;
}

async function shareDialog(save) {
  const groups = await groupChoices(save);
  const select = el('select', {multiple: true, size: String(Math.min(12, Math.max(4, groups.length + 3)))});
  fillGroupsSelect(select, groups, save.shared_with || []);
  const comment = el('input', {type: 'text', maxlength: '100', value: save.comment || ''});
  const error = el('p', {class: 'form-error'});
  error.hidden = true;
  const cancel = el('button', {type: 'button'}, _('Cancel'));
  const none = el('button', {type: 'button'}, _('Share with nobody'));
  const submit = el('button', {type: 'submit', class: 'primary'}, _('Save'));
  const form = el('form', {},
    el('label', {}, _('Comment'), comment),
    el('label', {}, _('Groups whose members may restore this saved project'), select),
    el('p', {class: 'muted'}, groups.length
      ? _('A member who restores it gets a project of their own with your answers and the state of your machines. Hold Ctrl (or Cmd) to choose several groups.')
      : _('You belong to no group to share with.')),
    error,
    el('div', {class: 'buttons'}, none, el('span', {class: 'spacer'}), cancel, submit));
  const dialog = el('dialog', {class: 'modal save-share'},
                    el('h2', {}, format(_('Share {lab}'), {lab: labLabel(save)})), form);
  cancel.addEventListener('click', () => dialog.close());
  none.addEventListener('click', () => {
    for (const option of select.options) {
      option.selected = false;
    }
  });
  dialog.addEventListener('close', () => dialog.remove());
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    submit.disabled = true;
    const changes = {shared_with: Array.from(select.selectedOptions).map((option) => option.value)};
    if (comment.value.trim() !== (save.comment || '')) {
      changes.comment = comment.value.trim();
    }
    try {
      await api.put(saveUrl(save), changes);
    } catch (e) {
      error.textContent = e.message;
      error.hidden = false;
      submit.disabled = false;
      return;
    }
    dialog.close();
    await load();
  });
  document.body.append(dialog);
  dialog.showModal();
}

// -- the page ---------------------------------------------------------------------------------

async function main() {
  await i18n.init();
  readUrl();
  for (const entry of Object.values(TABLES)) {
    if (entry.table) {
      // the times and the sizes: the newest and the largest first
      setupSort(entry.table, entry.sort, {ascFirst: (key) => key !== 'saved_at' && key !== 'size', onChange: render});
    }
  }
  for (const button of viewButtons) {
    button.addEventListener('click', async () => {
      state.view = button.dataset.view;
      writeUrl();
      await load();
    });
  }
  if (filterInput) {
    filterInput.addEventListener('input', () => {
      state.filter = filterInput.value.trim();
      writeUrl();
      render();
    });
  }
  refreshButton.addEventListener('click', () => load({refresh: true}));
  await load();
}

main();
