// The audience dialog of the presentations (present.js) and of the web conferences
// (webconf_dialog.js): the connected users (GET /api/presence, refreshed while the dialog is
// open), a text filter, the groups by kind (those of GET /api/groups: the departments, the
// directory groups, the custom groups, plus those of the connected users; a checked group takes
// its connected members and those connecting later, keyed as groups_model.js does), the users
// one by one; resolves to {logins, groups} or null (cancelled).

import * as api from './api.js';
import {el, clear} from './ui.js';
import {_, format} from './i18n.js';
import {KINDS, parseKey, normalizeKey, rowGroupKeys, sortGroups, kindsLabel} from './groups_model.js';

const PRESENCE_REFRESH = 5000;    // ms between two refreshes of the connected users while the dialog is open

// logins / groups: the audience checked at the opening; mode: 'start' or 'edit' (the OK label,
// unless okLabel is given); groupSources: whether any source of user groups is configured (the
// groups are offered); title: the heading (the presentations' by default); allowEmpty: whether
// an audience of nobody may be chosen (a conference room of the instructors alone).
export function openAudienceDialog({logins: checkedLogins, groups: checkedGroups, mode, groupSources = false,
                                    title = null, okLabel = null, allowEmpty = false}) {
  return new Promise((resolve) => {
    const logins = new Set(checkedLogins || []);
    const groupSet = new Set((checkedGroups || []).map(normalizeKey));   // a bare name: a department
    let rows = [];
    let result = null;
    let catalog = null;       // the groups of GET /api/groups, read once per opening
    const filter = el('input', {type: 'text', class: 'present-filter', placeholder: _('Filter…')});
    const groupBox = el('div', {class: 'present-groups'});
    groupBox.hidden = !groupSources;
    const list = el('ul', {class: 'present-list'});
    const count = el('p', {class: 'present-count muted'});
    const selectAll = el('button', {type: 'button'}, _('Select all'));
    const none = el('button', {type: 'button'}, _('None'));
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const ok = el('button', {type: 'button', class: 'primary'}, okLabel || (mode === 'edit' ? _('Apply') : _('Start')));
    const dialog = el('dialog', {class: 'modal present'},
      el('h2', {}, title || _('Present to…')),
      el('div', {class: 'present-toolbar'}, filter),
      groupBox, list, count,
      el('div', {class: 'buttons'}, selectAll, none, el('span', {class: 'spacer'}), cancel, ok));

    const matches = (row) => {
      const text = filter.value.trim().toLowerCase();
      const names = [...rowGroupKeys(row)].map((key) => parseKey(key).name);
      return !text || [row.login, row.fullname, row.group, ...names].some((v) => (v || '').toLowerCase().includes(text));
    };
    const viaGroup = (row) => [...rowGroupKeys(row)].some((key) => groupSet.has(key));

    function updateCount() {
      const selected = new Set(logins);
      for (const row of rows) {
        if (viaGroup(row)) {
          selected.add(row.login);
        }
      }
      count.textContent = format(_('{n} selected'), {n: selected.size});
      ok.disabled = !allowEmpty && selected.size === 0 && groupSet.size === 0;
    }

    function renderGroups() {
      clear(groupBox);
      const connected = new Map();      // key -> connected members
      for (const row of rows) {
        for (const key of rowGroupKeys(row)) {
          connected.set(key, (connected.get(key) || 0) + 1);
        }
      }
      const entries = new Map();
      for (const group of catalog || []) {
        entries.set(group.key, group);
      }
      for (const key of [...connected.keys(), ...groupSet]) {
        if (!entries.has(key)) {
          entries.set(key, {key, ...parseKey(key), members: null});
        }
      }
      const sorted = sortGroups([...entries.values()], {key: 'kind'});
      for (const kind of KINDS) {
        const ofKind = sorted.filter((group) => group.kind === kind);
        if (!ofKind.length) {
          continue;
        }
        const section = el('div', {class: 'present-kind'}, el('span', {class: `kind kind-${kind}`}, kindsLabel(kind)));
        for (const group of ofKind) {
          const box = el('input', {type: 'checkbox'});
          box.checked = groupSet.has(group.key);
          box.addEventListener('change', () => {
            if (box.checked) {
              groupSet.add(group.key);
            } else {
              groupSet.delete(group.key);
            }
            renderList();
            updateCount();
          });
          const n = connected.get(group.key) || 0;
          const label = group.members === null || group.members === undefined
            ? format(_('{group} ({n} connected)'), {group: group.name, n})
            : format(_('{group} ({n} connected, {m} members)'), {group: group.name, n, m: group.members});
          section.append(el('label', {}, box, label));
        }
        groupBox.append(section);
      }
    }

    async function loadCatalog() {
      try {
        const data = await api.get('/api/groups');
        catalog = Array.isArray(data.groups) ? data.groups : [];
      } catch (e) {
        catalog = [];
      }
      renderGroups();
    }

    function renderList() {
      clear(list);
      const shown = rows.filter(matches);
      if (!rows.length) {
        list.append(el('li', {class: 'empty'}, _('No user is connected.')));
      } else if (!shown.length) {
        list.append(el('li', {class: 'empty'}, _('No user matches the filter.')));
      }
      for (const row of shown) {
        const box = el('input', {type: 'checkbox', value: row.login});
        const inGroup = viaGroup(row);
        box.checked = inGroup || logins.has(row.login);
        box.disabled = inGroup;
        box.addEventListener('change', () => {
          if (box.checked) {
            logins.add(row.login);
          } else {
            logins.delete(row.login);
          }
          updateCount();
        });
        const label = el('label', {title: inGroup ? _('via group') : undefined}, box,
          el('span', {class: 'name'}, row.fullname || row.login),
          row.fullname ? el('span', {class: 'login muted'}, row.login) : null,
          row.group ? el('span', {class: 'muted'}, row.group) : null,
          row.role === 'instructor' ? el('span', {class: 'badge'}, _('instructor')) : null,
          row.presentation ? el('span', {class: 'busy'}, _('in a presentation')) : null,
          row.webconf ? el('span', {class: 'busy'}, _('in a conference')) : null);
        list.append(el('li', {}, label));
      }
    }

    async function refresh() {
      try {
        rows = await api.get('/api/presence');
      } catch (e) {
        clear(list);
        list.append(el('li', {class: 'error'}, e.message));
        return;
      }
      rows = Array.isArray(rows) ? rows : [];
      rows.sort((a, b) => (a.fullname || a.login).localeCompare(b.fullname || b.login));
      renderGroups();
      renderList();
      updateCount();
    }

    filter.addEventListener('input', renderList);
    selectAll.addEventListener('click', () => {
      for (const row of rows.filter(matches)) {
        logins.add(row.login);
      }
      renderList();
      updateCount();
    });
    none.addEventListener('click', () => {
      logins.clear();
      groupSet.clear();
      renderGroups();
      renderList();
      updateCount();
    });
    ok.addEventListener('click', () => {
      result = {logins: [...logins].sort(), groups: [...groupSet].sort()};
      dialog.close();
    });
    cancel.addEventListener('click', () => dialog.close());
    const interval = window.setInterval(refresh, PRESENCE_REFRESH);
    dialog.addEventListener('close', () => {
      window.clearInterval(interval);
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
    updateCount();
    refresh();
    if (groupSources) {
      loadCatalog();
    }
  });
}
