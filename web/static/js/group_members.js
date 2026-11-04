// The members dialog of the Groups page: the members of one group (GET /api/groups/{kind}/{name}:
// login, name, department; who added a member of a custom group and when), a text filter, and
// for a custom group when the database is configured the Add row (a login input with the
// suggestions of the directory, GET /api/groups/people?q=, the logins typed or picked kept as
// chips until Add posts them; a select adding every member of another group) and a Remove
// button per member.  Every write reloads the dialog and tells the page (onChanged).

import * as api from './api.js';
import {el, clear, toast} from './ui.js';
import {_, format} from './i18n.js';
import {KINDS, KIND_CUSTOM, kindLabel, kindsLabel, sortGroups} from './groups_model.js';

const SUGGEST_DELAY = 200;      // ms after the last keystroke before the directory is asked

export function customUrl(name, suffix = '') {
  return `/api/groups/custom/${encodeURIComponent(name)}${suffix}`;
}

export function groupUrl(group) {
  return `/api/groups/${encodeURIComponent(group.kind)}/${encodeURIComponent(group.name)}`;
}

// an ISO time of the API as the browser shows it ('' when missing)
export function isoText(iso) {
  if (!iso) {
    return '';
  }
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? String(iso) : date.toLocaleString();
}

export function createMembersDialog({canEdit = false, getGroups = () => [], onChanged = () => {}, onOpened = () => {},
                                     onClosed = () => {}} = {}) {
  let current = null;      // the open dialog: {group, editable, dialog, caption, filter, table, addRow, members}

  // the groups of the page changed: the select of the Add row follows
  function update() {
    if (current && current.addRow) {
      fillSources();
    }
  }

  function open(group) {
    if (current) {
      current.dialog.close();
    }
    const editable = canEdit && group.kind === KIND_CUSTOM;
    const caption = el('p', {class: 'muted caption'}, _('Loading…'));
    const filter = el('input', {type: 'text', class: 'watch-filter', placeholder: _('Filter…')});
    const table = el('table', {class: 'grid members'});
    const close = el('button', {type: 'button'}, _('Close'));
    const addRow = editable ? buildAddRow() : null;
    const dialog = el('dialog', {class: 'modal group-members'},
      el('h2', {}, el('span', {class: `kind kind-${group.kind}`}, kindLabel(group.kind)), ' ', group.name),
      caption,
      el('div', {class: 'members-toolbar'}, filter),
      addRow ? addRow.element : null,
      table,
      el('div', {class: 'buttons'}, el('span', {class: 'spacer'}), close));
    close.addEventListener('click', () => dialog.close());
    filter.addEventListener('input', renderMembers);
    dialog.addEventListener('close', () => {
      dialog.remove();
      if (current && current.dialog === dialog) {
        current = null;
        onClosed();
      }
    });
    current = {group, editable, dialog, caption, filter, table, addRow, members: []};
    document.body.append(dialog);
    dialog.showModal();
    onOpened(group.key);
    if (addRow) {
      fillSources();
    }
    load();
  }

  async function load() {
    const c = current;
    if (!c) {
      return;
    }
    let data;
    try {
      data = await api.get(groupUrl(c.group));
    } catch (e) {
      if (c !== current) {
        return;
      }
      if (e.status === 404) {
        toast(_('The group no longer exists.'), {error: true});
        c.dialog.close();
        onChanged();
        return;
      }
      c.caption.textContent = format(_('Error: {error}'), {error: e.message});
      return;
    }
    if (c !== current) {
      return;      // closed meanwhile
    }
    c.group = data.group || c.group;
    c.members = Array.isArray(data.members) ? data.members : [];
    renderCaption();
    renderMembers();
  }

  function renderCaption() {
    const c = current;
    const g = c.group;
    const parts = [];
    if (g.description) {
      parts.push(g.description);
    }
    parts.push(format(_('{n} member(s)'), {n: c.members.length}));
    if (g.kind === KIND_CUSTOM && g.created_by) {
      parts.push(format(_('created by {login} on {date}'), {login: g.created_by, date: isoText(g.created_at)}));
    }
    c.caption.textContent = parts.join(' · ');
  }

  function renderMembers() {
    const c = current;
    if (!c) {
      return;
    }
    clear(c.table);
    const custom = c.group.kind === KIND_CUSTOM;
    c.table.append(el('thead', {}, el('tr', {},
      el('th', {}, _('Login')), el('th', {}, _('Name')), el('th', {}, _('Department')),
      el('th', {hidden: !custom}, _('Added by')), el('th', {hidden: !custom}, _('Added')),
      el('th', {hidden: !c.editable}, ''))));
    const text = c.filter.value.trim().toLowerCase();
    const shown = c.members.filter((m) => !text || [m.login, m.fullname, m.group].some((v) => (v || '').toLowerCase().includes(text)));
    const tbody = el('tbody');
    if (!shown.length) {
      tbody.append(el('tr', {}, el('td', {colspan: 6, class: 'muted'},
                                   c.members.length ? _('No member matches the filter.') : _('No member.'))));
    }
    for (const m of shown) {
      const remove = c.editable
        ? el('button', {type: 'button', class: 'danger', onclick: () => removeMember(m.login)}, _('Remove')) : null;
      tbody.append(el('tr', {},
        el('td', {}, m.login), el('td', {}, m.fullname || ''), el('td', {}, m.group || ''),
        el('td', {hidden: !custom}, m.added_by || ''),
        el('td', {hidden: !custom, title: m.added_at || ''}, isoText(m.added_at)),
        el('td', {hidden: !c.editable, class: 'actions'}, remove)));
    }
    c.table.append(tbody);
  }

  async function removeMember(login) {
    const c = current;
    if (!c) {
      return;
    }
    try {
      await api.del(customUrl(c.group.name, `/members/${encodeURIComponent(login)}`));
    } catch (e) {
      if (e.status !== 404) {
        toast(e.message, {error: true});
        return;
      }
    }
    await load();
    onChanged();
  }

  // the Add row of a custom group: a login input with the suggestions of the directory, the
  // chips of the logins to add, the Add button, the select copying the members of another group
  function buildAddRow() {
    const input = el('input', {type: 'text', class: 'group-login', list: 'group-people', autocomplete: 'off',
                               placeholder: _('Login or name…')});
    const datalist = el('datalist', {id: 'group-people'});
    const chips = el('span', {class: 'chips'});
    const more = el('span', {class: 'muted more'});
    const add = el('button', {type: 'button', class: 'primary'}, _('Add'));
    const from = el('select', {class: 'group-from'});
    const element = el('div', {class: 'group-add'}, input, datalist, chips, add, from, more);
    const pending = new Map();      // login -> its chip
    let suggested = new Map();      // login -> the person suggested
    let timer = null;
    add.disabled = true;

    function addChip(login) {
      login = login.trim();
      if (!login || pending.has(login)) {
        return;
      }
      const chip = el('span', {class: 'chip'}, login,
        el('button', {type: 'button', title: _('Remove'), onclick: () => {
          chip.remove();
          pending.delete(login);
          add.disabled = pending.size === 0;
        }}, '×'));
      pending.set(login, chip);
      chips.append(chip);
      add.disabled = false;
    }

    // what is typed becomes chips (several logins at once: spaces, commas)
    function takeInput() {
      for (const part of input.value.split(/[\s,;]+/)) {
        addChip(part);
      }
      input.value = '';
    }

    async function suggest() {
      const q = input.value.trim();
      if (!q) {
        clear(datalist);
        more.textContent = '';
        return;
      }
      let data;
      try {
        data = await api.get(api.withQuery('/api/groups/people', {q}));
      } catch (e) {
        return;
      }
      if (input.value.trim() !== q) {
        return;
      }
      clear(datalist);
      suggested = new Map();
      for (const p of data.people || []) {
        suggested.set(p.login, p);
        datalist.append(el('option', {value: p.login}, [p.fullname, p.group].filter(Boolean).join(' · ')));
      }
      more.textContent = data.more ? _('More people match: type more of the name') : '';
    }

    async function post(body) {
      const c = current;
      if (!c) {
        return;
      }
      add.disabled = true;
      try {
        const result = await api.post(customUrl(c.group.name, '/members'), body);
        for (const chip of pending.values()) {
          chip.remove();
        }
        pending.clear();
        toast(format(_('{n} member(s) added'), {n: result.added}));
      } catch (e) {
        if (e.status === 400 && e.data && Array.isArray(e.data.unknown) && e.data.unknown.length) {
          toast(format(_('Unknown logins: {logins}'), {logins: e.data.unknown.join(', ')}), {error: true});
          for (const login of e.data.unknown) {
            const chip = pending.get(login);
            if (chip) {
              chip.classList.add('unknown');
            }
          }
        } else if (e.status === 404) {
          toast(_('The group no longer exists.'), {error: true});
          c.dialog.close();
          onChanged();
          return;
        } else {
          toast(e.message, {error: true});
        }
      } finally {
        add.disabled = pending.size === 0;
      }
      await load();
      onChanged();
    }

    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ',') {
        event.preventDefault();
        takeInput();
      }
    });
    input.addEventListener('change', () => {
      if (suggested.has(input.value.trim())) {
        takeInput();      // a suggestion picked
      }
    });
    input.addEventListener('blur', takeInput);
    input.addEventListener('input', () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(suggest, SUGGEST_DELAY);
    });
    add.addEventListener('click', async () => {
      takeInput();
      if (pending.size) {
        await post({logins: [...pending.keys()]});
      }
    });
    from.addEventListener('change', async () => {
      const key = from.value;
      from.value = '';
      if (key) {
        await post({from: key});
      }
    });
    return {element, from};
  }

  // the select of the Add row: the other groups of the page, by kind, with their sizes
  function fillSources() {
    const c = current;
    if (!c || !c.addRow) {
      return;
    }
    const select = c.addRow.from;
    clear(select);
    select.append(el('option', {value: ''}, _('Add the members of…')));
    const groups = getGroups() || [];
    for (const kind of KINDS) {
      const ofKind = sortGroups(groups.filter((g) => g.kind === kind && g.key !== c.group.key), {key: 'name'});
      if (!ofKind.length) {
        continue;
      }
      const optgroup = el('optgroup', {label: kindsLabel(kind)});
      for (const g of ofKind) {
        optgroup.append(el('option', {value: g.key}, `${g.name} (${g.members})`));
      }
      select.append(optgroup);
    }
  }

  return {open, update};
}
