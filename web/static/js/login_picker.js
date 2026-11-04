// A picker of logins: a text input with the suggestions of the directory (GET
// /api/groups/people?q=, shown in a <datalist>), the logins typed or picked kept as chips until
// the caller takes them (the Add row of the members dialog of a custom group, the audience of
// an exam).  Several logins may be typed at once (spaces, commas); a login the server did not
// know can be marked (markUnknown).  The caller lays the nodes out (input, datalist, chips, the
// hint saying more people match) and reads logins() when it posts.

import * as api from './api.js';
import {el, clear} from './ui.js';
import {_} from './i18n.js';

const SUGGEST_DELAY = 200;      // ms after the last keystroke before the directory is asked

// datalistId: the id of the <datalist> (unique in the page); placeholder: the input's;
// onChange(): the set of chips changed (the caller enables its button)
export function createLoginPicker({datalistId = 'login-people', placeholder = '', onChange = () => {}} = {}) {
  const input = el('input', {type: 'text', class: 'group-login', list: datalistId, autocomplete: 'off',
                             placeholder: placeholder || _('Login or name…')});
  const datalist = el('datalist', {id: datalistId});
  const chips = el('span', {class: 'chips'});
  const more = el('span', {class: 'muted more'});
  const pending = new Map();      // login -> its chip
  let suggested = new Map();      // login -> the person suggested
  let timer = null;

  function addChip(login) {
    login = login.trim();
    if (!login || pending.has(login)) {
      return;
    }
    const chip = el('span', {class: 'chip'}, login,
      el('button', {type: 'button', title: _('Remove'), onclick: () => {
        chip.remove();
        pending.delete(login);
        onChange();
      }}, '×'));
    pending.set(login, chip);
    chips.append(chip);
    onChange();
  }

  // what is typed becomes chips (several logins at once: spaces, commas)
  function take() {
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

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ',') {
      event.preventDefault();
      take();
    }
  });
  input.addEventListener('change', () => {
    if (suggested.has(input.value.trim())) {
      take();      // a suggestion picked
    }
  });
  input.addEventListener('blur', take);
  input.addEventListener('input', () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(suggest, SUGGEST_DELAY);
  });

  return {
    input, datalist, chips, more,
    nodes: [input, datalist, chips, more],
    take,
    logins: () => [...pending.keys()],
    size: () => pending.size,
    // the chips replaced by these logins (the edit form of an exam)
    set(logins) {
      for (const chip of pending.values()) {
        chip.remove();
      }
      pending.clear();
      for (const login of logins || []) {
        addChip(String(login));
      }
      onChange();
    },
    clear() {
      this.set([]);
    },
    markUnknown(logins) {
      for (const login of logins || []) {
        const chip = pending.get(login);
        if (chip) {
          chip.classList.add('unknown');
        }
      }
    },
  };
}
