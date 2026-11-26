// The sharing of the projects on the Watch page of the instructors.
//  - createSharingDialog(): the dialog of the Sharing cell of a row — whether the owner may share
//    the project (the decision of the instructors for this project: allowed, forbidden, or the
//    default of the site: POST /api/watch/sharing), and while it is shared: with whom, the
//    students in it (those on the project now marked), Remove for each of them
//    (DELETE {project}/sharing/participants/{login}) and Stop sharing (DELETE {project}/sharing).
//    The state is GET {project}/sharing, asked again every REFRESH_INTERVAL while the dialog is
//    open; update(rows) says so when the project closed.
//  - confirmClose(rows): the confirmation of the bulk close, listing the projects (a <dialog>,
//    Cancel focused), resolving true or false.
// The selection bar and the column itself are in watch.js; the texts of a sharing in
// sharing_model.js.

import * as api from './api.js';
import {el, clear, toast} from './ui.js';
import {_, format} from './i18n.js';
import {personName, usersOf, audienceText, POLICY_ALLOWED, POLICY_FORBIDDEN, POLICY_DEFAULT} from './sharing_model.js';

const REFRESH_INTERVAL = 5000;

function sharingApi(row) {
  return `/api/projects/${encodeURIComponent(row.host)}/${encodeURIComponent(row.running_lab_name)}/sharing`;
}

// title(row): the lab of a row; onChanged(): something was changed (the page refreshes its rows)
export function createSharingDialog({title, onChanged = () => {}}) {
  let current = null;      // the open dialog: {row, dialog, body, timer, state, closed}

  function heading(row) {
    return `${row.fullname || row.owner || ''}${row.fullname ? ` (${row.owner})` : ''} — ${title(row)} — ${row.host || ''}`;
  }

  async function change(send) {
    const c = current;
    if (!c || c.busy) {
      return;
    }
    c.busy = true;
    try {
      await send();
    } catch (e) {
      toast(e.message, {error: true});
    }
    c.busy = false;
    c.signature = '';        // drawn again whatever comes back: a refused change leaves no radio as the user set it
    onChanged();
    load();
  }

  function policyChoice(c, value, label, hint) {
    const radio = el('input', {type: 'radio', name: 'share-policy', value});
    radio.checked = c.state.policy === value;
    radio.addEventListener('change', () => {
      if (radio.checked) {
        change(() => api.post('/api/watch/sharing', {
          projects: [{host: c.row.host, rln: c.row.running_lab_name}], policy: value}));
      }
    });
    return el('label', {}, radio, ' ', label, hint ? el('span', {class: 'muted'}, ` ${hint}`) : null);
  }

  function render(c) {
    if (c.busy) {
      return;            // drawn again when the change is answered
    }
    const state = c.state;
    // drawn again only when what it shows changed (a poll that brings nothing new leaves the
    // radios and the focus alone)
    const signature = JSON.stringify(state);
    if (signature === c.signature) {
      return;
    }
    c.signature = signature;
    clear(c.body);
    if (!state.available && !state.shared) {
      c.body.append(el('p', {class: 'muted'}, _('This project cannot be shared.')));
      return;
    }
    // the default of the site, as it reads for this project
    const byDefault = state.policy === POLICY_DEFAULT ? state.allowed : null;
    c.body.append(el('fieldset', {class: 'share-policy', id: 'share-policy'},
      el('legend', {}, _('May its owner share it?')),
      policyChoice(c, POLICY_DEFAULT, _('Default of the site'),
                   byDefault === null ? '' : (byDefault ? _('(allowed)') : _('(not allowed)'))),
      policyChoice(c, POLICY_ALLOWED, _('Allowed')),
      policyChoice(c, POLICY_FORBIDDEN, _('Forbidden'), _('(ends the sharing in progress)'))));
    if (!state.shared) {
      c.body.append(el('p', {class: 'muted', id: 'share-state'}, _('This project is not shared.')));
      return;
    }
    const url = sharingApi(c.row);
    c.body.append(
      el('p', {id: 'share-state'}, format(_('Shared with {audience}.'), {audience: audienceText(state.audience)})),
      el('ul', {class: 'share-users', id: 'share-users'}, ...usersOf(state).map((user) => {
        const item = el('li', {dataset: {login: user.login}, class: user.connected ? 'connected' : 'away'},
          el('span', {class: 'dot', title: user.connected ? _('On the project now') : _('Not on the project now')}),
          el('span', {class: 'name'}, personName(user)));
        if (user.owner) {
          item.append(el('span', {class: 'muted'}, _('owner')));
        } else {
          item.append(el('button', {type: 'button', title: _('Take this participant out of the project'),
                                    onclick: () => change(() => api.del(`${url}/participants/${encodeURIComponent(user.login)}`))},
                         _('Remove')));
        }
        return item;
      })),
      el('div', {class: 'share-controls'},
         el('button', {type: 'button', class: 'danger', id: 'share-stop',
                       title: _('The participants are sent back to their own projects'),
                       onclick: () => change(() => api.del(url))}, _('Stop sharing'))));
  }

  async function load() {
    const c = current;
    if (!c || c.closed) {
      return;
    }
    let state;
    try {
      state = await api.get(sharingApi(c.row));
    } catch (e) {
      if (c === current) {
        clear(c.body);
        c.body.append(el('p', {class: 'error'}, e.message));
      }
      return;
    }
    if (c === current && !c.closed) {
      c.state = state;
      render(c);
    }
  }

  function open(row) {
    if (current) {
      current.dialog.close();
    }
    const body = el('div', {class: 'share-body'}, el('p', {class: 'muted'}, _('Loading…')));
    const close = el('button', {type: 'button'}, _('Close'));
    const dialog = el('dialog', {class: 'modal share-dialog watch-sharing'},
      el('h2', {}, _('Sharing of the project')), el('p', {class: 'muted'}, heading(row)), body,
      el('div', {class: 'buttons'}, close));
    close.addEventListener('click', () => dialog.close());
    const opened = {row, dialog, body, timer: 0, state: null, closed: false, busy: false, signature: ''};
    dialog.addEventListener('close', () => {
      window.clearInterval(opened.timer);
      dialog.remove();
      if (current === opened) {
        current = null;
      }
    });
    current = opened;
    document.body.append(dialog);
    dialog.showModal();
    opened.timer = window.setInterval(load, REFRESH_INTERVAL);
    load();
  }

  return {
    open,
    // the rows of a poll: the project of the open dialog closed meanwhile
    update(rows) {
      const c = current;
      if (!c || c.closed) {
        return;
      }
      const there = rows.some((row) => row.host === c.row.host && row.running_lab_name === c.row.running_lab_name);
      if (!there) {
        c.closed = true;
        window.clearInterval(c.timer);
        clear(c.body);
        c.body.append(el('p', {class: 'muted'}, _('The project is closed.')));
      }
    },
  };
}

// The confirmation of the bulk close of *rows* (title(row): the lab): a Promise of true (Close)
// or false (Cancel, Escape).
export function confirmClose(rows, {title}) {
  return new Promise((resolve) => {
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const confirm = el('button', {type: 'button', class: 'danger', id: 'watch-close-confirm'},
                       format(_('Close {n} project(s)'), {n: rows.length}));
    const dialog = el('dialog', {class: 'modal watch-close'},
      el('h2', {}, _('Close projects')),
      el('p', {}, _('Their machines will be stopped, after the last evaluation of the labs that ask for one:')),
      el('ul', {id: 'watch-close-list'}, ...rows.map((row) => el('li', {dataset: {rln: row.running_lab_name}},
        `${row.fullname || row.owner || ''} — ${title(row)} (${row.host || ''})`))),
      el('div', {class: 'buttons'}, cancel, confirm));
    let answer = false;
    cancel.addEventListener('click', () => dialog.close());
    confirm.addEventListener('click', () => {
      answer = true;
      dialog.close();
    });
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(answer);
    });
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}
