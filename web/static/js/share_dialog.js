// The Share button of the project page and its dialog (the shared projects: the owner of a
// running project lets other students work in it).  The button counts the users on the project
// now ("Shared · 2", the instructors never counted); the dialog lists them and, by role:
//  - the owner chooses whom the project is shared with (everybody, or one group of theirs:
//    PUT {api_base}/sharing), answers the students asking to join (POST …/requests/{id}/accept
//    or /decline), takes a participant out (DELETE …/participants/{login}) and stops the
//    sharing (DELETE {api_base}/sharing); while an instructor has not allowed the sharing of the
//    project (or has forbidden it) the dialog says so;
//  - a participant sees who is there and may leave;
//  - an instructor helping on a shared project may take somebody out or stop the sharing.
// The state is GET {api_base}/sharing, asked again every 5 s while the page is open and at once
// on the `sre-share` event of the document (sharing.js: a request came, or ended).

import * as api from './api.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {KINDS, kindsLabel, sortGroups} from './groups_model.js';
import {AUDIENCE_ALL, personName, usersOf, shareLabel, shareButtonShown, audienceText} from './sharing_model.js';

export const WS_SHARE_ENDED = 4413;      // the close code of a participant's sockets when the sharing ends for them
const REFRESH_INTERVAL = 5000;

export function createSharing({apiBase, button, isOwner, participant, isInstructor, onEnded, onLeft}) {
  const url = `${apiBase}/sharing`;
  const login = document.body.dataset.login || '';
  let state = null;          // the last answer of the portal
  let timer = null;
  let dialog = null;         // {element, body} while open
  let busy = false;          // a change is being sent
  let stopped = false;

  function renderButton() {
    button.hidden = !shareButtonShown(state, {isOwner, participant});
    button.textContent = shareLabel(state);
    button.setAttribute('aria-pressed', state && state.shared ? 'true' : 'false');
    const waiting = state && state.requests ? state.requests.length : 0;
    button.classList.toggle('attention', waiting > 0);
    button.dataset.requests = String(waiting);
  }

  async function refresh() {
    if (stopped) {
      return;
    }
    let view;
    try {
      view = await api.get(url);
    } catch (e) {
      if (participant && (e.status === 403 || e.status === 404)) {
        onEnded();           // no longer in: the page ends
      }
      return;
    }
    if (stopped) {
      return;
    }
    state = view;
    renderButton();
    renderDialog();
  }

  // one change sent to the portal; its answer is the new state
  async function change(send, {closes = false} = {}) {
    if (busy) {
      return;
    }
    busy = true;
    try {
      const view = await send();
      if (view && typeof view === 'object' && 'shared' in view) {
        state = view;
      }
    } catch (e) {
      toast(e.message, {error: true});
    } finally {
      busy = false;
    }
    renderButton();
    if (dialog) {
      dialog.signature = '';       // drawn again whatever came back: a refused change leaves no control as the user set it
    }
    if (closes && dialog) {
      dialog.element.close();
    } else {
      renderDialog();
    }
    refresh();
  }

  // -- the dialog ------------------------------------------------------------------------------

  function audienceSelect() {
    const select = el('select', {id: 'share-audience'});
    select.append(el('option', {value: AUDIENCE_ALL}, _('Everybody')));
    const groups = (state.audiences || []).filter((a) => a.kind !== AUDIENCE_ALL);
    for (const kind of KINDS) {
      const ofKind = sortGroups(groups.filter((g) => g.kind === kind), {key: 'name'});
      if (!ofKind.length) {
        continue;
      }
      const optgroup = el('optgroup', {label: kindsLabel(kind)});
      for (const group of ofKind) {
        optgroup.append(el('option', {value: group.key}, group.name));
      }
      select.append(optgroup);
    }
    const current = state.shared && state.audience ? state.audience.key : AUDIENCE_ALL;
    if (!select.querySelector(`option[value="${CSS.escape(current)}"]`)) {
      select.append(el('option', {value: current}, audienceText(state.audience)));    // a group they left since
    }
    select.value = current;
    return select;
  }

  function ownerControls() {
    if (!state.shared && !state.allowed) {
      return el('p', {class: 'share-denied', id: 'share-denied'},
                state.policy === 'forbidden'
                  ? _('An instructor has forbidden the sharing of this project.')
                  : _('An instructor must allow the sharing of this project first.'));
    }
    const select = audienceSelect();
    const row = el('div', {class: 'share-controls'}, el('label', {for: 'share-audience'}, _('Share with')), select);
    if (state.shared) {
      // a new choice is a new audience at once: those already in stay
      select.addEventListener('change', () => change(() => api.put(url, {audience: select.value})));
      row.append(el('button', {type: 'button', class: 'danger', id: 'share-stop',
                               title: _('The participants are sent back to their own projects'),
                               onclick: () => change(() => api.del(url))}, _('Stop sharing')));
    } else {
      row.append(el('button', {type: 'button', class: 'primary', id: 'share-start',
                               onclick: () => change(() => api.put(url, {audience: select.value}))}, _('Share')));
    }
    return row;
  }

  function userItem(user, mayRemove) {
    const item = el('li', {dataset: {login: user.login}, class: user.connected ? 'connected' : 'away'},
                    el('span', {class: 'dot', title: user.connected ? _('On the project now') : _('Not on the project now')}),
                    el('span', {class: 'name'}, personName(user)));
    if (user.owner) {
      item.append(el('span', {class: 'muted'}, _('owner')));
    } else if (mayRemove) {
      item.append(el('button', {type: 'button', title: _('Take this participant out of the project'),
                                onclick: () => change(() => api.del(`${url}/participants/${encodeURIComponent(user.login)}`))},
                     _('Remove')));
    }
    return item;
  }

  function requestItem(request) {
    const answer = (what) => change(() => api.post(`${url}/requests/${encodeURIComponent(request.id)}/${what}`));
    return el('li', {dataset: {request: request.id, login: request.login}},
              el('span', {class: 'name'}, personName(request)),
              el('button', {type: 'button', class: 'primary', onclick: () => answer('accept')}, _('Accept')),
              el('button', {type: 'button', onclick: () => answer('decline')}, _('Refuse')));
  }

  function renderDialog() {
    if (!dialog || !state) {
      return;
    }
    // drawn again only when what it shows changed: a poll that brings nothing new leaves the
    // controls alone (the list of the groups open under the user's hand, the focus)
    const signature = JSON.stringify(state);
    if (signature === dialog.signature) {
      return;
    }
    dialog.signature = signature;
    const body = dialog.body;
    const focused = body.contains(document.activeElement) ? document.activeElement.id : '';
    clear(body);
    if (isOwner) {
      body.append(ownerControls());
    }
    if (state.shared) {
      if (!isOwner) {
        body.append(el('p', {class: 'muted', id: 'share-audience-text'},
                       format(_('Shared by {name} with {audience}.'),
                              {name: personName(state.owner), audience: audienceText(state.audience)})));
      }
      const mayRemove = isOwner || isInstructor;
      body.append(el('h3', {}, _('On this project')),
                  el('ul', {class: 'share-users', id: 'share-users'}, ...usersOf(state).map((u) => userItem(u, mayRemove))));
      if (!state.participants.length) {
        body.append(el('p', {class: 'muted'}, _('Nobody has joined yet.')));
      }
      const requests = state.requests || [];
      if (isOwner && requests.length) {
        body.append(el('h3', {}, _('Asking to join')),
                    el('ul', {class: 'share-users', id: 'share-requests'}, ...requests.map(requestItem)));
      }
      if (isInstructor && !isOwner) {
        body.append(el('div', {class: 'share-controls'},
                       el('button', {type: 'button', class: 'danger', id: 'share-stop',
                                     onclick: () => change(() => api.del(url))}, _('Stop sharing'))));
      }
    } else if (!isOwner) {
      body.append(el('p', {class: 'muted'}, _('This project is not shared.')));
    }
    const again = focused ? document.getElementById(focused) : null;
    if (again && body.contains(again)) {
      again.focus();       // the control the user was on, in the dialog drawn again
    }
  }

  function open() {
    if (dialog || !state) {
      return;
    }
    const body = el('div', {class: 'share-body'});
    const buttons = el('div', {class: 'buttons'});
    if (participant) {
      buttons.append(el('button', {type: 'button', id: 'share-leave', onclick: leave}, _('Leave the project')),
                     el('span', {class: 'spacer'}));
    }
    const close = el('button', {type: 'button', id: 'share-close'}, _('Close'));
    buttons.append(close);
    const element = el('dialog', {class: 'modal share-dialog'}, el('h2', {}, _('Sharing of the project')),
                       el('p', {class: 'muted'},
                          _('The students you accept work in this project with you: its terminals, its questions, its evaluation.'),
                          ' ', _('Only you close or save it.')),
                       body, buttons);
    if (!isOwner) {
      element.querySelector('p.muted').hidden = true;
    }
    dialog = {element, body, signature: ''};
    close.addEventListener('click', () => element.close());
    element.addEventListener('close', () => {
      element.remove();
      dialog = null;
    });
    document.body.append(element);
    renderDialog();
    element.showModal();
    refresh();
  }

  async function leave() {
    try {
      await api.del(`${url}/participants/${encodeURIComponent(login)}`);
    } catch (e) {
      toast(e.message, {error: true});
      return;
    }
    stop();
    onLeft();
  }

  function onPush() {
    refresh();       // a request came or ended, somebody is in or out
  }

  function stop() {
    stopped = true;
    if (timer) {
      window.clearInterval(timer);
      timer = null;
    }
    document.removeEventListener('sre-share', onPush);
    if (dialog) {
      dialog.element.close();
    }
    button.hidden = true;
  }

  button.addEventListener('click', open);
  return {
    // the first state, then the polls
    start() {
      if (stopped || timer) {
        return;
      }
      document.addEventListener('sre-share', onPush);
      timer = window.setInterval(refresh, REFRESH_INTERVAL);
      return refresh();
    },
    stop,
    refresh,
    state: () => state,
  };
}
