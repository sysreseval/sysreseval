// The shared projects on every page: what the portal pushes on the presence socket (handed over
// by base.js).
//  - {t: 'share-request', id, host, rln, lab, title, from: {login, fullname}, to: {login, fullname}}:
//    a student asks to join a project of this user.  The owner gets a banner across the top of
//    the page they are on — Accept / Refuse —, one line per student waiting, with a short chime
//    and a mark in the title of the page; nothing happens before they answer.
//  - {..., ended: true, reason: accepted | declined | cancelled | expired | stopped, url}: the
//    request is over.  The line goes; the one who asked is told: accepted, the page that asked
//    (expect(), called by the Open a shared lab dialog) opens the project, their other pages
//    show the way; refused or left unanswered, a toast says so.
//  - {t: 'share', id, host, rln, owner, title, ended: true, reason: removed | left | stopped |
//    forbidden | closed | exam}: this user no longer takes part in that project.  A toast on
//    whatever page; the page of the project itself shuts down (project.js).
// Every push is also dispatched as the `sre-share` event of the document: the Share dialog, the
// Open a shared lab dialog and the cards of the Projects page refresh on it.

import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {siteUrl} from './base_path.js';
import {el, toast} from './ui.js';
import {shortName} from './sharing_model.js';

const MARK = '⇄ ';                 // before the title of the page while the banner is shown
const body = document.body;
const login = body.dataset.login || '';
let ready = null;                  // the catalog loaded
let banner = null;                 // the banner of the owner
const waiting = new Map();         // request id -> its line of the banner
const expected = new Set();        // the requests this page made: it opens the project when accepted

// The Open a shared lab dialog made this request from this page.
export function expect(requestId) {
  expected.add(requestId);
}

function projectApi(message) {
  return `/api/projects/${encodeURIComponent(message.host)}/${encodeURIComponent(message.rln)}/sharing`;
}

function labOf(message) {
  return String(message.title || message.lab || '');
}

// A push of the presence socket.
export async function onPush(message) {
  ready = ready || i18n.init();
  await ready;
  if (!message || typeof message !== 'object' || typeof message.id !== 'string' || !message.id) {
    return;
  }
  if (message.t === 'share-request') {
    onRequest(message);
  } else if (message.t === 'share' && message.ended) {
    onOut(message);
  }
  document.dispatchEvent(new CustomEvent('sre-share', {detail: message}));
}

function onRequest(message) {
  const from = message.from || {};
  const to = message.to || {};
  if (!message.ended) {
    if (to.login === login && typeof message.host === 'string' && typeof message.rln === 'string') {
      addLine(message);
    }
    return;
  }
  if (waiting.has(message.id)) {
    removeLine(message.id);
    if (message.reason === 'cancelled' || message.reason === 'expired') {
      toast(format(_('{name} no longer asks to join.'), {name: shortName(from)}));
    }
  }
  if (from.login !== login) {
    return;
  }
  const mine = expected.delete(message.id);
  const owner = shortName(to);
  if (message.reason === 'accepted') {
    const url = typeof message.url === 'string' && message.url.startsWith('/projects/') ? siteUrl(message.url) : '';
    if (mine && url) {
      window.location.assign(url);
    } else if (url) {
      const note = toast(format(_('{name} accepted you on {lab}.'), {name: owner, lab: labOf(message)}));
      note.append(' ', el('a', {href: url}, _('Open')));
    }
  } else if (message.reason === 'declined') {
    toast(format(_('{name} refused.'), {name: owner}));
  } else if (message.reason === 'expired') {
    toast(format(_('{name} did not answer.'), {name: owner}));
  } else if (message.reason === 'stopped') {
    toast(format(_('{name} no longer shares this project.'), {name: owner}));
  }
}

// this user is out of a project they took part in
function onOut(message) {
  const owner = shortName(message.owner);
  const texts = {
    removed: _('You were taken out of the project of {name}.'),
    stopped: _('{name} no longer shares the project with you.'),
    closed: _('The project of {name} is closed.'),
    forbidden: _('An instructor ended the sharing of the project of {name}.'),
    exam: _('The sharing of the project of {name} ended: no shared project during an exam.'),
  };
  const text = texts[message.reason];     // nothing when they left by themselves
  if (text) {
    toast(format(text, {name: owner}));
  }
}

// -- the banner of the owner ------------------------------------------------------------------------

// Where the banner goes: an open modal dialog makes the rest of the page inert, so the banner is
// put inside the one on top (the last opened), and back in the page when it closes.
function place() {
  if (!banner) {
    return;
  }
  const dialogs = document.querySelectorAll('dialog[open]');
  if (dialogs.length) {
    const dialog = dialogs[dialogs.length - 1];
    dialog.append(banner);
    dialog.addEventListener('close', place, {once: true});
  } else {
    body.append(banner);
  }
}

function addLine(message) {
  if (waiting.has(message.id)) {
    return;
  }
  if (!banner) {
    banner = el('div', {id: 'share-requests', class: 'share-requests', role: 'alert'});
  }
  const accept = el('button', {type: 'button', class: 'primary'}, _('Accept'));
  const refuse = el('button', {type: 'button'}, _('Refuse'));
  const text = el('span', {class: 'text'}, format(_('{name} asks to join {lab}'),
                                                  {name: shortName(message.from), lab: labOf(message)}));
  const line = el('div', {class: 'share-request', dataset: {request: message.id, login: (message.from || {}).login || ''}},
                  text, accept, refuse);
  accept.addEventListener('click', () => answer(message, 'accept', [accept, refuse]));
  refuse.addEventListener('click', () => answer(message, 'decline', [accept, refuse]));
  waiting.set(message.id, line);
  banner.append(line);
  place();
  if (!document.title.startsWith(MARK)) {
    document.title = MARK + document.title;
  }
  chime();
}

function removeLine(id) {
  const line = waiting.get(id);
  if (!line) {
    return;
  }
  line.remove();
  waiting.delete(id);
  if (!waiting.size && banner) {
    banner.remove();
    banner = null;
    if (document.title.startsWith(MARK)) {
      document.title = document.title.slice(MARK.length);
    }
  }
}

async function answer(message, what, buttons) {
  for (const button of buttons) {
    button.disabled = true;
  }
  try {
    await api.post(`${projectApi(message)}/requests/${encodeURIComponent(message.id)}/${what}`);
  } catch (e) {
    if (e.status === 410) {
      removeLine(message.id);        // over meanwhile: the push that said so is on its way, or was lost
      toast(_('This request is over.'));
      return;
    }
    toast(e.message, {error: true});
    for (const button of buttons) {
      button.disabled = false;
    }
  }
}

// Two short notes, on the page the user looks at; silent when the browser does not let a page
// play before a click.
function chime() {
  if (document.visibilityState !== 'visible') {
    return;
  }
  try {
    const Context = window.AudioContext || window.webkitAudioContext;
    if (!Context) {
      return;
    }
    const context = new Context();
    const start = context.currentTime;
    for (const [frequency, at] of [[523, 0], [784, 0.16]]) {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.frequency.value = frequency;
      gain.gain.setValueAtTime(0.0001, start + at);
      gain.gain.exponentialRampToValueAtTime(0.1, start + at + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + at + 0.15);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(start + at);
      oscillator.stop(start + at + 0.16);
    }
    window.setTimeout(() => context.close().catch(() => {}), 1000);
  } catch (e) {
    // no sound
  }
}
