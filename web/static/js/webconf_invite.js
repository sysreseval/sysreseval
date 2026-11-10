// The invitation to a private conversation (BigBlueButton): an instructor on a student's project
// asks the student to talk alone (talk.js), and the portal pushes it to both on the presence
// socket ({t: 'webconf-invite', id, from: {login, fullname}, to: {login, fullname}}, handed over
// by base.js), then its end ({..., ended: true, reason: 'accepted' | 'declined' | 'cancelled' |
// 'expired' | 'failed'}).  The invited one gets a banner on every page — Join / Not now — with a
// short chime and a mark in the title of the page; nothing else happens before the answer: the
// class conference goes on, no microphone is opened.  Join names this browser tab (TAB of
// webconf.js): the portal makes the room and pushes it, and this tab alone shows it.  The one
// who invited is told how it ended by a toast, on whatever page; the button of the project page
// follows the `sre-talk` event of the document and currentInvitation().

import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, toast} from './ui.js';
import {TAB} from './webconf.js';

const MARK = '☎ ';                 // before the title of the page while the banner is shown
const body = document.body;
const login = body.dataset.login || '';
let ready = null;          // the catalog loaded
let outgoing = null;       // the pending invitation this user made: {id, from, to}
let incoming = null;       // the one this user got (its banner is shown)
let banner = null;

function person(value) {
  const who = value && typeof value === 'object' ? value : {};
  return {login: typeof who.login === 'string' ? who.login : '', fullname: typeof who.fullname === 'string' ? who.fullname : ''};
}

function nameOf(who) {
  return who.fullname || who.login;
}

// The pending invitation this user made (the Talk privately button), or null.
export function currentInvitation() {
  return outgoing;
}

// A push of the presence socket.
export async function onPush(message) {
  ready = ready || i18n.init();
  await ready;
  if (!message || typeof message !== 'object' || typeof message.id !== 'string' || !message.id) {
    return;
  }
  const invitation = {id: message.id, from: person(message.from), to: person(message.to)};
  if (message.ended) {
    if (outgoing && outgoing.id === invitation.id) {
      outgoing = null;
      tellInviter(message.reason, invitation.to);
    }
    if (incoming && incoming.id === invitation.id) {
      incoming = null;
      removeBanner();
      tellInvited(message.reason, invitation.from);
    }
  } else if (invitation.from.login === login) {
    outgoing = invitation;
  } else if (invitation.to.login === login) {
    incoming = invitation;
    showBanner(invitation);
  }
  document.dispatchEvent(new CustomEvent('sre-talk', {detail: {id: invitation.id, ended: Boolean(message.ended),
                                                                reason: message.ended ? message.reason : null}}));
}

function tellInviter(reason, to) {
  if (reason === 'declined') {
    toast(format(_('{name} declined the conversation.'), {name: nameOf(to)}));
  } else if (reason === 'expired') {
    toast(format(_('{name} did not answer.'), {name: nameOf(to)}));
  } else if (reason === 'failed') {
    toast(_('The private conversation could not be started.'), {error: true});
  }
}

function tellInvited(reason, from) {
  if (reason === 'cancelled' || reason === 'expired') {
    toast(format(_('{name} is no longer calling.'), {name: nameOf(from)}));
  } else if (reason === 'failed') {
    toast(_('The private conversation could not be started.'), {error: true});
  }
}

// -- the banner --------------------------------------------------------------------------------

// Where the banner goes: an open modal dialog makes the rest of the page inert, so the banner
// is put inside the one on top (the last opened), and back in the page when it closes.
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

function showBanner(invitation) {
  removeBanner();
  const join = el('button', {type: 'button', class: 'primary'}, _('Join'));
  const later = el('button', {type: 'button'}, _('Not now'));
  const text = el('span', {class: 'text'}, format(_('{name} would like to talk with you'), {name: nameOf(invitation.from)}));
  banner = el('div', {id: 'webconf-invite', class: 'webconf-invite', role: 'alert'}, text, join, later);
  join.addEventListener('click', () => answer(invitation, 'accept', [join, later]));
  later.addEventListener('click', () => answer(invitation, 'decline', [join, later]));
  place();
  if (!document.title.startsWith(MARK)) {
    document.title = MARK + document.title;
  }
  chime();
}

function removeBanner() {
  if (banner) {
    banner.remove();
    banner = null;
  }
  if (document.title.startsWith(MARK)) {
    document.title = document.title.slice(MARK.length);
  }
}

async function answer(invitation, what, buttons) {
  for (const button of buttons) {
    button.disabled = true;
  }
  try {
    await api.post(`/api/webconfs/invitations/${encodeURIComponent(invitation.id)}/${what}`, {tab: TAB});
  } catch (e) {
    if (e.status === 410) {
      // over meanwhile: the push that said so is on its way, or was lost
      if (incoming && incoming.id === invitation.id) {
        incoming = null;
        removeBanner();
      }
      toast(_('The invitation is over.'));
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
    for (const [frequency, at] of [[660, 0], [880, 0.18]]) {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.frequency.value = frequency;
      gain.gain.setValueAtTime(0.0001, start + at);
      gain.gain.exponentialRampToValueAtTime(0.12, start + at + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + at + 0.16);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(start + at);
      oscillator.stop(start + at + 0.17);
    }
    window.setTimeout(() => context.close().catch(() => {}), 1000);
  } catch (e) {
    // no sound
  }
}
