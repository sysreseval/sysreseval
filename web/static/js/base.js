// Behaviour of the header bar of every page: the language selector of a logged-in user posts
// the new language to the portal (the session cookie is rewritten) and reloads the page.
//
// Every page of a logged-in user also keeps the presence socket open (GET /api/presence/ws):
// the portal lists the connected users to the instructors through it (and, on the Watch page,
// the browsers: the socket names the page shown and the random id this browser keeps, and
// says when the page is left, see clientId() below), and pushes the start
// and the end of a presentation the user is in ({"t": "presentation", "id", "url",
// "presenter"} / {"t": "presentation", "id", "ended": true}).  A presentation is shown in an
// iframe covering the page (the project page of the presenter, read-only: /present/{id}), so
// that the student's own page, terminals included, is still there when it ends.  The same
// socket brings the focus an instructor puts on the student's project ({"t": "focus", "id",
// "url", "host", "rln", "instructor"} / {..., "ended": true}): a page that does not show that
// project navigates to it, the project page itself is told (the `sre-focus` event on the
// document, handled by focus.js) and follows the instructor.  An instructor is not kept there:
// the messages of both kinds say `free` for one (a colleague follows their project, or put them
// in an audience).  Their pages go to the focused project once (`bring`) and show a notice bar
// of base.html afterwards, the way back; the page of a presentation has a Leave button for them
// (project.js, the `presentation-leave` message of the iframe), the overlay then gives way to a
// notice bar that brings it back, in every tab of the browser.  The same socket tells a student
// that the phase of the exam they are in changed ({"t": "exam", "id", "phase"}): the message is
// handed to exam.js (the `sre-exam-push` event), which fetches the state again and shows the
// exam bar, the countdowns and the end overlay on every page.  The same socket brings the web
// conference (BigBlueButton) an instructor put the user in ({"t": "webconf", "id", "name",
// "owner", "role", "join_url"} / {..., "ended": true}): webconf.js shows the client in an iframe
// over the page (a floating window, the Webconf tab of a project, full page), and
// webconf_dialog.js is the Webconf button of the instructors.  And the invitation of an
// instructor to a private conversation ({"t": "webconf-invite", "id", "from", "to"} / {...,
// "ended": true, "reason"}): webconf_invite.js shows the banner of the one invited.  Nothing of
// this runs inside the presentation iframe.  The Logout button asks about the running projects
// before the form is submitted (logout.js).  No _() here: base.js loads no catalog (exam.js,
// webconf.js and webconf_invite.js load their own).

import * as api from './api.js';
import {el, toast} from './ui.js';
import {ReconnectingSocket} from './events.js';
import {setupLogout} from './logout.js';
import {setupExam} from './exam.js';
import * as webconf from './webconf.js';
import * as webconfInvite from './webconf_invite.js';
import {setupWebconfDialog} from './webconf_dialog.js';

const select = document.getElementById('language-select');
if (select) {
  select.addEventListener('change', async () => {
    try {
      await api.post('/api/language', {language: select.value});
      window.location.reload();
    } catch (e) {
      toast(e.message, {error: true});
    }
  });
}

setupLogout();

// -- presentations -----------------------------------------------------------------------------

const body = document.body;
const framed = window.self !== window.top || Boolean(body.dataset.presentation);
let overlay = null;     // {id, element, iframe} while a presentation is shown
let presentation = null;    // the presentation this user is in: the last message that started it
// An instructor of the audience is free to leave the presentation (`free` of the message; the
// Leave button of the page in the iframe) and to come back (the notice bar): the id of the
// presentation left, kept for the next pages and the other tabs of this browser.
const LEFT_KEY = 'sreweb.presentation.left';
let left = readLeft();
const presentationNotice = document.getElementById('presentation-notice');   // an instructor's page
const focusNotice = document.getElementById('focus-notice');

function readLeft() {
  try {
    return window.localStorage.getItem(LEFT_KEY);
  } catch (e) {
    return null;        // no storage: what is left is forgotten at the next page
  }
}

function setLeft(id) {
  left = id;
  try {
    if (id) {
      window.localStorage.setItem(LEFT_KEY, id);
    } else {
      window.localStorage.removeItem(LEFT_KEY);
    }
  } catch (e) {
    // this page only
  }
}

// A notice bar of base.html (an instructor's pages): shown with the name of who follows or
// presents, hidden with a null name.
function setNotice(element, name) {
  if (!element) {
    return;
  }
  if (name === null) {
    element.hidden = true;
    return;
  }
  const text = element.querySelector('.text');
  text.textContent = text.dataset.text.replace('{name}', name);
  element.hidden = false;
}

function removeOverlay() {
  if (!overlay) {
    return;
  }
  overlay.element.remove();
  overlay = null;
  body.classList.remove('has-presentation');
}

function showOverlay(id, url) {
  if (overlay && overlay.id === id) {
    return;
  }
  removeOverlay();
  // a modal dialog lives in the top layer, above any z-index
  for (const dialog of document.querySelectorAll('dialog[open]')) {
    dialog.close();
  }
  const iframe = el('iframe', {src: url});
  const element = el('div', {id: 'presentation-overlay'}, iframe);
  body.append(element);
  body.classList.add('has-presentation');
  iframe.addEventListener('load', () => iframe.focus());
  overlay = {id, element, iframe};
}

// The presentation as this page shows it: the overlay, or the notice bar when the user, an
// instructor, has left it.
function renderPresentation() {
  const away = Boolean(presentation && presentation.free && presentationNotice && left === presentation.id);
  if (presentation && !away) {
    showOverlay(presentation.id, presentation.url);
  } else {
    removeOverlay();
  }
  setNotice(presentationNotice, away ? String(presentation.presenter || '') : null);
}

function presentationOver(id) {
  if (left === id) {
    setLeft(null);
  }
  if (presentation && presentation.id === id) {
    presentation = null;
  }
  if (overlay && overlay.id === id) {
    removeOverlay();
  }
  renderPresentation();
}

// -- focus -------------------------------------------------------------------------------------

let focus = null;       // the focus this user (a student) is in: the last message that started it

// The focus the page learnt of before focus.js asked (the project page of the focused project).
export function currentFocus() {
  return focus;
}

// A student is kept on the project: every page that does not show it goes there, now and when
// it is opened later.  An instructor a colleague follows is `free`: their pages go there once
// (`bring`, the first time the portal tells them), then a page elsewhere shows the notice bar,
// the way back.
function onFocus(message) {
  if (message.ended) {
    if (focus && focus.id === message.id) {
      focus = null;
      setNotice(focusNotice, null);
    }
    document.dispatchEvent(new CustomEvent('sre-focus', {detail: message}));
    return;
  }
  focus = message;
  setNotice(focusNotice, null);
  if (body.dataset.host === message.host && body.dataset.rln === message.rln) {
    document.dispatchEvent(new CustomEvent('sre-focus', {detail: message}));   // this page: follow
  } else if (typeof message.url === 'string' && message.url.startsWith('/projects/')) {
    if (!message.free || message.bring) {
      window.location.assign(message.url);                                     // any other page: go there
    } else if (focusNotice) {
      focusNotice.querySelector('a').href = message.url;
      setNotice(focusNotice, String(message.instructor || ''));
    }
  }
}

function onPresence(message) {
  if (!message || !message.id) {
    return;
  }
  if (message.t === 'focus') {
    onFocus(message);
    return;
  }
  if (message.t === 'exam') {
    document.dispatchEvent(new CustomEvent('sre-exam-push', {detail: message}));   // exam.js fetches the state
    return;
  }
  if (message.t === 'webconf') {
    webconf.onPush(message);
    return;
  }
  if (message.t === 'webconf-invite') {
    webconfInvite.onPush(message);
    return;
  }
  if (message.t !== 'presentation') {
    return;
  }
  if (message.ended) {
    presentationOver(message.id);
  } else if (typeof message.url === 'string' && message.url.startsWith('/present/')) {
    presentation = message;
    renderPresentation();
  }
}

// -- this browser, for the Clients view of the instructors' Watch page -----------------------------

const CLIENT_KEY = 'sreweb.client';

// The random id of this browser, kept in its local storage: the same in every tab and window of
// a browser profile, another one in a private window or another browser.  The portal lists the
// pages of one id as one client.  '' when the storage is blocked: the portal then tells the
// browser by its address and User-Agent.
function clientId() {
  try {
    let id = window.localStorage.getItem(CLIENT_KEY);
    if (!id || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
      const bytes = new Uint8Array(12);
      window.crypto.getRandomValues(bytes);
      id = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
      window.localStorage.setItem(CLIENT_KEY, id);
    }
    return id;
  } catch (e) {
    return '';
  }
}

if (body.dataset.login && !framed) {
  // A page that is left may stay in the back/forward cache of the browser with this socket
  // open (Chrome): it says `away` when it is hidden for good and `back` when it is shown again
  // from the cache, so that the portal does not count it as a page somebody looks at.  A socket
  // that opens late (it was connecting when the page was left) repeats it.
  let away = false;
  const presence = new ReconnectingSocket(
    api.withQuery('/api/presence/ws', {page: window.location.pathname, client: clientId()}),
    {onMessage: onPresence,
     onOpen: () => {
       if (away) {
         presence.send({t: 'away'});
       }
     }});
  presence.connect();
  window.addEventListener('pagehide', () => {
    away = true;
    presence.send({t: 'away'});
  });
  window.addEventListener('pageshow', (ev) => {
    if (ev.persisted) {
      away = false;
      presence.send({t: 'back'});
    }
  });
  // the iframe says the presentation is over (its own socket was closed), or that its user, an
  // instructor, leaves it (the Leave button of project.js)
  window.addEventListener('message', (ev) => {
    if (ev.origin !== window.location.origin || !overlay || ev.source !== overlay.iframe.contentWindow) {
      return;
    }
    if (ev.data && ev.data.t === 'presentation-ended') {
      presentationOver(overlay.id);
    } else if (ev.data && ev.data.t === 'presentation-leave' && presentation && presentation.free) {
      setLeft(presentation.id);
      renderPresentation();
    }
  });
  if (presentationNotice) {
    presentationNotice.querySelector('button').addEventListener('click', () => {
      setLeft(null);
      renderPresentation();
    });
    // left or watched again in another tab of this browser: this one follows
    window.addEventListener('storage', (ev) => {
      if (ev.key === LEFT_KEY || ev.key === null) {
        left = readLeft();
        renderPresentation();
      }
    });
  }
  setupExam();
  webconf.setup();
  setupWebconfDialog();      // nothing without the Webconf button (a student, or no [bbb])
}
