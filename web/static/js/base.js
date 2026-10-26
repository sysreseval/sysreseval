// Behaviour of the header bar of every page: the language selector of a logged-in user posts
// the new language to the portal (the session cookie is rewritten) and reloads the page.
//
// Every page of a logged-in user also keeps the presence socket open (GET /api/presence/ws):
// the portal lists the connected users to the instructors through it, and pushes the start
// and the end of a presentation the user is in ({"t": "presentation", "id", "url",
// "presenter"} / {"t": "presentation", "id", "ended": true}).  A presentation is shown in an
// iframe covering the page (the project page of the presenter, read-only: /present/{id}), so
// that the student's own page, terminals included, is still there when it ends.  Nothing of
// this runs inside that iframe.  No _() here: base.js loads no catalog.

import * as api from './api.js';
import {el, toast} from './ui.js';
import {ReconnectingSocket} from './events.js';

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

// -- presentations -----------------------------------------------------------------------------

const body = document.body;
const framed = window.self !== window.top || Boolean(body.dataset.presentation);
let overlay = null;     // {id, element, iframe} while a presentation is shown

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

function onPresence(message) {
  if (!message || message.t !== 'presentation' || !message.id) {
    return;
  }
  if (message.ended) {
    if (overlay && overlay.id === message.id) {
      removeOverlay();
    }
  } else if (typeof message.url === 'string' && message.url.startsWith('/present/')) {
    showOverlay(message.id, message.url);
  }
}

if (body.dataset.login && !framed) {
  new ReconnectingSocket(api.withQuery('/api/presence/ws', {page: window.location.pathname}),
                         {onMessage: onPresence}).connect();
  // the iframe says the presentation is over (its own socket was closed)
  window.addEventListener('message', (ev) => {
    if (ev.origin !== window.location.origin || !overlay || ev.source !== overlay.iframe.contentWindow) {
      return;
    }
    if (ev.data && ev.data.t === 'presentation-ended') {
      removeOverlay();
    }
  });
}
