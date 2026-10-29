// The focus side of the project page.  An instructor on a student's project (the helper view)
// turns the "Focus student on project" button on: POST /api/focus; the portal tells the
// student's pages through their presence socket (base.js: a page not on the project navigates
// to it, the project page gets the `sre-focus` event handled here).  Both pages then keep the
// socket GET /api/focus/{id}/ws open and share one view (the active tab, the terminal sub-tab
// shown, the question selected): each page publishes its own view a moment after a change
// (PUT .../view, through the ctx.onViewChange() hook the tabs call) and applies what the socket
// brings, last change wins.  A view being applied is not published again, nor the echo of a
// view this page published (the portal pushes every view to every socket).  The instructor's
// page takes the class `focusing` and the student's page the class `focused` (the focus colour
// of the top bars, sre.css) with a "Followed by" label.  A reloaded instructor's page resumes
// its focus (GET /api/focus); the portal ends it when that page is gone for a minute.

import * as api from './api.js';
import {toast} from './ui.js';
import {_, format} from './i18n.js';
import {ReconnectingSocket} from './events.js';
import {currentFocus} from './base.js';

const PUBLISH_DELAY = 150;        // ms between the last change of the view and its PUT
const WS_FOCUS_ENDED = 4412;
const VIEW_KEYS = ['tab', 'terminal', 'question'];

// The shared view: the three keys, null when absent (one JSON form for the comparisons).
function normalise(view) {
  const out = {};
  for (const key of VIEW_KEYS) {
    const value = view && typeof view === 'object' && view[key] !== undefined ? view[key] : null;
    out[key] = value;
  }
  return out;
}

// leader: an instructor on somebody else's project (the button); otherwise the owner's page,
// which follows when an instructor focuses it.  getView() / applyView(view) are the page's
// (project.js), isLoaded() tells whether a view can be applied yet.
export function createFocus(ctx, {host, rln, login, leader, getView, applyView, isLoaded, elements}) {
  let focus = null;         // {id, host, rln, instructor...}: the JSON of the portal, or the presence message
  let socket = null;
  let timer = null;
  let inFlight = null;
  let dirty = false;
  let applying = false;     // the other page's view being applied: the tabs' notifications are not published
  let pending = null;       // a view received before the project was loaded
  let lastKey = null;       // the normalised view last published or applied (JSON): never published again
  const warned = new Set(); // the statuses of the PUT view already shown as a toast
  const buttonTitle = elements.button ? elements.button.title : '';

  function isActive() {
    return focus !== null;
  }

  function focusUrl(id, suffix = '') {
    return `/api/focus/${encodeURIComponent(id)}${suffix}`;
  }

  // -- the shared view ----------------------------------------------------------------------
  function schedule() {
    if (!focus || applying) {
      return;
    }
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(publish, PUBLISH_DELAY);
  }

  async function publish() {
    timer = null;
    if (!focus || applying) {
      return;
    }
    if (inFlight) {
      dirty = true;      // sent after the PUT in progress
      return;
    }
    const view = normalise(getView());
    const key = JSON.stringify(view);
    if (key === lastKey) {
      return;          // what the other page sent, or what this page already published
    }
    lastKey = key;
    const id = focus.id;
    inFlight = api.put(focusUrl(id, '/view'), {view});
    try {
      await inFlight;
    } catch (e) {
      if (e.status === 404) {
        ended();
        return;
      }
      if (!warned.has(e.status)) {
        warned.add(e.status);
        toast(e.message, {error: true});
      }
    } finally {
      inFlight = null;
    }
    if (dirty) {
      dirty = false;
      schedule();
    }
  }

  function apply(view) {
    if (!view || typeof view !== 'object') {
      return;
    }
    if (!isLoaded()) {
      pending = view;
      return;
    }
    const wanted = normalise(view);
    applying = true;
    try {
      applyView(wanted);
    } finally {
      applying = false;
    }
    lastKey = JSON.stringify(wanted);
  }

  // The project is loaded (or loaded again): the view received before can be applied.
  function projectLoaded() {
    if (pending && isLoaded()) {
      const view = pending;
      pending = null;
      apply(view);
    }
  }

  // -- the socket ---------------------------------------------------------------------------
  function renderStatus(connected) {
    if (elements.button) {
      elements.button.title = Number(connected) > 0 ? _("The student's page follows") : _("Waiting for the student's page");
    }
  }

  function open(f) {
    focus = f;
    socket = new ReconnectingSocket(focusUrl(f.id, '/ws'), {
      onMessage: (message) => {
        if (message.t === 'view' && message.view) {
          apply(message.view);
        } else if (message.t === 'student' && leader) {
          renderStatus(message.connected);
        }
      },
      onClose: (ev) => {
        if (ev.code === WS_FOCUS_ENDED || ev.code === 4403 || ev.code === 4404) {
          ended();
          return false;
        }
        return true;
      },
    });
    socket.connect();
  }

  function leave() {
    if (socket) {
      const s = socket;
      socket = null;
      s.close();
    }
    if (timer) {
      window.clearTimeout(timer);
      timer = null;
    }
    focus = null;
    pending = null;
    lastKey = null;
    dirty = false;
    if (leader) {
      elements.button.setAttribute('aria-pressed', 'false');
      elements.button.title = buttonTitle;
      document.body.classList.remove('focusing');
    } else {
      document.body.classList.remove('focused');
      if (elements.label) {
        elements.label.hidden = true;
        elements.label.textContent = '';
      }
    }
  }

  // The portal ended it (the instructor's page gone, another instructor, a restart).
  function ended() {
    if (!focus) {
      return;
    }
    leave();
    if (leader) {
      toast(_('The focus has ended.'));
    }
  }

  // -- the leader: the button ---------------------------------------------------------------
  function enter(f) {
    leave();
    elements.button.setAttribute('aria-pressed', 'true');
    document.body.classList.add('focusing');
    renderStatus(f.connected);
    open(f);
  }

  async function start() {
    if (focus) {
      return;
    }
    try {
      enter(await api.post('/api/focus', {host, rln, view: normalise(getView())}));
    } catch (e) {
      toast(e.message, {error: true});
    }
  }

  // Turned off by the instructor, or the project closed: the student's page is released.
  async function end() {
    if (!focus) {
      return;
    }
    const id = focus.id;
    leave();
    if (!leader) {
      return;
    }
    try {
      await api.del(focusUrl(id));
    } catch (e) {
      // over already (the portal ended it, or restarted)
    }
  }

  // -- the follower: the student's page -----------------------------------------------------
  function follow(message) {
    if (!message || message.host !== host || message.rln !== rln) {
      return;
    }
    if (focus && focus.id === message.id) {
      return;      // told twice (a second presence socket of this login)
    }
    leave();
    document.body.classList.add('focused');
    if (elements.label) {
      elements.label.textContent = format(_('Followed by {name}'), {name: message.instructor || ''});
      elements.label.hidden = false;
    }
    open({id: message.id, host: message.host, rln: message.rln, instructor: message.instructor});
  }

  function onFocusEvent(ev) {
    const message = ev.detail;
    if (!message || !message.id) {
      return;
    }
    if (message.ended) {
      if (focus && focus.id === message.id) {
        leave();
      }
      return;
    }
    follow(message);
  }

  // A reloaded page goes on: the instructor's page finds its focus at the portal, the
  // student's page the one base.js was told of.
  async function resume() {
    if (!leader) {
      follow(currentFocus());
      return;
    }
    let mine;
    try {
      mine = await api.get('/api/focus');
    } catch (e) {
      return;
    }
    const f = ((mine && mine.leading) || []).find((x) => x.host === host && x.rln === rln &&
                                                          x.instructor && x.instructor.login === login);
    if (f) {
      enter(f);
    }
  }

  if (leader) {
    elements.button.addEventListener('click', () => (focus ? end() : start()));
  } else {
    document.addEventListener('sre-focus', onFocusEvent);
  }

  return {resume, schedule, end, projectLoaded, isActive};
}
