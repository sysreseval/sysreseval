// The presentation side of the project page of an instructor: the Present button opens the
// audience dialog (audience_dialog.js, shared with the web conferences: the connected users of
// GET /api/presence, one by one and by student group),
// POST /api/presentations starts the presentation, and while it runs the top bars take the
// presentation colour (the class `presenting` on the body, sre.css) and the bar under the
// project bar shows the audience counts (the socket GET /api/presentations/{id}/ws), Edit
// audience changes it (PUT .../audience) and Stop presenting ends it (DELETE).  The view the
// spectators follow (the active tab, the open terminals, the question, the schema options, the
// instructor texts, the position inside the tab shown — the scroll, the pan and zoom of the
// schema —, the selection of the presenter (pointer.js) and the counter telling that the
// answers changed) is published with PUT .../view a moment after each change: the tabs call
// ctx.onViewChange() / ctx.onScroll(), project.js builds the view (getView).  A scroll in
// progress is followed: the PUT waits for a pause, PUBLISH_MAX_DELAY at most; a change leaving
// the view as last sent (a terminal's scrollback scrolled) sends nothing.  The presenter's mouse
// pointer travels on the socket itself (the tracker of pointer.js sends its frames while the
// presentation runs, and again after a reconnection).  The table of the Evaluation tab travels apart (PUT .../evaluation,
// publishEvaluation, called through ctx.onEvaluated() after each change of the table and at the
// start): the spectators show it as it is, the letters of the presenter's own self-evaluation
// included, which no archive of the project holds.  A reloaded page resumes its presentation
// (GET /api/presentations); the portal ends it when the page is gone for a minute.

import * as api from './api.js';
import {el, toast} from './ui.js';
import {_, format} from './i18n.js';
import {ReconnectingSocket} from './events.js';
import {openAudienceDialog} from './audience_dialog.js';

const PUBLISH_DELAY = 150;        // ms between the last change of the view and its PUT
const PUBLISH_MAX_DELAY = 300;    // ms at most between the first change not sent yet and its PUT (a scroll going on)
const WS_PRESENTATION_ENDED = 4411;

// tracker: the pointer tracker of pointer.js (createPointerTracker), started while presenting
export function createPresenter(ctx, {host, rln, login, groups, getView, getEvaluation, elements, tracker = null}) {
  let presentation = null;        // the JSON of the portal: {id, host, rln, presenter, audience, count, connected}
  let socket = null;
  const counters = {answers: 0};
  let timer = null;
  let since = null;               // when the first change waiting for a PUT happened (ms)
  let inFlight = null;
  let dirty = false;
  let lastKey = null;             // the JSON of the last view PUT: the same view again is not sent
  let evaluationQueue = Promise.resolve();   // the PUTs of the table, one after the other
  let lastEvaluationKey = null;   // the JSON of the last table PUT: the same table again is not sent
  const warned = new Set();       // the statuses of the PUTs already shown as a toast

  function isPresenting() {
    return presentation !== null;
  }

  function presentationUrl(id, suffix = '') {
    return `/api/presentations/${encodeURIComponent(id)}${suffix}`;
  }

  // -- the view -----------------------------------------------------------------------------
  function schedule() {
    if (!presentation) {
      return;
    }
    const now = Date.now();
    if (since === null) {
      since = now;
    }
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(publish, Math.max(0, Math.min(PUBLISH_DELAY, since + PUBLISH_MAX_DELAY - now)));
  }

  function bump(name) {
    counters[name] = (counters[name] || 0) + 1;
    schedule();
  }

  async function publish() {
    timer = null;
    since = null;
    if (!presentation) {
      return;
    }
    if (inFlight) {
      dirty = true;      // sent after the PUT in progress
      return;
    }
    const id = presentation.id;
    const view = {...getView(), ...counters};
    const key = JSON.stringify(view);
    if (key === lastKey) {
      return;            // a change without effect on the view
    }
    inFlight = api.put(presentationUrl(id, '/view'), {view});
    try {
      await inFlight;
      lastKey = key;
    } catch (e) {
      if (e.status === 404) {
        leave();
        toast(_('The presentation has ended.'));
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

  // -- the evaluation table -----------------------------------------------------------------
  // The table of the Evaluation tab as the page shows it (getEvaluation(): header, rows,
  // caption; null before any), sent as it is to the spectators.  The PUTs are chained so that
  // two quick changes reach the portal in order.
  function publishEvaluation() {
    evaluationQueue = evaluationQueue.then(sendEvaluation);
    return evaluationQueue;
  }

  async function sendEvaluation() {
    if (!presentation || !getEvaluation) {
      return;
    }
    const evaluation = getEvaluation();
    if (!evaluation) {
      return;
    }
    const key = JSON.stringify(evaluation);
    if (key === lastEvaluationKey) {
      return;
    }
    try {
      await api.put(presentationUrl(presentation.id, '/evaluation'), {evaluation});
      lastEvaluationKey = key;
    } catch (e) {
      if (e.status === 404) {
        leave();
        toast(_('The presentation has ended.'));
        return;
      }
      if (!warned.has(e.status)) {
        warned.add(e.status);
        toast(e.message, {error: true});
      }
    }
  }

  // -- presenting ---------------------------------------------------------------------------
  function renderStatus(count, connected) {
    elements.status.textContent = format(_('Presenting to {n} students ({m} connected)'),
                                         {n: Number(count) || 0, m: Number(connected) || 0});
  }

  function enter(p) {
    presentation = p;
    if (p.view && typeof p.view === 'object') {
      // a resumed page goes on with the counter of its last view
      counters.answers = Number(p.view.answers) || 0;
    }
    elements.button.hidden = true;
    elements.bar.hidden = false;
    document.body.classList.add('presenting');
    lastKey = null;
    lastEvaluationKey = null;
    renderStatus(p.count, p.connected);
    socket = new ReconnectingSocket(presentationUrl(p.id, '/ws'), {
      onMessage: (message) => {
        if (message.t === 'audience') {
          renderStatus(message.count, message.connected);
        }
      },
      onReconnect: () => {
        if (tracker) {
          tracker.resend();     // the spectators lost the pointer while the socket was down
        }
      },
      onClose: (ev) => {
        if (ev.code === WS_PRESENTATION_ENDED) {
          leave();
          toast(_('The presentation has ended.'));
          return false;
        }
        return true;
      },
    });
    socket.connect();
    if (tracker) {
      tracker.start({send: (obj) => Boolean(socket && socket.send(obj))});
    }
    publish();
    publishEvaluation();      // the table shown now, if any (a resumed page publishes again once its tab has one)
  }

  function leave() {
    if (tracker) {
      tracker.stop();         // before the socket goes: its last frame hides the pointer
    }
    if (socket) {
      const s = socket;
      socket = null;
      s.close();
    }
    if (timer) {
      window.clearTimeout(timer);
      timer = null;
    }
    since = null;
    dirty = false;
    lastKey = null;
    lastEvaluationKey = null;
    presentation = null;
    elements.bar.hidden = true;
    elements.button.hidden = false;
    document.body.classList.remove('presenting');
  }

  async function end() {
    if (!presentation) {
      return;
    }
    const id = presentation.id;
    leave();
    try {
      await api.del(presentationUrl(id));
    } catch (e) {
      // over already (the portal ended it, or restarted)
    }
  }

  async function resume() {
    let list;
    try {
      list = await api.get('/api/presentations');
    } catch (e) {
      return;
    }
    const mine = (list || []).find((p) => p.host === host && p.rln === rln && p.presenter && p.presenter.login === login);
    if (mine) {
      enter(mine);
    }
  }

  // -- the controls -------------------------------------------------------------------------
  elements.button.addEventListener('click', async () => {
    const audience = await openAudienceDialog({logins: [], groups: [], mode: 'start', groupSources: groups});
    if (!audience || presentation) {
      return;
    }
    try {
      enter(await api.post('/api/presentations', {host, rln, audience}));
    } catch (e) {
      toast(e.message, {error: true});
    }
  });
  elements.edit.addEventListener('click', async () => {
    if (!presentation) {
      return;
    }
    const current = presentation.audience || {};
    const audience = await openAudienceDialog({logins: current.logins || [], groups: current.groups || [], mode: 'edit',
                                              groupSources: groups});
    if (!audience || !presentation) {
      return;
    }
    try {
      presentation = await api.put(presentationUrl(presentation.id, '/audience'), {audience});
      renderStatus(presentation.count, presentation.connected);
    } catch (e) {
      toast(e.message, {error: true});
    }
  });
  elements.stop.addEventListener('click', () => end());

  return {resume, schedule, bump, publishEvaluation, end, isPresenting};
}
