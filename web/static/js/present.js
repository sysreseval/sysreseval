// The presentation side of the project page of an instructor: the Present button opens the
// audience dialog (the connected users of GET /api/presence, one by one and by student group),
// POST /api/presentations starts the presentation, and while it runs the top bars take the
// presentation colour (the class `presenting` on the body, sre.css) and the bar under the
// project bar shows the audience counts (the socket GET /api/presentations/{id}/ws), Edit
// audience changes it (PUT .../audience) and Stop presenting ends it (DELETE).  The view the
// spectators follow (the active tab, the open terminals, the question, the schema options, the
// instructor texts, and the counters telling that the answers or the evaluation changed) is
// published with PUT .../view a moment after each change: the tabs call ctx.onViewChange() /
// ctx.onEvaluated(), project.js builds the view (getView).  A reloaded page resumes its
// presentation (GET /api/presentations); the portal ends it when the page is gone for a minute.

import * as api from './api.js';
import {el, clear, toast} from './ui.js';
import {_, format} from './i18n.js';
import {ReconnectingSocket} from './events.js';

const PUBLISH_DELAY = 150;        // ms between the last change of the view and its PUT
const PRESENCE_REFRESH = 5000;    // ms between two refreshes of the connected users while the dialog is open
const WS_PRESENTATION_ENDED = 4411;

export function createPresenter(ctx, {host, rln, login, groups, getView, elements}) {
  let presentation = null;        // the JSON of the portal: {id, host, rln, presenter, audience, count, connected}
  let socket = null;
  const counters = {evaluated: 0, answers: 0};
  let timer = null;
  let inFlight = null;
  let dirty = false;
  const warned = new Set();       // the statuses of the PUT view already shown as a toast

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
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(publish, PUBLISH_DELAY);
  }

  function bump(name) {
    counters[name] = (counters[name] || 0) + 1;
    schedule();
  }

  async function publish() {
    timer = null;
    if (!presentation) {
      return;
    }
    if (inFlight) {
      dirty = true;      // sent after the PUT in progress
      return;
    }
    const id = presentation.id;
    const view = {...getView(), ...counters};
    inFlight = api.put(presentationUrl(id, '/view'), {view});
    try {
      await inFlight;
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

  // -- presenting ---------------------------------------------------------------------------
  function renderStatus(count, connected) {
    elements.status.textContent = format(_('Presenting to {n} students ({m} connected)'),
                                         {n: Number(count) || 0, m: Number(connected) || 0});
  }

  function enter(p) {
    presentation = p;
    if (p.view && typeof p.view === 'object') {
      // a resumed page goes on with the counters of its last view
      counters.evaluated = Number(p.view.evaluated) || 0;
      counters.answers = Number(p.view.answers) || 0;
    }
    elements.button.hidden = true;
    elements.bar.hidden = false;
    document.body.classList.add('presenting');
    renderStatus(p.count, p.connected);
    socket = new ReconnectingSocket(presentationUrl(p.id, '/ws'), {
      onMessage: (message) => {
        if (message.t === 'audience') {
          renderStatus(message.count, message.connected);
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
    publish();
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

  // -- the audience dialog ------------------------------------------------------------------
  // The connected users (refreshed while the dialog is open), a text filter, the student groups
  // among them (a checked group takes its connected members and those connecting later), the
  // users one by one; resolves to {logins, groups} or null (cancelled).
  function openAudienceDialog({logins: checkedLogins, groups: checkedGroups, mode}) {
    return new Promise((resolve) => {
      const logins = new Set(checkedLogins || []);
      const groupSet = new Set(checkedGroups || []);
      let rows = [];
      let result = null;
      const filter = el('input', {type: 'text', class: 'present-filter', placeholder: _('Filter…')});
      const groupBox = el('div', {class: 'present-groups'});
      groupBox.hidden = !groups;
      const list = el('ul', {class: 'present-list'});
      const count = el('p', {class: 'present-count muted'});
      const selectAll = el('button', {type: 'button'}, _('Select all'));
      const none = el('button', {type: 'button'}, _('None'));
      const cancel = el('button', {type: 'button'}, _('Cancel'));
      const ok = el('button', {type: 'button', class: 'primary'}, mode === 'edit' ? _('Apply') : _('Start'));
      const dialog = el('dialog', {class: 'modal present'},
        el('h2', {}, _('Present to…')),
        el('div', {class: 'present-toolbar'}, filter),
        groupBox, list, count,
        el('div', {class: 'buttons'}, selectAll, none, el('span', {class: 'spacer'}), cancel, ok));

      const matches = (row) => {
        const text = filter.value.trim().toLowerCase();
        return !text || [row.login, row.fullname, row.group].some((v) => (v || '').toLowerCase().includes(text));
      };
      const viaGroup = (row) => Boolean(row.group && groupSet.has(row.group));

      function updateCount() {
        const selected = new Set(logins);
        for (const row of rows) {
          if (viaGroup(row)) {
            selected.add(row.login);
          }
        }
        count.textContent = format(_('{n} selected'), {n: selected.size});
        ok.disabled = selected.size === 0 && groupSet.size === 0;
      }

      function renderGroups() {
        clear(groupBox);
        const members = new Map();
        for (const row of rows) {
          if (row.group) {
            members.set(row.group, (members.get(row.group) || 0) + 1);
          }
        }
        for (const group of [...new Set([...members.keys(), ...groupSet])].sort()) {
          const box = el('input', {type: 'checkbox'});
          box.checked = groupSet.has(group);
          box.addEventListener('change', () => {
            if (box.checked) {
              groupSet.add(group);
            } else {
              groupSet.delete(group);
            }
            renderList();
            updateCount();
          });
          groupBox.append(el('label', {}, box, format(_('{group} ({n} connected)'), {group, n: members.get(group) || 0})));
        }
      }

      function renderList() {
        clear(list);
        const shown = rows.filter(matches);
        if (!rows.length) {
          list.append(el('li', {class: 'empty'}, _('No user is connected.')));
        } else if (!shown.length) {
          list.append(el('li', {class: 'empty'}, _('No user matches the filter.')));
        }
        for (const row of shown) {
          const box = el('input', {type: 'checkbox', value: row.login});
          const inGroup = viaGroup(row);
          box.checked = inGroup || logins.has(row.login);
          box.disabled = inGroup;
          box.addEventListener('change', () => {
            if (box.checked) {
              logins.add(row.login);
            } else {
              logins.delete(row.login);
            }
            updateCount();
          });
          const label = el('label', {title: inGroup ? _('via group') : undefined}, box,
            el('span', {class: 'name'}, row.fullname || row.login),
            row.fullname ? el('span', {class: 'login muted'}, row.login) : null,
            row.group ? el('span', {class: 'muted'}, row.group) : null,
            row.role === 'instructor' ? el('span', {class: 'badge'}, _('instructor')) : null,
            row.presentation ? el('span', {class: 'busy'}, _('in a presentation')) : null);
          list.append(el('li', {}, label));
        }
      }

      async function refresh() {
        try {
          rows = await api.get('/api/presence');
        } catch (e) {
          clear(list);
          list.append(el('li', {class: 'error'}, e.message));
          return;
        }
        rows = Array.isArray(rows) ? rows : [];
        rows.sort((a, b) => (a.fullname || a.login).localeCompare(b.fullname || b.login));
        renderGroups();
        renderList();
        updateCount();
      }

      filter.addEventListener('input', renderList);
      selectAll.addEventListener('click', () => {
        for (const row of rows.filter(matches)) {
          logins.add(row.login);
        }
        renderList();
        updateCount();
      });
      none.addEventListener('click', () => {
        logins.clear();
        groupSet.clear();
        renderGroups();
        renderList();
        updateCount();
      });
      ok.addEventListener('click', () => {
        result = {logins: [...logins].sort(), groups: [...groupSet].sort()};
        dialog.close();
      });
      cancel.addEventListener('click', () => dialog.close());
      const interval = window.setInterval(refresh, PRESENCE_REFRESH);
      dialog.addEventListener('close', () => {
        window.clearInterval(interval);
        dialog.remove();
        resolve(result);
      });
      document.body.append(dialog);
      dialog.showModal();
      updateCount();
      refresh();
    });
  }

  // -- the controls -------------------------------------------------------------------------
  elements.button.addEventListener('click', async () => {
    const audience = await openAudienceDialog({logins: [], groups: [], mode: 'start'});
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
    const audience = await openAudienceDialog({logins: current.logins || [], groups: current.groups || [], mode: 'edit'});
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

  return {resume, schedule, bump, end, isPresenting};
}
