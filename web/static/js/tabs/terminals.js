// The Terminals tab: one sub-tab per open terminal.  Each Connect button of the Machines and
// Networks tabs opens a new terminal on its device (like a new xterm in the Qt GUI), so a
// machine may have several (titled "gw", "gw (2)", ...); the select at the end of the bar opens
// one on any device.  Every terminal is an xterm.js on the WebSocket of its device
// (terminal.js), closed with the × of its sub-tab.  A device closed to the students is disabled
// (orange; a debug project opens it all the same, as `sre connect` lets a debug project in), a
// hidden machine of a debug project is red, like the Qt view.  The font size and colour scheme
// controls are on the right.
//
// A terminal is a session shared by its viewers: the live sessions of the project the user does
// not have on this page are listed under the bar with a Join button (the same shell, everybody
// sees and types), a sub-tab shows how many viewers its session has.  An instructor on a
// student's project joins the student's terminals by default when the tab opens, and can open
// private terminals the student does not see (the select offers both kinds).
//
// On the page of a spectator of a presentation (ctx.spectator) nothing can be opened or closed:
// the sub-tabs are those of the presenter's page (setView, read-only sessions joined by their
// id), the active one follows; on the presenter's page every change calls ctx.onViewChange().

import * as settings from '../settings.js';
import {el, clear} from '../ui.js';
import {_, format} from '../i18n.js';
import {TerminalSession} from '../terminal.js';

export function createTerminalsTab(ctx) {
  const spectator = Boolean(ctx.spectator);
  const tabs = el('div', {class: 'terminal-tabs', role: 'tablist'});
  const newSelect = el('select', {class: 'new-terminal', title: _('New terminal…')});
  const live = el('div', {class: 'live-sessions'});
  const host = el('div', {class: 'terminal-host'});
  const schemeSelect = el('select', {title: _('Color scheme')},
    el('option', {value: 'black_on_white'}, _('Black on White')),
    el('option', {value: 'white_on_black'}, _('White on Black')));
  schemeSelect.value = settings.get('terminal_color_scheme');
  schemeSelect.addEventListener('change', () => settings.set('terminal_color_scheme', schemeSelect.value));
  const smaller = el('button', {type: 'button', title: _('Smaller terminal font')}, 'A−');
  const larger = el('button', {type: 'button', title: _('Larger terminal font')}, 'A+');
  smaller.addEventListener('click', () => settings.set('terminal_font_size', settings.get('terminal_font_size') - 1));
  larger.addEventListener('click', () => settings.set('terminal_font_size', settings.get('terminal_font_size') + 1));
  const bar = el('div', {class: 'ctrl-bar'}, tabs, newSelect, el('span', {class: 'spacer'}), schemeSelect, smaller, larger);
  const pane = el('div', {class: 'pane no-scroll'}, el('div', {class: 'terminals'}, bar, live, host));
  newSelect.hidden = spectator;
  live.hidden = spectator;

  const sessions = new Map();   // id -> {id, device, title, box, tab, badge, session, remoteId}, in opening order
  const counters = new Map();   // device -> number of terminals opened on it so far (the titles)
  let nextId = 1;
  let devices = [];
  let debug = false;
  let current = null;           // the id of the shown terminal
  let pending = null;           // a device being opened by a Connect button: show() must not auto-open
  let remote = [];              // the live sessions of the project (setSessions): {id, device, created_by, private, clients}
  const dismissed = new Set();  // the remote sessions the user closed here: never joined again by themselves
  let shown = false;            // the tab has been shown at least once
  // an instructor on somebody else's project: joins the owner's terminals, opens private ones
  const helper = Boolean(ctx.isInstructor && !ctx.isOwner && !spectator);

  // the presenter's page: the sub-tabs changed (published to the spectators)
  function notify() {
    if (ctx.onViewChange) {
      ctx.onViewChange();
    }
  }

  settings.onChange('terminal_font_size', (size) => {
    for (const {session} of sessions.values()) {
      session.setFontSize(size);
    }
  });
  settings.onChange('terminal_color_scheme', (scheme) => {
    for (const {session} of sessions.values()) {
      session.setScheme(scheme);
    }
  });

  function canOpen(device) {
    return Boolean(device.allow_connection || debug);
  }

  function deviceOf(name) {
    return devices.find((d) => d.name === name);
  }

  function deviceClass(device) {
    if (!device) {
      return null;
    }
    return device.hidden ? 'hidden-device' : (device.allow_connection ? null : 'closed-device');
  }

  // the select opening a new terminal on a device (two kinds for a helping instructor)
  function renderSelect() {
    clear(newSelect);
    newSelect.append(el('option', {value: ''}, _('New terminal…')));
    const options = (prefix) => devices.map((device) => {
      const option = el('option', {value: prefix + device.name, class: deviceClass(device)}, device.name);
      option.disabled = !canOpen(device);
      return option;
    });
    if (helper) {
      newSelect.append(el('optgroup', {label: _('Private terminal (the student does not see it)')}, ...options('private:')));
      newSelect.append(el('optgroup', {label: _('Shared terminal (the student can join it)')}, ...options('shared:')));
    } else {
      newSelect.append(...options(''));
    }
    newSelect.value = '';
  }
  newSelect.addEventListener('change', () => {
    const value = newSelect.value;
    newSelect.value = '';
    if (!value) {
      return;
    }
    if (value.startsWith('private:')) {
      openNew(value.slice('private:'.length), {priv: true});
    } else if (value.startsWith('shared:')) {
      openNew(value.slice('shared:'.length));
    } else {
      openNew(value);
    }
  });

  function titleFor(name) {
    const n = (counters.get(name) || 0) + 1;
    counters.set(name, n);
    return n === 1 ? name : format(_('{device} ({n})'), {device: name, n});
  }

  function makeTab(entry) {
    entry.badge = el('span', {class: 'viewers'});
    const button = el('button', {type: 'button', role: 'tab', class: deviceClass(deviceOf(entry.device)),
      dataset: {id: String(entry.id), device: entry.device}}, entry.title, entry.badge);
    if (spectator) {
      button.disabled = true;      // the presenter chooses the terminal shown
      return button;
    }
    const close = el('span', {class: 'close', role: 'button', title: _('Close terminal'),
      'aria-label': _('Close terminal')}, '×');
    close.addEventListener('click', (event) => {
      event.stopPropagation();
      closeSession(entry.id);
    });
    button.append(close);
    button.addEventListener('click', () => select(entry.id));
    return button;
  }

  function select(id) {
    const entry = sessions.get(id);
    if (!entry) {
      return;
    }
    current = id;
    for (const other of sessions.values()) {
      other.box.hidden = other !== entry;
      other.tab.setAttribute('aria-selected', other === entry ? 'true' : 'false');
    }
    entry.session.refit();
    if (!spectator) {
      entry.session.focus();
    }
    notify();
  }

  function remoteOf(entry) {
    return entry.remoteId ? remote.find((r) => r.id === entry.remoteId) : null;
  }

  // a private terminal: opened private here, or a joined session listed private (an
  // instructor's, seen by instructors only)
  function isPrivate(entry) {
    const r = remoteOf(entry);
    return Boolean(entry.private || (r && r.private));
  }

  // the viewer count of a sub-tab (the session is shared when it is above one): the browsers
  // typing in it and the read-only spectators of a presentation
  function updateBadge(entry) {
    const r = remoteOf(entry);
    const n = r ? (Number(r.clients) || 0) + (Number(r.viewers) || 0) : (entry.session.clients || 0);
    entry.badge.textContent = n > 1 ? `(${n})` : '';
    entry.badge.title = n > 1 ? format(_('{n} viewers'), {n}) : '';
  }

  function attachedIds() {
    return new Set([...sessions.values()].map((e) => e.remoteId).filter(Boolean));
  }

  // the live sessions of the project not on this page: a Join button each
  function renderLive() {
    clear(live);
    if (spectator) {
      return;
    }
    const attached = attachedIds();
    // a private session is an instructor's (the agent lists them to instructors only)
    const others = remote.filter((r) => !attached.has(r.id) && (!r.private || ctx.isInstructor));
    if (!others.length) {
      return;
    }
    live.append(el('span', {class: 'muted'}, _('Live terminals:')));
    for (const r of others) {
      const who = r.created_by === ctx.login ? _('you') : r.created_by;
      const button = el('button', {type: 'button', class: r.private ? 'private' : null,
        title: format(_('{n} viewers'), {n: r.clients})},
        format(_('Join {device} ({who})'), {device: r.device, who}) + (r.private ? ' · ' + _('private') : ''));
      button.addEventListener('click', () => join(r));
      live.append(button);
    }
  }

  // a new terminal on a device (or, with join, one more viewer of a live session): a new box, a
  // new sub-tab, a new WebSocket
  function openNew(name, {join: joinId = null, priv = false, title = null} = {}) {
    const device = deviceOf(name);
    // a joined session is addressed by its id: its device need not be listed (a spectator's view
    // may name a session before the terminals event does)
    if (!joinId && (!device || !canOpen(device))) {
      return null;
    }
    const id = nextId++;
    const box = el('div', {class: 'terminal-box'});
    host.append(box);
    const entry = {id, device: name, title: title || titleFor(name), box, session: null, tab: null, badge: null,
                   remoteId: joinId, private: priv};
    if (priv) {
      entry.title = format(_('{title} (private)'), {title: entry.title});
    }
    const session = new TerminalSession(box, ctx.url(`/terminals/${encodeURIComponent(name)}`), {
      fontSize: settings.get('terminal_font_size'),
      scheme: settings.get('terminal_color_scheme'),
      join: joinId,
      private: priv,
      readonly: spectator,
      onReady: (info) => {
        entry.remoteId = info.session || entry.remoteId;
        updateBadge(entry);
        renderLive();
        notify();         // the session id is known: the spectators can join it
      },
    });
    entry.session = session;
    entry.tab = makeTab(entry);
    tabs.append(entry.tab);
    sessions.set(id, entry);
    select(id);
    session.connect();
    renderLive();
    return entry;
  }

  function join(r) {
    const who = r.created_by === ctx.login ? null : r.created_by;
    const title = who ? format(_('{device} ({who})'), {device: r.device, who}) : titleFor(r.device);
    openNew(r.device, {join: r.id, title});
  }

  // the × of a sub-tab (or a device gone from the project): the WebSocket is closed, which ends
  // `sre connect` on the host when nobody else is attached; the neighbouring terminal is shown
  function closeSession(id) {
    const entry = sessions.get(id);
    if (!entry) {
      return;
    }
    if (entry.remoteId) {
      dismissed.add(entry.remoteId);
    }
    const ids = [...sessions.keys()];
    const index = ids.indexOf(id);
    entry.session.close();
    entry.box.remove();
    entry.tab.remove();
    sessions.delete(id);
    if (current === id) {
      current = null;
      const neighbour = sessions.has(ids[index + 1]) ? ids[index + 1] : ids[index - 1];
      if (neighbour !== undefined && sessions.has(neighbour)) {
        select(neighbour);
      }
    }
    renderLive();
    notify();
  }

  // -- the presenter's view of the sub-tabs, and a spectator following it --------------------
  function getView() {
    const open = [...sessions.values()].filter((e) => e.remoteId)
      .map((e) => ({id: e.remoteId, device: e.device, title: e.title}));
    const entry = current !== null ? sessions.get(current) : null;
    return {open, active: entry && entry.remoteId ? entry.remoteId : null};
  }

  function setView(view) {
    const open = Array.isArray(view && view.open) ? view.open.filter((o) => o && o.id && o.device) : [];
    const wanted = new Set(open.map((o) => o.id));
    for (const entry of [...sessions.values()]) {
      if (!entry.remoteId || !wanted.has(entry.remoteId)) {
        closeSession(entry.id);
      }
    }
    const byRemote = new Map([...sessions.values()].map((e) => [e.remoteId, e]));
    for (const o of open) {
      if (!byRemote.has(o.id)) {
        const entry = openNew(o.device, {join: o.id, title: o.title || o.device});
        if (entry) {
          byRemote.set(o.id, entry);
        }
      }
    }
    for (const o of open) {              // the order of the presenter's sub-tabs
      const entry = byRemote.get(o.id);
      if (entry) {
        tabs.append(entry.tab);
      }
    }
    const active = view && view.active ? byRemote.get(view.active) : null;
    if (active) {
      select(active.id);
    }
  }

  // -- a focus (focus.js): the sub-tab shown, shared with the other page by the id of its
  // session.  Never a private terminal: the student must not see nor join one.
  function focusTarget() {
    const entry = current !== null ? sessions.get(current) : null;
    return entry && entry.remoteId && !isPrivate(entry) ? entry.remoteId : null;
  }

  // the sub-tab the other page shows: shown when it is open here, joined when it is a live
  // session of the project this page may see (never a private one), else kept until the
  // terminals event lists it
  let wantedSession = null;
  function focusSession(remoteId) {
    if (!remoteId) {
      return;
    }
    const entry = [...sessions.values()].find((e) => e.remoteId === remoteId);
    if (entry) {
      wantedSession = null;
      if (current !== entry.id) {
        select(entry.id);
      }
      return;
    }
    const r = remote.find((x) => x.id === remoteId);
    if (r) {
      wantedSession = null;
      if (!r.private) {
        join(r);
      }
    } else {
      wantedSession = remoteId;
    }
  }

  // a helping instructor: the owner's live sessions not yet on this page
  function autoJoin() {
    if (!helper || !shown) {
      return;
    }
    const attached = attachedIds();
    for (const r of remote) {
      if (r.created_by === ctx.owner && !attached.has(r.id) && !dismissed.has(r.id)) {
        join(r);
      }
    }
  }

  return {
    id: 'terminals',
    element: pane,
    // autoOpen false: the tab is shown by a focus (the other page went there), not by the
    // user: no terminal is opened for them (the instructor's new terminal, a private one say,
    // would otherwise be echoed by a terminal of the student's own on the first machine)
    show({autoOpen = true} = {}) {
      shown = true;
      if (current !== null) {
        select(current);
      } else if (spectator) {
        // the presenter's view says what is open: nothing by itself
      } else if (sessions.size === 0 && pending === null) {
        if (helper) {
          autoJoin();   // the student's terminals; nothing when there is none
        } else if (autoOpen) {
          // the first open device, as the first terminal tab of the Qt view starts when shown
          const first = devices.find(canOpen);
          if (first) {
            openNew(first.name);
          }
        }
      }
    },
    hide() {},
    update(project) {
      devices = project.terminal_devices || [];
      debug = Boolean(project.debug_project);
      for (const entry of [...sessions.values()]) {
        if (!deviceOf(entry.device)) {
          closeSession(entry.id);
        }
      }
      renderSelect();
      renderLive();
    },
    // the live sessions of the project (GET of the project, then the terminals events)
    setSessions(list) {
      remote = Array.isArray(list) ? list : [];
      for (const entry of sessions.values()) {
        updateBadge(entry);
      }
      renderLive();
      autoJoin();
      if (wantedSession) {
        focusSession(wantedSession);
      }
    },
    // the Connect buttons of the Machines / Networks tabs: a new terminal every time (a private
    // one for a helping instructor)
    openNew(name) {
      pending = name;
      try {
        ctx.selectTab('terminals');
      } finally {
        pending = null;
      }
      openNew(name, {priv: helper});
    },
    closeAll() {
      for (const entry of sessions.values()) {
        entry.session.close();
      }
    },
    getView,
    setView,
    focusTarget,
    focusSession,
  };
}
