// The Terminals tab: one sub-tab per docked terminal, and the floating windows over the page.
// Each Connect button of the Machines and Networks tabs opens a new terminal on its device in a
// floating window (like a new xterm window in the Qt GUI: the window floats over whatever tab is
// shown, dragged by its title bar, resized by its corner, closed by its ×), so a machine may have
// several (titled "gw", "gw (2)", ...); the "New terminal…" select of the bar opens one as a
// sub-tab, the "New window…" select one in a window; the ⧉ of a sub-tab moves the terminal into
// a window, the dock button of a window brings it back as a sub-tab (the same shell goes on: the
// box of the xterm is moved, terminal_windows.js).  Every terminal is an xterm.js on the
// WebSocket of its device (terminal.js).  A device closed to the students is disabled (orange; a
// debug project opens it all the same, as `sre connect` lets a debug project in), a hidden
// machine of a debug project is red, like the Qt view.  The font size and colour scheme controls
// are on the right and apply to every terminal, docked or floating.
//
// A terminal is a session shared by its viewers: the live sessions of the project the user does
// not have on this page are listed under the bar with a Join button (the same shell, everybody
// sees and types), a sub-tab or a window shows how many viewers its session has.  An instructor
// on a student's project joins the student's terminals by default when the tab opens, and can
// open private terminals the student does not see (the selects offer both kinds).
//
// The agent keeps a session for a while after its last browser left (a page closed, reloaded
// or cut, another project opened: `terminals_linger` of agent.toml), so the page coming back
// joins the user's own sessions again (resumeOwn, at the first list of the project), each
// where it was on this browser: a sub-tab, or a window at its place, with its title (the
// layouts are kept in localStorage by session id).  The × of a sub-tab or of a window tells
// the agent to end the session at once (TerminalSession.close({end: true})).  The browser
// keeps a page it navigated away from in its back/forward cache with its sockets open: the
// sockets are closed on pagehide (the sessions linger on the agent) and the same sessions
// joined again on a pageshow from the cache (the Back button).
//
// On the page of a spectator of a presentation (ctx.spectator) nothing can be opened or closed:
// the sub-tabs and the windows are those of the presenter's page (setView, read-only sessions
// joined by their id, the windows at the same relative place and size), the active one follows;
// on the presenter's page every change calls ctx.onViewChange().

import * as settings from '../settings.js';
import {el, clear} from '../ui.js';
import {_, format} from '../i18n.js';
import {TerminalSession} from '../terminal.js';
import {createTerminalWindows, parseFloating} from '../terminal_windows.js';

export function createTerminalsTab(ctx) {
  const spectator = Boolean(ctx.spectator);
  const tabs = el('div', {class: 'terminal-tabs', role: 'tablist'});
  const newSelect = el('select', {class: 'new-terminal', title: _('New terminal…')});
  const newWindowSelect = el('select', {class: 'new-terminal new-window', title: _('New window…')});
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
  const bar = el('div', {class: 'ctrl-bar'}, tabs, newSelect, newWindowSelect, el('span', {class: 'spacer'}),
    schemeSelect, smaller, larger);
  const pane = el('div', {class: 'pane no-scroll'}, el('div', {class: 'terminals'}, bar, live, host));
  newSelect.hidden = spectator;
  newWindowSelect.hidden = spectator;
  live.hidden = spectator;
  // the layer of the floating windows, appended to #panes by project.js (tab.overlay): a
  // spectator's windows are read-only and placed by the presenter's fractions
  const windows = createTerminalWindows({readonly: spectator, onChange: notify});

  // id -> {id, device, title, box, tab, badge, session, remoteId, private, mode, win}, in opening
  // order; mode 'tab' (a sub-tab, the box in the host) or 'window' (the box in a floating window,
  // win its handle)
  const sessions = new Map();
  const counters = new Map();   // device -> number of terminals opened on it so far (the titles)
  let nextId = 1;
  let devices = [];
  let debug = false;
  let current = null;           // the id of the docked terminal shown in the host (null: none docked)
  let lastFocused = null;       // the id of the terminal the user last went to, docked or floating
  let remote = [];              // the live sessions of the project (setSessions): {id, device, created_by, private, clients}
  const dismissed = new Set();  // the remote sessions the user closed here: never joined again by themselves
  let shown = false;            // the tab has been shown at least once
  // an instructor on somebody else's project (project.js): joins the owner's terminals, opens
  // private ones
  const helper = Boolean(ctx.helper);
  let resumed = false;          // the page's own sessions joined again (the first list of the project)

  // -- the layout of the terminals across the pages of this browser: where each session was
  // (a sub-tab, or a window at its place) and its title, by session id, so that a page coming
  // back to the project finds its terminals where they were; never on a spectator's page
  const LAYOUT_KEY = 'sreweb.terminal_layouts';
  const LAYOUT_MAX_AGE = 2 * 24 * 3600 * 1000;    // ms: the entries of sessions long gone are dropped
  const SAVE_DELAY = 300;                          // ms: the layouts are written after a pause
  let layouts = loadLayouts();
  let saveTimer = null;

  function loadLayouts() {
    try {
      const stored = JSON.parse(window.localStorage.getItem(LAYOUT_KEY) || '{}');
      const now = Date.now();
      const kept = {};
      for (const [id, layout] of Object.entries(stored && typeof stored === 'object' ? stored : {})) {
        if (layout && typeof layout === 'object' && now - (Number(layout.t) || 0) < LAYOUT_MAX_AGE) {
          kept[id] = layout;
        }
      }
      return kept;
    } catch (e) {
      return {};
    }
  }

  function saveLayouts() {
    saveTimer = null;
    const now = Date.now();
    for (const entry of sessions.values()) {
      if (entry.remoteId) {
        layouts[entry.remoteId] = {mode: entry.mode, title: entry.title, t: now,
                                   floating: entry.mode === 'window' && entry.win ? entry.win.fractions() : null};
      }
    }
    try {
      window.localStorage.setItem(LAYOUT_KEY, JSON.stringify(layouts));
    } catch (e) {
      // private browsing: the layouts last for the page only
    }
  }

  function scheduleSave() {
    if (spectator) {
      return;
    }
    if (saveTimer !== null) {
      window.clearTimeout(saveTimer);
    }
    saveTimer = window.setTimeout(saveLayouts, SAVE_DELAY);
  }

  // the page leaves: the layouts written now, the sockets closed (the agent keeps the sessions
  // for a while; a page the browser keeps in its back/forward cache would otherwise hold them
  // open); back from that cache, the same sessions are joined again
  window.addEventListener('pagehide', () => {
    if (!spectator && saveTimer !== null) {
      window.clearTimeout(saveTimer);
      saveLayouts();
    }
    for (const entry of sessions.values()) {
      entry.session.disconnect();
    }
  });
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      for (const entry of sessions.values()) {
        entry.session.rejoin();
      }
    }
  });

  // the sub-tabs or the windows changed: the layouts are saved; on the presenter's page the
  // view is published to the spectators
  function notify() {
    scheduleSave();
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

  // what the student may open themself: a device they see with allow_connection (every one of a
  // debug project, the hidden machines apart, which the agent never shows them).  An
  // instructor's terminal on any other device is made private by the agent whatever the page
  // asks: a shared session is joined without the device check.
  function openToStudent(device) {
    return Boolean(!device.hidden && (device.allow_connection || debug));
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

  // a select opening a new terminal on a device (two kinds for a helping instructor): the same
  // list for the sub-tabs and for the windows
  function fillSelect(select, placeholder) {
    clear(select);
    select.append(el('option', {value: ''}, placeholder));
    const options = (prefix) => devices.map((device) => {
      const option = el('option', {value: prefix + device.name, class: deviceClass(device)}, device.name);
      option.disabled = !canOpen(device) || (prefix === 'shared:' && !openToStudent(device));
      if (prefix === 'shared:' && canOpen(device) && !openToStudent(device)) {
        option.title = _('Closed to the student: private terminal only');
      }
      return option;
    });
    if (helper) {
      select.append(el('optgroup', {label: _('Private terminal (the student does not see it)')}, ...options('private:')));
      select.append(el('optgroup', {label: _('Shared terminal (the student can join it)')}, ...options('shared:')));
    } else {
      select.append(...options(''));
    }
    select.value = '';
  }
  function renderSelect() {
    fillSelect(newSelect, _('New terminal…'));
    fillSelect(newWindowSelect, _('New window…'));
  }
  // the value of an option: the device and the kind of session
  function choiceOf(value) {
    if (value.startsWith('private:')) {
      return {name: value.slice('private:'.length), priv: true};
    }
    if (value.startsWith('shared:')) {
      return {name: value.slice('shared:'.length), priv: false};
    }
    return {name: value, priv: false};
  }
  for (const select of [newSelect, newWindowSelect]) {
    select.addEventListener('change', () => {
      const value = select.value;
      select.value = '';
      if (value) {
        const {name, priv} = choiceOf(value);
        openNew(name, {priv, floating: select === newWindowSelect});
      }
    });
  }

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
    const popout = el('span', {class: 'popout', role: 'button', title: _('Open in a window'),
      'aria-label': _('Open in a window')}, '⧉');
    popout.addEventListener('click', (event) => {
      event.stopPropagation();
      undock(entry.id);
    });
    const close = el('span', {class: 'close', role: 'button', title: _('Close terminal'),
      'aria-label': _('Close terminal')}, '×');
    close.addEventListener('click', (event) => {
      event.stopPropagation();
      closeSession(entry.id);
    });
    button.append(popout, close);
    button.addEventListener('click', () => select(entry.id));
    return button;
  }

  // the terminal the user goes to: a window is raised, a sub-tab shown in the host (the other
  // sub-tabs hidden); the keyboard focus goes to it
  function select(id) {
    const entry = sessions.get(id);
    if (!entry) {
      return;
    }
    if (entry.mode === 'window') {
      entry.win.raise();
      if (!spectator) {
        entry.session.focus();
      }
      focused(entry);
      return;
    }
    current = id;
    for (const other of sessions.values()) {
      if (other.mode !== 'tab') {
        continue;
      }
      other.box.hidden = other !== entry;
      other.tab.setAttribute('aria-selected', other === entry ? 'true' : 'false');
    }
    entry.session.refit();
    if (!spectator) {
      entry.session.focus();
    }
    focused(entry);
  }

  // the terminal last gone to, docked or floating: the active one of the presenter's view and
  // the target of a focus
  function focused(entry) {
    lastFocused = entry.id;
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

  // the title of a terminal, on its sub-tab (the text before the badge) and on its window
  function setTitle(entry, title) {
    entry.title = title;
    if (entry.tab && entry.tab.firstChild) {
      entry.tab.firstChild.textContent = title;
    }
    if (entry.win) {
      entry.win.setTitle(title);
    }
  }

  // the viewer count of a sub-tab or a window (the session is shared when it is above one): the
  // browsers typing in it and the read-only spectators of a presentation
  function updateBadge(entry) {
    const r = remoteOf(entry);
    const n = r ? (Number(r.clients) || 0) + (Number(r.viewers) || 0) : (entry.session.clients || 0);
    const text = n > 1 ? `(${n})` : '';
    const tooltip = n > 1 ? format(_('{n} viewers'), {n}) : '';
    entry.badge.textContent = text;
    entry.badge.title = tooltip;
    if (entry.win) {
      entry.win.setViewers(text, tooltip);
    }
  }

  function attachedIds() {
    return new Set([...sessions.values()].map((e) => e.remoteId).filter(Boolean));
  }

  // the ids of the docked terminals, in opening order (the neighbours of a sub-tab)
  function dockedIds() {
    return [...sessions.values()].filter((e) => e.mode === 'tab').map((e) => e.id);
  }

  // the sub-tab next to the one at index in ids (the one after, else the one before) shown
  function showNeighbour(ids, index) {
    const neighbour = sessions.has(ids[index + 1]) ? ids[index + 1] : ids[index - 1];
    if (neighbour !== undefined && sessions.has(neighbour)) {
      select(neighbour);
    }
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
        format(_('Join {device} ({who})'), {device: r.device, who}) + (r.private ? ' · ' + _('private') : '')
        + (r.lingering ? ' · ' + _('idle') : ''));
      button.addEventListener('click', () => join(r));
      live.append(button);
    }
  }

  // a new terminal on a device (or, with join, one more viewer of a live session): a new box, a
  // new WebSocket, and a new sub-tab, or a floating window (floating: true for the cascade, a
  // spectator's fractions to place it)
  function openNew(name, {join: joinId = null, priv = false, title = null, floating = null} = {}) {
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
                   remoteId: joinId, private: priv, mode: 'tab', win: null};
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
        if (info.private && !entry.private) {
          // the agent made it private: a device the student may not open (see openToStudent)
          entry.private = true;
          setTitle(entry, format(_('{title} (private)'), {title: entry.title}));
        }
        updateBadge(entry);
        renderLive();
        notify();         // the session id is known: the spectators can join it
      },
    });
    entry.session = session;
    entry.tab = makeTab(entry);
    sessions.set(id, entry);
    if (floating) {
      // laid out before connect(): the size of the box gives the cols / rows of the socket
      undock(id, floating === true ? null : floating);
    } else {
      tabs.append(entry.tab);
      select(id);
    }
    session.connect();
    renderLive();
    return entry;
  }

  function join(r) {
    const who = r.created_by === ctx.login ? null : r.created_by;
    const title = who ? format(_('{device} ({who})'), {device: r.device, who}) : titleFor(r.device);
    openNew(r.device, {join: r.id, title});
  }

  // the × of a sub-tab or of a window (or a device gone from the project): the agent is told the
  // user closed it, so that `sre connect` ends on the host at once when nobody else is attached
  // (a session nobody closed is kept for a while for a page to come back to it); the
  // neighbouring sub-tab is shown
  function closeSession(id) {
    const entry = sessions.get(id);
    if (!entry) {
      return;
    }
    if (entry.remoteId) {
      dismissed.add(entry.remoteId);
      delete layouts[entry.remoteId];
    }
    const docked = dockedIds();
    const index = docked.indexOf(id);
    entry.session.close({end: true});
    if (entry.win) {
      entry.win.close();
      entry.win = null;
    }
    entry.box.remove();
    entry.tab.remove();
    sessions.delete(id);
    if (lastFocused === id) {
      lastFocused = null;
    }
    if (current === id) {
      current = null;
      showNeighbour(docked, index);
    }
    renderLive();
    notify();
  }

  // the ⧉ of a sub-tab (or a terminal opened in a window): the box of the xterm moves into a
  // floating window (placed by fractions when a spectator's view gives them), the neighbouring
  // sub-tab is shown; the shell goes on
  function undock(id, fractions = null) {
    const entry = sessions.get(id);
    if (!entry || entry.mode !== 'tab') {
      return;
    }
    const docked = dockedIds();
    const index = docked.indexOf(id);
    entry.mode = 'window';
    entry.tab.remove();
    entry.box.hidden = false;
    entry.win = windows.open(entry.box, {
      title: entry.title,
      className: deviceClass(deviceOf(entry.device)),
      fractions,
      fontSize: settings.get('terminal_font_size'),
      onDock: () => dock(id),
      onClose: () => closeSession(id),
      onFocus: () => focused(entry),
    });
    updateBadge(entry);
    if (current === id) {
      current = null;
      showNeighbour(docked, index);
    }
    entry.session.moved();
    focused(entry);
  }

  // the dock button of a window: the box goes back into the host as a sub-tab, shown
  function dock(id) {
    const entry = sessions.get(id);
    if (!entry || entry.mode !== 'window') {
      return;
    }
    entry.mode = 'tab';
    entry.win.close();
    entry.win = null;
    host.append(entry.box);
    tabs.append(entry.tab);
    updateBadge(entry);
    entry.session.moved();
    if (!spectator) {
      ctx.selectTab('terminals');
    }
    select(id);
  }

  // -- the presenter's view of the sub-tabs and the windows, and a spectator following it ------
  function getView() {
    const open = [...sessions.values()].filter((e) => e.remoteId).map((e) => {
      const item = {id: e.remoteId, device: e.device, title: e.title};
      if (e.mode === 'window') {
        const floating = e.win.fractions();
        if (floating) {
          item.floating = floating;
        }
      }
      return item;
    });
    const entry = lastFocused !== null ? sessions.get(lastFocused) : null;
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
      const floating = parseFloating(o.floating);    // a window of the presenter's, placed like it
      let entry = byRemote.get(o.id);
      if (!entry) {
        entry = openNew(o.device, {join: o.id, title: o.title || o.device, floating});
        if (entry) {
          byRemote.set(o.id, entry);
        }
      } else if (floating && entry.mode === 'tab') {
        undock(entry.id, floating);
      } else if (!floating && entry.mode === 'window') {
        dock(entry.id);
      } else if (floating) {
        entry.win.setFractions(floating);
      }
    }
    for (const o of open) {              // the order of the presenter's sub-tabs
      const entry = byRemote.get(o.id);
      if (entry && entry.mode === 'tab') {
        tabs.append(entry.tab);
      }
    }
    const active = view && view.active ? byRemote.get(view.active) : null;
    if (active) {
      select(active.id);
    }
  }

  // -- a focus (focus.js): the terminal the user last went to, sub-tab or window, shared with
  // the other page by the id of its session.  Never a private terminal: the student must not see
  // nor join one.
  function focusTarget() {
    const entry = lastFocused !== null ? sessions.get(lastFocused) : null;
    return entry && entry.remoteId && !isPrivate(entry) ? entry.remoteId : null;
  }

  // the terminal the other page shows: shown (a window raised) when it is open here, joined as
  // a sub-tab when it is a live session of the project this page may see (never a private one),
  // else kept until the terminals event lists it
  let wantedSession = null;
  function focusSession(remoteId) {
    if (!remoteId) {
      return;
    }
    const entry = [...sessions.values()].find((e) => e.remoteId === remoteId);
    if (entry) {
      wantedSession = null;
      if (entry.mode === 'window' || current !== entry.id) {
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

  // the page's own terminals, as the first list of the project gives them: the sessions this
  // login opened (kept by the agent for a while after their last browser left), joined again
  // where they were on this browser (a sub-tab, or a window at its place, the title kept), in
  // their order; the later lists never join by themselves (a session opened from another
  // browser of the same login stays a Join button)
  function resumeOwn() {
    if (resumed || spectator) {
      return;
    }
    resumed = true;
    const attached = attachedIds();
    for (const r of remote) {
      if (r.created_by !== ctx.login || attached.has(r.id)) {
        continue;
      }
      const layout = layouts[r.id];
      const stored = layout && typeof layout.title === 'string' ? layout.title : '';
      const title = titleFor(r.device);       // the counter of the device advances
      const floating = layout && layout.mode === 'window' ? (parseFloating(layout.floating) || true) : null;
      openNew(r.device, {join: r.id, title: stored || title, priv: !stored && Boolean(r.private), floating});
    }
  }

  return {
    id: 'terminals',
    element: pane,
    // the layer of the floating windows, over every pane (project.js appends it to #panes)
    overlay: windows.element,
    // autoOpen false: the tab is shown by a focus (the other page went there), not by the
    // user: no terminal is opened for them (the instructor's new terminal, a private one say,
    // would otherwise be echoed by a terminal of the student's own on the first machine).  A
    // floating window is a session too: nothing is opened while one exists.
    show({autoOpen = true} = {}) {
      shown = true;
      if (current !== null) {
        select(current);
      } else if (spectator) {
        // the presenter's view says what is open: nothing by itself
      } else if (sessions.size === 0) {
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
      resumeOwn();
      for (const entry of sessions.values()) {
        updateBadge(entry);
      }
      renderLive();
      autoJoin();
      if (wantedSession) {
        focusSession(wantedSession);
      }
    },
    // the Connect buttons of the Machines / Networks tabs: a new terminal every time, in a
    // floating window over the page whatever the tab shown, like the external xterm of the Qt
    // GUI (a private one for a helping instructor)
    openWindow(name) {
      openNew(name, {priv: helper, floating: true});
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
