// The web conference a page takes part in (BigBlueButton): the push of the presence socket
// ({t: 'webconf', id, name, owner, role, join_url}, handed over by base.js) shows the BBB client
// in one iframe, never reloaded while the user changes how it is shown.  The iframe is fixed
// over the page and placed over a *slot*: the body of a floating window (the chrome of
// terminal_windows.js in a layer over the whole page), the Webconf tab of the project page
// (tabs/webconf.js registers its slot with setTabHost), or the viewport under a thin bar (full
// mode); it is hidden, alive, while its slot is not shown (the title bar alone when minimized,
// another tab shown).  The user may also pop the client out to a separate browser window, or
// leave: a pill in the site bar then offers to come back.  The mode and the place of the window
// are kept in localStorage (webconf_model.js: the state machine, the storage format), so that the
// next page of the site shows the conference as the previous one did; a page change reloads the
// client (a new join), which a multi-page site cannot avoid.  The {t: 'webconf', id, ended: true}
// push removes everything.  The client's own Leave meeting button lands on /webconf/left, which
// tells this page (postMessage {t: 'webconf-left'}: webconf_left.js).  Two tabs of the same user
// would join twice: the tabs talk over a BroadcastChannel (open while a conference exists, closed
// on pagehide: an open channel keeps a page out of the back/forward cache) and only one holds the
// client, the others show a pill to bring it there.  Nothing here runs in the iframe of a
// presentation (base.js).

import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, toast} from './ui.js';
import {createTerminalWindows} from './terminal_windows.js';
import * as M from './webconf_model.js';

export const FULLBAR_HEIGHT = 32;        // px: the bar over the client in full mode (sre.css)
const SAVE_DELAY = 300;                  // ms: the geometry is written after a pause
const CLAIM_DELAY = 300;                 // ms: a new page waits that long for another tab holding the client
const CHANNEL = 'sreweb.webconf.tabs';
const POPUP_FEATURES = 'popup,width=1100,height=750';
const ALLOW = 'camera *; microphone *; display-capture *; fullscreen; autoplay';

const body = document.body;
let ready = null;          // the catalog loaded (setup)
let state = null;          // the state of webconf_model.js
let layer = null;          // the layer of the window (createTerminalWindows)
let slot = null;           // the body of the window: the iframe is placed over it
let handle = null;         // the window
let fullbar = null;        // {element, title, tab}: the bar of the full mode
let frame = null;          // the iframe
let pill = null;           // the pill of the site bar
let host = null;           // the Webconf tab of the project page: {slot, select(), onAvailable(live)}
let hostObserver = null;
let popup = null;          // the popped-out window
let saveTimer = null;
let channel = null;        // the BroadcastChannel of the tabs of this browser
let claim = null;          // {id, held: true | false | null (asked, waiting), timer}

export function setup() {
  if (ready) {
    return;
  }
  ready = i18n.init();
  window.addEventListener('message', onMessage);
  window.addEventListener('resize', place);
  window.addEventListener('pagehide', () => {
    flushSave();
    closeChannel();
  });
  window.addEventListener('pageshow', (ev) => {
    if (ev.persisted && state) {
      openChannel();
    }
  });
}

// A push of the presence socket.
export async function onPush(message) {
  if (!ready) {
    setup();
  }
  await ready;
  if (!message || typeof message !== 'object') {
    return;
  }
  if (message.ended) {
    if (state && state.id === message.id) {
      const name = state.name;
      apply(null);
      toast(format(_('The conference {name} has ended'), {name}));
    }
    return;
  }
  const room = M.roomOf(message);
  if (room) {
    apply(M.nextState(state, {type: 'push', room, stored: readStored()}));
  }
}

// The Webconf tab of the project page (tabs/webconf.js): {slot, select(), onAvailable(live)},
// or null when the page is over.
export function setTabHost(newHost) {
  if (hostObserver) {
    hostObserver.disconnect();
    hostObserver = null;
  }
  host = newHost;
  if (host && typeof ResizeObserver === 'function') {
    hostObserver = new ResizeObserver(() => place());
    hostObserver.observe(host.slot);
  }
  if (state) {
    apply(state);
  }
}

export function current() {
  return state;
}

// An action of the user (the buttons of the window, of the full bar, of the tab, of the pill).
export function act(type, detail) {
  if (!state) {
    return;
  }
  if (type === 'popout') {
    // synchronously in the click: the popup blockers
    const opened = window.open(state.joinUrl, 'sre-webconf-' + state.id, POPUP_FEATURES);
    if (!opened) {
      toast(_('The browser blocked the separate window.'), {error: true});
      return;
    }
    popup = opened;
  }
  const next = M.nextState(state, {type, ...(detail || {})});
  if (next === state) {
    return;
  }
  apply(next);
  if (type === 'dock' && host) {
    host.select();
  }
}

// -- the rendering -----------------------------------------------------------------------------

function titleOf(room) {
  if (room.role === 'viewer') {
    return format(_('{name} ({owner})'), {name: room.name, owner: room.owner.fullname || room.owner.login});
  }
  return room.name;
}

// The one place the page is made to match the state.
function apply(next) {
  const previous = state;
  state = next;
  if (previous && (!next || previous.id !== next.id)) {
    teardown();
  }
  if (!next) {
    writeStored();
    closeChannel();
    return;
  }
  openChannel();
  const mode = M.effectiveMode(next, {hasTabHost: Boolean(host)});
  const live = M.isLive(mode);
  const held = live ? holding(next.id) : null;     // true, false (another tab has it), null (asked)
  ensureLayer();
  if (live && held === true) {
    ensureFrame(next.joinUrl);
  } else {
    removeFrame();
  }
  const windowed = held === true && (mode === M.MODE_WINDOW || mode === M.MODE_MINIMIZED);
  if (windowed) {
    ensureWindow(next);
    handle.element.hidden = false;
    const minimized = mode === M.MODE_MINIMIZED;
    handle.element.classList.toggle('minimized', minimized);
    handle.setTitle(titleOf(next));
    handle.buttons.minimize.title = minimized ? _('Restore') : _('Minimize');
    handle.buttons.minimize.textContent = minimized ? '▫' : '–';
    handle.buttons.dock.hidden = !host;
  } else if (handle) {
    handle.element.hidden = true;
  }
  const full = held === true && mode === M.MODE_FULL;
  fullbar.element.hidden = !full;
  fullbar.title.textContent = titleOf(next);
  fullbar.tab.hidden = !host;
  body.classList.toggle('has-webconf-full', full);
  if (held === false) {
    showPill('elsewhere', next);
  } else if (mode === M.MODE_LEFT) {
    showPill('left', next);
  } else if (mode === M.MODE_POPOUT) {
    showPill('popout', next);
  } else {
    removePill();
  }
  if (host) {
    host.onAvailable(live && held === true);
  }
  writeStored();
  place();
}

function teardown() {
  removeFrame();
  if (handle) {
    handle.close();
    handle = null;
  }
  if (fullbar) {
    fullbar.element.hidden = true;
  }
  body.classList.remove('has-webconf-full');
  removePill();
  if (host) {
    host.onAvailable(false);
  }
  if (claim && claim.timer !== null) {
    window.clearTimeout(claim.timer);
  }
  claim = null;
}

function ensureLayer() {
  if (layer) {
    return;
  }
  layer = createTerminalWindows({onChange: () => {
    scheduleSave();
    place();
  }});
  layer.element.id = 'webconf-layer';
  fullbar = createFullbar();
  layer.element.append(fullbar.element);
  body.append(layer.element);
  slot = el('div', {class: 'webconf-slot'});
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(() => place()).observe(slot);
  }
}

function createFullbar() {
  const title = el('span', {class: 'title'});
  const windowButton = el('button', {type: 'button', title: _('Back to a window')}, '▢');
  const tab = el('button', {type: 'button', title: _('Show in the Webconf tab')}, '⇲');
  const leave = el('button', {type: 'button', class: 'danger'}, _('Leave the conference'));
  windowButton.addEventListener('click', () => act('window'));
  tab.addEventListener('click', () => act('dock'));
  leave.addEventListener('click', () => act('leave'));
  const element = el('div', {class: 'webconf-fullbar'}, title, windowButton, tab, leave);
  element.hidden = true;
  return {element, title, tab};
}

function ensureWindow(room) {
  if (handle) {
    return;
  }
  const area = {width: layer.element.clientWidth, height: layer.element.clientHeight};
  handle = layer.open(slot, {
    title: titleOf(room), className: 'webconf', mins: M.WEBCONF_MINS, size: M.defaultWindowSize(area),
    fractions: room.fractions || M.defaultWindowFractions(area),
    buttons: [
      {name: 'minimize', label: '–', title: _('Minimize'),
       onClick: () => act(state && state.mode === M.MODE_MINIMIZED ? 'restore' : 'minimize')},
      {name: 'dock', label: '⇲', title: _('Dock into the Webconf tab'), onClick: () => act('dock')},
      {name: 'full', label: '⛶', title: _('Full screen'), onClick: () => act('full')},
      {name: 'popout', label: '⧉', title: _('Open in a separate browser window'), onClick: () => act('popout')},
      {name: 'close', label: '×', title: _('Leave the conference'), onClick: () => act('leave')},
    ],
    onMove: () => place(),
  });
}

function ensureFrame(url) {
  if (frame) {
    return;
  }
  frame = el('iframe', {id: 'webconf-frame', src: url, allow: ALLOW, allowfullscreen: true, title: _('Web conference')});
  frame.style.visibility = 'hidden';
  body.append(frame);
}

function removeFrame() {
  if (frame) {
    frame.remove();
    frame = null;
  }
}

// The iframe over the slot of the mode shown: the window's body, the tab's slot, the viewport
// under the full bar; hidden (never 0 × 0) while the slot is not shown.  Called after every
// move or resize of a slot, of the window, of the viewport.
function place() {
  if (!frame || !state) {
    return;
  }
  const mode = M.effectiveMode(state, {hasTabHost: Boolean(host)});
  let rect = null;
  if (mode === M.MODE_WINDOW && handle && !handle.element.hidden) {
    rect = rectOf(slot);
  } else if (mode === M.MODE_TAB && host) {
    rect = rectOf(host.slot);
  } else if (mode === M.MODE_FULL) {
    rect = M.fullRect({width: window.innerWidth, height: window.innerHeight}, FULLBAR_HEIGHT);
  }
  if (!rect || !(rect.w > 0 && rect.h > 0)) {
    frame.style.visibility = 'hidden';
    return;
  }
  frame.style.left = `${rect.x}px`;
  frame.style.top = `${rect.y}px`;
  frame.style.width = `${rect.w}px`;
  frame.style.height = `${rect.h}px`;
  frame.style.visibility = '';
  // the pointer stays with the title bar while the window is dragged over the iframe
  frame.classList.toggle('dragging', Boolean(handle) && handle.element.classList.contains('dragging'));
}

function rectOf(element) {
  const r = element.getBoundingClientRect();
  return {x: r.left, y: r.top, w: r.width, h: r.height};
}

// -- the pill of the site bar --------------------------------------------------------------------

function showPill(kind, room) {
  removePill();
  let text;
  let label;
  let action;
  if (kind === 'left') {
    text = format(_('Webconf: {name}'), {name: room.name});
    label = _('Rejoin');
    action = () => act('window');
  } else if (kind === 'popout') {
    text = _('Webconf in a separate window');
    label = _('Bring back');
    action = () => act('window');
  } else {
    text = _('Webconf open in another tab');
    label = _('Bring here');
    action = take;
  }
  const button = el('button', {type: 'button'}, label);
  button.addEventListener('click', action);
  pill = el('span', {id: 'webconf-pill', class: `webconf-pill ${kind}`}, el('span', {}, text), button);
  const nav = document.querySelector('header.topbar .topbar-nav');
  (nav || body).append(pill);
}

function removePill() {
  if (pill) {
    pill.remove();
    pill = null;
  }
}

// -- the client's Leave meeting ------------------------------------------------------------------

function onMessage(ev) {
  if (ev.origin !== window.location.origin || !state || !ev.data || ev.data.t !== 'webconf-left' || ev.data.id !== state.id) {
    return;
  }
  const fromFrame = frame !== null && ev.source === frame.contentWindow;
  const fromPopup = popup !== null && ev.source === popup;
  if (fromFrame || fromPopup) {
    act('left-page');
  }
}

// -- the storage -------------------------------------------------------------------------------

function readStored() {
  try {
    return M.parseStored(window.localStorage.getItem(M.STORAGE_KEY), Date.now());
  } catch (e) {
    return null;
  }
}

function writeStored() {
  try {
    if (state) {
      window.localStorage.setItem(M.STORAGE_KEY, JSON.stringify(M.storedOf(state, Date.now())));
    } else {
      window.localStorage.removeItem(M.STORAGE_KEY);
    }
  } catch (e) {
    // private browsing: the state lasts for the page only
  }
}

function scheduleSave() {
  if (saveTimer !== null) {
    window.clearTimeout(saveTimer);
  }
  saveTimer = window.setTimeout(flushSave, SAVE_DELAY);
}

// The geometry of the window into the state (a window, not minimized: the collapsed rect is not
// a place) and the storage.
function flushSave() {
  if (saveTimer !== null) {
    window.clearTimeout(saveTimer);
    saveTimer = null;
  }
  if (handle && state && state.mode === M.MODE_WINDOW && !handle.element.hidden) {
    const fractions = handle.fractions();
    if (fractions) {
      state = M.nextState(state, {type: 'moved', fractions});
    }
  }
  writeStored();
}

// -- the other tabs of this browser ---------------------------------------------------------------

function openChannel() {
  if (channel || typeof BroadcastChannel !== 'function') {
    return;
  }
  channel = new BroadcastChannel(CHANNEL);
  channel.addEventListener('message', onChannel);
}

function closeChannel() {
  if (channel) {
    channel.close();
    channel = null;
  }
}

// Whether this page holds the client of the room: asked once per room to the other tabs; true
// after CLAIM_DELAY unless one answers that it holds it (false then: the pill offers to bring it
// here); null while waiting.
function holding(id) {
  if (!claim || claim.id !== id) {
    claim = {id, held: null, timer: null};
    if (channel) {
      channel.postMessage({t: 'who', id});
      claim.timer = window.setTimeout(() => {
        if (claim && claim.id === id && claim.held === null) {
          claim.held = true;
          apply(state);
        }
      }, CLAIM_DELAY);
    } else {
      claim.held = true;
    }
  }
  return claim.held;
}

function onChannel(ev) {
  const message = ev.data;
  if (!message || !state || !claim || message.id !== state.id) {
    return;
  }
  if (message.t === 'who' && claim.held === true) {
    channel.postMessage({t: 'holder', id: state.id});
  } else if (message.t === 'holder' && claim.held !== true) {
    if (claim.timer !== null) {
      window.clearTimeout(claim.timer);
      claim.timer = null;
    }
    claim.held = false;
    apply(state);
  } else if (message.t === 'take' && claim.held === true) {
    claim.held = false;
    apply(state);
  }
}

// The Bring here of the pill: this page takes the client from the tab holding it.
function take() {
  if (!state) {
    return;
  }
  if (!claim || claim.id !== state.id) {
    claim = {id: state.id, held: null, timer: null};
  }
  claim.held = true;
  if (channel) {
    channel.postMessage({t: 'take', id: state.id});
  }
  apply(state);
}
