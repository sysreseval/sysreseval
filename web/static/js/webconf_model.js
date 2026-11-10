// The state of the web conference a page shows (webconf.js): a pure module, no DOM, run under
// node / bun by tests/test_web_templates.py.  The room comes from the push of the presence
// socket ({t: 'webconf', id, name, owner, role, join_url}); the user chooses how the BBB client
// is shown — a floating window (the default), minimized to its title bar, docked in the Webconf
// tab of the project page, full page, popped out to a separate browser window, or left (a pill
// to rejoin) — and the mode and the geometry of the window are kept in localStorage, so that the
// next page of the site shows the conference as the previous one did.
//
// A *private conversation* (a push with kind: 'private', peer: the other one, tab: the browser
// tab that shows it) takes the user out of their class conference for a while: its state takes
// the mode and the place of the conference it replaces and remembers them (`back`), so that the
// class conference comes back as it was when the conversation ends; it is never left (leaving is
// ending it, which the page asks the portal).  Class rooms carry no `kind`.

import {clampRect, parseFloating, toFractions} from './terminal_windows.js';

export const MODE_WINDOW = 'window';
export const MODE_MINIMIZED = 'minimized';
export const MODE_TAB = 'tab';
export const MODE_FULL = 'full';
export const MODE_POPOUT = 'popout';
export const MODE_LEFT = 'left';
export const MODES = [MODE_WINDOW, MODE_MINIMIZED, MODE_TAB, MODE_FULL, MODE_POPOUT, MODE_LEFT];
export const LIVE_MODES = [MODE_WINDOW, MODE_MINIMIZED, MODE_TAB, MODE_FULL];   // the iframe exists
export const STORAGE_KEY = 'sreweb.webconf';
export const STORED_MAX_AGE = 2 * 24 * 3600 * 1000;    // ms: a state stored longer ago is dropped
export const WEBCONF_MINS = {minWidth: 320, minHeight: 200};   // px: the smallest window
export const MAX_WINDOW = {w: 640, h: 480};             // px: the default window at most
export const WINDOW_FRACTION = 0.6;                     // of the layer: the default window at most
export const WINDOW_MARGIN = 16;                        // px: from the bottom-right corner
export const KIND_PRIVATE = 'private';                  // the kind of the room of a private conversation
const ROLES = ['moderator', 'viewer'];
const JOIN_PREFIX = '/api/webconfs/';
const PRIVATE_MODES = [MODE_WINDOW, MODE_TAB, MODE_FULL];   // what a conversation takes from the conference it replaces

function person(value) {
  const who = value && typeof value === 'object' ? value : {};
  return {login: typeof who.login === 'string' ? who.login : '', fullname: typeof who.fullname === 'string' ? who.fullname : ''};
}

// The room of a push: {id, name, owner: {login, fullname}, role, joinUrl}, or null when the
// message is not one (a malformed push shows nothing); a private conversation also has kind,
// peer: {login, fullname} (the other one) and tab (the browser tab that shows it, '' unknown).
export function roomOf(message) {
  if (!message || typeof message !== 'object' || typeof message.id !== 'string' || !message.id) {
    return null;
  }
  if (typeof message.join_url !== 'string' || !message.join_url.startsWith(JOIN_PREFIX)) {
    return null;
  }
  const room = {
    id: message.id,
    name: typeof message.name === 'string' ? message.name : '',
    owner: person(message.owner),
    role: ROLES.includes(message.role) ? message.role : 'viewer',
    joinUrl: message.join_url,
  };
  if (message.kind === KIND_PRIVATE) {
    room.kind = KIND_PRIVATE;
    room.peer = person(message.peer);
    room.tab = typeof message.tab === 'string' ? message.tab : '';
  }
  return room;
}

export function isLive(mode) {
  return LIVE_MODES.includes(mode);
}

// Whether a room, a state or a stored state is a private conversation.
export function isPrivate(room) {
  return Boolean(room) && room.kind === KIND_PRIVATE;
}

// What a conference that is over leaves in the storage: the conference its state (or its stored
// state) had replaced, as it was, or null.  The next push of that conference restores it.
export function backStored(state) {
  const back = state && state.back;
  return back ? {id: back.id, mode: back.mode, fractions: back.fractions || null} : null;
}

// Two pages told of a room at the same moment both ask who holds its client: the claim of the
// page that held the previous client comes first, then a visible page, then the tab ids decide.
// A rank: {held, visible, tab}.
export function outranks(a, b) {
  if (!a) {
    return false;
  }
  if (!b) {
    return true;
  }
  if (Boolean(a.held) !== Boolean(b.held)) {
    return Boolean(a.held);
  }
  if (Boolean(a.visible) !== Boolean(b.visible)) {
    return Boolean(a.visible);
  }
  return String(a.tab || '') > String(b.tab || '');
}

// The state after an action: null (no conference) or {id, name, owner, role, joinUrl, mode,
// fractions} (+ kind, peer, tab, back for a private conversation).  Actions: {type: 'push', room,
// stored} (a new room starts in a window, or as the stored state of the same room says; the same
// room again keeps its mode; a private conversation takes the mode and the place of the stored
// conference it replaces, kept as `back`; the conference a stored conversation had replaced
// comes back as it was), {type: 'ended', id}, the modes ('minimize', 'restore', 'dock', 'undock',
// 'full', 'window' — the Rejoin / Bring back of a left or popped-out conference too —, 'popout',
// 'leave', 'left-page': the client's own Leave meeting; neither applies to a private
// conversation), {type: 'moved', fractions}.  The same state comes back when the action does not
// apply.
export function nextState(state, action) {
  if (!action || typeof action !== 'object') {
    return state;
  }
  if (action.type === 'push') {
    const room = action.room;
    if (!room) {
      return state;
    }
    if (state && state.id === room.id) {
      return {...state, ...room};
    }
    const stored = action.stored || null;
    if (stored && stored.id === room.id) {
      const same = {...room, mode: stored.mode, fractions: stored.fractions};
      if (stored.back) {
        same.back = stored.back;
      }
      return same;
    }
    if (isPrivate(room)) {
      const next = {...room, mode: MODE_WINDOW, fractions: null};
      if (stored) {
        next.mode = PRIVATE_MODES.includes(stored.mode) ? stored.mode : MODE_WINDOW;
        next.fractions = stored.fractions || null;
        // a popup cannot be opened again without a click: a popped-out conference comes back in a window
        const back = isPrivate(stored) ? stored.back : {id: stored.id, mode: stored.mode === MODE_POPOUT ? MODE_WINDOW : stored.mode,
                                                        fractions: stored.fractions || null};
        if (back) {
          next.back = back;
        }
      }
      return next;
    }
    if (stored && stored.back && stored.back.id === room.id) {
      return {...room, mode: stored.back.mode, fractions: stored.back.fractions || null};    // the end was missed
    }
    return {...room, mode: MODE_WINDOW, fractions: null};
  }
  if (action.type === 'ended') {
    return state && state.id === action.id ? null : state;
  }
  if (!state) {
    return state;
  }
  const live = isLive(state.mode);
  switch (action.type) {
    case 'minimize':
      return state.mode === MODE_WINDOW ? {...state, mode: MODE_MINIMIZED} : state;
    case 'restore':
      return state.mode === MODE_MINIMIZED ? {...state, mode: MODE_WINDOW} : state;
    case 'dock':
      return live && state.mode !== MODE_TAB ? {...state, mode: MODE_TAB} : state;
    case 'undock':
      return state.mode === MODE_TAB ? {...state, mode: MODE_WINDOW} : state;
    case 'full':
      return live && state.mode !== MODE_FULL ? {...state, mode: MODE_FULL} : state;
    case 'window':
      return state.mode === MODE_WINDOW ? state : {...state, mode: MODE_WINDOW};
    case 'popout':
      return state.mode === MODE_POPOUT ? state : {...state, mode: MODE_POPOUT};
    case 'leave':
      return live && !isPrivate(state) ? {...state, mode: MODE_LEFT} : state;
    case 'left-page':
      return (live || state.mode === MODE_POPOUT) && !isPrivate(state) ? {...state, mode: MODE_LEFT} : state;
    case 'moved': {
      const fractions = parseFloating(action.fractions);
      return fractions && state.mode === MODE_WINDOW ? {...state, fractions} : state;
    }
    default:
      return state;
  }
}

// The mode a page shows: a conference docked in the Webconf tab is a window on a page without
// that tab (the stored mode stays 'tab': the next project page docks it again).
export function effectiveMode(state, {hasTabHost = false} = {}) {
  if (!state) {
    return null;
  }
  return state.mode === MODE_TAB && !hasTabHost ? MODE_WINDOW : state.mode;
}

function placeOf(value) {
  if (!value || typeof value !== 'object' || typeof value.id !== 'string' || !value.id || !MODES.includes(value.mode)) {
    return null;
  }
  return {id: value.id, mode: value.mode, fractions: parseFloating(value.fractions)};
}

// The stored state ({id, mode, fractions} of localStorage; + kind and back: {id, mode,
// fractions} for a private conversation), or null when missing, malformed or older than
// STORED_MAX_AGE.
export function parseStored(text, now) {
  if (!text) {
    return null;
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    return null;
  }
  const stored = placeOf(value);
  if (!stored) {
    return null;
  }
  const t = Number(value.t);
  if (!Number.isFinite(t) || now - t >= STORED_MAX_AGE) {
    return null;
  }
  if (value.kind === KIND_PRIVATE) {
    stored.kind = KIND_PRIVATE;
    const back = placeOf(value.back);
    if (back) {
      stored.back = back;
    }
  }
  return stored;
}

// What is stored for a state (null: nothing).
export function storedOf(state, now) {
  if (!state) {
    return null;
  }
  const stored = {id: state.id, mode: state.mode, fractions: state.fractions || null, t: now};
  if (isPrivate(state)) {
    stored.kind = KIND_PRIVATE;
    if (state.back) {
      stored.back = {id: state.back.id, mode: state.back.mode, fractions: state.back.fractions || null};
    }
  }
  return stored;
}

// The default size of the window: at most MAX_WINDOW and WINDOW_FRACTION of the layer, never
// below the minimums.
export function defaultWindowSize(area) {
  const w = Math.max(WEBCONF_MINS.minWidth, Math.min(MAX_WINDOW.w, Math.floor(area.width * WINDOW_FRACTION)));
  const h = Math.max(WEBCONF_MINS.minHeight, Math.min(MAX_WINDOW.h, Math.floor(area.height * WINDOW_FRACTION)));
  return {w, h};
}

// Where a new window opens, as fractions of the layer: the bottom-right corner, a margin away;
// null without an area.
export function defaultWindowFractions(area) {
  if (!(area.width > 0 && area.height > 0)) {
    return null;
  }
  const size = defaultWindowSize(area);
  const rect = clampRect({x: area.width - size.w - WINDOW_MARGIN, y: area.height - size.h - WINDOW_MARGIN,
                          w: size.w, h: size.h}, area, WEBCONF_MINS);
  return toFractions(rect, area);
}

// The rect of the client in full mode: the viewport under the bar.
export function fullRect(viewport, barHeight) {
  return {x: 0, y: barHeight, w: viewport.width, h: Math.max(0, viewport.height - barHeight)};
}
