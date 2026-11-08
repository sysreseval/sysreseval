// Floating terminal windows over the project page.  tabs/terminals.js moves the box of a
// terminal (its xterm) into a window and back; this module knows nothing of the sessions: it is
// the chrome of a window (a title bar with the title, the viewers badge and the dock / close
// buttons, the box as its body), dragged by its title bar, resized by its bottom-right corner
// (CSS resize), raised when clicked, kept inside the layer, which covers the panes of the page
// (#panes: the windows float over whatever tab is shown and go with the panes when the page is
// over).  The geometry of a window is published to the spectators of a presentation as fractions
// of the layer (x, y, w, h in [0, 1]) and applied on their layer, whatever its size, as read-only
// windows (no buttons, no drag, no resize).  The same chrome holds the window of a web
// conference (webconf.js: its own layer over the whole page, its own buttons, a default size of
// its own, the iframe placed over the window's body through onMove).  The pure helpers
// (clampRect, toFractions, toPixels, cascadePosition, defaultSize, parseFloating) are tested
// under node / bun: nothing of the DOM at the module top level.

import {el} from './ui.js';
import {_} from './i18n.js';

export const MIN_WIDTH = 240;       // px: the smallest window
export const MIN_HEIGHT = 140;
export const CASCADE_STEP = 28;     // px between two windows opened one after the other
export const CASCADE_WRAP = 8;      // windows per cascade before it starts again from the corner
const MARGIN = 16;                  // px: the first window of a cascade
const DECIMALS = 4;                 // of a fraction: 0.2 px on a 2000 px layer
const DEFAULT_COLS = 80;
const DEFAULT_ROWS = 24;
const CHROME_WIDTH = 2 + 4 + 14;         // the border, the padding of the wrap, the scrollbar of xterm
const CHROME_HEIGHT = 2 + 26 + 24 + 4;   // the border, the title bar, the status bar, the padding
const MAX_FRACTION = 0.9;                // a default window takes at most that much of the layer

// The rect kept inside the area: its size capped to the area (never below the minimums), then
// its position so that it does not overflow (0 when it cannot fit).
export function clampRect(rect, area, {minWidth = MIN_WIDTH, minHeight = MIN_HEIGHT} = {}) {
  const w = Math.max(minWidth, Math.min(rect.w, area.width));
  const h = Math.max(minHeight, Math.min(rect.h, area.height));
  const x = Math.max(0, Math.min(rect.x, area.width - w));
  const y = Math.max(0, Math.min(rect.y, area.height - h));
  return {x, y, w, h};
}

// The rect as fractions of the area (what the presenter publishes); null without an area.
export function toFractions(rect, area) {
  if (!(area.width > 0 && area.height > 0)) {
    return null;
  }
  const f = (v) => Number(v.toFixed(DECIMALS));
  return {x: f(rect.x / area.width), y: f(rect.y / area.height), w: f(rect.w / area.width), h: f(rect.h / area.height)};
}

// The fractions back to a rect of the area, kept inside it.
export function toPixels(fractions, area, mins) {
  return clampRect({x: fractions.x * area.width, y: fractions.y * area.height,
                    w: fractions.w * area.width, h: fractions.h * area.height}, area, mins);
}

// Where the index-th window opens: a cascade from the top-left corner.
export function cascadePosition(index, area, size, mins) {
  const step = (index % CASCADE_WRAP) * CASCADE_STEP;
  return clampRect({x: MARGIN + step, y: MARGIN + step, w: size.w, h: size.h}, area, mins);
}

// About 80 × 24 cells of a monospace font of fontSize px (0.6 × fontSize per column, 1.2 ×
// fontSize per row: what the fit addon then measures decides the real grid), the chrome added,
// capped to 90 % of the area.
export function defaultSize(fontSize, area) {
  const size = Math.max(6, Number(fontSize) || 12);
  const w = Math.round(DEFAULT_COLS * 0.6 * size) + CHROME_WIDTH;
  const h = DEFAULT_ROWS * Math.round(1.2 * size) + CHROME_HEIGHT;
  return {w: Math.min(w, Math.floor(area.width * MAX_FRACTION)), h: Math.min(h, Math.floor(area.height * MAX_FRACTION))};
}

// The geometry of a presenter's window as the view carries it: {x, y, w, h} fractions in [0, 1]
// with a size, or null (an old presenter script sends none: the terminal stays a sub-tab).
export function parseFloating(value) {
  if (!value || typeof value !== 'object') {
    return null;
  }
  const out = {};
  for (const key of ['x', 'y', 'w', 'h']) {
    const v = Number(value[key]);
    if (!Number.isFinite(v) || v < 0 || v > 1) {
      return null;
    }
    out[key] = v;
  }
  return out.w > 0 && out.h > 0 ? out : null;
}

// The layer of the windows: `element` is appended to #panes by project.js; readonly for a
// spectator's page (the windows are the presenter's, placed by their fractions); onChange()
// after a move, a resize or a change of the layer's size (the presenter's page publishes).
export function createTerminalWindows({readonly = false, onChange = null} = {}) {
  const element = el('div', {class: 'terminal-windows'});
  const windows = [];      // the handles, in opening order
  let zTop = 0;
  let opened = 0;          // windows opened so far: the cascade

  function area() {
    return {width: element.clientWidth, height: element.clientHeight};
  }

  function changed() {
    if (onChange) {
      onChange();
    }
  }

  // the layer changed size (the browser window, a bar above): a spectator's windows keep their
  // fractions, a presenter's are kept inside
  function relayout() {
    const a = area();
    if (!(a.width > 0 && a.height > 0)) {
      return;
    }
    for (const win of windows) {
      win.relayout(a);
    }
    changed();
  }
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(() => relayout()).observe(element);
  }

  // A window around `box` (a .terminal-box, or the slot of a web conference): fractions place
  // it (a spectator's, a stored one), else the cascade and `size`, or the default size for the
  // font; `mins` are its minimums ({minWidth, minHeight}, the terminal's by default); className
  // colours the title (a closed or a hidden device); the buttons of the title bar are the dock
  // and close ones calling onDock / onClose, or the `buttons` given ([{name, label, title,
  // onClick}], the handle exposes them by name); onFocus on a click, onMove(rect) after every
  // placement (a drag step, a relayout, the fractions applied).  A readonly layer has no
  // buttons and ignores the clicks.
  function open(box, {title = '', className = null, fractions = null, fontSize = 12, size = null, mins = undefined,
                      buttons = null, onDock = null, onClose = null, onFocus = null, onMove = null} = {}) {
    const titleText = el('span', {class: 'title'}, title);
    const viewers = el('span', {class: 'viewers'});
    const bar = el('div', {class: 'terminal-window-title'}, titleText, viewers);
    const win = el('div', {class: 'terminal-window' + (readonly ? ' readonly' : '') + (className ? ' ' + className : '')});
    const buttonElements = {};
    if (!readonly) {
      const spec = buttons || [
        {name: 'dock', label: '⇲', title: _('Dock into the Terminals tab'), onClick: onDock},
        {name: 'close', label: '×', title: _('Close terminal'), onClick: onClose},
      ];
      for (const b of spec) {
        const button = el('button', {type: 'button', class: b.name, title: b.title}, b.label);
        button.addEventListener('click', () => b.onClick && b.onClick());
        bar.append(button);
        buttonElements[b.name] = button;
      }
    }
    win.append(bar, box);
    element.append(win);
    const minWidth = (mins && mins.minWidth) || MIN_WIDTH;
    const minHeight = (mins && mins.minHeight) || MIN_HEIGHT;
    let stored = fractions;      // a spectator's window: the presenter's fractions, applied again on a relayout
    let drag = null;
    let observer = null;

    // the rect of the window relative to the layer, as laid out (the native resize writes the
    // inline width / height itself)
    function current() {
      const r = win.getBoundingClientRect();
      const l = element.getBoundingClientRect();
      return {x: r.left - l.left, y: r.top - l.top, w: r.width, h: r.height};
    }

    function place(rect) {
      win.style.left = rect.x + 'px';
      win.style.top = rect.y + 'px';
      win.style.width = rect.w + 'px';
      win.style.height = rect.h + 'px';
      if (!readonly) {
        // the native resize handle cannot drag the window past the layer
        const a = area();
        win.style.maxWidth = Math.max(minWidth, a.width - rect.x) + 'px';
        win.style.maxHeight = Math.max(minHeight, a.height - rect.y) + 'px';
      }
      if (onMove) {
        onMove(rect);
      }
    }

    function raise() {
      zTop += 1;
      win.style.zIndex = String(zTop);
    }

    // the pointer relative to the layer
    function pointer(ev) {
      const l = element.getBoundingClientRect();
      return {x: ev.clientX - l.left, y: ev.clientY - l.top};
    }

    win.addEventListener('pointerdown', () => {
      raise();
      if (onFocus) {
        onFocus();
      }
    }, {capture: true});

    if (!readonly) {
      bar.addEventListener('pointerdown', (ev) => {
        if (ev.button !== 0 || ev.target.closest('button')) {
          return;
        }
        const r = current();
        const p = pointer(ev);
        drag = {dx: p.x - r.x, dy: p.y - r.y, w: r.w, h: r.h};
        win.classList.add('dragging');
        bar.setPointerCapture(ev.pointerId);
        ev.preventDefault();      // the terminal keeps the keyboard focus, no text selected
      });
      bar.addEventListener('pointermove', (ev) => {
        if (!drag) {
          return;
        }
        const p = pointer(ev);
        place(clampRect({x: p.x - drag.dx, y: p.y - drag.dy, w: drag.w, h: drag.h}, area(), mins));
      });
      const stop = (ev) => {
        if (!drag) {
          return;
        }
        drag = null;
        win.classList.remove('dragging');
        if (bar.hasPointerCapture(ev.pointerId)) {
          bar.releasePointerCapture(ev.pointerId);
        }
        changed();
      };
      bar.addEventListener('pointerup', stop);
      bar.addEventListener('pointercancel', stop);
      if (typeof ResizeObserver === 'function') {
        // the native resize (and the first layout)
        observer = new ResizeObserver(() => changed());
        observer.observe(win);
      }
    }

    const a = area();
    place(fractions ? toPixels(fractions, a, mins) : cascadePosition(opened, a, size || defaultSize(fontSize, a), mins));
    opened += 1;
    raise();

    const handle = {
      element: win,
      buttons: buttonElements,     // name -> the button of the title bar (a caller hides one)
      raise,
      setTitle(text) {
        titleText.textContent = text;
      },
      setViewers(text, tooltip) {
        viewers.textContent = text || '';
        viewers.title = tooltip || '';
      },
      // the geometry as the presenter publishes it
      fractions() {
        return toFractions(current(), area());
      },
      // a spectator's window: the presenter's geometry
      setFractions(f) {
        stored = f;
        place(toPixels(f, area(), mins));
      },
      relayout(areaNow) {
        if (readonly && stored) {
          place(toPixels(stored, areaNow, mins));
        } else if (!readonly) {
          place(clampRect(current(), areaNow, mins));
        }
      },
      // the chrome removed; the caller takes the box back
      close() {
        if (observer) {
          observer.disconnect();
        }
        const index = windows.indexOf(handle);
        if (index >= 0) {
          windows.splice(index, 1);
        }
        win.remove();
      },
    };
    windows.push(handle);
    return handle;
  }

  return {
    element,
    open,
    count() {
      return windows.length;
    },
  };
}
