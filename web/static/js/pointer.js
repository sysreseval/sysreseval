// The presenter's mouse pointer and selection shown on the spectators' pages of a presentation
// (present.js publishes, project.js applies; the formats are in pointer_model.js).  The pointer
// travels as text frames of the presenter's presentation socket ({t: 'pointer', pointer:
// locator | null}, about 25 times a second while the mouse moves, null when it leaves the page),
// the selection as the `selection` key of the view (PUT .../view, debounced like the scroll).
//
// createPointerTracker (the presenter's page): the mouse over the pane shown, the tab bar or a
// terminal located (pointer_model.js: a path of child indices and fractions, a character of a
// text node, a cell of a terminal counted from its cursor), located again when what is under a
// still mouse moves (a scroll, the output of the terminal under it); the selection of the page
// (document.getSelection(), inside the pane shown) or of a terminal (xterm's onSelectionChange,
// through the hook of tabs/terminals.js), counted again when that terminal writes (the cursor
// goes down, the selected rows stay).
// createPointerView (a spectator's page): an arrow labelled with the presenter's name over the
// resolved point, moved again when the page scrolls, resizes or changes (a MutationObserver of
// the panes and the tab bar, the mutations inside the xterms left out: they rewrite their rows at
// every byte, and an applied selection is one of their mutations); the selection of the texts as
// a highlight of the CSS Custom Highlight API (the student's own selection untouched; the plain
// selection when the browser lacks it), the selection of a terminal applied to the spectator's
// read-only xterm (drawn in the inactive colour, lavender: terminal.js) on the rows holding its
// text, once they are there (a joined session's replay lands after it opened), and again for
// each new selection the view brings.  Nothing here is pixels: the two pages have different
// sizes, fonts and word wraps, and the spectator's lab text may even be in another language (a
// text node of another length is left unresolved: the pointer falls back to the element, the
// selection is not shown).

import {el} from './ui.js';
import {nodePath, resolvePath, parseLocator, parseSelection, fraction, selectionCells, selectionRows,
        terminalSelectionLength, cellAt, cellFractions} from './pointer_model.js';

const POINTER_INTERVAL = 40;         // ms between two pointer frames of the presenter's page
const SETTLE_DELAY = 5000;           // ms during which the writes of a terminal look again for a selection not found
const HIGHLIGHT_NAME = 'presenter-selection';
const SVG_NS = 'http://www.w3.org/2000/svg';

function textNode(node) {
  return Boolean(node) && node.nodeType === Node.TEXT_NODE;
}

function elementOf(node) {
  return node && node.nodeType === Node.ELEMENT_NODE ? node : (node ? node.parentNode : null);
}

function inXterm(node) {
  const element = elementOf(node);
  return Boolean(element && element.closest && element.closest('.xterm'));
}

// The buffer row of an xterm's cursor, and the text of a row of its buffer.
function cursorRow(term) {
  const buffer = term.buffer.active;
  return buffer.baseY + buffer.cursorY;
}

function lineText(term, y) {
  const line = term.buffer.active.getLine(y);
  return line ? line.translateToString(true) : '';
}

// The caret position under a point of the viewport: {node, offset}, or null.
function caretAt(x, y) {
  if (document.caretPositionFromPoint) {
    const position = document.caretPositionFromPoint(x, y);
    return position ? {node: position.offsetNode, offset: position.offset} : null;
  }
  if (document.caretRangeFromPoint) {
    const range = document.caretRangeFromPoint(x, y);
    return range ? {node: range.startContainer, offset: range.startOffset} : null;
  }
  return null;
}

// The rect of `node`, or of its nearest ancestor with a size, up to `root` (null when none: the
// pane is hidden).
function sizedRect(node, root) {
  let current = elementOf(node);
  while (current) {
    const rect = current.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      return rect;
    }
    if (current === root) {
      break;
    }
    current = current.parentNode;
  }
  return null;
}

// -- the presenter's page -------------------------------------------------------------------------
// panes, tabbar: the elements; paneOf(): the pane element of the tab shown (null: none);
// sharedTab(): the id of the tab shown as the spectators know it (null for a tab of this page
// alone); terminalAt(element): {remoteId, term, screen, box, window} of the terminal holding the
// element (tabs/terminals.js); onSelection(): the selection changed (the view is published).
export function createPointerTracker({panes, tabbar, paneOf, sharedTab, terminalAt, onSelection}) {
  let send = null;               // the socket of the presentation while presenting
  let lastSent = null;           // the JSON of the last locator sent
  let lastLocator = null;        // the last locator (sent again after a reconnection)
  let lastPoint = null;          // the last position of the mouse over the page ({x, y}); null: out of it
  let due = false;               // a location of lastPoint is due (the throttle)
  let timer = null;
  let followed = null;           // {term, disposable}: the terminal under the mouse, whose output moves the text under it
  let selection = null;          // the selection as the view carries it (null: none)
  let selectionKey = 'null';
  let watched = null;            // {term, disposable}: the terminal holding the selection, whose output moves its cursor
  const listeners = [];

  function listen(target, type, handler, options) {
    target.addEventListener(type, handler, options);
    listeners.push([target, type, handler, options]);
  }

  // -- where the mouse is
  function locate(x, y) {
    const hit = document.elementFromPoint(x, y);
    if (!hit) {
      return null;
    }
    const terminal = terminalAt(hit);
    if (terminal) {
      return terminalLocator(terminal, hit, x, y);
    }
    const pane = paneOf();
    const tab = sharedTab();
    if (pane && tab && pane.contains(hit)) {
      return paneLocator({tab}, pane, hit, x, y);
    }
    if (tabbar && tabbar.contains(hit)) {
      return paneLocator({tabbar: true}, tabbar, hit, x, y);
    }
    return null;
  }

  // a cell of the screen (counted from the cursor: the text, not the pixel), else a point of the
  // box (its status bar) or of the window (its title bar)
  function terminalLocator(terminal, hit, x, y) {
    const term = terminal.term;
    if (terminal.screen && terminal.screen.contains(hit) && term && term.cols > 0 && term.rows > 0) {
      const rect = terminal.screen.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        const cell = cellAt((x - rect.left) / rect.width, (y - rect.top) / rect.height, term.cols, term.rows);
        follow(term);
        return {terminal: terminal.remoteId, part: 'screen', col: cell.col,
                fromCursor: cursorRow(term) - (term.buffer.active.viewportY + cell.row), fx: cell.fx, fy: cell.fy};
      }
    }
    for (const [part, element] of [['box', terminal.box], ['window', terminal.window]]) {
      if (element && element.contains(hit)) {
        const rect = element.getBoundingClientRect();
        return {terminal: terminal.remoteId, part, fx: fraction(x, rect.left, rect.width), fy: fraction(y, rect.top, rect.height)};
      }
    }
    return null;
  }

  function paneLocator(where, root, hit, x, y) {
    const caret = caretAt(x, y);
    if (caret && textNode(caret.node) && hit.contains(caret.node)) {
      // the character under the mouse, when the mouse is on its line and near it (not in the
      // margin at the end of a short line: the element then)
      const offset = Math.min(caret.offset, caret.node.length);
      const range = document.createRange();
      range.setStart(caret.node, offset);
      range.collapse(true);
      const rect = range.getBoundingClientRect();
      if (rect.height > 0 && y >= rect.top - 1 && y <= rect.bottom + 1 && Math.abs(x - rect.left) <= 2 * rect.height) {
        const path = nodePath(root, caret.node);
        if (path) {
          return {...where, path, offset, len: caret.node.length, fy: fraction(y, rect.top, rect.height)};
        }
      }
    }
    let element = hit;
    let rect = element.getBoundingClientRect();
    while (element !== root && !(rect.width > 0 && rect.height > 0)) {
      element = element.parentNode;
      rect = element.getBoundingClientRect();
    }
    const path = nodePath(root, element);
    return path ? {...where, path, fx: fraction(x, rect.left, rect.width), fy: fraction(y, rect.top, rect.height)} : null;
  }

  // the terminal under the mouse: its output moves the text under a still mouse (located again)
  function follow(term) {
    if (followed && followed.term === term) {
      return;
    }
    if (followed) {
      followed.disposable.dispose();
      followed = null;
    }
    if (term) {
      followed = {term, disposable: term.onWriteParsed(relocate)};
    }
  }

  function emit(locator) {
    lastLocator = locator;
    const key = JSON.stringify(locator);
    if (key === lastSent) {
      return;
    }
    if (send && send({t: 'pointer', pointer: locator})) {
      lastSent = key;
    }
  }

  function schedule() {
    due = true;
    if (timer === null) {
      timer = window.setTimeout(flush, POINTER_INTERVAL);
    }
  }

  function flush() {
    timer = null;
    if (!due || !lastPoint) {
      return;
    }
    due = false;
    const locator = locate(lastPoint.x, lastPoint.y);
    if (!locator || locator.part !== 'screen') {
      follow(null);
    }
    emit(locator);
  }

  function onMove(ev) {
    lastPoint = {x: ev.clientX, y: ev.clientY};
    schedule();
  }

  // what is under a still mouse moved (a pane or a terminal scrolled, the terminal wrote)
  function relocate() {
    if (lastPoint) {
      schedule();
    }
  }

  function gone() {
    lastPoint = null;
    due = false;
    follow(null);
    emit(null);
  }

  // -- what is selected
  function setSelection(next) {
    const key = JSON.stringify(next);
    if (key === selectionKey) {
      return;
    }
    selection = next;
    selectionKey = key;
    if (onSelection) {
      onSelection();
    }
  }

  function point(root, node, offset) {
    const path = nodePath(root, node);
    if (!path) {
      return null;
    }
    const p = {path, offset};
    if (textNode(node)) {
      p.len = node.length;
    }
    return p;
  }

  // the selection of the page, inside the pane shown (never one of an xterm's helper: xterm
  // selects by itself); null without
  function domSelection() {
    const sel = document.getSelection();
    if (!sel || sel.rangeCount === 0 || sel.isCollapsed) {
      return null;
    }
    const pane = paneOf();
    const tab = sharedTab();
    if (!pane || !tab) {
      return null;
    }
    const range = sel.getRangeAt(0);
    if (!pane.contains(range.startContainer) || !pane.contains(range.endContainer)
        || inXterm(range.startContainer) || inXterm(range.endContainer)) {
      return null;
    }
    const start = point(pane, range.startContainer, range.startOffset);
    const end = point(pane, range.endContainer, range.endOffset);
    return start && end ? {tab, start, end} : null;
  }

  function onSelectionChange() {
    const dom = domSelection();
    if (dom) {
      watch(null);
      setSelection(dom);
    } else if (selection && selection.tab) {
      setSelection(null);        // the selection of the page is gone; a terminal's stays
    }
  }

  // the selection of a terminal changed (the hook of tabs/terminals.js), or its output moved its
  // cursor (the rows counted from it change)
  function terminalSelection(remoteId, term) {
    if (!remoteId || !term) {
      return;
    }
    if (term.hasSelection()) {
      const cells = selectionCells(term.getSelectionPosition(), cursorRow(term), (y) => lineText(term, y));
      if (cells) {
        watch(term, remoteId);
        setSelection({terminal: remoteId, ...cells});
        return;
      }
    }
    if (selection && selection.terminal === remoteId) {
      watch(null);
      setSelection(null);
    }
  }

  function watch(term, remoteId) {
    if (watched && watched.term === term) {
      return;
    }
    if (watched) {
      watched.disposable.dispose();
      watched = null;
    }
    if (term) {
      watched = {term, disposable: term.onWriteParsed(() => terminalSelection(remoteId, term))};
    }
  }

  // -- presenting
  function start(options) {
    stop();
    send = options.send;
    listen(document, 'mousemove', onMove, {passive: true});
    listen(document.documentElement, 'mouseleave', gone);
    listen(document, 'mouseout', (ev) => {
      if (!ev.relatedTarget) {
        gone();                // out of the window (or into an iframe: the web conference)
      }
    });
    listen(window, 'blur', gone);
    listen(document, 'visibilitychange', () => {
      if (document.visibilityState !== 'visible') {
        gone();
      }
    });
    listen(document, 'scroll', relocate, {capture: true, passive: true});
    listen(document, 'selectionchange', onSelectionChange);
    onSelectionChange();       // a selection made before the presentation started
  }

  function stop() {
    for (const [target, type, handler, options] of listeners.splice(0)) {
      target.removeEventListener(type, handler, options);
    }
    if (timer !== null) {
      window.clearTimeout(timer);
      timer = null;
    }
    lastPoint = null;
    due = false;
    follow(null);
    if (send) {
      emit(null);              // best effort: the socket may be gone already
    }
    send = null;
    lastSent = null;
    lastLocator = null;
    watch(null);
    selection = null;
    selectionKey = 'null';
  }

  // the socket was opened again: the spectators lost the pointer meanwhile
  function resend() {
    lastSent = null;
    emit(lastLocator);
  }

  // the selection as the view carries it; a terminal's is gone with its terminal (closed)
  function getSelection() {
    if (selection && selection.terminal && watched && !(watched.term.element && watched.term.element.isConnected)) {
      watch(null);
      selection = null;
      selectionKey = 'null';
    }
    return selection;
  }

  return {start, stop, resend, terminalSelection, getSelection};
}

// -- a spectator's page ---------------------------------------------------------------------------
// panes, tabbar: the elements; paneOf(tab): the pane element of `tab` when it is the one shown
// (null otherwise); terminalByRemote(id): {session, box, win} of the terminal joined on that
// session (tabs/terminals.js; null when not joined); label: the presenter's name.
export function createPointerView({panes, tabbar, paneOf, terminalByRemote, label}) {
  const arrow = document.createElementNS(SVG_NS, 'svg');
  arrow.setAttribute('viewBox', '0 0 16 22');
  arrow.setAttribute('aria-hidden', 'true');
  const shape = document.createElementNS(SVG_NS, 'path');
  shape.setAttribute('d', 'M1 1 L1 16.5 L5 12.8 L8.2 20.5 L10.8 19.3 L7.7 11.8 L13.2 11.5 Z');
  arrow.append(shape);
  const element = el('div', {id: 'presenter-pointer', hidden: true}, arrow, el('span', {class: 'label'}, label || ''));
  document.body.append(element);

  let pointer = null;            // the last locator received, parsed (null: hidden)
  let wanted = null;             // the selection received, parsed
  let highlight = null;          // the Highlight of the CSS Custom Highlight API, when the browser has it
  let ownRange = false;          // the fallback: the selection of the page is ours
  let terminal = null;           // {term, applied, since, disposable}: the spectator's xterm holding the selection
  let frame = null;              // the animation frame of refresh()

  // -- the pointer
  function inside(root, point) {
    const r = root.getBoundingClientRect();
    return point.x >= r.left - 1 && point.x <= r.right + 1 && point.y >= r.top - 1 && point.y <= r.bottom + 1 ? point : null;
  }

  function resolveTerminal(locator) {
    const t = terminalByRemote(locator.terminal);
    if (!t || !t.box.isConnected || t.box.hidden) {
      return null;
    }
    if (locator.part === 'screen') {
      const term = t.session.term;
      const screen = t.box.querySelector('.xterm-screen');
      const rect = screen ? screen.getBoundingClientRect() : null;
      if (!rect || !(rect.width > 0 && rect.height > 0)) {
        return null;
      }
      const at = cellFractions(locator, cursorRow(term), term.buffer.active.viewportY, term.cols, term.rows);
      return at ? {x: rect.left + at.fx * rect.width, y: rect.top + at.fy * rect.height} : null;
    }
    const part = locator.part === 'window' ? (t.win ? t.win.element : null) : t.box;
    const rect = part ? sizedRect(part, part) : null;
    return rect ? {x: rect.left + locator.fx * rect.width, y: rect.top + locator.fy * rect.height} : null;
  }

  function resolvePointer(locator) {
    if (locator.terminal) {
      return resolveTerminal(locator);
    }
    const root = locator.tabbar ? tabbar : paneOf(locator.tab);
    if (!root || root.hidden) {
      return null;
    }
    const {node, exact} = resolvePath(root, locator.path);
    if (exact && locator.offset !== undefined && textNode(node) && node.length === locator.len) {
      const range = document.createRange();
      range.setStart(node, Math.min(locator.offset, node.length));
      range.collapse(true);
      const rect = range.getBoundingClientRect();
      if (rect.height > 0) {
        return inside(root, {x: rect.left, y: rect.top + locator.fy * rect.height});
      }
    }
    const rect = sizedRect(node, root);
    if (!rect) {
      return null;
    }
    const fx = locator.fx !== undefined ? locator.fx : 0;
    return inside(root, {x: rect.left + fx * rect.width, y: rect.top + locator.fy * rect.height});
  }

  function place() {
    const point = pointer ? resolvePointer(pointer) : null;
    if (!point) {
      element.hidden = true;
      return;
    }
    element.hidden = false;
    element.style.transform = `translate(${Math.round(point.x)}px, ${Math.round(point.y)}px)`;
  }

  function setPointer(value) {
    pointer = parseLocator(value);
    place();
  }

  // -- the selection of the texts
  function endpoint(root, p) {
    const {node, exact} = resolvePath(root, p.path);
    if (!exact) {
      return null;
    }
    if (textNode(node)) {
      if (p.len !== undefined && node.length !== p.len) {
        return null;             // another text (another language): not this one
      }
      return {node, offset: Math.min(p.offset, node.length)};
    }
    return {node, offset: Math.min(p.offset, node.childNodes.length)};
  }

  function rangeOf(root, sel) {
    const start = endpoint(root, sel.start);
    const end = endpoint(root, sel.end);
    if (!start || !end) {
      return null;
    }
    const range = document.createRange();
    try {
      range.setStart(start.node, start.offset);
      range.setEnd(end.node, end.offset);
    } catch (e) {
      return null;
    }
    return range.collapsed ? null : range;
  }

  function clearHighlight() {
    if (highlight) {
      highlight.clear();
    }
    if (ownRange) {
      document.getSelection().removeAllRanges();
      ownRange = false;
    }
  }

  function applyDom() {
    const root = paneOf(wanted.tab);
    const range = root && !root.hidden ? rangeOf(root, wanted) : null;
    if (!range) {
      clearHighlight();
      return;
    }
    if (window.Highlight && window.CSS && CSS.highlights) {
      if (!highlight) {
        highlight = new Highlight();
        CSS.highlights.set(HIGHLIGHT_NAME, highlight);
      }
      highlight.clear();
      highlight.add(range);
    } else {
      const sel = document.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      ownRange = true;
    }
  }

  // -- the selection of a terminal
  function clearTerminal() {
    if (!terminal) {
      return;
    }
    terminal.disposable.dispose();
    try {
      terminal.term.clearSelection();
    } catch (e) {
      // disposed with its session
    }
    terminal = null;
  }

  // the rows holding the selection's text nearest to where the cursor puts them, once the buffer
  // has them (the replay of a joined session lands after `ready`: each write tries again until
  // then, for SETTLE_DELAY at most: rows older than the replay are never there); after that the
  // xterm keeps the selection on its rows, and only a new selection of the view moves it (a
  // student's own selection in the read-only terminal stays until then)
  function applyTerminal() {
    const t = terminalByRemote(wanted.terminal);
    if (!t) {
      clearTerminal();           // not joined yet: refresh() comes back once the view opened it
      return;
    }
    const term = t.session.term;
    if (terminal && terminal.term !== term) {
      clearTerminal();
    }
    if (!terminal) {
      terminal = {term, applied: false, since: Date.now(), disposable: term.onWriteParsed(() => {
        if (terminal && !terminal.applied && Date.now() - terminal.since <= SETTLE_DELAY) {
          refresh();
        }
      })};
    }
    if (terminal.applied) {
      return;
    }
    const rows = selectionRows(wanted, cursorRow(term), term.buffer.active.length, (y) => lineText(term, y));
    const current = term.getSelectionPosition();
    if (!rows) {
      if (current) {
        term.clearSelection();   // not (or no longer) in this buffer: an older selection is not shown instead
      }
      return;
    }
    terminal.applied = true;
    const length = terminalSelectionLength(rows.startX, rows.startY, rows.endX, rows.endY, term.cols);
    if (length <= 0) {
      if (current) {
        term.clearSelection();
      }
      return;
    }
    if (!current || current.start.x !== rows.startX || current.start.y !== rows.startY
        || current.end.x !== rows.endX || current.end.y !== rows.endY) {
      term.select(rows.startX, rows.startY, length);
    }
  }

  function applySelection() {
    if (!wanted || !wanted.terminal) {
      clearTerminal();
    }
    if (!wanted || !wanted.tab) {
      clearHighlight();
    }
    if (!wanted) {
      return;
    }
    if (wanted.terminal) {
      applyTerminal();
    } else {
      applyDom();
    }
  }

  function setSelection(value) {
    const next = parseSelection(value);
    if (JSON.stringify(next) === JSON.stringify(wanted)) {
      return;
    }
    wanted = next;
    if (terminal) {
      terminal.applied = false;    // a new selection (or the same rows counted from a moved cursor)
      terminal.since = Date.now();
    }
    applySelection();
  }

  // -- the page changed: the pointer moved again, the selection applied again
  function refresh() {
    if (frame !== null) {
      return;
    }
    frame = window.requestAnimationFrame(() => {
      frame = null;
      place();
      if (wanted) {
        applySelection();
      }
    });
  }

  const observer = new MutationObserver((records) => {
    for (const record of records) {
      if (!inXterm(record.target)) {
        refresh();
        return;
      }
    }
  });
  const observed = {childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'hidden', 'class']};
  observer.observe(panes, observed);
  if (tabbar) {
    observer.observe(tabbar, observed);
  }
  document.addEventListener('scroll', refresh, {capture: true, passive: true});
  window.addEventListener('resize', refresh);

  function destroy() {
    observer.disconnect();
    document.removeEventListener('scroll', refresh, {capture: true});
    window.removeEventListener('resize', refresh);
    if (frame !== null) {
      window.cancelAnimationFrame(frame);
      frame = null;
    }
    wanted = null;
    clearTerminal();
    clearHighlight();
    if (highlight && window.CSS && CSS.highlights) {
      CSS.highlights.delete(HIGHLIGHT_NAME);
      highlight = null;
    }
    pointer = null;
    element.remove();
  }

  return {setPointer, setSelection, refresh, destroy};
}
