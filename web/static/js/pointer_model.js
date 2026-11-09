// The presenter's pointer and selection as a presentation carries them (pointer.js on both
// pages, present.js publishes): a pure module, no DOM, run under node / bun by
// tests/test_web_templates.py.  A position is never a number of pixels: the spectator's page has
// another window size, another font size, another word wrap, so the same pixel shows another
// thing.  A point is named by a node of the pane shown — the indices of the children walked down
// from the pane element (a `path`, as the scroll anchors of scroll.js name a block by its index)
// — and inside it by fractions of its rect, or by a character offset of a text node (with the
// length of that node: a spectator reading the lab in another language has other text, left
// unresolved).  A point or a selection of an xterm terminal is named by cells: a column, and a row
// counted from the row of the cursor (`fromCursor`: the cursor's row minus the row, positive
// above the cursor).  Both terminals parse the same output, so a line is as many rows above the
// cursor on both, whatever the height of their grids, the length of their buffers (the
// spectator's holds the last 64 KiB of the session, the presenter's up to 5000 lines) or a blank
// line one of them wrote by itself; the columns are the same, the spectator's grid being the
// pty's.  A selection also carries the text of its first and last rows: the spectator's page puts
// it on the rows holding that text nearest to where the cursor says (its output may lag behind or
// run ahead of the presenter's for a moment, the replay of a joined session lands after it opened).
//
// Locators (the pointer; `fx`, `fy` fractions in [0, 1], of the caret rect for a text position):
//   {tab, path, fx, fy}                          an element of the pane of the tab
//   {tab, path, offset, len, fy}                 the character `offset` of a text node of `len` characters
//   {tabbar: true, path, fx, fy}                 an element of the tab bar (the same buttons on both pages)
//   {terminal, part: 'screen', col, fromCursor, fx, fy}   a cell of a terminal's screen, fx / fy inside the cell
//   {terminal, part: 'box' | 'window', fx, fy}   the box of a terminal (its status bar) or its window (the title bar)
// Selections (the `selection` key of the view):
//   {tab, start: {path, offset, len?}, end: {...}}                          the two ends of a DOM range (text nodes carry len)
//   {terminal, start: {x, fromCursor, text}, end: {x, fromCursor, text}}    the cells of an xterm selection, the end exclusive

export const MAX_PATH_DEPTH = 40;
export const MAX_ROWS_FROM_CURSOR = 100000;   // rows between a terminal cell and the cursor, at most (a scrollback and more)
export const MAX_ROW_TEXT = 256;              // the characters of a selected row kept to find it again
export const SEARCH_ROWS = 200;               // the rows around the expected one where the spectator looks for a selection
export const TERMINAL_PARTS = ['screen', 'box', 'window'];
const DECIMALS = 4;

export function round4(value) {
  return Number(Number(value).toFixed(DECIMALS));
}

// The fraction of `size` at `value - start`, kept in [0, 1] (0 without a size).
export function fraction(value, start, size) {
  if (!(size > 0)) {
    return 0;
  }
  return round4(Math.min(1, Math.max(0, (value - start) / size)));
}

// The indices of the children walked from `root` down to `node` (childNodes: the text nodes
// count); null when `node` is not under `root` or too deep.
export function nodePath(root, node) {
  const path = [];
  let current = node;
  while (current && current !== root) {
    const parent = current.parentNode;
    if (!parent) {
      return null;
    }
    const index = Array.prototype.indexOf.call(parent.childNodes, current);
    if (index < 0) {
      return null;
    }
    path.unshift(index);
    if (path.length > MAX_PATH_DEPTH) {
      return null;
    }
    current = parent;
  }
  return current === root ? path : null;
}

// The node at `path` under `root`: the deepest one reached ({node, exact}, exact when every
// index resolved: a path stopping early names the nearest ancestor the spectator's page has, a
// button of the presenter's row the spectator's lacks, say).
export function resolvePath(root, path) {
  let node = root;
  let exact = true;
  for (const index of path) {
    const children = node.childNodes;
    const child = children && Number.isInteger(index) && index >= 0 && index < children.length ? children[index] : null;
    if (!child) {
      exact = false;
      break;
    }
    node = child;
  }
  return {node, exact};
}

function isFraction(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isCount(value) {
  return Number.isInteger(value) && value >= 0;
}

function isRowOffset(value) {
  return Number.isInteger(value) && Math.abs(value) <= MAX_ROWS_FROM_CURSOR;
}

function isPath(value) {
  return Array.isArray(value) && value.length <= MAX_PATH_DEPTH && value.every(isCount);
}

// A locator as received, checked (one of the shapes above), or null.
export function parseLocator(value) {
  if (!value || typeof value !== 'object') {
    return null;
  }
  if (typeof value.terminal === 'string' && value.terminal) {
    const part = value.part === undefined ? 'screen' : value.part;
    if (!TERMINAL_PARTS.includes(part) || !isFraction(value.fx) || !isFraction(value.fy)) {
      return null;
    }
    if (part !== 'screen') {
      return {terminal: value.terminal, part, fx: value.fx, fy: value.fy};
    }
    if (!isCount(value.col) || !isRowOffset(value.fromCursor)) {
      return null;
    }
    return {terminal: value.terminal, part, col: value.col, fromCursor: value.fromCursor, fx: value.fx, fy: value.fy};
  }
  if (!isPath(value.path) || !isFraction(value.fy)) {
    return null;
  }
  let where = null;
  if (value.tabbar === true) {
    where = {tabbar: true};
  } else if (typeof value.tab === 'string' && value.tab) {
    where = {tab: value.tab};
  } else {
    return null;
  }
  if (value.offset !== undefined) {
    if (!isCount(value.offset) || !isCount(value.len)) {
      return null;
    }
    return {...where, path: value.path, offset: value.offset, len: value.len, fy: value.fy};
  }
  if (!isFraction(value.fx)) {
    return null;
  }
  return {...where, path: value.path, fx: value.fx, fy: value.fy};
}

function parsePoint(value) {
  if (!value || typeof value !== 'object' || !isPath(value.path) || !isCount(value.offset)) {
    return null;
  }
  const point = {path: value.path, offset: value.offset};
  if (value.len !== undefined) {
    if (!isCount(value.len)) {
      return null;
    }
    point.len = value.len;
  }
  return point;
}

function parseCell(value) {
  if (!value || typeof value !== 'object' || !isCount(value.x) || !isRowOffset(value.fromCursor)
      || typeof value.text !== 'string' || value.text.length > MAX_ROW_TEXT) {
    return null;
  }
  return {x: value.x, fromCursor: value.fromCursor, text: value.text};
}

// A selection as the view carries it, checked (one of the two shapes above), or null.
export function parseSelection(value) {
  if (!value || typeof value !== 'object') {
    return null;
  }
  if (typeof value.terminal === 'string' && value.terminal) {
    const start = parseCell(value.start);
    const end = parseCell(value.end);
    return start && end && start.fromCursor >= end.fromCursor ? {terminal: value.terminal, start, end} : null;
  }
  if (typeof value.tab !== 'string' || !value.tab) {
    return null;
  }
  const start = parsePoint(value.start);
  const end = parsePoint(value.end);
  return start && end ? {tab: value.tab, start, end} : null;
}

// The text a terminal row is known by: what xterm gives for it (translateToString(true): the
// trailing blanks dropped), cut to MAX_ROW_TEXT characters.
export function rowText(text) {
  return String(text === undefined || text === null ? '' : text).slice(0, MAX_ROW_TEXT);
}

// The presenter's side: the selection of an xterm (getSelectionPosition(): rows of the buffer,
// the end exclusive) as cells counted from the cursor's row `cursorRow`, with the text of their
// rows (lineText(y): the text of the row y of the buffer).
export function selectionCells(position, cursorRow, lineText) {
  if (!position || !position.start || !position.end) {
    return null;
  }
  const cell = (c) => ({x: c.x, fromCursor: cursorRow - c.y, text: rowText(lineText(c.y))});
  return {start: cell(position.start), end: cell(position.end)};
}

// The spectator's side: where the cells of a received selection are in a buffer of `length`
// rows whose cursor is on the row `cursorRow` ({startX, startY, endX, endY}): the rows holding the
// texts of its first and last rows nearest to where the cursor puts them, within `radius` rows;
// null when the buffer holds no such rows (not yet, or no longer).
export function selectionRows(selection, cursorRow, length, lineText, radius = SEARCH_ROWS) {
  const span = selection.start.fromCursor - selection.end.fromCursor;
  if (span < 0) {
    return null;
  }
  const expected = cursorRow - selection.start.fromCursor;
  for (let d = 0; d <= radius; d++) {
    for (const y of d === 0 ? [expected] : [expected + d, expected - d]) {
      if (y >= 0 && y + span < length && rowText(lineText(y)) === selection.start.text
          && rowText(lineText(y + span)) === selection.end.text) {
        return {startX: selection.start.x, startY: y, endX: selection.end.x, endY: y + span};
      }
    }
  }
  return null;
}

// The length xterm's select(column, row, length) takes for the cells from (startX, startY) to
// (endX, endY) exclusive: a run wrapping across the rows by `cols`.
export function terminalSelectionLength(startX, startY, endX, endY, cols) {
  return (endY - startY) * cols + (endX - startX);
}

// The cell of a terminal screen of cols × rows at the fractions (fx, fy) of the screen, and the
// fractions inside it ({col, row, fx, fy}).
export function cellAt(fx, fy, cols, rows) {
  const x = Math.min(cols, Math.max(0, fx * cols));
  const y = Math.min(rows, Math.max(0, fy * rows));
  const col = Math.min(cols - 1, Math.floor(x));
  const row = Math.min(rows - 1, Math.floor(y));
  return {col, row, fx: round4(Math.min(1, x - col)), fy: round4(Math.min(1, y - row))};
}

// The fractions of a terminal screen of cols × rows, whose cursor is on the buffer row `cursorRow`
// and which shows the rows from `viewportY`, where a cell locator points; null when its row is not
// on the screen (scrolled away, or not in the buffer).
export function cellFractions(locator, cursorRow, viewportY, cols, rows) {
  const row = cursorRow - locator.fromCursor - viewportY;
  if (!(cols > 0 && rows > 0) || row < 0 || row >= rows) {
    return null;
  }
  const col = Math.min(locator.col, cols - 1);
  const fx = locator.col > col ? 1 : locator.fx;
  return {fx: round4((col + fx) / cols), fy: round4((row + locator.fy) / rows)};
}
