// The position inside a scrolling pane, as the view of a presentation carries it (present.js:
// the spectators follow the presenter's scroll).  Not a number of pixels: the spectator's page
// has the student's window size, and the content font size and the word wrap are settings of
// each browser, so the same scrollTop would show another line.  The position is an anchor:
// the first child of the content container still visible at the top of the scroller, by its
// index, and the fraction of its height hidden above the top edge (slightly negative when the
// edge is in the padding or the margin above it: the exact position comes back on an identical
// layout).  Both pages render the same HTML, so the indexes match; another width or font size
// only changes the heights, and the line at the top is the same.  A scroller without element
// children (the <pre> of the Log tab) falls back to a fraction of its scrolled height.

const DECIMALS = 5;   // a fraction of the Log tab's text (100 000 lines) is still within a few lines

function round(value) {
  return Math.round(value * 10 ** DECIMALS) / 10 ** DECIMALS;
}

// {index, offset} for the children of `container` (the scroller itself by default), {ratio}
// without any, null when the scroller is not in the document.
export function scrollAnchor(scroller, container = scroller) {
  if (!scroller || !scroller.isConnected) {
    return null;
  }
  const top = scroller.getBoundingClientRect().top;
  const children = container && container.isConnected ? container.children : [];
  for (let i = 0; i < children.length; i++) {
    const rect = children[i].getBoundingClientRect();
    if (rect.height > 0 && rect.bottom > top) {
      return {index: i, offset: round((top - rect.top) / rect.height)};
    }
  }
  const height = scroller.scrollHeight;
  return {ratio: height > 0 ? round(scroller.scrollTop / height) : 0};
}

// Scroll `scroller` to the anchor (a malformed one is ignored).
export function applyScrollAnchor(scroller, anchor, container = scroller) {
  if (!scroller || !scroller.isConnected || !anchor || typeof anchor !== 'object') {
    return;
  }
  if (Number.isFinite(anchor.ratio)) {
    scroller.scrollTop = Math.max(0, anchor.ratio) * scroller.scrollHeight;
    return;
  }
  const children = container && container.isConnected ? container.children : [];
  const index = Number(anchor.index);
  const offset = Number(anchor.offset);
  if (!Number.isInteger(index) || index < 0 || index >= children.length || !Number.isFinite(offset)) {
    return;
  }
  const top = scroller.getBoundingClientRect().top;
  const rect = children[index].getBoundingClientRect();
  scroller.scrollTop += (rect.top - top) + offset * rect.height;
}

// The two methods of a tab whose pane scrolls: to spread into the tab object.
export function paneScroll(scroller, container = scroller) {
  return {
    getScroll() {
      return scrollAnchor(scroller, container);
    },
    setScroll(anchor) {
      applyScrollAnchor(scroller, anchor, container);
    },
  };
}
