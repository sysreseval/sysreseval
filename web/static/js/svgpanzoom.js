// Pan and zoom of an inline SVG (the schema of a project) by editing its viewBox: drag to pan,
// wheel to zoom about the pointer, double-click to reset.  The SVG keeps its own coordinate
// system; the pointer positions are converted with the screen CTM of the <svg> element.

const ZOOM_FACTOR = 1.25;   // per wheel notch, like the Qt view
const MIN_SCALE = 0.05;
const MAX_SCALE = 40;

export class SvgPanZoom {
  constructor(container) {
    this.container = container;
    this.svg = null;
    this.base = null;      // the viewBox of the document as loaded: {x, y, w, h}
    this.view = null;      // the current viewBox
    this.drag = null;      // {x, y} of the last pointer position while dragging
    container.addEventListener('wheel', (ev) => this.onWheel(ev), {passive: false});
    container.addEventListener('pointerdown', (ev) => this.onPointerDown(ev));
    container.addEventListener('pointermove', (ev) => this.onPointerMove(ev));
    container.addEventListener('pointerup', (ev) => this.onPointerUp(ev));
    container.addEventListener('pointercancel', (ev) => this.onPointerUp(ev));
    container.addEventListener('dblclick', () => this.reset());
  }

  // Replace the drawing by the SVG text; the current pan and zoom are kept when the new
  // document has the same size (a redraw after an info.json update), reset otherwise.
  load(svgText) {
    const doc = new DOMParser().parseFromString(svgText, 'image/svg+xml');
    const svg = doc.documentElement;
    if (!svg || svg.nodeName.toLowerCase() !== 'svg' || doc.querySelector('parsererror')) {
      throw new Error('not an SVG document');
    }
    const base = parseViewBox(svg);
    const keepView = this.base && this.view && sameBox(this.base, base);
    svg.removeAttribute('width');
    svg.removeAttribute('height');
    svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
    this.container.textContent = '';
    this.container.append(document.importNode(svg, true));
    this.svg = this.container.querySelector('svg');
    this.base = base;
    this.view = keepView ? this.view : {...base};
    this.apply();
  }

  clear() {
    this.container.textContent = '';
    this.svg = null;
  }

  apply() {
    if (this.svg && this.view) {
      const v = this.view;
      this.svg.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`);
    }
  }

  reset() {
    if (this.base) {
      this.view = {...this.base};
      this.apply();
    }
  }

  // The SVG coordinates of a pointer event.
  toSvgPoint(ev) {
    const ctm = this.svg.getScreenCTM();
    if (!ctm) {
      return null;
    }
    const point = new DOMPoint(ev.clientX, ev.clientY).matrixTransform(ctm.inverse());
    return {x: point.x, y: point.y, scale: ctm.a};
  }

  onWheel(ev) {
    if (!this.svg) {
      return;
    }
    ev.preventDefault();
    const point = this.toSvgPoint(ev);
    if (!point) {
      return;
    }
    const factor = ev.deltaY < 0 ? 1 / ZOOM_FACTOR : ZOOM_FACTOR;
    const scale = this.base.w / (this.view.w * factor);   // zoom relative to the document
    if (scale < MIN_SCALE || scale > MAX_SCALE) {
      return;
    }
    // the point under the pointer stays under the pointer
    const v = this.view;
    this.view = {
      x: point.x - (point.x - v.x) * factor,
      y: point.y - (point.y - v.y) * factor,
      w: v.w * factor,
      h: v.h * factor,
    };
    this.apply();
  }

  onPointerDown(ev) {
    if (!this.svg || ev.button !== 0) {
      return;
    }
    this.drag = {x: ev.clientX, y: ev.clientY};
    this.container.classList.add('dragging');
    this.container.setPointerCapture(ev.pointerId);
    ev.preventDefault();
  }

  onPointerMove(ev) {
    if (!this.drag || !this.svg) {
      return;
    }
    const ctm = this.svg.getScreenCTM();
    if (!ctm) {
      return;
    }
    const dx = (ev.clientX - this.drag.x) / ctm.a;
    const dy = (ev.clientY - this.drag.y) / ctm.d;
    this.drag = {x: ev.clientX, y: ev.clientY};
    this.view = {...this.view, x: this.view.x - dx, y: this.view.y - dy};
    this.apply();
  }

  onPointerUp(ev) {
    if (this.drag) {
      this.drag = null;
      this.container.classList.remove('dragging');
      if (this.container.hasPointerCapture(ev.pointerId)) {
        this.container.releasePointerCapture(ev.pointerId);
      }
    }
  }
}

// The viewBox of an <svg> element, built from width / height when it has none.
function parseViewBox(svg) {
  const attr = (svg.getAttribute('viewBox') || '').trim().split(/[\s,]+/).map(Number);
  if (attr.length === 4 && attr.every((n) => Number.isFinite(n)) && attr[2] > 0 && attr[3] > 0) {
    return {x: attr[0], y: attr[1], w: attr[2], h: attr[3]};
  }
  const w = parseFloat(svg.getAttribute('width')) || 800;
  const h = parseFloat(svg.getAttribute('height')) || 600;
  return {x: 0, y: 0, w, h};
}

function sameBox(a, b) {
  return a.x === b.x && a.y === b.y && a.w === b.w && a.h === b.h;
}
