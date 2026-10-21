// The Schema tab (and the Full Schema of a debug project, hidden machines included): the SVG of
// GET {api_base}/schema.svg drawn inline with pan and zoom, and the controls of the Qt view:
// Lines (straight / curved), the Compact-Spread slider, the node Order (forward, reverse,
// random with a seed kept until the next click) and Nodes (icons / shapes).  Lines, spacing and
// nodes are kept in the settings; the order is per page, like the Qt view.

import * as api from '../api.js';
import * as settings from '../settings.js';
import {el, clear} from '../ui.js';
import {_} from '../i18n.js';
import {SvgPanZoom} from '../svgpanzoom.js';

export function createSchemaTab(ctx, {hidden = false} = {}) {
  const id = hidden ? 'full_schema' : 'schema';
  const order = {reverse: false, seed: null};
  let loaded = false;
  let shown = false;

  // -- controls ---------------------------------------------------------------------------
  const radio = (name, value, label, checked, onChange) => {
    const input = el('input', {type: 'radio', name: `${id}-${name}`, value});
    input.checked = checked;
    input.addEventListener('change', () => {
      if (input.checked) {
        onChange(value);
      }
    });
    return el('label', {}, input, label);
  };
  const straight = radio('lines', 'straight', _('Straight'), !settings.get('schema_curved'), () => setCurved(false));
  const curved = radio('lines', 'curved', _('Curved'), settings.get('schema_curved'), () => setCurved(true));
  const slider = el('input', {type: 'range', min: 0, max: 9, step: 1});
  slider.value = settings.get('schema_sep');
  slider.addEventListener('change', () => {
    settings.set('schema_sep', Number(slider.value));
    reload();
  });
  const forward = el('button', {type: 'button', class: 'toggle', 'aria-pressed': 'true'}, '→');
  const reverse = el('button', {type: 'button', class: 'toggle', 'aria-pressed': 'false'}, '←');
  const random = el('button', {type: 'button', class: 'toggle', 'aria-pressed': 'false'}, _('random'));
  const pressOrder = (button) => {
    for (const b of [forward, reverse, random]) {
      b.setAttribute('aria-pressed', b === button ? 'true' : 'false');
    }
  };
  forward.addEventListener('click', () => {
    order.reverse = false;
    order.seed = null;
    pressOrder(forward);
    reload();
  });
  reverse.addEventListener('click', () => {
    order.reverse = true;
    order.seed = null;
    pressOrder(reverse);
    reload();
  });
  random.addEventListener('click', () => {
    // every click draws a new permutation, as in the Qt view
    order.reverse = false;
    order.seed = Math.floor(Math.random() * 2 ** 31);
    pressOrder(random);
    reload();
  });
  const icons = radio('nodes', 'icons', _('Icons'), settings.get('schema_icons'), () => setIcons(true));
  const shapes = radio('nodes', 'shapes', _('Shapes'), !settings.get('schema_icons'), () => setIcons(false));

  const bar = el('div', {class: 'ctrl-bar'},
    el('span', {}, _('Lines:')), straight, curved,
    el('span', {class: 'sep'}),
    el('span', {}, _('Compact')), slider, el('span', {}, _('Spread')),
    el('span', {class: 'sep'}),
    el('span', {}, _('Order:')), forward, reverse, random,
    el('span', {class: 'sep'}),
    el('span', {}, _('Nodes:')), icons, shapes);
  const view = el('div', {class: 'schema-view'});
  const pane = el('div', {class: 'pane no-scroll'}, bar, view);
  const panzoom = new SvgPanZoom(view);

  function setCurved(value) {
    settings.set('schema_curved', value);
    reload();
  }

  function setIcons(value) {
    settings.set('schema_icons', value);
    reload();
  }

  // The two schema tabs share the settings: the controls follow them when the tab is shown.
  function syncControls() {
    const isCurved = settings.get('schema_curved');
    curved.querySelector('input').checked = isCurved;
    straight.querySelector('input').checked = !isCurved;
    const useIcons = settings.get('schema_icons');
    icons.querySelector('input').checked = useIcons;
    shapes.querySelector('input').checked = !useIcons;
    slider.value = settings.get('schema_sep');
  }

  function orderText() {
    if (order.seed !== null) {
      return `random:${order.seed}`;
    }
    return order.reverse ? 'reverse' : 'forward';
  }

  function query() {
    return {
      curved: settings.get('schema_curved') ? 1 : 0,
      sep: settings.get('schema_sep'),
      order: orderText(),
      icons: settings.get('schema_icons') ? 1 : 0,
      hidden: hidden ? 1 : undefined,
    };
  }

  // The query string of GET {api_base}/export mirroring the display (sre export options).
  function exportQuery() {
    return {
      curved: settings.get('schema_curved') ? 1 : 0,
      sep: settings.get('schema_sep'),
      shapes: settings.get('schema_icons') ? 0 : 1,
      reverse: order.reverse ? 1 : 0,
      random_seed: order.seed === null ? undefined : order.seed,
    };
  }

  let pending = false;
  async function reload() {
    if (ctx.onSchemaOptions) {
      ctx.onSchemaOptions(exportQuery());
    }
    if (pending) {
      return;
    }
    pending = true;
    try {
      const response = await api.fetchRaw('GET', ctx.url('/schema.svg', query()));
      panzoom.load(await response.text());
      loaded = true;
    } catch (e) {
      clear(view);
      view.append(el('div', {class: 'message error'}, e.message));
    } finally {
      pending = false;
    }
  }

  return {
    id,
    element: pane,
    show() {
      shown = true;
      syncControls();
      if (!loaded) {
        reload();
      }
    },
    hide() {
      shown = false;
    },
    // a new info.json: the topology may have changed
    update() {
      if (shown || loaded) {
        reload();
      }
    },
    exportQuery,
  };
}
