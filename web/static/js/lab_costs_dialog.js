// The costs table of the Open page (instructors): a dialog listing every lab the pool heard of
// with the weight it declares, the containers its projects had, what one more project of it is
// counted for on a host and where that comes from (measured on its projects, the weight it
// declares, or the default) — GET /api/pool/costs, asked when the dialog opens and every
// REFRESH_INTERVAL while it is open.  Above the table, what a lab never seen costs and what one
// unit of weight stands for.  The titles and the texts are those of lab_costs.js, shared with
// the columns the Lab costs button shows beside the labs of the tree.  On a pool that measured
// projects with two container engines, each lab is followed by one row per engine (the Engine
// column, hidden otherwise): what one more project of the lab is counted for with that engine.

import * as api from './api.js';
import {el, clear} from './ui.js';
import {_, resolveText} from './i18n.js';
import {costColumns, costCells, costNote, engineOf, hasEngineRows, sourceTip, NOTE_SEPARATOR} from './lab_costs.js';

const REFRESH_INTERVAL = 5000;

export function createCostsDialog() {
  let current = null;      // the open dialog: {dialog, note, body, columns, timer}

  function message(c, text, cls) {
    clear(c.body);
    c.body.append(el('tr', {}, el('td', {colspan: c.columns, class: cls}, text)));
  }

  function render(c, costs) {
    c.note.textContent = costNote(costs).join(NOTE_SEPARATOR);
    const labs = Array.isArray(costs.labs) ? costs.labs.filter((lab) => lab && typeof lab === 'object') : [];
    if (!labs.length) {
      message(c, _('No lab measured or declared yet.'), 'muted');
      return;
    }
    clear(c.body);
    c.table.classList.toggle('with-engines', hasEngineRows(costs));
    for (const lab of labs) {
      const cells = costCells(lab);
      const source = cells.pop();
      const engine = engineOf(lab);
      // the row of an engine comes under the row of its lab: the name is not said twice
      c.body.append(el('tr', {class: engine ? 'of-engine' : '', dataset: {lab: lab.lab || '', engine}},
        el('td', {title: resolveText(lab.title) || ''}, engine ? '' : lab.lab || ''),
        el('td', {class: 'engine'}, engine),
        ...cells.map((text) => el('td', {class: 'num'}, text)),
        el('td', {class: `source ${lab.source || ''}`, title: sourceTip(lab.source)}, source)));
    }
  }

  async function load() {
    const c = current;
    if (!c) {
      return;
    }
    let costs;
    try {
      costs = await api.get('/api/pool/costs');
    } catch (e) {
      if (c === current) {
        message(c, e.message, 'error');
      }
      return;
    }
    if (c === current) {
      render(c, costs && typeof costs === 'object' ? costs : {});
    }
  }

  function open() {
    if (current) {
      return;
    }
    const columns = costColumns();
    const note = el('p', {class: 'lab-costs-note muted'});
    const body = el('tbody', {}, el('tr', {}, el('td', {colspan: columns.length + 2, class: 'muted'}, _('Loading…'))));
    const table = el('table', {class: 'grid watch'},
      el('thead', {}, el('tr', {}, el('th', {}, _('Lab')),
                         el('th', {class: 'engine', title: _('The container engine the row is about: a lab measured with two engines has a row for each')}, _('Engine')),
                         ...columns.map((column) => el('th', {title: column.tip}, column.title)))),
      body);
    const close = el('button', {type: 'button'}, _('Close'));
    const dialog = el('dialog', {class: 'modal lab-costs-table'},
      el('h2', {}, _('Lab costs')), note, table, el('div', {class: 'buttons'}, close));
    close.addEventListener('click', () => dialog.close());
    const opened = {dialog, note, body, table, columns: columns.length + 2, timer: 0};
    dialog.addEventListener('close', () => {
      window.clearInterval(opened.timer);
      dialog.remove();
      if (current === opened) {
        current = null;
      }
    });
    current = opened;
    document.body.append(dialog);
    dialog.showModal();
    opened.timer = window.setInterval(load, REFRESH_INTERVAL);
    load();
  }

  return {open};
}
