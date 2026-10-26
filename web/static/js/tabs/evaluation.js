// The Evaluation tab: a "Start evaluation" button (POST {api_base}/eval) and the table of the
// grades the agent lays out (header labels and rows with their colours, from
// SRE/evaluation_table.py).  While the lab's cooldown runs, the button is replaced by a
// countdown "Next evaluation allowed in {n} s", as in the Qt view.  An instructor first sees
// the last archived evaluation of the project (GET {api_base}/evaluation), whoever ran it; so
// does a spectator of a presentation (ctx.spectator, no button), again after each evaluation
// the presenter runs (reload); the presenter's page calls ctx.onEvaluated() then.

import * as api from '../api.js';
import {el, clear, toast} from '../ui.js';
import {_, format} from '../i18n.js';

const KIND_SEPARATOR = 'separator';

export function createEvaluationTab(ctx) {
  const button = el('button', {type: 'button', class: 'primary'}, _('Start evaluation'));
  const countdown = el('span', {hidden: true});
  const caption = el('p', {class: 'evaluation-caption muted', hidden: true});
  const table = el('table', {class: 'grid evaluation'});
  const pane = el('div', {class: 'pane'}, el('div', {class: 'evaluation-bar'}, button, countdown), caption, table);
  let columns = 3;
  let deadline = null;   // ms timestamp of the end of the cooldown
  let timer = null;
  let lastLoaded = false;
  let shown = false;
  const spectator = Boolean(ctx.spectator);
  if (spectator) {
    button.hidden = true;
  }

  function renderTable(header, rows) {
    clear(table);
    columns = header.length || 3;
    table.append(el('thead', {}, el('tr', {}, ...header.map((label) => el('th', {}, label)))));
    const body = el('tbody');
    for (const row of rows) {
      const tr = el('tr', {class: (row.bold ? 'bold ' : '') + (row.kind === KIND_SEPARATOR ? 'separator' : '')});
      if (row.span) {
        const cell = row.cells[0] || {text: ''};
        tr.append(styledCell(cell, columns));
      } else {
        row.cells.forEach((cell, index) => tr.append(styledCell(cell, 1, index > 0)));
      }
      body.append(tr);
    }
    table.append(body);
  }

  function styledCell(cell, colspan, numeric) {
    const td = el('td', {colspan: colspan > 1 ? colspan : undefined, class: numeric ? 'num' : undefined}, cell.text || '');
    if (cell.color) {
      td.style.backgroundColor = cell.color;
    }
    if (cell.align && cell.align !== 'left') {
      td.style.textAlign = cell.align;
    }
    return td;
  }

  function errorRow(message) {
    clear(table);
    table.append(el('tbody', {}, el('tr', {}, el('td', {colspan: columns, class: 'error'},
                                                 format(_('Error: {error}'), {error: message})))));
  }

  function setDelay(seconds) {
    deadline = Date.now() + seconds * 1000;
    button.hidden = true;
    countdown.hidden = false;
    tick();
  }

  function tick() {
    if (timer) {
      window.clearTimeout(timer);
      timer = null;
    }
    const remaining = deadline === null ? 0 : Math.ceil((deadline - Date.now()) / 1000);
    if (remaining > 0) {
      countdown.textContent = format(_('Next evaluation allowed in {n} s'), {n: remaining});
      timer = window.setTimeout(tick, 1000);
      return;
    }
    deadline = null;
    countdown.hidden = true;
    button.hidden = false;
    button.disabled = false;
  }

  // instructors: the last archived evaluation, with its date and the errors of the run
  async function loadLast() {
    lastLoaded = true;
    let data;
    try {
      data = await api.get(ctx.url('/evaluation'));
    } catch (e) {
      if (e.status === 404) {
        caption.textContent = _('No archived evaluation yet.');
        caption.hidden = false;
      } else if (e.status !== 403) {
        errorRow(e.message);
      }
      return;
    }
    renderTable(data.header || [], data.rows || []);
    const when = data.eval_date ? new Date(data.eval_date).toLocaleString() : '';
    let text = format(_('Last archived evaluation: {date}'), {date: when});
    if (data.error_count || data.warning_count) {
      text += ' — ' + format(_('{errors} error(s), {warnings} warning(s)'),
                             {errors: data.error_count || 0, warnings: data.warning_count || 0});
    }
    caption.textContent = text;
    caption.title = (data.errors || []).map((e) => `${e.category}: ${e.text}`).join('\n');
    caption.hidden = false;
  }

  async function start() {
    button.disabled = true;
    let data;
    try {
      data = await api.post(ctx.url('/eval'));
    } catch (e) {
      if (e.status === 429 && e.data.retry_after) {
        setDelay(Number(e.data.retry_after));
      } else if (e.status === 409) {
        toast(_('The project is busy, try again later.'), {error: true});
        button.disabled = false;
      } else {
        errorRow(e.message);
        button.disabled = false;
      }
      return;
    }
    const result = data.result || {};
    if (result.grades !== null && result.grades !== undefined) {
      renderTable(data.header || [], data.rows || []);
      caption.hidden = true;
      if (ctx.onEvaluated) {
        ctx.onEvaluated();      // the spectators load the archived evaluation again
      }
    }
    // grades null: still in the cooldown, the previous table stays
    const delay = Number(data.delay_before_self_grade || result.delay_before_self_grade || 0);
    if (delay > 0) {
      setDelay(delay);
    } else {
      button.disabled = false;
    }
  }

  button.addEventListener('click', start);
  return {
    id: 'evaluation',
    element: pane,
    show() {
      shown = true;
      if ((ctx.isInstructor || spectator) && !lastLoaded) {
        loadLast();
      }
    },
    hide() {
      shown = false;
    },
    update() {},
    // a spectator: the presenter evaluated: the last archived evaluation again
    reload() {
      lastLoaded = false;
      if (shown) {
        loadLast();
      }
    },
  };
}
