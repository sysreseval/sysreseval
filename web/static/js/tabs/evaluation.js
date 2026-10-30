// The Evaluation tab: a "Start evaluation" button (POST {api_base}/eval) and the table of the
// grades the agent lays out (header labels and rows with their colours, from
// SRE/evaluation_table.py).  While the lab's cooldown runs, the button is replaced by a
// countdown "Next evaluation allowed in {n} s", as in the Qt view.  An instructor on somebody
// else's project (ctx.helper) first sees the last archived evaluation of the project
// (GET {api_base}/evaluation), whoever ran it; so does a spectator of a presentation
// (ctx.spectator, no button), again after each evaluation the presenter runs (reload); the
// presenter's page calls ctx.onEvaluated() then.  The owner, instructor or not, gets the
// student's tab: nothing loaded before the button, and the table its self-evaluation gives is
// kept (the letters of a lab hiding the marks, which no archive holds).  The spectators follow
// the presenter's scroll (scroll.js), applied again once the table is loaded.

import * as api from '../api.js';
import {el, clear, toast} from '../ui.js';
import {_, format} from '../i18n.js';
import {renderEvaluationTable} from '../evaluation_table.js';
import {paneScroll} from '../scroll.js';

export function createEvaluationTab(ctx) {
  const button = el('button', {type: 'button', class: 'primary'}, _('Start evaluation'));
  const countdown = el('span', {hidden: true});
  const caption = el('p', {class: 'evaluation-caption muted', hidden: true});
  const table = el('table', {class: 'grid evaluation'});
  const pane = el('div', {class: 'pane'}, el('div', {class: 'evaluation-bar'}, button, countdown), caption, table);
  const scroll = paneScroll(pane);
  let columns = 3;
  let deadline = null;   // ms timestamp of the end of the cooldown
  let timer = null;
  let lastLoaded = false;
  let shown = false;
  let wantedScroll = null;   // a spectator: the presenter's scroll, applied again when the table arrives
  const spectator = Boolean(ctx.spectator);
  if (spectator) {
    button.hidden = true;
  }

  function renderTable(header, rows) {
    columns = renderEvaluationTable(table, header, rows);
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

  // a helper or a spectator: the last archived evaluation, with its date and the errors of the run
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
    scroll.setScroll(wantedScroll);
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
      if ((ctx.helper || spectator) && !lastLoaded) {
        loadLast();
      }
    },
    hide() {
      shown = false;
    },
    update() {},
    // the last archived evaluation again: a helper's page on the `evaluated` event (a periodic
    // evaluation, the student's, another instructor's), a spectator's when the presenter
    // evaluated; never the owner's page (project.js), whose own table stays
    reload() {
      lastLoaded = false;
      if (shown) {
        loadLast();
      }
    },
    getScroll: scroll.getScroll,
    setScroll(anchor) {
      wantedScroll = anchor;
      scroll.setScroll(anchor);
    },
  };
}
