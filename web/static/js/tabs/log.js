// The Log tab of a debug or instructor-mode project: the operations log (what every state and
// evaluation executed).  The file is read once when the tab is first shown (GET
// {api_base}/log?offset=0), then the "log" events of the project socket are appended (reset:
// the file was truncated).  At most MAX_LINES lines are kept; Clear empties the display only.

import * as api from '../api.js';
import {el} from '../ui.js';
import {_} from '../i18n.js';

const MAX_LINES = 100000;   // params.operations_log_view_max_lines

export function createLogTab(ctx) {
  const clearButton = el('button', {type: 'button'}, _('Clear'));
  const view = el('pre', {class: 'log-view'});
  const pane = el('div', {class: 'pane no-scroll'},
                  el('div', {class: 'ctrl-bar'}, el('span', {class: 'spacer'}), clearButton), view);
  let loaded = false;
  let loading = false;
  const backlog = [];   // events received before the first read of the file

  clearButton.addEventListener('click', () => {
    view.textContent = '';
  });

  function append(text, reset) {
    if (reset) {
      view.textContent = '';
    }
    if (!text) {
      return;
    }
    const atBottom = view.scrollTop + view.clientHeight >= view.scrollHeight - 4;
    let content = view.textContent + text;
    // keep the last MAX_LINES lines
    let count = 0;
    let index = content.length;
    while (count <= MAX_LINES && index > 0) {
      index = content.lastIndexOf('\n', index - 1);
      if (index < 0) {
        break;
      }
      count += 1;
    }
    if (count > MAX_LINES && index >= 0) {
      content = content.slice(index + 1);
    }
    view.textContent = content;
    if (atBottom) {
      view.scrollTop = view.scrollHeight;
    }
  }

  async function load() {
    if (loaded || loading) {
      return;
    }
    loading = true;
    try {
      const data = await api.get(ctx.url('/log', {offset: 0}));
      append(data.data || '', true);
      loaded = true;
      for (const ev of backlog) {
        append(ev.data || '', Boolean(ev.reset));
      }
      backlog.length = 0;
    } catch (e) {
      append(e.message + '\n', true);
    } finally {
      loading = false;
    }
  }

  return {
    id: 'log',
    element: pane,
    show() {
      load();
    },
    hide() {},
    update() {},
    // a "log" event of the project socket
    onLog(ev) {
      if (loaded) {
        append(ev.data || '', Boolean(ev.reset));
      } else {
        backlog.push(ev);
      }
    },
    reset() {
      loaded = false;
      backlog.length = 0;
      view.textContent = '';
    },
  };
}
