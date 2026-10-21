// The Terminals tab: one sub-tab per open terminal.  Each Connect button of the Machines and
// Networks tabs opens a new terminal on its device (like a new xterm in the Qt GUI), so a
// machine may have several (titled "gw", "gw (2)", ...); the select at the end of the bar opens
// one on any device.  Every terminal is an xterm.js on the WebSocket of its device
// (terminal.js), closed with the × of its sub-tab.  A device closed to the students is disabled
// (orange; a debug project opens it all the same, as `sre connect` lets a debug project in), a
// hidden machine of a debug project is red, like the Qt view.  The font size and colour scheme
// controls are on the right.

import * as settings from '../settings.js';
import {el, clear} from '../ui.js';
import {_, format} from '../i18n.js';
import {TerminalSession} from '../terminal.js';

export function createTerminalsTab(ctx) {
  const tabs = el('div', {class: 'terminal-tabs', role: 'tablist'});
  const newSelect = el('select', {class: 'new-terminal', title: _('New terminal…')});
  const host = el('div', {class: 'terminal-host'});
  const schemeSelect = el('select', {title: _('Color scheme')},
    el('option', {value: 'black_on_white'}, _('Black on White')),
    el('option', {value: 'white_on_black'}, _('White on Black')));
  schemeSelect.value = settings.get('terminal_color_scheme');
  schemeSelect.addEventListener('change', () => settings.set('terminal_color_scheme', schemeSelect.value));
  const smaller = el('button', {type: 'button', title: _('Smaller terminal font')}, 'A−');
  const larger = el('button', {type: 'button', title: _('Larger terminal font')}, 'A+');
  smaller.addEventListener('click', () => settings.set('terminal_font_size', settings.get('terminal_font_size') - 1));
  larger.addEventListener('click', () => settings.set('terminal_font_size', settings.get('terminal_font_size') + 1));
  const bar = el('div', {class: 'ctrl-bar'}, tabs, newSelect, el('span', {class: 'spacer'}), schemeSelect, smaller, larger);
  const pane = el('div', {class: 'pane no-scroll'}, el('div', {class: 'terminals'}, bar, host));

  const sessions = new Map();   // id -> {id, device, title, box, tab, session}, in opening order
  const counters = new Map();   // device -> number of terminals opened on it so far (the titles)
  let nextId = 1;
  let devices = [];
  let debug = false;
  let current = null;           // the id of the shown terminal
  let pending = null;           // a device being opened by a Connect button: show() must not auto-open

  settings.onChange('terminal_font_size', (size) => {
    for (const {session} of sessions.values()) {
      session.setFontSize(size);
    }
  });
  settings.onChange('terminal_color_scheme', (scheme) => {
    for (const {session} of sessions.values()) {
      session.setScheme(scheme);
    }
  });

  function canOpen(device) {
    return Boolean(device.allow_connection || debug);
  }

  function deviceOf(name) {
    return devices.find((d) => d.name === name);
  }

  function deviceClass(device) {
    if (!device) {
      return null;
    }
    return device.hidden ? 'hidden-device' : (device.allow_connection ? null : 'closed-device');
  }

  // the select opening a new terminal on a device
  function renderSelect() {
    clear(newSelect);
    newSelect.append(el('option', {value: ''}, _('New terminal…')));
    for (const device of devices) {
      const option = el('option', {value: device.name, class: deviceClass(device)}, device.name);
      option.disabled = !canOpen(device);
      newSelect.append(option);
    }
    newSelect.value = '';
  }
  newSelect.addEventListener('change', () => {
    const name = newSelect.value;
    newSelect.value = '';
    if (name) {
      openNew(name);
    }
  });

  function titleFor(name) {
    const n = (counters.get(name) || 0) + 1;
    counters.set(name, n);
    return n === 1 ? name : format(_('{device} ({n})'), {device: name, n});
  }

  function makeTab(entry) {
    const close = el('span', {class: 'close', role: 'button', title: _('Close terminal'),
      'aria-label': _('Close terminal')}, '×');
    close.addEventListener('click', (event) => {
      event.stopPropagation();
      closeSession(entry.id);
    });
    const button = el('button', {type: 'button', role: 'tab', class: deviceClass(deviceOf(entry.device)),
      dataset: {id: String(entry.id), device: entry.device}}, entry.title, close);
    button.addEventListener('click', () => select(entry.id));
    return button;
  }

  function select(id) {
    const entry = sessions.get(id);
    if (!entry) {
      return;
    }
    current = id;
    for (const other of sessions.values()) {
      other.box.hidden = other !== entry;
      other.tab.setAttribute('aria-selected', other === entry ? 'true' : 'false');
    }
    entry.session.refit();
    entry.session.focus();
  }

  // a new terminal on a device: a new box, a new sub-tab, a new WebSocket
  function openNew(name) {
    const device = deviceOf(name);
    if (!device || !canOpen(device)) {
      return null;
    }
    const id = nextId++;
    const box = el('div', {class: 'terminal-box'});
    host.append(box);
    const session = new TerminalSession(box, ctx.url(`/terminals/${encodeURIComponent(name)}`), {
      fontSize: settings.get('terminal_font_size'),
      scheme: settings.get('terminal_color_scheme'),
    });
    const entry = {id, device: name, title: titleFor(name), box, session, tab: null};
    entry.tab = makeTab(entry);
    tabs.append(entry.tab);
    sessions.set(id, entry);
    select(id);
    session.connect();
    return entry;
  }

  // the × of a sub-tab (or a device gone from the project): the WebSocket is closed, which ends
  // `sre connect` on the host; the neighbouring terminal is shown
  function closeSession(id) {
    const entry = sessions.get(id);
    if (!entry) {
      return;
    }
    const ids = [...sessions.keys()];
    const index = ids.indexOf(id);
    entry.session.close();
    entry.box.remove();
    entry.tab.remove();
    sessions.delete(id);
    if (current === id) {
      current = null;
      const neighbour = sessions.has(ids[index + 1]) ? ids[index + 1] : ids[index - 1];
      if (neighbour !== undefined && sessions.has(neighbour)) {
        select(neighbour);
      }
    }
  }

  return {
    id: 'terminals',
    element: pane,
    show() {
      if (current !== null) {
        select(current);
      } else if (sessions.size === 0 && pending === null) {
        // the first open device, as the first terminal tab of the Qt view starts when shown
        const first = devices.find(canOpen);
        if (first) {
          openNew(first.name);
        }
      }
    },
    hide() {},
    update(project) {
      devices = project.terminal_devices || [];
      debug = Boolean(project.debug_project);
      for (const entry of [...sessions.values()]) {
        if (!deviceOf(entry.device)) {
          closeSession(entry.id);
        }
      }
      renderSelect();
    },
    // the Connect buttons of the Machines / Networks tabs: a new terminal every time
    openNew(name) {
      pending = name;
      try {
        ctx.selectTab('terminals');
      } finally {
        pending = null;
      }
      openNew(name);
    },
    closeAll() {
      for (const entry of sessions.values()) {
        entry.session.close();
      }
    },
  };
}
