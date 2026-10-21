// The Terminals tab: one sub-tab per device of the project (the machines, then the manageable
// switches), each opened lazily as an xterm.js terminal on the WebSocket of the device
// (terminal.js).  A device closed to the students is disabled (orange; a debug project opens it
// all the same, as `sre connect` lets a debug project in), a hidden machine of a debug project
// is red, like the Qt view.  The font size and colour scheme controls are on the right.

import * as settings from '../settings.js';
import {el, clear} from '../ui.js';
import {_} from '../i18n.js';
import {TerminalSession} from '../terminal.js';

export function createTerminalsTab(ctx) {
  const tabs = el('div', {class: 'terminal-tabs', role: 'tablist'});
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
  const bar = el('div', {class: 'ctrl-bar'}, tabs, el('span', {class: 'spacer'}), schemeSelect, smaller, larger);
  const pane = el('div', {class: 'pane no-scroll'}, el('div', {class: 'terminals'}, bar, host));

  const sessions = new Map();   // device -> {box, session}
  let devices = [];
  let debug = false;
  let current = null;
  let shown = false;

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

  function renderTabs() {
    clear(tabs);
    for (const device of devices) {
      const button = el('button', {type: 'button', role: 'tab', dataset: {device: device.name}}, device.name);
      if (device.hidden) {
        button.classList.add('hidden-device');
      } else if (!device.allow_connection) {
        button.classList.add('closed-device');
      }
      button.disabled = !canOpen(device);
      button.setAttribute('aria-selected', device.name === current ? 'true' : 'false');
      button.addEventListener('click', () => open(device.name));
      tabs.append(button);
    }
  }

  function open(name) {
    const device = devices.find((d) => d.name === name);
    if (!device || !canOpen(device)) {
      return;
    }
    current = name;
    for (const button of tabs.querySelectorAll('[role="tab"]')) {
      button.setAttribute('aria-selected', button.dataset.device === name ? 'true' : 'false');
    }
    let entry = sessions.get(name);
    if (!entry) {
      const box = el('div', {class: 'terminal-box'});
      host.append(box);
      const session = new TerminalSession(box, ctx.url(`/terminals/${encodeURIComponent(name)}`), {
        fontSize: settings.get('terminal_font_size'),
        scheme: settings.get('terminal_color_scheme'),
      });
      entry = {box, session};
      sessions.set(name, entry);
      for (const other of sessions.values()) {
        other.box.hidden = other !== entry;
      }
      session.connect();
    } else {
      for (const other of sessions.values()) {
        other.box.hidden = other !== entry;
      }
      entry.session.refit();
      entry.session.focus();
    }
  }

  return {
    id: 'terminals',
    element: pane,
    show() {
      shown = true;
      if (current) {
        open(current);
      } else {
        // the first open device, as the first terminal tab of the Qt view starts when shown
        const first = devices.find(canOpen);
        if (first) {
          open(first.name);
        }
      }
    },
    hide() {
      shown = false;
    },
    update(project) {
      devices = project.terminal_devices || [];
      debug = Boolean(project.debug_project);
      for (const [name, entry] of [...sessions]) {
        if (!devices.some((d) => d.name === name)) {
          entry.session.close();
          entry.box.remove();
          sessions.delete(name);
          if (current === name) {
            current = null;
          }
        }
      }
      renderTabs();
    },
    // the Connect buttons of the Machines / Networks tabs
    open(name) {
      const device = devices.find((d) => d.name === name);
      if (device && canOpen(device)) {
        current = name;   // show() opens the current device
      }
      ctx.selectTab('terminals');
      open(name);
    },
    closeAll() {
      for (const entry of sessions.values()) {
        entry.session.close();
      }
    },
    isShown() {
      return shown;
    },
  };
}
