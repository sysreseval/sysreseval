// The Machines tab: one row per visible machine, like the Qt table: Name, NAT network to host
// (Yes / No, green / red), Connection (a green Connect button opening the terminal of the
// machine, or an empty red cell when the lab forbids it), Ports.

import {el, clear} from '../ui.js';
import {_} from '../i18n.js';

export function createMachinesTab(ctx) {
  const table = el('table', {class: 'grid machines'});
  const pane = el('div', {class: 'pane'}, table);

  function render(project) {
    clear(table);
    table.append(el('thead', {}, el('tr', {},
      el('th', {}, _('Name')), el('th', {}, _('NAT network to host')),
      el('th', {}, _('Connection')), el('th', {}, _('Ports')))));
    const body = el('tbody');
    for (const machine of project.machines || []) {
      const connection = el('td');
      if (machine.allow_connection) {
        if (!ctx.spectator) {      // a spectator of a presentation opens nothing
          const button = el('button', {type: 'button', class: 'connect'}, _('Connect'));
          button.addEventListener('click', () => ctx.openTerminal(machine.name));
          connection.append(button);
        }
      } else {
        connection.className = 'closed';
      }
      const name = el('td', {}, machine.name);
      if (machine.hidden) {
        name.className = 'hidden-device';
      }
      body.append(el('tr', {},
        name,
        el('td', {class: machine.bridged ? 'yes' : 'no'}, machine.bridged ? _('Yes') : _('No')),
        connection,
        el('td', {}, machine.ports_text || '')));
    }
    table.append(body);
  }

  return {
    id: 'machines',
    element: pane,
    show() {},
    hide() {},
    update: render,
  };
}
