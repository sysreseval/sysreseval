// The Networks tab: the networks of the project seen as switches: Name, Type (Hub, Switch,
// Manageable switch; red when a manageable switch is closed to the students) and, for a
// manageable switch open to the students, a Connect button opening its management console (in
// a debug project a closed switch gets an orange button all the same, like the Qt view).

import {el, clear} from '../ui.js';
import {_} from '../i18n.js';
import {paneScroll} from '../scroll.js';

const MODE_MANAGED = 'managed';
const MODE_SWITCH = 'switch';

function modeLabel(mode) {
  if (mode === MODE_MANAGED) {
    return _('Manageable switch');
  }
  if (mode === MODE_SWITCH) {
    return _('Switch');
  }
  return _('Hub');
}

export function createNetworksTab(ctx) {
  const table = el('table', {class: 'grid networks'});
  const pane = el('div', {class: 'pane'}, table);

  function render(project) {
    clear(table);
    table.append(el('thead', {}, el('tr', {},
      el('th', {}, _('Name')), el('th', {}, _('Type')), el('th', {}, _('Connection')))));
    const body = el('tbody');
    for (const network of project.switches || []) {
      const managed = network.mode === MODE_MANAGED;
      const allowed = Boolean(network.allow_connection);
      const type = el('td', {class: 'center' + (managed && !allowed ? ' closed' : '')}, modeLabel(network.mode));
      const connection = el('td');
      if (managed && (allowed || project.debug_project) && !ctx.spectator) {
        const button = el('button', {type: 'button', class: 'connect' + (allowed ? '' : ' debug')}, _('Connect'));
        button.addEventListener('click', () => ctx.openTerminal(network.name));
        connection.append(button);
      }
      body.append(el('tr', {}, el('td', {}, network.name), type, connection));
    }
    table.append(body);
  }

  return {
    id: 'networks',
    element: pane,
    show() {},
    hide() {},
    update: render,
    ...paneScroll(pane),     // the spectators of a presentation follow the presenter's scroll
  };
}
