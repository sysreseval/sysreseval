// The Webconf tab of the project page: the slot the BBB client is placed over when the user
// docks the web conference into the page (webconf.js keeps the one iframe, fixed over the slot,
// alive while another tab is shown), with the buttons to open it in a window again, to show it
// full page, or to leave (a private conversation: to end it).  The tab button appears while a
// conference is shown (project.js: ctx.setWebconfTab, called by webconf.js through the host
// registered here).

import {el} from '../ui.js';
import {_} from '../i18n.js';
import {act, current, leaveLabel, setTabHost} from '../webconf.js';

export function createWebconfTab(ctx) {
  const undock = el('button', {type: 'button', title: _('Open in a window')}, '⧉');
  const full = el('button', {type: 'button', title: _('Full screen')}, '⛶');
  const leave = el('button', {type: 'button', class: 'danger'}, _('Leave the conference'));
  const slot = el('div', {class: 'webconf-slot'});
  const pane = el('div', {class: 'pane no-scroll webconf'},
                  el('div', {class: 'ctrl-bar'}, undock, full, el('span', {class: 'spacer'}), leave), slot);
  undock.addEventListener('click', () => act('undock'));
  full.addEventListener('click', () => act('full'));
  leave.addEventListener('click', () => act('leave'));
  document.addEventListener('sre-webconf', () => {
    if (current()) {
      leave.textContent = leaveLabel(current());
    }
  });
  setTabHost({slot, select: () => ctx.selectTab('webconf'), onAvailable: (live) => ctx.setWebconfTab(live)});
  return {
    id: 'webconf',
    element: pane,
    show() {},
    hide() {},
    update() {},
  };
}
