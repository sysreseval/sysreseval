// The Informations tab: the course text of the lab, rendered from markdown by the agent
// (informations_html: the instructor fragments come as styled spans in the instructor view).
// The spectators of a presentation follow the presenter's scroll (scroll.js: the block of the
// text at the top of the pane).

import * as settings from '../settings.js';
import {el} from '../ui.js';
import {paneScroll} from '../scroll.js';

export function createInformationsTab(ctx) {
  const content = el('div', {class: 'content' + (settings.get('word_wrap') ? '' : ' nowrap')});
  const pane = el('div', {class: 'pane'}, content);
  settings.onChange('word_wrap', (wrap) => content.classList.toggle('nowrap', !wrap));
  return {
    id: 'informations',
    element: pane,
    show() {},
    hide() {},
    update(project) {
      content.innerHTML = project.informations_html || '';
    },
    ...paneScroll(pane, content),
  };
}
