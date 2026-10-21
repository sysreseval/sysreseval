// The Apply Configuration tab: one row per state the user may apply (the admin-only ones in red
// for a debug project or the instructor view) with an Apply button (POST
// {api_base}/states/{name}); the button is disabled while the state runs, an error goes into
// its title; the answers the state may have set (cheat.json) are applied to the Questions tab.

import * as api from '../api.js';
import {el, clear, toast} from '../ui.js';
import {_} from '../i18n.js';

export function createStatesTab(ctx) {
  const table = el('table', {class: 'grid states'});
  const pane = el('div', {class: 'pane'}, table);

  async function apply(name, button) {
    button.disabled = true;
    button.title = '';
    try {
      const result = await api.post(ctx.url(`/states/${encodeURIComponent(name)}`));
      if (result && result.answers) {
        ctx.applyAnswers(result.answers);
      }
    } catch (e) {
      button.title = e.message;
      toast(e.message, {error: true});
    } finally {
      button.disabled = false;
    }
  }

  function render(project) {
    clear(table);
    const body = el('tbody');
    for (const state of project.states || []) {
      const button = el('button', {type: 'button'}, _('Apply'));
      button.addEventListener('click', () => apply(state.name, button));
      body.append(el('tr', {},
        el('td', {class: state.admin_only ? 'admin-only' : undefined}, state.label || state.name),
        el('td', {}, button)));
    }
    table.append(body);
  }

  return {
    id: 'apply_config',
    element: pane,
    show() {},
    hide() {},
    update: render,
  };
}
