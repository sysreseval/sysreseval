// The Projects page: the running projects of the user (GET /api/projects every 5 s), one card
// per project with its Open link and Close button.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, resolveText} from './i18n.js';
import {el, clear, toast, formatTimestamp} from './ui.js';
import {projectUrl} from './creation.js';

const REFRESH_INTERVAL = 5000;

const list = document.getElementById('projects');
const closing = new Set();   // running lab names whose close is in progress

function projectApi(project) {
  return `/api/projects/${encodeURIComponent(project.host)}/${encodeURIComponent(project.running_lab_name)}`;
}

function card(project) {
  const rln = project.running_lab_name;
  const title = resolveText(project.title) || project.lab_name;
  const closeButton = el('button', {type: 'button', class: 'danger'}, _('Close Project'));
  if (closing.has(rln)) {
    closeButton.disabled = true;
    closeButton.textContent = _('closing in progress...');
  }
  closeButton.addEventListener('click', async () => {
    if (!window.confirm(_('Close this project? Its machines will be stopped.'))) {
      return;
    }
    closing.add(rln);
    closeButton.disabled = true;
    closeButton.textContent = _('closing in progress...');
    try {
      await api.del(projectApi(project));
    } catch (e) {
      toast(e.message, {error: true});
    } finally {
      closing.delete(rln);
    }
    refresh();
  });
  return el('div', {class: 'card' + (project.debug_project ? ' debug' : '')},
    el('h2', {title: rln}, title),
    el('div', {class: 'meta'},
      el('div', {}, _('Lab: ') + project.lab_name),
      el('div', {}, _('Host: ') + project.host),
      el('div', {}, _('Started: ') + formatTimestamp(project.started_at))),
    el('div', {class: 'actions'},
      el('a', {class: 'button primary', href: projectUrl(project.host, rln)}, _('Open')),
      closeButton));
}

async function refresh() {
  let projects;
  try {
    projects = await api.get('/api/projects');
  } catch (e) {
    clear(list);
    list.append(el('p', {class: 'error'}, e.message));
    return;
  }
  clear(list);
  if (!projects.length) {
    list.append(el('p', {class: 'muted'}, _('No running project.')));
    return;
  }
  for (const project of projects) {
    list.append(card(project));
  }
}

async function main() {
  await i18n.init();
  await refresh();
  window.setInterval(refresh, REFRESH_INTERVAL);
}

main();
