// The project page: the tab bar and its panes (tabs/*.js), the data of GET {api_base} (the
// sanitised view of the project and the answers), the events WebSocket ({api_base}/events)
// refreshing them, the corner controls (instructor view, word wrap, content font size,
// Export links, Close project) and the touch keeping the project alive every minute.

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import * as settings from './settings.js';
import {_} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {ProjectEvents} from './events.js';
import {createSchemaTab} from './tabs/schema.js';
import {createInformationsTab} from './tabs/informations.js';
import {createMachinesTab} from './tabs/machines.js';
import {createNetworksTab} from './tabs/networks.js';
import {createQuestionsTab} from './tabs/questions.js';
import {createEvaluationTab} from './tabs/evaluation.js';
import {createTerminalsTab} from './tabs/terminals.js';
import {createStatesTab} from './tabs/states.js';
import {createLogTab} from './tabs/log.js';

const TOUCH_INTERVAL = 60000;   // ms

const body = document.body;
const apiBase = body.dataset.apiBase;
const isInstructor = body.dataset.instructor === 'true';

const tabBar = document.getElementById('tabbar');
const panes = document.getElementById('panes');
const titleElement = document.getElementById('project-title');
const instructorToggle = document.getElementById('instructor-toggle');
const wrapToggle = document.getElementById('wrap-toggle');
const fontMinus = document.getElementById('font-minus');
const fontPlus = document.getElementById('font-plus');
const exportLink = document.getElementById('export-link');
const closeButton = document.getElementById('close-project');
const closedBanner = document.getElementById('closed-banner');

const state = {
  project: null,
  answers: {},
  instructorView: false,
  closed: false,
  exportQuery: {},
};

// What the tabs get: the project URLs (with the instructor view when it is on), the answers,
// the terminals, the tab selection.
const ctx = {
  url(suffix, params) {
    return api.withQuery(apiBase + suffix, {...(params || {}), view: state.instructorView ? 'instructor' : undefined});
  },
  getAnswers() {
    return state.answers;
  },
  async putAnswers(patch) {
    const result = await api.put(ctx.url('/answers'), {answers: patch});
    if (result && result.answers) {
      state.answers = result.answers;
    }
    return result;
  },
  applyAnswers(answers) {
    state.answers = answers || {};
    if (tabs.questions) {
      tabs.questions.setAnswers(state.answers);
    }
  },
  openTerminal(device) {
    tabs.terminals.openNew(device);   // a new terminal every time, like a new xterm in the Qt GUI
  },
  selectTab,
  onSchemaOptions(query) {
    state.exportQuery = query;
    updateExportLink();
  },
};

// -- tabs ----------------------------------------------------------------------------------------

const tabs = {};        // id -> the tab object (created on first use, kept across updates)
let currentTab = null;

function tabLabels() {
  return {
    schema: _('Schema'), full_schema: _('Full Schema'), informations: _('Informations'),
    machines: _('Machines'), networks: _('Networks'), questions: _('Questions'),
    evaluation: _('Evaluation'), terminals: _('Terminals'), apply_config: _('Apply Configuration'),
    log: _('Log'),
  };
}

function createTab(id) {
  switch (id) {
    case 'schema': return createSchemaTab(ctx);
    case 'full_schema': return createSchemaTab(ctx, {hidden: true});
    case 'informations': return createInformationsTab(ctx);
    case 'machines': return createMachinesTab(ctx);
    case 'networks': return createNetworksTab(ctx);
    case 'questions': return createQuestionsTab(ctx);
    case 'evaluation': return createEvaluationTab(ctx);
    case 'terminals': return createTerminalsTab(ctx);
    case 'apply_config': return createStatesTab(ctx);
    case 'log': return createLogTab(ctx);
    default: return null;
  }
}

function tab(id) {
  if (!tabs[id]) {
    const created = createTab(id);
    if (!created) {
      return null;
    }
    tabs[id] = created;
    created.element.hidden = true;
    created.element.setAttribute('role', 'tabpanel');
    panes.append(created.element);
  }
  return tabs[id];
}

function selectTab(id) {
  if (!state.project || !state.project.tabs.includes(id) || !tab(id)) {
    return;
  }
  if (currentTab && currentTab !== id && tabs[currentTab]) {
    tabs[currentTab].element.hidden = true;
    tabs[currentTab].hide();
  }
  currentTab = id;
  for (const button of tabBar.querySelectorAll('[role="tab"]')) {
    button.setAttribute('aria-selected', button.dataset.tab === id ? 'true' : 'false');
  }
  tabs[id].element.hidden = false;
  tabs[id].show();
}

function renderTabBar(ids) {
  const labels = tabLabels();
  clear(tabBar);
  for (const id of ids) {
    const button = el('button', {type: 'button', role: 'tab', dataset: {tab: id}}, labels[id] || id);
    button.setAttribute('aria-selected', id === currentTab ? 'true' : 'false');
    button.addEventListener('click', () => selectTab(id));
    tabBar.append(button);
  }
}

// -- the project -------------------------------------------------------------------------------

function applyProject(project) {
  state.project = project;
  document.title = `${project.title || project.lab_name} - SRE`;
  titleElement.textContent = project.title || project.lab_name;
  renderTabBar(project.tabs);
  for (const id of project.tabs) {
    const t = tab(id);
    if (t) {
      t.update(project);
    }
  }
  // the tabs that are no longer listed (the Log tab after the instructor view is turned off)
  for (const [id, t] of Object.entries(tabs)) {
    if (!project.tabs.includes(id)) {
      t.element.hidden = true;
      if (currentTab === id) {
        currentTab = null;
      }
    }
  }
  if (!currentTab || !project.tabs.includes(currentTab)) {
    selectTab(project.tabs[0]);
  }
  instructorToggle.hidden = !(isInstructor && project.has_instructor_texts);
  instructorToggle.setAttribute('aria-pressed', state.instructorView ? 'true' : 'false');
  exportLink.hidden = !project.export_kathara_project;
  updateExportLink();
}

function updateExportLink() {
  exportLink.href = ctx.url('/export', state.exportQuery);
}

async function load() {
  const data = await api.get(ctx.url(''));
  state.answers = data.answers || {};
  applyProject(data.project);
  if (tabs.questions) {
    tabs.questions.setAnswers(state.answers);
  }
}

function projectClosed() {
  if (state.closed) {
    return;
  }
  state.closed = true;
  events.close();
  if (touchTimer) {
    window.clearInterval(touchTimer);
  }
  if (tabs.terminals) {
    tabs.terminals.closeAll();
  }
  tabBar.hidden = true;
  panes.hidden = true;
  closedBanner.hidden = false;
  closeButton.disabled = true;
}

// -- the events socket -------------------------------------------------------------------------

function onEvent(ev) {
  if (state.closed) {
    return;
  }
  switch (ev.t) {
    case 'info':
      if (ev.project) {
        applyProject(ev.project);
      }
      break;
    case 'answers':
      ctx.applyAnswers(ev.answers || {});
      break;
    case 'log':
      if (tab('log')) {
        tabs.log.onLog(ev);
      }
      break;
    case 'removed':
      projectClosed();
      break;
    default:
      break;
  }
}

const events = new ProjectEvents(ctx.url('/events'), {
  onEvent,
  onReconnect: () => {
    // the events missed while the socket was down: fetch everything again
    load().catch((e) => {
      if (e.status === 404) {
        projectClosed();
      } else {
        toast(e.message, {error: true});
      }
    });
  },
});

let touchTimer = null;

// -- corner controls ---------------------------------------------------------------------------

function setInstructorView(on) {
  state.instructorView = on;
  instructorToggle.setAttribute('aria-pressed', on ? 'true' : 'false');
  if (tabs.log) {
    tabs.log.reset();
  }
  load().then(() => events.reopen(ctx.url('/events')))
        .catch((e) => toast(e.message, {error: true}));
}

function adjustFontSize(delta) {
  settings.set('content_font_size', settings.get('content_font_size') + delta);
}

function setupControls() {
  instructorToggle.addEventListener('click', () => setInstructorView(!state.instructorView));
  wrapToggle.setAttribute('aria-pressed', settings.get('word_wrap') ? 'true' : 'false');
  wrapToggle.addEventListener('click', () => {
    const wrap = !settings.get('word_wrap');
    settings.set('word_wrap', wrap);
    wrapToggle.setAttribute('aria-pressed', wrap ? 'true' : 'false');
  });
  fontMinus.addEventListener('click', () => adjustFontSize(-1));
  fontPlus.addEventListener('click', () => adjustFontSize(1));
  // Ctrl+plus / Ctrl+minus change the content font size, as in the Qt views (not in a terminal)
  document.addEventListener('keydown', (ev) => {
    const inTerminal = ev.target instanceof Element && ev.target.closest('.xterm');
    if (!ev.ctrlKey || ev.altKey || ev.metaKey || inTerminal) {
      return;
    }
    if (ev.key === '+' || ev.key === '=') {
      ev.preventDefault();
      adjustFontSize(1);
    } else if (ev.key === '-' || ev.key === '_') {
      ev.preventDefault();
      adjustFontSize(-1);
    }
  });
  closeButton.addEventListener('click', async () => {
    if (!window.confirm(_('Close this project? Its machines will be stopped.'))) {
      return;
    }
    closeButton.disabled = true;
    closeButton.textContent = _('closing in progress...');
    try {
      await api.del(ctx.url(''));
      projectClosed();
      window.location.href = '/projects';
    } catch (e) {
      toast(e.message, {error: true});
      closeButton.disabled = false;
      closeButton.textContent = _('Close Project');
    }
  });
}

// -- start -------------------------------------------------------------------------------------

async function main() {
  await i18n.init();
  setupControls();
  try {
    await load();
  } catch (e) {
    if (e.status === 404) {
      projectClosed();
      return;
    }
    tabBar.hidden = true;
    panes.append(el('div', {class: 'banner error'}, e.message));
    return;
  }
  events.connect();
  touchTimer = window.setInterval(() => {
    api.post(ctx.url('/touch')).catch(() => {});
  }, TOUCH_INTERVAL);
}

main();
