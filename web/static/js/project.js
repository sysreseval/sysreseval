// The project page: the tab bar and its panes (tabs/*.js), the data of GET {api_base} (the
// sanitised view of the project and the answers), the events WebSocket ({api_base}/events)
// refreshing them, the corner controls (instructor view, word wrap, content font size,
// Export Schema to PDF, Close project) and the touch keeping the project alive every minute.
//
// Three more roles: an instructor may present the project (present.js: the Present button, the
// bar, the view published after each change through the ctx.onViewChange / onEvaluated hooks of
// the tabs); the same page in the iframe of /present/{id} is a spectator's (data-presentation
// on the body): read-only, no control, the tabs and the terminals following the presenter's
// view (the socket /api/presentations/{id}/ws); and an instructor on a student's project may
// focus the student on it (focus.js: the Focus student on project button, the tab, the terminal
// and the question shared both ways with the student's own page, which follows through the same
// module).

import './base.js';
import * as api from './api.js';
import * as i18n from './i18n.js';
import * as settings from './settings.js';
import {_} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {ProjectEvents, ReconnectingSocket} from './events.js';
import {createPresenter} from './present.js';
import {createFocus} from './focus.js';
import {createSchemaTab} from './tabs/schema.js';
import {createInformationsTab} from './tabs/informations.js';
import {createMachinesTab} from './tabs/machines.js';
import {createNetworksTab} from './tabs/networks.js';
import {createQuestionsTab} from './tabs/questions.js';
import {createEvaluationTab} from './tabs/evaluation.js';
import {createTerminalsTab} from './tabs/terminals.js';
import {createDisplayTab} from './tabs/display.js';
import {createStatesTab} from './tabs/states.js';
import {createLogTab} from './tabs/log.js';

const TOUCH_INTERVAL = 60000;   // ms

const body = document.body;
const apiBase = body.dataset.apiBase;
const isInstructor = body.dataset.instructor === 'true';
const login = body.dataset.login || '';
const owner = (body.dataset.rln || '').split('@@@')[2] || '';
const isOwner = owner === login;
// a spectator of a presentation (the page in the iframe of /present/{id}): read-only, driven
// by the presenter's view
const presentationId = body.dataset.presentation || '';
const spectator = Boolean(presentationId);
const groupsEnabled = body.dataset.groups === 'true';
// an instructor on a student's project: the top bars take the helper colour (sre.css); the
// student's own page and a spectator's page keep theirs
if (isInstructor && !isOwner && !spectator) body.classList.add('helping');

const tabBar = document.getElementById('tabbar');
const panes = document.getElementById('panes');
const titleElement = document.getElementById('project-title');
const instructorToggle = document.getElementById('instructor-toggle');
const wrapToggle = document.getElementById('wrap-toggle');
const fontMinus = document.getElementById('font-minus');
const fontPlus = document.getElementById('font-plus');
const schemaPdfLink = document.getElementById('schema-pdf-link');
const closeButton = document.getElementById('close-project');
const closedBanner = document.getElementById('closed-banner');
const endedBanner = document.getElementById('ended-banner');          // a spectator's page
const presentButton = document.getElementById('present');             // an instructor's page
const presentationBar = document.getElementById('presentation-bar');
const focusButton = document.getElementById('focus-student');         // an instructor's page
const focusLabel = document.getElementById('focus-label');            // a student's page: "Followed by"
let presenter = null;      // the presentation side of an instructor's page (present.js)
let focus = null;          // the focus side (focus.js): the instructor's button, or the student's page following

const state = {
  project: null,
  answers: {},
  answersReadonly: false,   // an instructor on a student's project only reads the answers
  terminals: [],            // the live terminal sessions of the project (shared with the viewers)
  instructorView: false,
  closed: false,
  exportQuery: {},          // the options of the Schema tab, as the presenter's view carries them
  view: null,               // a spectator: the last view of the presenter applied
};

// What the tabs get: the project URLs (with the instructor view when it is on), the answers,
// the terminals, the tab selection, who the user is for this project.
const ctx = {
  isInstructor,
  isOwner,
  owner,
  login,
  spectator,
  url(suffix, params) {
    return api.withQuery(apiBase + suffix, {...(params || {}), view: state.instructorView ? 'instructor' : undefined});
  },
  answersReadonly() {
    return spectator || state.answersReadonly;
  },
  getAnswers() {
    return state.answers;
  },
  async putAnswers(patch) {
    const result = await api.put(ctx.url('/answers'), {answers: patch});
    if (result && result.answers) {
      state.answers = result.answers;
    }
    if (presenter) {
      presenter.bump('answers');     // the spectators fetch the answers again
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
    updateSchemaPdfLink();
    if (presenter) {
      presenter.schedule();
    }
  },
};
if (!spectator) {
  // the hooks of the tabs publishing the presenter's view and the view shared by a focus
  // (absent on a spectator's page, which applies the view without publishing anything)
  ctx.onViewChange = () => {
    if (presenter) {
      presenter.schedule();
    }
    if (focus) {
      focus.schedule();
    }
  };
  ctx.onEvaluated = () => {
    if (presenter) {
      presenter.bump('evaluated');
    }
  };
}

// -- tabs ----------------------------------------------------------------------------------------

const tabs = {};        // id -> the tab object (created on first use, kept across updates)
let currentTab = null;

function tabLabels() {
  return {
    schema: _('Schema'), full_schema: _('Full Schema'), informations: _('Informations'),
    machines: _('Machines'), networks: _('Networks'), questions: _('Questions'),
    evaluation: _('Evaluation'), terminals: _('Terminals'), display: _('Display'),
    apply_config: _('Apply Configuration'), log: _('Log'),
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
    case 'display': return createDisplayTab(ctx);
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

// options: what the tab's show() takes (the terminals tab: autoOpen false when a focus brings
// the page there, so that no terminal is opened for the user)
function selectTab(id, options = {}) {
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
  tabs[id].show(options);
  if (ctx.onViewChange) {
    ctx.onViewChange();
  }
}

function renderTabBar(ids) {
  const labels = tabLabels();
  clear(tabBar);
  for (const id of ids) {
    const button = el('button', {type: 'button', role: 'tab', dataset: {tab: id}}, labels[id] || id);
    button.setAttribute('aria-selected', id === currentTab ? 'true' : 'false');
    if (spectator) {
      button.disabled = true;        // the presenter chooses the tab
    } else {
      button.addEventListener('click', () => selectTab(id));
    }
    tabBar.append(button);
  }
}

// -- the project -------------------------------------------------------------------------------

function applyProject(project) {
  state.project = project;
  const name = project.title || project.lab_name;
  document.title = `${name} - SRE`;
  // somebody else's project (an instructor helping): the owner next to the title
  titleElement.textContent = isOwner || !owner ? name : `${name} (${owner})`;
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
  if (tabs.terminals) {
    tabs.terminals.setSessions(state.terminals);
  }
  instructorToggle.hidden = spectator || !(isInstructor && project.has_instructor_texts);
  instructorToggle.setAttribute('aria-pressed', state.instructorView ? 'true' : 'false');
  if (schemaPdfLink) {
    schemaPdfLink.hidden = spectator || !project.export_schema_pdf;
    updateSchemaPdfLink();
  }
  if (presentButton && presenter && !presenter.isPresenting()) {
    presentButton.hidden = false;
  }
  if (focus) {
    if (focusButton && isInstructor && !isOwner) {
      focusButton.hidden = false;
    }
    focus.projectLoaded();     // a view received before the load
  }
  if (spectator && pendingView) {
    const view = pendingView;
    pendingView = null;
    applyView(view);
  }
}

// The Export Schema to PDF link downloads the drawing of the Schema tab with its current options
// (never the Full Schema: the hidden machines are never exported, as in the Qt GUI).  The link
// may be missing when the page and this script are not of the same version (a script cached
// before an update): the project is shown without it.
function updateSchemaPdfLink() {
  if (schemaPdfLink) {
    schemaPdfLink.href = ctx.url('/schema.pdf', tabs.schema && tabs.schema.pdfQuery ? tabs.schema.pdfQuery() : {});
  }
}

// The view a focus shares both ways (focus.js): the active tab, the terminal sub-tab shown (by
// the id of its session: the two pages share the student's sessions; never a private terminal
// of the instructor, which the student must not see) and the question selected.
function focusView() {
  return {
    tab: currentTab,
    terminal: tabs.terminals ? tabs.terminals.focusTarget() : null,
    question: tabs.questions ? tabs.questions.getSelected() : null,
  };
}

// The other page's view of a focus applied here: nothing is closed, the rest of the page is
// left alone (the user keeps every control).
function applyFocusView(view) {
  if (!state.project || state.closed) {
    return;
  }
  const listed = (id) => (state.project.tabs.includes(id) ? tab(id) : null);
  const questions = listed('questions');
  if (questions && view.question) {
    questions.setSelected(view.question);
  }
  if (view.tab && view.tab !== currentTab) {
    selectTab(view.tab, {autoOpen: false});    // the other page went there: no terminal opened here
  }
  const terminals = listed('terminals');
  if (terminals && view.terminal) {
    terminals.focusSession(view.terminal);
  }
}

// The presenter's view, as present.js publishes it to the spectators.
function getView() {
  return {
    tab: currentTab,
    terminals: tabs.terminals ? tabs.terminals.getView() : {open: [], active: null},
    question: tabs.questions ? tabs.questions.getSelected() : null,
    schema: state.exportQuery,
    instructorView: state.instructorView,
  };
}

async function load() {
  const data = await api.get(ctx.url(''));
  state.answers = data.answers || {};
  state.answersReadonly = Boolean(data.answers_readonly);
  state.terminals = data.terminals || [];
  applyProject(data.project);
  if (tabs.questions) {
    tabs.questions.setAnswers(state.answers);
  }
}

// The page is over (the project closed, or the presentation ended): every socket closed, the
// tabs hidden; false when it already was.
function shutDown() {
  if (state.closed) {
    return false;
  }
  state.closed = true;
  events.close();
  if (presentationSocket) {
    presentationSocket.close();
  }
  if (touchTimer) {
    window.clearInterval(touchTimer);
  }
  if (tabs.terminals) {
    tabs.terminals.closeAll();
  }
  if (tabs.display) {
    tabs.display.close();
  }
  tabBar.hidden = true;
  panes.hidden = true;
  closeButton.disabled = true;
  if (presentButton) {
    presentButton.hidden = true;
  }
  return true;
}

function projectClosed() {
  if (state.closed) {
    return;
  }
  if (presenter) {
    presenter.end();      // the spectators are told the presentation is over (before the controls go)
  }
  if (focus) {
    focus.end();          // the student's page released (the instructor's page), or the label dropped
  }
  shutDown();
  closedBanner.hidden = false;
}

// A spectator: the presentation is over (the presenter stopped it, or left); the parent page
// removes the overlay when told.
function presentationEnded() {
  if (!shutDown()) {
    return;
  }
  if (endedBanner) {
    endedBanner.hidden = false;
  }
  if (window.parent !== window) {
    window.parent.postMessage({t: 'presentation-ended', id: presentationId}, window.location.origin);
  }
}

// -- a spectator: the presenter's view ----------------------------------------------------------

let pendingView = null;          // a view received before the project was loaded
let presentationSocket = null;

// The active tab, the terminals, the question, the schema options, the instructor texts, and
// the counters telling that the answers or the evaluation changed.
function applyView(view) {
  if (!view || typeof view !== 'object') {
    return;
  }
  if (!state.project || state.closed) {
    pendingView = view;
    return;
  }
  const previous = state.view;
  state.view = view;
  if (Boolean(view.instructorView) !== state.instructorView) {
    // the texts and the tabs change with the view: the project loaded again, then the view applied
    setInstructorView(Boolean(view.instructorView)).then(() => applyView(view));
    return;
  }
  if (previous && view.answers !== previous.answers) {
    load().catch(() => {});      // PUT answers are not broadcast by the agent
  }
  const listed = (id) => (state.project.tabs.includes(id) ? tab(id) : null);
  for (const id of ['schema', 'full_schema']) {
    const schema = listed(id);
    if (schema && view.schema) {
      schema.setOptions(view.schema);
    }
  }
  const questions = listed('questions');
  if (questions) {
    questions.setSelected(view.question || null);
  }
  if (view.tab) {
    selectTab(view.tab);
  }
  const terminals = listed('terminals');
  if (terminals) {
    terminals.setView(view.terminals || {});
  }
  if (previous && view.evaluated !== previous.evaluated && tabs.evaluation) {
    tabs.evaluation.reload();
  }
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
    case 'terminals':
      state.terminals = ev.terminals || [];
      if (tabs.terminals) {
        tabs.terminals.setSessions(state.terminals);
      }
      break;
    case 'evaluated':
      // a new archived evaluation (periodic, the student's, an instructor's): the instructor's
      // Evaluation tab, and a spectator's, show it
      if (tabs.evaluation && (ctx.isInstructor || spectator)) {
        tabs.evaluation.reload();
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
  const done = load().then(() => events.reopen(ctx.url('/events')))
                     .catch((e) => toast(e.message, {error: true}));
  if (ctx.onViewChange) {
    ctx.onViewChange();
  }
  return done;
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

if (isInstructor && !spectator && presentButton && presentationBar) {
  presenter = createPresenter(ctx, {
    host: body.dataset.host || '', rln: body.dataset.rln || '', login, groups: groupsEnabled, getView,
    elements: {
      button: presentButton, bar: presentationBar,
      status: document.getElementById('presentation-status'),
      edit: document.getElementById('presentation-edit'),
      stop: document.getElementById('presentation-stop'),
    },
  });
}

if (!spectator && focusLabel && (isOwner || (isInstructor && focusButton))) {
  // an instructor on a student's project leads a focus; the owner's page follows one
  focus = createFocus(ctx, {
    host: body.dataset.host || '', rln: body.dataset.rln || '', login, leader: isInstructor && !isOwner,
    getView: focusView, applyView: applyFocusView,
    isLoaded: () => Boolean(state.project) && !state.closed,
    elements: {button: focusButton, label: focusLabel},
  });
}

async function main() {
  await i18n.init();
  setupControls();
  if (spectator) {
    // the presenter's view, now and on every change; the socket is closed when the presentation
    // is over (a closed presentation closes it at once: the page ends cleanly even before the load)
    presentationSocket = new ReconnectingSocket(`/api/presentations/${encodeURIComponent(presentationId)}/ws`, {
      onMessage: (message) => {
        if (message.t === 'view' && message.view) {
          applyView(message.view);
        }
      },
      onClose: (ev) => {
        if (ev.code === 4411 || ev.code === 4403 || ev.code === 4404) {
          presentationEnded();
          return false;
        }
        return true;
      },
    });
    presentationSocket.connect();
  }
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
  if (presenter) {
    presenter.resume();       // a reloaded page goes on presenting
  }
  if (focus) {
    focus.resume();           // a reloaded page goes on focusing, or following
  }
}

main();
