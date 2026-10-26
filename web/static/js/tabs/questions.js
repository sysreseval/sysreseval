// The Questions tab: the titles on the left (in the order of the lab), the current question on
// the right: its description, then a text area (text question), the form of its chunks (form
// question) or nothing (a display-only question).  The answers are saved 500 ms after the last
// change (PUT {api_base}/answers); an answers event (a state applied) refreshes the current
// widget without saving again.  On somebody else's project (an instructor helping) the answers
// are shown read-only: nothing is saved.  A spectator of a presentation (ctx.spectator) cannot
// choose the question either: the presenter's choice is applied (setSelected), and on the
// presenter's page every choice calls ctx.onViewChange().

import * as settings from '../settings.js';
import {el, clear, toast} from '../ui.js';
import {_} from '../i18n.js';
import {Form} from '../form.js';

const TYPE_DUMMY = 0;
const TYPE_TEXT = 1;
const TYPE_FORM = 2;
const SAVE_DELAY = 500;   // ms

export function createQuestionsTab(ctx) {
  const list = el('ul', {class: 'question-list'});
  const panel = el('div', {class: 'question-panel'});
  const pane = el('div', {class: 'pane no-scroll'}, el('div', {class: 'questions'}, list, panel));

  let questions = [];
  let currentHash = null;
  let answers = {};          // hash -> stored value (a string; JSON text for a form)
  let pending = {};          // hash -> value to send (a string, or the object of a form)
  let timer = null;
  let saving = null;         // the promise of the PUT in progress
  let widget = null;         // {kind: 'text', textarea} | {kind: 'form', form} | null
  let wordWrap = settings.get('word_wrap');
  const spectator = Boolean(ctx.spectator);
  let wanted = null;         // a spectator: the presenter's question, until the list holds it

  settings.onChange('word_wrap', (wrap) => {
    wordWrap = wrap;
    const text = panel.querySelector('.question-text');
    if (text) {
      text.classList.toggle('nowrap', !wrap);
    }
    if (widget && widget.kind === 'text') {
      widget.textarea.classList.toggle('nowrap', !wrap);
      if (wrap) {
        widget.textarea.removeAttribute('wrap');
      } else {
        widget.textarea.setAttribute('wrap', 'off');
      }
    } else if (widget && widget.kind === 'form') {
      widget.form.setWordWrap(wrap);
    }
  });

  // -- saving -----------------------------------------------------------------------------
  function changed(hash, value) {
    if (ctx.answersReadonly && ctx.answersReadonly()) {
      return;
    }
    // value: the string of a text question, the answers object of a form
    answers[hash] = typeof value === 'string' ? value : JSON.stringify(value);
    pending[hash] = value;
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(flush, SAVE_DELAY);
  }

  async function flush() {
    timer = null;
    if (saving) {
      // a PUT is running: the next one goes after it
      timer = window.setTimeout(flush, SAVE_DELAY);
      return;
    }
    const patch = pending;
    pending = {};
    if (!Object.keys(patch).length) {
      return;
    }
    saving = ctx.putAnswers(patch);
    try {
      await saving;
    } catch (e) {
      toast(e.message, {error: true});
      pending = {...patch, ...pending};   // sent again with the next change
    } finally {
      saving = null;
    }
  }

  // The answers of the server with the changes not sent yet on top (ours win).
  function withPending(values) {
    const merged = {...(values || {})};
    for (const [hash, value] of Object.entries(pending)) {
      merged[hash] = typeof value === 'string' ? value : JSON.stringify(value);
    }
    return merged;
  }

  // -- display ------------------------------------------------------------------------------
  function parsedForm(hash) {
    try {
      const value = JSON.parse(answers[hash] || '{}');
      return value && typeof value === 'object' ? value : {};
    } catch (e) {
      return {};
    }
  }

  function renderCurrent() {
    clear(panel);
    widget = null;
    const question = questions.find((q) => q.question_hash === currentHash);
    if (!question) {
      return;
    }
    const type = question.question_type;
    const hash = question.question_hash;
    if (type === TYPE_FORM) {
      const container = el('div', {class: 'question-text content'});
      panel.append(container);
      const form = new Form(container, question.chunks || [], {
        wordWrap,
        onChange: (values) => changed(hash, values),
      });
      form.setAnswers(parsedForm(hash));
      widget = {kind: 'form', form};
      setReadonly(container);
      return;
    }
    const text = el('div', {class: 'question-text content' + (wordWrap ? '' : ' nowrap')});
    text.innerHTML = question.description_html || '';
    panel.append(text);
    if (type === TYPE_DUMMY) {
      return;
    }
    const textarea = el('textarea', {class: 'answer' + (wordWrap ? '' : ' nowrap'),
                                     placeholder: _('Write your answer here...')});
    if (!wordWrap) {
      textarea.setAttribute('wrap', 'off');
    }
    textarea.value = answers[hash] || '';
    textarea.addEventListener('input', () => changed(hash, textarea.value));
    panel.append(textarea);
    setReadonly(panel);
    widget = {kind: 'text', textarea};
  }

  // a non-owner reads the answers: every control of the question is disabled
  function setReadonly(container) {
    if (!(ctx.answersReadonly && ctx.answersReadonly())) {
      return;
    }
    for (const control of container.querySelectorAll('input, select, textarea, button')) {
      control.disabled = true;
    }
  }

  function select(hash) {
    currentHash = hash;
    for (const button of list.querySelectorAll('button')) {
      button.setAttribute('aria-selected', button.dataset.hash === hash ? 'true' : 'false');
    }
    renderCurrent();
    if (ctx.onViewChange) {
      ctx.onViewChange();
    }
  }

  function renderList() {
    clear(list);
    for (const question of questions) {
      const button = el('button', {type: 'button', dataset: {hash: question.question_hash}},
                        question.title || _('Untitled'));
      button.disabled = spectator;     // the presenter chooses the question
      button.addEventListener('click', () => select(question.question_hash));
      list.append(el('li', {}, button));
    }
  }

  const known = (hash) => hash !== null && questions.some((q) => q.question_hash === hash);

  return {
    id: 'questions',
    element: pane,
    show() {},
    hide() {},
    update(project) {
      questions = [...(project.questions || [])].sort((a, b) => (a.order || 0) - (b.order || 0));
      answers = withPending(ctx.getAnswers());
      renderList();
      if (known(wanted)) {
        const hash = wanted;
        wanted = null;
        select(hash);
        return;
      }
      select(known(currentHash) ? currentHash : (questions.length ? questions[0].question_hash : null));
    },
    // a spectator: the presenter's question (kept until the list holds it)
    setSelected(hash) {
      if (!hash || hash === currentHash) {
        return;
      }
      if (known(hash)) {
        select(hash);
      } else {
        wanted = hash;
      }
    },
    getSelected() {
      return currentHash;
    },
    // the answers changed on the server (a state applied, another tab of the browser)
    setAnswers(values) {
      answers = withPending(values);
      if (!widget || currentHash === null) {
        return;
      }
      if (widget.kind === 'text') {
        if (widget.textarea.value !== (answers[currentHash] || '')) {
          widget.textarea.value = answers[currentHash] || '';
        }
      } else {
        widget.form.setAnswers(parsedForm(currentHash));
      }
    },
  };
}
