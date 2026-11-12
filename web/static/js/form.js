// The forms described by the @@{field:spec}@@ grammar (SRE/form_spec.py): the form questions and
// the Flavor form of a lab.  The server sends the description as chunks, in order:
//   {type: "text", html}                                   markdown already rendered
//   {type: "field", name, kind, options, lines, regex, default, label}
// with kind "checkbox" (on the row of the preceding text, as in the Qt widget), "select"
// (options = [[label, value], ...]), "multiline" (lines), "line" (regex, a hint: the server
// stores what is typed) or "submit" (Flavor forms only: a button).
// The chunks of an inline row (the fields a lab names name~N, with the texts of their source
// line) all carry the same `row` number and are drawn side by side; such a "line" field has a
// `width` in characters.  The other chunks have no `row`: one field per row, below its text.

import {el} from './ui.js';
import {_} from './i18n.js';

// The chunks in the groups the form draws: {inline: false, items: [chunk]} for a chunk without
// `row`, {inline: true, row, items} for the consecutive chunks of one inline row.
export function groupRows(chunks) {
  const groups = [];
  let open = null;   // the inline group being filled
  for (const chunk of chunks || []) {
    const row = chunk.row;
    if (row === undefined || row === null) {
      open = null;
      groups.push({inline: false, items: [chunk]});
    } else if (open && open.row === row) {
      open.items.push(chunk);
    } else {
      open = {inline: true, row, items: [chunk]};
      groups.push(open);
    }
  }
  return groups;
}

export class Form {
  // container: the element the form is rendered into (emptied first)
  // onChange(answers): called after every change of a field
  // onSubmit(buttonName): a submit button was pressed (null for the default button)
  // allowSubmit: add a default Submit button when the chunks hold none (Flavor forms)
  constructor(container, chunks, {onChange = null, onSubmit = null, allowSubmit = false, wordWrap = true} = {}) {
    this.container = container;
    this.onChange = onChange;
    this.onSubmit = onSubmit;
    this.inputs = {};        // field name -> input / select / textarea / checkbox
    this.kinds = {};         // field name -> kind
    this.submitButtons = {}; // field name -> button
    this.loading = false;    // true while setAnswers() fills the fields (no onChange)
    this.wordWrap = wordWrap;
    this.render(chunks, allowSubmit);
  }

  render(chunks, allowSubmit) {
    const container = this.container;
    container.textContent = '';
    container.classList.add('form');
    const notify = () => {
      if (!this.loading && this.onChange) {
        this.onChange(this.getAnswers());
      }
    };
    let pendingText = null;   // the text chunk waiting for the field that follows it
    const textElement = (chunk) => {
      const div = el('div', {class: 'form-text content' + (this.wordWrap ? '' : ' nowrap')});
      div.innerHTML = chunk.html;   // rendered by the server from the lab markdown
      return div;
    };
    const flush = () => {
      if (pendingText) {
        container.append(textElement(pendingText));
        pendingText = null;
      }
    };
    const selectInput = (chunk) => {
      const select = el('select', {name: chunk.name});
      for (const [label, value] of chunk.options || []) {
        select.append(el('option', {value}, label));
      }
      select.addEventListener('change', notify);
      this.inputs[chunk.name] = select;
      return select;
    };
    const lineInput = (chunk) => {
      // size: the width in characters of an inline field
      const input = el('input', {type: 'text', name: chunk.name, size: chunk.width || null});
      if (chunk.regex) {
        // a hint for the browser (:invalid); the pattern must be a valid JavaScript regex
        try {
          new RegExp(chunk.regex);
          input.setAttribute('pattern', chunk.regex);
        } catch (e) {
          // a Python-only pattern: no hint
        }
      }
      input.addEventListener('input', notify);
      this.inputs[chunk.name] = input;
      return input;
    };
    for (const group of groupRows(chunks)) {
      if (group.inline) {
        // the texts and the fields of one source line, side by side
        flush();
        const row = el('div', {class: 'form-row inline'});
        for (const item of group.items) {
          if (item.type === 'text') {
            row.append(textElement(item));
          } else {
            this.kinds[item.name] = item.kind;
            row.append(item.kind === 'select' ? selectInput(item) : lineInput(item));
          }
        }
        container.append(row);
        continue;
      }
      const chunk = group.items[0];
      if (chunk.type === 'text') {
        flush();
        pendingText = chunk;
        continue;
      }
      const name = chunk.name;
      this.kinds[name] = chunk.kind;
      if (chunk.kind === 'checkbox') {
        const box = el('input', {type: 'checkbox', name});
        box.checked = Boolean(chunk.default);
        box.addEventListener('change', notify);
        this.inputs[name] = box;
        if (pendingText) {
          // same row as the preceding text, the box at its end
          container.append(el('div', {class: 'form-row'}, textElement(pendingText), box));
          pendingText = null;
        } else {
          container.append(el('div', {class: 'form-field'}, box));
        }
        continue;
      }
      flush();
      if (chunk.kind === 'submit') {
        const button = el('button', {type: 'button'}, chunk.label || name);
        button.addEventListener('click', () => this.submit(name));
        this.submitButtons[name] = button;
        container.append(el('div', {class: 'form-field'}, button));
      } else if (chunk.kind === 'select') {
        container.append(el('div', {class: 'form-field'}, selectInput(chunk)));
      } else if (chunk.kind === 'multiline') {
        const area = el('textarea', {name, rows: chunk.lines || 4});
        if (!this.wordWrap) {
          area.setAttribute('wrap', 'off');
        }
        area.addEventListener('input', notify);
        this.inputs[name] = area;
        container.append(el('div', {class: 'form-field'}, area));
      } else {
        container.append(el('div', {class: 'form-field'}, lineInput(chunk)));
      }
    }
    flush();
    if (allowSubmit && !Object.keys(this.submitButtons).length) {
      const button = el('button', {type: 'button', class: 'primary'}, _('Submit'));
      button.addEventListener('click', () => this.submit(null));
      container.append(el('div', {class: 'form-field'}, button));
    }
  }

  // The values of the fields: strings for the texts and selects, booleans for the checkboxes
  // and, after a submit, true for the pressed button and false for the others.
  getAnswers() {
    const answers = {};
    for (const [name, input] of Object.entries(this.inputs)) {
      answers[name] = input.type === 'checkbox' ? input.checked : input.value;
    }
    for (const name of Object.keys(this.submitButtons)) {
      answers[name] = name === this.pressed;
    }
    return answers;
  }

  // Fill the fields from {name: value} without calling onChange.
  setAnswers(answers) {
    answers = answers || {};
    this.loading = true;
    try {
      for (const [name, input] of Object.entries(this.inputs)) {
        if (!(name in answers)) {
          continue;
        }
        const value = answers[name];
        if (input.type === 'checkbox') {
          input.checked = Boolean(value);
        } else if (input.tagName === 'SELECT') {
          const text = value === null || value === undefined ? '' : String(value);
          const options = Array.from(input.options);
          const byValue = options.find((o) => o.value === text) || options.find((o) => o.text === text);
          if (byValue) {
            input.value = byValue.value;
          }
        } else {
          input.value = value === null || value === undefined ? '' : String(value);
        }
      }
    } finally {
      this.loading = false;
    }
  }

  // Mark the fields that the server (or the pattern) refused.
  markInvalid(names) {
    for (const [name, input] of Object.entries(this.inputs)) {
      input.classList.toggle('invalid', names.includes(name));
    }
  }

  setWordWrap(wrap) {
    this.wordWrap = wrap;
    for (const text of this.container.querySelectorAll('.form-text')) {
      text.classList.toggle('nowrap', !wrap);
    }
    for (const area of this.container.querySelectorAll('textarea')) {
      if (wrap) {
        area.removeAttribute('wrap');
      } else {
        area.setAttribute('wrap', 'off');
      }
    }
  }

  submit(buttonName) {
    // the line fields must match their pattern (the rule of the Qt Flavor dialog)
    const invalid = [];
    for (const [name, input] of Object.entries(this.inputs)) {
      if (input.tagName === 'INPUT' && input.type === 'text' && !input.checkValidity()) {
        invalid.push(name);
      }
    }
    this.markInvalid(invalid);
    if (invalid.length) {
      return;
    }
    this.pressed = buttonName;
    if (this.onSubmit) {
      this.onSubmit(buttonName);
    }
  }
}
