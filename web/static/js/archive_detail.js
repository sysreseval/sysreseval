// The dialog of one row of the Archives page: an archived evaluation read from the database
// (GET /api/archives/{id}: the stored elements, laid out by evaluation_rows.js as the agent lays
// out the evaluation of a running project, then the errors and the warnings of the run), the
// student, the lab and the host in the title, the time of the evaluation and of the start of
// the project in the caption.

import * as api from './api.js';
import {el, clear, formatTimestamp} from './ui.js';
import {_, format, resolveText} from './i18n.js';
import {renderEvaluationTable} from './evaluation_table.js';
import {buildEvaluationRows, evaluationHeader} from './evaluation_rows.js';

const WARNING = 'WARNING';

// the start of a project from its running lab name (timestamp@@@lab@@@login)
export function startOf(rln) {
  const parts = String(rln || '').split('@@@');
  return parts.length >= 3 ? formatTimestamp(parts[0]) : '';
}

export function createArchiveDialog() {
  let current = null;      // the open dialog: {row, dialog, caption, table, errors}

  function heading(row) {
    const who = [row.fullname, row.group].filter(Boolean).join(', ');
    return `${row.login || ''}${who ? ` (${who})` : ''} — ${row.lab || ''} — ${row.host || ''}`;
  }

  function open(row) {
    if (current) {
      current.dialog.close();
    }
    const caption = el('p', {class: 'evaluation-caption muted'}, _('Loading…'));
    const table = el('table', {class: 'grid evaluation'});
    const errors = el('ul', {class: 'evaluation-errors'});
    const close = el('button', {type: 'button'}, _('Close'));
    const title = el('h2', {}, heading(row));
    const dialog = el('dialog', {class: 'modal archive-detail'},
      title, caption, table, errors,
      el('div', {class: 'buttons'}, el('span', {class: 'spacer'}), close));
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      dialog.remove();
      if (current && current.dialog === dialog) {
        current = null;
      }
    });
    current = {row, dialog, title, caption, table, errors};
    document.body.append(dialog);
    dialog.showModal();
    load();
  }

  async function load() {
    const c = current;
    if (!c) {
      return;
    }
    let data;
    try {
      data = await api.get(`/api/archives/${encodeURIComponent(c.row.id)}`);
    } catch (e) {
      if (c !== current) {
        return;
      }
      clear(c.table);
      clear(c.errors);
      c.caption.textContent = format(_('Error: {error}'), {error: e.message});
      return;
    }
    if (c !== current) {
      return;
    }
    c.title.textContent = heading(data);     // a row opened from the URL (?open=id) had no fields
    const details = data.details || {};
    const language = details.language || 'en';
    const rows = buildEvaluationRows(details.elements || [], details.parts || [],
                                     {mark: data.mark, maximumMark: data.maximum_mark, defaultLanguage: language});
    renderEvaluationTable(c.table, evaluationHeader(), rows);
    const when = data.ts ? new Date(data.ts * 1000).toLocaleString() : '';
    const texts = [format(_('Evaluation of {date}'), {date: when})];
    const started = startOf(data.rln);
    if (started) {
      texts.push(format(_('project started {date}'), {date: started}));
    }
    if (data.errors || data.warnings) {
      texts.push(format(_('{errors} error(s), {warnings} warning(s)'), {errors: data.errors || 0, warnings: data.warnings || 0}));
    }
    c.caption.textContent = texts.join(' — ');
    c.caption.title = data.archive || '';
    clear(c.errors);
    const entries = Array.isArray(details.errors) ? details.errors : [];
    const sorted = [...entries.filter((e) => e.category !== WARNING), ...entries.filter((e) => e.category === WARNING)];
    for (const entry of sorted) {
      c.errors.append(el('li', {class: entry.category === WARNING ? 'warning' : 'error'},
                         `[${entry.category}] ${resolveText(entry.text)}`));
    }
  }

  return {open};
}
