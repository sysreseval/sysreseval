// The dialog of one row of the Watch page (the grades screen of `sre watch`): the last archived
// evaluation of the project (GET /api/projects/{host}/{rln}/evaluation: the table the agent
// lays out, then the errors and the warnings of the run), the owner, the lab and the host in
// the title, a link to the project page.  The page keeps polling while the dialog is open:
// update() reloads the content when the project has a new archive, and says so when the
// project is closed.

import * as api from './api.js';
import {el, clear} from './ui.js';
import {_, format} from './i18n.js';
import {renderEvaluationTable} from './evaluation_table.js';

const WARNING = 'WARNING';

// projectUrl(row): the project page; projectApi(row): the base of its API; title(row): its lab
export function createDetailDialog({projectUrl, projectApi, title}) {
  let current = null;      // the open dialog: {row, dialog, caption, table, errors, openLink, archive, closed}

  function heading(row) {
    const who = [row.fullname, row.group].filter(Boolean).join(', ');
    return `${row.owner || ''}${who ? ` (${who})` : ''} — ${title(row)} — ${row.host || ''}`;
  }

  function sameProject(a, b) {
    return a.running_lab_name === b.running_lab_name && a.host === b.host;
  }

  function open(row) {
    if (current) {
      current.dialog.close();
    }
    const caption = el('p', {class: 'evaluation-caption muted'}, _('Loading…'));
    const table = el('table', {class: 'grid evaluation'});
    const errors = el('ul', {class: 'evaluation-errors'});
    const openLink = el('a', {class: 'button primary', href: projectUrl(row)}, _('Open the project'));
    const close = el('button', {type: 'button'}, _('Close'));
    const dialog = el('dialog', {class: 'modal watch-detail'},
      el('h2', {}, heading(row)), caption, table, errors,
      el('div', {class: 'buttons'}, openLink, el('span', {class: 'spacer'}), close));
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      dialog.remove();
      if (current && current.dialog === dialog) {
        current = null;
      }
    });
    // archive: the name of the archive shown (null: none), undefined while the first load runs
    current = {row, dialog, caption, table, errors, openLink, archive: undefined, closed: false};
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
      data = await api.get(`${projectApi(c.row)}/evaluation`);
    } catch (e) {
      if (c !== current) {
        return;
      }
      clear(c.table);
      clear(c.errors);
      if (e.status === 404) {
        c.caption.textContent = _('No archived evaluation yet.');
        c.archive = null;
      } else {
        c.caption.textContent = format(_('Error: {error}'), {error: e.message});
      }
      return;
    }
    if (c !== current) {
      return;
    }
    c.archive = data.archive || null;
    renderEvaluationTable(c.table, data.header || [], data.rows || []);
    const when = data.eval_date ? new Date(data.eval_date).toLocaleString() : '';
    let text = format(_('Last archived evaluation: {date}'), {date: when});
    if (data.error_count || data.warning_count) {
      text += ' — ' + format(_('{errors} error(s), {warnings} warning(s)'),
                             {errors: data.error_count || 0, warnings: data.warning_count || 0});
    }
    c.caption.textContent = text;
    clear(c.errors);
    const entries = Array.isArray(data.errors) ? data.errors : [];
    const sorted = [...entries.filter((e) => e.category !== WARNING), ...entries.filter((e) => e.category === WARNING)];
    for (const entry of sorted) {
      c.errors.append(el('li', {class: entry.category === WARNING ? 'warning' : 'error'},
                         `[${entry.category}] ${entry.text}`));
    }
  }

  // the rows of the last poll: a new archive of the project reloads, a project gone is closed
  function update(rows) {
    const c = current;
    if (!c) {
      return;
    }
    const row = rows.find((r) => sameProject(r, c.row));
    if (!row) {
      if (!c.closed) {
        c.closed = true;
        c.caption.textContent = _('The project is closed.');
        c.openLink.classList.add('disabled');
        c.openLink.removeAttribute('href');
      }
      return;
    }
    c.row = row;
    const archive = row.last_eval ? row.last_eval.archive || null : null;
    if (c.archive !== undefined && archive !== c.archive) {
      load();
    }
  }

  return {open, update};
}
