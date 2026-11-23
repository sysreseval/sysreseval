// The dialog of an archive file of the Archives page: the whole content of the file of one row
// (GET /api/archives/{id}/file, read by the portal in `[archives] directory` of web.toml), as
// `sre cat` shows it, one tab per section: the commands run on each machine with their outputs,
// the answers, the data of the lab, the errors, the grades, the saved files.  The file itself
// and each saved file can be downloaded.  The file is looked up by its name at each request: an
// error (not found, not readable, the directory being read) is shown with a Retry button.

import * as api from './api.js';
import {el, clear} from './ui.js';
import {_, format, resolveText} from './i18n.js';
import {saveBlob} from './download.js';
import {codeKind, commandCount, formatSize, pretty, splitAnswers, testGroups} from './archive_file_view.js';

const TABS = ['tests', 'answers', 'data', 'errors', 'grades', 'files'];
const WARNING = 'WARNING';
const OPEN_GROUPS_UP_TO = 20;     // commands: with more, the machines start folded

export function createArchiveFileDialog() {
  let current = null;      // the open dialog: {row, dialog, title, caption, warning, status, tabs, pane, retry, save, view, tab}

  function tabLabel(id, view) {
    if (id === 'tests') {
      return format(_('Tests ({count})'), {count: commandCount(view.tests)});
    }
    if (id === 'answers') {
      return _('Answers');
    }
    if (id === 'data') {
      return _('Data');
    }
    if (id === 'errors') {
      return format(_('Errors ({count})'), {count: (view.errors || []).length});
    }
    if (id === 'grades') {
      return _('Grades');
    }
    return format(_('Files ({count})'), {count: (view.files || []).length});
  }

  function fileUrl(row, suffix) {
    return `/api/archives/${encodeURIComponent(row.id)}/file${suffix || ''}`;
  }

  function open(row) {
    if (current) {
      current.dialog.close();
    }
    const title = el('h2', {}, row.archive || _('Archive file'));
    const caption = el('p', {class: 'evaluation-caption muted'}, _('Loading…'));
    const warning = el('p', {class: 'archive-file-warning', hidden: true});
    const status = el('p', {class: 'archive-file-status error', hidden: true});
    const tabs = el('div', {class: 'tabbar', role: 'tablist'});
    const pane = el('div', {class: 'archive-file-pane'});
    const retry = el('button', {type: 'button', hidden: true}, _('Retry'));
    const save = el('button', {type: 'button', disabled: true}, _('Download the archive'));
    const close = el('button', {type: 'button'}, _('Close'));
    const dialog = el('dialog', {class: 'modal archive-file'},
      title, caption, warning, tabs, pane, status,
      el('div', {class: 'buttons'}, save, retry, el('span', {class: 'spacer'}), close));
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      dialog.remove();
      if (current && current.dialog === dialog) {
        current = null;
      }
    });
    current = {row, dialog, title, caption, warning, status, tabs, pane, retry, save, view: null, tab: TABS[0]};
    const c = current;
    retry.addEventListener('click', () => load(c));
    save.addEventListener('click', () => download(c, save, fileUrl(row, '/raw'), (c.view && c.view.archive) || 'archive.zst'));
    document.body.append(dialog);
    dialog.showModal();
    load(c);
  }

  async function load(c) {
    c.retry.hidden = true;
    c.status.hidden = true;
    c.caption.textContent = _('Loading…');
    let view;
    try {
      view = await api.get(fileUrl(c.row));
    } catch (e) {
      if (c !== current) {
        return;
      }
      c.caption.textContent = format(_('Error: {error}'), {error: e.message});
      c.retry.hidden = false;
      return;
    }
    if (c !== current) {
      return;
    }
    c.view = view;
    c.title.textContent = view.archive || '';
    const when = view.mtime ? new Date(view.mtime * 1000).toLocaleString() : '';
    c.caption.textContent = [view.directory || _('(at the root of the archives directory)'),
                             formatSize(view.size), when].filter(Boolean).join(' · ');
    c.warning.hidden = !view.mismatch;
    c.warning.textContent = view.mismatch
      ? _('This file is not of the project of the row: another file of the same name was found.') : '';
    c.save.disabled = false;
    clear(c.tabs);
    for (const id of TABS) {
      c.tabs.append(el('button', {type: 'button', role: 'tab', dataset: {tab: id},
                                  'aria-selected': id === c.tab ? 'true' : 'false',
                                  onclick: () => select(c, id)}, tabLabel(id, view)));
    }
    render(c);
  }

  function select(c, id) {
    c.tab = id;
    for (const button of c.tabs.children) {
      button.setAttribute('aria-selected', button.dataset.tab === id ? 'true' : 'false');
    }
    render(c);
  }

  function nothing(text) {
    return el('p', {class: 'muted'}, text);
  }

  function codeText(code) {
    const kind = codeKind(code);
    if (kind === 'timeout') {
      return _('timeout');
    }
    if (kind === 'unknown') {
      return _('no exit code');
    }
    return format(_('exit {code}'), {code});
  }

  function renderTests(c) {
    const groups = testGroups(c.view.tests);
    if (!groups.length) {
      return [nothing(_('No command was run.'))];
    }
    const unfolded = commandCount(c.view.tests) <= OPEN_GROUPS_UP_TO;
    const blocks = groups.map((group) => {
      const counts = group.failed
        ? format(_('{count} command(s), {failed} with a non-zero exit code'), {count: group.commands.length, failed: group.failed})
        : format(_('{count} command(s)'), {count: group.commands.length});
      const block = el('details', {class: 'archive-tests', open: unfolded},
        el('summary', {}, el('strong', {}, group.machine), ` — ${format(_('step {step}'), {step: group.step})} `,
           el('span', {class: 'muted'}, `(${counts})`)));
      for (const command of group.commands) {
        const kind = codeKind(command.code);
        const line = el('div', {class: 'archive-command-line'},
          el('code', {}, `$ ${command.command}`),
          el('span', {class: `archive-code ${kind}`}, codeText(command.code)),
          el('span', {class: 'muted'}, format(_('timeout {seconds} s'), {seconds: command.timeout})));
        const output = typeof command.output === 'string' ? command.output : pretty(command.output);
        block.append(el('div', {class: 'archive-command'}, line,
          output ? el('pre', {class: 'archive-output'}, output) : el('p', {class: 'archive-no-output muted'}, _('(no output)')),
          command.truncated
            ? el('p', {class: 'muted'}, format(_('Output cut: {shown} of {length} characters shown (download the archive for all of it).'),
                                              {shown: output.length, length: command.length}))
            : null));
      }
      return block;
    });
    const toggle = el('button', {type: 'button'}, unfolded ? _('Fold all') : _('Unfold all'));
    toggle.addEventListener('click', () => {
      const openAll = blocks.some((block) => !block.open);
      for (const block of blocks) {
        block.open = openAll;
      }
      toggle.textContent = openAll ? _('Fold all') : _('Unfold all');
    });
    return [el('div', {class: 'archive-file-tools'}, toggle), ...blocks];
  }

  function keyValueTable(rows, keyHeader, valueHeader) {
    const body = el('tbody', {});
    for (const [key, text] of rows) {
      body.append(el('tr', {}, el('th', {scope: 'row', title: key}, key), el('td', {}, el('pre', {}, text))));
    }
    return el('table', {class: 'grid archive-answers'},
      el('thead', {}, el('tr', {}, el('th', {}, keyHeader), el('th', {}, valueHeader))), body);
  }

  function renderAnswers(c) {
    const split = splitAnswers(c.view.answers);
    const parts = [];
    if (split.metadata.length) {
      parts.push(keyValueTable(split.metadata, _('Field'), _('Value')));
    }
    if (split.answers.length) {
      parts.push(el('p', {class: 'muted'}, _('The answers are stored under the hash of their question: the text of the questions is not in an archive.')));
      parts.push(keyValueTable(split.answers, _('Question (hash)'), _('Answer')));
    } else {
      parts.push(nothing(_('No answer in this archive.')));
    }
    return parts;
  }

  function renderErrors(c) {
    const entries = Array.isArray(c.view.errors) ? c.view.errors : [];
    if (!entries.length) {
      return [nothing(_('No error nor warning.'))];
    }
    const sorted = [...entries.filter((e) => e.category !== WARNING), ...entries.filter((e) => e.category === WARNING)];
    const list = el('ul', {class: 'evaluation-errors'});
    for (const entry of sorted) {
      list.append(el('li', {class: entry.category === WARNING ? 'warning' : 'error'},
                     `[${entry.category}] ${resolveText(entry.text)}`));
    }
    return [list];
  }

  function renderFiles(c) {
    const files = Array.isArray(c.view.files) ? c.view.files : [];
    if (!files.length) {
      return [nothing(_('No file was saved in this archive.'))];
    }
    const body = el('tbody', {});
    for (const file of files) {
      const button = el('button', {type: 'button'}, _('Download'));
      button.addEventListener('click', () => download(
        c, button, api.withQuery(fileUrl(c.row, '/saved'), {name: file.name}), file.name));
      body.append(el('tr', {}, el('td', {}, file.name), el('td', {class: 'number'}, formatSize(file.size)), el('td', {}, button)));
    }
    return [el('table', {class: 'grid archive-saved'},
      el('thead', {}, el('tr', {}, el('th', {}, _('File')), el('th', {}, _('Size')), el('th', {}, ''))), body)];
  }

  function render(c) {
    clear(c.pane);
    let parts;
    if (c.tab === 'tests') {
      parts = renderTests(c);
    } else if (c.tab === 'answers') {
      parts = renderAnswers(c);
    } else if (c.tab === 'errors') {
      parts = renderErrors(c);
    } else if (c.tab === 'files') {
      parts = renderFiles(c);
    } else {
      parts = [el('pre', {class: 'archive-json'}, pretty(c.tab === 'data' ? c.view.data : c.view.grades))];
    }
    c.pane.append(...parts);
    c.pane.scrollTop = 0;
  }

  // a download of the dialog (the archive, a saved file): the file saved by the browser, an
  // error shown in the dialog (a toast would be under it)
  async function download(c, button, url, name) {
    button.disabled = true;
    c.status.hidden = true;
    try {
      const response = await api.fetchRaw('GET', url);
      saveBlob(await response.blob(), name, c.dialog);
    } catch (e) {
      if (c === current) {
        c.status.textContent = format(_('Error: {error}'), {error: e.message});
        c.status.hidden = false;
      }
    } finally {
      button.disabled = false;
    }
  }

  return {open};
}
