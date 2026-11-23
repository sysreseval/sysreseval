// The dialog saving a running project (the Save Project button of the project page): a comment,
// then POST {api_base}/save, which answers once the project is saved in the shared directory of
// the hosts (the machines keep running meanwhile; there is no progress to show, only that it
// runs).  When the user already keeps as many saved projects as they may (409 with the code
// "quota" and their saves), the dialog lists them with a Delete button each: one deleted, the
// save can be tried again.

import * as api from './api.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {siteUrl} from './base_path.js';
import {isoText} from './group_members.js';
import {labLabel, formatSize} from './saves_model.js';

const MAX_COMMENT = 100;

export function saveUrl(save) {
  return `/api/saves/${encodeURIComponent(save.owner)}/${encodeURIComponent(save.id)}`;
}

// url: the application path of the save call of the project; resolves with the save made, or
// null when the dialog was closed without one
export function openSaveDialog({url}) {
  return new Promise((resolve) => {
    const comment = el('input', {type: 'text', name: 'comment', maxlength: String(MAX_COMMENT),
                                 placeholder: _('What this save is, for you (optional)')});
    const note = el('p', {class: 'muted'},
                    _('The machines keep running while the project is saved; this can take a minute.'));
    const error = el('p', {class: 'form-error'});
    error.hidden = true;
    const quotaBox = el('div', {class: 'save-quota'});
    quotaBox.hidden = true;
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const submit = el('button', {type: 'submit', class: 'primary'}, _('Save'));
    const form = el('form', {},
      el('label', {}, _('Comment'), comment),
      note, error, quotaBox,
      el('div', {class: 'buttons'},
         el('a', {href: siteUrl('/saves')}, _('Saved projects')), el('span', {class: 'spacer'}), cancel, submit));
    const dialog = el('dialog', {class: 'modal save-dialog'}, el('h2', {}, _('Save Project')), form);
    let saved = null;
    let saving = false;

    function showError(message) {
      error.textContent = message;
      error.hidden = !message;
    }

    // the saves of the user, one to delete before this project can be saved
    function showQuota(data) {
      const saves = (data.saves || []).slice();
      clear(quotaBox);
      quotaBox.hidden = false;
      submit.disabled = true;
      quotaBox.append(el('p', {}, format(
        _('You already keep {n} saved projects, the most you may. Delete one to save this project.'),
        {n: data.quota})));
      const list = el('ul', {class: 'save-list'});
      quotaBox.append(list);
      const render = () => {
        clear(list);
        for (const save of saves) {
          const remove = el('button', {type: 'button', class: 'danger'}, _('Delete'));
          remove.addEventListener('click', async () => {
            remove.disabled = true;
            try {
              await api.del(saveUrl(save));
            } catch (e) {
              remove.disabled = false;
              showError(e.message);
              return;
            }
            saves.splice(saves.indexOf(save), 1);
            showError('');
            render();
          });
          list.append(el('li', {dataset: {id: save.id}},
            el('span', {class: 'save-what'}, labLabel(save), save.comment ? ` — ${save.comment}` : ''),
            el('span', {class: 'muted'}, `${isoText(save.saved_at)}, ${formatSize(save.size)}`),
            remove));
        }
        if (saves.length < data.quota) {
          submit.disabled = false;
        }
      };
      render();
    }

    cancel.addEventListener('click', () => dialog.close());
    dialog.addEventListener('cancel', (event) => {
      if (saving) {
        event.preventDefault();          // Escape while it saves: the save goes on anyway, say how it ends
      }
    });
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(saved);
    });
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      showError('');
      quotaBox.hidden = true;
      saving = true;
      submit.disabled = true;
      cancel.disabled = true;
      comment.disabled = true;
      submit.textContent = _('Saving…');
      try {
        const answer = await api.post(url, {comment: comment.value.trim()});
        saved = answer.save || {};
        toast(_('Project saved.'));
        dialog.close();
        return;
      } catch (e) {
        if (e.status === 409 && e.data && e.data.code === 'quota') {
          showQuota(e.data);
        } else if (e.status === 429 && e.data && e.data.retry_after) {
          showError(format(_('Please wait {n} s before saving again.'), {n: e.data.retry_after}));
          submit.disabled = false;
        } else {
          showError(e.message || String(e));
          submit.disabled = false;
        }
      } finally {
        saving = false;
        cancel.disabled = false;
        comment.disabled = false;
        submit.textContent = _('Save');
      }
    });
    document.body.append(dialog);
    dialog.showModal();
    comment.focus();
  });
}
