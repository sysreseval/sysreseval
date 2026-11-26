// The Open a shared lab dialog of the Open page (students): the running projects of the others
// this user may join — those whose owner shares them with everybody or with a group of theirs —,
// the ones they asked to join and the ones they already take part in (GET /api/shares, asked
// when the dialog opens, every REFRESH_INTERVAL while it is open and on the `sre-share` event
// of the document).  Ask to join posts the request (POST {project}/sharing/requests): the owner
// answers on their own page, and when they accept this page opens the project (sharing.js: the
// push of the portal, expect()); meanwhile the row says who is being waited for, with a Cancel.
// A project already joined opens at once.

import * as api from './api.js';
import {el, clear, toast, formatTimestamp} from './ui.js';
import {_, format} from './i18n.js';
import {siteUrl} from './base_path.js';
import {expect} from './sharing.js';
import {personName, shortName, audienceText} from './sharing_model.js';

const REFRESH_INTERVAL = 5000;
const COLUMNS = 6;

function sharingApi(share) {
  return `/api/projects/${encodeURIComponent(share.host)}/${encodeURIComponent(share.rln)}/sharing`;
}

// titleOf(labName): the title of a lab as the page knows it (the tree of the Open page), or ''
export function createSharedLabsDialog({titleOf = () => ''} = {}) {
  let current = null;      // the open dialog: {dialog, body, timer}
  const asking = new Set();     // the projects a request is being sent for

  function message(c, text, cls) {
    clear(c.body);
    c.body.append(el('tr', {}, el('td', {colspan: COLUMNS, class: cls}, text)));
  }

  function labOf(share) {
    return titleOf(share.lab_name) || share.title || share.lab_name || '';
  }

  async function ask(share) {
    const key = `${share.host}\n${share.rln}`;
    if (asking.has(key)) {
      return;
    }
    asking.add(key);
    try {
      const request = await api.post(`${sharingApi(share)}/requests`);
      expect(request.id);         // accepted: this page opens the project
    } catch (e) {
      if (e.status === 409 && e.data && e.data.code === 'owner_away') {
        toast(format(_('{name} is not connected: nobody to ask.'), {name: shortName(share.owner)}), {error: true});
      } else if (e.status === 409 && e.data && e.data.code === 'full') {
        toast(_('This project takes no more participant.'), {error: true});
      } else if (e.status === 429) {
        toast(_('Please wait a moment before asking again.'), {error: true});
      } else if (e.status === 404) {
        toast(_('This project is no longer shared.'), {error: true});
      } else {
        toast(e.message, {error: true});
      }
    } finally {
      asking.delete(key);
    }
    load();
  }

  async function cancel(share) {
    try {
      await api.del(`${sharingApi(share)}/requests/${encodeURIComponent(share.request)}`);
    } catch (e) {
      if (e.status !== 410) {
        toast(e.message, {error: true});
      }
    }
    load();
  }

  function row(share, state) {
    let action;
    if (state === 'joined') {
      action = el('a', {class: 'button primary', href: siteUrl(share.url)}, _('Open'));
    } else if (state === 'requested') {
      action = el('span', {class: 'waiting'},
                  el('span', {class: 'muted'}, format(_('waiting for {name}…'), {name: shortName(share.owner)})), ' ',
                  el('button', {type: 'button', onclick: () => cancel(share)}, _('Cancel')));
    } else if (share.full) {
      action = el('span', {class: 'muted'}, _('full'));
    } else {
      action = el('button', {type: 'button', class: 'primary', onclick: () => ask(share)}, _('Ask to join'));
    }
    return el('tr', {dataset: {rln: share.rln, host: share.host, state}},
              el('td', {title: share.lab_name || ''}, labOf(share)),
              el('td', {}, personName(share.owner)),
              el('td', {}, audienceText(share.audience)),
              el('td', {}, formatTimestamp(share.project_started_at) || share.project_started_at || ''),
              el('td', {class: 'num'}, String(share.participants || 0)),
              el('td', {class: 'actions'}, action));
  }

  function render(c, shares) {
    const rows = [...(shares.joined || []).map((s) => row(s, 'joined')),
                  ...(shares.requested || []).map((s) => row(s, 'requested')),
                  ...(shares.joinable || []).map((s) => row(s, 'joinable'))];
    if (!rows.length) {
      message(c, _('Nobody shares a project with you now.'), 'muted');
      return;
    }
    clear(c.body);
    c.body.append(...rows);
  }

  async function load() {
    const c = current;
    if (!c) {
      return;
    }
    let shares;
    try {
      shares = await api.get('/api/shares');
    } catch (e) {
      if (c === current) {
        message(c, e.message, 'error');
      }
      return;
    }
    if (c === current) {
      render(c, shares && typeof shares === 'object' ? shares : {});
    }
  }

  function open() {
    if (current) {
      return;
    }
    const body = el('tbody', {}, el('tr', {}, el('td', {colspan: COLUMNS, class: 'muted'}, _('Loading…'))));
    const table = el('table', {class: 'grid watch', id: 'shared-labs'},
      el('thead', {}, el('tr', {}, el('th', {}, _('Lab')), el('th', {}, _('Owner')), el('th', {}, _('Shared with')),
                         el('th', {}, _('Started')), el('th', {title: _('The students already in the project')}, _('Participants')),
                         el('th', {}, ''))),
      body);
    const close = el('button', {type: 'button'}, _('Close'));
    const dialog = el('dialog', {class: 'modal shared-labs'},
      el('h2', {}, _('Open a shared lab')),
      el('p', {class: 'muted'}, _('The running projects other students share with you.'), ' ',
         _('Their owner must accept you; you then work in the project with them.')),
      table, el('div', {class: 'buttons'}, close));
    close.addEventListener('click', () => dialog.close());
    const opened = {dialog, body, timer: 0};
    const onPush = () => load();
    dialog.addEventListener('close', () => {
      window.clearInterval(opened.timer);
      document.removeEventListener('sre-share', onPush);
      dialog.remove();
      if (current === opened) {
        current = null;
      }
    });
    current = opened;
    document.body.append(dialog);
    dialog.showModal();
    document.addEventListener('sre-share', onPush);
    opened.timer = window.setInterval(load, REFRESH_INTERVAL);
    load();
  }

  return {open};
}
