// The Webconf dialog of the instructors (the Webconf button of the site bar, shown when [bbb] of
// web.toml names a BigBlueButton server): the rooms of the portal (GET /api/webconfs, refreshed
// while the dialog is open) with their audience, who is connected to the site and who is in the
// room, and for each one Join (POST .../attend: this browser shows the room, as a moderator),
// Audience… (PUT .../audience, through the audience dialog of the presentations) and End
// (DELETE); below, a new room: a name and its audience (POST /api/webconfs).  Every participant's
// browser is then told by the presence socket (webconf.js shows the client).

import * as api from './api.js';
import * as i18n from './i18n.js';
import {_, format} from './i18n.js';
import {el, clear, toast} from './ui.js';
import {openAudienceDialog} from './audience_dialog.js';

const REFRESH = 5000;      // ms between two refreshes of the rooms while the dialog is open
let ready = null;

export function setupWebconfDialog() {
  const button = document.getElementById('webconf-button');
  if (!button) {
    return;
  }
  button.addEventListener('click', async () => {
    ready = ready || i18n.init();
    await ready;
    openDialog();
  });
}

function roomUrl(id, suffix = '') {
  return `/api/webconfs/${encodeURIComponent(id)}${suffix}`;
}

function audienceTitle(room) {
  const audience = room.audience || {};
  return [...(audience.logins || []), ...(audience.groups || [])].join(', ');
}

function openDialog() {
  const groupSources = document.body.dataset.groupSources === 'true';
  const defaultName = document.body.dataset.fullname || document.body.dataset.login || '';
  const tbody = el('tbody');
  const table = el('table', {class: 'grid webconfs'},
    el('thead', {}, el('tr', {}, el('th', {}, _('Name')), el('th', {}, _('Owner')), el('th', {}, _('Audience')),
                                 el('th', {}, _('Connected')), el('th', {}, _('In the room')), el('th'))),
    tbody);
  const nameInput = el('input', {type: 'text', value: defaultName, placeholder: _('Room name'), maxlength: '64'});
  const audienceButton = el('button', {type: 'button'}, _('Audience…'));
  const audienceText = el('span', {class: 'muted'});
  const createButton = el('button', {type: 'button', class: 'primary'}, _('Create'));
  const close = el('button', {type: 'button'}, _('Close'));
  let audience = {logins: [], groups: []};
  const dialog = el('dialog', {class: 'modal webconf'},
    el('h2', {}, _('Web conferences')),
    table,
    el('fieldset', {class: 'webconf-new'}, el('legend', {}, _('New room')), nameInput, audienceButton, audienceText,
       createButton),
    el('div', {class: 'buttons'}, close));

  function describeAudience() {
    audienceText.textContent = format(_('{n} users, {m} groups'), {n: audience.logins.length, m: audience.groups.length});
  }

  async function chooseAudience(current) {
    return openAudienceDialog({logins: current.logins || [], groups: current.groups || [], mode: 'edit', groupSources,
                               title: _('Audience of the conference…'), okLabel: _('Choose'), allowEmpty: true});
  }

  function row(room) {
    const join = el('button', {type: 'button', class: 'primary'}, _('Join'));
    join.addEventListener('click', async () => {
      try {
        await api.post(roomUrl(room.id, '/attend'));
        dialog.close();            // the push shows the room; a modal would cover it
      } catch (e) {
        toast(e.message, {error: true});
      }
    });
    const edit = el('button', {type: 'button'}, _('Audience…'));
    edit.addEventListener('click', async () => {
      const chosen = await chooseAudience(room.audience || {});
      if (!chosen) {
        return;
      }
      try {
        await api.put(roomUrl(room.id, '/audience'), {audience: chosen});
        refresh();
      } catch (e) {
        toast(e.message, {error: true});
      }
    });
    const end = el('button', {type: 'button', class: 'danger'}, _('End'));
    end.addEventListener('click', async () => {
      if (!window.confirm(format(_('End the conference «{name}»? Its participants will be disconnected.'), {name: room.name}))) {
        return;
      }
      try {
        await api.del(roomUrl(room.id));
        refresh();
      } catch (e) {
        toast(e.message, {error: true});
      }
    });
    const connected = (room.connected || []).map((c) => c.fullname || c.login);
    const inRoom = (room.participants || []).map((p) => p.fullname || p.user_id);
    return el('tr', {},
      el('td', {}, room.name),
      el('td', {}, room.owner.fullname || room.owner.login),
      el('td', {class: 'center', title: audienceTitle(room)}, String(room.count)),
      el('td', {class: 'center', title: connected.join(', ')}, String(connected.length)),
      el('td', {class: 'center', title: inRoom.join(', ')}, room.running ? String(inRoom.length) : '–'),
      el('td', {class: 'actions'}, join, edit, end));
  }

  async function refresh() {
    let rooms;
    try {
      rooms = await api.get('/api/webconfs');
    } catch (e) {
      clear(tbody);
      tbody.append(el('tr', {}, el('td', {colspan: '6', class: 'error'}, e.message)));
      return;
    }
    clear(tbody);
    if (!Array.isArray(rooms) || !rooms.length) {
      tbody.append(el('tr', {}, el('td', {colspan: '6', class: 'muted'}, _('No room is open.'))));
      return;
    }
    for (const room of rooms) {
      tbody.append(row(room));
    }
  }

  audienceButton.addEventListener('click', async () => {
    const chosen = await chooseAudience(audience);
    if (chosen) {
      audience = chosen;
      describeAudience();
    }
  });
  createButton.addEventListener('click', async () => {
    createButton.disabled = true;
    try {
      await api.post('/api/webconfs', {name: nameInput.value, audience});
      audience = {logins: [], groups: []};
      describeAudience();
      refresh();
    } catch (e) {
      toast(e.message, {error: true});
    } finally {
      createButton.disabled = false;
    }
  });
  close.addEventListener('click', () => dialog.close());
  const interval = window.setInterval(refresh, REFRESH);
  dialog.addEventListener('close', () => {
    window.clearInterval(interval);
    dialog.remove();
  });
  document.body.append(dialog);
  dialog.showModal();
  describeAudience();
  refresh();
}
