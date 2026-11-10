// The Talk privately button of an instructor on a student's project (the helper view): a private
// conversation with the owner of the project, voice and text, in a BigBlueButton room of the two
// alone.  A click invites the student (POST /api/webconfs/invitations, with this browser tab:
// the one that will show the room); the student's pages show a banner (webconf_invite.js) and
// nothing else changes until the answer; a click meanwhile takes the invitation back (DELETE).
// When the student joins, the portal pushes the private room to both browsers in place of their
// class conference (webconf.js) and the button ends the conversation (POST .../leave: both go
// back to the class conference).  The button has no state of its own: it shows the invitation
// this user made (currentInvitation(), the `sre-talk` event) and the conference the page shows
// (current(), the `sre-webconf` event), so a reloaded page, or another project page of the
// same student, shows the same thing.

import * as api from './api.js';
import {_, format} from './i18n.js';
import {toast} from './ui.js';
import {TAB, act, current as currentWebconf} from './webconf.js';
import {currentInvitation} from './webconf_invite.js';

export const TALK_IDLE = 'idle';
export const TALK_INVITING = 'inviting';
export const TALK_ACTIVE = 'active';

// {owner: the student's login, getOwnerName(): their full name ('' unknown), host, rln: the
// project (the log of the portal), button}.
export function createTalk({owner, getOwnerName, host, rln, button}) {
  let busy = false;

  function situation() {
    const room = currentWebconf();
    if (room && room.kind === 'private' && room.peer && room.peer.login === owner) {
      return {name: TALK_ACTIVE};
    }
    const invitation = currentInvitation();
    if (invitation && invitation.to.login === owner) {
      return {name: TALK_INVITING, invitation};
    }
    return {name: TALK_IDLE};
  }

  function render() {
    const now = situation().name;
    const name = getOwnerName() || owner;
    button.dataset.state = now;
    button.setAttribute('aria-pressed', now === TALK_IDLE ? 'false' : 'true');
    if (now === TALK_ACTIVE) {
      button.textContent = _('End conversation');
      button.title = format(_('End the private conversation with {name}: both go back to the class conference'), {name});
    } else if (now === TALK_INVITING) {
      button.textContent = _('Calling… (cancel)');
      button.title = format(_('{name} is being asked: click to take the invitation back'), {name});
    } else {
      button.textContent = _('Talk privately');
      button.title = format(_('Invite {name} to a private voice and text conversation (a web conference of the two of you)'), {name});
    }
  }

  async function click() {
    if (busy) {
      return;
    }
    busy = true;
    button.disabled = true;
    const now = situation();
    try {
      if (now.name === TALK_IDLE) {
        await api.post('/api/webconfs/invitations', {login: owner, tab: TAB, host, rln});
      } else if (now.name === TALK_INVITING) {
        await api.del(`/api/webconfs/invitations/${encodeURIComponent(now.invitation.id)}`);
      } else {
        act('leave');
      }
    } catch (e) {
      if (e.status !== 410) {          // 410: answered meanwhile, the push says how
        toast(e.message, {error: true});
      }
    } finally {
      busy = false;
      button.disabled = false;
      render();
    }
  }

  button.addEventListener('click', click);
  document.addEventListener('sre-talk', render);
  document.addEventListener('sre-webconf', render);
  return {render};
}
