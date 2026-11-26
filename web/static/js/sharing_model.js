// The shared projects as the pages show them: the texts and the orders computed from the answers
// of the portal (GET {api_base}/sharing, GET /api/shares, the `sharing` of the Watch rows).  Pure
// (i18n.js only): the Share button and its dialog (share_dialog.js), the Open a shared lab dialog
// (shared_labs.js), the cards of the Projects page (projects.js) and the Sharing column of the
// Watch page (watch.js, watch_sharing.js) all read a sharing through here, so that what one of
// them calls "shared" or "forbidden" is what the others do.

import {_, format} from './i18n.js';

export const AUDIENCE_ALL = 'all';
export const POLICY_ALLOWED = 'allowed';
export const POLICY_FORBIDDEN = 'forbidden';
export const POLICY_DEFAULT = 'default';

// "Alice A (alice)", or the login alone without a name
export function personName(person) {
  const who = person && typeof person === 'object' ? person : {};
  const login = typeof who.login === 'string' ? who.login : '';
  const fullname = typeof who.fullname === 'string' ? who.fullname : '';
  return fullname && fullname !== login ? `${fullname} (${login})` : login;
}

// the short form: the full name, else the login
export function shortName(person) {
  const who = person && typeof person === 'object' ? person : {};
  return (typeof who.fullname === 'string' && who.fullname) || (typeof who.login === 'string' ? who.login : '');
}

// An audience ({key, kind, name} of the portal, or the bare key of a Watch row) in words.
export function audienceText(audience) {
  if (!audience) {
    return '';
  }
  if (typeof audience === 'string') {
    if (audience === AUDIENCE_ALL) {
      return _('everybody');
    }
    const cut = audience.indexOf(':');
    return cut > 0 ? audience.slice(cut + 1) : audience;
  }
  return audience.kind === AUDIENCE_ALL || audience.key === AUDIENCE_ALL ? _('everybody') : String(audience.name || audience.key || '');
}

// The users of a shared project, the owner first: {login, fullname, connected, owner}.
export function usersOf(state) {
  if (!state || !state.shared) {
    return [];
  }
  const owner = state.owner || {};
  return [{login: owner.login || '', fullname: owner.fullname || '', connected: Boolean(owner.connected), owner: true},
          ...(state.participants || []).map((p) => ({login: p.login, fullname: p.fullname || '',
                                                     connected: Boolean(p.connected), owner: false}))];
}

// how many of them have the page of the project open now
export function connectedCount(state) {
  return usersOf(state).filter((user) => user.connected).length;
}

// The text of the Share button of the project page: "Share" while the project is not shared,
// else "Shared · n" with the users on the project now.
export function shareLabel(state) {
  if (!state || !state.shared) {
    return _('Share');
  }
  return format(_('Shared · {n}'), {n: connectedCount(state)});
}

// Whether the Share button is shown to the user of the page: a participant always (they are
// in), the owner when the project can be shared at all (the dialog says why it may not be
// now), an instructor helping only while it is shared.
export function shareButtonShown(state, {isOwner = false, participant = false} = {}) {
  if (!state) {
    return false;
  }
  if (participant) {
    return true;
  }
  if (isOwner) {
    return Boolean(state.available || state.shared);
  }
  return Boolean(state.shared);
}

// The Sharing cell of a Watch row (its `sharing`): blank for a project that cannot be shared
// (a debug or exam project, the Qt GUI's, an older agent), else what holds for it.
export function watchSharingText(sharing) {
  if (!sharing || typeof sharing !== 'object') {
    return '';
  }
  if (sharing.shared) {
    return format(_('shared · {n}'), {n: Number(sharing.participants) || 0});
  }
  if (!sharing.available) {
    return '';
  }
  if (sharing.policy === POLICY_FORBIDDEN) {
    return _('forbidden');
  }
  if (sharing.policy === POLICY_ALLOWED) {
    return _('allowed');
  }
  return sharing.allowed ? _('allowed (default)') : _('not allowed (default)');
}

// ... and what the column sorts on: the projects shared first, by their participants, then
// those that may be, then those that may not, the ones that cannot be shared at all last.
export function watchSharingRank(sharing) {
  if (!sharing || typeof sharing !== 'object') {
    return -3;
  }
  if (sharing.shared) {
    return 1 + (Number(sharing.participants) || 0);
  }
  if (!sharing.available) {
    return -2;
  }
  return sharing.allowed ? 0 : -1;
}

// the tooltip of that cell
export function watchSharingTitle(sharing) {
  if (!sharing || typeof sharing !== 'object') {
    return '';
  }
  if (sharing.shared) {
    return format(_('Shared with {audience}: {n} participant(s), {connected} on the project now'),
                  {audience: audienceText(sharing.audience), n: Number(sharing.participants) || 0,
                   connected: Number(sharing.connected) || 0});
  }
  if (!sharing.available) {
    return _('This project cannot be shared');
  }
  return sharing.allowed ? _('Its owner may share this project') : _('Its owner may not share this project');
}

// The key of a project in a selection of the Watch page.
export function projectKey(row) {
  return `${row.host || ''}\n${row.running_lab_name || row.rln || ''}`;
}
