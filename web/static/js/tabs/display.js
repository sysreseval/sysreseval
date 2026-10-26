// The Display tab: the virtual X desktop of the project, where the graphical applications of its
// x11_host machines show up (one Xvnc per project on the pool host, run by the agent), drawn by
// noVNC on the WebSocket {api_base}/display/ws (subprotocol "sre-display.v1": binary frames
// carrying the RFB stream, nothing else; a failure is a close code).  The X server is started
// by the agent after the project; POST {api_base}/display starts it again after it stopped.
// noVNC is vendored by `make novnc` under /static/vendor/novnc/ and loaded on first use: the page
// works without it, only this tab reports the missing file.  A spectator of a presentation
// (ctx.spectator) sees the desktop view-only (noVNC's viewOnly; the agent drops the input
// messages anyway), scaled to the tab, without the clipboard and resize controls, and never
// starts the X server (GET instead of POST).

import * as api from '../api.js';
import {wsUrl} from '../api.js';
import {el, clear} from '../ui.js';
import {_} from '../i18n.js';

const SUBPROTOCOL = 'sre-display.v1';
const NOVNC_MODULE = '/static/vendor/novnc/core/rfb.js';
const SPECTATOR_RETRIES = 10;         // a spectator waits for the presenter's X server this many times
const SPECTATOR_RETRY_DELAY = 1000;   // ms

// The texts of the close codes of the agent and the portal.
function closeMessage(code) {
  switch (code) {
    case 4401: return _('Not logged in.');
    case 4403: return _('Connection to the display is not allowed.');
    case 4404: return _('No display for this project.');
    case 4500: return _('The X server stopped.');
    case 4502: return _('The host does not answer.');
    default: return '';
  }
}

export function createDisplayTab(ctx) {
  const statusText = el('span', {class: 'display-status'});
  const reconnectButton = el('button', {type: 'button', hidden: true}, _('Reconnect'));
  const fitBox = el('input', {type: 'checkbox'});
  const resizeBox = el('input', {type: 'checkbox'});
  resizeBox.checked = true;
  const clipboard = el('textarea', {class: 'display-clipboard', rows: '1',
    title: _('Text to paste into the X desktop, or received from it')});
  const sendButton = el('button', {type: 'button'}, _('Send to the X clipboard'));
  const desktopName = el('span', {class: 'display-name'});
  const spectator = Boolean(ctx.spectator);
  const bar = spectator
    ? el('div', {class: 'ctrl-bar'}, statusText, reconnectButton, el('span', {class: 'spacer'}), desktopName)
    : el('div', {class: 'ctrl-bar'}, statusText, reconnectButton, el('span', {class: 'sep'}),
         el('label', {}, fitBox, _('Fit to window')), el('label', {}, resizeBox, _('Resize the desktop')),
         el('span', {class: 'spacer'}), desktopName, clipboard, sendButton);
  const screen = el('div', {class: 'display-screen'});
  const pane = el('div', {class: 'pane no-scroll'}, el('div', {class: 'display'}, bar, screen));

  let RFB = null;          // the noVNC class, once loaded
  let rfb = null;          // the live session
  let available = false;
  let connecting = false;

  function setStatus(text, {error = false} = {}) {
    statusText.textContent = text;
    statusText.classList.toggle('error', error);
  }

  async function loadNoVNC() {
    if (RFB === null) {
      const module = await import(NOVNC_MODULE);
      RFB = module.default;
    }
    return RFB;
  }

  function disconnect() {
    if (rfb) {
      const session = rfb;
      rfb = null;
      session.disconnect();
    }
  }

  async function connect() {
    if (connecting || !available) {
      return;
    }
    connecting = true;
    reconnectButton.hidden = true;
    disconnect();
    setStatus(_('Starting the display…'));
    try {
      // a spectator never starts the X server: the presenter's page does, maybe a moment later
      let status = spectator ? await api.get(ctx.url('/display')) : await api.post(ctx.url('/display'));
      for (let attempt = 0; spectator && !status.running && attempt < SPECTATOR_RETRIES; attempt++) {
        await new Promise((resolve) => window.setTimeout(resolve, SPECTATOR_RETRY_DELAY));
        status = await api.get(ctx.url('/display'));
      }
      if (!status.running) {
        throw new Error(status.error || _('The X server stopped.'));
      }
      const Rfb = await loadNoVNC();
      clear(screen);
      // the socket is made here so that the close code of the agent can be shown
      const socket = new WebSocket(wsUrl(ctx.url('/display/ws')), [SUBPROTOCOL]);
      let closeCode = null;
      socket.addEventListener('close', (ev) => {
        closeCode = ev.code;
      });
      const session = new Rfb(screen, socket, {shared: true});
      session.background = '#303030';
      session.viewOnly = spectator;
      session.focusOnClick = !spectator;
      session.scaleViewport = spectator ? true : fitBox.checked;
      session.resizeSession = spectator ? false : resizeBox.checked;
      session.addEventListener('connect', () => setStatus(_('Connected.')));
      session.addEventListener('disconnect', (ev) => {
        if (rfb !== session) {
          return;
        }
        rfb = null;
        const message = closeMessage(closeCode);
        if (message) {
          setStatus(message, {error: true});
        } else {
          setStatus(ev.detail.clean ? _('Disconnected.') : _('Connection lost.'), {error: !ev.detail.clean});
        }
        reconnectButton.hidden = false;
      });
      session.addEventListener('desktopname', (ev) => {
        desktopName.textContent = ev.detail.name;
      });
      if (!spectator) {
        session.addEventListener('clipboard', (ev) => {
          clipboard.value = ev.detail.text;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(ev.detail.text).catch(() => {});
          }
        });
      }
      rfb = session;
      setStatus(_('Connecting…'));
    } catch (e) {
      setStatus((e && e.message) || _('Error'), {error: true});
      reconnectButton.hidden = false;
    } finally {
      connecting = false;
    }
  }

  reconnectButton.addEventListener('click', () => connect());
  fitBox.addEventListener('change', () => {
    if (rfb) {
      rfb.scaleViewport = fitBox.checked;
    }
  });
  resizeBox.addEventListener('change', () => {
    if (rfb) {
      rfb.resizeSession = resizeBox.checked;
    }
  });
  sendButton.addEventListener('click', () => {
    if (rfb) {
      rfb.clipboardPasteFrom(clipboard.value);
      rfb.focus();
    }
  });

  return {
    id: 'display',
    element: pane,
    show() {
      if (rfb) {
        if (!spectator) {
          rfb.focus();
        }
      } else if (available && !connecting) {
        connect();
      }
    },
    hide() {},
    update(project) {
      available = Boolean(project.display && project.display.available);
      if (!available) {
        disconnect();
        setStatus(_('No display for this project.'));
        reconnectButton.hidden = true;
      }
    },
    close() {
      disconnect();
    },
  };
}
