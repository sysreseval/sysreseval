// One terminal of the Terminals tab: an xterm.js terminal (vendored UMD builds loaded by
// project.html as classic scripts: window.Terminal, window.FitAddon) attached to the WebSocket
// {api_base}/terminals/{device} with the subprotocol "sre-term.v1":
//   binary frames   raw bytes both ways (keystrokes to the pty, its output to the terminal)
//   text frames     JSON; sent: {"t": "resize", "cols", "rows"}
//                   received: {"t": "ready", "session", "device", "clients", "viewers", "cols", "rows", "joined"}
//                             | {"t": "size", "cols", "rows"} | {"t": "exit", "code"} | {"t": "error", "message"}
// A session is shared: `join` attaches to a live session (its id) instead of opening a new one,
// `private` opens one the student does not see (instructors).  After a disconnection, Reconnect
// joins the same session again while another viewer keeps it alive.  `readonly` (a spectator of
// a presentation) only watches: nothing is sent, the terminal renders the grid of the pty as the
// `ready` and `size` frames give it, with the largest font that fits the box.

import {wsUrl, withQuery} from './api.js';
import {el} from './ui.js';
import {_, format} from './i18n.js';

const SUBPROTOCOL = 'sre-term.v1';
const MIN_FONT_SIZE = 6;     // px: below that a read-only grid is clipped rather than shrunk

// The themes of the Qt GUI (settings.terminal_color_scheme).
export const THEMES = {
  black_on_white: {background: '#ffffff', foreground: '#000000', cursor: '#000000',
                   cursorAccent: '#ffffff', selectionBackground: '#b4d5fe'},
  white_on_black: {background: '#000000', foreground: '#ffffff', cursor: '#ffffff',
                   cursorAccent: '#000000', selectionBackground: '#4a6a8a'},
};

// The texts of the close codes of the agent and the portal.
function closeMessage(code) {
  switch (code) {
    case 4401: return _('Not logged in.');
    case 4403: return _('Connection to this device is not allowed.');
    case 4404: return _('The project is gone.');
    case 4409: return _('Too many terminals are open.');
    case 4410: return _('This connection fell behind the terminal output.');
    case 4502: return _('The host does not answer.');
    default: return '';
  }
}

export class TerminalSession {
  // container: a .terminal-box element; path: {api_base}/terminals/{device} (+ query);
  // join: the id of a live session to attach to; private: a new session hidden from the student;
  // onReady(info): the ready frame (the session id, the number of viewers); readonly: a
  // spectator (join required): nothing sent, the grid of the pty rendered
  constructor(container, path, {fontSize, scheme, join = null, private: priv = false, onReady = null,
                                readonly = false}) {
    this.path = path;
    this.join = join;
    this.private = priv;
    this.readonly = readonly;
    this.maxFontSize = fontSize;
    this.onReady = onReady;
    this.sessionId = null;
    this.clients = 0;
    this.container = container;
    this.scheme = scheme in THEMES ? scheme : 'black_on_white';
    this.socket = null;
    this.size = {cols: 0, rows: 0};
    this.wrap = el('div', {class: 'xterm-wrap'});
    this.statusText = el('span');
    this.reconnectButton = el('button', {type: 'button', hidden: true}, _('Reconnect'));
    this.reconnectButton.addEventListener('click', () => this.connect());
    this.status = el('div', {class: 'status'}, this.statusText, this.reconnectButton);
    container.classList.add(this.scheme);
    if (readonly) {
      container.classList.add('readonly');
    }
    container.append(this.wrap, this.status);

    this.term = new window.Terminal({
      fontSize,
      fontFamily: 'ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace',
      theme: THEMES[this.scheme],
      cursorBlink: !readonly,
      disableStdin: readonly,
      scrollback: 5000,
      allowProposedApi: false,
    });
    this.fit = new window.FitAddon.FitAddon();
    this.term.loadAddon(this.fit);
    this.term.open(this.wrap);
    this.encoder = new TextEncoder();
    if (!readonly) {
      this.term.onData((data) => this.send(this.encoder.encode(data)));
      this.term.onBinary((data) => {
        // xterm gives a binary string: one byte per character
        const bytes = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
          bytes[i] = data.charCodeAt(i) & 0xff;
        }
        this.send(bytes);
      });
    }
    // Ctrl+Shift+C / Ctrl+Shift+V: copy the selection / paste, like the xterm of the Qt GUI
    this.term.attachCustomKeyEventHandler((ev) => {
      if (ev.type !== 'keydown' || !ev.ctrlKey || !ev.shiftKey) {
        return true;
      }
      if (ev.code === 'KeyC' && this.term.hasSelection()) {
        navigator.clipboard.writeText(this.term.getSelection()).catch(() => {});
        return false;
      }
      if (ev.code === 'KeyV' && !readonly) {
        navigator.clipboard.readText().then((text) => this.term.paste(text)).catch(() => {});
        return false;
      }
      return true;
    });
    this.observer = new ResizeObserver(() => this.refit());
    this.observer.observe(this.wrap);
  }

  // Fit the terminal to its box and tell the pty when the size changed (read-only: the grid is
  // the pty's, the font is fitted instead).
  refit() {
    if (this.readonly) {
      this.fitFont();
      return;
    }
    if (!this.wrap.isConnected || this.wrap.clientWidth === 0 || this.wrap.clientHeight === 0) {
      return;
    }
    try {
      this.fit.fit();
    } catch (e) {
      return;
    }
    const cols = this.term.cols;
    const rows = this.term.rows;
    if (cols !== this.size.cols || rows !== this.size.rows) {
      this.size = {cols, rows};
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({t: 'resize', cols, rows}));
      }
    }
  }

  // Read-only: the size of the pty, as the ready and size frames give it.
  applySize(cols, rows) {
    cols = Number(cols);
    rows = Number(rows);
    if (!(cols > 0 && rows > 0)) {
      return;
    }
    this.size = {cols, rows};
    this.term.resize(cols, rows);
    this.fitFont();
  }

  // Read-only: the largest font size (up to the one chosen) at which the grid fits the box; the
  // fit addon measures what a size would hold (setting fontSize re-measures the cells at once).
  fitFont() {
    if (!this.wrap.isConnected || this.wrap.clientWidth === 0 || this.wrap.clientHeight === 0 || !this.size.cols) {
      return;
    }
    const fits = (size) => {
      this.term.options.fontSize = size;
      const dims = this.fit.proposeDimensions();
      return Boolean(dims) && dims.cols >= this.size.cols && dims.rows >= this.size.rows;
    };
    let low = MIN_FONT_SIZE;
    let high = Math.max(MIN_FONT_SIZE, this.maxFontSize);
    if (fits(high)) {
      return;
    }
    while (high - low > 1) {
      const middle = Math.floor((low + high) / 2);
      if (fits(middle)) {
        low = middle;
      } else {
        high = middle;
      }
    }
    this.term.options.fontSize = low;    // the grid is clipped when even that does not fit
  }

  send(bytes) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(bytes);
    }
  }

  setStatus(text, {error = false} = {}) {
    this.statusText.textContent = text;
    this.status.classList.toggle('error', error);
  }

  connect() {
    this.reconnectButton.hidden = true;
    this.refit();
    if (this.size.cols && this.term.buffer.active.length > 1) {
      this.term.write('\r\n');
    }
    this.setStatus(_('Connecting…'));
    const query = this.readonly
      ? {join: this.join || undefined}
      : {cols: this.size.cols || 80, rows: this.size.rows || 24,
         join: this.join || undefined, private: this.private && !this.join ? 1 : undefined};
    const url = wsUrl(withQuery(this.path, query));
    const socket = new WebSocket(url, [SUBPROTOCOL]);
    socket.binaryType = 'arraybuffer';
    this.socket = socket;
    socket.addEventListener('open', () => {
      this.refit();
      if (!this.readonly) {
        this.term.focus();
      }
    });
    socket.addEventListener('message', (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        this.term.write(new Uint8Array(ev.data));
        return;
      }
      let obj;
      try {
        obj = JSON.parse(ev.data);
      } catch (e) {
        return;
      }
      if (obj.t === 'ready') {
        this.sessionId = obj.session || null;
        this.clients = Number(obj.clients) || 1;
        this.setStatus(_('Connected.'));
        if (this.readonly) {
          this.applySize(obj.cols, obj.rows);
        }
        if (this.onReady) {
          this.onReady(obj);
        }
      } else if (obj.t === 'size') {
        if (this.readonly) {
          this.applySize(obj.cols, obj.rows);
        }
      } else if (obj.t === 'exit') {
        const code = obj.code === null || obj.code === undefined ? '?' : obj.code;
        this.setStatus(format(_('Disconnected (exit code {code}).'), {code}));
      } else if (obj.t === 'error') {
        this.setStatus(obj.message || _('Error'), {error: true});
      }
    });
    socket.addEventListener('close', (ev) => {
      if (this.socket !== socket) {
        return;
      }
      this.socket = null;
      let message = closeMessage(ev.code) || (ev.reason ? ev.reason : '');
      if (ev.code === 4404 && this.join) {
        message = _('This terminal is closed.');
        this.join = null;                      // Reconnect opens a new one
      } else if (this.sessionId && ev.code !== 4403) {
        this.join = this.sessionId;            // Reconnect joins the same session while it lives
      }
      if (message) {
        this.setStatus(message, {error: ev.code !== 1000});
      } else if (!this.statusText.textContent.startsWith(_('Disconnected'))) {
        this.setStatus(_('Disconnected.'));
      }
      this.reconnectButton.hidden = false;
    });
  }

  focus() {
    this.term.focus();
  }

  setFontSize(size) {
    if (this.readonly) {
      this.maxFontSize = size;     // a cap: the grid of the pty decides
      this.fitFont();
      return;
    }
    this.term.options.fontSize = size;
    this.refit();
  }

  setScheme(scheme) {
    if (!(scheme in THEMES)) {
      return;
    }
    this.container.classList.remove(this.scheme);
    this.scheme = scheme;
    this.container.classList.add(scheme);
    this.term.options.theme = THEMES[scheme];
  }

  close() {
    this.observer.disconnect();
    if (this.socket) {
      const socket = this.socket;
      this.socket = null;
      socket.close();
    }
    this.term.dispose();
  }
}
