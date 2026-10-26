// Reconnecting WebSockets of the pages: text frames holding one JSON object each.  A socket is
// reopened with an exponential backoff when it drops (the page re-fetches everything then,
// through onReconnect); onClose(ev) may stop that (return false) on a close code meaning "over".
// ProjectEvents is the events socket of an open project page ({api_base}/events:
// {"t": "info" | "answers" | "log" | "terminals" | "removed", ...}); the presence socket of
// base.js and the presentation sockets of project.js / present.js are plain ReconnectingSockets.

import {wsUrl} from './api.js';

const FIRST_DELAY = 1000;     // ms
const MAX_DELAY = 30000;

export class ReconnectingSocket {
  // onMessage(obj): a decoded frame; onReconnect(): the socket is open again after a drop;
  // onClose(ev): the socket closed, before the reconnection is scheduled (false = stop for good)
  constructor(path, {onMessage, onReconnect = null, onClose = null, protocols = undefined}) {
    this.path = path;
    this.onMessage = onMessage;
    this.onReconnect = onReconnect;
    this.onClose = onClose;
    this.protocols = protocols;
    this.socket = null;
    this.delay = FIRST_DELAY;
    this.timer = null;
    this.closed = false;
    this.wasConnected = false;
  }

  connect() {
    if (this.closed) {
      return;
    }
    const url = wsUrl(this.path);
    const socket = this.protocols ? new WebSocket(url, this.protocols) : new WebSocket(url);
    this.socket = socket;
    socket.addEventListener('open', () => {
      this.delay = FIRST_DELAY;
      if (this.wasConnected && this.onReconnect) {
        this.onReconnect();
      }
      this.wasConnected = true;
    });
    socket.addEventListener('message', (ev) => {
      if (typeof ev.data !== 'string') {
        return;
      }
      let obj;
      try {
        obj = JSON.parse(ev.data);
      } catch (e) {
        return;
      }
      if (obj && typeof obj === 'object') {
        this.onMessage(obj);
      }
    });
    socket.addEventListener('close', (ev) => {
      if (this.socket === socket) {
        this.socket = null;
        if (this.onClose && this.onClose(ev) === false) {
          this.closed = true;
          return;
        }
        this.scheduleReconnect();
      }
    });
  }

  scheduleReconnect() {
    if (this.closed || this.timer) {
      return;
    }
    this.timer = window.setTimeout(() => {
      this.timer = null;
      this.connect();
    }, this.delay);
    this.delay = Math.min(this.delay * 2, MAX_DELAY);
  }

  // Change the path (the instructor view toggles a query string) and reconnect at once.
  reopen(path) {
    this.path = path;
    this.wasConnected = false;
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.close();
    }
    if (this.timer) {
      window.clearTimeout(this.timer);
      this.timer = null;
    }
    this.delay = FIRST_DELAY;
    this.connect();
  }

  close() {
    this.closed = true;
    if (this.timer) {
      window.clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.socket) {
      const socket = this.socket;
      this.socket = null;
      socket.close();
    }
  }
}

export class ProjectEvents extends ReconnectingSocket {
  // onEvent(obj): a decoded frame; onReconnect(): the socket is open again after a drop
  constructor(path, {onEvent, onReconnect}) {
    super(path, {onMessage: onEvent, onReconnect});
  }
}
