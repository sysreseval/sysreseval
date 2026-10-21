// The events WebSocket of an open project page ({api_base}/events): text frames holding one
// JSON object each ({"t": "info" | "answers" | "log" | "removed", ...}).  The socket is
// reopened with an exponential backoff when it drops; the page re-fetches everything then.

import {wsUrl} from './api.js';

const FIRST_DELAY = 1000;     // ms
const MAX_DELAY = 30000;

export class ProjectEvents {
  // onEvent(obj): a decoded frame; onReconnect(): the socket is open again after a drop
  constructor(path, {onEvent, onReconnect}) {
    this.path = path;
    this.onEvent = onEvent;
    this.onReconnect = onReconnect;
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
    const socket = new WebSocket(wsUrl(this.path));
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
        this.onEvent(obj);
      }
    });
    socket.addEventListener('close', () => {
      if (this.socket === socket) {
        this.socket = null;
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
