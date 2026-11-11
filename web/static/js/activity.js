// The actions of the user on a project page that never reach the server: a key pressed, a click
// or a touch, a turn of the wheel (a tab change, a question picked, the course read, the virtual
// desktop).  The page of the owner reports them on the events socket of the project, and the
// agent keeps the newest as the last action of the owner: the Last action column of the Watch
// page.  What the agent sees by itself (terminal input, answers, evaluations, states) needs no
// report; a mouse that only moves is not an action.
//
// One frame {"t": "activity", "ago": <seconds since the gesture>} at the first gesture, then at
// most one per `interval` while the user goes on; a frame the socket could not take (closed) is
// kept and sent by resend(), which the page calls when the socket is open again.

export const ACTIVITY_INTERVAL = 10000;    // ms between two frames at most
// capture: xterm and noVNC stop the propagation of what they handle.  No `scroll`: the output of
// a terminal scrolls by itself.
export const ACTIVITY_EVENTS = ['keydown', 'pointerdown', 'wheel'];

// send(frame) → true when the frame left.  now / setTimer / clearTimer: the clock (the wall clock:
// it goes on while the machine sleeps) and the timers, replaced by the tests.
export function createActivityTracker({send, target = document, interval = ACTIVITY_INTERVAL,
                                       now = () => Date.now(),
                                       setTimer = (fn, ms) => window.setTimeout(fn, ms),
                                       clearTimer = (id) => window.clearTimeout(id)}) {
  let last = null;        // the time of the newest gesture not reported yet
  let sentAt = null;      // the time of the last frame that left
  let timer = null;

  function flush() {
    timer = null;
    if (last === null) {
      return;
    }
    const at = now();
    if (send({t: 'activity', ago: Math.max(0, Math.round((at - last) / 1000))})) {
      last = null;
      sentAt = at;
    }
  }

  function note() {
    last = now();
    if (timer !== null) {
      return;
    }
    const wait = sentAt === null ? 0 : sentAt + interval - last;
    if (wait <= 0) {
      flush();
    } else {
      timer = setTimer(flush, wait);
    }
  }

  for (const type of ACTIVITY_EVENTS) {
    target.addEventListener(type, note, {capture: true, passive: true});
  }

  return {
    // the socket is open again: the gesture it refused, if any
    resend() {
      if (last !== null && timer === null) {
        flush();
      }
    },
    stop() {
      for (const type of ACTIVITY_EVENTS) {
        target.removeEventListener(type, note, {capture: true});
      }
      if (timer !== null) {
        clearTimer(timer);
        timer = null;
      }
      last = null;
    },
  };
}
