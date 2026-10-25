"""A terminal of the web shared by several browsers: one ``sre connect`` on a pty
(``pty_session.PtySession``), the clients attached to it (the owner's browser, the instructors
who joined to help), every one typing into the same pty and getting the same output.

- The pty has the size of the smallest client (tmux's default), recomputed when a client comes,
  goes or resizes.
- A joining client first gets the last :data:`REPLAY_SIZE` bytes of output (the screen as it
  was, roughly: the replay may start inside an escape sequence, the next prompt or redraw
  settles it).
- Each client has its own output buffer and sender task: a client that falls
  :data:`CLIENT_HIGH_WATER` bytes behind is dropped (close code :data:`WS_OVERRUN`), the session
  and the other clients go on; the pty is throttled by the slowest live client up to that point.
- The session ends when its last client leaves, or when the child exits (every client then gets
  ``{"t": "exit", "code": N}`` and a normal close).
- The keystrokes typed before the shell shows up are held: Kathara switches the pty to raw mode
  with ``TCSAFLUSH`` when it attaches, which discards whatever is queued on it.  But a machine
  whose startup never ends (an ``/sbin/init`` machine without ``/tmp/EOS``) shows nothing until
  "the user requests the control", which Kathara detects as a readable stdin: a newline is
  written to the pty at the first keystroke, and after :data:`PROBE_DELAY` seconds of silence
  anyway (in an xterm the student would press Enter); it is discarded by the raw switch, or
  reaches the shell as an empty line.  All of this is per session, whatever the number of
  clients.
"""
import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Awaitable, Callable

from .pty_session import PtySession
from ..identity import Identity

log = logging.getLogger('sreweb.agent')

REPLAY_SIZE = 1 << 16          # bytes of output replayed to a joining client
CLIENT_HIGH_WATER = 1 << 20    # a client this far behind is dropped (the pty is not stopped for it)
MAX_CLIENTS_PER_SESSION = 8
#: Close code of a client dropped for falling behind the output.
WS_OVERRUN = 4410
EARLY_INPUT_MAX = 4096       # keystrokes held until the first output of the terminal
EARLY_INPUT_HOLD = 20.0      # seconds after which they go through anyway
PROBE_DELAY = 5.0            # seconds of silence after which a newline is sent to the terminal


@dataclass
class TerminalClient:
    """One browser attached to a session: how to reach it, its window size, its pending output."""
    id: int
    identity: Identity
    send_bytes: Callable[[bytes], Awaitable[None]]
    send_json: Callable[[dict], Awaitable[None]]
    close: Callable[[int, str], Awaitable[None]]
    cols: int
    rows: int
    buffer: bytearray = field(default_factory=bytearray)
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    dropped: bool = False


class TerminalSession:
    """One ``sre connect`` on a pty and its clients (see the module docstring).

    *on_change()* is called when the list of clients changes (the app pushes the ``terminals``
    event), *on_closed(session)* once when the session is over (child exited or closed),
    *on_activity()* whenever output reaches a client (the idle clock of the project)."""

    def __init__(self, session_id: str, device: str, argv: list, env: dict, *, created_by: str,
                 private: bool = False, cols: int = 80, rows: int = 24,
                 on_change: Callable[[], None] | None = None,
                 on_closed: Callable[['TerminalSession'], None] | None = None,
                 on_activity: Callable[[], None] | None = None):
        self.id = session_id
        self.device = device
        self.created_by = created_by
        self.private = bool(private)
        self.created_at = time.time()
        self.on_change = on_change
        self.on_closed = on_closed
        self.on_activity = on_activity
        self.clients: dict[int, TerminalClient] = {}
        self._next_client = 1
        self.replay = bytearray()
        self.exited = asyncio.Event()
        self.exit_code: int | None = None
        self.closing = False
        self._closed_reported = False
        self._started = asyncio.Event()
        self._early_input = bytearray()
        self._probed = False
        self._release_task: asyncio.Task | None = None
        self._size = (cols, rows)
        self.pty = PtySession(argv, env, cols=cols, rows=rows, on_output=self._on_output, on_exit=self._on_exit)

    # -- life cycle -----------------------------------------------------------------------------

    async def start(self):
        """Start the child (``OSError`` propagates: the caller reports it and forgets the session)."""
        await self.pty.start()
        self._release_task = asyncio.ensure_future(self._release_early_input())

    async def close(self, grace: float = 5.0):
        """Hang the terminal up for every client."""
        if self.closing:
            return
        self.closing = True
        if self._release_task is not None:
            self._release_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._release_task
        await self.pty.close(grace)
        self._finished()

    def _finished(self):
        if self._closed_reported:
            return
        self._closed_reported = True
        if self.on_closed is not None:
            self.on_closed(self)

    @property
    def alive(self) -> bool:
        return self.pty.alive and not self.closing

    def visible_to(self, identity: Identity) -> bool:
        """A private session is listed to the instructors (and its creator) only."""
        return not self.private or identity.is_instructor or identity.login == self.created_by

    def to_dict(self) -> dict:
        return {'id': self.id, 'device': self.device, 'created_by': self.created_by, 'private': self.private,
                'clients': len(self._live()), 'created_at': datetime.fromtimestamp(self.created_at).isoformat(timespec='seconds')}

    # -- clients --------------------------------------------------------------------------------

    def attach(self, identity: Identity, *, send_bytes, send_json, close, cols: int, rows: int) -> TerminalClient:
        """A new client: it gets the replay first (after the caller's ``ready`` frame, through its
        own buffer), then the live output; the pty takes the smallest size."""
        client = TerminalClient(self._next_client, identity, send_bytes, send_json, close, cols, rows)
        self._next_client += 1
        self.clients[client.id] = client
        if self.replay:
            client.buffer.extend(self.replay)
            client.wake.set()
        self._apply_size()
        self._changed()
        return client

    def detach(self, client: TerminalClient):
        """A client left: the last one takes the session with it."""
        self.clients.pop(client.id, None)
        if not self.clients:
            if not self.closing:
                asyncio.ensure_future(self.close())
            return
        self._apply_size()
        self._changed()

    def resize_client(self, client: TerminalClient, cols: int, rows: int):
        client.cols, client.rows = cols, rows
        self._apply_size()

    def _live(self) -> list:
        return [c for c in self.clients.values() if not c.dropped]

    def _apply_size(self):
        live = self._live()
        if not live:
            return
        size = (min(c.cols for c in live), min(c.rows for c in live))
        if size != self._size:
            self._size = size
            self.pty.resize(*size)

    def _changed(self):
        if self.on_change is not None:
            self.on_change()

    # -- output: pty -> every client ------------------------------------------------------------

    def _on_output(self, data: bytes):
        # the echo of the probe newline (bare line ends) is not the shell showing up
        if not self._started.is_set() and (not self._probed or data.strip(b'\r\n')):
            self._start()
        self.replay.extend(data)
        if len(self.replay) > REPLAY_SIZE:
            del self.replay[:len(self.replay) - REPLAY_SIZE]
        for client in self._live():
            client.buffer.extend(data)
            client.wake.set()
            if len(client.buffer) >= CLIENT_HIGH_WATER:
                self._drop(client)
        self._update_pending()

    def _update_pending(self):
        self.pty.output_pending(max((len(c.buffer) for c in self._live()), default=0))

    def _drop(self, client: TerminalClient):
        """The slow client goes, the session stays."""
        client.dropped = True
        client.buffer.clear()
        client.wake.set()
        log.info("terminal %s/%s: client %s dropped (output overrun)", self.device, self.id, client.identity.login)
        asyncio.ensure_future(client.close(WS_OVERRUN, "terminal output overrun"))
        self._changed()

    def _on_exit(self, rc):
        self.exit_code = rc
        self.exited.set()
        for client in self.clients.values():
            client.wake.set()
        self._finished()

    async def pump(self, client: TerminalClient):
        """The sender task of a client: its pending output, then the exit frame and the close."""
        while True:
            await client.wake.wait()
            client.wake.clear()
            if client.dropped:
                return
            if client.buffer:
                data = bytes(client.buffer)
                client.buffer.clear()
                self._update_pending()
                if self.on_activity is not None:
                    self.on_activity()
                await client.send_bytes(data)
            if self.exited.is_set() and not client.buffer:
                with contextlib.suppress(Exception):
                    await client.send_json({'t': 'exit', 'code': self.exit_code})
                with contextlib.suppress(Exception):
                    await client.close(1000, '')
                return

    # -- input: any client -> pty ---------------------------------------------------------------

    def type_in(self, data: bytes):
        if self._started.is_set():
            self.pty.write(data)
        else:
            if len(self._early_input) < EARLY_INPUT_MAX:
                self._early_input.extend(data)
            self._probe()

    def _probe(self):
        if not self._probed and not self._started.is_set():
            self._probed = True
            self.pty.write(b'\n')

    def _start(self):
        self._started.set()
        if self._early_input:
            self.pty.write(bytes(self._early_input))
            self._early_input.clear()

    async def _release_early_input(self):
        # a silent terminal gets the probe newline; a shell that prints nothing even then: the
        # held keystrokes go through after a while anyway
        try:
            await asyncio.wait_for(self._started.wait(), PROBE_DELAY)
            return
        except TimeoutError:
            self._probe()
        try:
            await asyncio.wait_for(self._started.wait(), EARLY_INPUT_HOLD - PROBE_DELAY)
        except TimeoutError:
            if not self._started.is_set():
                self._start()
