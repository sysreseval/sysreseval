"""A terminal of the web: ``sre connect <project> <device>`` on a pseudo-terminal.

Kathara's ``connect_tty`` puts its stdin in raw mode (``termios.tcgetattr``) and resizes the
Docker exec on ``SIGWINCH``, so the process needs a real controlling terminal: the master side
is read by the event loop (``loop.add_reader``) and fed by the browser through the WebSocket,
the slave side is the stdin/stdout/stderr of the child, which runs in its own session
(``start_new_session``) and takes the slave as its controlling terminal (``TIOCSCTTY`` in the
child before ``exec``).  ``pty.fork()`` is deliberately not used: forking the event loop of a
threaded process is unsafe, and ``create_subprocess_exec`` reaps the child for us.

Session recording (``asciinema``) happens inside ``sre connect`` when the lab asks for it.
"""
import asyncio
import fcntl
import os
import signal
import struct
import termios
from typing import Callable

READ_SIZE = 1 << 16
#: Pending output above which the master is no longer read until the consumer catches up.
OUTPUT_HIGH_WATER = 1 << 20


def _window_size(cols: int, rows: int) -> bytes:
    return struct.pack('HHHH', max(1, rows), max(1, cols), 0, 0)


def _take_controlling_terminal():
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class PtySession:
    """One child process on a pty.

    *on_output(data: bytes)* is called from the event loop with every chunk read on the master;
    *on_exit(returncode)* once, when the child has exited and the master is closed."""

    def __init__(self, argv: list, env: dict, *, cols: int = 80, rows: int = 24,
                 on_output: Callable[[bytes], None], on_exit: Callable[[int | None], None] | None = None):
        self.argv = list(argv)
        self.env = dict(env)
        self.cols, self.rows = cols, rows
        self._on_output = on_output
        self._on_exit = on_exit
        self._loop = None
        self._master: int | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._pending_in = bytearray()
        self._pending_out = 0
        self._reading = False
        self._writer_registered = False
        self._exited = asyncio.Event()
        self._closed = False

    # -- life cycle -----------------------------------------------------------------------------

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode if self._proc else None

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self):
        self._loop = asyncio.get_running_loop()
        master, slave = os.openpty()
        try:
            fcntl.ioctl(master, termios.TIOCSWINSZ, _window_size(self.cols, self.rows))
            self._proc = await asyncio.create_subprocess_exec(
                *self.argv, env=self.env, stdin=slave, stdout=slave, stderr=slave,
                start_new_session=True, preexec_fn=_take_controlling_terminal, close_fds=True)
        except BaseException:
            os.close(master)
            os.close(slave)
            raise
        os.close(slave)
        self._master = master
        os.set_blocking(master, False)
        self._start_reading()
        asyncio.ensure_future(self._wait_exit())

    async def _wait_exit(self):
        rc = await self._proc.wait()
        # the child is gone: drain what is left on the master, then close it
        self._drain_after_exit()
        self._close_master()
        self._exited.set()
        if self._on_exit is not None:
            self._on_exit(rc)

    def _drain_after_exit(self):
        if self._master is None:
            return
        while True:
            try:
                data = os.read(self._master, READ_SIZE)
            except (BlockingIOError, OSError):
                return
            if not data:
                return
            self._on_output(data)

    async def close(self, grace: float = 5.0):
        """Hang the terminal up: the master is closed (``SIGHUP`` to the session of the child),
        then the process group is killed if it is still there after *grace* seconds."""
        if self._closed:
            await self._exited.wait()
            return
        self._closed = True
        self._close_master()
        if self._proc is not None and self._proc.returncode is None:
            try:
                await asyncio.wait_for(self._exited.wait(), grace)
            except TimeoutError:
                try:
                    os.killpg(self._proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await self._exited.wait()

    async def wait(self):
        await self._exited.wait()

    def _close_master(self):
        if self._master is None:
            return
        self._stop_reading()
        if self._writer_registered:
            self._loop.remove_writer(self._master)
            self._writer_registered = False
        try:
            os.close(self._master)
        except OSError:
            pass
        self._master = None

    # -- output: master -> consumer ---------------------------------------------------------------

    def _start_reading(self):
        if self._master is not None and not self._reading:
            self._loop.add_reader(self._master, self._on_readable)
            self._reading = True

    def _stop_reading(self):
        if self._master is not None and self._reading:
            self._loop.remove_reader(self._master)
            self._reading = False

    def _on_readable(self):
        try:
            data = os.read(self._master, READ_SIZE)
        except BlockingIOError:
            return
        except OSError:
            # EIO: the slave side is closed (the child exited); _wait_exit() finishes the job
            self._stop_reading()
            return
        if not data:
            self._stop_reading()
            return
        self._on_output(data)

    def output_pending(self, nbytes: int):
        """Backpressure: the consumer tells how many bytes it has not sent yet; reading stops
        above :data:`OUTPUT_HIGH_WATER` and resumes below."""
        self._pending_out = nbytes
        if nbytes >= OUTPUT_HIGH_WATER:
            self._stop_reading()
        elif not self._closed:
            self._start_reading()

    # -- input: consumer -> master ----------------------------------------------------------------

    def write(self, data: bytes):
        if self._master is None or not data:
            return
        if self._pending_in:
            self._pending_in += data
            return
        try:
            n = os.write(self._master, data)
        except BlockingIOError:
            n = 0
        except OSError:
            return
        if n < len(data):
            self._pending_in += data[n:]
            self._loop.add_writer(self._master, self._flush_pending)
            self._writer_registered = True

    def _flush_pending(self):
        if self._master is None:
            return
        try:
            n = os.write(self._master, bytes(self._pending_in))
        except BlockingIOError:
            return
        except OSError:
            del self._pending_in[:]
            n = 0
        del self._pending_in[:n]
        if not self._pending_in and self._writer_registered:
            self._loop.remove_writer(self._master)
            self._writer_registered = False

    def resize(self, cols: int, rows: int):
        """New window size: the kernel sends ``SIGWINCH`` to the foreground process group of
        the terminal, which Kathara turns into a resize of the Docker exec."""
        self.cols, self.rows = cols, rows
        if self._master is not None:
            try:
                fcntl.ioctl(self._master, termios.TIOCSWINSZ, _window_size(cols, rows))
            except OSError:
                pass
