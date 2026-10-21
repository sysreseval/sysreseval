"""Tests of sreweb.agent.pty_session: a child on a pseudo-terminal driven by the event loop."""
import asyncio
import os
import sys
import textwrap

import pytest

from sreweb.agent.pty_session import PtySession

CHILD = textwrap.dedent('''\
    import os, sys, signal
    winch = []
    signal.signal(signal.SIGWINCH, lambda *a: winch.append(1))
    print("tty=%s" % os.isatty(0), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if line == "size":
            s = os.get_terminal_size(0); print("size=%dx%d winch=%d" % (s.columns, s.lines, len(winch)), flush=True)
        elif line == "exit":
            sys.exit(3)
        else:
            print("echo:" + line, flush=True)
''')


class Harness:
    def __init__(self, **kw):
        self.out = bytearray()
        self.exit_code = 'unset'
        self.session = PtySession([sys.executable, '-u', '-c', CHILD], {'PATH': os.environ.get('PATH', '')},
                                  on_output=self.out.extend, on_exit=self._on_exit, **kw)

    def _on_exit(self, rc):
        self.exit_code = rc

    async def expect(self, text: str, timeout=5.0):
        async with asyncio.timeout(timeout):
            while text.encode() not in bytes(self.out):
                await asyncio.sleep(0.02)


def run(coro):
    return asyncio.run(coro)


def test_controlling_terminal_echo_and_exit_code():
    async def go():
        h = Harness(cols=100, rows=30)
        await h.session.start()
        await h.expect('tty=True')
        h.session.write(b'hello\n')
        await h.expect('echo:hello')
        h.session.write(b'exit\n')
        await h.session.wait()
        assert h.exit_code == 3 and h.session.returncode == 3 and not h.session.alive
        return bytes(h.out)
    out = run(go())
    # the terminal echoes what is typed (canonical mode), then the child answers
    assert b'echo:hello' in out


def test_initial_size_and_resize_sends_sigwinch():
    async def go():
        h = Harness(cols=100, rows=30)
        await h.session.start()
        await h.expect('tty=True')
        h.session.write(b'size\n')
        await h.expect('size=100x30 winch=0')
        h.session.resize(132, 43)
        await asyncio.sleep(0.1)
        h.session.write(b'size\n')
        await h.expect('size=132x43 winch=1')
        await h.session.close()
        assert h.exit_code is not None
    run(go())


def test_close_hangs_up_and_reaps():
    async def go():
        h = Harness()
        await h.session.start()
        await h.expect('tty=True')
        pid = h.session.pid
        await h.session.close(grace=2.0)
        assert not h.session.alive
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)   # already reaped by asyncio
        await h.session.close()           # idempotent
    run(go())


def test_backpressure_pauses_reading():
    async def go():
        h = Harness()
        await h.session.start()
        await h.expect('tty=True')
        h.session.output_pending(2 << 20)      # consumer is far behind: stop reading
        h.session.write(b'later\n')
        await asyncio.sleep(0.3)
        assert b'echo:later' not in bytes(h.out)
        h.session.output_pending(0)
        await h.expect('echo:later')
        await h.session.close()
    run(go())
