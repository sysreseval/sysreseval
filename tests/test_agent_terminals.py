"""Tests of sreweb.agent.terminals: one pty session shared by several clients (the Python child of
test_agent_pty.py plays the shell; fake clients record what they get)."""
import asyncio
import os
import sys
import textwrap

import pytest

from sreweb.agent import terminals as T
from sreweb.identity import Identity

ALICE = Identity(login='alice')
PROF = Identity(login='prof', role='instructor')

CHILD = textwrap.dedent('''\
    import os, sys, signal
    winch = []
    signal.signal(signal.SIGWINCH, lambda *a: winch.append(1))
    if "--wait" in sys.argv:
        import select
        while not select.select([0], [], [], 0.1)[0]:
            pass
        import termios
        termios.tcflush(0, termios.TCIFLUSH)
    print("tty=%s" % os.isatty(0), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if line == "size":
            s = os.get_terminal_size(0); print("size=%dx%d winch=%d" % (s.columns, s.lines, len(winch)), flush=True)
        elif line == "flood":
            sys.stdout.write("x" * (3 << 20)); sys.stdout.flush(); print("\\nflooded", flush=True)
        elif line == "exit":
            sys.exit(3)
        else:
            print("echo:" + line, flush=True)
''')


class FakeClient:
    """What the WebSocket side of a client would do; `stuck` blocks every send."""

    def __init__(self, stuck=False):
        self.out = bytearray()
        self.frames = []
        self.closed = None
        self.release = asyncio.Event()
        if not stuck:
            self.release.set()

    async def send_bytes(self, data):
        await self.release.wait()
        self.out.extend(data)

    async def send_json(self, obj):
        self.frames.append(obj)

    async def close(self, code, message):
        self.closed = (code, message)

    async def expect(self, text, timeout=5.0):
        async with asyncio.timeout(timeout):
            while text.encode() not in bytes(self.out):
                await asyncio.sleep(0.02)


class Harness:
    def __init__(self, *, wait=False, cols=100, rows=30, **kw):
        self.changes = 0
        self.closed = []
        self.activity = 0
        argv = [sys.executable, '-u', '-c', CHILD] + (['--wait'] if wait else [])
        self.session = T.TerminalSession('s1', 'm1', argv, {'PATH': os.environ.get('PATH', '')},
                                         created_by='alice', cols=cols, rows=rows,
                                         on_change=self._changed, on_closed=self.closed.append,
                                         on_activity=self._activity, **kw)
        self.pumps = {}

    def _changed(self):
        self.changes += 1

    def _activity(self):
        self.activity += 1

    def attach(self, identity, cols=100, rows=30, stuck=False):
        fake = FakeClient(stuck)
        client = self.session.attach(identity, send_bytes=fake.send_bytes, send_json=fake.send_json,
                                     close=fake.close, cols=cols, rows=rows)
        self.pumps[client.id] = asyncio.ensure_future(self.session.pump(client))
        return fake, client

    async def finish(self):
        for task in self.pumps.values():
            task.cancel()
        with contextlib_suppress():
            await asyncio.gather(*self.pumps.values(), return_exceptions=True)
        await self.session.close(grace=2.0)


class contextlib_suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


def run(coro):
    return asyncio.run(coro)


def test_two_clients_share_the_pty_and_the_smallest_size():
    async def go():
        h = Harness()
        await h.session.start()
        a, ca = h.attach(ALICE, 100, 30)
        await a.expect('tty=True')
        h.session.type_in(b'size\n')
        await a.expect('size=100x30 winch=0')
        b, cb = h.attach(PROF, 80, 24)
        await b.expect('tty=True')                       # the replay: what came before the join
        assert h.session.to_dict()['clients'] == 2 and h.changes == 2
        h.session.type_in(b'size\n')
        await a.expect('size=80x24 winch=1')             # the smallest client decides
        await b.expect('size=80x24 winch=1')
        h.session.type_in(b'hello\n')                    # typed by anyone, seen by everyone
        await a.expect('echo:hello')
        await b.expect('echo:hello')
        h.session.resize_client(cb, 120, 40)
        await asyncio.sleep(0.1)
        h.session.type_in(b'size\n')
        await a.expect('size=100x30 winch=2')            # alice is now the smallest
        h.session.detach(cb)
        assert h.session.alive and h.closed == []
        h.session.detach(ca)
        await asyncio.wait_for(h.session.pty.wait(), 5)
        await asyncio.sleep(0.05)
        assert h.closed == [h.session] and not h.session.alive and h.activity > 0
        await h.finish()
    run(go())


def test_replay_is_capped():
    async def go():
        h = Harness()
        await h.session.start()
        a, ca = h.attach(ALICE)
        await a.expect('tty=True')
        h.session.type_in(b'flood\n')
        await a.expect('flooded', timeout=20)
        assert len(h.session.replay) == T.REPLAY_SIZE
        b, cb = h.attach(PROF)
        await b.expect('flooded')
        assert len(b.out) == T.REPLAY_SIZE and bytes(b.out) == bytes(h.session.replay)
        await h.finish()
    run(go())


def test_slow_client_is_dropped_not_the_session():
    async def go():
        h = Harness()
        await h.session.start()
        a, ca = h.attach(ALICE)
        await a.expect('tty=True')
        b, cb = h.attach(PROF, stuck=True)
        h.session.type_in(b'flood\n')
        await a.expect('flooded', timeout=20)
        async with asyncio.timeout(5):
            while b.closed is None:
                await asyncio.sleep(0.02)
        assert b.closed[0] == T.WS_OVERRUN and cb.dropped and not cb.buffer
        assert h.session.alive and h.session.to_dict()['clients'] == 1
        h.session.type_in(b'after\n')
        await a.expect('echo:after')
        h.session.detach(cb)
        assert h.session.alive
        await h.finish()
    run(go())


def test_probe_and_early_input_once_per_session():
    async def go():
        h = Harness(wait=True)
        await h.session.start()
        a, ca = h.attach(ALICE)
        await asyncio.sleep(0.3)
        assert not a.out                                  # nothing until stdin is readable
        h.session.type_in(b'hi\n')                        # held, and the probe newline goes out
        b, cb = h.attach(PROF)
        h.session.type_in(b'again\n')                     # a second client does not re-probe
        await a.expect('echo:hi')
        await a.expect('echo:again')
        await b.expect('echo:again')
        assert b'echo:\n' not in bytes(a.out).replace(b'\r', b'')    # the probe newline was flushed by the raw switch
        await h.finish()
    run(go())


def test_silence_probes_after_a_delay(monkeypatch):
    monkeypatch.setattr(T, 'PROBE_DELAY', 0.3)
    async def go():
        h = Harness(wait=True)
        await h.session.start()
        a, ca = h.attach(ALICE)
        await a.expect('tty=True', timeout=5)             # the automatic probe brought the prompt
        await h.finish()
    run(go())


def test_exit_notifies_every_client():
    async def go():
        h = Harness()
        await h.session.start()
        a, ca = h.attach(ALICE)
        b, cb = h.attach(PROF)
        await a.expect('tty=True')
        h.session.type_in(b'exit\n')
        async with asyncio.timeout(5):
            while a.closed is None or b.closed is None:
                await asyncio.sleep(0.02)
        assert a.frames[-1] == {'t': 'exit', 'code': 3} and b.frames[-1] == {'t': 'exit', 'code': 3}
        assert a.closed == (1000, '') and b.closed == (1000, '')
        assert h.closed == [h.session] and h.session.exit_code == 3
        h.session.detach(ca)
        h.session.detach(cb)
        await asyncio.sleep(0.05)
        assert h.closed == [h.session]                   # reported once
        await h.finish()
    run(go())


def test_visibility_and_dict():
    async def go():
        private = T.TerminalSession('p1', 'm2', ['true'], {}, created_by='prof', private=True)
        assert private.visible_to(PROF) and not private.visible_to(ALICE)
        assert private.visible_to(Identity(login='prof'))               # its creator
        shared = T.TerminalSession('s2', 'm1', ['true'], {}, created_by='alice')
        assert shared.visible_to(ALICE) and shared.visible_to(PROF)
        d = private.to_dict()
        assert d['id'] == 'p1' and d['device'] == 'm2' and d['created_by'] == 'prof' and d['private'] is True
        assert d['clients'] == 0 and 'T' in d['created_at']
    run(go())
