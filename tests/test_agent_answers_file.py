"""
answers/answers.json is shared with the Qt GUI of the same student on the pool host: the agent
keeps the owner of a file it did not create (the student's, who must go on writing it), and tells
the open pages when another program wrote the file (the `answers` event, from the file's
signature).  Before 2026-11-03 the owner's page load gave the file to sre:docker and the GUI,
unable to write it any more, silently lost every answer typed afterwards.
"""
import json
import os
import threading
import time

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it")

from SRE.answers import AnswersLock  # noqa: E402
from sreweb.agent import answers as agent_answers  # noqa: E402
from test_agent_api import Harness, headers, run, receive_event, events_of, TEXT_HASH, FORM_HASH  # noqa: E402


def gui_write(answers_file, data: dict):
    """What the Qt GUI does: a new file replaces the old one."""
    tmp = answers_file.with_name('.answers.json.gui')
    tmp.write_text(json.dumps(data))
    os.replace(tmp, answers_file)


class TestSharedAnswersFile:
    def test_owner_of_an_existing_file_is_kept(self, tmp_path, monkeypatch):
        chowns = []
        monkeypatch.setattr(os, 'geteuid', lambda: 0)
        monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: chowns.append((uid, gid)))

        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                # the file the agent creates at the start: sre:docker
                assert chowns and chowns[-1] == h.agent.answers.owner
                answers_file = h.pub / 'projects' / rln / 'answers' / 'answers.json'
                # the file of the Qt GUI (another owner, the student): kept by every write
                answers_file.write_text(json.dumps({TEXT_HASH: 'gui'}))
                st = answers_file.stat()
                assert (st.st_uid, st.st_gid) != h.agent.answers.owner
                page = await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json()
                assert page['answers'] == {TEXT_HASH: 'gui'}
                assert chowns[-1] == (st.st_uid, st.st_gid)       # the metadata written again at the page load
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'web'}},
                                   headers=headers())
                assert chowns[-1] == (st.st_uid, st.st_gid)
                assert json.loads(answers_file.read_text())[TEXT_HASH] == 'web'
        run(go())

    def test_write_of_another_program_is_pushed_to_the_pages(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                answers_file = h.pub / 'projects' / rln / 'answers' / 'answers.json'
                # the Qt GUI replaces the file
                gui_write(answers_file, {**json.loads(answers_file.read_text()), TEXT_HASH: 'typed in the GUI'})
                msg = await receive_event(ws, 'answers')
                assert msg['answers'] == {TEXT_HASH: 'typed in the GUI'}
                # an older GUI rewrites it in place
                answers_file.write_text(json.dumps({**json.loads(answers_file.read_text()), TEXT_HASH: 'again'}))
                msg = await receive_event(ws, 'answers')
                assert msg['answers'] == {TEXT_HASH: 'again'}
                # the agent's own writes are pushed once, by put, never again by the watcher
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'web'}},
                                   headers=headers())
                events = await events_of(ws, 0.5)
                assert [e['answers'][TEXT_HASH] for e in events if e['t'] == 'answers'] == ['web']
                await ws.close()
        run(go())

    def test_simultaneous_write_of_the_gui_is_kept(self, tmp_path):
        """The Qt GUI reads the file and writes it a moment later (its read-merge-write under
        the lock on the directory): a PUT meanwhile waits for it instead of undoing it."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                answers_file = h.pub / 'projects' / rln / 'answers' / 'answers.json'
                holding = threading.Event()

                def gui():
                    lock = AnswersLock(answers_file)
                    assert lock.acquire(2.0)
                    holding.set()
                    data = json.loads(answers_file.read_text())
                    time.sleep(0.3)
                    gui_write(answers_file, {**data, TEXT_HASH: 'typed in the GUI'})
                    lock.release()
                t = threading.Thread(target=gui)
                t.start()
                assert holding.wait(2.0)
                t0 = time.monotonic()
                resp = await h.client.put(f'/v1/projects/{rln}/answers',
                                          json={'answers': {FORM_HASH: {'ip': '10.0.0.2', 'ok': False}}},
                                          headers=headers())
                assert resp.status == 200 and time.monotonic() - t0 >= 0.2    # waited for the GUI's write
                t.join()
                on_disk = json.loads(answers_file.read_text())
                assert on_disk[TEXT_HASH] == 'typed in the GUI'
                assert json.loads(on_disk[FORM_HASH]) == {'ip': '10.0.0.2', 'ok': False}
                assert (await resp.json())['answers'][TEXT_HASH] == 'typed in the GUI'
        run(go())

    def test_a_stuck_holder_does_not_block_the_agent(self, tmp_path, monkeypatch):
        """A process holding the lock for too long (a stopped GUI): the agent writes anyway
        after LOCK_TIMEOUT."""
        monkeypatch.setattr(agent_answers, 'LOCK_TIMEOUT', 0.2)

        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                holder = AnswersLock(h.pub / 'projects' / rln / 'answers' / 'answers.json')
                assert holder.try_acquire()
                try:
                    t0 = time.monotonic()
                    resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'web'}},
                                              headers=headers())
                    assert resp.status == 200 and 0.2 <= time.monotonic() - t0 < 1.5
                    assert (await resp.json())['answers'][TEXT_HASH] == 'web'
                finally:
                    holder.release()
        run(go())
