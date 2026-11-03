"""
answers/answers.json is shared with the Qt GUI of the same student on the pool host: the agent
keeps the owner of a file it did not create (the student's, who must go on writing it), and tells
the open pages when another program wrote the file (the `answers` event, from the file's
signature).  Before 2026-11-03 the owner's page load gave the file to sre:docker and the GUI,
unable to write it any more, silently lost every answer typed afterwards.
"""
import json
import os

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it")

from test_agent_api import Harness, headers, run, receive_event, events_of, TEXT_HASH  # noqa: E402


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
                tmp = answers_file.with_name('.answers.json.gui')
                tmp.write_text(json.dumps({**json.loads(answers_file.read_text()), TEXT_HASH: 'typed in the GUI'}))
                os.replace(tmp, answers_file)
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
