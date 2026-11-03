"""
The answers file written by both writers for real, on the same project: the Qt GUI's Questions
tab (an offscreen QuestionsView, as the desktop session of the test user) and the web agent (the
real one, on the fake sre of tests/mock_sre.py), in every order of use: a project started in the
GUI then opened on the web, started on the web then opened in the GUI, two web pages one after
the other, an instructor's page next to the student's GUI, the cheat answers of a state applied
on the web.  Each writer keeps what the other wrote and shows it: the GUI within a second
(reload_if_changed, called every second by ProjectWidget.refresh), the pages at once (the
`answers` event).  The two per-writer files (test_gui_questions_view.py, test_agent_answers_file.py)
simulate the other writer; here nothing is simulated.
"""
import asyncio
import getpass
import json
import os
import time

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it")
pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval.view.questions_view import QuestionsView  # noqa: E402
from mock_sre import CHEAT_TEXT_ANSWER, CHEAT_FORM_ANSWER  # noqa: E402
from test_agent_api import Harness, headers, run, receive_event, TEXT_HASH, FORM_HASH, PROF  # noqa: E402

_app = QApplication.instance() or QApplication([])

FORM_ANSWER = {'ip': '10.0.0.1', 'ok': True}


@pytest.fixture
def shared_pub(tmp_path, tmp_pub_dir):
    """The GUI's directories (params, patched by tmp_pub_dir) are those of the agent's Harness:
    both are tmp_path / 'pub'."""
    assert tmp_pub_dir == tmp_path / 'pub'
    return tmp_pub_dir


def answers_file(h, rln):
    return h.pub / 'projects' / rln / params.answer_dir_name / params.answer_file_name


def on_disk(h, rln) -> dict:
    return json.loads(answers_file(h, rln).read_text(encoding='utf-8'))


def open_gui(h, rln, row=0) -> QuestionsView:
    """The Questions tab of the GUI on the project: its construction reads the file and writes
    it again with the identity of the desktop session."""
    info = json.loads((h.pub / 'projects' / rln / 'info.json').read_text(encoding='utf-8'))
    view = QuestionsView(info['questions'], rln)
    view.list_widget.setCurrentRow(row)
    _app.processEvents()
    return view


def show_row(view, row):
    view.list_widget.setCurrentRow(row)
    _app.processEvents()


def type_text(view, text):
    view.answer_text.setPlainText(text)
    _app.processEvents()


async def answers_event(ws, predicate, timeout=5.0) -> dict:
    """The next `answers` event whose answers satisfy *predicate* (the others are skipped: the
    watcher may push the current content once more after a rewrite of the metadata)."""
    async with asyncio.timeout(timeout):
        while True:
            event = await receive_event(ws, 'answers')
            if predicate(event['answers']):
                return event['answers']


async def gui_sees(view, predicate, timeout=3.0):
    """The GUI's tick (reload_if_changed every second) until *predicate(view)* holds."""
    deadline = time.monotonic() + timeout
    while True:
        view.reload_if_changed()
        _app.processEvents()
        if predicate(view):
            return
        assert time.monotonic() < deadline, "the GUI never showed the change"
        await asyncio.sleep(0.05)


async def page_answers(h, rln, identity=None) -> dict:
    """The answers of a project page load (the owner's load completes the metadata)."""
    resp = await h.client.get(f'/v1/projects/{rln}', headers=headers() if identity is None else headers(identity))
    assert resp.status == 200
    return (await resp.json())['answers']


async def put(h, rln, answers: dict, identity=None):
    resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': answers},
                              headers=headers() if identity is None else headers(identity))
    assert resp.status == 200, await resp.text()
    return (await resp.json())['answers']


class TestBothWriters:
    def test_started_in_the_gui_then_opened_on_the_web(self, tmp_path, shared_pub):
        """The reported case: answers typed in the GUI, the project opened on the web (the owner's
        page load completes the metadata), more answers on both sides afterwards."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                answers_file(h, rln).unlink()          # as if started from the GUI: the GUI creates the file
                view = open_gui(h, rln)
                type_text(view, 'local 1')
                data = on_disk(h, rln)
                assert data[TEXT_HASH] == 'local 1' and params.group_keyword not in data
                # the owner opens the project page: the answers shown, the metadata completed
                assert await page_answers(h, rln) == {TEXT_HASH: 'local 1'}
                data = on_disk(h, rln)
                assert data[TEXT_HASH] == 'local 1' and data[params.group_keyword] == 'INFO1'
                assert view.reload_if_changed() is True and view.answer_text.toPlainText() == 'local 1'
                # the GUI goes on typing: in the file, pushed to the page (lost before 2026-11-03)
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                type_text(view, 'local 2')
                await answers_event(ws, lambda a: a.get(TEXT_HASH) == 'local 2')
                data = on_disk(h, rln)
                assert data[TEXT_HASH] == 'local 2' and data[params.group_keyword] == 'INFO1'
                # the page answers the form question: the GUI shows it
                await put(h, rln, {FORM_HASH: FORM_ANSWER})
                await gui_sees(view, lambda v: FORM_HASH in v._answers)
                show_row(view, 1)
                assert view._current_form_widget.get_answers() == FORM_ANSWER
                show_row(view, 0)
                type_text(view, 'local 3')
                await answers_event(ws, lambda a: a.get(TEXT_HASH) == 'local 3')
                data = on_disk(h, rln)
                assert data[TEXT_HASH] == 'local 3' and json.loads(data[FORM_HASH]) == FORM_ANSWER
                page = await page_answers(h, rln)
                assert page[TEXT_HASH] == 'local 3' and json.loads(page[FORM_HASH]) == FORM_ANSWER
                await ws.close()
        run(go())

    def test_started_on_the_web_then_opened_in_the_gui(self, tmp_path, shared_pub):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                await put(h, rln, {TEXT_HASH: 'web 1'})
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                # the GUI opens the project: the web answer shown, the file written again with
                # the identity of the desktop session, the group of the web identity kept
                view = open_gui(h, rln)
                assert view.answer_text.toPlainText() == 'web 1'
                data = on_disk(h, rln)
                assert (data[TEXT_HASH], data[params.login_keyword], data[params.group_keyword]) == \
                    ('web 1', getpass.getuser(), 'INFO1')
                type_text(view, 'local')
                await answers_event(ws, lambda a: a.get(TEXT_HASH) == 'local')
                assert await page_answers(h, rln) == {TEXT_HASH: 'local'}
                assert on_disk(h, rln)[params.fullname_keyword] == 'Alice A'   # the page load: the web identity's name
                await put(h, rln, {TEXT_HASH: 'web 2'})
                await gui_sees(view, lambda v: v.answer_text.toPlainText() == 'web 2')
                assert view._pending == {}
                await ws.close()
        run(go())

    def test_two_web_pages_one_after_the_other_then_the_gui(self, tmp_path, shared_pub):
        """Two pages of the same student (two browsers, two tabs): each one's answer reaches
        the other at once, the GUI opened afterwards shows both."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                ws1 = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                ws2 = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                await put(h, rln, {TEXT_HASH: 'from page 1'})
                for ws in (ws1, ws2):
                    assert await answers_event(ws, lambda a: a.get(TEXT_HASH) == 'from page 1') == {TEXT_HASH: 'from page 1'}
                await put(h, rln, {FORM_HASH: FORM_ANSWER})
                for ws in (ws1, ws2):
                    answers = await answers_event(ws, lambda a: FORM_HASH in a)
                    assert answers[TEXT_HASH] == 'from page 1' and json.loads(answers[FORM_HASH]) == FORM_ANSWER
                page = await page_answers(h, rln)
                assert page[TEXT_HASH] == 'from page 1' and json.loads(page[FORM_HASH]) == FORM_ANSWER
                view = open_gui(h, rln)
                assert view.answer_text.toPlainText() == 'from page 1'
                show_row(view, 1)
                assert view._current_form_widget.get_answers() == FORM_ANSWER
                show_row(view, 0)
                type_text(view, 'from the GUI')
                for ws in (ws1, ws2):
                    answers = await answers_event(ws, lambda a: a.get(TEXT_HASH) == 'from the GUI')
                    assert json.loads(answers[FORM_HASH]) == FORM_ANSWER
                await ws1.close()
                await ws2.close()
        run(go())

    def test_instructor_page_next_to_the_students_gui(self, tmp_path, shared_pub):
        """An instructor helping from a browser while the student types in the GUI: each sees
        the other's answer, the file keeps the student's identity."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                view = open_gui(h, rln)
                type_text(view, 'student')
                ws_prof = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                assert (await page_answers(h, rln, PROF)) == {TEXT_HASH: 'student'}
                await put(h, rln, {TEXT_HASH: 'prof'}, PROF)
                await gui_sees(view, lambda v: v.answer_text.toPlainText() == 'prof')
                type_text(view, 'student again')
                await answers_event(ws_prof, lambda a: a.get(TEXT_HASH) == 'student again')
                data = on_disk(h, rln)
                assert data[TEXT_HASH] == 'student again' and data[params.login_keyword] == getpass.getuser()
                assert 'prof' not in json.dumps(data)
                assert (await page_answers(h, rln, PROF)) == {TEXT_HASH: 'student again'}
                await ws_prof.close()
        run(go())

    def test_cheat_answers_of_a_state_reach_the_gui(self, tmp_path, shared_pub):
        """A state applied from the page writes cheat.json; the agent merges it at its next
        tick and the GUI shows the answers."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                view = open_gui(h, rln)
                type_text(view, 'before')
                resp = await h.client.post(f'/v1/projects/{rln}/states/final', headers=headers())
                assert resp.status == 200
                await gui_sees(view, lambda v: v.answer_text.toPlainText() == CHEAT_TEXT_ANSWER)
                assert json.loads(view._answers[FORM_HASH]) == CHEAT_FORM_ANSWER
                assert not (h.pub / 'projects' / rln / params.answer_dir_name / params.cheat_file_name).exists()
                type_text(view, 'after')
                data = on_disk(h, rln)
                assert data[TEXT_HASH] == 'after' and json.loads(data[FORM_HASH]) == CHEAT_FORM_ANSWER
        run(go())
