"""
The Questions tab shares answers/answers.json with the web agent (the browser of the same
student, or of an instructor helping): every save reads the file first and merges only the
answers changed here, then replaces the file atomically; reload_if_changed() (every second from
ProjectWidget.refresh) shows what another writer changed; a failed save keeps the pending
answers for the next one and is reported once on stderr.  Before 2026-11-03 the GUI rewrote
its whole in-memory copy in place and dropped every error: once the agent had written the file
as sre, every answer typed in the GUI was lost.
Offscreen Qt.
"""
import json
import os
import stat

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from SRE.form_spec import form_fields  # noqa: E402
from sysreseval.view.questions_view import QuestionsView  # noqa: E402

_app = QApplication.instance() or QApplication([])

RLN = '20260101120000@@@sre@dhcp.py@@@alice'
Q1 = 'a' * 64
Q2 = 'b' * 64
QF = 'c' * 64
FORM = "IP: @@{ip:[0-9.]+}@@ ok: @@{ok:?false}@@"
QUESTIONS = [
    {'question_hash': Q1, 'question_type': 1, 'title': 'Q1', 'description': 'first', 'order': 1},
    {'question_hash': Q2, 'question_type': 1, 'title': 'Q2', 'description': 'second', 'order': 2},
    {'question_hash': QF, 'question_type': 2, 'title': 'QF', 'description': FORM, 'fields': form_fields(FORM),
     'order': 3},
]


@pytest.fixture
def answers_dir(tmp_pub_dir):
    d = tmp_pub_dir / 'projects' / RLN / params.answer_dir_name
    d.mkdir(parents=True)
    return d


def read(answers_dir):
    return json.loads((answers_dir / params.answer_file_name).read_text(encoding='utf-8'))


def web_write(answers_dir, data):
    """What the web agent does: a new file replaces the old one."""
    tmp = answers_dir / '.answers.json.web'
    tmp.write_text(json.dumps(data), encoding='utf-8')
    os.replace(tmp, answers_dir / params.answer_file_name)


def view_on(row=0):
    view = QuestionsView(QUESTIONS, RLN)
    view.list_widget.setCurrentRow(row)
    _app.processEvents()
    return view


def type_text(view, text):
    view.answer_text.setPlainText(text)
    _app.processEvents()


class TestSharedAnswersFile:
    def test_atomic_write_readable_by_sre(self, answers_dir):
        view = view_on()
        type_text(view, 'one')
        data = read(answers_dir)
        assert data[Q1] == 'one' and data[params.login_keyword] and data[params.hostname_keyword]
        assert stat.S_IMODE((answers_dir / params.answer_file_name).stat().st_mode) == 0o644
        assert [p.name for p in answers_dir.iterdir()] == [params.answer_file_name]   # no temporary file left
        assert view._pending == {}

    def test_answers_of_the_other_writer_are_kept(self, answers_dir):
        view = view_on()
        type_text(view, 'one')
        web_write(answers_dir, {**read(answers_dir), Q2: 'from the web'})
        type_text(view, 'one more')
        data = read(answers_dir)
        assert data[Q1] == 'one more' and data[Q2] == 'from the web'
        # known to the view too: the second question shows it
        view.list_widget.setCurrentRow(1)
        _app.processEvents()
        assert view.answer_text.toPlainText() == 'from the web'

    def test_reload_shows_the_change_of_the_other_writer(self, answers_dir):
        view = view_on()
        type_text(view, 'one')
        assert view.reload_if_changed() is False           # our own write
        web_write(answers_dir, {**read(answers_dir), Q1: 'edited on the web'})
        assert view.reload_if_changed() is True
        assert view.answer_text.toPlainText() == 'edited on the web' and view._answers[Q1] == 'edited on the web'
        assert view.reload_if_changed() is False
        web_write(answers_dir, {**read(answers_dir), Q2: 'two'})
        type_text(view, 'edited here')
        data = read(answers_dir)
        assert data[Q1] == 'edited here' and data[Q2] == 'two'

    def test_reload_of_a_form_question(self, answers_dir):
        view = view_on(row=2)
        web_write(answers_dir, {**read(answers_dir), QF: json.dumps({'ip': '10.0.0.1', 'ok': True})})
        assert view.reload_if_changed() is True
        assert view._current_form_widget.get_answers() == {'ip': '10.0.0.1', 'ok': True}

    def test_unreadable_file_is_not_reloaded(self, answers_dir):
        view = view_on()
        type_text(view, 'one')
        (answers_dir / params.answer_file_name).write_text('{"half', encoding='utf-8')
        assert view.reload_if_changed() is False
        assert view._answers[Q1] == 'one' and view.answer_text.toPlainText() == 'one'
        web_write(answers_dir, {Q1: 'back'})
        assert view.reload_if_changed() is True and view.answer_text.toPlainText() == 'back'

    def test_cheat_answers_are_saved_and_shown(self, answers_dir):
        view = view_on()
        view.apply_cheat({Q2: 'cheat2'})
        assert read(answers_dir)[Q2] == 'cheat2' and view.answer_text.toPlainText() == ''
        view.apply_cheat({Q1: 'cheat1'})
        assert view.answer_text.toPlainText() == 'cheat1' and read(answers_dir)[Q1] == 'cheat1'

    @pytest.mark.skipif(os.geteuid() == 0, reason="root writes anywhere")
    def test_failed_save_keeps_the_answer_and_is_reported_once(self, answers_dir, capsys):
        view = view_on()
        type_text(view, 'one')
        answers_dir.chmod(0o500)
        try:
            type_text(view, 'two')
            type_text(view, 'three')
            assert view._pending == {Q1: 'three'} and view._answers[Q1] == 'three'
            assert read(answers_dir)[Q1] == 'one'
            assert capsys.readouterr().err.count('cannot save the answers') == 1
        finally:
            answers_dir.chmod(0o755)
        type_text(view, 'four')
        assert read(answers_dir)[Q1] == 'four' and view._pending == {}
        assert capsys.readouterr().err == ''
