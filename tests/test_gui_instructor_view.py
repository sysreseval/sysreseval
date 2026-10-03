"""
Instructor mode in the GUI: the Informations and Questions views draw the instructor() fragments
of a project in instructor mode only while the main window's "Instructor mode" button is on, and
show the student's view otherwise; the button itself is visible only on such a project.
Offscreen Qt.
"""
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from SRE.instructor_text import instructor, set_instructor_context  # noqa: E402
from sysreseval.view.apply_config_view import ApplyConfigView  # noqa: E402
from sysreseval.view.form_question_widget import FormQuestionWidget  # noqa: E402
from sysreseval.view.information_view import InformationsView  # noqa: E402
from sysreseval.view.questions_view import QuestionsView  # noqa: E402

_app = QApplication.instance() or QApplication([])

RUNNING = '20260101000000@@@test@@@user'
LINUX_ONLY = pytest.mark.skipif(sys.platform != 'linux',
                                reason="ProjectWidget's sibling views load libc.so.6: Linux only")


@pytest.fixture
def texts():
    """Lab texts as info.json holds them for a project in instructor mode."""
    set_instructor_context(True)
    return {
        'informations': instructor("""
            ## Solution
            Use `ip route`.
            """) + """
            Public text.
            """,
        'title': "Gateway" + instructor(" (expected: 10.0.0.1)"),
        'description': "Which gateway?" + instructor("\n\nAny notation is fine."),
        'form': instructor("Hint one. @@{a:[0-9]+}@@ Hint two.") + " Public end. @@{b:[0-9]+}@@",
    }


def _questions(texts) -> list:
    return [
        {"title": texts['title'], "description": texts['description'], "question_hash": "h1",
         "order": 100, "question_type": 1},
        {"title": "Form", "description": texts['form'], "question_hash": "h2", "order": 200,
         "question_type": 2, "fields": [{"name": "a", "regex": "[0-9]+"}, {"name": "b", "regex": "[0-9]+"}]},
    ]


class TestInformationsView:
    def test_hidden_until_the_button_is_on(self, texts):
        view = InformationsView(texts['informations'])
        assert 'Solution' not in view.toPlainText() and 'Public text.' in view.toPlainText()
        view.set_instructor_view(True)
        assert 'Solution' in view.toPlainText() and 'Public text.' in view.toPlainText()
        assert params.instructor_text_color in view.toHtml()
        assert params.instructor_background_color in view.toHtml()
        view.set_instructor_view(False)
        assert 'Solution' not in view.toPlainText()
        assert params.instructor_text_color not in view.toHtml()

    def test_new_text_follows_the_button(self, texts):
        view = InformationsView("plain")
        view.set_instructor_view(True)
        view.update_data(texts['informations'])
        assert 'Solution' in view.toPlainText()


class TestQuestionsView:
    @pytest.fixture
    def view(self, tmp_pub_dir, texts):
        return QuestionsView(_questions(texts), RUNNING)

    def test_text_question(self, view):
        assert view.list_widget.item(0).text() == "Gateway"
        assert 'Any notation' not in view.question_text.toPlainText()
        view.set_instructor_view(True)
        assert view.list_widget.item(0).text() == "Gateway (expected: 10.0.0.1)"
        assert 'Any notation is fine.' in view.question_text.toPlainText()
        assert params.instructor_text_color in view.question_text.toHtml()
        view.set_instructor_view(False)
        assert view.list_widget.item(0).text() == "Gateway"
        assert 'Any notation' not in view.question_text.toPlainText()

    def test_answer_survives_the_toggle(self, view):
        view.answer_text.setPlainText("10.0.0.1")
        view.set_instructor_view(True)
        assert view.answer_text.toPlainText() == "10.0.0.1"
        assert view.list_widget.currentRow() == 0

    def test_form_question(self, view):
        view.list_widget.setCurrentRow(1)

        def chunks():
            return [browser.toPlainText() for browser in view._current_form_widget._browsers]

        assert chunks() == ["Public end."]
        assert set(view._current_form_widget.get_answers()) == {'a', 'b'}
        view.set_instructor_view(True)
        assert chunks() == ["Hint one.", "Hint two. Public end."]
        html = view._current_form_widget._browsers[1].toHtml()
        assert params.instructor_text_color in html


class TestFormQuestionWidget:
    def test_fragment_across_a_field_is_drawn_on_both_sides(self, texts):
        widget = FormQuestionWidget(texts['form'], [], {}, font_size=12, show_instructor=True)
        first, second = widget._browsers
        assert params.instructor_text_color in first.toHtml()
        assert params.instructor_text_color in second.toHtml()
        assert 'SREINSTRUCTOR' not in first.toPlainText() + second.toPlainText()


# what info.json holds for a debug or instructor-mode project: every state, and the list of
# those a student could not apply
STATES = {"broken": {"en": "Break the route"}, "final": {"en": "Apply the solution"}}
BROKEN, FINAL = "Break the route", "Apply the solution"


def _listed(view: ApplyConfigView) -> list:
    return [view._table.item(row, 0).text() for row in range(view._table.rowCount())]


class TestApplyConfigView:
    def test_everything_listed_by_default(self):
        """Debug projects: unchanged."""
        view = ApplyConfigView(STATES, RUNNING, admin_only_states=['final'])
        assert _listed(view) == [BROKEN, FINAL] and view.has_states()
        assert view._table.item(1, 0).foreground().color().name() == '#ff0000'

    def test_admin_only_states_listed_on_request(self):
        view = ApplyConfigView(STATES, RUNNING, admin_only_states=['final'], show_admin_only=False)
        assert _listed(view) == [BROKEN] and view.has_states()
        view.set_show_admin_only(True)
        assert _listed(view) == [BROKEN, FINAL]
        assert view._table.item(1, 0).foreground().color().name() == '#ff0000'
        view.set_show_admin_only(False)
        assert _listed(view) == [BROKEN]

    def test_nothing_to_list_when_every_state_is_admin_only(self):
        view = ApplyConfigView(STATES, RUNNING, admin_only_states=['broken', 'final'], show_admin_only=False)
        assert _listed(view) == [] and not view.has_states()
        view.set_show_admin_only(True)
        assert _listed(view) == [BROKEN, FINAL] and view.has_states()

    def test_new_data_and_language_keep_the_choice(self):
        view = ApplyConfigView({}, RUNNING, show_admin_only=False)
        view.update_data(STATES, admin_only_states=['final'])
        assert _listed(view) == [BROKEN]
        view.set_language_priority(['fr', 'en'])
        assert _listed(view) == [BROKEN]


def _write_info(project_dir: Path, texts, instructor_mode: bool, **fields):
    (project_dir / params.info_json_name).write_text(json.dumps({
        "lab_name": "test", "machines": [], "instructor_mode": instructor_mode,
        "informations": texts['informations'] if instructor_mode else "Public text.",
        "questions": _questions(texts) if instructor_mode else [], **fields}))


@LINUX_ONLY
class TestProjectWidget:
    @pytest.fixture
    def project_dir(self, tmp_pub_dir):
        d = Path(params.sre_projects_dir) / RUNNING
        d.mkdir(parents=True)
        return d

    def test_views_follow_the_button(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, True)
        widget = ProjectWidget(project_dir)
        assert 'Solution' not in widget._info_view.toPlainText()
        widget.set_instructor_view(True)
        assert 'Solution' in widget._info_view.toPlainText()
        assert widget._questions_view.list_widget.item(0).text() == "Gateway (expected: 10.0.0.1)"
        widget.set_instructor_view(False)
        assert 'Solution' not in widget._info_view.toPlainText()
        assert widget._questions_view.list_widget.item(0).text() == "Gateway"

    def _apply_tab_visible(self, widget) -> bool:
        return widget._tabs.isTabVisible(widget._tabs.indexOf(widget._apply_config_view))

    def test_states_follow_the_button(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, True, user_allowed_states=STATES, admin_only_states=['final'])
        widget = ProjectWidget(project_dir)
        assert self._apply_tab_visible(widget) and _listed(widget._apply_config_view) == [BROKEN]
        widget.set_instructor_view(True)
        assert self._apply_tab_visible(widget) and _listed(widget._apply_config_view) == [BROKEN, FINAL]
        widget.set_instructor_view(False)
        assert _listed(widget._apply_config_view) == [BROKEN]

    def test_apply_tab_comes_with_the_button_when_no_state_is_user_allowed(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, True, user_allowed_states=STATES, admin_only_states=['broken', 'final'])
        widget = ProjectWidget(project_dir)
        assert not self._apply_tab_visible(widget)
        widget.set_instructor_view(True)
        assert self._apply_tab_visible(widget) and _listed(widget._apply_config_view) == [BROKEN, FINAL]
        widget.set_exam_mode(True)      # like a debug project, the instructor's tab stays
        assert self._apply_tab_visible(widget)
        widget.set_exam_mode(False)
        widget.set_instructor_view(False)
        assert not self._apply_tab_visible(widget)

    def test_states_of_a_mode_set_on_a_running_project(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, False, user_allowed_states={"broken": STATES["broken"]},
                    admin_only_states=[])
        widget = ProjectWidget(project_dir)
        widget.set_instructor_view(True)
        assert _listed(widget._apply_config_view) == [BROKEN]
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, texts, True, user_allowed_states=STATES, admin_only_states=['final'])
        assert widget.refresh() is True
        assert _listed(widget._apply_config_view) == [BROKEN, FINAL]

    def test_debug_project_lists_every_state_whatever_the_button(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, False, debug_project=True, user_allowed_states=STATES,
                    admin_only_states=['final'])
        widget = ProjectWidget(project_dir)
        assert self._apply_tab_visible(widget) and _listed(widget._apply_config_view) == [BROKEN, FINAL]
        widget.set_instructor_view(True)
        widget.set_instructor_view(False)
        assert _listed(widget._apply_config_view) == [BROKEN, FINAL]

    def test_normal_project_states_and_exam_mode(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, False, user_allowed_states={"broken": STATES["broken"]},
                    admin_only_states=[])
        widget = ProjectWidget(project_dir)
        assert self._apply_tab_visible(widget) and _listed(widget._apply_config_view) == [BROKEN]
        widget.set_exam_mode(True)
        assert not self._apply_tab_visible(widget)

    def test_mode_set_on_a_running_project_is_picked_up(self, project_dir, texts):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, texts, False)
        widget = ProjectWidget(project_dir)
        widget.set_instructor_view(True)
        assert 'Solution' not in widget._info_view.toPlainText()
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, texts, True)
        assert widget.refresh() is True
        assert 'Solution' in widget._info_view.toPlainText()


@LINUX_ONLY
class TestMainWindowButton:
    @pytest.fixture
    def window(self, tmp_pub_dir):
        from sysreseval import main_window
        Path(params.sre_projects_dir).mkdir()
        win = main_window.MainWindow()
        yield win
        win._timer.stop()
        win.close()
        win.deleteLater()
        _app.processEvents()

    def _add(self, window, texts, name: str, instructor_mode: bool):
        project_dir = Path(params.sre_projects_dir) / name
        project_dir.mkdir()
        _write_info(project_dir, texts, instructor_mode)
        window.add_project(project_dir)
        return window.tabs.currentWidget()

    def test_button_only_on_an_instructor_project(self, window, texts):
        assert window._instructor_btn.isHidden() and not window._instructor_btn.isChecked()
        normal = self._add(window, texts, '20260101000000@@@normal@@@user', False)
        assert window._instructor_btn.isHidden()
        project = self._add(window, texts, '20260101000001@@@instructor@@@user', True)
        assert not window._instructor_btn.isHidden()
        window.tabs.setCurrentWidget(normal)
        assert window._instructor_btn.isHidden()
        window.tabs.setCurrentWidget(project)
        assert not window._instructor_btn.isHidden()

    def test_button_drives_the_projects(self, window, texts):
        project = self._add(window, texts, '20260101000001@@@instructor@@@user', True)
        assert 'Solution' not in project._info_view.toPlainText()
        window._instructor_btn.setChecked(True)
        assert 'Solution' in project._info_view.toPlainText()
        # a project opened while the button is on shows its instructor texts at once
        other = self._add(window, texts, '20260101000002@@@instructor@@@user', True)
        assert 'Solution' in other._info_view.toPlainText()
        window._instructor_btn.setChecked(False)
        assert 'Solution' not in project._info_view.toPlainText()
        assert 'Solution' not in other._info_view.toPlainText()
