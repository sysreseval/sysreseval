"""The German interface of the Qt GUI: the catalog translations/sysreseval_de.qm loaded by a
QTranslator (the section headings of the settings dialog included, which lupdate did not see
while they were written inside f-strings), German in the language list, and the priority list
of a first run under a German locale: German, then English for the lab texts without German."""
import os
from pathlib import Path

import pytest

pytest.importorskip('PySide6')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QTranslator  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval import settings  # noqa: E402
from sysreseval.settings_dialog import SettingsDialog  # noqa: E402
from sysreseval.view.evaluations_view import EvaluationView  # noqa: E402

_app = QApplication.instance() or QApplication([])

TRANSLATIONS = Path(__file__).parent.parent / 'translations'
RUNNING = '20260101000000@@@test@@@user'
PARTS = [{'title': 'p1', 'description': 'Part one'}]
ELEMENTS = [{'title': 'plain', 'description': 'Plain element', 'grade': 3, 'max_grade': 4, 'grade_part': 'p1',
             'scope': params.BOTH_EVAL_SCOPE, 'bonus': False}]


@pytest.fixture
def translated():
    """Install the catalog of a language for the test: ``translated('de')``."""
    installed = []

    def install(lang):
        translator = QTranslator()
        assert translator.load(str(TRANSLATIONS / f'sysreseval_{lang}.qm'))
        _app.installTranslator(translator)
        installed.append(translator)

    yield install
    for translator in installed:
        _app.removeTranslator(translator)


def _headings(dialog) -> list:
    return [label.text() for label in dialog.findChildren(QLabel) if label.text().startswith('<b>')]


@pytest.fixture
def first_run(tmp_path, monkeypatch):
    """settings.load() on a missing config file under the locale given: ``first_run('de_DE.UTF-8')``."""
    def run(lang_env):
        for name in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG'):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv('LANGUAGE', lang_env)
        monkeypatch.setattr(settings, '_CONFIG_FILE', tmp_path / 'sysreseval')
        monkeypatch.setattr(settings, '_cfg', settings.configparser.ConfigParser())
        settings.load()
        return settings.get_language_priority()
    return run


class TestGermanCatalog:
    def test_settings_dialog(self, translated):
        translated('de')
        dialog = SettingsDialog()
        assert dialog.windowTitle() == 'Einstellungen'
        assert _headings(dialog) == ['<b>Oberfläche</b>', '<b>Terminal</b>', '<b>Schema</b>', '<b>Inhalt</b>']

    def test_settings_dialog_in_french(self, translated):
        """The headings outside the f-strings are now translated in French too."""
        translated('fr')
        assert _headings(SettingsDialog()) == ['<b>Interface</b>', '<b>Terminal</b>', '<b>Schéma</b>',
                                               '<b>Contenu</b>']

    def test_evaluation_table(self, translated):
        translated('de')
        view = EvaluationView([], RUNNING, 'test')
        view._populate_table(ELEMENTS, grade_parts=PARTS)
        texts = [view._table.item(r, 0).text() for r in range(view._table.rowCount()) if view._table.item(r, 0)]
        assert 'Summe für Part one' in texts and 'Summe' in texts
        assert view._table.horizontalHeaderItem(0).text() == 'Element'


class TestLanguages:
    def test_german_is_offered(self):
        assert 'de' in params.available_language_in_interface
        assert params.language_display_names['de'] == 'Deutsch'

    @pytest.mark.parametrize('lang_env, priority', [('de_DE.UTF-8', ['de', 'en']), ('fr_FR.UTF-8', ['fr', 'en']),
                                                    ('en_US.UTF-8', ['en'])])
    def test_first_run_priority(self, first_run, lang_env, priority):
        assert first_run(lang_env) == priority

    def test_a_saved_priority_is_kept(self, first_run, tmp_path):
        (tmp_path / 'sysreseval').write_text('[interface]\nlanguage_priority = de\n')
        assert first_run('de_DE.UTF-8') == ['de']
