import argparse
import os
import signal
import sys
from pathlib import Path

from PySide6.QtCore import QTranslator, QLocale, QLibraryInfo
from PySide6.QtWidgets import QApplication

from sysreseval.main_window import MainWindow
from sysreseval import settings

_PID_FILE = Path(f"/tmp/sysreseval-{os.getuid()}.pid")


def _enforce_single_instance():
    if _PID_FILE.exists():
        try:
            pid = int(_PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    _PID_FILE.write_text(str(os.getpid()))


if __name__ == "__main__":
    import SRE.params as params
    parser = argparse.ArgumentParser(add_help=False)
    if params.debug_mode:
        parser.add_argument("--debug", action="store_true", default=False)
    args, qt_argv = parser.parse_known_args()
    if not params.debug_mode:
        args.debug = False

    _enforce_single_instance()
    app = QApplication([sys.argv[0]] + qt_argv)
    app.aboutToQuit.connect(lambda: _PID_FILE.unlink(missing_ok=True))

    def _apply_system_font(size: int):
        font = app.font()
        font.setPointSize(size)
        app.setFont(font)

    _apply_system_font(settings.get_system_font_size())
    settings.add_system_font_size_listener(_apply_system_font)

    translations_dirs = [
        Path(__file__).resolve().parent.parent / "translations",
        Path(params.main_sre_dir) / "translations",
    ]
    qt_translations = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)

    app_translator = QTranslator(app)
    qt_translator = QTranslator(app)

    def _load_translators(priority):
        lang = priority[0] if priority else 'en'
        locale = QLocale(lang)
        app.removeTranslator(app_translator)
        for d in translations_dirs:
            if app_translator.load(locale, "sysreseval", "_", str(d)):
                app.installTranslator(app_translator)
                break
        app.removeTranslator(qt_translator)
        if qt_translator.load(locale, "qtbase", "_", qt_translations):
            app.installTranslator(qt_translator)

    _load_translators(settings.get_language_priority())
    settings.add_language_listener(_load_translators)

    win = MainWindow(debug=args.debug)
    win.show()
    sys.exit(app.exec())
