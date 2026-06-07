import base64
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QByteArray, QEvent, QTimer, QRectF, Qt
from PySide6.QtGui import QAction, QIcon, QKeySequence, QFont, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
    QMainWindow, QTabWidget, QToolButton, QWidget, QMessageBox,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QStackedWidget, QSizePolicy,
    QSpacerItem,
)

from sysreseval.open_project_dialog import OpenProjectDialog
from sysreseval.project_widget import ProjectWidget
from sysreseval.util import load_projects, log_wrapper_cmd
from sysreseval import util, settings
from SRE import params
from SRE.common import TranslatedText


def _parse_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


class _LogoWidget(QWidget):
    def __init__(self, svg_path: str, parent=None):
        super().__init__(parent)
        self._renderer = QSvgRenderer(svg_path, self)

    def paintEvent(self, event):
        size = self._renderer.defaultSize()
        if size.isEmpty():
            return
        r = self.rect()
        scale = min(r.width() / size.width(), r.height() / size.height())
        w = size.width() * scale
        h = size.height() * scale
        x = (r.width() - w) / 2
        y = (r.height() - h) / 2
        painter = QPainter(self)
        self._renderer.render(painter, QRectF(x, y, w, h))


_WRAP_ICON_SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <line x1="3" y1="6" x2="21" y2="6" stroke="#555" stroke-width="2" stroke-linecap="round"/>
  <path d="M3 12 h12 a3 3 0 0 1 0 6 h-3" stroke="#555" stroke-width="2"
        fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <polyline points="9,15 6,18 9,21" stroke="#555" stroke-width="2"
            fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

_SETTINGS_ICON_SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <circle cx="12" cy="12" r="3" stroke="#555" stroke-width="2" fill="none"/>
  <path d="M12 2 l-1.5 2.6 a7 7 0 0 0-2.6 1.1 L5 5 l-2 3.5 2 1.9
           a7 7 0 0 0 0 3.2 L3 15.5 5 19 l2.9-.7 a7 7 0 0 0 2.6 1.1
           L12 22 l1.5-2.6 a7 7 0 0 0 2.6-1.1 L19 19 l2-3.5-2-1.9
           a7 7 0 0 0 0-3.2 L21 8.5 19 5 l-2.9.7 a7 7 0 0 0-2.6-1.1 Z"
        stroke="#555" stroke-width="2" fill="none" stroke-linejoin="round"/>
</svg>"""

_LANGUAGE_ICON_SVG = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <circle cx="12" cy="12" r="9" stroke="#555" stroke-width="2" fill="none"/>
  <path d="M12 3 C9 7 9 17 12 21 M12 3 C15 7 15 17 12 21"
        stroke="#555" stroke-width="2" fill="none"/>
  <line x1="3.5" y1="9" x2="20.5" y2="9" stroke="#555" stroke-width="2"/>
  <line x1="3.5" y1="15" x2="20.5" y2="15" stroke="#555" stroke-width="2"/>
</svg>"""



def _make_icon(svg_bytes: bytes, size: int = 22) -> QIcon:
    renderer = QSvgRenderer(QByteArray(svg_bytes))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


class _LanguagePriorityDialog(QDialog):
    """Dialog to set the language priority order."""

    def __init__(self, current_priority: list, project_langs: set, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr("Language Priority"))
        self.resize(320, 320)

        # Build the ordered list: interface languages + project-only languages
        all_interface = list(params.available_language_in_interface)
        extra = sorted(l for l in project_langs if l not in all_interface)
        all_langs = all_interface + extra

        # Start from current priority; append anything not yet listed
        ordered = [l for l in current_priority if l in all_langs]
        for l in all_langs:
            if l not in ordered:
                ordered.append(l)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(self.tr("Drag or use the buttons to set the priority order.\n"
                                        "The first language is preferred.")))

        self._list = QListWidget()
        self._list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        for code in ordered:
            name = params.language_display_names.get(code, code)
            item = QListWidgetItem(f"{name}  [{code}]")
            item.setData(Qt.ItemDataRole.UserRole, code)
            self._list.addItem(item)
        layout.addWidget(self._list)

        btn_row = QHBoxLayout()
        up_btn = QPushButton(self.tr("▲ Up"))
        up_btn.clicked.connect(self._move_up)
        down_btn = QPushButton(self.tr("▼ Down"))
        down_btn.clicked.connect(self._move_down)
        btn_row.addWidget(up_btn)
        btn_row.addWidget(down_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _move_up(self):
        row = self._list.currentRow()
        if row > 0:
            item = self._list.takeItem(row)
            self._list.insertItem(row - 1, item)
            self._list.setCurrentRow(row - 1)

    def _move_down(self):
        row = self._list.currentRow()
        if 0 <= row < self._list.count() - 1:
            item = self._list.takeItem(row)
            self._list.insertItem(row + 1, item)
            self._list.setCurrentRow(row + 1)

    def priority(self) -> list:
        return [
            self._list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self._list.count())
        ]


class MainWindow(QMainWindow):
    def __init__(self, debug: bool = False):
        super().__init__()
        self.setWindowTitle("SysResEval")
        self.resize(1400, 900)

        self._debug = debug
        util._debug = debug
        self._app_start_time: datetime = datetime.now()
        self._exam_data: dict | None = None
        self._pre_start_called = False
        self._start_exam_called = False
        self._exam_fields_snapshot: tuple | None = None
        self._end_eval_called = False
        self._eval_exam_proc: subprocess.Popen | None = None
        self._eval_exam_interval: int | None = None
        self._next_eval_exam: datetime | None = None
        self._last_known_labs: list | None = None

        # Debug tracking (only meaningful when self._debug is True)
        self._dbg_prev_phase: str | None = None
        self._dbg_prev_exam_data: dict | None = None
        self._dbg_prev_projects_ready: bool | None = None

        if self._debug:
            self._dbg("startup",
                      app_start_time=self._app_start_time.isoformat(timespec='seconds'),
                      exam_json=str(Path(params.sre_pub_dir) / params.exam_json_name))

        self._build_menu()
        self._build_central()

        # Permanent "+" tab kept at the end
        self._plus_widget = QWidget()
        self.tabs.addTab(self._plus_widget, "+")

        self._prev_index = -1
        self.tabs.currentChanged.connect(self._on_current_changed)
        self.tabs.tabBar().tabBarClicked.connect(self._on_tab_bar_clicked)

        self.load_existing_projects()
        self._update_exam_state()

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._scan_projects)
        self._timer.start()

    # ------------------------------------------------------------------
    # Central widget construction
    # ------------------------------------------------------------------

    def _build_central(self):
        central = QWidget()
        vbox = QVBoxLayout(central)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        # Exam bar (countdown strip shown during active phase)
        self._exam_bar = QWidget()
        self._exam_bar.setVisible(False)
        bar_layout = QHBoxLayout(self._exam_bar)
        bar_layout.setContentsMargins(8, 4, 8, 4)
        bar_layout.addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        self._countdown_label = QLabel()
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        self._countdown_label.setFont(font)
        bar_layout.addWidget(self._countdown_label)
        bar_layout.addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        vbox.addWidget(self._exam_bar)

        # Stacked widget
        self._stacked = QStackedWidget()

        # Page 0: normal tabs
        self.tabs = QTabWidget()
        self.tabs.setMovable(False)
        self._word_wrap = True
        self._wrap_btn = QToolButton()
        self._wrap_btn.setIcon(_make_icon(_WRAP_ICON_SVG))
        self._wrap_btn.setCheckable(True)
        self._wrap_btn.setChecked(True)
        self._wrap_btn.setFixedSize(28, 28)
        self._wrap_btn.setToolTip(self.tr("Wrap"))
        self._wrap_btn.toggled.connect(self._on_wrap_toggled)

        self._settings_btn = QToolButton()
        self._settings_btn.setIcon(_make_icon(_SETTINGS_ICON_SVG))
        self._settings_btn.setFixedSize(28, 28)
        self._settings_btn.setToolTip(self.tr("Settings"))
        self._settings_btn.clicked.connect(self._open_settings)

        self._language_btn = QToolButton()
        self._language_btn.setIcon(_make_icon(_LANGUAGE_ICON_SVG))
        self._language_btn.setFixedSize(28, 28)
        self._language_btn.setToolTip(self.tr("Language"))
        self._language_btn.clicked.connect(self._open_language_dialog)

        _corner = QWidget()
        _corner_layout = QHBoxLayout(_corner)
        _corner_layout.setContentsMargins(0, 0, 4, 0)
        _corner_layout.setSpacing(2)
        _corner_layout.addWidget(self._wrap_btn)
        _corner_layout.addWidget(self._settings_btn)
        _corner_layout.addWidget(self._language_btn)
        self.tabs.setCornerWidget(_corner, Qt.Corner.TopRightCorner)
        self._stacked.addWidget(self.tabs)

        # Page 1: logo — shown when empty or exam waiting
        self._logo_widget = _LogoWidget(params.sysreseval_logo_svg)
        self._stacked.addWidget(self._logo_widget)

        # Page 2: shown when exam ended
        self._ended_widget = _LogoWidget(params.thats_all_folks_svg)
        self._stacked.addWidget(self._ended_widget)

        # Page 3: shown while eval_before_exit evals are running
        self._closing_widget = QWidget()
        closing_layout = QVBoxLayout(self._closing_widget)
        self._closing_label = QLabel(self.tr("closing in progress..."))
        closing_label = self._closing_label
        closing_font = QFont()
        closing_font.setPointSize(18)
        closing_label.setFont(closing_font)
        closing_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        closing_layout.addStretch()
        closing_layout.addWidget(closing_label)
        closing_layout.addStretch()
        self._stacked.addWidget(self._closing_widget)

        vbox.addWidget(self._stacked)
        self.setCentralWidget(central)

    # ------------------------------------------------------------------
    # Menu bar
    # ------------------------------------------------------------------

    def _build_menu(self):
        mb = self.menuBar()

        # File
        self._file_menu = mb.addMenu(self.tr("File"))
        file_menu = self._file_menu

        self._open_action = QAction(self.tr("Open Project"), self)
        self._open_action.setShortcut(QKeySequence.StandardKey.Open)
        self._open_action.triggered.connect(self._open_new_project)
        file_menu.addAction(self._open_action)

        self._close_action = QAction(self.tr("Close Project"), self)
        self._close_action.setShortcut(QKeySequence("Ctrl+W"))
        self._close_action.setEnabled(False)
        self._close_action.triggered.connect(self._close_current_project)
        file_menu.addAction(self._close_action)

        self._close_all_action = QAction(self.tr("Close All Projects"), self)
        self._close_all_action.setEnabled(False)
        self._close_all_action.triggered.connect(self._close_all_projects)
        file_menu.addAction(self._close_all_action)

        file_menu.addSeparator()

        self._export_action = QAction(self.tr("Export Kathara Project"), self)
        self._export_action.setEnabled(False)
        self._export_action.triggered.connect(self._export_project)
        file_menu.addAction(self._export_action)

        file_menu.addSeparator()

        self._settings_action = QAction(self.tr("Settings"), self)
        self._settings_action.triggered.connect(self._open_settings)
        file_menu.addAction(self._settings_action)

        self._language_action = QAction(self.tr("Language"), self)
        self._language_action.triggered.connect(self._open_language_dialog)
        file_menu.addAction(self._language_action)

        file_menu.addSeparator()

        self._quit_action = QAction(self.tr("Quit"), self)
        self._quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        self._quit_action.triggered.connect(self._quit)
        file_menu.addAction(self._quit_action)

        # Edit
        self._edit_menu = mb.addMenu(self.tr("Edit"))
        edit_menu = self._edit_menu
        edit_menu.aboutToShow.connect(self._update_edit_menu)

        self._select_all_action = QAction(self.tr("Select All"), self)
        self._select_all_action.setShortcut(QKeySequence("Shift+Ctrl+A"))
        self._select_all_action.triggered.connect(self._edit_select_all)
        edit_menu.addAction(self._select_all_action)

        edit_menu.addSeparator()

        self._cut_action = QAction(self.tr("Cut"), self)
        self._cut_action.setShortcut(QKeySequence("Shift+Ctrl+X"))
        self._cut_action.triggered.connect(self._edit_cut)
        edit_menu.addAction(self._cut_action)

        self._copy_action = QAction(self.tr("Copy"), self)
        self._copy_action.setShortcut(QKeySequence("Shift+Ctrl+C"))
        self._copy_action.triggered.connect(self._edit_copy)
        edit_menu.addAction(self._copy_action)

        self._paste_action = QAction(self.tr("Paste"), self)
        self._paste_action.setShortcut(QKeySequence("Shift+Ctrl+V"))
        self._paste_action.triggered.connect(self._edit_paste)
        edit_menu.addAction(self._paste_action)

    # ------------------------------------------------------------------
    # Project management
    # ------------------------------------------------------------------

    def load_existing_projects(self):
        for project_dir in load_projects():
            self.add_project(project_dir)

    def add_project(self, project_dir: Path, switch_to: bool = True):
        plus_index = self.tabs.indexOf(self._plus_widget)
        widget = ProjectWidget(project_dir)
        title = self._tab_title_for(widget)
        self.tabs.insertTab(plus_index, widget, title)

        if self._exam_data is not None:
            widget.set_exam_mode(True)
        if self._word_wrap:
            widget.set_word_wrap(True)

        if switch_to:
            self.tabs.setCurrentIndex(plus_index)
        self._refresh_tab_titles()
        self._update_menu_state()

    def _stop_project(self, widget: ProjectWidget):
        cmd = [params.sre_wrapper, "stop", widget.project_dir.name]
        log_wrapper_cmd(cmd)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _close_current_project(self):
        widget = self.tabs.currentWidget()
        if isinstance(widget, ProjectWidget):
            self._stop_project(widget)

    def _close_all_projects(self):
        cmd = [params.sre_wrapper, "wipe"]
        log_wrapper_cmd(cmd)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _export_project(self):
        widget = self.tabs.currentWidget()
        if not isinstance(widget, ProjectWidget):
            return

        running_lab_name = widget.project_dir.name
        lab_name = params.get_lab_name_from_running_lab_name(running_lab_name)
        lab_display = lab_name.replace('@', '/').split('/')[-1].removesuffix('.py')
        zip_path = Path.home() / f"{lab_display}.zip"

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            cmd = [params.sre_wrapper, "export", running_lab_name] + widget.schema_export_args()
            log_wrapper_cmd(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True)
        finally:
            QApplication.restoreOverrideCursor()

        if result.returncode != 0:
            QMessageBox.critical(self, self.tr("Export Error"),
                                 self.tr("Export failed:\n") + result.stderr.strip())
            return

        try:
            zip_data = base64.b64decode(result.stdout.strip())
            zip_path.write_bytes(zip_data)
        except Exception as e:
            QMessageBox.critical(self, self.tr("Export Error"),
                                 self.tr("Failed to save file:\n") + str(e))
            return

        QMessageBox.information(self, self.tr("Export"),
                                self.tr("Project exported to ") + str(zip_path))

    def _update_menu_state(self):
        has_projects = any(
            isinstance(self.tabs.widget(i), ProjectWidget)
            for i in range(self.tabs.count())
        )
        current_widget = self.tabs.currentWidget()
        current_is_project = isinstance(current_widget, ProjectWidget)
        in_exam = self._exam_data is not None
        self._open_action.setEnabled(not in_exam)
        self._close_action.setEnabled(not in_exam and current_is_project)
        self._close_all_action.setEnabled(not in_exam and has_projects)
        can_export = (not in_exam and current_is_project and
                      current_widget.info.get("export_kathara_project", True))
        self._export_action.setEnabled(can_export)

    def _tab_title_for(self, widget: ProjectWidget) -> str:
        priority = settings.get_language_priority()
        raw = widget.info.get("title", widget.info.get("lab_name", widget.project_dir.name).removesuffix('.py'))
        return TranslatedText.from_value(raw).resolve_priority(priority) or str(raw)

    def _refresh_tab_titles(self):
        """Set each project tab's title to the project title, with a number suffix when
        the same title appears more than once (ordered by project_dir.name)."""
        entries = [
            (i, self.tabs.widget(i))
            for i in range(self.tabs.count())
            if isinstance(self.tabs.widget(i), ProjectWidget)
        ]

        groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for i, widget in entries:
            display = self._tab_title_for(widget)
            groups[display].append((widget.project_dir.name, i))

        for i, widget in entries:
            display = self._tab_title_for(widget)
            group = sorted(groups[display])
            if len(group) == 1:
                title = display
            else:
                rank = next(n + 1 for n, (dn, _) in enumerate(group)
                            if dn == widget.project_dir.name)
                title = f"{display} ({rank})"
            self.tabs.setTabText(i, title)

    def _on_wrap_toggled(self, checked: bool):
        self._word_wrap = checked
        for pw in self._project_widgets():
            pw.set_word_wrap(checked)

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self._retranslate()
        super().changeEvent(event)

    def _retranslate(self):
        self._file_menu.setTitle(self.tr("File"))
        self._open_action.setText(self.tr("Open Project"))
        self._close_action.setText(self.tr("Close Project"))
        self._close_all_action.setText(self.tr("Close All Projects"))
        self._export_action.setText(self.tr("Export Kathara Project"))
        self._settings_action.setText(self.tr("Settings"))
        self._language_action.setText(self.tr("Language"))
        self._quit_action.setText(self.tr("Quit"))
        self._edit_menu.setTitle(self.tr("Edit"))
        self._select_all_action.setText(self.tr("Select All"))
        self._cut_action.setText(self.tr("Cut"))
        self._copy_action.setText(self.tr("Copy"))
        self._paste_action.setText(self.tr("Paste"))
        self._closing_label.setText(self.tr("closing in progress..."))
        self._wrap_btn.setToolTip(self.tr("Wrap"))
        self._settings_btn.setToolTip(self.tr("Settings"))
        self._language_btn.setToolTip(self.tr("Language"))
        self._refresh_tab_titles()

    def _apply_language_priority(self, priority: list):
        settings.set_language_priority(priority)
        for pw in self._project_widgets():
            pw.set_language_priority(priority)
        self._refresh_tab_titles()

    def _open_language_dialog(self):
        priority = settings.get_language_priority()
        project_langs = self._collect_project_languages()
        dlg = _LanguagePriorityDialog(priority, project_langs, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._apply_language_priority(dlg.priority())

    def _collect_project_languages(self) -> set:
        """Gather all language codes present in open projects."""
        langs = set()
        for pw in self._project_widgets():
            info = pw.info
            for key in ('title', 'informations'):
                v = info.get(key)
                if isinstance(v, dict):
                    langs.update(v.keys())
            for q in info.get('questions', []):
                for field in ('title', 'description'):
                    v = q.get(field)
                    if isinstance(v, dict):
                        langs.update(v.keys())
        return langs

    def _update_stacked_page(self):
        if self._exam_data is not None:
            phase = self._compute_exam_phase(self._exam_data)
            if phase == "ended":
                self._stacked.setCurrentIndex(2)
                return
            if phase == "waiting":
                self._stacked.setCurrentIndex(1)
                return
            # active: show tabs only once all expected projects are running
            if not self._projects_ready(self._exam_data):
                self._stacked.setCurrentIndex(1)
                return
        self._stacked.setCurrentIndex(0 if self._project_widgets() else 1)

    def _scan_projects(self):
        self._update_exam_state()

        current_dirs = set(load_projects())

        changed = False
        for i in range(self.tabs.count() - 1, -1, -1):
            widget = self.tabs.widget(i)
            if not isinstance(widget, ProjectWidget):
                continue
            if widget.project_dir not in current_dirs:
                self.tabs.removeTab(i)
                changed = True
            else:
                if widget.refresh():
                    changed = True

        tab_dirs = {self.tabs.widget(i).project_dir
                    for i in range(self.tabs.count())
                    if isinstance(self.tabs.widget(i), ProjectWidget)}
        for project_dir in sorted(current_dirs - tab_dirs):
            self.add_project(project_dir, switch_to=False)
            changed = True

        if self._exam_data is None:
            for pw in self._project_widgets():
                pw.tick_bg_eval()

        if changed:
            self._refresh_tab_titles()
            self._update_menu_state()
            self._update_stacked_page()
            project_widgets = self._project_widgets()
            if (len(project_widgets) == 1
                    and not isinstance(self.tabs.currentWidget(), ProjectWidget)):
                self.tabs.setCurrentWidget(project_widgets[0])

    # ------------------------------------------------------------------
    # Exam state management / debug logging
    # ------------------------------------------------------------------

    def _dbg(self, event: str, **fields):
        data = {"time": datetime.now().strftime("%H:%M:%S.%f")[:-3], "event": event}
        data.update(fields)
        print(json.dumps(data), file=sys.stderr, flush=True)

    def _dbg_exam_state(self, exam_data: dict | None, phase: str | None):
        """Emit debug lines every tick when exam mode is active, plus on every state change."""
        if not self._debug:
            return

        prev_data = self._dbg_prev_exam_data
        prev_phase = self._dbg_prev_phase
        now = datetime.now()

        # --- exam mode entered / exited (on change only) ---
        if prev_data is None and exam_data is not None:
            self._dbg("exam_entered", exam_data=exam_data)
        elif prev_data is not None and exam_data is None:
            self._dbg("exam_exited")

        # --- exam.json content changed (on change only) ---
        if prev_data is not None and exam_data is not None and exam_data != prev_data:
            added   = {k: exam_data[k] for k in exam_data if k not in prev_data}
            removed = {k: prev_data[k] for k in prev_data if k not in exam_data}
            changed = {k: [prev_data[k], exam_data[k]]
                       for k in exam_data
                       if k in prev_data and exam_data[k] != prev_data[k]}
            self._dbg("exam_modified", added=added, removed=removed, changed=changed)

        # --- phase change (on change only) ---
        if exam_data is not None and phase is not None and phase != prev_phase:
            self._dbg("phase_change",
                      prev=prev_phase,
                      new=phase,
                      now=now.isoformat(timespec='seconds'),
                      start_after=exam_data.get(params.exam_start_after),
                      started_at=exam_data.get(params.exam_started_at),
                      end_before=exam_data.get(params.exam_end_before),
                      duration=exam_data.get(params.exam_duration),
                      labs=exam_data.get(params.exam_labs, []),
                      app_start_time=self._app_start_time.isoformat(timespec='seconds'))

        # --- per-tick state line (every second when exam mode is on) ---
        if exam_data is not None:
            labs_internal = sorted(
                params.get_lab_name_from_cli_arg(lab, is_path=lab.startswith('/'))
                for lab, _ in (params.parse_lab_entry(e) for e in exam_data.get(params.exam_labs, []))
            )
            running = sorted(
                params.get_lab_name_from_running_lab_name(pw.project_dir.name)
                for pw in self._project_widgets()
            )
            projects_ready = (running == labs_internal) if labs_internal else True

            # Log projects-ready change separately for emphasis
            if phase == "active" and projects_ready != self._dbg_prev_projects_ready:
                self._dbg("projects_ready_change",
                          ready=projects_ready,
                          expected=labs_internal,
                          running=running)

            self._dbg("tick",
                      phase=phase,
                      now=now.isoformat(timespec='seconds'),
                      start_after=exam_data.get(params.exam_start_after),
                      started_at=exam_data.get(params.exam_started_at),
                      end_before=exam_data.get(params.exam_end_before),
                      duration=exam_data.get(params.exam_duration),
                      pre_start_called=self._pre_start_called,
                      start_exam_called=self._start_exam_called,
                      end_eval_called=self._end_eval_called,
                      expected_labs=labs_internal,
                      running_labs=running,
                      projects_ready=projects_ready)
            self._dbg_prev_projects_ready = projects_ready if phase == "active" else None
        else:
            self._dbg_prev_projects_ready = None

        self._dbg_prev_exam_data = dict(exam_data) if exam_data is not None else None
        self._dbg_prev_phase = phase

    def _read_exam_json(self) -> dict | None:
        path = Path(params.sre_pub_dir) / params.exam_json_name
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def _compute_exam_phase(self, exam_data: dict) -> str:
        now = datetime.now()

        # a. waiting phase
        start_after = None
        if params.exam_start_after in exam_data:
            try:
                start_after = _parse_dt(exam_data[params.exam_start_after])
            except (ValueError, TypeError):
                pass
        if (start_after is not None and now < start_after
                and params.exam_started_at not in exam_data):
            return "waiting"

        # b. compute real_starting_time
        started_at = None
        if params.exam_started_at in exam_data:
            try:
                started_at = _parse_dt(exam_data[params.exam_started_at])
            except (ValueError, TypeError):
                pass
        if started_at is not None:
            real_starting_time = started_at
        elif start_after is not None:
            real_starting_time = start_after
        else:
            real_starting_time = self._app_start_time

        # c. end_before check
        end_before = None
        if params.exam_end_before in exam_data:
            try:
                end_before = _parse_dt(exam_data[params.exam_end_before])
            except (ValueError, TypeError):
                pass
        if end_before is not None and now >= end_before:
            return "ended"

        # d. duration check — only when started_at is known.
        # Without it the exam was never formally started, so duration cannot have elapsed.
        if started_at is not None:
            try:
                duration = int(exam_data[params.exam_duration])
            except (KeyError, ValueError, TypeError):
                duration = params.default_exam_duration
            if now >= started_at + timedelta(minutes=duration):
                return "ended"

        # e. active
        return "active"

    def _projects_ready(self, exam_data: dict) -> bool:
        """True when there is exactly one running project per lab in exam_data['labs'], no others."""
        labs = sorted(
            params.get_lab_name_from_cli_arg(lab, is_path=lab.startswith('/'))
            for lab, _ in (params.parse_lab_entry(e) for e in exam_data.get(params.exam_labs, []))
        )
        if not labs:
            return True
        running = sorted(
            params.get_lab_name_from_running_lab_name(pw.project_dir.name)
            for pw in self._project_widgets()
        )
        return running == labs

    def _maybe_pre_start_for_labs_change(self, exam_data: dict):
        """If the labs list changed since the last pre-start, re-launch pre-start-exam
        so new labs get their projects created. Only fires once _last_known_labs is set
        (i.e. after a prior pre-start-exam) — the initial pre-start is handled by
        _maybe_pre_start.
        """
        if self._last_known_labs is None:
            return
        current_labs = list(exam_data.get(params.exam_labs, []))
        def _entry_key(e):
            lab, flavor = params.parse_lab_entry(e)
            return (lab, flavor or "")
        if sorted(current_labs, key=_entry_key) == sorted(self._last_known_labs, key=_entry_key):
            return
        cmd = [params.sre_wrapper, "pre-start-exam"]
        log_wrapper_cmd(cmd)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._last_known_labs = current_labs

    def _update_exam_state(self):
        exam_data = self._read_exam_json()

        # Detect transition: exam → no-exam (exam.json disappeared, e.g. del-exam)
        if self._exam_data is not None and exam_data is None:
            self._kill_all_terminals()

        # Detect transition: no-exam → exam (reset flags)
        if self._exam_data is None and exam_data is not None:
            self._pre_start_called = False
            self._start_exam_called = False
            self._exam_fields_snapshot = None
            self._eval_exam_proc = None
            self._eval_exam_interval = None
            self._next_eval_exam = None
            self._end_eval_called = False
            self._last_known_labs = None

        # Detect exam reset: set-exam was called again and cleared execution-state fields.
        # Reset the corresponding GUI flags so pre-start-exam / start-exam fire again.
        if self._exam_data is not None and exam_data is not None:
            if (params.exam_pre_start_date in self._exam_data
                    and params.exam_pre_start_date not in exam_data):
                self._pre_start_called = False
            if (params.exam_started_at in self._exam_data
                    and params.exam_started_at not in exam_data):
                self._start_exam_called = False
                self._exam_fields_snapshot = None
                self._eval_exam_interval = None
                self._next_eval_exam = None
                self._end_eval_called = False
                self._last_known_labs = None

        self._exam_data = exam_data

        if exam_data is None:
            self._dbg_exam_state(None, None)
            self._set_exam_ui(False)
            self._exam_bar.setVisible(False)
            for pw in self._project_widgets():
                pw.set_exam_mode(False)
            self._update_stacked_page()
            return

        # In exam mode
        self._set_exam_ui(True)
        for pw in self._project_widgets():
            pw.set_exam_mode(True)

        phase = self._compute_exam_phase(exam_data)
        self._dbg_exam_state(exam_data, phase)

        if phase == "waiting":
            self._exam_bar.setVisible(True)
            self._update_waiting_countdown(exam_data)
            self._maybe_pre_start(exam_data)
            # If pre-start already ran and labs changed since then, re-fire pre-start-exam
            # so new labs get their projects created before the active phase begins.
            if self._pre_start_called:
                self._maybe_pre_start_for_labs_change(exam_data)

        elif phase == "active":
            # If pre_start_date is missing (set-exam without start-after went straight
            # to active), fire pre-start-exam now. _maybe_start_exam will defer until
            # pre_start_date appears in exam.json.
            self._maybe_pre_start(exam_data)
            self._maybe_start_exam()
            self._maybe_pre_start_for_labs_change(exam_data)
            projects_ready = self._projects_ready(exam_data)
            if projects_ready:
                current_snapshot = (
                    exam_data.get(params.exam_started_at),
                    exam_data.get(params.exam_start_after),
                    exam_data.get(params.exam_duration),
                    exam_data.get(params.exam_end_before),
                )
                if current_snapshot != self._exam_fields_snapshot:
                    for pw in self._project_widgets():
                        pw.save_answers()
                    self._exam_fields_snapshot = current_snapshot
            self._maybe_eval_exam(exam_data)
            self._exam_bar.setVisible(True)
            if not projects_ready:
                self._countdown_label.setText(self.tr("The machines are starting, exam will start shortly"))
            else:
                self._update_remaining_countdown(exam_data)

        elif phase == "ended":
            self._exam_bar.setVisible(False)
            self._maybe_end_eval()

        self._update_stacked_page()

    def _set_exam_ui(self, active: bool):
        has_projects = any(
            isinstance(self.tabs.widget(i), ProjectWidget)
            for i in range(self.tabs.count())
        )
        current_widget = self.tabs.currentWidget()
        current_is_project = isinstance(current_widget, ProjectWidget)
        self._open_action.setEnabled(not active)
        self._close_action.setEnabled(not active and current_is_project)
        self._close_all_action.setEnabled(not active and has_projects)
        can_export = (not active and current_is_project and
                      current_widget.info.get("export_kathara_project", True))
        self._export_action.setEnabled(can_export)
        self.tabs.setTabVisible(self.tabs.indexOf(self._plus_widget), not active)

    def _maybe_pre_start(self, exam_data: dict):
        if self._pre_start_called:
            return
        # Skip firing only if the exam is already established: started_at is set
        # AND all expected labs have running projects. Otherwise (fresh exam,
        # post-wipe, etc.) we need to fire pre-start-exam to (re)deploy.
        if (params.exam_started_at in exam_data
                and self._projects_ready(exam_data)):
            self._pre_start_called = True
            self._last_known_labs = list(exam_data.get(params.exam_labs, []))
            return
        if params.exam_start_after in exam_data:
            try:
                start_after = _parse_dt(exam_data[params.exam_start_after])
            except (ValueError, TypeError):
                return
            now = datetime.now()
            # In waiting phase, hold off until close to start_after. Once we're
            # within the pre-start window (or past start_after), fire.
            if now < start_after - timedelta(seconds=params.max_duration_between_exam_pre_start_and_start):
                return
        # pre-start-exam is idempotent (only starts labs not already running, only
        # stops projects not in the allowed list), so fire even if pre_start_date is
        # already in exam.json — the previous run's projects may have been wiped.
        cmd = [params.sre_wrapper, "pre-start-exam"]
        log_wrapper_cmd(cmd)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._pre_start_called = True
        # Snapshot the labs we pre-started so that _maybe_pre_start_for_labs_change
        # can detect any change that happened between pre-start and going active.
        self._last_known_labs = list(exam_data.get(params.exam_labs, []))

    def _maybe_start_exam(self) -> bool:
        if self._start_exam_called:
            return False
        if self._exam_data is None:
            return False
        if params.exam_started_at in self._exam_data:
            return False
        # Wait for the labs to actually be running before marking the exam as
        # started. This naturally serialises pre-start-exam → start-exam without
        # racing on exam.json (pre-start-exam runs before projects come up).
        if not self._projects_ready(self._exam_data):
            return False
        if params.exam_start_after in self._exam_data:
            try:
                start_after = _parse_dt(self._exam_data[params.exam_start_after])
                if datetime.now() < start_after:
                    return False
            except Exception:
                return False
        cmd = [params.sre_wrapper, "start-exam"]
        log_wrapper_cmd(cmd)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._start_exam_called = True
        return True

    def _quit(self):
        self._kill_all_terminals()
        if self._exam_data is None:
            procs = []
            for pw in self._project_widgets():
                if pw.info.get("eval_before_exit", False):
                    cmd = [params.sre_wrapper, "eval", pw.project_dir.name]
                    log_wrapper_cmd(cmd)
                    procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            if procs:
                self._stacked.setCurrentWidget(self._closing_widget)
                self._exam_bar.setVisible(False)
                QApplication.processEvents()
                for proc in procs:
                    proc.wait()
        QApplication.instance().quit()

    def closeEvent(self, event):
        self._kill_all_terminals()
        super().closeEvent(event)

    def _kill_all_terminals(self):
        for pw in self._project_widgets():
            pw.kill_terminals()

    def _maybe_end_eval(self):
        self._kill_all_terminals()
        if self._end_eval_called:
            return
        cmd = [params.sre_wrapper, "end-exam"]
        log_wrapper_cmd(cmd)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._end_eval_called = True

    def _maybe_eval_exam(self, exam_data: dict):
        if params.exam_started_at not in exam_data:
            return
        try:
            interval = int(exam_data[params.exam_eval_interval])
        except (KeyError, ValueError, TypeError):
            return
        now = datetime.now()

        if self._next_eval_exam is None:
            # First call: schedule immediately
            self._next_eval_exam = now
            self._eval_exam_interval = interval
        elif interval != self._eval_exam_interval:
            # Interval changed: restart the period from now
            self._eval_exam_interval = interval
            self._next_eval_exam = now + timedelta(seconds=interval)

        if now < self._next_eval_exam:
            return

        # Due — but wait if the previous run is still in progress
        if self._eval_exam_proc is not None and self._eval_exam_proc.poll() is None:
            return

        cmd = [params.sre_wrapper, "eval-exam"]
        log_wrapper_cmd(cmd)
        self._eval_exam_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._next_eval_exam = now + timedelta(seconds=interval)

    def _update_waiting_countdown(self, exam_data: dict):
        try:
            start_after = _parse_dt(exam_data[params.exam_start_after])
            delta = start_after - datetime.now()
            total_seconds = max(0, int(delta.total_seconds()))
            days = total_seconds // 86400
            remainder = total_seconds % 86400
            h = remainder // 3600
            m = (remainder % 3600) // 60
            s = remainder % 60
            if days > 0:
                text = self.tr("Exam starts in {days}d {time}").format(days=days, time=f"{h:02d}:{m:02d}:{s:02d}")
            else:
                text = self.tr("Exam starts in {time}").format(time=f"{h:02d}:{m:02d}:{s:02d}")
            self._countdown_label.setText(text)
        except Exception:
            self._countdown_label.setText(self.tr("Exam starts soon"))

    def _update_remaining_countdown(self, exam_data: dict):
        try:
            duration = int(exam_data[params.exam_duration])
        except (KeyError, ValueError, TypeError):
            duration = params.default_exam_duration
        try:
            ref_time = _parse_dt(exam_data[params.exam_started_at])
        except (KeyError, ValueError, TypeError):
            try:
                ref_time = _parse_dt(exam_data[params.exam_start_after])
            except (KeyError, ValueError, TypeError):
                ref_time = self._app_start_time
        end_time = ref_time + timedelta(minutes=duration)
        if params.exam_end_before in exam_data:
            try:
                end_before = _parse_dt(exam_data[params.exam_end_before])
                if end_before < end_time:
                    end_time = end_before
            except (ValueError, TypeError):
                pass
        delta = end_time - datetime.now()
        total_seconds = max(0, int(delta.total_seconds()))
        h = total_seconds // 3600
        m = (total_seconds % 3600) // 60
        s = total_seconds % 60
        self._countdown_label.setText(self.tr("Time remaining: {time}").format(time=f"{h:02d}:{m:02d}:{s:02d}"))

    def _project_widgets(self) -> list[ProjectWidget]:
        return [self.tabs.widget(i) for i in range(self.tabs.count())
                if isinstance(self.tabs.widget(i), ProjectWidget)]

    # ------------------------------------------------------------------
    # Tab bar events
    # ------------------------------------------------------------------

    def _on_current_changed(self, index):
        if self.tabs.widget(index) is self._plus_widget:
            if self._prev_index >= 0:
                self.tabs.setCurrentIndex(self._prev_index)
        else:
            self._prev_index = index
        self._update_menu_state()

    def _on_tab_bar_clicked(self, index):
        if self.tabs.widget(index) is self._plus_widget:
            self._open_new_project()

    # ------------------------------------------------------------------
    # File menu actions
    # ------------------------------------------------------------------

    def _open_new_project(self):
        dialog = OpenProjectDialog(self)
        if dialog.exec() != OpenProjectDialog.Accepted:
            return

        project = dialog.selected_project
        from sysreseval.start_progress_dialog import StartProgressDialog
        progress = StartProgressDialog(project, parent=self)
        if progress.exec() != StartProgressDialog.DialogCode.Accepted:
            return

        existing = {self.tabs.widget(i).project_dir
                    for i in range(self.tabs.count())
                    if isinstance(self.tabs.widget(i), ProjectWidget)}
        for project_dir in load_projects():
            if project_dir not in existing:
                self.add_project(project_dir)

    def _open_settings(self):
        from sysreseval.settings_dialog import SettingsDialog
        SettingsDialog(self).exec()

    # ------------------------------------------------------------------
    # Edit menu actions
    # ------------------------------------------------------------------

    def _active_terminal(self):
        project = self.tabs.currentWidget()
        if isinstance(project, ProjectWidget):
            return project.active_terminal()
        return None

    def _update_edit_menu(self):
        term = self._active_terminal()
        in_terminal = term is not None
        self._select_all_action.setEnabled(not in_terminal)
        self._cut_action.setEnabled(not in_terminal)
        self._copy_action.setEnabled(True)

    @staticmethod
    def _edit_select_all():
        w = QApplication.focusWidget()
        if hasattr(w, "selectAll"):
            w.selectAll()

    @staticmethod
    def _edit_cut():
        w = QApplication.focusWidget()
        if hasattr(w, "cut"):
            w.cut()

    def _edit_copy(self):
        term = self._active_terminal()
        if term:
            term.copy()
            return
        w = QApplication.focusWidget()
        if hasattr(w, "copy"):
            w.copy()

    def _edit_paste(self):
        term = self._active_terminal()
        if term:
            term.paste()
            return
        w = QApplication.focusWidget()
        if hasattr(w, "paste"):
            w.paste()
