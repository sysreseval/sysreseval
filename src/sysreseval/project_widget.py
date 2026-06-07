import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from sysreseval.view.machines_view import MachinesView

from sysreseval.view.information_view import InformationsView

from sysreseval.view.schema_view import SchemaView

from sysreseval.view.terminals_view import TerminalsView

from sysreseval.view.evaluations_view import EvaluationView

from sysreseval.view.questions_view import QuestionsView
from sysreseval.view.apply_config_view import ApplyConfigView

from sysreseval.util import load_info
from sysreseval import settings, util

from SRE import params
from SRE.common import TranslatedText


class ProjectWidget(QWidget):
    def __init__(self, project_dir: Path, parent=None):
        super().__init__(parent)

        self.project_dir = project_dir
        self.info = load_info(project_dir)
        self._lang_priority = settings.get_language_priority()

        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        self._tabs = tabs

        self._schema_view = SchemaView(self.info.get("machines", []),
                                       network_colors=self.info.get("network_colors", {}),
                                       network_shapes=self.info.get("network_shapes", {}),
                                       show_nat_network=self.info.get("show_nat_network", False),
                                       nat_network_name=self.info.get("nat_network_name", ''),
                                       nat_network_color=self.info.get("nat_network_color", ''),
                                       host_network_exploded=self.info.get("host_network_exploded", False),
                                       host_network_edge_relative_length=float(self.info.get("host_network_edge_relative_length", 1.0)),
                                       schema_splines=self.info.get("schema_splines", "curved"),
                                       schema_overlap=self.info.get("schema_overlap", "prism"))
        tabs.addTab(self._schema_view, self.tr("Schema"))

        self._info_view = InformationsView(self._resolve_tt(self.info.get("informations", "")))
        tabs.addTab(self._info_view, self.tr("Informations"))

        self._machines_view = MachinesView(project_dir.name, self.info.get("machines", []))
        tabs.addTab(self._machines_view, self.tr("Machines"))

        self._questions_view = QuestionsView(self.info.get("questions", []), project_dir.name)
        tabs.addTab(self._questions_view, self.tr("Questions"))
        tabs.setTabVisible(tabs.indexOf(self._questions_view),
                           bool(self.info.get("questions")))

        debug_project = bool(self.info.get("debug_project", False))

        self._eval_view = EvaluationView(
            self.info.get("evaluation", []),
            running_lab_name=project_dir.name,
            canonical_lab_name=self.info.get("lab_name", project_dir.name),
            debug_project=debug_project,
        )
        tabs.addTab(self._eval_view, self.tr("Evaluation"))

        self._terminals_view = TerminalsView(project_dir.name, self.info.get("machines", []),
                                             debug_project=debug_project)
        tabs.addTab(self._terminals_view, self.tr("Terminals"))

        self._apply_config_view = ApplyConfigView(
            self.info.get("user_allowed_states", {}), project_dir.name,
            admin_only_states=self.info.get("admin_only_states", []),
        )
        tabs.addTab(self._apply_config_view, self.tr("Apply Configuration"))

        layout.addWidget(tabs)

        self._exam_mode = False
        self._info_mtime = self._mtime(project_dir / params.info_json_name)
        self._update_eval_visibility()
        self._update_apply_config_visibility()

        self._bg_eval_interval: int = self.info.get("eval_interval_without_exam_mode", 0)
        self._bg_eval_next: datetime | None = None
        self._bg_eval_proc: subprocess.Popen | None = None

    def changeEvent(self, event):
        if event.type() == QEvent.Type.LanguageChange:
            self._tabs.setTabText(self._tabs.indexOf(self._schema_view), self.tr("Schema"))
            self._tabs.setTabText(self._tabs.indexOf(self._info_view), self.tr("Informations"))
            self._tabs.setTabText(self._tabs.indexOf(self._machines_view), self.tr("Machines"))
            self._tabs.setTabText(self._tabs.indexOf(self._questions_view), self.tr("Questions"))
            self._tabs.setTabText(self._tabs.indexOf(self._eval_view), self.tr("Evaluation"))
            self._tabs.setTabText(self._tabs.indexOf(self._terminals_view), self.tr("Terminals"))
            self._tabs.setTabText(self._tabs.indexOf(self._apply_config_view), self.tr("Apply Configuration"))
        super().changeEvent(event)

    def _resolve_tt(self, v) -> str:
        return TranslatedText.from_value(v).resolve_priority(self._lang_priority)

    def set_word_wrap(self, checked: bool):
        self._info_view.set_word_wrap(checked)
        self._questions_view.set_word_wrap(checked)

    def set_language_priority(self, priority: list):
        self._lang_priority = priority
        self._info_view.update_data(self._resolve_tt(self.info.get("informations", "")))
        self._questions_view.set_language_priority(priority)
        self._apply_config_view.set_language_priority(priority)
        self._eval_view.set_language_priority(priority)

    def schema_export_args(self) -> list[str]:
        return self._schema_view.schema_export_args()

    def save_answers(self):
        """Force-write answers.json for this project (e.g. on exam start)."""
        self._questions_view.save_answers()

    def _update_eval_visibility(self):
        visible = not self._exam_mode and self.info.get("allow_self_grade", True)
        self._tabs.setTabVisible(self._tabs.indexOf(self._eval_view), visible)

    def _update_apply_config_visibility(self):
        debug = bool(self.info.get("debug_project", False))
        visible = debug or (not self._exam_mode and bool(self.info.get("user_allowed_states")))
        self._tabs.setTabVisible(self._tabs.indexOf(self._apply_config_view), visible)

    def set_exam_mode(self, active: bool):
        self._exam_mode = active
        if active:
            self._bg_eval_next = None
            self._bg_eval_proc = None
        self._update_eval_visibility()
        self._update_apply_config_visibility()

    def tick_bg_eval(self):
        """Called every second when not in exam mode. Fires a background eval if due."""
        if self._exam_mode or self._bg_eval_interval <= 0:
            return
        now = datetime.now()
        if self._bg_eval_next is None:
            self._bg_eval_next = now + timedelta(seconds=self._bg_eval_interval)
            return
        if now < self._bg_eval_next:
            return
        if self._bg_eval_proc is not None and self._bg_eval_proc.poll() is None:
            return
        cmd = [params.sre_wrapper, "eval", self.project_dir.name]
        util.log_wrapper_cmd(cmd)
        self._bg_eval_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._bg_eval_next = now + timedelta(seconds=self._bg_eval_interval)

    def kill_terminals(self):
        self._machines_view.kill_terminals()
        self._terminals_view.kill_terminals()

    def active_terminal(self):
        if self._tabs.currentWidget() is self._terminals_view:
            return self._terminals_view.active_terminal()
        return None

    @staticmethod
    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    def refresh(self) -> bool:
        """Reload from info.json if it changed. Returns True if an update occurred."""
        # Consume cheat.json on every tick regardless of info.json state
        cheat_path = Path(params.cheat_filename(self.project_dir.name))
        if cheat_path.exists():
            try:
                cheat = json.loads(cheat_path.read_text())
                cheat_path.unlink()
                self._questions_view.apply_cheat(cheat)
            except Exception:
                pass

        info_path = self.project_dir / params.info_json_name
        info_mtime = self._mtime(info_path)
        if info_mtime == self._info_mtime:
            return False
        self._info_mtime = info_mtime
        try:
            self.info = load_info(self.project_dir)
        except Exception:
            return False
        machines = self.info.get("machines", [])
        self._schema_view.update_data(machines,
                                      network_colors=self.info.get("network_colors", {}),
                                      network_shapes=self.info.get("network_shapes", {}),
                                      show_nat_network=self.info.get("show_nat_network", False),
                                      nat_network_name=self.info.get("nat_network_name", ''),
                                      nat_network_color=self.info.get("nat_network_color", ''),
                                      host_network_exploded=self.info.get("host_network_exploded", False),
                                      host_network_edge_relative_length=float(self.info.get("host_network_edge_relative_length", 1.0)),
                                      schema_splines=self.info.get("schema_splines", "curved"),
                                      schema_overlap=self.info.get("schema_overlap", "prism"))
        self._info_view.update_data(self._resolve_tt(self.info.get("informations", "")))
        self._machines_view.update_data(machines)
        questions = self.info.get("questions", [])
        self._questions_view.update_data(questions)
        self._tabs.setTabVisible(self._tabs.indexOf(self._questions_view), bool(questions))
        self._terminals_view.update_data(machines)
        self._apply_config_view.update_data(self.info.get("user_allowed_states", {}),
                                            admin_only_states=self.info.get("admin_only_states", []))
        self._update_eval_visibility()
        self._update_apply_config_visibility()
        new_interval = self.info.get("eval_interval_without_exam_mode", 0)
        if new_interval != self._bg_eval_interval:
            self._bg_eval_interval = new_interval
            self._bg_eval_next = None
        return True
