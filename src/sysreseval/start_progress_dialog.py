import json

from PySide6.QtCore import QProcess, QTimer
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QProgressBar, QDialogButtonBox
)

from SRE import params
from SRE.common import TranslatedText
from sysreseval import settings, util


class StartProgressDialog(QDialog):
    """Runs 'sre-wrapper start <project>' and shows progress from its stderr."""

    def __init__(self, project: str, flavor: str | None = None, parent=None):
        super().__init__(parent)
        self._project = project
        self._stderr_buf = ""
        self._flavor_form: str | None = None
        self._flavor_form_size: list | None = None
        self._flavor_error: str | None = None
        self._last_flavor_json: str | None = None
        self._last_plain_stderr: str = ""

        self.setWindowTitle(self.tr("Opening project"))
        self.setMinimumWidth(420)
        self.setModal(True)
        # Prevent closing the dialog while the process is running
        self.setWindowFlag(self.windowFlags().__class__.WindowCloseButtonHint, False)

        layout = QVBoxLayout(self)

        self._label = QLabel(self.tr("Starting…"))
        layout.addWidget(self._label)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)   # indeterminate until first real event
        layout.addWidget(self._bar)

        # Only shown on error
        self._buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        self._buttons.accepted.connect(self.reject)
        self._buttons.hide()
        layout.addWidget(self._buttons)

        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self._process.readyReadStandardError.connect(self._read_stderr)
        self._process.finished.connect(self._on_finished)
        args = ["start", "--flavor-json", flavor, project] if flavor is not None else ["start", project]
        util.log_wrapper_cmd([params.sre_wrapper] + args)
        self._process.start(params.sre_wrapper, args)

    # ------------------------------------------------------------------

    def _read_stderr(self):
        raw = self._process.readAllStandardError().toStdString()
        self._stderr_buf += raw
        while "\n" in self._stderr_buf:
            line, self._stderr_buf = self._stderr_buf.split("\n", 1)
            line = line.strip()
            if line:
                try:
                    self._handle_event(json.loads(line))
                except (json.JSONDecodeError, KeyError):
                    self._last_plain_stderr = line

    def _handle_event(self, ev: dict):
        phase = ev.get("phase")
        status = ev.get("status")

        if phase == "flavor_form" and status == "needed":
            self._flavor_form = ev.get("form", "")
            self._flavor_form_size = ev.get("form_size")
        elif phase == "flavor_error":
            self._flavor_error = ev.get("message", "")

        elif phase == "pull":
            if status == "start":
                self._bar.setRange(0, 0)
                self._label.setText(self.tr("Downloading images…"))
            elif status == "downloading":
                pct = ev.get("overall_percent", 0)
                self._bar.setRange(0, 100)
                self._bar.setValue(pct)
                self._label.setText(self.tr("Downloading images: {pct}%").format(pct=pct))
            elif status == "end":
                self._bar.setRange(0, 100)
                self._bar.setValue(100)
                self._label.setText(self.tr("Images ready."))

        elif phase == "deploy":
            if status == "start":
                total = ev.get("total", 0)
                self._bar.setRange(0, max(total, 1))
                self._bar.setValue(0)
                self._label.setText(
                    self.tr("Starting {n} machine(s)…").format(n=total)
                )
            elif status == "progress":
                current = ev.get("current", 0)
                total = ev.get("total", 1)
                self._bar.setRange(0, total)
                self._bar.setValue(current)
                self._label.setText(
                    self.tr("Starting machines: {cur}/{tot}").format(cur=current, tot=total)
                )
            elif status == "end":
                self._bar.setValue(self._bar.maximum())
                self._label.setText(self.tr("All machines started."))

    def _on_finished(self, exit_code: int, _exit_status):
        self._read_stderr()  # flush any remaining buffered output
        if exit_code == 0:
            self.accept()
        elif exit_code == params.exit_code_flavor_form_needed and self._flavor_form is not None:
            self._show_flavor_form()
        elif exit_code == params.exit_code_flavor_not_allowed:
            raw = self._flavor_error or self.tr("This flavor is not allowed.")
            error_message = TranslatedText.from_value(raw).resolve_priority(settings.get_language_priority())
            self._show_flavor_form(error_message=error_message)
        else:
            detail = f": {self._last_plain_stderr}" if self._last_plain_stderr else ""
            self._label.setText(
                self.tr("Failed to start project (exit code {code}){detail}.").format(
                    code=exit_code, detail=detail)
            )
            self._bar.setRange(0, 1)
            self._bar.setValue(0)
            self._buttons.show()

    def _show_flavor_form(self, error_message: str | None = None):
        from .flavor_form_dialog import FlavorFormDialog
        previous_answers = json.loads(self._last_flavor_json) if self._last_flavor_json else None
        form_text = self._flavor_form
        if isinstance(form_text, dict):
            form_text = TranslatedText(form_text).resolve_priority(settings.get_language_priority())
        dlg = FlavorFormDialog(form_text, form_size=self._flavor_form_size,
                               previous_answers=previous_answers,
                               error_message=error_message, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._restart_with_flavor(dlg.get_flavor_json())
        else:
            self.reject()

    def _restart_with_flavor(self, flavor_json: str):
        self._last_flavor_json = flavor_json
        self._flavor_error = None
        self._stderr_buf = ""
        self._last_plain_stderr = ""
        self._label.setText(self.tr("Starting…"))
        self._bar.setRange(0, 0)
        self._buttons.hide()
        args = ["start", "--flavor-json", flavor_json, self._project]
        util.log_wrapper_cmd([params.sre_wrapper] + args)
        QTimer.singleShot(0, lambda: self._process.start(params.sre_wrapper, args))

    def reject(self):
        # Prevent closing with Escape while the process is running
        if self._process.state() != QProcess.ProcessState.NotRunning:
            return
        super().reject()
