import json
from pathlib import Path

from PySide6.QtCore import QIODevice, QProcess
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QProgressBar, QDialogButtonBox
)

from SRE import params
from sysreseval import util


class WrapperProgressDialog(QDialog):
    """Runs an sre-wrapper command and shows the JSON progress events it writes on stderr.

    Subclasses override ``_handle_extra_event``, ``_on_failure`` and ``_failure_text``
    to add command-specific behaviour (see StartProgressDialog for the flavor form).
    """

    def __init__(self, args: list[str], title: str, initial_label: str,
                 stdin_file: str | None = None, stdout_file: str | None = None, parent=None):
        super().__init__(parent)
        self._stdin_file = stdin_file
        self._stdout_file = stdout_file
        self._stderr_buf = ""
        self._last_plain_stderr: str = ""
        self._process: QProcess | None = None

        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.setModal(True)
        # Prevent closing the dialog while the process is running
        self.setWindowFlag(self.windowFlags().__class__.WindowCloseButtonHint, False)

        layout = QVBoxLayout(self)

        self._label = QLabel(initial_label)
        layout.addWidget(self._label)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)   # indeterminate until first real event
        layout.addWidget(self._bar)

        # Only shown on error
        self._buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        self._buttons.accepted.connect(self.reject)
        self._buttons.hide()
        layout.addWidget(self._buttons)

        self._start_process(args)

    # ------------------------------------------------------------------

    def _start_process(self, args: list[str]):
        util.log_wrapper_cmd([params.sre_wrapper] + args)
        if self._process is None:
            self._process = QProcess(self)
            self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
            self._process.readyReadStandardError.connect(self._read_stderr)
            self._process.finished.connect(self._on_finished)
        if self._stdin_file is not None:
            self._process.setStandardInputFile(self._stdin_file)
        if self._stdout_file is not None:
            self._process.setStandardOutputFile(self._stdout_file, QIODevice.OpenModeFlag.Truncate)
        self._process.start(params.sre_wrapper, args)

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

    # Hooks for subclasses ------------------------------------------------

    def _handle_extra_event(self, ev: dict) -> bool:
        """Return True when the event was consumed by the subclass."""
        return False

    def _on_failure(self, exit_code: int) -> bool:
        """Return True when the failure was handled (no generic error display)."""
        return False

    def _failure_text(self, exit_code: int, detail: str) -> str:
        return self.tr("Command failed (exit code {code}){detail}.").format(code=exit_code, detail=detail)

    # ------------------------------------------------------------------

    def _handle_event(self, ev: dict):
        if self._handle_extra_event(ev):
            return

        phase = ev.get("phase")
        status = ev.get("status")

        if phase == "pull":
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
            return
        if self._on_failure(exit_code):
            return
        detail = f": {self._last_plain_stderr}" if self._last_plain_stderr else ""
        self._label.setText(self._failure_text(exit_code, detail))
        self._bar.setRange(0, 1)
        self._bar.setValue(0)
        self._buttons.show()

    def reject(self):
        # Prevent closing with Escape while the process is running
        if self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning:
            return
        super().reject()


class SaveProjectDialog(WrapperProgressDialog):
    """Runs 'sre-wrapper save <running_lab>' with stdout redirected to the chosen file."""

    def __init__(self, running_lab_name: str, out_path: str, parent=None):
        self._out_path = out_path
        super().__init__(["save", running_lab_name],
                         title=self.tr("Saving project"),
                         initial_label=self.tr("Saving project…"),
                         stdout_file=out_path, parent=parent)

    def _on_failure(self, exit_code: int) -> bool:
        # Do not leave a truncated/partial save file behind.
        Path(self._out_path).unlink(missing_ok=True)
        return False

    def _failure_text(self, exit_code: int, detail: str) -> str:
        return self.tr("Failed to save project (exit code {code}){detail}.").format(
            code=exit_code, detail=detail)


class RestoreProjectDialog(WrapperProgressDialog):
    """Runs 'sre-wrapper restore -' with the chosen save file on stdin."""

    def __init__(self, save_path: str, parent=None):
        super().__init__(["restore", params.save_stdio_arg],
                         title=self.tr("Restoring project"),
                         initial_label=self.tr("Restoring project…"),
                         stdin_file=save_path, parent=parent)

    def _failure_text(self, exit_code: int, detail: str) -> str:
        return self.tr("Failed to restore project (exit code {code}){detail}.").format(
            code=exit_code, detail=detail)
