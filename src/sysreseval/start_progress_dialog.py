import json

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QDialog

from SRE import params
from SRE.common import TranslatedText
from sysreseval import settings
from sysreseval.wrapper_progress_dialog import WrapperProgressDialog


class StartProgressDialog(WrapperProgressDialog):
    """Runs 'sre-wrapper start <project>' and shows progress from its stderr."""

    def __init__(self, project: str, flavor: str | None = None, parent=None):
        self._project = project
        self._flavor_form: str | None = None
        self._flavor_form_size: list | None = None
        self._flavor_error: str | None = None
        self._last_flavor_json: str | None = None
        args = ["start", "--flavor-json", flavor, project] if flavor is not None else ["start", project]
        super().__init__(args,
                         title=self.tr("Opening project"),
                         initial_label=self.tr("Starting…"),
                         parent=parent)

    # ------------------------------------------------------------------

    def _handle_extra_event(self, ev: dict) -> bool:
        phase = ev.get("phase")
        status = ev.get("status")
        if phase == "flavor_form" and status == "needed":
            self._flavor_form = ev.get("form", "")
            self._flavor_form_size = ev.get("form_size")
            return True
        if phase == "flavor_error":
            self._flavor_error = ev.get("message", "")
            return True
        return False

    def _on_failure(self, exit_code: int) -> bool:
        if exit_code == params.exit_code_flavor_form_needed and self._flavor_form is not None:
            self._show_flavor_form()
            return True
        if exit_code == params.exit_code_flavor_not_allowed:
            raw = self._flavor_error or self.tr("This flavor is not allowed.")
            error_message = TranslatedText.from_value(raw).resolve_priority(settings.get_language_priority())
            self._show_flavor_form(error_message=error_message)
            return True
        return False

    def _failure_text(self, exit_code: int, detail: str) -> str:
        return self.tr("Failed to start project (exit code {code}){detail}.").format(
            code=exit_code, detail=detail)

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
        QTimer.singleShot(0, lambda: self._start_process(args))
