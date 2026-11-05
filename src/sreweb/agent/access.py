"""The access rules of the agent, as pure functions (``AccessError`` carries the HTTP status).

The ``sre`` CLI only checks, in user mode, that the project belongs to the caller or to root
(``params.check_project_owner``; ``resolve_running_lab_name`` still accepts a substring among
those), and ``allow_connection``, ``allow_self_grade`` or the user-allowed states are enforced by
the Qt GUI only.  The agent therefore checks, before spawning anything: the exact running lab
name, its owner (an instructor is served by a privileged call, which the CLI never checks), the
visibility of a device, the state, and the flags of the lab.
Save and restore are not offered on the web: no endpoint, no rule.
"""
import os
import re

from SRE import params
from ..config import client_allowed   # noqa: F401  (re-exported: the peer check of ``allowed_clients``)
from ..identity import Identity, ROLE_INSTRUCTOR

_RLN = re.compile(params.running_lab_name_match_pattern)
#: The kinds of a device of the Terminals tab.
DEVICE_MACHINE = 'machine'
DEVICE_SWITCH = 'switch'


class AccessError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def check_running_lab_name(rln: str) -> str:
    """The running lab name of a request: exactly ``<timestamp>@@@<lab>@@@<owner>``, no path
    component.  Existence is checked by the registry (404)."""
    if not rln or '/' in rln or '\\' in rln or '\0' in rln or rln in ('.', '..') or not _RLN.match(rln):
        raise AccessError(404, "unknown project")
    return rln


def owner_of(rln: str) -> str:
    return params.get_username_from_running_lab_name(rln)


def check_owner(rln: str, identity: Identity):
    """The project belongs to the user, or the user is an instructor."""
    if owner_of(rln) != identity.login and identity.role != ROLE_INSTRUCTOR:
        raise AccessError(403, "not your project")


def is_privileged_caller(rln: str, identity: Identity) -> bool:
    """An instructor acting on a project that is not theirs: the agent runs ``sre`` privileged
    for them (no ``--user``, their own login), never as the student, so a student's cooldown,
    counters and answers are untouched by the help they get.  The owner, instructor or not,
    follows the student path."""
    return identity.role == ROLE_INSTRUCTOR and owner_of(rln) != identity.login


def instructor_view_allowed(info: dict, identity: Identity) -> bool:
    """The instructor view shows the instructor() texts and every state: instructors only, on
    the projects that hold those texts (instructor mode or debug project), like the "Instructor
    mode" button of the Qt GUI."""
    return (identity.role == ROLE_INSTRUCTOR and identity.instructor_view
            and bool(info.get('instructor_mode') or info.get('debug_project')))


def visible_machines(info: dict, identity: Identity) -> list:
    """The machines a user may see: never the hidden ones for a student (info.json lists them
    only for debug projects, which an instructor may inspect)."""
    machines = info.get('machines', []) or []
    if identity.role == ROLE_INSTRUCTOR:
        return list(machines)
    return [m for m in machines if not m.get('hidden', False)]


def visible_switches(info: dict) -> list:
    return list(info.get('switches', []) or [])


def check_device(info: dict, device: str, identity: Identity, *, connect_all: bool = False) -> str:
    """A device of the Terminals tab: a visible machine with ``allow_connection``, or a managed
    switch with ``allow_connection``; a debug project opens every device (the Qt GUI does the
    same), and so does *connect_all* (an instructor on a student's project: privileged
    ``sre connect`` lets them in).  Returns :data:`DEVICE_MACHINE` or :data:`DEVICE_SWITCH`."""
    debug = bool(info.get('debug_project', False)) or bool(connect_all)
    for m in visible_machines(info, identity):
        if m.get('name') == device:
            if not (m.get('allow_connection', False) or debug):
                raise AccessError(403, f"connection to {device} is not allowed")
            return DEVICE_MACHINE
    for s in visible_switches(info):
        if s.get('name') == device:
            if s.get('mode') != params.network_mode_managed:
                raise AccessError(403, f"{device} has no console")
            if not (s.get('allow_connection', False) or debug):
                raise AccessError(403, f"connection to {device} is not allowed")
            return DEVICE_SWITCH
    raise AccessError(404, f"unknown device {device}")


#: A student-path probe: what the owner of a project may do (the role decides, not the login).
_STUDENT_PATH = Identity(login='student')


def device_open_to_students(info: dict, device: str) -> bool:
    """Whether a student may open a terminal on *device* themself: what :func:`check_device`
    grants without *connect_all* (a visible machine or a managed switch with
    ``allow_connection``, every listed device of a debug project but the hidden machines,
    which a student never sees).  A session an instructor opens on any other device exists
    thanks to the privileged call only: the agent makes it private whatever the page asked,
    since a shared session is joined without the device check."""
    try:
        check_device(info, device, _STUDENT_PATH, connect_all=False)
    except AccessError:
        return False
    return True


def display_available(info: dict, identity: Identity) -> bool:
    """The lab has a machine the user sees that draws on the X server of the host
    (``x11_host``): the project gets a virtual desktop (the Display tab)."""
    return any(m.get('x11_host', False) and not m.get('hidden', False) for m in visible_machines(info, identity))


def check_display(info: dict, identity: Identity):
    if not display_available(info, identity):
        raise AccessError(404, "no display for this project")


def allowed_states(info: dict, identity: Identity) -> dict:
    """The states the user may apply: ``user_allowed_states`` of info.json without the
    admin-only ones, unless the project is a debug one or the instructor view is on."""
    states = dict(info.get('user_allowed_states', {}) or {})
    if info.get('debug_project') or instructor_view_allowed(info, identity):
        return states
    admin_only = set(info.get('admin_only_states', []) or [])
    return {name: desc for name, desc in states.items() if name not in admin_only}


def check_state(info: dict, state: str, identity: Identity):
    if not state or state not in allowed_states(info, identity):
        raise AccessError(403, f"state {state!r} is not allowed")


def check_self_grade(info: dict):
    if not info.get('allow_self_grade', True):
        raise AccessError(403, "self-evaluation is not allowed for this lab")


def check_schema_pdf(info: dict):
    """The lab's ``export_schema_pdf`` flag (File → Export Schema to PDF of the GUI), for
    everybody: it is a property of the lab, not a permission."""
    if not info.get('export_schema_pdf', True):
        raise AccessError(403, "the schema of this lab cannot be exported to PDF")


def exam_mode_on(pub_dir: str = None) -> bool:
    return os.path.exists(os.path.join(pub_dir or params.sre_pub_dir, params.exam_json_name))


def check_not_exam(pub_dir: str = None):
    """``sre`` refuses every user-mode command while ``exam.json`` exists: say so before
    spawning (409)."""
    if exam_mode_on(pub_dir):
        raise AccessError(409, "this host is in exam mode")


def check_exam_action(exam: dict | None, *, privileged: bool, during: bool = False):
    """The owner of an exam project (``exam.py``: the exam the portal programmed for it): 409
    "the exam is over" once it ended and, with *during*, 409 "exam in progress" while it runs
    (the self-evaluation, the states and the close: what the Qt GUI hides in exam mode).  An
    instructor on somebody else's project (*privileged*) is never refused, a plain project
    neither."""
    if exam is None or privileged:
        return
    if exam.get(params.exam_ended_at):
        raise AccessError(409, "the exam is over")
    if during:
        raise AccessError(409, "exam in progress")
