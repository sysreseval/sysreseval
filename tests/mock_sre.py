#!/usr/bin/env python3
"""
Mock of the ``sre`` CLI for the offline tests of the web agent (``src/sreweb/agent/``).

The agent spawns ``<sre_exe> --user <cmd...>`` with the environment ``LOGNAME=root
SUDO_USER=<login> USER_USERNAME=<login>`` and reads the JSON events of stderr, the JSON of stdout
and the project directories.  This script answers like ``sre`` itself (not like ``sre-wrapper``):
same argument parser (subset), same exit codes and messages, same events of ``SRE/progress.py``,
same project layout and an ``info.json`` built through ``SRE.common.InfoLab`` so that it has every
key of a real one.  No Docker, no Kathara, no root: the "containers" are the stub below.

Environment variables (all optional but the first):
  SRE_PUB_DIR         the public dir: projects in <SRE_PUB_DIR>/projects, cooldown files in
                      <SRE_PUB_DIR>/last_self_grades, archives in <SRE_PUB_DIR>/archives, user
                      public dirs in <SRE_PUB_DIR>/home (required: the mock never touches /var/lib/sre)
  MOCK_X11            set: the open machine of the stub lab is an x11_host (its info.json)
  MOCK_SRE_LOG        a file where every invocation appends one JSON line
                      {"argv": [...], "env": {<the keys of LOGGED_ENV present in the environment>},
                       "username": <the SRE username of the call>, "user_mode": <--user given>}
  MOCK_LAB_LIST       JSON list of the lab names `list` prints (default DEFAULT_LAB_LIST)
  MOCK_FLAVOR_FORM    when set, `start` without --flavor-json (user mode) exits 3 with the
                      flavor_form event, `form` being its value
  MOCK_FLAVOR_REFUSE  when set, `start --flavor-json` exits 4 with the flavor_error event carrying
                      this message
  MOCK_START_DELAY    seconds (float) slept between two progress events of start / restore
  MOCK_EVAL_DELAY     seconds (float) slept by `eval` while it holds .private/eval_in_progress
  MOCK_EVAL_ERRORS    JSON list of [category, text] pairs: the `errors` of the archives `eval` writes
                      (real archives: zstandard + msgpack, the keys of Grade0.save_tests_on_file,
                      `tests` keyed by tuples)
  MOCK_EVAL_INTERVAL  seconds (int): the `eval_interval_without_exam_mode` of the info.json `start`
                      writes (default 0: no periodic evaluation by the agent)
  MOCK_COOLDOWN       seconds (int): `eval --auto-eval` answers {"grades": null,
                      "delay_before_self_grade": N} when the previous auto-eval of the same lab
                      and owner is younger than that (timestamp file of
                      params.self_grade_timestamp_file(lab, user)); also the delay_before_self_grade
                      of the grades JSON (0 without it)
  MOCK_FAIL           the subcommand that exits 1 with `sre: mock failure` on stderr

`main(argv, env)` runs one invocation and returns its exit code (the script itself runs
`main(sys.argv[1:], os.environ)`); `connect` replaces the process by a shell, so never call it
in-process.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import importlib.util
import io
import json
import math
import os
import re
import shlex
import shutil
import socket
import sys
import time
import warnings
import zipfile
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'src'))

if __name__ == '__main__':
    warnings.simplefilter('ignore')
    # SRE.common needs msgpack: when run through the shebang with a Python that lacks it (the
    # agent runs <sre_exe> directly), start again under the interpreter of the venv
    if importlib.util.find_spec('msgpack') is None:
        _venv_python = ROOT / 'venv' / 'bin' / 'python3'
        if _venv_python.is_file() and Path(sys.executable).resolve() != _venv_python.resolve():
            os.execv(str(_venv_python), [str(_venv_python), '-W', 'ignore', __file__, *sys.argv[1:]])

import msgpack  # noqa: E402
import zstandard as zstd  # noqa: E402

from SRE import access, params  # noqa: E402
from SRE.answers import load_answers  # noqa: E402
from SRE.instructor_text import instructor, set_instructor_context  # noqa: E402
from SRE.common import (GradeElement, GradePart, InfoInterface, InfoLab, InfoMachine, InfoSwitch,  # noqa: E402
                        project_accessible,
                        QuestionForm, QuestionText, TranslatedText)

ENV_PUB_DIR = 'SRE_PUB_DIR'
ENV_LOG = 'MOCK_SRE_LOG'
ENV_LAB_LIST = 'MOCK_LAB_LIST'
ENV_FLAVOR_FORM = 'MOCK_FLAVOR_FORM'
ENV_FLAVOR_REFUSE = 'MOCK_FLAVOR_REFUSE'
ENV_START_DELAY = 'MOCK_START_DELAY'
ENV_EVAL_DELAY = 'MOCK_EVAL_DELAY'
ENV_EVAL_ERRORS = 'MOCK_EVAL_ERRORS'
ENV_EVAL_INTERVAL = 'MOCK_EVAL_INTERVAL'
ENV_COOLDOWN = 'MOCK_COOLDOWN'
ENV_FAIL = 'MOCK_FAIL'
ENV_X11 = 'MOCK_X11'               # set: the open machine of the stub lab is an x11_host

#: the environment keys written to MOCK_SRE_LOG (when present in the environment)
LOGGED_ENV = ('SUDO_USER', 'USER_USERNAME', 'LOGNAME', 'SUDO_COMMAND', 'SRE_IN_RECORDER', 'TERM',
              'SRE_XAUTH_COOKIE', 'SRE_X11_DISPLAY')

DEFAULT_LAB_LIST = ["sre/dhcp.py", "s4/tp_ssh"]
#: the title of the first lab of the list (`list --with-titles`, `info.json`); the others have none
FIRST_LAB_TITLE = {"en": "DHCP lab", "fr": "TP DHCP"}
DEFAULT_LANGUAGE = 'en'

#: the machines of the stub lab: the hidden one is listed in info.json of debug projects only
MACHINE_OPEN = 'm1'
MACHINE_CLOSED = 'm2'
MACHINE_HIDDEN = 'probe'
DEPLOY_ORDER = (MACHINE_OPEN, MACHINE_CLOSED, MACHINE_HIDDEN)
#: the networks: a managed switch with a console and a plain switch without
SWITCH_MANAGED = 'lan'
SWITCH_PLAIN = 'dmz'
FINAL_STATE = 'final'
#: the cheat answers of the final state (the form answer is JSON-encoded, like Grade0.question_form)
CHEAT_TEXT_ANSWER = "42"
CHEAT_FORM_ANSWER = {"ip": "10.0.0.1", "ok": True}
FLAVOR_FILE_NAME = 'flavor.json'   # .private/flavor.json: the --flavor-json value of the start
FORM_SIZE = [640, 480]
SWITCH_PROMPT = 'switch> '
SHELL_PROMPT = 'mock$ '
STUB_IMAGE = params.default_docker_image
EVAL_PART_TITLE = 'Routing'

MOCK_FAILURE_MESSAGE = "mock failure"

# the attributes of params that follow SRE_PUB_DIR (what the tmp_pub_dir fixture of conftest patches)
_PATCHED_PARAMS = ('sre_pub_dir', 'sre_projects_dir', 'self_grade_timestamp_dir', 'archive_dirs',
                   'sre_user_public_dir', 'save_tmp_dir')


class _Quit(SystemExit):
    pass


def error_quit(message: str):
    print(f"sre: {message}", file=sys.stderr, flush=True)
    raise _Quit(1)


def emit(obj: dict):
    print(json.dumps(obj), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------
# the stub lab
# ---------------------------------------------------------------------------------------------

def _tr(en: str, fr: str) -> TranslatedText:
    return TranslatedText({'en': en, 'fr': fr})


def stub_questions() -> list:
    """The two questions of the stub lab: a free-text one and a form with a regex field and a
    checkbox.  Their hashes are those of the real classes (title, or title + description)."""
    text = QuestionText(_tr("Gateway of m1", "Passerelle de m1"),
                        _tr("Give the IPv4 address of the default gateway of `m1`.",
                            "Donnez l'adresse IPv4 de la passerelle par défaut de `m1`."),
                        order=100)
    form = QuestionForm(_tr("Addressing plan", "Plan d'adressage"),
                        _tr("Address of m2: @@{ip:[0-9.]+}@@\n\nConfiguration done: @@{ok:?}@@",
                            "Adresse de m2 : @@{ip:[0-9.]+}@@\n\nConfiguration terminée : @@{ok:?}@@"),
                        order=200,
                        fields=[{"name": "ip", "regex": "[0-9.]+"}, {"name": "ok", "checkbox": False}])
    return [text, form]


def question_hashes() -> tuple:
    """``(text_hash, form_hash)`` of the stub questions."""
    text, form = stub_questions()
    return text.question_hash, form.question_hash


def stub_machines(include_hidden: bool, x11_host: bool = False) -> list:
    lan, dmz = SWITCH_MANAGED, SWITCH_PLAIN
    machines = [
        InfoMachine(name=MACHINE_OPEN, status="running", allow_connection=True, hidden=False,
                    interfaces=[InfoInterface(lan, "eth0"), InfoInterface(dmz, "eth1")],
                    ports=["2222:22/tcp"], bridged=True, x11_host=x11_host),
        InfoMachine(name=MACHINE_CLOSED, status="running", allow_connection=False, hidden=False,
                    interfaces=[InfoInterface(lan, "eth0")], ports=[], bridged=False),
    ]
    if include_hidden:
        machines.append(InfoMachine(name=MACHINE_HIDDEN, status="running", allow_connection=False,
                                    hidden=True, interfaces=[InfoInterface(lan, "eth0"),
                                                             InfoInterface(dmz, "eth1")],
                                    ports=[], bridged=False))
    return machines


def stub_info(running_lab_name: str, title, *, debug_project: bool, instructor_mode: bool,
              x11_host: bool = False, eval_interval: int = 0) -> InfoLab:
    """The ``info.json`` of a project of the stub lab, as ``Grade0.save_lab_info()`` would write
    it: the hidden machine and every state only in a debug project; an ``instructor()`` fragment
    (the solution) at the top of the informations of an instructor-mode or debug project, as a
    real lab keeps it there (stripped everywhere else)."""
    set_instructor_context(debug_project or instructor_mode)
    try:
        solution = instructor(_tr("**Solution:** the gateway of m1 is 10.0.0.254.\n\n",
                                  "**Solution :** la passerelle de m1 est 10.0.0.254.\n\n"))
    finally:
        set_instructor_context(False)
    return InfoLab(
        lab_name=params.get_lab_name_from_running_lab_name(running_lab_name),
        lab_hash=hashlib.md5(running_lab_name.encode()).hexdigest(),
        title=TranslatedText.from_value(title, DEFAULT_LANGUAGE),
        informations=solution + _tr(
            "# Mock lab\n\nA stub project of `tests/mock_sre.py`: two machines on `lan`, "
            "`m1` also on `dmz`.\n\n| Machine | Role |\n|---|---|\n| m1 | client |\n| m2 | server |\n",
            "# TP factice\n\nUn projet factice de `tests/mock_sre.py` : deux machines sur `lan`, "
            "`m1` aussi sur `dmz`.\n\n| Machine | Rôle |\n|---|---|\n| m1 | client |\n| m2 | serveur |\n"),
        export_kathara_project=True,
        allow_self_grade=True,
        machines=stub_machines(include_hidden=debug_project, x11_host=x11_host),
        questions=stub_questions(),
        delay_between_self_grade=5,
        eval_interval_without_exam_mode=eval_interval,
        eval_before_exit=False,
        user_allowed_states={FINAL_STATE: _tr("Solution", "Solution")},
        debug_project=debug_project,
        instructor_mode=instructor_mode,
        allow_save_restore=True,
        export_schema_pdf=True,
        admin_only_states=[],
        default_language=DEFAULT_LANGUAGE,
        network_colors={SWITCH_PLAIN: "lightyellow"},
        network_shapes={},
        show_nat_network=params.default_show_nat_network,
        nat_network_name=params.default_host_network_name,
        nat_network_color=params.default_host_network_color,
        host_network_exploded=params.default_host_network_exploded,
        host_network_edge_relative_length=params.default_host_network_edge_relative_length,
        schema_splines=params.graphviz_default_splines,
        schema_overlap=params.graphviz_default_overlap,
        switches=[InfoSwitch(SWITCH_MANAGED, params.network_mode_managed, True),
                  InfoSwitch(SWITCH_PLAIN, params.network_mode_switch, True)],
    )


def stub_tests() -> dict:
    """The ``tests`` of an archive as ``Grade0`` keeps them: ``{(machine, step): {(command,
    timeout): (stdout, exit code)}}``; msgpack writes the tuple keys as arrays, which a reader
    unpacking them as lists cannot use as keys."""
    return {(MACHINE_OPEN, 1): {('cat /etc/hostname', 10): (f'{MACHINE_OPEN}\n', 0),
                                ('ip -4 -j addr', 10): ('[]', 0)},
            (MACHINE_CLOSED, 1): {('cat /etc/hostname', 10): (f'{MACHINE_CLOSED}\n', 0)}}


def stub_grades() -> tuple:
    """``(grade_parts, grade_elements, mark)``: two elements in a part plus one bonus element."""
    part = GradePart(title=EVAL_PART_TITLE, description=_tr("Routing between lan and dmz",
                                                             "Routage entre lan et dmz"))
    elements = [
        GradeElement(title="Default route of m1", max_grade=2, grade=2, grade_part=EVAL_PART_TITLE),
        GradeElement(title="Address of m2", max_grade=3, grade=1.5, grade_part=EVAL_PART_TITLE),
        GradeElement(title="IPv6 route of m1", max_grade=1, grade=1, bonus=True),
    ]
    total = sum(e.grade for e in elements)
    total_max = sum(e.max_grade for e in elements if not e.bonus)
    mark = min(params.default_maximum_mark, params.default_maximum_mark * total / total_max)
    return [part], elements, mark


# ---------------------------------------------------------------------------------------------
# one invocation
# ---------------------------------------------------------------------------------------------

class Mock:
    def __init__(self, args, env: dict):
        self.args = args
        self.env = env
        self.user_mode = bool(args.user)
        self.username = access.resolve_username(env, user_flag=args.user,
                                                use_sudo_user=params.use_sudo_user_for_username)

    # --- environment ---

    def lab_list(self) -> list:
        value = self.env.get(ENV_LAB_LIST)
        return json.loads(value) if value else list(DEFAULT_LAB_LIST)

    def lab_title(self, lab_cli_arg: str):
        labs = self.lab_list()
        return dict(FIRST_LAB_TITLE) if labs and lab_cli_arg == labs[0] else None

    def delay(self, name: str) -> float:
        value = self.env.get(name)
        return float(value) if value else 0.0

    def sleep_between_events(self):
        delay = self.delay(ENV_START_DELAY)
        if delay > 0:
            time.sleep(delay)

    # --- projects ---

    def require_project(self, running_lab_name: str) -> str:
        """The running lab name, which must be exact (no substring resolution), exist and, in user
        mode, be accessible to the caller (the ownership check of the real resolver)."""
        if (not re.fullmatch(params.running_lab_name_match_pattern, running_lab_name)
                or not os.path.isdir(params.public_lab_dir(running_lab_name))):
            error_quit(f"unknown running lab '{running_lab_name}'")
        if self.user_mode and not project_accessible(running_lab_name, self.username):
            error_quit(f"you're not allowed to access project '{running_lab_name}'")
        return running_lab_name

    @staticmethod
    def is_debug_project(running_lab_name: str) -> bool:
        return os.path.exists(params.debug_project_marker_filename(running_lab_name))

    @staticmethod
    def logs_operations(running_lab_name: str) -> bool:
        return (os.path.exists(params.debug_project_marker_filename(running_lab_name))
                or os.path.exists(params.instructor_mode_marker_filename(running_lab_name)))

    def not_allowed_in_exam_mode(self):
        if self.user_mode and os.path.exists(os.path.join(params.sre_pub_dir, params.exam_json_name)):
            error_quit("you're not allowed to run this command in exam mode")

    def create_project(self, lab_cli_arg: str, *, is_path: bool, debug_project: bool, instructor_mode: bool,
                       flavor=None) -> str:
        """The project directory of a new instance of *lab_cli_arg* (layout of
        ``start.create_project_directories``), the progress events, ``info.json``, then the
        ``project created`` event; returns the running lab name."""
        lab_name = params.get_lab_name_from_cli_arg(lab_cli_arg, is_path)
        now = datetime.datetime.now()
        running_lab_name = params.get_running_lab_name(lab_name, now, self.username)
        while os.path.exists(params.public_lab_dir(running_lab_name)):
            now += datetime.timedelta(seconds=1)   # same-second collision
            running_lab_name = params.get_running_lab_name(lab_name, now, self.username)

        os.makedirs(params.sre_projects_dir, mode=0o755, exist_ok=True)
        os.mkdir(params.public_lab_dir(running_lab_name))
        os.mkdir(params.private_lab_dir(running_lab_name))
        os.chmod(params.private_lab_dir(running_lab_name), 0o700)
        if debug_project:
            Path(params.debug_project_marker_filename(running_lab_name)).touch(mode=0o600)
        if instructor_mode:
            Path(params.instructor_mode_marker_filename(running_lab_name)).touch(mode=0o600)
        os.makedirs(params.files_dir(running_lab_name))
        os.mkdir(params.answers_dir(running_lab_name))
        os.chmod(params.answers_dir(running_lab_name), 0o777)
        os.symlink(str(Path(__file__).resolve()), params.srelab_link_filename(running_lab_name))

        base = f"{params.sre_user_public_dir}/{params.get_abbreviated_lab_name_from_running_lab_name(running_lab_name)}"
        user_public_dir, counter = base, 1
        while os.path.exists(user_public_dir):
            user_public_dir = f"{base}_{counter}"
            counter += 1
        os.makedirs(user_public_dir)
        os.chmod(user_public_dir, 0o755)
        os.symlink(user_public_dir, params.link_to_user_public_dir(running_lab_name))

        if flavor is not None:
            Path(params.private_lab_dir(running_lab_name), FLAVOR_FILE_NAME).write_text(json.dumps(flavor))

        self.emit_deployment()

        info = stub_info(running_lab_name, self.lab_title(lab_cli_arg) or lab_name.removesuffix('.py'),
                         debug_project=debug_project, instructor_mode=instructor_mode, x11_host=bool(self.env.get(ENV_X11)),
                         eval_interval=int(self.env.get(ENV_EVAL_INTERVAL) or 0))
        Path(params.info_filename(running_lab_name)).write_text(info.to_json())
        emit({"phase": "project", "status": "created", "running_lab_name": running_lab_name})
        return running_lab_name

    def emit_deployment(self):
        """The pull and deploy events of ``SRE/progress.py`` (``machine`` only in privileged mode)."""
        emit({"phase": "pull", "status": "start"})
        self.sleep_between_events()
        emit({"phase": "pull", "status": "downloading", "layer": "a1b2c3d4e5f6", "current": 512, "total": 1024,
              "overall_percent": 50})
        self.sleep_between_events()
        emit({"phase": "pull", "status": "end"})
        self.sleep_between_events()
        emit({"phase": "deploy", "status": "start", "total": len(DEPLOY_ORDER)})
        self.sleep_between_events()
        for current, machine in enumerate(DEPLOY_ORDER, 1):
            msg = {"phase": "deploy", "status": "progress", "current": current, "total": len(DEPLOY_ORDER)}
            if not self.user_mode:
                msg["machine"] = machine
            emit(msg)
            self.sleep_between_events()
        emit({"phase": "deploy", "status": "end"})

    @staticmethod
    def append_operations_log(running_lab_name: str, title: str, lines: list):
        """One block of ``operations.log``: ``=== <time>  <title>`` (preceded by a blank line unless
        the file is empty) then *lines*."""
        path = params.operations_log_filename(running_lab_name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            separator = "\n" if os.fstat(fd).st_size > 0 else ""
            header = f"=== {datetime.datetime.now():%Y-%m-%d %H:%M:%S}  {title}\n"
            os.write(fd, (separator + header + ''.join(lines)).encode())
        finally:
            os.close(fd)

    # --- actions ---

    def action_list(self):
        self.not_allowed_in_exam_mode()
        labs = self.lab_list()
        if self.args.with_titles:
            data = [{"name": lab, "title": self.lab_title(lab)} for lab in labs]
        else:
            data = labs
        print(json.dumps(data, ensure_ascii=False))

    def action_start(self):
        args = self.args
        if args.data_version is not None:
            if args.data is not None:
                error_quit("--data and data_version are mutually exclusive")
            if self.user_mode:
                error_quit("data_version argument is only available to privileged users")
        if args.set_flavor_name is not None and self.user_mode:
            error_quit("--set-flavor-name is not available in user mode")
        if args.debug_project and self.user_mode:
            error_quit("--debug-project is not available in user mode")
        if args.instructor_mode and self.user_mode:
            error_quit("--instructor-mode is not available in user mode")
        if args.xauth_file is not None and self.user_mode:
            error_quit("--xauth-file is only available to privileged users")
        self.not_allowed_in_exam_mode()
        is_path = bool(args.path) or bool(args.debug_project)
        if is_path and self.user_mode:
            error_quit("--user and --path options are mutually exclusive")
        if not is_path and args.lab not in self.lab_list():
            error_quit(f"lab '{args.lab}' does not exist")

        flavor = None
        if args.flavor_json is not None or args.flavor is not None:
            if args.flavor_json is not None:
                try:
                    flavor = json.loads(args.flavor_json)
                except ValueError:
                    error_quit("--flavor-json: invalid JSON")
            else:
                flavor = {}
                for item in args.flavor:
                    if ':' not in item:
                        error_quit(f"--flavor: expected key:value, got '{item}'")
                    key, value = item.split(':', 1)
                    flavor[key] = value
            refusal = self.env.get(ENV_FLAVOR_REFUSE)
            if refusal:
                emit({"phase": "flavor_error", "message": refusal})
                raise _Quit(params.exit_code_flavor_not_allowed)
        elif self.user_mode and self.env.get(ENV_FLAVOR_FORM):
            emit({"phase": "flavor_form", "status": "needed", "form": self.env[ENV_FLAVOR_FORM],
                  "form_size": FORM_SIZE})
            raise _Quit(params.exit_code_flavor_form_needed)

        self.create_project(args.lab, is_path=is_path, debug_project=bool(args.debug_project),
                            instructor_mode=bool(args.instructor_mode), flavor=flavor)

    def action_eval(self):
        self.not_allowed_in_exam_mode()
        running_lab_name = self.require_project(self.args.running_lab)
        owner = params.get_username_from_running_lab_name(running_lab_name)
        lab_name = params.get_lab_name_from_running_lab_name(running_lab_name)
        auto_eval = bool(self.args.auto_eval)
        cooldown = int(self.env.get(ENV_COOLDOWN) or 0)
        if self.user_mode and auto_eval and cooldown > 0:
            ts_file = params.self_grade_timestamp_file(lab_name=lab_name, username=owner)
            if os.path.exists(ts_file):
                diff = time.time() - os.stat(ts_file).st_mtime
                if diff < cooldown:
                    print(json.dumps({'grades': None,
                                      'delay_before_self_grade': math.ceil(cooldown - diff)}, indent=2))
                    return
            Path(params.self_grade_timestamp_dir).mkdir(parents=True, exist_ok=True)
            Path(ts_file).touch()

        lock_path = Path(params.private_lab_dir(running_lab_name)) / params.eval_in_progress_name
        lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        os.ftruncate(lock_fd, 0)
        os.write(lock_fd, str(os.getpid()).encode())
        try:
            delay = self.delay(ENV_EVAL_DELAY)
            if delay > 0:
                time.sleep(delay)
            now = datetime.datetime.now()
            parts, elements, mark = stub_grades()
            result = {
                params.running_lab_name_keyword: running_lab_name,
                params.eval_date_keyword: now.isoformat(),
                params.login_keyword: owner,
                params.hostname_keyword: socket.gethostname(),
                'grades': [asdict(e) for e in elements],
                'grade_parts': [asdict(p) for p in parts],
                'mark': mark,
                'maximum_mark': params.default_maximum_mark,
                'delay_before_self_grade': cooldown if self.user_mode else 0,
            }
            self.write_archive(running_lab_name, now, parts, elements, mark, auto_eval=auto_eval)
            if self.is_debug_project(running_lab_name):
                lines = [f"grade - [{e.grade_part}] {e.title} : {e.grade} / {e.max_grade}\n"
                         if e.grade_part else f"grade - {e.title} : {e.grade} / {e.max_grade}\n"
                         for e in elements]
                lines.append(f"total - self-eval : mark {mark:g} / {params.default_maximum_mark}\n")
                self.append_operations_log(running_lab_name, "evaluation", lines)
            if auto_eval or not self.user_mode:
                print(json.dumps(result, indent=2))
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)

    def write_archive(self, running_lab_name: str, now, parts, elements, mark, *, auto_eval: bool):
        """The archive of an evaluation, as ``Grade0.save_tests_on_file()`` writes it (zstandard +
        msgpack, same keys): the answers of the project with the metadata ``sre eval`` adds, the
        errors of MOCK_EVAL_ERRORS, the grade list, the same totals for both scopes."""
        archive_dir = Path(params.archive_dirs[0])
        archive_dir.mkdir(parents=True, exist_ok=True)
        answers = dict(load_answers(params.answers_filename(running_lab_name)))
        answers.setdefault(params.login_keyword, params.get_username_from_running_lab_name(running_lab_name))
        answers.setdefault(params.hostname_keyword, socket.gethostname())
        previous = [p for p in archive_dir.iterdir()
                    if (m := re.fullmatch(params.archive_name_match_pattern, p.name)) and m.group(2) == running_lab_name]
        answers[params.auto_eval_count_keyword] = len(previous) + 1 if auto_eval and self.user_mode else len(previous)
        errors = [tuple(e) if isinstance(e, list) else e for e in json.loads(self.env.get(ENV_EVAL_ERRORS) or '[]')]
        total = sum(e.grade for e in elements)
        total_max = sum(e.max_grade for e in elements if not e.bonus)
        archive = {
            params.running_lab_name_keyword: running_lab_name,
            params.eval_date_keyword: now.isoformat(),
            params.re_eval_date_keyword: None,
            'data_json': '{}',
            'tests': stub_tests(),
            'errors': errors,
            'answers': answers,
            'grade_list': [asdict(e) for e in elements],
            'grade_parts': [asdict(p) for p in parts],
            'total_grade_self_eval': total, 'total_max_self_eval': total_max, 'mark_self_eval': mark,
            'total_grade_exo_eval': total, 'total_max_exo_eval': total_max, 'mark_exo_eval': mark,
            'maximum_mark': params.default_maximum_mark,
            'files': {},
        }
        packed = msgpack.packb(archive, use_bin_type=True)
        (archive_dir / params.get_archive_name(running_lab_name, now)).write_bytes(
            zstd.ZstdCompressor(level=6).compress(packed))

    def action_state(self):
        self.not_allowed_in_exam_mode()
        running_lab_name = self.require_project(self.args.running_lab)
        state = self.args.state
        if state not in (params.initial_state_name, FINAL_STATE):
            error_quit(f"unknown state '{state}'")
        if self.logs_operations(running_lab_name):
            self.append_operations_log(running_lab_name, f"state {state}", [
                f"step1 - on {MACHINE_OPEN} : hostname\n",
                f"    {MACHINE_OPEN}\n",
                "    exit code 0\n",
            ])
        cheat_path = Path(params.cheat_filename(running_lab_name))
        cheat_path.parent.mkdir(parents=True, exist_ok=True)
        if state == FINAL_STATE:
            text_hash, form_hash = question_hashes()
            cheat = {text_hash: CHEAT_TEXT_ANSWER, form_hash: json.dumps(CHEAT_FORM_ANSWER)}
            fd = os.open(str(cheat_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o666)
            with os.fdopen(fd, 'w') as f:
                f.write(json.dumps(cheat, indent=2, ensure_ascii=False))
        else:
            cheat_path.unlink(missing_ok=True)

    def action_connect(self):
        args = self.args
        running_lab_name = self.require_project(args.running_lab)
        device = args.device
        debug_project = self.is_debug_project(running_lab_name)
        if args.shell is not None and self.user_mode:
            error_quit("--shell is not allowed in user mode")
        if args.no_records and self.user_mode:
            error_quit("--no-records is not allowed in user mode")
        if device == SWITCH_MANAGED:
            if args.shell is not None:
                error_quit("--shell does not apply to a switch")
            if args.exec_cmd:
                if self.user_mode:
                    error_quit("--exec is not allowed in user mode")
                print("ok")   # one console command, privileged only
                return
            self.switch_console(device, running_lab_name)
            return
        if device == SWITCH_PLAIN:
            error_quit(f"device {device} is a {params.network_mode_switch}: it has no console")
        if device not in DEPLOY_ORDER:
            error_quit(f"device {device} is unknown")
        if device == MACHINE_HIDDEN and self.user_mode and not debug_project:
            error_quit(f"device {device} is unknown")
        if args.exec_cmd:
            if self.user_mode:
                error_quit("--exec is not allowed in user mode")
            sys.stdout.flush()
            os.execv('/bin/sh', ['sh', '-c', shlex.join(args.exec_cmd)])
        if not os.isatty(0):
            error_quit("Machine not running")
        sys.stdout.flush()
        sys.stderr.flush()
        if self.env.get('MOCK_CONNECT_WAIT_INPUT'):
            # like Kathara on a machine whose startup never ends: nothing is printed until the
            # user "requests the control", i.e. until stdin becomes readable (nothing is read)
            import select
            while not select.select([0], [], [], 0.1)[0]:
                pass
            import termios
            termios.tcflush(0, termios.TCIFLUSH)   # the raw switch of Kathara discards the queue
        os.execve('/bin/sh', ['sh', '-i'], dict(os.environ, PS1=SHELL_PROMPT))

    def switch_console(self, network: str, running_lab_name: str):
        """The management console of the managed switch: ``ok`` to every command (in user mode
        only those of ``params.switch_user_commands`` reach it), ends on exit / quit / logout, on
        the end of the input and when the project is closed."""
        print(f"Switch {network}: management console ('help' lists the commands, 'exit' leaves)")
        while os.path.isdir(params.public_lab_dir(running_lab_name)):
            try:
                line = input(SWITCH_PROMPT).strip()
            except EOFError:
                print()
                return
            if not line:
                continue
            name = line.split()[0]
            if name in params.switch_console_exit_commands:
                return
            if self.user_mode and name not in params.switch_user_commands:
                print(f"error: command '{name}' is not allowed", file=sys.stderr, flush=True)
                continue
            print("ok", flush=True)
        print(f"The project was closed: end of the session on {network}.")

    def action_stop(self):
        self.not_allowed_in_exam_mode()
        running_lab_name = self.require_project(self.args.running_lab)
        self.remove_project(running_lab_name)

    @staticmethod
    def remove_project(running_lab_name: str):
        link = Path(params.link_to_user_public_dir(running_lab_name))
        if link.is_symlink():
            user_public_dir = link.resolve()
            if user_public_dir.is_dir() and str(user_public_dir).startswith(params.sre_user_public_dir + "/"):
                shutil.rmtree(user_public_dir, ignore_errors=True)
        home_dir = Path(params.sre_user_public_dir) / params.get_abbreviated_lab_name_from_running_lab_name(
            running_lab_name)
        if home_dir.is_dir():
            shutil.rmtree(home_dir, ignore_errors=True)
        shutil.rmtree(params.public_lab_dir(running_lab_name), ignore_errors=True)

    def action_wipe(self):
        if self.user_mode:
            error_quit("you're not allowed to run this command")
        projects = Path(params.sre_projects_dir)
        if projects.is_dir():
            for entry in projects.iterdir():
                if entry.is_dir():
                    self.remove_project(entry.name)

    def action_stop_all(self):
        """Every project the caller may access (all of them for a privileged caller)."""
        self.not_allowed_in_exam_mode()
        projects = Path(params.sre_projects_dir)
        if projects.is_dir():
            for entry in sorted(projects.iterdir()):
                if entry.is_dir() and (not self.user_mode or project_accessible(entry.name, self.username)):
                    self.remove_project(entry.name)

    def action_save(self):
        self.not_allowed_in_exam_mode()
        args = self.args
        if self.user_mode:
            if args.output is not None:
                error_quit("-o/--output is not available in user mode (the save file is written to stdout)")
            if args.full_images:
                error_quit("--full-images is only available to privileged users")
        running_lab_name = self.require_project(args.running_lab)
        header = {
            params.save_meta_format_version: params.save_format_version,
            params.save_meta_sre_version: params.sre_version,
            params.save_meta_lab_name: params.get_lab_name_from_running_lab_name(running_lab_name),
            params.save_meta_running_lab_name: running_lab_name,
            params.save_meta_username: params.get_username_from_running_lab_name(running_lab_name),
            params.save_meta_saved_at: datetime.datetime.now().isoformat(timespec='seconds'),
            params.save_meta_debug_project: self.is_debug_project(running_lab_name),
            params.save_meta_full_images: bool(args.full_images),
            params.save_meta_encrypted: False,
        }
        payload = params.save_file_magic + json.dumps(header).encode() + b"\n" + os.urandom(1024)
        if args.output is not None:
            try:
                Path(args.output).write_bytes(payload)
            except OSError as e:
                error_quit(f"cannot write '{args.output}': {e}")
        else:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()

    def action_restore(self):
        args = self.args
        if args.instructor_mode and self.user_mode:
            error_quit("--instructor-mode is not available in user mode")
        self.not_allowed_in_exam_mode()
        if args.save_file == params.save_stdio_arg:
            source = sys.stdin.buffer
        else:
            if self.user_mode:
                error_quit(f"in user mode the save file is read from stdin (use '{params.save_stdio_arg}')")
            try:
                source = open(args.save_file, 'rb')
            except OSError as e:
                error_quit(f"cannot open '{args.save_file}': {e}")
        with source:
            if source.read(len(params.save_file_magic)) != params.save_file_magic:
                error_quit("not an SRE save file")
            line = source.readline()
            if not line.endswith(b"\n"):
                error_quit("truncated save file header")
            try:
                header = json.loads(line)
            except ValueError:
                error_quit("invalid save file header")
            source.read()   # the payload
        # the lab of the save file: a name of the lab list, or a path (project started with
        # --path / --debug-project) that only a privileged user may restore
        lab_cli_arg = header[params.save_meta_lab_name].replace("@", "/")
        is_path = lab_cli_arg.startswith("/")
        if is_path and self.user_mode:
            error_quit("this save file refers to a lab outside the lab directory; restoring it requires privileges")
        if not is_path and lab_cli_arg not in self.lab_list():
            error_quit(f"lab '{lab_cli_arg}' does not exist")
        debug_project = bool(header.get(params.save_meta_debug_project)) and not self.user_mode
        running_lab_name = self.create_project(lab_cli_arg, is_path=is_path, debug_project=debug_project,
                                               instructor_mode=bool(args.instructor_mode))
        if not self.user_mode:
            print(running_lab_name)

    def action_export(self):
        self.not_allowed_in_exam_mode()
        running_lab_name = self.require_project(self.args.running_lab)
        lab_display = params.get_abbreviated_lab_name_from_running_lab_name(running_lab_name)
        lines = []
        for machine in stub_machines(include_hidden=True):
            for index, interface in enumerate(machine.interfaces):
                lines.append(f'{machine.name}[{index}]="{interface.network}"')
            lines.append(f'{machine.name}[image]="{STUB_IMAGE}"')
            if machine.bridged:
                lines.append(f'{machine.name}[bridged]="true"')
            lines.append("")
        lines.append(f'CD_MODE[{SWITCH_PLAIN}]="{params.network_mode_switch}"')
        lines.append(f'CD_MODE[{SWITCH_MANAGED}]="{params.network_mode_managed}"')
        lines.append("")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{lab_display}/lab.conf", "\n".join(lines))
        print(base64.b64encode(buf.getvalue()).decode("ascii"))


# ---------------------------------------------------------------------------------------------
# the parser (the subset of src/sre.py the agent uses) and the entry point
# ---------------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='SRE', description='SRE (mock)')
    parser.add_argument('--user', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--version', action='version', version=params.sre_version)
    subparsers = parser.add_subparsers(title='Actions', dest='action')

    parser_start = subparsers.add_parser('start')
    parser_start.add_argument('-d', '--data', metavar='src_data_file')
    parser_start.add_argument('-p', '--path', action='store_true')
    parser_start.add_argument('lab', metavar='lab')
    parser_start.add_argument('data_version', metavar='data_version', nargs='?', default=None)
    flavor_group = parser_start.add_mutually_exclusive_group()
    flavor_group.add_argument('--flavor', metavar='key:value', nargs='+')
    flavor_group.add_argument('--flavor-json', metavar='flavor_json')
    flavor_group.add_argument('--set-flavor-name', metavar='flavor_name')
    parser_start.add_argument('--debug-project', dest='debug_project', action='store_true')
    parser_start.add_argument('--instructor-mode', dest='instructor_mode', action='store_true')
    parser_start.add_argument('--xauth-file', metavar='x-authority-file', dest='xauth_file', default=None)

    parser_stop = subparsers.add_parser('stop')
    parser_stop.add_argument('running_lab', metavar='running_lab')

    parser_save = subparsers.add_parser('save')
    parser_save.add_argument('running_lab', metavar='running_lab')
    parser_save.add_argument('-o', '--output', metavar='save_file', default=None)
    parser_save.add_argument('--full-images', dest='full_images', action='store_true')

    parser_restore = subparsers.add_parser('restore')
    parser_restore.add_argument('--instructor-mode', dest='instructor_mode', action='store_true')
    parser_restore.add_argument('save_file', metavar='save_file')

    subparsers.add_parser('stop-all')

    subparsers.add_parser('wipe')

    parser_connect = subparsers.add_parser('connect')
    parser_connect.add_argument('--shell', metavar='shell', default=None)
    parser_connect.add_argument('--exec', metavar='argument', dest='exec_cmd', nargs=argparse.REMAINDER)
    parser_connect.add_argument('--no-records', action='store_true', dest='no_records')
    parser_connect.add_argument('running_lab', metavar='running_lab')
    parser_connect.add_argument('device')

    parser_eval = subparsers.add_parser('eval')
    parser_eval.add_argument('-p', '--path', metavar='path')
    parser_eval.add_argument('--auto-eval', dest='auto_eval', action='store_true')
    parser_eval.add_argument('running_lab', metavar='running_lab')

    parser_state = subparsers.add_parser('state')
    parser_state.add_argument('running_lab', metavar='running_lab')
    parser_state.add_argument('state')

    parser_list = subparsers.add_parser('list')
    parser_list.add_argument('--with-titles', action='store_true')

    parser_export = subparsers.add_parser('export')
    parser_export.add_argument('running_lab', metavar='running_lab')
    parser_export.add_argument('--sep', type=int, default=3, metavar='N')
    parser_export.add_argument('--curved', action='store_true')
    parser_export.add_argument('--shapes', action='store_true')
    parser_export.add_argument('--reverse', action='store_true')
    parser_export.add_argument('--random-seed', type=int, default=None, metavar='N')
    return parser


def log_invocation(argv: list, env: dict):
    log_file = env.get(ENV_LOG)
    if not log_file:
        return
    user_mode = '--user' in argv
    try:
        username = access.resolve_username(env, user_flag=user_mode, use_sudo_user=params.use_sudo_user_for_username)
    except Exception:
        username = None
    entry = {"argv": list(argv), "env": {key: env[key] for key in LOGGED_ENV if key in env},
             "username": username, "user_mode": user_mode}
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry) + "\n")


def run(argv: list, env: dict):
    log_invocation(argv, env)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.action is None:
        parser.print_help()
        raise _Quit(1)
    if args.user and args.debug:
        error_quit("--user and --debug are mutually exclusive")
    mock = Mock(args, env)
    if not access.is_valid_username(mock.username):
        error_quit(f"invalid username: '{mock.username}'")
    pub_dir = env.get(ENV_PUB_DIR)
    if not pub_dir:
        error_quit(f"{ENV_PUB_DIR} is not set (the mock never uses {params.sre_pub_dir})")
    if env.get(ENV_FAIL) == args.action:
        error_quit(MOCK_FAILURE_MESSAGE)

    saved = {name: getattr(params, name) for name in _PATCHED_PARAMS}
    params.sre_pub_dir = pub_dir
    params.sre_projects_dir = f"{pub_dir}/projects"
    params.self_grade_timestamp_dir = f"{pub_dir}/last_self_grades"
    params.archive_dirs = [f"{pub_dir}/archives"]
    params.sre_user_public_dir = f"{pub_dir}/home"
    params.save_tmp_dir = f"{pub_dir}/tmp"
    try:
        getattr(mock, 'action_' + args.action.replace('-', '_'))()
    finally:
        for name, value in saved.items():
            setattr(params, name, value)


def main(argv: list, env: dict) -> int:
    """One invocation of the mock: the exit code of ``sre`` (``connect`` never returns)."""
    try:
        run(argv, env)
    except SystemExit as e:
        code = e.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:], os.environ))
