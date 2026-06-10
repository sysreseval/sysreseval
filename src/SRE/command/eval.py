import datetime
import fcntl
import json
import math
import os
import shlex
import sys
import time
from dataclasses import asdict

from pathlib import Path
from Kathara.manager.Kathara import Kathara

from ..utils import error_quit, set_all_variables_for_action, user_not_allowed_in_exam_mode, exam_mode_is_on, \
    resolve_running_lab_name, dedup_preserve_order
from ..utils_privileges import drop_privileges_permanently_if_not_needed, drop_privileges_permanently, \
    drop_privileges_temporarily, gain_privileges_if_needed, gain_privileges, set_sudo_uid_for_username
from ..files_transfert import copy_state_files
from .. import params
from ..params import SRE


def _acquire_eval_lock(lock_path: Path) -> int:
    """Acquire an exclusive lock on lock_path, blocking until available.

    Returns the open file descriptor; the caller must close it to release the lock.
    Uses fcntl.flock so the kernel guarantees mutual exclusion with no TOCTOU window.
    """
    fd = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd


def _read_auto_eval_count(log_path: Path) -> int:
    """Return the number of previously-logged auto-evaluations.

    Counts lines in log_path; returns 0 when the file is missing.
    """
    try:
        with open(log_path) as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


def _append_auto_eval_timestamp(log_path: Path) -> None:
    """Append a new ISO timestamp line to log_path."""
    with open(log_path, 'a') as f:
        f.write(datetime.datetime.now().isoformat() + '\n')


def action_eval():
    user_not_allowed_in_exam_mode()
    do_eval(running_lab_name=resolve_running_lab_name(SRE.args.running_lab), print_result=True)


def do_eval(running_lab_name, multiples_evals=False, print_result=False):
    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
    if not multiples_evals:
        drop_privileges_permanently_if_not_needed(net_scheme)
    else:
        drop_privileges_temporarily()
    # Align Kathara's user filter with the project's actual owner (the trailing
    # @@@ segment of running_lab_name). Without this, a privileged lab started
    # by one user (e.g. root via `sre start -p ...`) cannot be found by an eval
    # launched as another user (e.g. the GUI's `sudo sre --user eval`), and
    # run_tests() leaves every test at its empty default_value.
    set_sudo_uid_for_username(params.get_username_from_running_lab_name(running_lab_name))

    srelab_file = params.get_current_srelab_file_from_running_lab_name(running_lab_name)
    info_file = params.info_filename(running_lab_name)
    srelab_real = os.path.realpath(srelab_file)
    if (os.path.exists(srelab_real) and os.path.exists(info_file)
            and os.path.getmtime(srelab_real) > os.path.getmtime(info_file)):
        grade = module_rvlab.Grade(net_scheme=net_scheme)
        grade.save_lab_info()

    debug_project = os.path.exists(params.debug_project_marker_filename(running_lab_name))

    if hasattr(module_rvlab, 'delay_between_self_grade'):
        delay_between_self_grade = module_rvlab.delay_between_self_grade
    else:
        delay_between_self_grade = 0
    if debug_project:
        delay_between_self_grade = 0

    auto_eval = getattr(SRE.args, 'auto_eval', False)
    if SRE.args.user and auto_eval and delay_between_self_grade > 0 and not exam_mode_is_on():
        ts_file = params.self_grade_timestamp_file(lab_name=net_scheme.lab_name)
        if os.path.exists(ts_file):
            diff = time.time() - os.stat(ts_file).st_mtime
            if diff < delay_between_self_grade:
                delay_before_self_grade = math.ceil(delay_between_self_grade - diff)
                result = {
                    'grades': None,
                    'delay_before_self_grade': delay_before_self_grade
                }
                print(json.dumps(result, indent=2))
                sys.exit(0)
        else:
            if not Path(params.self_grade_timestamp_dir).is_dir():
                Path(params.self_grade_timestamp_dir).mkdir(parents=True, exist_ok=True)
        try:
            Path(ts_file).touch()
        except PermissionError:
            # Stale file/dir owned by root (e.g. leftover from an earlier
            # privileged-lab run where the touch happened with euid=0). For
            # privileged labs saved-uid is still 0 here, so we can briefly
            # raise euid to repair ownership of both the dir and the file.
            gain_privileges()
            try:
                os.chown(params.self_grade_timestamp_dir,
                         params.sre_uid, params.docker_gid)
                try:
                    os.unlink(ts_file)
                except FileNotFoundError:
                    pass
            finally:
                drop_privileges_temporarily()
            Path(ts_file).touch()
    delay_before_self_grade = delay_between_self_grade

    lock_path = Path(params.private_lab_dir(net_scheme.running_lab_name)) / params.eval_in_progress_name
    lock_fd = _acquire_eval_lock(lock_path)
    try:
        log_path = Path(params.auto_eval_log_filename(net_scheme.running_lab_name))
        auto_eval_count = _read_auto_eval_count(log_path)

        grade = module_rvlab.Grade(net_scheme=net_scheme)
        grade._default_language = getattr(module_rvlab, 'default_language', 'en')
        grade.archive_dirs = dedup_preserve_order(
            list(params.archive_dirs) + list(getattr(module_rvlab, 'archive_dirs', [])))
        grade.files_to_save_in_archives = getattr(module_rvlab, 'files_to_save_in_archives', [])
        grade._use_numerical_marks = getattr(module_rvlab, 'use_numerical_marks', params.use_numerical_marks_by_default)
        grade._display_marks_in_auto_evaluations = getattr(module_rvlab, 'display_marks_in_auto_evaluations', params.display_marks_in_auto_evaluations_by_default)
        grade._maximum_mark = getattr(module_rvlab, 'maximum_mark', params.default_maximum_mark)
        grade.auto_eval_count = auto_eval_count
        gain_privileges_if_needed(net_scheme=net_scheme)
        grade.run_tests()
        if not multiples_evals:
            drop_privileges_permanently_if_not_needed(net_scheme)
        # Always lower effective uid to sre before writing archives so
        # files are owned by sre even when the lab has privileged machines
        # (gain_privileges_if_needed raised euid to 0 for run_tests, and
        # drop_privileges_permanently_if_not_needed is a NOP for privileged labs).
        drop_privileges_temporarily()
        if SRE.args.user and auto_eval:
            _append_auto_eval_timestamp(log_path)
        grade._answers[params.auto_eval_count_keyword] = grade.auto_eval_count
        grade.save_tests()
        try:
            no_grade = SRE.args.user and module_rvlab.no_mark_on_self_grade
        except AttributeError:
            no_grade = False

        hide_potential_penalties = SRE.args.user and getattr(module_rvlab, 'hide_potential_penalty_grades_in_self_grade', False)

        if debug_project:
            no_grade = False
            hide_potential_penalties = False

        scope_bit = params.SELF_EVAL_SCOPE if auto_eval else params.EXO_EVAL_SCOPE
        response_mark = grade._mark_self_eval if auto_eval else grade._mark_exo_eval

        if debug_project:
            grade_list = list(grade.get_grade_list())
        else:
            grade_list = [e for e in grade.get_grade_list() if e.scope & scope_bit]
        if hide_potential_penalties:
            grade_list = [e for e in grade_list if not (e.grade == 0 and e.max_grade == 0)]

        if no_grade:
            grades = [asdict(e.to_grade_letter()) for e in grade_list]
        else:
            grades = [asdict(e) for e in grade_list]

        answers = grade.get_answers()

        show_mark = debug_project or not SRE.args.user or grade._display_marks_in_auto_evaluations
        result = {
            params.running_lab_name_keyword: running_lab_name,
            params.eval_date_keyword: datetime.datetime.now().isoformat(),
            params.login_keyword: answers.get(params.login_keyword, ""),
            params.hostname_keyword: answers.get(params.hostname_keyword, ""),
            'grades': grades,
            'grade_parts': [asdict(p) for p in grade.get_grade_parts()],
            'mark': (None if no_grade else response_mark) if show_mark else None,
            'maximum_mark': grade._maximum_mark if show_mark else None,
            'delay_before_self_grade': delay_before_self_grade
        }
        if print_result and (not SRE.args.user or auto_eval):
            print(json.dumps(result, indent=2))
    finally:
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)
