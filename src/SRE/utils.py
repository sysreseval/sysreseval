import importlib
import json
import os
import sys
import re
import logging
from datetime import datetime, timedelta
from pathlib import Path

from .params import SRE
from . import params


def error_quit(error):
    print(f"sre: {error}", file=sys.stderr)
    sys.exit(1)


def log_error(error):
    if not SRE.args.user:
        print(f"{error}", file=sys.stderr)


#    logger = logging.getLogger(__name__)
#    logger.error(error)

def log_debug(message):
    if not SRE.args.user:
        print(f"{message}", file=sys.stderr)


def dedup_preserve_order(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def user_not_allowed():
    if in_user_mode():
        error_quit("you're not allowed to run this command")

def in_user_mode():
    return hasattr(SRE.args, "user") and SRE.args.user

def exam_mode_is_on():
    exam_path = Path(params.sre_pub_dir) / params.exam_json_name
    return exam_path.exists()


def exam_remaining_seconds(exam_data: dict, now: datetime | None = None) -> int | None:
    """Return remaining exam seconds from an exam.json-shaped dict, or None
    if inputs are missing or invalid. Reference time is `started_at` if
    present, else `start_after`. Result is clamped by `end_before` if set."""
    if not isinstance(exam_data, dict):
        return None
    try:
        duration = int(exam_data[params.exam_duration])
    except (KeyError, ValueError, TypeError):
        return None
    ref_str = exam_data.get(params.exam_started_at) or exam_data.get(params.exam_start_after)
    if ref_str is None:
        return None
    try:
        ref_time = datetime.fromisoformat(ref_str)
        if ref_time.tzinfo is not None:
            ref_time = ref_time.astimezone().replace(tzinfo=None)
    except (ValueError, TypeError):
        return None
    end_time = ref_time + timedelta(minutes=duration)
    if params.exam_end_before in exam_data:
        try:
            end_before = datetime.fromisoformat(exam_data[params.exam_end_before])
            if end_before.tzinfo is not None:
                end_before = end_before.astimezone().replace(tzinfo=None)
            if end_before < end_time:
                end_time = end_before
        except (ValueError, TypeError):
            pass
    if now is None:
        now = datetime.now()
    return max(0, int((end_time - now).total_seconds()))


def should_record_sessions(module_rvlab):
    """Return whether sessions should be recorded.
    In exam mode, uses exam.json's record_sessions field exclusively.
    Outside exam mode, falls back to the srelab module attribute."""
    exam_path = Path(params.sre_pub_dir) / params.exam_json_name
    if exam_path.exists():
        try:
            import json
            data = json.loads(exam_path.read_text())
            return bool(data.get(params.exam_record_sessions, False))
        except Exception:
            return False
    return getattr(module_rvlab, 'record_sessions', False)


def user_not_allowed_in_exam_mode():
    if hasattr(SRE.args, "user") and SRE.args.user:
        if exam_mode_is_on():
            error_quit("you're not allowed to run this command in exam mode")


#
# return module, lab_name, running_lab_name, current_srelab_file
#
def set_lab_dir_and_import_module(start_projet=False, lab_cli_arg=None, path=None, running_lab_name=None):
    if start_projet:
        if (lab_cli_arg is None and path is None) or (lab_cli_arg is not None and path is not None) or (
                running_lab_name is not None):
            error_quit("Inernal error: either lab or path should be specified, running_lab_name should not")
        if path is not None:
            if os.path.isdir(path):
                current_srelab_file = f"{os.path.abspath(path)}/{params.srelab_py_name}"
            else:
                current_srelab_file = os.path.abspath(path)
                if not current_srelab_file.endswith('.py'):
                    error_quit(f"'{current_srelab_file}' don't end with .py")
            lab_name = params.get_lab_name_from_cli_arg(path, is_path=True)
            if not os.path.isfile(current_srelab_file):
                error_quit(f"the file '{current_srelab_file}' does not exist")
        else:
            # we use lab_name
            lab_list = get_lab_list(include_exam_only_labs=True)
            if lab_cli_arg not in lab_list:
                error_quit(f"lab '{SRE.args.lab}' does not exist")
            lab_name = params.get_lab_name_from_cli_arg(lab_cli_arg, is_path=False)
            if os.path.isdir(f'{params.lab_dir}/{lab_cli_arg}'):
                current_srelab_file = f'{params.lab_dir}/{lab_cli_arg}/{params.srelab_py_name}'
            else:
                current_srelab_file = f'{params.lab_dir}/{lab_cli_arg}'
    else:
        if lab_cli_arg is not None or path is not None:
            error_quit("Internal error: lab_name or path should not be specified")
        if running_lab_name is None:
            if not hasattr(SRE.args, 'running_lab'):
                error_quit(f"running_lab parameter missing")
            running_lab_name = SRE.args.running_lab
        lab_name = params.get_lab_name_from_running_lab_name(running_lab_name)
        current_srelab_file = Path(params.srelab_link_filename(running_lab_name)).resolve()

    if not os.path.isfile(current_srelab_file):
        error_quit(f"The project does not exist")
    if not any(Path(d) in Path(current_srelab_file).parents for d in params.authorized_src_dir):
        error_quit(f"'{current_srelab_file}' not allowed")

    module = None
    try:
        lib_path = Path(params.lib_dir).resolve()
        sys.path.insert(0, str(lib_path))
        importlib.invalidate_caches()

        spec = importlib.util.spec_from_file_location(params.srelab_py_name.removesuffix(".py"), current_srelab_file)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except ImportError as e:
        missing = getattr(e, "name", None)
        lib_listing = sorted(os.listdir(params.lib_dir))[:20] if os.path.isdir(params.lib_dir) else None
        target_in_lib = None
        if missing:
            cand = os.path.join(params.lib_dir, f"{missing}.py")
            if os.path.exists(cand):
                target_in_lib = (
                    f"{cand} exists "
                    f"(readable: {os.access(cand, os.R_OK)}, "
                    f"size: {os.path.getsize(cand)})"
                )
        error_quit(
            f"failed to import '{current_srelab_file}': {e}\n"
            f"       missing module = {missing!r}\n"
            f"       params.lib_dir = {params.lib_dir!r} (exists: {os.path.isdir(params.lib_dir)})\n"
            f"       lib listing    = {lib_listing}\n"
            f"       {missing}.py in lib = {target_in_lib}\n"
            f"       process uid/gid = {os.getuid()}/{os.getgid()} (effective {os.geteuid()}/{os.getegid()})\n"
            f"       sys.path       = {sys.path}"
        )
    return module, lab_name, running_lab_name, current_srelab_file


def _is_exam_only(name):
    return any(affix in name for affix in params.exam_only_affix)


def _iter_labs(lab_dir, *, include_exam_only_labs, recursive=True):
    """Yield ``(parent_dir_abs, lab_local_name)`` pairs for every lab under *lab_dir*.

    ``lab_local_name`` is the basename used as the key in that directory's
    ``titles.json``: ``"<name>.py"`` for a file lab, ``"<dirname>"`` for a
    directory lab containing ``srelab.py``. When *recursive* is False, only
    the immediate contents of *lab_dir* are scanned.
    """
    lab_dir_abs = os.path.abspath(lab_dir)

    if recursive:
        for dirpath, dirnames, filenames in os.walk(lab_dir_abs):
            if not include_exam_only_labs:
                dirnames[:] = [d for d in dirnames if not _is_exam_only(d)]

            # Directory containing srelab.py is itself a lab; stop recursion.
            if dirpath != lab_dir_abs and params.srelab_py_name in filenames:
                dirnames[:] = []
                yield os.path.dirname(dirpath), os.path.basename(dirpath)
                continue

            for fname in filenames:
                if fname.endswith('.py') and fname != params.srelab_py_name:
                    if include_exam_only_labs or not _is_exam_only(fname):
                        yield dirpath, fname
        return

    try:
        entries = sorted(os.listdir(lab_dir_abs))
    except OSError:
        return
    for name in entries:
        if not include_exam_only_labs and _is_exam_only(name):
            continue
        full_path = os.path.join(lab_dir_abs, name)
        if os.path.isdir(full_path):
            if os.path.isfile(os.path.join(full_path, params.srelab_py_name)):
                yield lab_dir_abs, name
        elif name.endswith('.py') and name != params.srelab_py_name:
            yield lab_dir_abs, name


def get_lab_list(include_exam_only_labs=False):
    lab_dir_abs = os.path.abspath(params.lab_dir)
    result = []
    for parent_dir_abs, lab_local_name in _iter_labs(
        params.lab_dir, include_exam_only_labs=include_exam_only_labs
    ):
        full_path = os.path.join(parent_dir_abs, lab_local_name)
        result.append(os.path.relpath(full_path, lab_dir_abs))
    return sorted(result)


_titles_cache: dict = {}


def load_titles(parent_dir_abs: str) -> dict:
    """Read ``parent_dir_abs/titles.json`` (cached). Returns ``{}`` on any error."""
    if parent_dir_abs in _titles_cache:
        return _titles_cache[parent_dir_abs]
    path = os.path.join(parent_dir_abs, params.titles_file_name)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except (OSError, json.JSONDecodeError):
        data = {}
    _titles_cache[parent_dir_abs] = data
    return data


def get_lab_list_with_titles(include_exam_only_labs=False):
    """Walk the lab directory and return ``[{"name": rel_path, "title": dict|None}, ...]``.

    The filesystem walk is the source of truth: stale entries in ``titles.json``
    that do not have a matching lab file/dir on disk are silently ignored.
    """
    lab_dir_abs = os.path.abspath(params.lab_dir)
    result = []
    for parent_dir_abs, lab_local_name in _iter_labs(
        params.lab_dir, include_exam_only_labs=include_exam_only_labs
    ):
        titles = load_titles(parent_dir_abs)
        title = titles.get(lab_local_name)
        if title is not None and not isinstance(title, (dict, str)):
            title = None
        full_path = os.path.join(parent_dir_abs, lab_local_name)
        result.append({
            "name": os.path.relpath(full_path, lab_dir_abs),
            "title": title,
        })
    result.sort(key=lambda e: e["name"])
    return result


def resolve_running_lab_name(partial: str) -> str:
    """Resolve a partial running-lab-name to a full one.

    If `partial` exactly matches a running lab, return it as-is.
    Otherwise return the unique running lab whose name contains `partial`.
    Prints the list of candidates and exits if zero or more than one match.
    """
    try:
        entries = os.listdir(params.sre_projects_dir)
    except OSError:
        entries = []

    running_labs = sorted(
        e for e in entries if re.match(params.running_lab_name_match_pattern, e)
    )

    if partial in running_labs:
        return partial

    matches = [lab for lab in running_labs if partial in lab]

    if len(matches) == 1:
        return matches[0]

    if not matches:
        error_quit(f"no running lab matches '{partial}'")

    # Multiple matches — list them and exit
    print(f"Ambiguous name '{partial}', matching running labs:", file=sys.stderr)
    for m in matches:
        print(f"  {m}", file=sys.stderr)
    sys.exit(1)


def set_all_variables_for_action(running_lab_name):
    module_rvlab, lab_name, running_lab_name, current_srelab_file = set_lab_dir_and_import_module(
        running_lab_name=running_lab_name)
    data = module_rvlab.Data.load_from_json_file(params.data_filename(running_lab_name))
    net_scheme = module_rvlab.NetScheme(data=data, running_lab_name=running_lab_name)
    return module_rvlab, net_scheme


#
# Time arguments shared by `watch -S` and the -S/--start, -F/--finish options
# of `outline` and `sheet`
#
TIME_OR_DATETIME_FORMATS = ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M",
                            "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")
TIME_ONLY_FORMATS = ("%H:%M", "%H:%M:%S")


def parse_time_or_datetime(text: str, now: datetime | None = None) -> datetime | None:
    """Parse a user-supplied time; '' means "no bound" (None).

    Accepts a date-time ('2026-09-10 15:01', '2026-09-10T15:01', optional
    ':SS'), a date alone (midnight) or a time alone ('15:01', '15:01:30'),
    which means today at that time — even when that is later than *now*.
    Raises ValueError otherwise.  Mirrors set_exam._parse_date."""
    text = (text or '').strip()
    if not text:
        return None
    for fmt in TIME_OR_DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    today = (now or datetime.now()).date()
    for fmt in TIME_ONLY_FORMATS:
        try:
            return datetime.combine(today, datetime.strptime(text, fmt).time())
        except ValueError:
            pass
    raise ValueError(f"expected a time like 15:01 or a date-time like "
                     f"2026-09-10 15:01, got {text!r}")


def in_time_interval(dt: datetime, start: datetime | None, finish: datetime | None) -> bool:
    """True when *dt* lies in [start, finish]; a None bound is open."""
    return (start is None or dt >= start) and (finish is None or dt <= finish)


def format_instance_start(instance_start: str) -> str:
    """'YYYY-MM-DD HH:MM:SS' for the 14-digit start timestamp of a running
    project (see params.get_start_date_string_from_running_lab_name); '' when
    empty, the raw string when it is not a date."""
    if not instance_start:
        return ''
    try:
        return params.string_to_datetime(instance_start).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return instance_start


def archive_creation_time(path) -> datetime:
    """When an archive was created: the eval date encoded in its filename
    (see params.get_archive_name), else the file's mtime."""
    path = Path(path)
    return (params.get_date_from_archive_name(path.name)
            or datetime.fromtimestamp(path.stat().st_mtime))


def collect_archive_paths(files, recursive: bool,
                          start: datetime | None = None,
                          finish: datetime | None = None) -> list[Path]:
    """Archive paths named by *files*: a directory contributes its sorted
    '*.zst' entries (recursively with *recursive*), anything else is taken
    as an archive file.  With a bound, only archives whose creation time
    (see archive_creation_time) lies in [start, finish] are kept; a file that
    cannot be stat'ed is kept so that the reader reports it."""
    paths: list[Path] = []
    for arg in files:
        p = Path(arg)
        if p.is_dir():
            glob_fn = p.rglob if recursive else p.glob
            paths.extend(sorted(glob_fn('*.zst')))
        else:
            paths.append(p)
    if start is None and finish is None:
        return paths
    kept = []
    for p in paths:
        try:
            if not in_time_interval(archive_creation_time(p), start, finish):
                continue
        except OSError:
            pass
        kept.append(p)
    return kept


def parse_time_interval_args(start_text, finish_text) -> tuple[datetime | None, datetime | None]:
    """Parse the --start / --finish command-line values (None or '' = no
    bound); exits with a message on an invalid value or when start is after
    finish."""
    bounds = []
    for option, text in (('--start', start_text), ('--finish', finish_text)):
        try:
            bounds.append(parse_time_or_datetime(text or ''))
        except ValueError as exc:
            error_quit(f"invalid {option} value {text!r}: {exc}")
    start, finish = bounds
    if start is not None and finish is not None and start > finish:
        error_quit(f"--start {start:%Y-%m-%d %H:%M:%S} is after --finish {finish:%Y-%m-%d %H:%M:%S}")
    return start, finish
