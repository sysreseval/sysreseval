import sys
import tarfile
from datetime import datetime
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import user_not_allowed, error_quit, set_lab_dir_and_import_module


_archive_suffix = "__records.tar.gz"


def _archive_pattern(running_lab_name: str) -> str:
    return f"__{running_lab_name}{_archive_suffix}"


def save_records_for_project(running_lab_name, dest_dirs, only_last_record=True, ts=None,
                              strict=False) -> bool:
    """Archive the records/ dir of one running project into each of `dest_dirs`.

    With strict=False (default), per-dir failures (mkdir, write) are caught and
    logged so the remaining dirs are still attempted — this is what exam-mode
    auto-saving wants. With strict=True the first OSError raises, preserving
    the original `sre save-records` CLI behavior.
    Returns True if at least one archive was written.
    """
    records_path = Path(params.records_dir(running_lab_name))
    if not records_path.is_dir():
        return False

    if ts is None:
        ts = params.datetime_to_string(datetime.now())

    archive_basename = f"{ts}__{running_lab_name}{_archive_suffix}"
    written_any = False

    for dest in dest_dirs:
        dest_dir = Path(dest)
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            if strict:
                raise
            print(f"warning: cannot create directory {dest_dir}: {e.strerror}", file=sys.stderr)
            continue

        archive_path = dest_dir / archive_basename
        try:
            with tarfile.open(archive_path, 'w:gz') as tar:
                tar.add(records_path, arcname=params.records_dir_name)
        except OSError as e:
            if strict:
                raise
            print(f"warning: cannot write {archive_path}: {e.strerror}", file=sys.stderr)
            continue

        written_any = True

        if only_last_record:
            suffix = _archive_pattern(running_lab_name)
            try:
                for old in dest_dir.iterdir():
                    if old.name.endswith(suffix) and old != archive_path:
                        old.unlink(missing_ok=True)
            except OSError as e:
                if strict:
                    raise
                print(f"warning: cannot prune old archives in {dest_dir}: {e.strerror}", file=sys.stderr)

    return written_any


def _latest_archive_age_seconds(running_lab_name, dest_dirs) -> float | None:
    """Return the age (seconds) of the most recent archive for `running_lab_name`
    across all `dest_dirs`, or None if none exist. Filenames whose timestamp
    prefix can't be parsed are skipped."""
    suffix = _archive_pattern(running_lab_name)
    most_recent = None
    for dest in dest_dirs:
        dest_dir = Path(dest)
        if not dest_dir.is_dir():
            continue
        try:
            entries = list(dest_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.name.endswith(suffix):
                continue
            ts_str = entry.name.split('__', 1)[0]
            if len(ts_str) != 14 or not ts_str.isdigit():
                continue
            try:
                dt = params.string_to_datetime(ts_str)
            except ValueError:
                continue
            if most_recent is None or dt > most_recent:
                most_recent = dt
    if most_recent is None:
        return None
    return (datetime.now() - most_recent).total_seconds()


def _dedup_preserve_order(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def save_exam_records_for_project(running_lab_name, force=False) -> None:
    """Archive a running exam project's records into params.archive_dirs +
    the project's own archive_dirs, throttled by save_record_interval_during_exams.
    Setting the interval to 0 disables archiving (even when force=True).
    Failures are caught and logged so they never abort the surrounding exam loop.
    """
    try:
        module, _lab_name, _running, _src = set_lab_dir_and_import_module(
            running_lab_name=running_lab_name)

        interval = getattr(module, 'save_record_interval_during_exams',
                           params.default_save_record_interval_during_exams)
        if interval == 0:
            return

        dest_dirs = _dedup_preserve_order(
            list(params.archive_dirs) + list(getattr(module, 'archive_dirs', [])))
        if not dest_dirs:
            return

        if not force:
            age = _latest_archive_age_seconds(running_lab_name, dest_dirs)
            if age is not None and age < interval:
                return

        save_records_for_project(running_lab_name, dest_dirs, only_last_record=True)
    except Exception as e:
        print(f"warning: failed to save records for {running_lab_name}: {e}", file=sys.stderr)


def action_save_records():
    user_not_allowed()
    dest_dir = Path(SRE.args.directory)
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        error_quit(f"cannot create directory {dest_dir}: {e.strerror}")

    projects_dir = Path(params.sre_projects_dir)
    if not projects_dir.exists():
        return

    running_lab_names = [
        d.name
        for d in sorted(projects_dir.iterdir())
        if d.is_dir() and '@@@' in d.name and (d / params.info_json_name).exists()
    ]

    ts = params.datetime_to_string(datetime.now())

    for running_lab_name in running_lab_names:
        try:
            save_records_for_project(
                running_lab_name,
                [str(dest_dir)],
                only_last_record=SRE.args.only_last_record,
                ts=ts,
                strict=True,
            )
        except OSError as e:
            error_quit(f"cannot write archive for {running_lab_name}: {e.strerror}")
