import os
from pathlib import Path
import multiprocessing

from . import params
from .engine import get_engine
from .utils import error_quit, remove_tree, cannot_remove_message
from .utils_privileges import gain_privileges, drop_privileges_permanently

_KATHARA_WIPE_TIMEOUT = 30  # seconds

#: Entries of `params.sre_user_public_dir` that are never SRE's to remove (the directory may be
#: a filesystem of its own).
_KEEP_IN_USER_PUBLIC_DIR = frozenset({'lost+found'})


def _docker_wipe():
    get_engine().force_wipe()


def _kathara_wipe_worker():
    try:
        get_engine().wipe_all()
    except Exception:
        raise SystemExit(1)


def remove_lab_leftovers(lab_hash: str, errors: list[str]) -> list[str]:
    """Force-remove the containers, then the networks, still carrying *lab_hash*, whatever their
    `user` label, and return their names: the last resort for what the undeploy could not see
    (the engine's `remove_leftovers()` says why some are left).  Each object that cannot be
    removed is appended to *errors*; one already gone is simply skipped."""
    return get_engine().remove_leftovers(lab_hash, errors)


def _remove_entries(base: Path, errors: list[str], keep: frozenset = frozenset()) -> None:
    """Remove every entry of *base* (`rmtree` for directories, `unlink` otherwise) and go on
    after a failure: each entry that cannot be removed is appended to *errors*.  The names in
    *keep* and the mount points are left alone: as root, `rmtree` would otherwise empty a
    mounted filesystem."""
    if not base.is_dir():
        return
    for entry in base.iterdir():
        if entry.name in keep:
            continue
        try:
            if entry.is_dir() and not entry.is_symlink():
                if os.path.ismount(entry):
                    continue
                remove_tree(entry, errors)
            else:
                entry.unlink()
        except OSError as e:
            errors.append(f"{entry}: {e}")


def _forced_wipe() -> str:
    """The last resort of the engine when its own wipe hung or failed; what went wrong, `''`
    when nothing did."""
    try:
        _docker_wipe()
    except Exception as e:
        return str(e) or type(e).__name__
    return ''


def wipe():
    """Undeploy every container, then remove every project dir and every user public dir while
    still root: the containers run as host root and leave root-owned files in `shared/` and the
    volume dirs that the sre user cannot delete.  Privileges are dropped permanently afterwards,
    before the entries left behind (if any) are reported.

    An engine that cannot even force its wipe (at a shutdown, what it needs may be gone
    already) does not keep the directories from being removed: a host must not come back with
    the projects of the day before.  It is reported at the end, with exit status 1."""
    errors: list[str] = []
    engine_error = ''
    gain_privileges()
    try:
        proc = multiprocessing.Process(target=_kathara_wipe_worker)
        proc.start()
        proc.join(timeout=_KATHARA_WIPE_TIMEOUT)
        if proc.is_alive():
            proc.kill()
            proc.join()
            engine_error = _forced_wipe()
        elif proc.exitcode != 0:
            # sometimes with privileged containers an error occurs
            engine_error = _forced_wipe()
        _remove_entries(Path(params.sre_projects_dir), errors)
        _remove_entries(Path(params.sre_user_public_dir), errors, keep=_KEEP_IN_USER_PUBLIC_DIR)
    finally:
        drop_privileges_permanently()
    messages = [f"the machines of the projects may still run: {engine_error}"] if engine_error else []
    if errors:
        messages.append(cannot_remove_message(errors))
    if messages:
        error_quit("\n".join(messages))
