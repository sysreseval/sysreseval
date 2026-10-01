import os
from pathlib import Path
import multiprocessing
import subprocess
from Kathara.manager.Kathara import Kathara

from . import params
from .utils import error_quit, remove_tree, cannot_remove_message
from .utils_privileges import gain_privileges, drop_privileges_permanently

_KATHARA_WIPE_TIMEOUT = 30  # seconds

#: Entries of `params.sre_user_public_dir` that are never SRE's to remove (the directory may be
#: a filesystem of its own).
_KEEP_IN_USER_PUBLIC_DIR = frozenset({'lost+found'})


def _docker_wipe():
    r = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=kathara_"],
        capture_output=True, text=True, timeout=10,
    )
    ids = r.stdout.split()
    if ids:
        subprocess.run(["docker", "rm", "-f"] + ids, capture_output=True, timeout=60)

    subprocess.run(["docker", "network", "prune", "-f"], capture_output=True, timeout=60)


def _kathara_wipe_worker():
    try:
        Kathara.get_instance().wipe(all_users=True)
    except Exception:
        raise SystemExit(1)


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


def wipe():
    """Undeploy every container, then remove every project dir and every user public dir while
    still root: the containers run as host root and leave root-owned files in `shared/` and the
    volume dirs that the sre user cannot delete.  Privileges are dropped permanently afterwards,
    before the entries left behind (if any) are reported."""
    errors: list[str] = []
    gain_privileges()
    try:
        proc = multiprocessing.Process(target=_kathara_wipe_worker)
        proc.start()
        proc.join(timeout=_KATHARA_WIPE_TIMEOUT)
        if proc.is_alive():
            proc.kill()
            proc.join()
            _docker_wipe()
        elif proc.exitcode != 0:
            # sometimes with privileged containers an error occurs
            _docker_wipe()
        _remove_entries(Path(params.sre_projects_dir), errors)
        _remove_entries(Path(params.sre_user_public_dir), errors, keep=_KEEP_IN_USER_PUBLIC_DIR)
    finally:
        drop_privileges_permanently()
    if errors:
        error_quit(cannot_remove_message(errors))
