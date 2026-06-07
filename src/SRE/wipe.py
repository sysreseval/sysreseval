
from pathlib import Path
import multiprocessing
import shutil
import subprocess
from Kathara.manager.Kathara import Kathara

from . import params
from .utils_privileges import gain_privileges, drop_privileges_permanently

_KATHARA_WIPE_TIMEOUT = 30  # seconds


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


def wipe():
    gain_privileges()
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
    drop_privileges_permanently()

    base = Path(params.sre_projects_dir)
    if base.exists():
        for entry in base.iterdir():
            if entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()
    base = Path(params.sre_user_public_dir)
    for entry in base.iterdir():
        try:
            if entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        except PermissionError:
            pass
