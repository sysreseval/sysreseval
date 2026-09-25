"""Helpers for tests that need real .zst evaluation archives on disk."""
import os
from pathlib import Path

import msgpack
import zstandard as zstd

from SRE import params

LAB = 'lab@x.py'


def rln(start_ts='20260516100000', lab=LAB, user='etudiant') -> str:
    """Build a running_lab_name as params.get_running_lab_name does."""
    return f"{start_ts}@@@{lab}@@@{user}"


def archive_name(running_lab_name: str, eval_date: str) -> str:
    """Archive basename for an eval at *eval_date* (YYYYmmddHHMMSS)."""
    return params.get_archive_name(running_lab_name, params.string_to_datetime(eval_date))


def write_archive(path, *, hostname, login, running_lab_name,
                  eval_date='20260516120000', grade=10.0, max_grade=10.0,
                  errors=(), grade_list=(), mtime=None) -> str:
    """Write a real zstd+msgpack archive laid out like Grade0.save_tests_on_file.
    Returns the path as a string."""
    archive = {
        params.running_lab_name_keyword: running_lab_name,
        params.eval_date_keyword: eval_date,
        'answers': {params.hostname_keyword: hostname, params.login_keyword: login},
        'errors': list(errors),
        'grade_list': list(grade_list),
        'grade_parts': [],
        'total_grade_exo_eval': grade,
        'total_max_exo_eval': max_grade,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f:
        with zstd.ZstdCompressor().stream_writer(f) as compressor:
            compressor.write(msgpack.packb(archive, use_bin_type=True))
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return str(path)


# One student ('bob' on host 'hb') who opened LAB twice on 2026-09-10, at
# 10:00 and 11:00, two evaluations each; eval dates are ISO like real archives.
# Best grade overall: 9.0, in the second instance.
TWO_INSTANCES = [
    ('20260910100000', '2026-09-10T10:05:00', 3.0),
    ('20260910100000', '2026-09-10T10:20:00', 5.0),
    ('20260910110000', '2026-09-10T11:05:00', 4.0),
    ('20260910110000', '2026-09-10T11:20:00', 9.0),
]


def write_two_instances(root, *, lab=LAB, login='bob', hostname='hb') -> None:
    """Write the TWO_INSTANCES archives under *root*."""
    for start_ts, eval_iso, grade in TWO_INSTANCES:
        r = rln(start_ts=start_ts, lab=lab, user=login)
        compact = eval_iso.replace('-', '').replace(':', '').replace('T', '')
        write_archive(Path(root) / archive_name(r, compact), hostname=hostname, login=login,
                      running_lab_name=r, eval_date=eval_iso, grade=grade, max_grade=10.0)
