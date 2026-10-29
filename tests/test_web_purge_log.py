"""Tests of scripts/web-purge-log.py: the rotated files and the rows of the connection log older
than N days (the files in a temporary directory, the database on the fake server of
test_web_accessdb.py, the command line through a subprocess)."""
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.config import AccessDatabaseConfig  # noqa: E402
from sreweb.portal.accessdb import utc_datetime  # noqa: E402
from test_web_accessdb import FakeServer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'web-purge-log.py'
DAY = 86400


def load_script():
    spec = importlib.util.spec_from_file_location('web_purge_log', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules['web_purge_log'] = module
    spec.loader.exec_module(module)
    return module


def touch(path: Path, age_days: float, now: float):
    path.write_text('x')
    os.utime(path, (now - age_days * DAY, now - age_days * DAY))


class TestFiles:
    def test_rotated_files_older_than_the_cutoff(self, tmp_path):
        purge = load_script()
        now = time.time()
        log = tmp_path / 'access.log'
        touch(log, 400, now)                                   # the current file: never touched, whatever its age
        touch(tmp_path / 'access.log.2025-09-01', 400, now)    # the portal's rotation
        touch(tmp_path / 'access.log.1.gz', 370, now)          # logrotate's
        touch(tmp_path / 'access.log.2026-10-28', 1, now)
        touch(tmp_path / 'other.log.2025-09-01', 400, now)     # another log
        assert [p.name for p in purge.rotated_files(str(log))] == ['access.log.1.gz', 'access.log.2025-09-01',
                                                                  'access.log.2026-10-28']
        planned = purge.purge_files(str(log), now - 365 * DAY, dry_run=True)
        assert [p.name for p in planned] == ['access.log.1.gz', 'access.log.2025-09-01']
        assert len(list(tmp_path.iterdir())) == 5
        removed = purge.purge_files(str(log), now - 365 * DAY)
        assert [p.name for p in removed] == ['access.log.1.gz', 'access.log.2025-09-01']
        assert sorted(p.name for p in tmp_path.iterdir()) == ['access.log', 'access.log.2026-10-28', 'other.log.2025-09-01']
        assert purge.purge_files(str(log), now - 365 * DAY) == []


class TestDatabase:
    @staticmethod
    def cfg() -> AccessDatabaseConfig:
        return AccessDatabaseConfig(host='db.example.org', user='sre_web', password='pw', name='sre', table='web_log')

    def test_count_then_batches(self):
        purge = load_script()
        server = FakeServer(table_exists=True)
        server.select_names, server.select_rows = ['n'], [(10005,)]
        server.purge_counts = [purge.BATCH, 5]
        cutoff = 1_700_000_000.0
        assert purge.purge_database(self.cfg(), cutoff, connect=server.connect) == 10005
        kinds = [(sql.split()[0], args) for kind, sql, args in server.statements]
        before = utc_datetime(cutoff)
        assert kinds == [('SELECT', (before,)), ('DELETE', (before,)), ('DELETE', (before,))]
        assert server.statements[0][1] == "SELECT COUNT(*) FROM `web_log` WHERE ts < %s"
        assert server.statements[1][1] == f"DELETE FROM `web_log` WHERE ts < %s LIMIT {purge.BATCH}"
        assert not server.statements_of('OPTIMIZE') and server.connections[-1].closed

    def test_dry_run_and_optimize(self):
        purge = load_script()
        server = FakeServer(table_exists=True)
        server.select_names, server.select_rows = ['n'], [(7,)]
        assert purge.purge_database(self.cfg(), 1000.0, dry_run=True, connect=server.connect) == 7
        assert not server.statements_of('DELETE') and server.connections[-1].closed
        server.purge_counts = [7]
        assert purge.purge_database(self.cfg(), 1000.0, optimize=True, connect=server.connect) == 7
        assert [s[1] for s in server.statements_of('OPTIMIZE')] == ["OPTIMIZE TABLE `web_log`"]
        assert len(server.statements_of('DELETE')) == 1

    def test_errors_propagate(self):
        purge = load_script()
        server = FakeServer(table_exists=True)
        server.down = True
        with pytest.raises(Exception, match="Can't connect"):
            purge.purge_database(self.cfg(), 1000.0, connect=server.connect)


class TestCommandLine:
    @staticmethod
    def run(*args, timeout=60) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=timeout)

    def test_files_from_a_configuration(self, tmp_path):
        now = time.time()
        log = tmp_path / 'logs' / 'access.log'
        log.parent.mkdir()
        touch(log, 10, now)
        touch(tmp_path / 'logs' / 'access.log.2026-09-01', 40, now)
        touch(tmp_path / 'logs' / 'access.log.2026-10-28', 1, now)
        toml = tmp_path / 'web.toml'
        toml.write_text(f'secret = "{"s" * 32}"\n[access_log]\nfile = "{log}"\n'
                        f'[[hosts]]\nname = "a01"\nurl = "http://127.0.0.1:9"\ntoken = "{"t" * 32}"\n')
        dry = self.run('--config', str(toml), '--days', '30', '--dry-run')
        assert dry.returncode == 0, dry.stderr
        assert 'would remove 1 rotated file(s)' in dry.stdout and 'access.log.2026-09-01' in dry.stdout
        assert (tmp_path / 'logs' / 'access.log.2026-09-01').exists()
        done = self.run('--config', str(toml), '--days', '30')
        assert done.returncode == 0 and 'removed 1 rotated file(s)' in done.stdout
        assert sorted(p.name for p in (tmp_path / 'logs').iterdir()) == ['access.log', 'access.log.2026-10-28']
        again = self.run('--config', str(toml))                      # 365 days by default: nothing older
        assert again.returncode == 0 and 'removed 0 rotated file(s)' in again.stdout and '365 days' in again.stdout
        nothing = self.run('--config', str(toml), '--database-only')
        assert nothing.returncode == 0 and 'nothing to purge' in nothing.stdout

    def test_usage_and_configuration_errors(self, tmp_path):
        assert self.run('--config', str(tmp_path / 'missing.toml')).returncode == 2
        bad = self.run('--config', str(tmp_path / 'missing.toml'), '--days', '0')
        assert bad.returncode == 2 and '--days' in bad.stderr
        both = self.run('--files-only', '--database-only')
        assert both.returncode == 2 and 'exclude' in both.stderr
        assert 'web-purge-log' in self.run('--help').stdout
