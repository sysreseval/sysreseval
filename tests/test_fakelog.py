"""Tests for fakelog."""
import datetime
import re
from dataclasses import dataclass

import pytest

from SRE.lib_sre import Data0, NetScheme0, _FileOp
from fakelog import fakelog, fakelog_content, _SERVERS


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


RUNNING_LAB = '20260101000000@@@test/test1@@@user'
START = datetime.datetime(2026, 7, 1, 0, 0, 0)
END = datetime.datetime(2026, 7, 2, 0, 0, 0)


class BareScheme(NetScheme0):
    _machine_specs = {'host': {}}

    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)


def _make_bare():
    return BareScheme(MockData())


def _ops(scheme, machine, step=1):
    return scheme._ops.get(step, {}).get(machine, [])


def _file_ops(scheme, machine, step=1):
    return [op for op in _ops(scheme, machine, step) if isinstance(op, _FileOp)]


def _cmd_ops(scheme, machine, step=1):
    return [op for op in _ops(scheme, machine, step) if isinstance(op, str)]


# Log timestamps always use English month abbreviations (never strptime's
# locale-dependent %b, which breaks under a non-English LC_TIME).
_MONTH_NUM = {m: i + 1 for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}


def _parse_apache_ts(s):
    """Parse an Apache CLF timestamp like ``01/Jul/2026:13:55:36`` (locale-free)."""
    date_part, hh, mm, ss = s.split(':')
    day, mon, year = date_part.split('/')
    return datetime.datetime(int(year), _MONTH_NUM[mon], int(day),
                             int(hh), int(mm), int(ss))


# Regexes matching one line of each format (anchored, no trailing newline).
_SYSLOG_TS = r'[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2}'
_LINE_RE = {
    'apache2': re.compile(
        r'^\d+\.\d+\.\d+\.\d+ - - \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+0000\] '
        r'"(GET|POST|HEAD) \S+ HTTP/1\.1" \d{3} \d+ "-" ".+"$'),
    'auth': re.compile(rf'^{_SYSLOG_TS} host sshd\[\d+\]: .+$'),
    'ldap': re.compile(rf'^{_SYSLOG_TS} host slapd\[\d+\]: conn=\d+ op=\d+ .+$'),
    'syslog': re.compile(rf'^{_SYSLOG_TS} host \S+: .+$'),
    'mail': re.compile(rf'^{_SYSLOG_TS} host postfix/\S+\[\d+\]: .+$'),
}


class TestFakelogContent:
    @pytest.mark.parametrize('server', ['apache2', 'auth', 'ldap', 'syslog', 'mail'])
    def test_line_count(self, server):
        txt, _ = fakelog_content(250, START, END, server=server, seed=1)
        assert txt.endswith('\n')
        assert len(txt.splitlines()) == 250

    def test_count_zero_is_empty(self):
        txt, stats = fakelog_content(0, START, END, server='syslog', seed=1)
        assert txt == ''
        assert stats['count'] == 0

    @pytest.mark.parametrize('server', ['apache2', 'auth', 'ldap', 'syslog', 'mail'])
    def test_line_format(self, server):
        txt, _ = fakelog_content(200, START, END, server=server, hostname='host', seed=3)
        rx = _LINE_RE[server]
        for line in txt.splitlines():
            assert rx.match(line), f'{server}: bad line: {line!r}'

    def test_timestamps_within_window_and_sorted(self):
        # Apache timestamps are unambiguous (full date) — easiest to parse back.
        txt, _ = fakelog_content(500, START, END, server='apache2', seed=7)
        stamps = [re.search(r'\[(.+?) \+0000\]', l).group(1) for l in txt.splitlines()]
        dts = [_parse_apache_ts(s) for s in stamps]
        assert dts == sorted(dts)
        assert all(START <= dt <= END for dt in dts)

    def test_deterministic_with_seed(self):
        a, sa = fakelog_content(300, START, END, server='auth', seed=42)
        b, sb = fakelog_content(300, START, END, server='auth', seed=42)
        assert a == b
        assert sa == sb

    def test_different_seed_differs(self):
        a, _ = fakelog_content(300, START, END, server='auth', seed=1)
        b, _ = fakelog_content(300, START, END, server='auth', seed=2)
        assert a != b

    def test_web_stats_consistent(self):
        _, stats = fakelog_content(400, START, END, server='apache2', seed=5)
        assert sum(stats['status_counts'].values()) == 400
        assert sum(stats['method_counts'].values()) == 400
        assert stats['top_ip'] in stats['ip_counts']

    def test_auth_stats_consistent(self):
        _, stats = fakelog_content(400, START, END, server='auth', seed=5)
        total = stats.get('accepted', 0) + stats.get('failed', 0) + stats.get('invalid', 0)
        assert total == 400

    def test_stats_metadata(self):
        _, stats = fakelog_content(10, START, END, server='ldap', seed=1)
        assert stats['count'] == 10
        assert stats['server'] == 'ldap'
        assert stats['start'] == START.isoformat()
        assert stats['end'] == END.isoformat()

    def test_unknown_server_raises(self):
        with pytest.raises(ValueError):
            fakelog_content(5, START, END, server='nope')

    def test_start_after_end_raises(self):
        with pytest.raises(ValueError):
            fakelog_content(5, END, START, server='syslog')


class TestFakelogWrite:
    def test_writes_file_op_default_path(self):
        s = _make_bare()
        fakelog(s, 'host', count=20, server='apache2', start=START, end=END, seed=1)
        fops = _file_ops(s, 'host')
        assert any(op.filename == '/var/log/apache2/access.log' for op in fops)

    def test_permissions_owner_and_mtime(self):
        s = _make_bare()
        fakelog(s, 'host', count=20, server='syslog', start=START, end=END, seed=1)
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/var/log/syslog')
        assert fop.permissions == 0o640
        assert fop.owner == 'root:adm'
        assert fop.mtime == END.timestamp()
        assert len(fop.content.splitlines()) == 20

    def test_mkdir_registered_before_file(self):
        s = _make_bare()
        fakelog(s, 'host', count=5, server='apache2', start=START, end=END, seed=1)
        ops = _ops(s, 'host')
        mkdir_idx = next(i for i, op in enumerate(ops)
                         if isinstance(op, str) and op.startswith('mkdir -p'))
        file_idx = next(i for i, op in enumerate(ops)
                        if isinstance(op, _FileOp) and op.filename == '/var/log/apache2/access.log')
        assert mkdir_idx < file_idx
        assert '/var/log/apache2' in _cmd_ops(s, 'host')[0]

    def test_no_mkdir_for_root_level_file(self):
        s = _make_bare()
        fakelog(s, 'host', count=5, file='/messages', server='syslog', start=START, end=END, seed=1)
        assert _cmd_ops(s, 'host') == []

    def test_file_override(self):
        s = _make_bare()
        fakelog(s, 'host', count=5, file='/tmp/custom.log', server='auth', start=START, end=END, seed=1)
        assert any(op.filename == '/tmp/custom.log' for op in _file_ops(s, 'host'))

    def test_hostname_defaults_to_machine(self):
        s = _make_bare()
        fakelog(s, 'host', count=5, server='auth', start=START, end=END, seed=1)
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/var/log/auth.log')
        assert b' host sshd[' in fop.content

    def test_returns_stats_with_file_and_machine(self):
        s = _make_bare()
        stats = fakelog(s, 'host', count=5, server='ldap', start=START, end=END, seed=1)
        assert stats['file'] == '/var/log/slapd.log'
        assert stats['machine'] == 'host'
        assert stats['count'] == 5


def test_all_servers_have_absolute_default_paths():
    for gen, path in _SERVERS.values():
        assert path.startswith('/')
