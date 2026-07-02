"""Tests for fakeauthlog."""
import datetime
import re
from dataclasses import dataclass

import pytest

from SRE.lib_sre import Data0, NetScheme0, _FileOp
from fakelog import fakeauthlog, fakeauthlog_content


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


# Syslog timestamps always use English month abbreviations (never strptime's
# locale-dependent %b, which breaks under a non-English LC_TIME).
_MONTH_NUM = {m: i + 1 for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}


def _parse_syslog_ts(line, year):
    """Parse the leading syslog timestamp of *line* (e.g. ``Jul  1 00:05:10``)."""
    m = re.match(r'^([A-Z][a-z]{2}) +(\d+) (\d{2}):(\d{2}):(\d{2}) ', line)
    mon, day, hh, mm, ss = m.groups()
    return datetime.datetime(year, _MONTH_NUM[mon], int(day),
                             int(hh), int(mm), int(ss))


def _accepted_count(content, user):
    """Number of successful SSH logins for *user* in the log text."""
    return len(re.findall(rf'Accepted (?:password|publickey) for {re.escape(user)} from ', content))


class TestFakeauthlogContent:
    def test_exact_login_counts_per_user(self):
        txt, _ = fakeauthlog_content(users={'alice': 3, 'bob': 5}, seed=1,
                                     start=START, end=END)
        assert _accepted_count(txt, 'alice') == 3
        assert _accepted_count(txt, 'bob') == 5

    def test_session_open_close_match_login_count(self):
        txt, _ = fakeauthlog_content(users={'alice': 4}, seed=1, start=START, end=END)
        assert len(re.findall(r'session opened for user alice\(', txt)) == 4
        assert len(re.findall(r'session closed for user alice', txt)) == 4
        # 6 lines per login.
        assert len(txt.splitlines()) == 4 * 6

    def test_stats_logins_per_user_matches_content(self):
        txt, stats = fakeauthlog_content(users={'alice': 2, 'bob': 7},
                                         other_users_count=5, seed=2,
                                         start=START, end=END)
        for user, n in stats['logins_per_user'].items():
            assert _accepted_count(txt, user) == n
        assert stats['total_logins'] == sum(stats['logins_per_user'].values())
        assert stats['total_lines'] == stats['total_logins'] * 6

    def test_other_users_count_and_names_distinct(self):
        _, stats = fakeauthlog_content(users={'alice': 3, 'bob': 5},
                                       other_users_count=10, seed=3,
                                       start=START, end=END)
        others = stats['other_users']
        assert len(others) == 10
        # No overlap with the explicit users.
        assert set(others) & {'alice', 'bob'} == set()

    def test_other_users_counts_differ_from_users(self):
        users = {'alice': 3, 'bob': 5}
        _, stats = fakeauthlog_content(users=users, other_users_count=20,
                                       other_users_min_login=1,
                                       other_users_max_login=50, seed=4,
                                       start=START, end=END)
        forbidden = set(users.values())
        assert all(c not in forbidden for c in stats['other_users'].values())
        # The example invariant: exactly one user has 3 logins (alice), one has 5 (bob).
        counts = list(stats['logins_per_user'].values())
        assert counts.count(3) == 1
        assert counts.count(5) == 1

    def test_other_users_counts_within_range(self):
        _, stats = fakeauthlog_content(users={'x': 100}, other_users_count=15,
                                       other_users_min_login=10,
                                       other_users_max_login=20, seed=5,
                                       start=START, end=END)
        assert all(10 <= c <= 20 for c in stats['other_users'].values())

    def test_many_other_users_get_numbered_fallback(self):
        # More than len(_NAMES) forces user### fallbacks; all must stay distinct.
        _, stats = fakeauthlog_content(other_users_count=80, seed=6,
                                       start=START, end=END)
        assert len(stats['other_users']) == 80
        assert len(set(stats['other_users'])) == 80

    def test_impossible_range_raises(self):
        with pytest.raises(ValueError):
            fakeauthlog_content(users={'x': 3}, other_users_count=1,
                                other_users_min_login=3, other_users_max_login=3,
                                start=START, end=END)

    def test_timestamps_sorted_and_within_window(self):
        txt, _ = fakeauthlog_content(users={'alice': 20}, other_users_count=5,
                                     seed=7, start=START, end=END)
        # year is not in the syslog format; reconstruct with the known window year.
        stamps = [_parse_syslog_ts(line, 2026) for line in txt.splitlines()]
        assert stamps == sorted(stamps)
        assert all(START <= dt <= END for dt in stamps)

    def test_deterministic_with_seed(self):
        a, sa = fakeauthlog_content(users={'alice': 3}, other_users_count=4, seed=9,
                                    start=START, end=END)
        b, sb = fakeauthlog_content(users={'alice': 3}, other_users_count=4, seed=9,
                                    start=START, end=END)
        assert a == b and sa == sb

    def test_empty_when_no_users(self):
        txt, stats = fakeauthlog_content(start=START, end=END)
        assert txt == ''
        assert stats['total_logins'] == 0

    def test_hostname_in_lines(self):
        txt, _ = fakeauthlog_content(users={'alice': 1}, hostname='bastion',
                                     seed=1, start=START, end=END)
        assert ' bastion sshd[' in txt


class TestFakeauthlogWrite:
    def test_default_path_permissions_owner_mtime(self):
        s = _make_bare()
        fakeauthlog(s, 'host', users={'alice': 2}, start=START, end=END, seed=1)
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/var/log/auth.log')
        assert fop.permissions == 0o640
        assert fop.owner == 'root:adm'
        assert fop.mtime == END.timestamp()

    def test_mkdir_registered_before_file_for_custom_path(self):
        s = _make_bare()
        fakeauthlog(s, 'host', users={'alice': 1}, file='/var/log/secure/auth.log',
                    start=START, end=END, seed=1)
        ops = _ops(s, 'host')
        mkdir_idx = next(i for i, op in enumerate(ops)
                         if isinstance(op, str) and op.startswith('mkdir -p'))
        file_idx = next(i for i, op in enumerate(ops)
                        if isinstance(op, _FileOp) and op.filename == '/var/log/secure/auth.log')
        assert mkdir_idx < file_idx

    def test_file_override(self):
        s = _make_bare()
        fakeauthlog(s, 'host', users={'bob': 1}, file='/tmp/my.log',
                    start=START, end=END, seed=1)
        assert any(op.filename == '/tmp/my.log' for op in _file_ops(s, 'host'))

    def test_hostname_defaults_to_machine(self):
        s = _make_bare()
        fakeauthlog(s, 'gw', users={'alice': 1}, start=START, end=END, seed=1)
        fop = next(op for op in _file_ops(s, 'gw') if op.filename == '/var/log/auth.log')
        assert b' gw sshd[' in fop.content

    def test_returns_stats(self):
        s = _make_bare()
        stats = fakeauthlog(s, 'host', users={'alice': 3, 'bob': 5},
                            other_users_count=2, start=START, end=END, seed=1)
        assert stats['file'] == '/var/log/auth.log'
        assert stats['machine'] == 'host'
        assert stats['logins_per_user']['alice'] == 3
        assert stats['logins_per_user']['bob'] == 5
