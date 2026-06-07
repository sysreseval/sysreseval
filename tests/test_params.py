"""Tests for params.py utility functions (pure string/datetime operations)."""
from datetime import datetime

import pytest

from SRE import params


class TestRunningLabName:
    def test_roundtrip(self):
        dt = datetime(2026, 3, 5, 14, 30, 0)
        name = params.get_running_lab_name('test/test1', dt, 'alice')
        assert params.get_lab_name_from_running_lab_name(name) == 'test/test1'

    def test_format(self):
        dt = datetime(2026, 1, 1, 0, 0, 0)
        name = params.get_running_lab_name('mylab', dt, 'bob')
        assert name == '20260101000000@@@mylab@@@bob'

    def test_lab_name_with_at_separator(self):
        """lab_name can contain @ (encoded slashes from path-based labs)."""
        dt = datetime(2026, 6, 1, 9, 0, 0)
        name = params.get_running_lab_name('s4@tp_ssh', dt, 'carol')
        assert params.get_lab_name_from_running_lab_name(name) == 's4@tp_ssh'

    def test_invalid_format_returns_error_sentinel(self):
        result = params.get_lab_name_from_running_lab_name('not_valid')
        assert result == 'ERROR-running_lab_name-ILLEGAL-FORMAT'

    def test_invalid_missing_username(self):
        result = params.get_lab_name_from_running_lab_name('20260101000000@@@labonly')
        assert result == 'ERROR-running_lab_name-ILLEGAL-FORMAT'


class TestLabNameFromCliArg:
    def test_plain_name_encodes_slashes(self):
        # get_lab_name_from_cli_arg always encodes / as @
        result = params.get_lab_name_from_cli_arg('s4/tp_ssh', is_path=False)
        assert result == 's4@tp_ssh'

    def test_path_arg_encodes_slashes(self, tmp_path):
        """is_path=True turns the absolute path into @-separated components."""
        p = str(tmp_path / 'labs' / 'mylab')
        result = params.get_lab_name_from_cli_arg(p, is_path=True)
        assert '/' not in result
        assert '@' in result


class TestDatetimeConversion:
    def test_roundtrip(self):
        dt = datetime(2026, 6, 1, 9, 0, 0)
        assert params.string_to_datetime(params.datetime_to_string(dt)) == dt

    def test_format_is_14_digits(self):
        dt = datetime(2026, 1, 2, 3, 4, 5)
        s = params.datetime_to_string(dt)
        assert s == '20260102030405'
        assert len(s) == 14


class TestGetCurrentSrelabFile:
    def test_directory_lab(self):
        name = '20260101000000@@@s4/tp_ssh@@@user'
        result = params.get_current_srelab_file_from_running_lab_name(name)
        assert result.endswith('srelab.py')
        assert 's4/tp_ssh' in result

    def test_file_lab(self):
        name = '20260101000000@@@test/mylab.py@@@user'
        result = params.get_current_srelab_file_from_running_lab_name(name)
        assert result.endswith('mylab.py')

    def test_path_lab_absolute(self):
        """Lab names that start with / (path-encoded with @) resolve to absolute paths."""
        name = '20260101000000@@@@home@etudiant@tp@@@user'
        result = params.get_current_srelab_file_from_running_lab_name(name)
        assert result.startswith('/')


class TestGetSrelabDir:
    def test_directory_lab_returns_dir(self):
        name = '20260101000000@@@s4/tp_ssh@@@user'
        result = params.get_srelab_dir(name)
        assert result is not None
        assert 's4/tp_ssh' in result

    def test_file_lab_returns_none(self):
        name = '20260101000000@@@test/mylab.py@@@user'
        result = params.get_srelab_dir(name)
        assert result is None
