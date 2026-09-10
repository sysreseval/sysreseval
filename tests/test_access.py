"""Tests for SRE.access — the entry-point rules of the ``sre`` CLI.

Covers who may run which action, how the student login is resolved, when a
process counts as "launched by sudo" (student path) versus an admin working in
a ``sudo -i`` shell, and the sre-wrapper ancestry walk against a fake /proc.
"""
import os

import pytest

from SRE import access

SRE_UID = 1100
ADMIN_UIDS = [500]
ADMIN_GIDS = [2000]


def _allowed_user(uid, gids=()):
    return access.is_allowed_user(uid, gids, sre_uid=SRE_UID,
                                  admin_uids=ADMIN_UIDS, admin_gids=ADMIN_GIDS)


class TestIsAllowedUser:
    def test_root(self):
        assert _allowed_user(0)

    def test_sre_user(self):
        assert _allowed_user(SRE_UID)

    def test_admin_uid(self):
        assert _allowed_user(500, gids=[100])

    def test_admin_gid(self):
        assert _allowed_user(1001, gids=[100, 2000])

    def test_plain_user(self):
        assert not _allowed_user(1001, gids=[100, 1001])

    def test_plain_user_no_admins_configured(self):
        assert not access.is_allowed_user(1001, [1001], sre_uid=SRE_UID,
                                          admin_uids=[], admin_gids=[])


class TestIsAllowedAction:
    @pytest.mark.parametrize('action', ['start', 'stop', 'exec', 'eval-exam', 'watch'])
    def test_root_any_action(self, action):
        assert access.is_allowed_action(0, action, sre_uid=SRE_UID)

    @pytest.mark.parametrize('action', ['start', 'stop', 'exec', 'eval-exam', 'watch'])
    def test_sre_user_any_action(self, action):
        assert access.is_allowed_action(SRE_UID, action, sre_uid=SRE_UID)

    @pytest.mark.parametrize('action', sorted(access.ADMIN_ACTIONS))
    def test_admin_read_only_tools(self, action):
        assert access.is_allowed_action(1001, action, sre_uid=SRE_UID)

    def test_admin_watch(self):
        """Regression: watch is a read-only archive viewer like cat/sheet/outline."""
        assert 'watch' in access.ADMIN_ACTIONS

    @pytest.mark.parametrize('action', ['start', 'stop', 'exec', 'eval', 'eval-all', 'state',
                                        'wipe', 'set-exam', 'eval-exam', 'end-exam',
                                        'preload-images', 'export', 'list'])
    def test_admin_privileged_actions_refused(self, action):
        assert not access.is_allowed_action(1001, action, sre_uid=SRE_UID)


class TestResolveUsername:
    ENV = {'LOGNAME': 'root', 'USER_USERNAME': 'alice', 'SUDO_USER': 'bob'}

    def test_user_flag_reads_user_username(self):
        assert access.resolve_username(self.ENV, user_flag=True, use_sudo_user=False) == 'alice'

    def test_user_flag_with_sudo_user_option(self):
        assert access.resolve_username(self.ENV, user_flag=True, use_sudo_user=True) == 'bob'

    def test_no_user_flag_reads_logname(self):
        assert access.resolve_username(self.ENV, user_flag=False, use_sudo_user=False) == 'root'

    def test_missing_variables_give_empty_name(self):
        assert access.resolve_username({}, user_flag=True, use_sudo_user=False) == ''
        assert access.resolve_username({}, user_flag=False, use_sudo_user=False) == ''


class TestIsValidUsername:
    @pytest.mark.parametrize('name', ['alice', 'jean-pierre.d_1', 'A9'])
    def test_valid(self, name):
        assert access.is_valid_username(name)

    @pytest.mark.parametrize('name', ['', 'a b', 'a/b', '../x', 'é', 'a;rm'])
    def test_invalid(self, name):
        assert not access.is_valid_username(name)


@pytest.fixture
def install(tmp_path):
    """A fake /opt layout: ``opt/sre`` is a symlink to a versioned directory,
    as a real install may be.  Returns (sre_exe as params sees it, real dir)."""
    real = tmp_path / 'opt' / 'sre-1.2'
    (real / 'bin').mkdir(parents=True)
    (real / 'sbin').mkdir()
    (real / 'sbin' / 'sre').write_text('#!/bin/bash\n')
    (real / 'bin' / 'sre-wrapper').write_bytes(b'\x7fELF')
    os.symlink('sre-1.2', tmp_path / 'opt' / 'sre')
    return str(tmp_path / 'opt' / 'sre'), real


class TestLaunchedBySudo:
    """SUDO_COMMAND is what distinguishes "sudo ran sre" (student path) from
    "sre runs inside a shell that sudo started" (admin doing ``sudo -i``)."""

    def test_c_wrapper_resolved_path(self, install):
        sre_dir, real = install
        env = {'SUDO_USER': 'alice', 'SUDO_COMMAND': f'{real}/sbin/sre --user start lab1'}
        assert access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_shell_wrapper_dotdot_path(self, install):
        """bin/sre-wrapper runs ``sudo "$DIR/../sbin/sre"`` and sudo keeps the ``..``."""
        sre_dir, _ = install
        env = {'SUDO_USER': 'alice', 'SUDO_COMMAND': f'{sre_dir}/bin/../sbin/sre --user start lab1'}
        assert access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_symlinked_install_dir(self, install):
        sre_dir, real = install
        env = {'SUDO_USER': 'alice', 'SUDO_COMMAND': f'{sre_dir}/sbin/sre --user cat x.zst'}
        assert access.launched_by_sudo(env, f'{real}/sbin/sre')

    def test_no_arguments(self, install):
        sre_dir, _ = install
        env = {'SUDO_USER': 'alice', 'SUDO_COMMAND': f'{sre_dir}/sbin/sre'}
        assert access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_sudo_i_login_shell(self, install):
        sre_dir, _ = install
        env = {'SUDO_USER': 'admin', 'SUDO_COMMAND': '/bin/bash'}
        assert not access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_sudo_s_shell(self, install):
        sre_dir, _ = install
        env = {'SUDO_USER': 'admin', 'SUDO_COMMAND': '/bin/zsh -c echo'}
        assert not access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_sudo_of_another_command_naming_sre(self, install):
        """Only the command sudo executed counts, not sre appearing in its arguments."""
        sre_dir, _ = install
        env = {'SUDO_USER': 'admin', 'SUDO_COMMAND': f'/usr/bin/env {sre_dir}/sbin/sre --user start x'}
        assert not access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_no_sudo_user(self, install):
        """Not started by sudo at all (su, root login, tests): SUDO_COMMAND is ignored."""
        sre_dir, _ = install
        env = {'SUDO_COMMAND': f'{sre_dir}/sbin/sre --user start lab1'}
        assert not access.launched_by_sudo(env, f'{sre_dir}/sbin/sre')

    def test_sudo_user_without_sudo_command(self, install):
        sre_dir, _ = install
        assert not access.launched_by_sudo({'SUDO_USER': 'alice'}, f'{sre_dir}/sbin/sre')
        assert not access.launched_by_sudo({'SUDO_USER': 'alice', 'SUDO_COMMAND': ''},
                                           f'{sre_dir}/sbin/sre')


def _fake_proc(root, procs):
    """Build a fake /proc tree.

    ``procs`` maps pid -> (exe, cmdline, ppid).  ``exe`` is the target of the
    ``exe`` symlink, or None to simulate a readlink refused by permissions.
    """
    root.mkdir()
    for pid, (exe, cmdline, ppid) in procs.items():
        d = root / str(pid)
        d.mkdir()
        if exe is not None:
            os.symlink(exe, d / 'exe')
        (d / 'cmdline').write_bytes(b''.join(a.encode() + b'\x00' for a in cmdline))
        (d / 'status').write_text(f'Name:\tx\nPid:\t{pid}\nPPid:\t{ppid}\n')
    return str(root)


class TestLaunchedFromWrapper:
    SUDO = '/usr/bin/sudo'
    BASH = '/usr/bin/bash'

    def test_c_wrapper(self, install, tmp_path):
        """C wrapper forks, then the child execs sudo which execs sre:
        sre (100) -> sudo (90) -> sre-wrapper (80) -> user shell (70)."""
        sre_dir, real = install
        wrapper = str(real / 'bin' / 'sre-wrapper')
        proc = _fake_proc(tmp_path / 'proc', {
            90: (self.SUDO, ['sudo', f'{real}/sbin/sre', '--user', 'start', 'lab1'], 80),
            80: (wrapper, [f'{sre_dir}/bin/sre-wrapper', 'start', 'lab1'], 70),
            70: (self.BASH, ['-bash'], 1),
        })
        assert access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)

    def test_c_wrapper_behind_sudo_monitor(self, install, tmp_path):
        """With sudoers ``use_pty`` sudo forks a monitor, so the wrapper is one
        level further up: sre (100) -> sudo (90) -> sudo (85) -> sre-wrapper (80)."""
        sre_dir, real = install
        wrapper = str(real / 'bin' / 'sre-wrapper')
        proc = _fake_proc(tmp_path / 'proc', {
            90: (self.SUDO, ['sudo', f'{real}/sbin/sre', '--user', 'start', 'lab1'], 85),
            85: (self.SUDO, ['sudo', f'{real}/sbin/sre', '--user', 'start', 'lab1'], 80),
            80: (wrapper, [f'{sre_dir}/bin/sre-wrapper', 'start', 'lab1'], 70),
            70: (self.BASH, ['-bash'], 1),
        })
        assert access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)

    def test_c_wrapper_exe_unreadable(self, install, tmp_path):
        """An unreadable /proc/<pid>/exe is a refusal: argv is not a fallback."""
        sre_dir, real = install
        proc = _fake_proc(tmp_path / 'proc', {
            90: (None, ['sudo', f'{real}/sbin/sre', '--user', 'start', 'lab1'], 80),
            80: (None, [f'{sre_dir}/bin/sre-wrapper', 'start', 'lab1'], 70),
            70: (None, ['-bash'], 1),
        })
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)

    def test_shell_script_wrapper_is_refused(self, install, tmp_path):
        """A bash-script wrapper has the interpreter as exe and the script only
        in argv, which is not trusted: only the compiled binary is accepted."""
        sre_dir, real = install
        proc = _fake_proc(tmp_path / 'proc', {
            90: (self.SUDO, ['sudo', f'{sre_dir}/bin/../sbin/sre', '--user', 'start', 'lab1'], 80),
            80: (self.BASH, ['/bin/bash', f'{sre_dir}/bin/sre-wrapper', 'start', 'lab1'], 70),
            70: (self.BASH, ['-bash'], 1),
        })
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)

    def test_direct_sudo_from_shell(self, install, tmp_path):
        """Student bypassing the wrapper: sre -> sudo -> bash -> sshd."""
        sre_dir, real = install
        proc = _fake_proc(tmp_path / 'proc', {
            90: (self.SUDO, ['sudo', f'{real}/sbin/sre', '--user', 'stop', 'lab1'], 80),
            80: (self.BASH, ['-bash'], 70),
            70: ('/usr/sbin/sshd', ['sshd: alice@pts/0'], 1),
        })
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)

    def test_wrapper_beyond_depth(self, install, tmp_path):
        """The walk stops after WRAPPER_ANCESTOR_DEPTH ancestors."""
        sre_dir, real = install
        depth = access.WRAPPER_ANCESTOR_DEPTH
        procs = {}
        pid = 90
        for _ in range(depth):
            procs[pid] = (self.BASH, ['bash'], pid - 1)
            pid -= 1
        procs[pid] = (str(real / 'bin' / 'sre-wrapper'), [f'{sre_dir}/bin/sre-wrapper'], 1)
        proc = _fake_proc(tmp_path / 'proc', procs)
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)
        assert access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc,
                                            depth=depth + 1)

    def test_stops_at_init(self, install, tmp_path):
        sre_dir, _ = install
        proc = _fake_proc(tmp_path / 'proc', {
            90: (self.BASH, ['bash'], 1),
            1: ('/sbin/init', ['/sbin/init'], 0),
        })
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)

    def test_missing_proc_entry(self, install, tmp_path):
        """A vanished ancestor (or unreadable /proc) is a refusal, not a crash."""
        sre_dir, _ = install
        proc = _fake_proc(tmp_path / 'proc', {90: (self.BASH, ['bash'], 80)})
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 90, proc=proc)
        assert not access.launched_from_wrapper(f'{sre_dir}/bin/sre-wrapper', 12345, proc=proc)

    @pytest.mark.parametrize('argv', [
        pytest.param(['{w}'], id='argv0-exec-a'),
        pytest.param(['/bin/bash', '{w}'], id='argv1-script-style'),
        pytest.param(['/bin/bash', '-c', '{w}'], id='argv2'),
    ])
    def test_argv_spoof_is_refused(self, install, tmp_path, argv):
        """argv is caller-controlled: ``exec -a /opt/sre/bin/sre-wrapper bash``
        followed by a direct ``sudo sre --user ...`` shows the wrapper path in
        argv while exe is bash.  Only /proc/<pid>/exe counts."""
        sre_dir, real = install
        w = f'{sre_dir}/bin/sre-wrapper'
        proc = _fake_proc(tmp_path / 'proc', {
            90: (self.SUDO, ['sudo', f'{real}/sbin/sre', '--user', 'stop', 'lab1'], 80),
            80: (self.BASH, [a.format(w=w) for a in argv], 70),
            70: (self.BASH, ['-bash'], 1),
        })
        assert not access.launched_from_wrapper(w, 90, proc=proc)
