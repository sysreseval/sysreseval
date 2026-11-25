"""The host guard of the init images (images/init12, images/init13).

A privileged machine has the host's /sys, /proc/sys and device nodes: the systemd of an init image
then acts on the host (udev coldplug of every device, kernel.* sysctls, a getty on tty1, the power
keys).  Both Dockerfiles carry one block that keeps it to the machine itself.  These tests read the
Dockerfiles only (no Docker): the block is the same in both images, and holds each measure.
"""
import shlex
from pathlib import Path

import pytest

IMAGES_DIR = Path(__file__).parent.parent / 'images'
INIT_IMAGES = ('init12', 'init13')
GUARD_MARKER = 'sre-host-guard.conf'
GUARD_FILES = {
    'udev': '/etc/systemd/system/systemd-udev-trigger.service.d/sre-host-guard.conf',
    'sysctl': '/etc/systemd/system/systemd-sysctl.service.d/sre-host-guard.conf',
    'logind': '/etc/systemd/logind.conf.d/sre-host-guard.conf',
}
MASKED_UNITS = ('getty@.service', 'autovt@.service', 'systemd-binfmt.service',
                'proc-sys-fs-binfmt_misc.automount')
IGNORED_KEYS = ('HandlePowerKey', 'HandlePowerKeyLongPress', 'HandleRebootKey', 'HandleSuspendKey',
                'HandleHibernateKey', 'HandleLidSwitch', 'HandleLidSwitchExternalPower',
                'HandleLidSwitchDocked')


def guard_block(image: str) -> str:
    """The comment and the RUN instruction of the guard: the paragraph of the Dockerfile (lines
    between two empty lines) that names the guard files."""
    text = (IMAGES_DIR / image / 'Dockerfile').read_text()
    blocks = [b for b in text.split('\n\n') if GUARD_MARKER in b]
    assert len(blocks) == 1, f"{image}: {len(blocks)} paragraphs name {GUARD_MARKER}"
    return blocks[0].strip('\n')


def guard_commands(image: str) -> list[list[str]]:
    """The shell commands of the RUN instruction, each as its words (redirection included)."""
    lines = [line for line in guard_block(image).splitlines() if not line.startswith('#')]
    script = ' '.join(line.rstrip('\\').strip() for line in lines)
    assert script.startswith('RUN '), script[:40]
    return [shlex.split(command) for command in script[len('RUN '):].split(' && ')]


def written_files(image: str) -> dict[str, list[str]]:
    """{path: lines} of the files the guard writes with ``printf '%s\\n' line... > path``."""
    files = {}
    for words in guard_commands(image):
        if words[0] == 'printf':
            # the format is the four characters %s\n: printf turns them into a line per argument
            assert words[1] == '%s\\n' and words[-2] == '>', words
            files[words[-1]] = words[2:-2]
    return files


def test_the_guard_is_the_same_in_both_images():
    assert guard_block('init12') == guard_block('init13')


@pytest.mark.parametrize('image', INIT_IMAGES)
class TestHostGuard:

    def test_it_writes_its_three_files(self, image):
        assert set(written_files(image)) == set(GUARD_FILES.values())

    def test_their_directories_are_created_first(self, image):
        commands = guard_commands(image)
        assert commands[0][:2] == ['mkdir', '-p']
        assert set(commands[0][2:]) == {str(Path(path).parent) for path in GUARD_FILES.values()}

    def test_the_coldplug_is_limited_to_the_network_interfaces(self, image):
        """The unit's own ExecStart lines are dropped (an empty ExecStart=), then one trigger of
        the net subsystem: the only devices that belong to the machine."""
        lines = written_files(image)[GUARD_FILES['udev']]
        assert lines[:2] == ['[Service]', 'ExecStart=']
        triggers = [line for line in lines[2:] if line.startswith('ExecStart=')]
        assert len(triggers) == 1 and len(lines) == 3
        words = triggers[0].split()
        assert words[:2] == ['ExecStart=-udevadm', 'trigger']
        assert '--subsystem-match=net' in words and '--type=devices' in words
        assert not any(word.startswith('--type=') and word != '--type=devices' for word in words)

    def test_sysctl_applies_the_net_keys_only(self, image):
        lines = written_files(image)[GUARD_FILES['sysctl']]
        assert lines == ['[Service]', 'ExecStart=',
                         'ExecStart=/usr/lib/systemd/systemd-sysctl --prefix=/net']

    def test_logind_reserves_no_terminal_and_ignores_the_keys(self, image):
        lines = written_files(image)[GUARD_FILES['logind']]
        assert lines[0] == '[Login]'
        settings = dict(line.split('=', 1) for line in lines[1:])
        assert settings.pop('NAutoVTs') == '0' and settings.pop('ReserveVT') == '0'
        assert settings == {key: 'ignore' for key in IGNORED_KEYS}

    def test_no_getty_on_a_virtual_terminal_and_no_binfmt(self, image):
        commands = guard_commands(image)
        assert ['rm', '-f', '/etc/systemd/system/getty.target.wants/getty@tty1.service'] in commands
        masked = {Path(words[-1]).name for words in commands
                  if words[:3] == ['ln', '-sf', '/dev/null']
                  and Path(words[-1]).parent == Path('/etc/systemd/system')}
        assert masked == set(MASKED_UNITS)

    def test_the_console_of_the_machine_keeps_its_getty(self, image):
        """console-getty is the machine's own console (docker attach), not a terminal of the host."""
        assert 'console-getty' not in ' '.join(' '.join(words) for words in guard_commands(image))

    def test_the_guard_comes_before_the_real_systemctl(self, image):
        """Same place in both files: just before the stand-in systemctl of the base image goes."""
        text = (IMAGES_DIR / image / 'Dockerfile').read_text()
        assert text.index(GUARD_MARKER) < text.index('RUN rm -f /usr/local/bin/systemctl')
