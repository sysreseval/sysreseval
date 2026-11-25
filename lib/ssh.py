import re
import shlex
from typing import List, Tuple

from SRE.lib_sre import NetScheme0, Grade0

_SSH_MONITOR_DAEMON = r'''#!/usr/bin/env python3
"""SSH agent monitor daemon.
Tails auth.log for SSH sessions; for each login logs either the forwarded
agent public keys or a 'no-agent' marker.
Log format: <ISO-ts> user=<u> from=<ip> pubkey=<type> <base64> [comment]
            <ISO-ts> user=<u> from=<ip> no-agent
"""
import os, sys, time, glob, subprocess, re, pwd, datetime

LOG = '/var/log/.ssh_monitor.log'
AUTH_LOG = '/var/log/auth.log'
# the process that logs a connection: sshd up to OpenSSH 9.7 (Debian 12), sshd-session since 9.8
SSHD = r'sshd(?:-session)?\[(\d+)\]'


def daemonize():
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    for fd in range(3):
        try:
            os.close(fd)
        except OSError:
            pass
    fd = os.open('/dev/null', os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    if fd > 2:
        os.close(fd)


def get_agent_keys_for_user(username, retries=5, delay=0.2):
    """Query all agent sockets owned by username; retry to handle timing."""
    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        return []
    for _ in range(retries):
        keys = []
        for sock in glob.glob('/tmp/ssh-*/agent.*'):
            try:
                if os.stat(sock).st_uid != uid:
                    continue
                env = dict(os.environ)
                env['SSH_AUTH_SOCK'] = sock
                r = subprocess.run(['ssh-add', '-L'], env=env, capture_output=True, timeout=5)
                if r.returncode == 0:
                    keys.extend(r.stdout.decode().strip().splitlines())
            except Exception:
                pass
        if keys:
            return keys
        time.sleep(delay)
    return []


def write_log(ts, username, src, keys):
    with open(LOG, 'a') as f:
        if keys:
            for key in keys:
                f.write(f'{ts} user={username} from={src} pubkey={key}\n')
        else:
            f.write(f'{ts} user={username} from={src} no-agent\n')


def main():
    daemonize()

    ts = datetime.datetime.now().isoformat(timespec='seconds')
    with open(LOG, 'a') as f:
        f.write(f'{ts} ssh-monitor daemon started\n')

    pid_to_ip = {}

    while not os.path.exists(AUTH_LOG):
        time.sleep(1)

    with open(AUTH_LOG, 'r') as f:
        f.seek(0, 2)
        buf = ''
        while True:
            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.1)
                continue
            buf += chunk
            while '\n' in buf:
                line, buf = buf.split('\n', 1)
                m = re.search(SSHD + r': Accepted \S+ for (\S+) from (\S+)', line)
                if m:
                    pid_to_ip[m.group(1)] = m.group(3)
                    continue
                m = re.search(SSHD + r'.*session opened for user (\w+)', line)
                if m:
                    pid, username = m.group(1), m.group(2)
                    src = pid_to_ip.pop(pid, 'unknown')
                    ts = datetime.datetime.now().isoformat(timespec='seconds')
                    keys = get_agent_keys_for_user(username)
                    write_log(ts, username, src, keys)


if __name__ == '__main__':
    main()
'''


# The syslog tag of the process that logs a connection in auth.log: `sshd[PID]` up to OpenSSH 9.7
# (Debian 12), `sshd-session[PID]` since OpenSSH 9.8 split the server (Debian 13: OpenSSH 10.0).
_SSHD_TAG_RE = re.compile(r'\bsshd(?:-session)?\[\d+\]')


def _accepted_then_session_opened(log_output: str, method: str, username: str) -> bool:
    """True when *log_output* (an auth.log) holds an sshd line `Accepted <method> for <username>`
    directly followed by the opening of the PAM session of that user."""
    lines = (log_output or '').splitlines()
    for i, line in enumerate(lines[:-1]):
        if (_SSHD_TAG_RE.search(line) and f"Accepted {method} for {username}" in line
                and f"pam_unix(sshd:session): session opened for user {username}" in lines[i + 1]):
            return True
    return False


def add_ssh_monitor_agent(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Install and start the SSH agent monitor daemon on a virtual machine.

    The daemon tails /var/log/auth.log and, when a new SSH session opens for a
    user who has a forwarded agent socket, queries the agent and appends one line
    per loaded key to /var/log/.ssh_monitor.log (mode 0622: root-writable,
    world-appendable):
        <ISO-timestamp> user=<u> from=<src-ip> pubkey=<type> <base64> [comment]

    The daemon uses double-fork daemonization to fully detach from the Docker
    exec_run call so it does not block lab startup.

    Args:
        net_scheme: the NetScheme0 instance (state phase).
        machine:    name of the virtual machine to deploy the monitor on.
        step:       execution step (default 1).
    """
    net_scheme.file(
        machine=machine,
        filename="/usr/local/sbin/ssh_monitor.py",
        content=_SSH_MONITOR_DAEMON,
        permissions=0o755,
        owner="root:root",
        step=step,
    )
    net_scheme.cmd(machine, "touch /var/log/.ssh_monitor.log", step=step)
    net_scheme.cmd(machine, "chmod 0622 /var/log/.ssh_monitor.log", step=step)
    net_scheme.cmd(machine, "python3 /usr/local/sbin/ssh_monitor.py", step=step)


def create_ssh_key_on_host(
    net_scheme: NetScheme0,
    filename: str,
    bits: int = 4096,
    key_type: str = "rsa",
    password: str = None,
    step: int = 1,
) -> str:
    passphrase = password if password is not None else ""
    net_scheme.host_cmd(
        f"ssh-keygen -t {shlex.quote(key_type)} -b {int(bits)} -f {shlex.quote(filename)} -N {shlex.quote(passphrase)}",
        step=step,
    )
    return filename


def create_ssh_key_and_copy_to_host(
    net_scheme: NetScheme0,
    machine: str,
    filename: str,
    bits: int = 4096,
    key_type: str = "rsa",
    password: str = None,
    step: int = 1,
) -> str:
    """Generate an SSH key pair inside `machine` and copy both files to the host.

    Equivalent in result to `create_ssh_key_on_host`, but the keypair is generated
    inside the container and then the private and public files are copied to the
    host's files directory.
    Be careful: this function will execute on 2 differents steps: first the key generation and then the copying

    Args:
        net_scheme: the NetScheme0 instance (state phase).
        machine:    name of the virtual machine where the key is generated.
        filename:   destination path for the private key on the host (the public
                    key is stored at filename + '.pub'); relative to the project's
                    files directory.
        bits:       key size in bits (default: 4096).
        key_type:   key type (default: "rsa").
        password:   passphrase to protect the private key (default: None).
        step:       execution step (default: 1).

    Returns:
        The filename argument unchanged.
    """
    from pathlib import PurePosixPath

    passphrase = password if password is not None else ""
    tmp_path = f"/tmp/.sre_keygen_{PurePosixPath(filename).name}"
    net_scheme.cmd(
        machine,
        f"ssh-keygen -t {shlex.quote(key_type)} -b {int(bits)} -f {shlex.quote(tmp_path)} -N {shlex.quote(passphrase)}",
        step=step,
    )
    net_scheme.cp_to_host(machine=machine, path=tmp_path, dest=filename, permissions=0o600, step=step+1)
    net_scheme.cp_to_host(machine=machine, path=f"{tmp_path}.pub", dest=f"{filename}.pub", step=step+1)
    return filename



def remove_ssh_password_authentication_on_sshd(
    net_scheme: NetScheme0, machine: str, restart_ssh: bool = False, step: int = 1
):
    net_scheme.cmd(
        machine=machine,
        command=r"sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
        step=step,
    )
    if restart_ssh:
        net_scheme.cmd(machine=machine, command="service ssh restart", step=step)


def set_forward_ssh_agent_in_ssh_config(
    net_scheme: NetScheme0, machine_name: str, step: int = 1
) -> None:
    """Enable ForwardAgent for all outgoing SSH connections on a virtual machine.

    Writes a drop-in file to /etc/ssh/ssh_config.d/forward_agent.conf and
    ensures the Include directive is present in /etc/ssh/ssh_config so the
    drop-in is loaded (Debian's default ssh_config already includes it, but
    some minimal images may not).

    Args:
         net_scheme:   the NetScheme0 instance (state phase).
         machine_name: name of the virtual machine to configure.
         step:         execution step (default 1).
    """
    net_scheme.cmd(machine_name, "mkdir -p /etc/ssh/ssh_config.d", step=step)
    net_scheme.file(
        machine=machine_name,
        filename="/etc/ssh/ssh_config.d/forward_agent.conf",
        content="Host *\n    ForwardAgent yes\n",
        permissions=0o644,
        owner="root:root",
        step=step,
    )
    net_scheme.cmd(
        machine_name,
        r"grep -q 'Include.*ssh_config\.d' /etc/ssh/ssh_config"
        r" || sed -i '1s/^/Include \/etc\/ssh\/ssh_config.d\/*.conf\n/' /etc/ssh/ssh_config",
        step=step,
    )


def copy_ssh_pub_key_on_machine(
    net_scheme: NetScheme0, machine: str, pub_key: str, username: str, step: int = 1
):
    auth_file = f"~{username}/.ssh/authorized_keys"
    tmp_path = f"/tmp/.sre_pubkey_{username}"

    net_scheme.cmd(
        machine=machine, command=f'sh -c "mkdir -p ~{username}/.ssh"', step=step
    )
    net_scheme.cmd(
        machine=machine,
        command=f'sh -c "touch {auth_file} && chmod 600 {auth_file}"',
        step=step,
    )
    net_scheme.cp_from_host(
        src=pub_key,
        machine=machine,
        dest=tmp_path,
        permissions=0o644,
        owner="root:root",
        step=step,
    )
    net_scheme.cmd(
        machine=machine,
        command=f'sh -c "grep -qF \\"$(cut -d\' \' -f2 {tmp_path})\\" {auth_file} || cat {tmp_path} >> {auth_file}; rm -f {tmp_path}"',
        step=step,
    )
    net_scheme.cmd(
        machine=machine,
        command=f'sh -c "chown -R {username}:{username} ~{username}/.ssh"',
        step=step,
    )


def eval_ssh_agent_with_loaded_key(
    grade: Grade0,
    machine_name: str,
    username: str,
    key_on_host: str,
    password: str = None,
    step: int = 1,
) -> bool:
    """Check that a specific private key is loaded in a running ssh-agent on a virtual machine.

    On the host, the public key is derived from `key_on_host` using `ssh-keygen -y`.
    On `machine_name`, every agent socket found under `/tmp/ssh-*/agent.*` and owned
    by `username` is queried with `ssh-add -L`. The function returns True if the
    derived public key appears in any of those agents.

    Args:
        grade:        the Grade0 instance (provides test execution and files dir).
        machine_name: name of the virtual machine to inspect.
        username:     the user whose agent sockets are checked.
        key_on_host:  path to the private key on the host — absolute, or relative to
                      the project's files directory.
        password:     passphrase to decrypt the private key (default: None, i.e. no passphrase).
        step:         evaluation step passed to grade.test() (default: 1).

    Returns:
        True if the key is loaded in an agent belonging to `username`, False otherwise.
    """
    import os
    import subprocess
    from pathlib import Path

    key_path = (
        key_on_host
        if key_on_host.startswith("/")
        else str(Path(grade.net_scheme.get_files_dir()) / key_on_host)
    )
    # ssh-keygen refuses to read a private key whose permissions expose it,
    # and cp_to_host writes the host copy with the default 0644 umask.
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    cmd = [
        "ssh-keygen",
        "-y",
        "-f",
        key_path,
        "-P",
        password if password is not None else "",
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        return False
    pub_key = result.stdout.decode().strip()
    key_token = pub_key.split()[1] if len(pub_key.split()) >= 2 else pub_key

    output, _ = grade.test(
        machine_name=machine_name,
        command=(
            f"sh -c 'for sock in /tmp/ssh-*/agent.*; do"
            f' [ -S "$sock" ] && [ "$(stat -c %U "$sock")" = "{username}" ]'
            f' && SSH_AUTH_SOCK="$sock" ssh-add -L 2>/dev/null;'
            f" done'"
        ),
        step=step,
        allow_error=True,
    )
    if not output:
        return False
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == key_token:
            return True
    return False


def check_ssh_key(
    grade: Grade0,
    machine: str,
    private_key: str,
    key_type: str = "rsa",
    bits: int = 4096,
    password: str = None,
    step: int = 1,
) -> bool:
    """Check that an SSH key pair on a machine has the expected properties.

    Verifies: public key file readable and matches key_type and bits;
    private key file exists and the passphrase is correct.

    ssh-keygen -l output format: '<bits> SHA256:<fp> <comment> (<TYPE>)'

    Args:
        grade:       the Grade0 instance.
        machine:     name of the virtual machine to inspect.
        private_key: path to the private key on the machine; the public key
                     is expected at private_key + '.pub'.
        key_type:    expected key type, e.g. 'rsa', 'ed25519' (default: 'rsa').
        bits:        expected bit length (default: 4096).
        password:    expected passphrase, or None for no passphrase (default: None).
        step:        evaluation step passed to grade.test() (default: 1).

    Returns:
        True if the key exists with the expected type, bits, and passphrase.
    """
    passphrase = password if password is not None else ""

    info_output, info_code = grade.test(
        machine_name=machine,
        command=f"ssh-keygen -l -f {private_key}.pub",
        step=step,
        allow_error=True,
    )
    _, pass_code = grade.test(
        machine_name=machine,
        command=f"ssh-keygen -y -f {private_key} -P '{passphrase}' > /dev/null",
        step=step,
        allow_error=True,
    )

    if info_code != 0 or not info_output:
        return False
    parts = info_output.strip().split()
    if len(parts) < 2:
        return False
    try:
        actual_bits = int(parts[0])
    except ValueError:
        return False
    actual_type = parts[-1].strip("()")
    if actual_bits != bits or actual_type.lower() != key_type.lower():
        return False

    return pass_code == 0


def eval_ssh_public_key_in_authorized_keys(
    grade: Grade0,
    machine: str,
    username: str,
    public_key_file: str = None,
    public_key: str = None,
    step: int = 1,
) -> bool:
    """Check that a public key is in authorized_keys with correct permissions.

    Exactly one of `public_key_file` or `public_key` must be provided.
    - `public_key_file`: path to the public key file on the host (absolute, or
      relative to the lab's files directory).
    - `public_key`: the public key content as a string.

    On `machine`, verifies:
    - the key's base64 token appears in ~username/.ssh/authorized_keys,
    - the file is owned by `username`,
    - the file is not readable by group or others (permissions & 0o044 == 0).

    Args:
        grade:           the Grade0 instance.
        machine:         name of the virtual machine to inspect.
        username:        the user whose authorized_keys is checked.
        public_key_file: path to the public key file on the host.
        public_key:      public key content as a string.
        step:            evaluation step passed to grade.test() (default: 1).

    Returns:
        True if the key is present and permissions are correct, False otherwise.
    """
    from pathlib import Path

    if (public_key_file is None) == (public_key is None):
        raise ValueError(
            "exactly one of public_key_file or public_key must be provided"
        )

    if public_key_file is not None:
        pub_key_path = (
            public_key_file
            if public_key_file.startswith("/")
            else str(Path(grade.net_scheme.get_files_dir()) / public_key_file)
        )
        with open(pub_key_path) as f:
            content = f.read().strip()
    else:
        content = public_key.strip()

    parts = content.split()
    key_token = parts[1] if len(parts) >= 2 else content

    auth_file = f"/home/{username}/.ssh/authorized_keys"

    # Commands are fixed (no key_token) so the string is identical on both grade() passes.
    auth_output, _ = grade.test(
        machine_name=machine,
        command=f"cat {auth_file}",
        step=step,
        allow_error=True,
    )
    stat_output, stat_code = grade.test(
        machine_name=machine,
        command=f"stat -c '%U %a' {auth_file}",
        step=step,
        default_code=-1,
        allow_error=True,
    )

    # Key comparison done in Python after both grade.test() calls are registered.
    if public_key_file is not None:
        pub_key_path = (
            public_key_file
            if public_key_file.startswith("/")
            else str(Path(grade.net_scheme.get_files_dir()) / public_key_file)
        )
        try:
            with open(pub_key_path) as f:
                content = f.read().strip()
        except OSError:
            return False
    else:
        content = public_key.strip()

    parts = content.split()
    key_token = parts[1] if len(parts) >= 2 else content

    if not auth_output:
        return False
    key_found = any(
        len(line.split()) >= 2 and line.split()[1] == key_token
        for line in auth_output.splitlines()
    )
    if not key_found:
        return False

    if stat_code != 0 or not stat_output:
        return False
    stat_parts = stat_output.strip().split()
    if len(stat_parts) < 2:
        return False
    owner, mode_str = stat_parts[0], stat_parts[1]
    if owner != username:
        return False
    try:
        return int(mode_str, 8) & 0o044 == 0
    except ValueError:
        return False


def eval_ssh_agent_exists(
    grade: Grade0, machine_name: str, username: str, step: int = 1
) -> bool:
    _, code = grade.test(
        machine_name=machine_name,
        command=f"pgrep -u {username} ssh-agent",
        step=step,
        default_code=-1,
        allow_error=True,
    )
    return code == 0


def eval_ssh_possible_with_password_authentification(
    grade: Grade0,
    src_machine: str,
    dest_machine: str,
    username: str = "nobody",
    step: int = 1,
) -> bool:
    """Check whether password authentication is offered by dest_machine's SSH server.

    From src_machine, attempts an SSH connection to dest_machine with
    PreferredAuthentications=password and BatchMode=yes. The verbose output reveals
    whether the server offered password as an authentication method: if it does, SSH
    tries it (and fails non-interactively); if not, it never attempts it.

    Args:
        grade:        the Grade0 instance.
        src_machine:  machine from which the SSH probe is run.
        dest_machine: machine whose sshd is being tested.
        username:     SSH username to connect as (default: "nobody").
        step:         evaluation step passed to grade.test() (default: 1).

    Returns:
        True if dest_machine's sshd offers password authentication, False otherwise.
    """
    _, code = grade.test(
        machine_name=src_machine,
        command=(
            f"ssh -o PreferredAuthentications=password -o BatchMode=yes"
            f" -o StrictHostKeyChecking=no -o ConnectTimeout=5"
            f" {username}@{dest_machine} true 2>&1"
            f" | grep -q 'Permission denied.*password'"
        ),
        step=step,
        default_code=-1,
        allow_error=True,
    )
    return code == 0


def eval_ssh_connection_with_password(
    grade: Grade0, machine_name: str, username: str, step: int = 1
) -> bool:
    log = grade.test(
        machine_name=machine_name, command=f"cat /var/log/auth.log", step=step, allow_error=True
    )

    log_output, _ = log
    return _accepted_then_session_opened(log_output, 'password', username)


def eval_ssh_connection_with_ssh_agent(
    grade: Grade0,
    machine_name: str,
    username: str,
    key_on_host: str,
    password: str = None,
    step: int = 1,
) -> bool:
    """Check via the SSH monitor log that a user logged in using an SSH agent carrying a specific key.

    Reads /var/log/.ssh_monitor.log written by the sshrc installed with add_ssh_monitor_agent().
    On the host, derives the public key from `key_on_host` and looks for a matching entry
    in the monitor log for `username`.

    The monitor log format per line:
        <ISO-ts> user=<u> from=<ip> pubkey=<type> <base64> [comment]

    Args:
        grade:        the Grade0 instance.
        machine_name: machine where the monitor is running.
        username:     SSH username to look for in the monitor log.
        key_on_host:  private key path on the host — absolute or relative to the files dir.
        password:     passphrase for the private key (default: None).
        step:         evaluation step passed to grade.test() (default: 1).

    Returns:
        True if the monitor log contains a login for `username` with the given key via an agent.
    """
    import os
    import subprocess
    from pathlib import Path

    key_path = (
        key_on_host
        if key_on_host.startswith("/")
        else str(Path(grade.net_scheme.get_files_dir()) / key_on_host)
    )
    # ssh-keygen refuses to read a private key whose permissions expose it,
    # and cp_to_host writes the host copy with the default 0644 umask.
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    cmd = [
        "ssh-keygen",
        "-y",
        "-f",
        key_path,
        "-P",
        password if password is not None else "",
    ]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        return False
    pub_key = result.stdout.decode().strip()
    parts = pub_key.split()
    key_token = parts[1] if len(parts) >= 2 else pub_key

    log_output, _ = grade.test(
        machine_name=machine_name, command="cat /var/log/.ssh_monitor.log", step=step, allow_error=True
    )
    if not log_output:
        return False
    for line in log_output.splitlines():
        if f"user={username}" in line and key_token in line:
            return True
    return False


def eval_synchronized_file(
    grade: Grade0, machine_list: List[str], filename: str, step: int = 1
) -> Tuple[bool, str]:
    """Check that a file is identical and identically timestamped on all machines.

    For each machine in machine_list, reads the file content and its mtime
    (truncated to the second via `date -r ... +%s`). Returns True only if:
    - the file exists on every machine (exit code 0 for both commands),
    - all mtimes are equal,
    - all contents are equal.

    Args:
        grade:        the Grade0 instance.
        machine_list: machines to check.
        filename:     absolute path to the file on each machine.
        step:         evaluation step passed to grade.test() (default: 1).

    Returns:
        (True, content) if the file is synchronized across all machines,
        (False, '')     otherwise.
    """
    # Register all tests unconditionally — grade() is called twice (register then eval).
    # Early exit here would prevent later machines' tests from being registered,
    # causing them to return defaults on the evaluation pass.
    results = {}
    for machine in machine_list:
        content, content_code = grade.test(
            machine_name=machine,
            command=f"cat {filename}",
            step=step,
            default_code=-1,
            allow_error=True,
        )
        mtime, mtime_code = grade.test(
            machine_name=machine,
            command=f"date -r {filename} +%s",
            step=step,
            default_code=-1,
            allow_error=True,
        )
        results[machine] = (content, content_code, (mtime or "").strip(), mtime_code)

    if not results:
        return False, ""

    for content, content_code, mtime, mtime_code in results.values():
        if content_code != 0 or mtime_code != 0:
            return False, ""

    reference_content = results[machine_list[0]][0] or ""
    reference_mtime = results[machine_list[0]][2]

    for content, _, mtime, _ in results.values():
        if (content or "") != reference_content or mtime != reference_mtime:
            return False, ""

    return True, reference_content


def eval_ssh_connection_with_key(
    grade: Grade0, machine_name: str, username: str, step: int = 1
) -> bool:
    log = grade.test(
        machine_name=machine_name,
        command=f"cat /var/log/auth.log",
        step=step,
        allow_error=True,
    )

    log_output, _ = log
    return _accepted_then_session_opened(log_output, 'publickey', username)


# ---------------------------------------------------------------------------
# Keys, configurations, certificates and logins (the ssh2 lab: tunnels, jumps, certificates)
# ---------------------------------------------------------------------------

import base64 as _base64
import hashlib as _hashlib
from dataclasses import dataclass as _dataclass, field as _field
from datetime import datetime as _datetime
from typing import Dict, Optional

# Never `@@@` in a grader command: it separates the commands of exetests.py.
_MARK = "==SRE-SSH=="


def generate_ed25519_keypair(comment: str = "") -> Tuple[str, str]:
    """A new Ed25519 key pair made in Python (no ssh-keygen needed).

    Returns ``(private, public)``: the private key in the OpenSSH format, unencrypted, ending
    with a newline (write it with mode 0600), and the public key line ``ssh-ed25519 AAAA…
    [comment]`` without newline.  Meant for ``Data.generate()``: the pair is stored in the data
    of the project and written to the machines by the states.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return private, (f"{public} {comment}" if comment else public)


def public_key_fingerprint(public_line: str) -> str:
    """``SHA256:…`` of a public key line (``type base64 [comment]``), as ssh-keygen -l prints it;
    '' when the line holds no key."""
    parts = (public_line or "").split()
    if len(parts) < 2:
        return ""
    try:
        blob = _base64.b64decode(parts[1], validate=True)
    except (ValueError, _base64.binascii.Error):
        return ""
    return "SHA256:" + _base64.b64encode(_hashlib.sha256(blob).digest()).decode().rstrip("=")


def public_key_blob(public_line: str) -> str:
    """The base64 field of a public key or certificate line ('' when there is none)."""
    parts = (public_line or "").split()
    return parts[1] if len(parts) >= 2 else ""


@_dataclass
class KeyFingerprint:
    """A line of ``ssh-keygen -l -f``: ``256 SHA256:… comment (ED25519)``."""
    bits: int
    fingerprint: str
    comment: str
    key_type: str


def parse_key_fingerprint(text: str) -> Optional[KeyFingerprint]:
    """The first ``ssh-keygen -l`` line of *text*, or None."""
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(SHA256:\S+|MD5:\S+)\s*(.*?)\s*\(([^()]+)\)\s*$", line)
        if m:
            return KeyFingerprint(int(m.group(1)), m.group(2), m.group(3), m.group(4))
    return None


def get_key_fingerprint(grade: Grade0, machine: str, path: str, step: int = 1) -> Optional[KeyFingerprint]:
    """``ssh-keygen -l -f path`` on *machine* (a public key, a private key or a certificate)."""
    output, _ = grade.test(machine_name=machine, command=f"ssh-keygen -l -f {shlex.quote(path)} 2>&1",
                           step=step, allow_error=True)
    return parse_key_fingerprint(output)


def parse_ssh_config_dump(text: str) -> Dict[str, List[str]]:
    """The ``keyword value`` lines of ``ssh -G`` or ``sshd -T``: {keyword (lower case): [values]}.

    A keyword printed several times (``identityfile``, ``localforward``, ``hostcertificate``…)
    keeps every value in order; a keyword without value gets ''.
    """
    values: Dict[str, List[str]] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(_MARK) or not re.match(r"^[A-Za-z][A-Za-z0-9]*(\s|$)", line):
            continue
        key, _, value = line.partition(" ")
        values.setdefault(key.lower(), []).append(value.strip())
    return values


def config_value(values: Dict[str, List[str]], key: str, default: str = "") -> str:
    """The first value of *key* in a parsed ``ssh -G`` / ``sshd -T`` dump."""
    found = values.get(key.lower())
    return found[0] if found else default


def get_ssh_client_config(grade: Grade0, machine: str, user: str, host: str, step: int = 1) -> Dict[str, List[str]]:
    """``ssh -G host`` run by *user* on *machine*: what the client configuration of that user
    (``~/.ssh/config`` and ``/etc/ssh/ssh_config``) gives for *host*, without connecting.
    {} when ssh refuses the configuration."""
    command = f"su - {shlex.quote(user)} -c {shlex.quote('ssh -G ' + shlex.quote(host))} 2>/dev/null"
    output, code = grade.test(machine_name=machine, command=command, step=step, allow_error=True)
    return parse_ssh_config_dump(output) if code == 0 else {}


@_dataclass
class SshdConfig:
    """What ``get_sshd_config()`` learned of the sshd of a machine.

    ``values``: the effective configuration (``sshd -T``, for a connection when one was given);
    ``valid``: ``sshd -T`` accepted the configuration; ``running``: the process of
    ``/run/sshd.pid`` is alive; ``stale``: the configuration files written after sshd started
    (``sshd_config`` and ``*.conf`` under ``/etc/ssh``, newer than the pid file): a change not
    applied yet.
    """
    values: Dict[str, List[str]] = _field(default_factory=dict)
    valid: bool = False
    running: bool = False
    stale: List[str] = _field(default_factory=list)

    def get(self, key: str, default: str = "") -> str:
        return config_value(self.values, key, default)

    @property
    def applied(self) -> bool:
        """The configuration is valid, sshd runs and nothing was written after it started."""
        return self.valid and self.running and not self.stale


def sshd_config_cmd(connection: Optional[Dict[str, str]] = None) -> str:
    """The shell command of ``get_sshd_config()``."""
    spec = ""
    if connection:
        spec = " -C " + shlex.quote(",".join(f"{k}={v}" for k, v in connection.items()))
    return (f"sshd -T{spec} 2>&1; echo \"{_MARK} rc=$?\"; "
            f"if [ -f /run/sshd.pid ] && kill -0 \"$(cat /run/sshd.pid)\" 2>/dev/null; "
            f"then echo '{_MARK} running'; fi; "
            f"find /etc/ssh -newer /run/sshd.pid \\( -name '*.conf' -o -name sshd_config \\) 2>/dev/null "
            f"| sed 's/^/{_MARK} stale /'")


def parse_sshd_config(output: str) -> SshdConfig:
    config = SshdConfig(values=parse_ssh_config_dump(output))
    for line in (output or "").splitlines():
        if line.startswith(f"{_MARK} rc="):
            config.valid = line.strip() == f"{_MARK} rc=0"
        elif line.strip() == f"{_MARK} running":
            config.running = True
        elif line.startswith(f"{_MARK} stale "):
            config.stale.append(line[len(f"{_MARK} stale "):].strip())
    if not config.valid:
        config.values = {}
    return config


def get_sshd_config(grade: Grade0, machine: str, connection: Optional[Dict[str, str]] = None,
                    step: int = 1) -> SshdConfig:
    """The sshd of *machine*: effective configuration (``sshd -T``, with ``-C`` when
    *connection* is given, e.g. ``{'user': 'upload', 'host': 'laptop', 'addr': '10.0.0.5'}``,
    so that the ``Match`` blocks are evaluated for that connection), whether sshd runs and the
    configuration files written since it started (one command)."""
    output, _ = grade.test(machine_name=machine, command=sshd_config_cmd(connection), step=step,
                           allow_error=True)
    return parse_sshd_config(output)


@_dataclass
class SshCertificate:
    """``ssh-keygen -L -f <certificate>``.

    ``kind``: 'user' or 'host'; ``public_key`` / ``ca``: the ``SHA256:…`` fingerprints of the
    certified key and of the signing CA; ``valid_from`` / ``valid_to``: None when unbounded (the
    times are those of the machine, compared with its clock ``now``).
    """
    kind: str = ""
    cert_type: str = ""
    public_key: str = ""
    ca: str = ""
    ca_type: str = ""
    key_id: str = ""
    serial: int = -1
    valid_from: Optional[_datetime] = None
    valid_to: Optional[_datetime] = None
    principals: List[str] = _field(default_factory=list)
    critical_options: List[str] = _field(default_factory=list)
    extensions: List[str] = _field(default_factory=list)
    now: Optional[_datetime] = None

    @property
    def forever(self) -> bool:
        return self.valid_from is None and self.valid_to is None

    def valid_at(self, when: Optional[_datetime] = None) -> bool:
        when = when or self.now
        if when is None:
            return False
        return ((self.valid_from is None or self.valid_from <= when)
                and (self.valid_to is None or when < self.valid_to))

    @property
    def lifetime_seconds(self) -> Optional[float]:
        """Seconds between the bounds; None when one of them is open."""
        if self.valid_from is None or self.valid_to is None:
            return None
        return (self.valid_to - self.valid_from).total_seconds()


def _cert_time(text: str) -> Optional[_datetime]:
    try:
        return _datetime.fromisoformat(text.strip())
    except ValueError:
        return None


def parse_ssh_certificate(text: str) -> Optional[SshCertificate]:
    """The certificate printed by ``ssh-keygen -L`` in *text* (None when there is none). A line
    ``==SRE-SSH== now <ISO time>`` sets ``now`` (``get_ssh_certificate()`` adds it)."""
    cert = SshCertificate()
    seen = False
    section = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith(f"{_MARK} now "):
            cert.now = _cert_time(line[len(f"{_MARK} now "):])
            continue
        m = re.match(r"^(Type|Public key|Signing CA|Key ID|Serial|Valid|Principals|Critical Options|Extensions):\s*(.*)$",
                     line)
        if m:
            name, value = m.group(1), m.group(2).strip()
            section = None
            if name == "Type":
                seen = True
                parts = value.split()
                cert.cert_type = parts[0] if parts else ""
                cert.kind = "user" if " user certificate" in f" {value}" else (
                    "host" if " host certificate" in f" {value}" else "")
            elif name == "Public key":
                parts = value.split()
                cert.public_key = parts[1] if len(parts) >= 2 else ""
            elif name == "Signing CA":
                parts = value.split()
                cert.ca_type = parts[0] if parts else ""
                cert.ca = parts[1] if len(parts) >= 2 else ""
            elif name == "Key ID":
                cert.key_id = value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
            elif name == "Serial":
                try:
                    cert.serial = int(value)
                except ValueError:
                    cert.serial = -1
            elif name == "Valid":
                mv = re.match(r"^from (\S+) to (\S+)$", value)
                if mv:
                    cert.valid_from, cert.valid_to = _cert_time(mv.group(1)), _cert_time(mv.group(2))
                elif value.startswith("after "):
                    cert.valid_from = _cert_time(value[len("after "):])
                elif value.startswith("before "):
                    cert.valid_to = _cert_time(value[len("before "):])
            else:
                section = {"Principals": cert.principals, "Critical Options": cert.critical_options,
                           "Extensions": cert.extensions}[name]
                if value and value != "(none)":
                    section.append(value)
            continue
        if section is not None and line and line != "(none)":
            section.append(line)
    return cert if seen else None


def get_ssh_certificate(grade: Grade0, machine: str, path: str, step: int = 1) -> Optional[SshCertificate]:
    """``ssh-keygen -L -f path`` on *machine*, with the clock of the machine (``now``)."""
    command = (f"ssh-keygen -L -f {shlex.quote(path)} 2>&1; "
               f"echo \"{_MARK} now $(date +%Y-%m-%dT%H:%M:%S)\"")
    output, _ = grade.test(machine_name=machine, command=command, step=step, allow_error=True)
    return parse_ssh_certificate(output)


@_dataclass
class AcceptedLogin:
    """An ``Accepted <method> for <user> from <source> port <port> ssh2[: <key>]`` line of sshd.

    ``key``: what follows ``ssh2:`` (``ED25519 SHA256:…`` for a key,
    ``ED25519-CERT SHA256:… ID <id> (serial <n>) CA ED25519 SHA256:…`` for a certificate);
    ``session``: the next line opens the PAM session of the user.
    """
    user: str
    method: str
    source: str
    port: int
    key: str = ""
    session: bool = False

    @property
    def certificate(self) -> bool:
        return "-CERT " in f"{self.key} "

    @property
    def key_fingerprint(self) -> str:
        parts = self.key.split()
        return parts[1] if len(parts) >= 2 else ""

    @property
    def ca_fingerprint(self) -> str:
        m = re.search(r"\bCA \S+ (SHA256:\S+)", self.key)
        return m.group(1) if m else ""

    @property
    def cert_id(self) -> str:
        m = re.search(r"\bID (.*) \(serial -?\d+\) CA ", self.key)
        return m.group(1) if m else ""


_ACCEPTED_RE = re.compile(r"\bsshd(?:-session)?\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+) ssh2(?:: (.*))?$")


def parse_accepted_logins(log_output: str) -> List[AcceptedLogin]:
    """Every accepted login of an auth.log, in order."""
    lines = (log_output or "").splitlines()
    logins = []
    for i, line in enumerate(lines):
        m = _ACCEPTED_RE.search(line)
        if not m:
            continue
        method, user, source, port, key = m.groups()
        session = (i + 1 < len(lines) and _SSHD_TAG_RE.search(lines[i + 1]) is not None
                   and f"pam_unix(sshd:session): session opened for user {user}" in lines[i + 1])
        logins.append(AcceptedLogin(user, method, source, int(port), (key or "").strip(), session))
    return logins


@_dataclass
class Listener:
    """A listening TCP socket of ``ss -Hltne``: local address, port, owner (uid) and, when ss can
    read them, the names of the processes (``-p``: only for the processes of root, without
    ``CAP_SYS_PTRACE`` in a container)."""
    address: str
    port: int
    uid: Optional[int] = None
    processes: List[str] = _field(default_factory=list)


def parse_ss_listeners(output: str) -> List[Listener]:
    """The ``LISTEN`` sockets of ``ss -Hltne`` / ``ss -Hltnp`` output (with or without header)."""
    listeners = []
    for line in (output or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] != "LISTEN":
            continue
        m = re.match(r"^(\[[^\]]*\]|[^\s\[\]]*?)(?:%\S+)?:(\d+)$", fields[3])
        if not m:
            continue
        address = m.group(1).strip("[]")
        uid = re.search(r"\buid:(\d+)\b", line)
        listeners.append(Listener(address, int(m.group(2)), int(uid.group(1)) if uid else None,
                                  re.findall(r'\("([^"]+)",pid=', line)))
    return listeners


def ssh_listener_cmd() -> str:
    """The command whose output ``parse_ss_listeners()`` reads (``-e``: the uid of each socket;
    the cgroup warning of ss in a container dropped)."""
    return "ss -Hltne 2>/dev/null"


def parse_keyscan_certificates(output: str) -> List[str]:
    """The base64 blobs of the host certificates printed by ``ssh-keyscan -c`` (the lines whose
    type ends with ``-cert-v01@openssh.com``, with or without the host name in front)."""
    blobs = []
    for line in (output or "").splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        for i, part in enumerate(parts[:-1]):
            if part.endswith("-cert-v01@openssh.com"):
                blobs.append(parts[i + 1])
                break
    return blobs
