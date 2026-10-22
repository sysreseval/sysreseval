"""Is the machine used locally?  A pool host is a classroom workstation: when a student sits at
it (a local login session) or runs projects with the Qt GUI (projects not started by the agent),
the web must not land new projects on it.  The agent reports it in its status; the portal then
places nothing there and never powers it off.

The sessions come from ``loginctl`` (systemd-logind: a session of class ``user`` on a seat or a
tty, not remote), with ``who`` as a fallback (a tty or an X display); both run through *run*
(``subprocess.run`` by default, a fake in the tests)."""
import subprocess

SYSTEM_UID_MAX = 999


def _run(run, argv) -> str:
    try:
        result = run(argv, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ''
    return result.stdout if result.returncode == 0 else ''


def loginctl_sessions(run=subprocess.run) -> list | None:
    """The user names of the local login sessions seen by logind; ``None`` when ``loginctl``
    is not usable (then :func:`who_sessions` is the fallback)."""
    listing = _run(run, ['loginctl', 'list-sessions', '--no-legend'])
    if not listing:
        return None
    users = []
    for line in listing.splitlines():
        fields = line.split()
        if not fields:
            continue
        details = _run(run, ['loginctl', 'show-session', fields[0], '-p', 'Name', '-p', 'Seat', '-p', 'TTY',
                             '-p', 'Class', '-p', 'Remote', '-p', 'User'])
        props = dict(item.split('=', 1) for item in details.splitlines() if '=' in item)
        if props.get('Remote', 'no') == 'yes' or props.get('Class', 'user') != 'user':
            continue
        if not (props.get('Seat') or props.get('TTY')):
            continue
        try:
            if int(props.get('User', '0') or 0) <= SYSTEM_UID_MAX:
                continue
        except ValueError:
            pass
        name = props.get('Name', '')
        if name and name not in users:
            users.append(name)
    return users


def who_sessions(run=subprocess.run) -> list:
    """The user names of the local sessions of ``who``: a tty, or an X display in the comment."""
    users = []
    for line in _run(run, ['who']).splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name, line_name = fields[0], fields[1]
        comment = fields[-1] if fields[-1].startswith('(') else ''
        if line_name.startswith('tty') or line_name.startswith(':') or comment.startswith('(:'):
            if name not in users:
                users.append(name)
    return users


def local_sessions(run=subprocess.run) -> list:
    sessions = loginctl_sessions(run)
    return who_sessions(run) if sessions is None else sessions


def occupancy(check: str, local_projects: int, run=subprocess.run) -> tuple:
    """``(occupied, reasons)`` for the ``occupied_check`` setting of the agent."""
    reasons = []
    if check in ('sessions', 'both'):
        reasons += [f'session:{user}' for user in local_sessions(run)]
    if check in ('projects', 'both') and local_projects > 0:
        reasons.append(f'projects:{local_projects}')
    return bool(reasons), reasons
