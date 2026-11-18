"""Who runs the Qt GUI on this machine?  A pool host is a classroom workstation: a student who
sits at it may work in the local GUI (``sysreseval``) rather than in a browser.  The agent tells
the portal who they are in its status (``gui_users``), for the Clients view of the Watch page
and the count of the clients of a project.

The GUIs are found among the processes of the machine (``SRE.procscan.gui_processes``: a Python
interpreter running ``sysreseval.py`` outside any container), the pid file of the GUI being left
behind by a GUI that was killed.  A GUI open without any project is listed too.
"""
import pwd

from SRE import procscan

from .occupancy import SYSTEM_UID_MAX

#: The full name is cut to this length (the GECOS field is free text).
MAX_FULLNAME = 128


class Users:
    """``uid`` → ``(login, full name)`` from the password database (*lookup*:
    ``pwd.getpwuid``), the answers kept: on a pool host a lookup may ask the directory.  An
    unknown uid gives its number as the login and is asked again the next time."""

    def __init__(self, lookup=pwd.getpwuid):
        self.lookup = lookup
        self._known: dict[int, tuple] = {}

    def __call__(self, uid: int) -> tuple:
        known = self._known.get(uid)
        if known is None:
            try:
                entry = self.lookup(uid)
            except KeyError:
                return str(uid), ''
            fullname = ''.join(c for c in (entry.pw_gecos or '').split(',')[0] if c.isprintable())
            known = self._known[uid] = (entry.pw_name, fullname.strip()[:MAX_FULLNAME])
        return known


def gui_users(proc: str = '/proc', *, user_of=None, uid_of=None) -> list:
    """The users with a running Qt GUI, by login: ``{'login', 'fullname', 'since'}``, one entry
    per user (*since*: the start of their oldest GUI in epoch seconds, ``None`` when unknown).
    The system accounts are left out, as for the local sessions.  *user_of(uid)* gives
    ``(login, full name)`` (a :class:`Users` by default), *uid_of* is that of
    ``procscan.gui_processes``."""
    if user_of is None:
        user_of = Users()
    users = {}
    for process in procscan.gui_processes(proc, uid_of=uid_of):
        if process['uid'] <= SYSTEM_UID_MAX:
            continue
        login, fullname = user_of(process['uid'])
        since = process['since']
        known = users.get(login)
        if known is None:
            users[login] = {'login': login, 'fullname': fullname, 'since': since}
        elif since is not None and (known['since'] is None or since < known['since']):
            known['since'] = since
    return [users[login] for login in sorted(users)]
