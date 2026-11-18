"""The clients of the Watch page: who is connected, and with what.

Two kinds of clients, both read from what the portal already holds (pure functions: the routes
hand them the presence sockets, the open sessions and the status of the hosts):

- the **browsers** connected to the portal (:func:`web_clients`), one row per browser.  Every
  page of a logged-in user keeps a presence socket open (``presentation.Presence``); the
  sockets of one browser are told by the random id it keeps and sends (``?client=``, see
  ``base.js``: one per browser profile, a private window having its own), or, without an id
  (a blocked storage), by its address and ``User-Agent``.  A page that said it is being left
  (``away``) is not a page shown, and a browser whose pages are all away is not listed;
- the users in the **Qt GUI** of a pool host (:func:`local_clients`), as the agents report
  them in their status (``pool.Pool.gui_users()``).

:func:`annotate_projects` counts, for each row of the Projects table, the clients of the
**owner** on the project: their browsers showing its page and their Qt GUI on its host, which
shows every project they have there.  Nobody else counts: neither an instructor who opened the
page nor the spectators of a presentation — and a socket of another user claiming the page of
a project (the page is what the browser says) changes nothing.

The id of a browser stays here: it is neither logged nor sent to a page.
"""
from urllib.parse import unquote

from .useragent import clean_user_agent, parse_user_agent
from ..identity import running_lab_name_owner

#: The browsers listed per login (the oldest ones): a script opening sockets under fresh ids
#: cannot flood the view.
MAX_BROWSERS_PER_LOGIN = 20
PROJECT_PAGE_PREFIX = '/projects/'


def page_project(page: str) -> tuple | None:
    """``(host, running lab name)`` of the path of a project page
    (``/projects/<host>/<quoted running lab name>``), ``None`` for any other page."""
    if not isinstance(page, str) or not page.startswith(PROJECT_PAGE_PREFIX):
        return None
    parts = page[len(PROJECT_PAGE_PREFIX):].split('/')
    if len(parts) != 2 or not parts[0]:
        return None
    host, rln = unquote(parts[0]), unquote(parts[1])
    if running_lab_name_owner(rln) is None:
        return None
    return host, rln


def browser_key(socket) -> tuple:
    """What tells the browser of a presence socket apart: its login with the id the browser
    sent, else with its address and ``User-Agent``."""
    login = socket.identity.login
    if socket.client:
        return login, 'id', socket.client
    return login, 'ua', socket.addr, socket.ua


def _browsers(sockets) -> dict:
    """The sockets of each browser showing at least one page: ``{browser key: [sockets]}``,
    the away sockets left out."""
    browsers = {}
    for socket in sockets:
        if not socket.away:
            browsers.setdefault(browser_key(socket), []).append(socket)
    return browsers


def _pages(sockets) -> list:
    pages = []
    for path in sorted({socket.page for socket in sockets if socket.page}):
        project = page_project(path)
        pages.append({'path': path, 'host': project[0] if project else None, 'rln': project[1] if project else None})
    return pages


def web_clients(sockets, *, visit_of=lambda key: None, limit: int = MAX_BROWSERS_PER_LOGIN) -> list:
    """One row per browser connected to the portal, by login then age: the identity of its
    newest socket (``login``, ``fullname``, ``group``, ``role``), the browser (``browser``,
    ``version``, ``system``, ``mobile`` of ``useragent.parse_user_agent``, ``ua`` = the header
    cleaned), ``addrs`` (the client addresses of its sockets), ``since`` (epoch seconds: the
    start of the session of the login from one of those addresses — *visit_of((login, addr))*,
    the ``accesslog.Visit`` or ``None`` —, else the oldest socket: a navigation opens a new one),
    ``tabs`` (the pages open) and ``pages`` (``[{path, host, rln}]``, the distinct ones, *host*
    and *rln* set for a project page).  At most *limit* browsers per login."""
    rows = []
    per_login = {}
    for key, group in _browsers(sockets).items():
        newest = max(group, key=lambda s: s.since)
        identity = newest.identity
        addrs = sorted({socket.addr for socket in group if socket.addr})
        starts = [visit.first_seen for visit in (visit_of((identity.login, addr)) for addr in addrs) if visit is not None]
        since = min(starts) if starts else min(socket.since for socket in group)
        rows.append({'login': identity.login, 'fullname': identity.fullname, 'group': identity.group,
                     'role': identity.role, **parse_user_agent(newest.ua), 'ua': clean_user_agent(newest.ua),
                     'addrs': addrs, 'since': round(since, 3), 'tabs': len(group), 'pages': _pages(group)})
    rows.sort(key=lambda row: (row['login'], row['since'], row['browser'], row['ua']))
    kept = []
    for row in rows:
        count = per_login.get(row['login'], 0)
        if count < limit:
            per_login[row['login']] = count + 1
            kept.append(row)
    return kept


def local_clients(gui_users: dict) -> list:
    """One row per user in the Qt GUI of a pool host (*gui_users*: ``Pool.gui_users()``), by
    host then login: ``host``, ``login``, ``fullname`` (the name of the account on the host),
    ``group`` (``''``: the directory completes it), ``since`` (the start of the GUI in epoch
    seconds, ``None`` unknown) and ``managed`` false, which lets ``roles.complete_owners`` give
    the directory's full name as for the projects of the Qt GUI."""
    rows = []
    for host in sorted(gui_users):
        for user in sorted(gui_users[host], key=lambda u: u['login']):
            rows.append({'host': host, 'login': user['login'], 'fullname': user.get('fullname', ''), 'group': '',
                         'since': user.get('since'), 'managed': False})
    return rows


def annotate_projects(rows: list, sockets, gui_users: dict) -> list:
    """``row['clients']`` = the clients of the owner on the project of each Watch row (the
    owner's browsers showing the project's page + 1 for their Qt GUI on the row's host) and
    ``row['client_local']`` = whether that GUI is one of them."""
    showing = {}
    for key, group in _browsers(sockets).items():
        for socket in group:
            project = page_project(socket.page)
            if project is not None and running_lab_name_owner(project[1]) == socket.identity.login:
                showing.setdefault(project, set()).add(key)
    local = {host: {user['login'] for user in users} for host, users in gui_users.items()}
    for row in rows:
        host, rln, owner = row.get('host'), row.get('running_lab_name'), row.get('owner')
        in_gui = bool(owner) and owner in local.get(host, ())
        row['clients'] = len(showing.get((host, rln), ())) + (1 if in_gui else 0)
        row['client_local'] = in_gui
    return rows
