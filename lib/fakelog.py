import datetime
import os
import random
import shlex

from SRE.lib_sre import NetScheme0

# English month abbreviations — hardcoded so timestamp rendering never depends
# on the host locale (strftime("%b") would).
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Reusable content pools. Small on purpose so values repeat across lines the way
# they do in real logs (a handful of clients, a handful of accounts, ...).
_USERS = ["root", "admin", "alice", "bob", "carol", "dave", "www-data",
          "backup", "mysql", "postgres", "ubuntu", "deploy", "git", "nagios"]
_BAD_USERS = ["oracle", "test", "guest", "pi", "user", "administrator",
              "ftpuser", "support", "hadoop", "ubnt"]
_WEB_PATHS = ["/", "/index.html", "/favicon.ico", "/robots.txt", "/login",
              "/logout", "/admin", "/admin/login.php", "/wp-login.php",
              "/api/v1/users", "/api/v1/status", "/static/app.js",
              "/static/style.css", "/images/logo.png", "/downloads/report.pdf",
              "/search?q=test", "/products", "/products/42", "/cart", "/checkout"]
_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "curl/8.6.0",
    "Wget/1.21.4",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]
# HTTP methods and status codes with rough real-world weights.
_METHODS = (["GET"] * 8) + ["POST", "POST", "HEAD"]
_STATUSES = ([200] * 16) + [304, 304, 301, 302, 404, 404, 403, 401, 500]
# Generic syslog daemons; None in the pid slot means "no [pid]" (e.g. kernel).
_SYSLOG_DAEMONS = ["systemd", "systemd-logind", "cron", "CRON", "dbus-daemon",
                   "kernel", "sshd", "systemd-resolved", "networkd-dispatcher"]
_SYSLOG_MSGS = [
    "Starting Daily apt download activities...",
    "Started Session {n} of user root.",
    "pam_unix(cron:session): session opened for user root by (uid=0)",
    "pam_unix(cron:session): session closed for user root",
    "Reached target Multi-User System.",
    "Time has been changed",
    "Failed to start Rotate log files.",
    "Received SIGTERM from PID 1 (systemd).",
    "Server listening on 0.0.0.0 port 22.",
    "Deactivated successfully.",
]


def _rand_ip(rnd):
    """Return a random, plausibly-public IPv4 address string."""
    return f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"


def _syslog_ts(dt):
    """Render *dt* as a syslog timestamp, e.g. ``Jul  2 13:55:36`` (space-padded day)."""
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def _apache_ts(dt, tz="+0000"):
    """Render *dt* as an Apache CLF timestamp, e.g. ``02/Jul/2026:13:55:36 +0000``."""
    return f"{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} {tz}"


def _bump(stats, section, key):
    """Increment ``stats[section][key]`` (a nested counter dict)."""
    stats.setdefault(section, {})
    stats[section][key] = stats[section].get(key, 0) + 1


def _gen_apache(rnd, dt, hostname, ctx, stats):
    """One Apache/nginx combined-log-format access line."""
    ip = rnd.choice(ctx["ips"])
    method = rnd.choice(_METHODS)
    path = rnd.choice(_WEB_PATHS)
    status = rnd.choice(_STATUSES)
    size = rnd.randint(120, 45000)
    ua = rnd.choice(_USER_AGENTS)
    _bump(stats, "status_counts", status)
    _bump(stats, "method_counts", method)
    _bump(stats, "ip_counts", ip)
    stats["bytes_total"] = stats.get("bytes_total", 0) + size
    return (f'{ip} - - [{_apache_ts(dt)}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{ua}"')


def _gen_auth(rnd, dt, hostname, ctx, stats):
    """One sshd auth.log line (accepted / failed / invalid-user login)."""
    pid = rnd.randint(600, 30000)
    ip = rnd.choice(ctx["ips"])
    port = rnd.randint(1024, 65535)
    roll = rnd.random()
    if roll < 0.45:
        user = rnd.choice(_USERS)
        _bump(stats, "user_counts", user)
        _bump(stats, "ip_counts", ip)
        stats["accepted"] = stats.get("accepted", 0) + 1
        body = f"Accepted password for {user} from {ip} port {port} ssh2"
    elif roll < 0.80:
        user = rnd.choice(_USERS)
        _bump(stats, "user_counts", user)
        _bump(stats, "ip_counts", ip)
        stats["failed"] = stats.get("failed", 0) + 1
        body = f"Failed password for {user} from {ip} port {port} ssh2"
    else:
        user = rnd.choice(_BAD_USERS)
        _bump(stats, "ip_counts", ip)
        stats["invalid"] = stats.get("invalid", 0) + 1
        body = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    return f"{_syslog_ts(dt)} {hostname} sshd[{pid}]: {body}"


def _gen_ldap(rnd, dt, hostname, ctx, stats):
    """One OpenLDAP slapd line (BIND / SRCH / RESULT / UNBIND)."""
    pid = rnd.randint(400, 5000)
    conn = rnd.randint(1000, 9999)
    op = rnd.randint(0, 12)
    base = ctx["ldap_base"]
    roll = rnd.random()
    if roll < 0.30:
        user = rnd.choice(_USERS)
        stats["binds"] = stats.get("binds", 0) + 1
        body = f'conn={conn} op={op} BIND dn="uid={user},ou=people,{base}" method=128'
    elif roll < 0.70:
        stats["searches"] = stats.get("searches", 0) + 1
        body = (f'conn={conn} op={op} SRCH base="{base}" scope=2 deref=0 '
                f'filter="(uid={rnd.choice(_USERS)})"')
    elif roll < 0.92:
        stats["results"] = stats.get("results", 0) + 1
        body = f"conn={conn} op={op} RESULT tag=101 err=0 text="
    else:
        stats["unbinds"] = stats.get("unbinds", 0) + 1
        body = f"conn={conn} op={op} UNBIND"
    return f"{_syslog_ts(dt)} {hostname} slapd[{pid}]: {body}"


def _gen_syslog(rnd, dt, hostname, ctx, stats):
    """One generic /var/log/syslog line from a mix of common daemons."""
    daemon = rnd.choice(_SYSLOG_DAEMONS)
    msg = rnd.choice(_SYSLOG_MSGS).replace("{n}", str(rnd.randint(1, 500)))
    _bump(stats, "by_daemon", daemon)
    if daemon == "kernel":
        prefix = f"{_syslog_ts(dt)} {hostname} kernel:"
    else:
        prefix = f"{_syslog_ts(dt)} {hostname} {daemon}[{rnd.randint(300, 30000)}]:"
    return f"{prefix} {msg}"


def _gen_mail(rnd, dt, hostname, ctx, stats):
    """One Postfix mail.log line (connect / message / disconnect)."""
    pid = rnd.randint(600, 30000)
    ip = rnd.choice(ctx["ips"])
    roll = rnd.random()
    if roll < 0.35:
        stats["connects"] = stats.get("connects", 0) + 1
        body = f"smtpd[{pid}]: connect from unknown[{ip}]"
    elif roll < 0.80:
        qid = "".join(rnd.choice("0123456789ABCDEF") for _ in range(10))
        user = rnd.choice(_USERS)
        stats["messages"] = stats.get("messages", 0) + 1
        body = (f"qmgr[{pid}]: {qid}: from=<{user}@example.org>, "
                f"size={rnd.randint(400, 90000)}, nrcpt=1 (queue active)")
    else:
        stats["disconnects"] = stats.get("disconnects", 0) + 1
        body = f"smtpd[{pid}]: disconnect from unknown[{ip}]"
    return f"{_syslog_ts(dt)} {hostname} postfix/{body}"


# server alias -> (line generator, default log path)
_SERVERS = {
    "syslog": (_gen_syslog, "/var/log/syslog"),
    "apache2": (_gen_apache, "/var/log/apache2/access.log"),
    "apache": (_gen_apache, "/var/log/apache2/access.log"),
    "httpd": (_gen_apache, "/var/log/httpd/access_log"),
    "nginx": (_gen_apache, "/var/log/nginx/access.log"),
    "auth": (_gen_auth, "/var/log/auth.log"),
    "sshd": (_gen_auth, "/var/log/auth.log"),
    "ssh": (_gen_auth, "/var/log/auth.log"),
    "ldap": (_gen_ldap, "/var/log/slapd.log"),
    "slapd": (_gen_ldap, "/var/log/slapd.log"),
    "mail": (_gen_mail, "/var/log/mail.log"),
    "postfix": (_gen_mail, "/var/log/mail.log"),
}


def _resolve_window(start, end):
    """Return (start, end) datetimes, defaulting to the last 24h; validate order."""
    if end is None:
        end = datetime.datetime.now()
    if start is None:
        start = end - datetime.timedelta(days=1)
    if start > end:
        raise ValueError(f"fakelog: start ({start}) is after end ({end})")
    return start, end


def _top(stats, section):
    """Return the key with the highest count in ``stats[section]`` (or None)."""
    d = stats.get(section)
    if not d:
        return None
    return max(d, key=d.get)


def fakelog_content(count=30000, start=None, end=None, server="syslog",
                    hostname="host", seed=None):
    """Return ``(log_text, stats)`` for a fake *server* log of *count* lines.

    Lines are timestamped non-decreasingly across ``[start, end]`` (defaulting to
    the last 24h). *server* selects the log format (``apache2``/``nginx``,
    ``auth``/``sshd``, ``ldap``/``slapd``, ``syslog``, ``mail``/``postfix``).
    Output is deterministic for a given *seed*.

    *stats* is a summary dict — ``count``, ``server``, ``start``/``end`` (ISO) plus
    server-specific tallies (e.g. ``status_counts`` for web, ``failed``/``accepted``
    for auth) — handy for building grading questions with known answers.
    """
    key = server.lower()
    if key not in _SERVERS:
        raise ValueError(f"fakelog: unknown server {server!r}; "
                         f"choose one of {sorted(_SERVERS)}")
    gen, _ = _SERVERS[key]
    start, end = _resolve_window(start, end)

    rnd = random.Random(seed)
    ctx = {
        "ips": [_rand_ip(rnd) for _ in range(rnd.randint(15, 40))],
        "ldap_base": "dc=example,dc=org",
    }

    span = (end - start).total_seconds()
    offsets = sorted(rnd.uniform(0, span) for _ in range(count))

    stats = {}
    lines = []
    for off in offsets:
        dt = start + datetime.timedelta(seconds=off)
        lines.append(gen(rnd, dt, hostname, ctx, stats))

    # Promote the busiest client / account into a convenient top-level field.
    if "ip_counts" in stats:
        stats["top_ip"] = _top(stats, "ip_counts")
    if "user_counts" in stats:
        stats["top_user"] = _top(stats, "user_counts")

    stats.update(count=count, server=key,
                 start=start.isoformat(), end=end.isoformat())
    content = "".join(line + "\n" for line in lines)
    return content, stats


def fakelog(net_scheme: NetScheme0, machine: str, count=30000, file=None,
            start=None, end=None, server="syslog", hostname=None, seed=None,
            permissions=0o640, owner="root:adm", step=1):
    """Write a fake *server* log of *count* lines to *file* on *machine*.

    Entries are spread non-decreasingly across ``[start, end]`` (defaulting to the
    last 24h). *server* picks the format and, when *file* is None, a sensible
    default path (e.g. ``apache2`` -> ``/var/log/apache2/access.log``). *hostname*
    defaults to *machine*. Pass *seed* for reproducible content.

    The file's mtime is set to *end* (the time of the last entry). Returns the
    stats summary produced by :func:`fakelog_content` (with *file*/*machine* added);
    the return value may be ignored when only the file is needed.
    """
    key = server.lower()
    if key not in _SERVERS:
        raise ValueError(f"fakelog: unknown server {server!r}; "
                         f"choose one of {sorted(_SERVERS)}")
    _, default_path = _SERVERS[key]
    file = file or default_path
    if hostname is None:
        hostname = machine
    start, end = _resolve_window(start, end)

    content, stats = fakelog_content(count=count, start=start, end=end,
                                     server=key, hostname=hostname, seed=seed)

    # Create the parent directory first (same step, registered before the write
    # so it runs first): Docker put_archive's in-place fallback writes with '>'
    # and would fail if e.g. /var/log/apache2/ does not exist yet.
    parent = os.path.dirname(file)
    if parent not in ("", "/"):
        net_scheme.cmd(machine, f"mkdir -p {shlex.quote(parent)}", step=step)

    net_scheme.file(machine=machine, filename=file, content=content,
                    permissions=permissions, owner=owner,
                    mtime=end.timestamp(), step=step)

    stats.update(file=file, machine=machine)
    return stats


# ---------------------------------------------------------------------------
# auth.log (auth/authpriv facilities) — per-user SSH login sessions
# ---------------------------------------------------------------------------

# Pool of realistic login names for the auto-generated "other" users. Falls back
# to numbered users (user001, ...) when more than len(_NAMES) are requested.
_NAMES = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan",
    "judy", "mallory", "oscar", "peggy", "trent", "victor", "walter", "sybil",
    "craig", "erin", "faythe", "olivia", "noah", "emma", "liam", "mia", "lucas",
    "chloe", "hugo", "lea", "jules", "manon", "nathan", "sarah", "thomas",
    "jenkins", "deploy", "gitlab", "backup", "postgres", "mysql", "redis",
    "ftp", "operator", "guest", "ubuntu", "debian", "student", "teacher",
]

_KEY_TYPES = ["RSA", "ED25519", "ECDSA"]
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _rand_fp(rnd):
    """Return a fake base64 SSH key fingerprint (43 chars, like SHA256 output)."""
    return "".join(rnd.choice(_B64) for _ in range(43))


def _pick_other_usernames(rnd, count, exclude):
    """Return *count* distinct usernames not present in *exclude* (a set)."""
    pool = [n for n in _NAMES if n not in exclude]
    rnd.shuffle(pool)
    names = pool[:count]
    i = 1
    taken = set(names) | set(exclude)
    while len(names) < count:
        candidate = f"user{i:03d}"
        if candidate not in taken:
            names.append(candidate)
            taken.add(candidate)
        i += 1
    return names


def _login_lines(rnd, user, uid, t_open, t_close, hostname, sid, logind_pid):
    """Return the auth.log lines for one SSH login session of *user*.

    Six lines per session: the sshd "Accepted" line + pam session-opened + logind
    "New session" at *t_open* (facilities auth/authpriv), then pam session-closed +
    logind logout/removed at *t_close*.
    """
    ip = _rand_ip(rnd)
    port = rnd.randint(1024, 65535)
    pid = rnd.randint(1000, 30000)
    to = _syslog_ts(t_open)
    tc = _syslog_ts(t_close)
    if rnd.random() < 0.5:
        accepted = f"Accepted password for {user} from {ip} port {port} ssh2"
    else:
        accepted = (f"Accepted publickey for {user} from {ip} port {port} ssh2: "
                    f"{rnd.choice(_KEY_TYPES)} SHA256:{_rand_fp(rnd)}")
    return [
        (t_open, f"{to} {hostname} sshd[{pid}]: {accepted}"),
        (t_open, f"{to} {hostname} sshd[{pid}]: pam_unix(sshd:session): "
                 f"session opened for user {user}(uid={uid}) by (uid=0)"),
        (t_open, f"{to} {hostname} systemd-logind[{logind_pid}]: "
                 f"New session {sid} of user {user}."),
        (t_close, f"{tc} {hostname} sshd[{pid}]: pam_unix(sshd:session): "
                  f"session closed for user {user}"),
        (t_close, f"{tc} {hostname} systemd-logind[{logind_pid}]: "
                  f"Session {sid} logged out. Waiting for processes to exit."),
        (t_close, f"{tc} {hostname} systemd-logind[{logind_pid}]: Removed session {sid}."),
    ]


def _build_login_counts(rnd, users, other_users_count,
                        other_users_min_login, other_users_max_login):
    """Return an ordered {username: login_count} map (explicit users then others).

    Each auto-generated "other" user gets a random login count in
    ``[other_users_min_login, other_users_max_login]`` that differs from every
    count present in *users*, so users listed in *users* stay uniquely
    identifiable by their login count (assuming those counts are distinct).
    """
    if other_users_min_login < 0 or other_users_max_login < other_users_min_login:
        raise ValueError(
            f"fakeauthlog: invalid login range [{other_users_min_login}, "
            f"{other_users_max_login}]")
    forbidden = set(users.values())
    available = [c for c in range(other_users_min_login, other_users_max_login + 1)
                 if c not in forbidden]
    if other_users_count > 0 and not available:
        raise ValueError(
            "fakeauthlog: no login count left for other users in range "
            f"[{other_users_min_login}, {other_users_max_login}] after excluding "
            f"the counts used in `users` ({sorted(forbidden)})")

    login_counts = dict(users)
    for name in _pick_other_usernames(rnd, other_users_count, exclude=set(users)):
        login_counts[name] = rnd.choice(available)
    return login_counts


def fakeauthlog_content(users=None, other_users_count=0,
                        other_users_min_login=1, other_users_max_login=50,
                        start=None, end=None, hostname="host", seed=None):
    """Return ``(log_text, stats)`` emulating auth/authpriv (``/var/log/auth.log``).

    *users* is a ``{username: n_logins}`` map giving an exact number of SSH login
    sessions per named user. *other_users_count* extra users are generated, each
    with a random login count in ``[other_users_min_login, other_users_max_login]``
    that is different from every count in *users*. Each login is one full SSH
    session (accept + pam session open/close + logind new/removed), six lines,
    timestamped non-decreasingly across ``[start, end]`` (default: last 24h).
    Deterministic for a given *seed*.

    *stats* reports ``logins_per_user`` (all users), ``users``/``other_users``,
    ``total_logins`` and ``total_lines`` — the expected answers for grading.
    """
    users = dict(users or {})
    start, end = _resolve_window(start, end)
    rnd = random.Random(seed)

    login_counts = _build_login_counts(
        rnd, users, other_users_count, other_users_min_login, other_users_max_login)
    uids = {u: 1000 + i for i, u in enumerate(login_counts)}
    logind_pid = rnd.randint(300, 900)  # stable within a boot
    span = (end - start).total_seconds()

    events = []
    sid = 0
    for user, n in login_counts.items():
        for _ in range(n):
            sid += 1
            t_open = start + datetime.timedelta(seconds=rnd.uniform(0, span))
            duration = datetime.timedelta(seconds=rnd.uniform(30, 6 * 3600))
            t_close = min(t_open + duration, end)
            events.extend(_login_lines(rnd, user, uids[user], t_open, t_close,
                                       hostname, sid, logind_pid))

    events.sort(key=lambda tl: tl[0])  # stable: same-timestamp lines keep order
    content = "".join(line + "\n" for _, line in events)

    stats = {
        "logins_per_user": dict(login_counts),
        "users": dict(users),
        "other_users": {u: c for u, c in login_counts.items() if u not in users},
        "total_logins": sum(login_counts.values()),
        "total_lines": len(events),
        "start": start.isoformat(),
        "end": end.isoformat(),
        "hostname": hostname,
    }
    return content, stats


def fakeauthlog(net_scheme: NetScheme0, machine: str, users=None,
                other_users_count=0, other_users_min_login=1,
                other_users_max_login=50, file="/var/log/auth.log",
                start=None, end=None, hostname=None, seed=None,
                permissions=0o640, owner="root:adm", step=1):
    """Write a fake auth/authpriv log (``/var/log/auth.log`` by default) on *machine*.

    *users* is a ``{username: n_logins}`` map (e.g. ``{"alice": 3, "bob": 5}`` ->
    3 SSH logins for alice, 5 for bob). *other_users_count* extra users are added,
    each with a random login count in ``[other_users_min_login,
    other_users_max_login]`` that differs from every count in *users* (so, above,
    only alice has 3 logins and only bob has 5). Pass *file* to change the path,
    *seed* for reproducible content.

    The file's mtime is set to *end*. Returns the stats summary produced by
    :func:`fakeauthlog_content` (with *file*/*machine* added).
    """
    if hostname is None:
        hostname = machine
    start, end = _resolve_window(start, end)

    content, stats = fakeauthlog_content(
        users=users, other_users_count=other_users_count,
        other_users_min_login=other_users_min_login,
        other_users_max_login=other_users_max_login,
        start=start, end=end, hostname=hostname, seed=seed)

    parent = os.path.dirname(file)
    if parent not in ("", "/"):
        net_scheme.cmd(machine, f"mkdir -p {shlex.quote(parent)}", step=step)
    net_scheme.file(machine=machine, filename=file, content=content,
                    permissions=permissions, owner=owner,
                    mtime=end.timestamp(), step=step)

    stats.update(file=file, machine=machine)
    return stats
