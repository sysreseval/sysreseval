"""Configuration files of ``sre-web`` and ``sre-agent``: TOML (stdlib ``tomllib``) read into
dataclasses with defaults and validation.  Unknown keys are refused (a typo must not silently
leave a default in place).  Durations are written as ``"2h"``, ``"30m"``, ``"90s"`` or a number
of seconds; ``listen`` as ``"host:port"`` (an IPv6 address between brackets).  A file may import
other files (``import = ["web.d"]``: a directory, a glob or a file), merged before the validation
by ``read_config``."""
import dataclasses
import glob
import ipaddress
import mimetypes
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

#: Minimum length of the portal secret and of an agent token.
MIN_SECRET_LENGTH = 16

_DURATION_RE = re.compile(r'^\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*$')
_MAC_RE = re.compile(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', re.I)
_HOURS_RE = re.compile(r'^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$')
_DURATION_UNITS = {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400}


class ConfigError(ValueError):
    """A configuration file cannot be used; the message names the file and the key."""


def parse_duration(value, key='duration') -> float:
    """Seconds of ``"2h"``, ``"30m"``, ``"90s"``, ``"0"`` or a number (seconds)."""
    if isinstance(value, bool):
        raise ConfigError(f"{key}: a duration is expected")
    if isinstance(value, (int, float)):
        if value < 0:
            raise ConfigError(f"{key}: a duration cannot be negative")
        return float(value)
    m = _DURATION_RE.match(str(value))
    if not m:
        raise ConfigError(f"{key}: bad duration {value!r} (use 90, '90s', '30m', '2h' or '1d')")
    return float(m.group(1)) * _DURATION_UNITS[m.group(2)]


def parse_listen(value, key='listen') -> tuple[str, int]:
    """``(host, port)`` of ``"host:port"``; the host of an IPv6 address is between brackets."""
    text = str(value).strip()
    if text.startswith('['):
        end = text.find(']')
        if end < 0 or not text[end + 1:].startswith(':'):
            raise ConfigError(f"{key}: bad address {value!r} (use '[::1]:8450')")
        host, port = text[1:end], text[end + 2:]
    else:
        host, sep, port = text.rpartition(':')
        if not sep:
            raise ConfigError(f"{key}: bad address {value!r} (use 'host:port')")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ConfigError(f"{key}: bad port in {value!r}")
    return host or '0.0.0.0', int(port)


def parse_mac(value, key='mac') -> str:
    """A MAC address as ``aa:bb:cc:dd:ee:ff`` (lower case, colons)."""
    text = str(value).strip()
    if not _MAC_RE.match(text):
        raise ConfigError(f"{key}: bad MAC address {value!r}")
    return text.lower().replace('-', ':')


def parse_active_hours(value, key='active_hours'):
    """``"07:00-20:00"`` as ``(start, end)`` minutes of the day; ``""`` means always (``None``).
    An end before the start wraps past midnight (``"22:00-06:00"``)."""
    text = str(value or '').strip()
    if not text:
        return None
    m = _HOURS_RE.match(text)
    if not m:
        raise ConfigError(f"{key}: bad time range {value!r} (use 'HH:MM-HH:MM')")
    h1, m1, h2, m2 = (int(x) for x in m.groups())
    if h1 > 24 or h2 > 24 or m1 > 59 or m2 > 59:
        raise ConfigError(f"{key}: bad time range {value!r}")
    return h1 * 60 + m1, h2 * 60 + m2


def in_active_hours(hours, minute_of_day: int) -> bool:
    if hours is None:
        return True
    start, end = hours
    if start <= end:
        return start <= minute_of_day < end
    return minute_of_day >= start or minute_of_day < end


def parse_networks(values, key='allowed_clients') -> list:
    """The addresses / networks of an allow-list (``"10.0.0.5"``, ``"10.0.0.0/24"``, ``"::1"``)
    as ``ipaddress`` networks."""
    if not isinstance(values, list):
        raise ConfigError(f"{key}: a list of addresses or networks is expected")
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            raise ConfigError(f"{key}: bad address or network {value!r}") from None
    return networks


def client_allowed(remote, networks) -> bool:
    """Whether the peer address *remote* (what aiohttp's ``request.remote`` gives) belongs to one
    of the ``ipaddress`` *networks* (``allowed_clients`` of the agent, ``trusted_proxies`` of the
    portal); an empty list allows every address, an unparsable one is refused.  An IPv4-mapped
    IPv6 address counts as its IPv4 address."""
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(str(remote or '').split('%', 1)[0])
    except ValueError:
        return False
    candidates = [address]
    mapped = getattr(address, 'ipv4_mapped', None)
    if mapped is not None:
        candidates.append(mapped)
    return any(candidate in network for network in networks for candidate in candidates
               if candidate.version == network.version)


def _section(data, key, path) -> dict:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: [{key}] must be a table")
    return value


def _check_keys(data: dict, allowed, where: str):
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")


def _fields(cls) -> list:
    return [f.name for f in dataclasses.fields(cls)]


def _build(cls, data: dict, where: str, **converted):
    """An instance of the dataclass *cls* from the plain values of *data* (already-converted
    values given as keywords), refusing unknown keys."""
    _check_keys(data, _fields(cls), where)
    values = {k: v for k, v in data.items() if k not in converted}
    values.update(converted)
    return cls(**values)


# ---------------------------------------------------------------------------------------------
# sre-web
# ---------------------------------------------------------------------------------------------

AUTH_ANONYMOUS = 'anonymous'
AUTH_LDAP = 'ldap'
AUTH_PROXY = 'proxy'
AUTH_MODES = (AUTH_ANONYMOUS, AUTH_LDAP, AUTH_PROXY)


@dataclass
class HostConfig:
    """A host of the pool: the URL of its agent and the token of that agent; how to wake it
    (a MAC address for a Wake-on-LAN packet, or a command with ``{name}`` / ``{mac}``),
    whether the portal may power it off, and whether it is reserved for the instructors'
    projects (``instructors_only``: never a student's project, outside the elastic pool)."""
    name: str
    url: str
    token: str
    max_projects: int = 25
    mac: str = ''
    wake_command: str = ''
    power: bool = False
    enabled: bool = True              # placement allowed (``sre-web-tool disable`` flips it)
    instructors_only: bool = False    # only the instructors' projects are placed there (chosen on their Open page)

    @property
    def can_wake(self) -> bool:
        return bool(self.mac or self.wake_command)


@dataclass
class LdapConfig:
    uri: str = ''
    bind_dn_template: str = ''        # "uid={login},ou=people,dc=example,dc=org" (bind as the user)
    search_base: str = ''             # search-then-bind: where to look for the user
    search_filter: str = '(uid={login})'
    bind_dn: str = ''                 # service account of the search (anonymous search otherwise)
    bind_password: str = ''
    attr_fullname: str = 'cn'
    attr_mail: str = 'mail'
    # The student group of the user ("departmentNumber"...; the first value of a multi-valued
    # attribute): shown on the Watch page, kept in the answers files; '' = no group.
    attr_group: str = ''
    instructor_groups: list = field(default_factory=list)   # DNs; members get the instructor role
    group_filter: str = ''            # "(member={dn})" group search when memberOf is not available
    # The instructor role is the OR of every configured test (a test with an empty key is skipped):
    # instructor_groups above, a filter the user's own entry must match (BASE search on its DN), and
    # a group search under group_search_base (setting it enables that test) whose filter gets the
    # login (filter-escaped) and the DN of the user.  The defaults are a primary group / a posixGroup
    # of gid 2000: another site blanks or changes them.
    instructor_filter: str = '(gidNumber=2000)'
    group_search_base: str = ''       # the base of the group searches (group_filter too); '' = search_base
    instructor_group_filter: str = '(&(objectClass=posixGroup)(gidNumber=2000)(memberUid={login}))'
    start_tls: bool = False
    timeout: float = 10.0


@dataclass
class ProxyAuthConfig:
    """``[auth.proxy]``: the request headers a reverse proxy of ``trusted_proxies`` passes the
    identity in, once it has authenticated the browser itself (Apache ``mod_authnz_ldap``...)."""
    header_login: str = 'X-Remote-User'
    header_fullname: str = 'X-Remote-Name'
    header_email: str = 'X-Remote-Email'
    header_groups: str = 'X-Remote-Groups'
    groups_separator: str = ';'       # mod_authnz_ldap joins the values of an attribute with "; "
    # The student group (the first value of the header, split like the groups header); '' = none
    # here (ldap_roles with attr_group of [auth.ldap] gives it otherwise).
    header_group: str = ''
    instructor_groups: list = field(default_factory=list)   # values of the groups header giving the role
    # A second header test: the values of instructor_header (split like the groups header) in
    # instructor_values give the role, e.g. X-Remote-Gid = AUTHENTICATE_GIDNUMBER and ["2000"].
    instructor_header: str = ''
    instructor_values: list = field(default_factory=list)
    # The portal runs the tests of [auth.ldap] itself for the login the proxy gives (the only way
    # to a group membership without a memberOf overlay in this mode); the role is cached per login.
    ldap_roles: bool = False
    ldap_roles_ttl: float = 600.0     # seconds
    logout_url: str = ''              # where Logout sends the browser; '' = no Logout button


@dataclass
class AuthConfig:
    mode: str = AUTH_ANONYMOUS
    ldap: LdapConfig = field(default_factory=LdapConfig)
    proxy: ProxyAuthConfig = field(default_factory=ProxyAuthConfig)


@dataclass
class PoolConfig:
    idle_timeout_anonymous: float = 2 * 3600.0      # seconds; 0 = never reaped
    idle_timeout_authenticated: float = 24 * 3600.0
    poll_interval: float = 2.0                      # status refresh of the agents
    # mutual TLS with the agents: the CA their certificates are verified against (instead of the
    # system store), and the client certificate of the portal presented to every agent
    ca: str = ''
    client_cert: str = ''
    client_key: str = ''
    # the elastic pool: hosts are woken when the spare capacity (free project slots of the hosts
    # up) drops below spare_projects, at most one wake per wake_interval, a host silent for
    # wake_timeout after its wake going back to sleep (with a backoff); min_hosts_up hosts are
    # kept awake during active_hours (HH:MM-HH:MM, local time; "" = always); a host with no
    # project for idle_host_timeout may be powered off (0 = never: the nightly cron does it)
    spare_projects: int = 5
    min_hosts_up: int = 1
    active_hours: str = '07:00-20:00'
    wake_timeout: float = 180.0
    wake_interval: float = 30.0
    wol_broadcast: str = '255.255.255.255'
    idle_host_timeout: float = 0.0


@dataclass
class LimitsConfig:
    eval_interval: float = 10.0        # seconds between two self-evaluations of one user
    start_interval: float = 30.0       # seconds between two starts of one user
    login_per_minute: int = 5          # per client address
    max_answer_bytes: int = 1 << 20


@dataclass
class AdminConfig:
    """The administration API of the portal (``sre-web-tool ...``): a bearer token, loopback
    clients only unless listen_any, and the file where the hosts added / removed / disabled by
    hand are kept (merged with the [[hosts]] of the configuration at startup)."""
    token: str = ''                   # '' : the administration API is disabled
    listen_any: bool = False
    state_file: str = ''              # '' : the default of the installation (see sre-web)


@dataclass
class AccessLogConfig:
    """``[access_log]``: the connection log of the portal (``sreweb/portal/accesslog.py``), one
    ``key=value`` line per event: the sessions of the users (first request to logout, idle
    timeout or shutdown, with their duration and the projects opened), the logins, the starts,
    the project pages, terminals, evaluations, states, stops, exports, the denied calls."""
    file: str = ''                      # '' : no file
    journal: bool = True                # the lines also go to the portal's log (stderr: the journal, docker logs)
    keep: int = 400                     # days of daily rotated files kept; 0 = no rotation (logrotate reopens the file)
    session_timeout: float = 1800.0     # a session idle for this long is closed (its duration ends at its last request)


_URL_PREFIXES = ('/', 'http://', 'https://')


@dataclass
class SiteConfig:
    """``[site]``: the institution shown next to the SRE logo in the header of every page: a
    logo (an image file, served at ``/site/logo``), a name (a string, or a table of strings by
    language) and the page the two link to.  Nothing by default: the SRE logo alone."""
    logo: str = ''                    # absolute path of the image file (JPG, PNG, SVG...), readable by sre-web
    name: object = ''                 # str, or {language: str}
    url: str = ''                     # '' = no link

    def name_for(self, language: str, languages: list) -> str:
        """The name in *language*, else in the first of *languages* (the default language of
        the site), else the first one given."""
        if not isinstance(self.name, dict):
            return self.name
        for lang in (language, *languages):
            if self.name.get(lang):
                return self.name[lang]
        return next(iter(self.name.values()), '')


def _check_access_log(cfg: AccessLogConfig, path: str):
    where = f"{path}: access_log."
    if not isinstance(cfg.file, str):
        raise ConfigError(f"{where}file must be the absolute path of the log file")
    if cfg.file and not os.path.isabs(cfg.file):
        raise ConfigError(f"{where}file must be the absolute path of the log file")
    if not isinstance(cfg.journal, bool):
        raise ConfigError(f"{where}journal must be true or false")
    if isinstance(cfg.keep, bool) or not isinstance(cfg.keep, int) or cfg.keep < 0:
        raise ConfigError(f"{where}keep must be a number of days (0 = no rotation)")
    if cfg.session_timeout <= 0:
        raise ConfigError(f"{where}session_timeout must be positive")


def _check_site(site: SiteConfig, path: str):
    where = f"{path}: site."
    if not isinstance(site.logo, str):
        raise ConfigError(f"{where}logo must be the absolute path of an image file")
    if site.logo:
        if not os.path.isabs(site.logo):
            raise ConfigError(f"{where}logo must be the absolute path of an image file")
        if not os.path.isfile(site.logo) or not os.access(site.logo, os.R_OK):
            raise ConfigError(f"{where}logo: {site.logo} is not a readable file")
        if not (mimetypes.guess_type(site.logo)[0] or '').startswith('image/'):
            raise ConfigError(f"{where}logo must be an image file (.jpg, .png, .svg, .gif, .webp)")
    if isinstance(site.name, dict):
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in site.name.items()):
            raise ConfigError(f"{where}name must be a string or a table of strings by language")
    elif not isinstance(site.name, str):
        raise ConfigError(f"{where}name must be a string or a table of strings by language")
    if not isinstance(site.url, str) or (site.url and not site.url.startswith(_URL_PREFIXES)):
        raise ConfigError(f"{where}url must be a path or an absolute URL")


@dataclass
class WebConfig:
    listen: tuple = ('127.0.0.1', 8450)
    public_url: str = ''
    secret: str = ''
    trusted_proxies: list = field(default_factory=list)   # ipaddress networks: the peers trusted in proxy mode
    tls_cert: str = ''
    tls_key: str = ''
    languages: list = field(default_factory=lambda: ['en', 'fr'])
    auth: AuthConfig = field(default_factory=AuthConfig)
    pool: PoolConfig = field(default_factory=PoolConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    admin: AdminConfig = field(default_factory=AdminConfig)
    access_log: AccessLogConfig = field(default_factory=AccessLogConfig)
    site: SiteConfig = field(default_factory=SiteConfig)
    hosts: list = field(default_factory=list)

    @property
    def groups_configured(self) -> bool:
        """Whether a source of the users' student group is configured in the current mode (the
        Watch page shows its Group column and filter then)."""
        if self.auth.mode == AUTH_LDAP:
            return bool(self.auth.ldap.attr_group)
        if self.auth.mode == AUTH_PROXY:
            proxy = self.auth.proxy
            return bool(proxy.header_group or (proxy.ldap_roles and self.auth.ldap.attr_group))
        return False


def host_config_from_dict(h: dict, where: str) -> HostConfig:
    """A [[hosts]] entry (of the configuration, or added with ``sre-web-tool add``)."""
    if not isinstance(h, dict):
        raise ConfigError(f"{where} must be a table")
    converted = {}
    if h.get('mac'):
        converted['mac'] = parse_mac(h['mac'], f'{where}.mac')
    host = _build(HostConfig, {'name': '', 'url': '', 'token': '', **{k: v for k, v in h.items() if k != 'mac' or not v}},
                  where, **converted)
    if not host.name or not host.url or not host.token:
        raise ConfigError(f"{where} needs name, url and token")
    if not re.match(r'^[A-Za-z0-9._-]+$', host.name):
        raise ConfigError(f"{where}: bad host name {host.name!r}")
    if host.max_projects < 1:
        raise ConfigError(f"{where}.max_projects must be positive")
    for key in ('power', 'enabled', 'instructors_only'):
        if not isinstance(getattr(host, key), bool):
            raise ConfigError(f"{where}.{key} must be true or false")
    return host


def web_config_from_dict(data: dict, path: str = 'web.toml') -> WebConfig:
    auth_data = _section(data, 'auth', path)
    ldap_data = _section(auth_data, 'ldap', path)
    ldap = _build(LdapConfig, ldap_data, f"{path}: [auth.ldap]",
                  timeout=parse_duration(ldap_data.get('timeout', 10.0), 'auth.ldap.timeout'))
    proxy_data = _section(auth_data, 'proxy', path)
    proxy = _build(ProxyAuthConfig, proxy_data, f"{path}: [auth.proxy]",
                   ldap_roles_ttl=parse_duration(proxy_data.get('ldap_roles_ttl', 600.0), 'auth.proxy.ldap_roles_ttl'))
    auth = _build(AuthConfig, {k: v for k, v in auth_data.items() if k not in ('ldap', 'proxy')}, f"{path}: [auth]",
                  ldap=ldap, proxy=proxy)
    if auth.mode not in AUTH_MODES:
        raise ConfigError(f"{path}: auth.mode must be " + ', '.join(f"'{m}'" for m in AUTH_MODES[:-1])
                          + f" or '{AUTH_MODES[-1]}'")
    if auth.mode == AUTH_LDAP or (auth.mode == AUTH_PROXY and proxy.ldap_roles):
        why = "in ldap mode" if auth.mode == AUTH_LDAP else "with auth.proxy.ldap_roles"
        if not ldap.uri:
            raise ConfigError(f"{path}: auth.ldap.uri is required {why}")
        if not ldap.bind_dn_template and not ldap.search_base:
            raise ConfigError(f"{path}: auth.ldap needs bind_dn_template or search_base {why}")
    if not isinstance(ldap.instructor_groups, list):
        raise ConfigError(f"{path}: auth.ldap.instructor_groups must be a list")
    for name in ('instructor_filter', 'group_filter', 'instructor_group_filter'):
        value = str(getattr(ldap, name)).strip()
        if value and not (value.startswith('(') and value.endswith(')')):
            raise ConfigError(f"{path}: auth.ldap.{name} must be an LDAP filter between parentheses")
    if ldap.instructor_group_filter.strip() and '{login}' not in ldap.instructor_group_filter \
            and '{dn}' not in ldap.instructor_group_filter:
        raise ConfigError(f"{path}: auth.ldap.instructor_group_filter must name the user with {{login}} or {{dn}}")
    if not isinstance(ldap.attr_group, str) or (ldap.attr_group.strip()
                                                and not re.match(r'^[A-Za-z][A-Za-z0-9;-]*$', ldap.attr_group.strip())):
        raise ConfigError(f"{path}: auth.ldap.attr_group must be an LDAP attribute name")
    ldap.attr_group = ldap.attr_group.strip()
    for name in ('header_login', 'header_fullname', 'header_email', 'header_groups', 'groups_separator'):
        if not str(getattr(proxy, name)).strip():
            raise ConfigError(f"{path}: auth.proxy.{name} cannot be empty")
    if not isinstance(proxy.header_group, str) or (proxy.header_group.strip()
                                                   and not re.match(r'^[A-Za-z0-9-]+$', proxy.header_group.strip())):
        raise ConfigError(f"{path}: auth.proxy.header_group must be a header name")
    proxy.header_group = proxy.header_group.strip()
    for name in ('instructor_groups', 'instructor_values'):
        if not isinstance(getattr(proxy, name), list):
            raise ConfigError(f"{path}: auth.proxy.{name} must be a list")
    if bool(proxy.instructor_values) != bool(proxy.instructor_header.strip()):
        raise ConfigError(f"{path}: auth.proxy.instructor_header and instructor_values go together")
    if proxy.ldap_roles_ttl < 0:
        raise ConfigError(f"{path}: auth.proxy.ldap_roles_ttl cannot be negative")
    if proxy.logout_url and not proxy.logout_url.startswith(_URL_PREFIXES):
        raise ConfigError(f"{path}: auth.proxy.logout_url must be a path or an absolute URL")
    pool_data = _section(data, 'pool', path)
    pool = _build(PoolConfig, pool_data, f"{path}: [pool]",
                  **{k: parse_duration(pool_data[k], f'pool.{k}') for k in
                     ('idle_timeout_anonymous', 'idle_timeout_authenticated', 'poll_interval', 'wake_timeout',
                      'wake_interval', 'idle_host_timeout') if k in pool_data})
    if bool(pool.client_cert) != bool(pool.client_key):
        raise ConfigError(f"{path}: pool.client_cert and pool.client_key go together")
    parse_active_hours(pool.active_hours, 'pool.active_hours')
    if pool.spare_projects < 0 or pool.min_hosts_up < 0:
        raise ConfigError(f"{path}: pool.spare_projects and pool.min_hosts_up cannot be negative")
    admin_data = _section(data, 'admin', path)
    admin = _build(AdminConfig, admin_data, f"{path}: [admin]")
    if admin.token and len(admin.token) < MIN_SECRET_LENGTH:
        raise ConfigError(f"{path}: admin.token must have at least {MIN_SECRET_LENGTH} characters")
    access_data = _section(data, 'access_log', path)
    access_log = _build(AccessLogConfig, access_data, f"{path}: [access_log]",
                        session_timeout=parse_duration(access_data.get('session_timeout', 1800.0),
                                                       'access_log.session_timeout'))
    _check_access_log(access_log, path)
    limits_data = _section(data, 'limits', path)
    limits = _build(LimitsConfig, limits_data, f"{path}: [limits]",
                    **{k: parse_duration(limits_data[k], f'limits.{k}') for k in
                       ('eval_interval', 'start_interval') if k in limits_data})
    site = _build(SiteConfig, _section(data, 'site', path), f"{path}: [site]")
    _check_site(site, path)
    hosts_data = data.get('hosts', [])
    if not isinstance(hosts_data, list):
        raise ConfigError(f"{path}: [[hosts]] must be an array of tables")
    hosts = [host_config_from_dict(h, f"{path}: hosts[{i}]") for i, h in enumerate(hosts_data)]
    if len({h.name for h in hosts}) != len(hosts):
        raise ConfigError(f"{path}: host names must be unique")
    top = {k: v for k, v in data.items()
           if k not in ('auth', 'pool', 'limits', 'admin', 'access_log', 'site', 'hosts')}
    cfg = _build(WebConfig, top, path, auth=auth, pool=pool, limits=limits, admin=admin, access_log=access_log,
                 site=site, hosts=hosts,
                 listen=parse_listen(top.get('listen', '127.0.0.1:8450')),
                 trusted_proxies=parse_networks(top.get('trusted_proxies', []), f'{path}: trusted_proxies'))
    if auth.mode == AUTH_PROXY and not cfg.trusted_proxies:
        raise ConfigError(f"{path}: trusted_proxies is required in proxy mode (the address of the reverse proxy)")
    if len(cfg.secret) < MIN_SECRET_LENGTH:
        raise ConfigError(f"{path}: secret must have at least {MIN_SECRET_LENGTH} characters")
    if bool(cfg.tls_cert) != bool(cfg.tls_key):
        raise ConfigError(f"{path}: tls_cert and tls_key go together")
    if not cfg.languages:
        raise ConfigError(f"{path}: languages cannot be empty")
    return cfg


def load_web_config(path) -> WebConfig:
    return web_config_from_dict(read_config(path), str(path))


# ---------------------------------------------------------------------------------------------
# sre-agent
# ---------------------------------------------------------------------------------------------

#: Timeouts (seconds) of the sre commands, by command.
DEFAULT_TIMEOUTS = {'start': 900.0, 'eval': 600.0, 'state': 600.0, 'stop': 300.0, 'export': 600.0, 'list': 30.0}


_GEOMETRY_RE = re.compile(r'^\d{3,5}x\d{3,5}$')
_USER_RE = re.compile(r'^[a-z_][a-z0-9_-]*$')
MAX_DISPLAY = 999


@dataclass
class DisplayConfig:
    """``[display]``: one virtual X desktop (Xvnc + a window manager) per project whose lab has an
    ``x11_host`` machine, shown in the Display tab of the web site."""
    enabled: bool = False
    user: str = 'sreweb-x11'                  # the unprivileged account of the X processes ('' = the agent's own
                                              # user: tests only, refused when the agent runs as root)
    xvnc_command: str = 'Xvnc'                # TigerVNC's Xvnc; shlex-split, the agent appends its options
    window_manager_command: str = 'openbox'   # '' = none
    geometry: str = '1280x800'
    depth: int = 24
    frame_rate: int = 30
    first_display: int = 10                   # :10 ... :99 -> X11 TCP ports 6010 ... 6099 on the pool host
    last_display: int = 99
    runtime_dir: str = '/run/sre-agent'       # the RFB sockets and X authority files (display/ inside)
    start_timeout: float = 10.0               # seconds for the RFB socket of Xvnc to appear


def _check_display(d: DisplayConfig, path: str):
    where = f"{path}: display."
    if not isinstance(d.enabled, bool):
        raise ConfigError(f"{where}enabled must be true or false")
    for name in ('depth', 'frame_rate', 'first_display', 'last_display'):
        value = getattr(d, name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}{name} must be an integer")
    if not 1 <= d.first_display <= MAX_DISPLAY:
        raise ConfigError(f"{where}first_display must be between 1 and {MAX_DISPLAY}")
    if not d.first_display <= d.last_display <= MAX_DISPLAY:
        raise ConfigError(f"{where}last_display must be between first_display and {MAX_DISPLAY}")
    if d.depth not in (16, 24):
        raise ConfigError(f"{where}depth must be 16 or 24")
    if not 1 <= d.frame_rate <= 120:
        raise ConfigError(f"{where}frame_rate must be between 1 and 120")
    if not isinstance(d.geometry, str) or not _GEOMETRY_RE.match(d.geometry):
        raise ConfigError(f"{where}geometry must be <width>x<height>, e.g. 1280x800")
    if d.enabled and not str(d.xvnc_command).strip():
        raise ConfigError(f"{where}xvnc_command cannot be empty when enabled")
    if not isinstance(d.user, str) or (d.user and not _USER_RE.match(d.user)):
        raise ConfigError(f"{where}user must be a system user name (or empty)")
    if not isinstance(d.runtime_dir, str) or not d.runtime_dir.startswith('/'):
        raise ConfigError(f"{where}runtime_dir must be an absolute path")
    if d.start_timeout <= 0:
        raise ConfigError(f"{where}start_timeout must be positive")


@dataclass
class AgentConfig:
    listen: tuple = ('127.0.0.1', 8451)
    token: str = ''
    sre_exe: str = ''                 # '' : params.sre_exe of the host
    poll_interval: float = 1.0        # scan of the projects directory (like the Qt GUI)
    max_idle: float = 24 * 3600.0     # default idle timeout of a project (the portal may give its own)
    terminals_per_project: int = 16
    terminals_per_device: int = 4     # each Connect of the web opens a new terminal on the machine
    max_concurrent_starts: int = 2
    max_concurrent_evals: int = 2
    lab_list_cache_ttl: float = 60.0
    state_dir: str = ''               # '' : <sre_pub_dir>/web-agent
    tls_cert: str = ''                # the certificate and key of the agent (both or none)
    tls_key: str = ''
    tls_ca: str = ''                  # when set: a client certificate signed by this CA is required (the portal's)
    allowed_clients: list = field(default_factory=list)   # ipaddress networks; empty = any address
    # the machine counts as occupied (no new web project) when a local user session exists
    # ("sessions"), when projects not started by the agent exist ("projects"), either ("both")
    # or never
    occupied_check: str = 'both'
    # POST /v1/power/off (the portal powers an idle host off) and the command it runs
    allow_power_off: bool = False
    power_off_command: str = 'systemctl poweroff'
    # on SIGTERM, the managed projects are evaluated / stopped first: "shutdown" (only when the
    # system is going down: the nightly cron, a poweroff), "always" (a restart of the unit too),
    # "never"; within shutdown_timeout seconds (the unit's TimeoutStopSec is longer)
    close_projects_on_stop: str = 'shutdown'
    shutdown_timeout: float = 240.0
    timeouts: dict = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))
    display: DisplayConfig = field(default_factory=DisplayConfig)


def agent_config_from_dict(data: dict, path: str = 'agent.toml', *, sre_exe: str = '',
                           state_dir: str = '') -> AgentConfig:
    """*sre_exe* and *state_dir* are the defaults of the host (``params.sre_exe``,
    ``params.sre_pub_dir + '/web-agent'``), given by the caller so that this module does not
    import ``SRE``."""
    timeouts = dict(DEFAULT_TIMEOUTS)
    given = data.get('timeouts', {})
    if not isinstance(given, dict):
        raise ConfigError(f"{path}: [timeouts] must be a table")
    _check_keys(given, DEFAULT_TIMEOUTS, f"{path}: [timeouts]")
    for k, v in given.items():
        timeouts[k] = parse_duration(v, f'timeouts.{k}')
    display_data = _section(data, 'display', path)
    display = _build(DisplayConfig, display_data, f"{path}: [display]",
                     **({'start_timeout': parse_duration(display_data['start_timeout'], 'display.start_timeout')}
                        if 'start_timeout' in display_data else {}))
    top = {k: v for k, v in data.items() if k not in ('timeouts', 'display')}
    converted = {k: parse_duration(top[k], k) for k in ('poll_interval', 'max_idle', 'lab_list_cache_ttl',
                                                        'shutdown_timeout') if k in top}
    cfg = _build(AgentConfig, top, path, timeouts=timeouts, display=display, listen=parse_listen(top.get('listen', '127.0.0.1:8451')),
                 allowed_clients=parse_networks(top.get('allowed_clients', []), f'{path}: allowed_clients'), **converted)
    if len(cfg.token) < MIN_SECRET_LENGTH:
        raise ConfigError(f"{path}: token must have at least {MIN_SECRET_LENGTH} characters")
    if not cfg.sre_exe:
        cfg.sre_exe = sre_exe
    if not cfg.state_dir:
        cfg.state_dir = state_dir
    for name in ('terminals_per_project', 'terminals_per_device', 'max_concurrent_starts', 'max_concurrent_evals'):
        if getattr(cfg, name) < 1:
            raise ConfigError(f"{path}: {name} must be positive")
    if cfg.poll_interval <= 0:
        raise ConfigError(f"{path}: poll_interval must be positive")
    if bool(cfg.tls_cert) != bool(cfg.tls_key):
        raise ConfigError(f"{path}: tls_cert and tls_key go together")
    if cfg.tls_ca and not cfg.tls_cert:
        raise ConfigError(f"{path}: tls_ca needs tls_cert and tls_key")
    if cfg.occupied_check not in ('sessions', 'projects', 'both', 'never'):
        raise ConfigError(f"{path}: occupied_check must be sessions, projects, both or never")
    if cfg.close_projects_on_stop not in ('shutdown', 'always', 'never'):
        raise ConfigError(f"{path}: close_projects_on_stop must be shutdown, always or never")
    _check_display(cfg.display, path)
    return cfg


def load_agent_config(path, *, sre_exe: str = '', state_dir: str = '') -> AgentConfig:
    return agent_config_from_dict(read_config(path), str(path), sre_exe=sre_exe, state_dir=state_dir)


# ---------------------------------------------------------------------------------------------
# The files: TOML, and the ``import`` key merging other files in
# ---------------------------------------------------------------------------------------------

def _is_array_of_tables(value) -> bool:
    """A ``[[hosts]]``-style value: a list whose elements are all tables (an empty list qualifies;
    ``tomllib`` gives a plain ``list`` for arrays and arrays of tables alike)."""
    return isinstance(value, list) and all(isinstance(v, dict) for v in value)


def merge_config(base: dict, extra: dict, origins: dict, extra_name: str, prefix: str = '') -> dict:
    """A new dict: *base* with the keys of *extra* (the content of the file *extra_name*) added.
    Tables merge recursively, two arrays of tables are concatenated (*base* first), and any other
    key present in both (a scalar, a plain array, a table against a non-table) is refused, naming
    both files: ``web.d/b.toml: secret is also given in web.toml``.  *origins* (dotted key → the
    file that first gave it) is filled in place; *prefix* is the dotted path of the table being
    merged (``"auth.ldap."``).  Neither dict argument is modified."""
    merged = dict(base)
    for key, value in extra.items():
        dotted = prefix + key
        origins.setdefault(dotted, extra_name)
        if key not in base:
            merged[key] = (merge_config({}, value, origins, extra_name, dotted + '.')
                           if isinstance(value, dict) else value)
        elif isinstance(base[key], dict) and isinstance(value, dict):
            merged[key] = merge_config(base[key], value, origins, extra_name, dotted + '.')
        elif _is_array_of_tables(base[key]) and _is_array_of_tables(value):
            merged[key] = base[key] + value
        else:
            raise ConfigError(f"{extra_name}: {dotted} is also given in {origins[dotted]}")
    return merged


def import_paths(entries: list, base_dir: str) -> list:
    """The files named by the ``import`` *entries*, each resolved against *base_dir* (an absolute
    entry stays as it is): a directory → its ``*.toml`` files, by name; a glob pattern (``*``,
    ``?``, ``[``) → the matching paths, by name, possibly none; anything else → that path, read
    later (``no such file`` when missing).  In the order of the entries, each path once."""
    paths, seen = [], set()
    for entry in entries:
        target = os.path.normpath(os.path.join(base_dir, entry))      # also drops a trailing '/'
        if os.path.isdir(target):
            found = sorted(glob.glob(os.path.join(target, '*.toml')))
        elif glob.has_magic(entry):
            found = sorted(glob.glob(target))
        else:
            found = [target]
        for p in found:
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def read_config(path) -> dict:
    """The data of the TOML file *path* with the files its ``import`` key names merged in
    (``merge_config``) and the key removed: what ``web_config_from_dict`` /
    ``agent_config_from_dict`` validate.  ``import`` is a path or a list of paths relative to the
    directory of *path* (``import_paths``); an imported file cannot ``import``."""
    main = _read_toml(path)
    entries = main.pop('import', [])
    if isinstance(entries, str):
        entries = [entries]
    if not isinstance(entries, list) or not all(isinstance(e, str) and e for e in entries):
        raise ConfigError(f"{path}: import must be a path or a list of paths")
    here = os.path.abspath(path)
    origins = {}
    data = merge_config({}, main, origins, str(path))
    for file in import_paths(entries, os.path.dirname(here)):
        if file == here:
            raise ConfigError(f"{path}: import names the file itself")
        extra = _read_toml(file)
        if 'import' in extra:
            raise ConfigError(f"{file}: import is not allowed in an imported file")
        data = merge_config(data, extra, origins, file)
    return data


def _read_toml(path) -> dict:
    try:
        with open(path, 'rb') as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"{path}: no such file") from None
    except IsADirectoryError:
        raise ConfigError(f"{path}: is a directory") from None
    except OSError as e:                                  # PermissionError, NotADirectoryError...
        raise ConfigError(f"{path}: {e.strerror or e}") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"{path}: {e}") from None
