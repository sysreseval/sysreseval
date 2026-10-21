"""Configuration files of ``sre-web`` and ``sre-agent``: TOML (stdlib ``tomllib``) read into
dataclasses with defaults and validation.  Unknown keys are refused (a typo must not silently
leave a default in place).  Durations are written as ``"2h"``, ``"30m"``, ``"90s"`` or a number
of seconds; ``listen`` as ``"host:port"`` (an IPv6 address between brackets)."""
import dataclasses
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

#: Minimum length of the portal secret and of an agent token.
MIN_SECRET_LENGTH = 16

_DURATION_RE = re.compile(r'^\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*$')
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


@dataclass
class HostConfig:
    """A host of the pool: the URL of its agent and the token of that agent."""
    name: str
    url: str
    token: str
    max_projects: int = 25


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
    instructor_groups: list = field(default_factory=list)   # DNs; members get the instructor role
    group_filter: str = ''            # "(member={dn})" group search when memberOf is not available
    start_tls: bool = False
    timeout: float = 10.0


@dataclass
class AuthConfig:
    mode: str = AUTH_ANONYMOUS
    ldap: LdapConfig = field(default_factory=LdapConfig)


@dataclass
class PoolConfig:
    idle_timeout_anonymous: float = 2 * 3600.0      # seconds; 0 = never reaped
    idle_timeout_authenticated: float = 24 * 3600.0
    poll_interval: float = 2.0                      # status refresh of the agents


@dataclass
class LimitsConfig:
    eval_interval: float = 10.0        # seconds between two self-evaluations of one user
    start_interval: float = 30.0       # seconds between two starts of one user
    login_per_minute: int = 5          # per client address
    max_answer_bytes: int = 1 << 20
    max_restore_mb: int = 512


@dataclass
class WebConfig:
    listen: tuple = ('127.0.0.1', 8450)
    public_url: str = ''
    secret: str = ''
    trusted_proxies: list = field(default_factory=list)
    tls_cert: str = ''
    tls_key: str = ''
    languages: list = field(default_factory=lambda: ['en', 'fr'])
    auth: AuthConfig = field(default_factory=AuthConfig)
    pool: PoolConfig = field(default_factory=PoolConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    hosts: list = field(default_factory=list)


def web_config_from_dict(data: dict, path: str = 'web.toml') -> WebConfig:
    auth_data = _section(data, 'auth', path)
    ldap_data = _section(auth_data, 'ldap', path)
    ldap = _build(LdapConfig, ldap_data, f"{path}: [auth.ldap]",
                  timeout=parse_duration(ldap_data.get('timeout', 10.0), 'auth.ldap.timeout'))
    auth = _build(AuthConfig, {k: v for k, v in auth_data.items() if k != 'ldap'}, f"{path}: [auth]", ldap=ldap)
    if auth.mode not in (AUTH_ANONYMOUS, AUTH_LDAP):
        raise ConfigError(f"{path}: auth.mode must be '{AUTH_ANONYMOUS}' or '{AUTH_LDAP}'")
    if auth.mode == AUTH_LDAP:
        if not ldap.uri:
            raise ConfigError(f"{path}: auth.ldap.uri is required in ldap mode")
        if not ldap.bind_dn_template and not ldap.search_base:
            raise ConfigError(f"{path}: auth.ldap needs bind_dn_template or search_base")
    pool_data = _section(data, 'pool', path)
    pool = _build(PoolConfig, pool_data, f"{path}: [pool]",
                  **{k: parse_duration(pool_data[k], f'pool.{k}') for k in
                     ('idle_timeout_anonymous', 'idle_timeout_authenticated', 'poll_interval') if k in pool_data})
    limits_data = _section(data, 'limits', path)
    limits = _build(LimitsConfig, limits_data, f"{path}: [limits]",
                    **{k: parse_duration(limits_data[k], f'limits.{k}') for k in
                       ('eval_interval', 'start_interval') if k in limits_data})
    hosts_data = data.get('hosts', [])
    if not isinstance(hosts_data, list):
        raise ConfigError(f"{path}: [[hosts]] must be an array of tables")
    hosts = []
    for i, h in enumerate(hosts_data):
        if not isinstance(h, dict):
            raise ConfigError(f"{path}: hosts[{i}] must be a table")
        host = _build(HostConfig, h, f"{path}: hosts[{i}]")
        if not host.name or not host.url or not host.token:
            raise ConfigError(f"{path}: hosts[{i}] needs name, url and token")
        if host.max_projects < 1:
            raise ConfigError(f"{path}: hosts[{i}].max_projects must be positive")
        hosts.append(host)
    if len({h.name for h in hosts}) != len(hosts):
        raise ConfigError(f"{path}: host names must be unique")
    top = {k: v for k, v in data.items() if k not in ('auth', 'pool', 'limits', 'hosts')}
    cfg = _build(WebConfig, top, path, auth=auth, pool=pool, limits=limits, hosts=hosts,
                 listen=parse_listen(top.get('listen', '127.0.0.1:8450')))
    if len(cfg.secret) < MIN_SECRET_LENGTH:
        raise ConfigError(f"{path}: secret must have at least {MIN_SECRET_LENGTH} characters")
    if bool(cfg.tls_cert) != bool(cfg.tls_key):
        raise ConfigError(f"{path}: tls_cert and tls_key go together")
    if not cfg.languages:
        raise ConfigError(f"{path}: languages cannot be empty")
    return cfg


def load_web_config(path) -> WebConfig:
    return web_config_from_dict(_read_toml(path), str(path))


# ---------------------------------------------------------------------------------------------
# sre-agent
# ---------------------------------------------------------------------------------------------

#: Timeouts (seconds) of the sre commands, by command.
DEFAULT_TIMEOUTS = {'start': 900.0, 'restore': 900.0, 'eval': 600.0, 'state': 600.0, 'stop': 300.0,
                    'save': 900.0, 'export': 600.0, 'list': 30.0}


@dataclass
class AgentConfig:
    listen: tuple = ('127.0.0.1', 8451)
    token: str = ''
    sre_exe: str = ''                 # '' : params.sre_exe of the host
    poll_interval: float = 1.0        # scan of the projects directory (like the Qt GUI)
    max_idle: float = 24 * 3600.0     # default idle timeout of a project (the portal may give its own)
    terminals_per_project: int = 8
    terminals_per_device: int = 2
    max_concurrent_starts: int = 2
    max_concurrent_evals: int = 2
    lab_list_cache_ttl: float = 60.0
    state_dir: str = ''               # '' : <sre_pub_dir>/web-agent
    tls_cert: str = ''
    tls_key: str = ''
    timeouts: dict = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))


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
    top = {k: v for k, v in data.items() if k != 'timeouts'}
    converted = {k: parse_duration(top[k], k) for k in ('poll_interval', 'max_idle', 'lab_list_cache_ttl') if k in top}
    cfg = _build(AgentConfig, top, path, timeouts=timeouts, listen=parse_listen(top.get('listen', '127.0.0.1:8451')),
                 **converted)
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
    return cfg


def load_agent_config(path, *, sre_exe: str = '', state_dir: str = '') -> AgentConfig:
    return agent_config_from_dict(_read_toml(path), str(path), sre_exe=sre_exe, state_dir=state_dir)


def _read_toml(path) -> dict:
    try:
        with open(path, 'rb') as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"{path}: no such file") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
