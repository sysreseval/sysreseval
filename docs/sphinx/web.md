# Web site (remote use)

The web site lets the students work on the labs from a browser, without the Qt interface and
without a remote desktop: the projects run on a **pool of Docker hosts**, every tab of the
graphical interface (Schema, Informations, Machines, Networks, Questions, Evaluation, Terminals,
Apply Configuration, Log) is rendered in the browser and the terminals go through WebSockets.
The users log in with an LDAP directory (the portal binds to it, or an Apache reverse proxy in
front authenticates them), or everybody is anonymous.

Nothing of a lab ever reaches the browser but what a student sees today: the content of
`info.json` (resolved to the user's language, the instructor texts stripped), the outputs of the
`sre --user` commands (the schema, the grades of a self-evaluation, the console of a machine).
The lab files, `data.json`, the hidden machines and the archives stay on the pool hosts.

## Architecture

```
browser ──HTTPS──► sre-web (the portal) ──HTTP + token──► sre-agent (one per pool host) ──► sre --user …
```

- **`sre-web`**, the portal, is the web site the browsers talk to. It authenticates the users,
  keeps a signed session cookie, knows the pool of hosts and relays every request about a project
  to the agent of the host running it. It runs as an unprivileged user, needs neither Docker,
  Kathara nor the labs, and may run anywhere on the network (the Debian package `sysreseval-web`
  installs alone).
- **`sre-agent`** runs on every pool host, as root, next to `sre`. It drives the `sre` CLI in user
  mode on behalf of the web users exactly as `sre-wrapper` + `sudo` do for the students of a
  workstation (`sre --user <cmd>` with `SUDO_USER=<login>`), owns the terminals (a pseudo-terminal
  per `sre connect`), writes the answers file with the user's identity, merges the cheat answers
  of the states, tails the operations log and schedules what the Qt GUI used to schedule: the
  periodic evaluations of a lab (`eval_interval_without_exam_mode`), the evaluation before a
  project is closed (`eval_before_exit`), and an idle reaper closing the projects nobody touched
  for the configured time.
- The pool hosts share the lab tree as today (NFS, rsync or the Debian package) and, if the
  instructor wants `sre watch` / `sre sheet` / `sre outline` across the pool, an `archive_dirs`
  entry on a shared directory. The `hostname` of the archives is the pool host.
- Placement: a new project goes to the reachable host with the lowest `projects / max_projects`
  (then the lowest load); a host in exam mode is never used. A classroom workstation holds about
  thirty projects (210 containers in 3.4 GB).

The agent enforces what the `sre` CLI does not check: the exact running lab name and its owner
(a user only reaches their own projects; the `wipe`, `exec` and exam commands have no endpoint),
`allow_connection` of the devices, `allow_self_grade`, the user-allowed states, the
`export_kathara_project` flag. Save and restore are not offered on the web.

## Installation

### From a checkout

`make venv` installs the Python dependencies (`aiohttp`, `jinja2`, `aiohttp-jinja2`, `ldap3`);
`make xterm` (run by `make install`) downloads the terminal library of the browser into
`web/static/vendor/` (checksum-pinned, not committed). `scripts/install.sh` offers to install the
systemd units `sre-agent.service` and `sre-web.service` (disabled) and the example configuration
files `etc/agent.toml` and `etc/web.toml` under the installation directory.

On every pool host: write `/opt/sre/etc/agent.toml` (root, mode 0600) with the listen address
of a management interface and a long random token, then `systemctl enable --now sre-agent`.

On the portal host: create the `sre-web` system user (`adduser --system --group --no-create-home
--shell /usr/sbin/nologin sre-web`), write `/opt/sre/etc/web.toml` (root:sre-web, mode 0640:
it holds the cookie secret and the agent tokens), then `systemctl enable --now sre-web`. Put a
reverse proxy doing TLS in front (`scripts/etc/sre-web-nginx.conf` is an nginx example,
`sre-web-apache.conf` an Apache one that also authenticates the users: the proxy mode below), or
give the portal its own certificate (`tls_cert` / `tls_key`).

### Debian packages

`sysreseval-agent` on every pool host (it depends on `sysreseval` and `sysreseval-web`, whose
code it shares), `sysreseval-web` on the portal host (it depends on nothing of SysResEval). The
units are `sysreseval-agent.service` and `sysreseval-web.service`, disabled by default; the
configuration files are `/etc/sysreseval/agent.toml` and `/etc/sysreseval/web.toml` (examples in
`/usr/share/doc/sysreseval-*/examples/`); the postinst of `sysreseval-web` creates the `sre-web`
user and protects `web.toml` when it exists.

## Configuration

### `agent.toml`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8451` | the address the portal reaches (a management interface, never the students' network) |
| `token` | required | the shared secret of this host, repeated in the portal's `[[hosts]]` entry (32+ characters) |
| `sre_exe` | the installation's `sre` | the command run for the users |
| `poll_interval` | `1` | seconds between two scans of the projects directory (the Qt GUI polls every second too) |
| `max_idle` | `24h` | default idle timeout of a project (the portal gives its own per user); `0` = never |
| `terminals_per_project`, `terminals_per_device` | `16`, `4` | caps on the open terminals (every Connect opens a new terminal on the machine) |
| `max_concurrent_starts`, `max_concurrent_evals` | `2`, `2` | concurrent `sre start` / `sre eval` on the host |
| `lab_list_cache_ttl` | `60` | seconds the output of `sre list` is cached |
| `state_dir` | `/var/lib/sre/web-agent` | the idle clocks of the projects, kept across restarts |
| `tls_cert`, `tls_key` | none | the certificate and key of this agent (TLS to the portal) |
| `tls_ca` | none | the CA a **client certificate** must be signed by: only the portal gets past the handshake (mutual TLS) |
| `allowed_clients` | `[]` (any) | the addresses or networks the agent answers, e.g. `["10.0.0.1", "10.0.1.0/24"]` |
| `occupied_check` | `both` | when the host reports itself *occupied* (no new project, never powered off): `sessions` (a local login session: `loginctl`, or `who`), `projects` (projects of the Qt GUI on the host), `both`, `never` |
| `close_projects_on_stop` | `shutdown` | what the agent does with the projects it manages when its unit stops: `shutdown` closes them (last evaluation, `sre stop`) only when the system is going down, `always`, `never`; within `shutdown_timeout` (`240` s, the unit's `TimeoutStopSec` is 300) |
| `allow_power_off` | `false` | the portal may power the host off (`POST /v1/power/off`, refused when occupied or with any project) with `power_off_command` (`systemctl poweroff`) |
| `[timeouts]` | `start = 900`, `eval = 600`, `state = 600`, `stop = 300`, `export = 600`, `list = 30` | seconds, per `sre` command |

Durations are written as `90`, `"90s"`, `"30m"`, `"2h"` or `"1d"`. An unknown key is refused.

### `web.toml`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8450` | behind a reverse proxy: the loopback |
| `public_url` | none | the URL the users type (the `Origin` of the WebSockets is checked against it) |
| `secret` | required | signs the session cookies (32+ random characters) |
| `trusted_proxies` | `[]` | proxy mode: the addresses or networks of the reverse proxy, the only peers whose identity headers are trusted (the TCP peer address, never `X-Forwarded-For`); required in that mode |
| `languages` | `["en", "fr"]` | the languages offered at login, the first one by default |
| `tls_cert`, `tls_key` | none | own TLS instead of a proxy |
| `[auth] mode` | `anonymous` | `anonymous`: a pseudonym `guest-xxxxxxxx` per browser (the user may type a display name); `ldap`: the directory account; `proxy`: the identity the reverse proxy passes in headers (below) |
| `[auth.ldap]` | | `uri`, then either `bind_dn_template = "uid={login},ou=people,…"` (bind as the user) or `search_base` + `search_filter` (+ `bind_dn` / `bind_password` of a service account) to find the user first; `attr_fullname` (`cn`), `attr_mail` (`mail`); `instructor_groups` (DNs; `memberOf`, or `group_filter = "(member={dn})"`); `start_tls`; `timeout` |
| `[auth.proxy]` | | `header_login` (`X-Remote-User`), `header_fullname` (`X-Remote-Name`), `header_email` (`X-Remote-Email`), `header_groups` (`X-Remote-Groups`): the headers set by the proxy; `groups_separator` (`;`); `instructor_groups`: the values of the groups header giving the instructor role; `logout_url`: where Logout sends the browser (none: no Logout button) |
| `[pool]` | | `idle_timeout_anonymous` (`2h`), `idle_timeout_authenticated` (`24h`): the idle timeout given to the agents per user, `0` = never; `poll_interval` (`2`): seconds between two polls of the agents; `ca`: the CA the agents' certificates are verified against (the system store without it); `client_cert`, `client_key`: the client certificate of the portal, presented to every agent; the elastic pool (below): `spare_projects` (`5`), `min_hosts_up` (`1`), `active_hours` (`07:00-20:00`, local time, `""` = always), `wake_timeout` (`180`), `wake_interval` (`30`), `wol_broadcast` (`255.255.255.255`), `idle_host_timeout` (`0` = never) |
| `[limits]` | | `eval_interval` (`10` s between two self-evaluations of a user), `start_interval` (`30` s between two starts), `login_per_minute` (`5` per client address), `max_answer_bytes` |
| `[admin]` | | `token`: the token of `sre-web pool …` (32+ characters; none = the command is refused), accepted from the loopback only unless `listen_any = true`; `state_file`: the hosts added, removed, enabled and disabled by hand (`/var/lib/sre-web/pool.json` when that directory exists, else `pool.json` next to `web.toml`) |
| `[[hosts]]` | required | one per pool host: `name` (what the URLs show), `url` of its agent, `token` of its `agent.toml`, `max_projects` (`25`); to wake it, `mac` (Wake-on-LAN) or `wake_command` (`{name}`, `{mac}` substituted); `power = true` lets the portal power it off; `enabled = false` keeps it polled without placing projects |

The full name and the e-mail of an LDAP account (`attr_fullname`, `attr_mail`) go into the
answers file of the projects like the GECOS fields do on a workstation, so `sre outline` and
`sre sheet` show them; an anonymous user is identified by the pseudonym and the display name.

### Authentication by the reverse proxy

With `[auth] mode = "proxy"` the portal has no login page: the reverse proxy in front
authenticates the users itself and names them in request headers, which the portal reads on
every request (pages, API calls, the NDJSON streams of the starts, the WebSockets of the
terminals). Nothing is stored in a cookie: the proxy's session is the session, and a request
that does not come from a peer of `trusted_proxies` has no identity whatever its headers.
`scripts/etc/sre-web-apache.conf` is the Apache 2.4 example (`mod_authnz_ldap` + `mod_proxy`):

```apache
<Location "/">
    AuthType Basic
    AuthName "SRE"
    AuthBasicProvider ldap
    AuthLDAPURL "ldaps://ldap.example.org/ou=people,dc=example,dc=org?uid,cn,mail,memberOf?sub?(objectClass=inetOrgPerson)"
    AuthLDAPRemoteUserAttribute uid
    Require valid-user
    RequestHeader set X-Remote-User "expr=%{REMOTE_USER}"
    RequestHeader unset X-Remote-Name
    RequestHeader set X-Remote-Name "%{AUTHENTICATE_CN}e" env=AUTHENTICATE_CN
    RequestHeader unset X-Remote-Email
    RequestHeader set X-Remote-Email "%{AUTHENTICATE_MAIL}e" env=AUTHENTICATE_MAIL
    RequestHeader unset X-Remote-Groups
    RequestHeader set X-Remote-Groups "%{AUTHENTICATE_MEMBEROF}e" env=AUTHENTICATE_MEMBEROF
    RequestHeader unset Authorization
</Location>
ProxyPreserveHost On
ProxyPass        "/" "http://127.0.0.1:8450/" upgrade=websocket timeout=3600
ProxyPassReverse "/" "http://127.0.0.1:8450/"
```

The rules that keep this safe:

- The portal listens on the loopback (or on an address only the proxy reaches) and
  `trusted_proxies` holds the proxy's address as the portal sees it (`127.0.0.1` and `::1` for
  a proxy on the same host); the portal takes the TCP peer address, never `X-Forwarded-For`.
- The proxy sets the four headers on **every** request, replacing whatever the browser sent
  (`RequestHeader set` does; never pass a client header through), after the authentication
  (not `early`). An optional header is removed when the attribute is missing, or `mod_headers`
  writes the literal `(null)`, which the portal treats as empty.
- The attributes exported by `mod_authnz_ldap` (`AUTHENTICATE_CN`...) are those listed in the
  `AuthLDAPURL`; a multi-valued one is joined with `; ` (hence `groups_separator = ";"`). The
  groups header may carry any attribute, `memberOf` DNs or `eduPersonAffiliation` values:
  `instructor_groups` lists the values giving the instructor role. A long list of groups can
  exceed Apache's `LimitRequestFieldSize` (8190 bytes): raise it or export fewer attributes.
- `public_url` must be the `https://` URL the users type (the `Secure` flag of the language
  cookie, the `Origin` check of the WebSockets together with `ProxyPreserveHost On`).
- HTTP Basic authentication cannot be logged out of: the Logout button is hidden unless
  `logout_url` names a logout handler (`mod_auth_form`, sketched at the end of the example).
- `sre-web pool …` talks to the loopback port directly, never through the proxy (the Basic
  authentication would refuse its bearer token).

### Securing the pool (mutual TLS)

The portal and the agents can authenticate each other with certificates of one private CA, on
top of the token: the agent serves TLS and requires a client certificate of that CA, the portal
verifies the agents against the same CA and presents its client certificate.
`scripts/web-tls.sh` makes the files with `openssl`:

```
scripts/web-tls.sh init-ca /root/sre-tls                      # ca.key, ca.crt (10 years)
scripts/web-tls.sh agent /root/sre-tls a01 IP:10.0.0.11 DNS:a01.example.org   # a01.key, a01.crt
scripts/web-tls.sh portal /root/sre-tls                       # portal.key, portal.crt
```

On each pool host, `agent.toml` gets its own certificate and the CA
(`tls_cert = ".../a01.crt"`, `tls_key = ".../a01.key"`, `tls_ca = ".../ca.crt"`, files readable
by root only) and, as a second fence, `allowed_clients = ["<address of the portal>"]`. On the
portal host, `web.toml` gets `[pool] ca = ".../ca.crt"`, `client_cert = ".../portal.crt"`,
`client_key = ".../portal.key"` (readable by `sre-web`), and every `[[hosts]]` URL becomes
`https://<name or address in the certificate's SANs>:8451`. The portal then logs
`TLS to the agents: CA …, client certificate …` and each host as reachable; an agent without
the right certificate, or a client without one, fails at the handshake, before any request.

### A pool of workstations

The pool hosts are typically classroom workstations: off when nobody needs them (a nightly cron
shuts them down), woken by Wake-on-LAN, and sometimes used at the keyboard by a student. The
portal gives each host a **state** from the status of its agent, and `sre-web pool list` shows
it:

| State | Meaning | New projects |
|---|---|---|
| `off` | the agent does not answer | no |
| `waking` | a wake was sent less than `wake_timeout` ago | no, but a start answers "a host is starting" (503, retried by the Open page) |
| `up` | the agent answers, the host is free | yes |
| `occupied` | the agent answers, the host is used locally (`occupied_check`) | no; the web projects already running there go on |
| `exam` | the agent answers, `exam.json` is on the host | no |
| `draining` | the portal asked the host to power off, or `sre-web pool drain` | no; powered off once it is empty |
| `disabled` | `sre-web pool disable`, or `enabled = false` | no |

**Waking.** A host with a `mac` gets a magic packet (UDP port 9 to `wol_broadcast`: the portal
must be on the hosts' network, or the routers must forward the directed broadcast); a host with a
`wake_command` gets that command instead (`ssh relay wakeonlan {mac}`, an IPMI or VM call…).
The portal wakes one sleeping host, in configuration order, whenever the free project slots of
the hosts up (plus the capacity of those waking) drop below `spare_projects`, and keeps
`min_hosts_up` hosts awake during `active_hours`: the floor is re-established in the morning and
not fought at night after the cron. A host still silent after `wake_timeout` is retried after 1,
2, 4… up to 30 minutes, so a machine that is really down is not hammered. The agent must be an
enabled systemd unit on every host (boot → agent up → the portal sees it).

**Occupied hosts.** The agent reports `occupied` when a local login session exists (`loginctl`,
`who` as a fallback) or when projects of the Qt GUI run on the host; the portal places nothing
there and never powers it off. The web projects already running there continue.

**Going down.** When the agent's unit stops because the system halts (the nightly cron, a
`poweroff`), the agent closes the projects it manages as a Close would (the last evaluation,
then `sre stop`), concurrently, within `TimeoutStopSec`; the browsers see "project closed".
With `power = true` on the host and `allow_power_off = true` in its `agent.toml`, the portal
powers off an idle host itself: `idle_host_timeout` (0 by default: only the cron does it), above
`min_hosts_up` and as long as the spare capacity stays, or at once with `sre-web pool poweroff`.

**By hand.** `sre-web pool …` talks to the running portal through its administration API
(`[admin] token`, loopback only by default; `--config`, `--url`, `--token` override the
configuration):

```
sre-web pool list                 # one line per host: state, projects/max, load, terminals, occupied by, uptime
sre-web pool status               # spare capacity, hosts awake vs the floor, active hours, hosts waking
sre-web pool add a03 --url https://10.0.0.13:8451 --token … [--mac … | --wake-command …] [--max-projects 25] [--power]
sre-web pool remove a03 [--force] # refused while the host has projects (--force leaves them to the agent's idle reaper)
sre-web pool disable a03 | enable a03 | wake a03 | poweroff a03 | drain a03
```

The additions, removals and enable / disable flags are kept in `[admin] state_file` and merged
with the `[[hosts]]` of `web.toml` at every start (`list` shows `config` or `added` per host); a
config host removed by hand comes back with `enable`. `--json` gives the raw rows.

## What the users see

- **Login**: the directory account, or (anonymous mode) a display name and a language; in
  proxy mode the web server in front has already asked, there is no login page.
- **Projects**: the user's running projects on the whole pool (Open, Close), "Open a lab" (the
  lab tree with its titles, the Flavor form when the lab has one, the progress of the pulls and
  deploys).
- **A project**: the tabs of the Qt GUI. The schema is drawn by the agent (graphviz) with the
  same options (lines, spacing, order, icons); the questions and the forms are the same; the
  evaluation table has the same parts, subtotals, bonuses and colours; the terminals are
  `xterm.js` windows on `sre connect`: every Connect button opens a new one on its machine (like
  a new xterm in the Qt GUI: `gw`, `gw (2)`, …), the select of the Terminals tab opens one on
  any device (the machines open to the students and the managed switches), the × of a sub-tab
  closes it, `terminals_per_device` caps them; the Log tab appears for debug projects. Export downloads the Kathara zip.
  Session recording (`asciinema`) applies as on a workstation, since it happens in `sre connect`.
- The answers are saved as the user types (debounced), with the identity of the session.

## Security

- The agent listens on a management address and refuses every request without its bearer token
  and the identity headers the portal adds (`X-SRE-Login`, …); the browser never talks to it.
  With mutual TLS (above) only the holder of a client certificate of the CA reaches the token
  check, the traffic to the agents is encrypted, and `allowed_clients` refuses every other
  address with 403. Without TLS the token and the terminals cross the network in clear: keep the
  agents on a trusted management network or behind a tunnel (the agent warns at startup).
- The session cookie is signed (HMAC-SHA256), `HttpOnly`, `SameSite=Strict`, `Secure` behind
  HTTPS; the state-changing calls need the `X-Requested-With: sre-web` header and the WebSockets a
  matching `Origin`; the pages carry a `Content-Security-Policy`.
- In proxy mode nothing is stored in a cookie: every request carries the identity set by the
  reverse proxy, accepted from the peers of `trusted_proxies` only (a request reaching the
  portal from anywhere else has no identity, headers or not).
- Rate limits per user (evaluations, starts) and per client address (logins); the size of the
  answers is capped.
- A project's owner is the third field of its running lab name; the portal and the agent both
  check it. Instructors are the members of `instructor_groups` (of `[auth.ldap]`, or of the
  groups header in proxy mode); the rest of the instructor role is phase 5.

## Limitations

- `x11_host` machines (GUI applications displayed on the student's X server, e.g. the Wireshark
  lab) have no display on a pool host: not supported by the web site.
- The `ports` of the bridged machines are bound on the pool host and shown with its name.
- A host in exam mode (`exam.json`) is excluded from the pool: the exam mode of the web site is a
  later phase, as are the instructor role (instructor-mode projects, the instructor view, every
  project of the pool), the reconnection of a terminal after a network cut, and the save of the
  terminal sessions across a restart of the agent.
- A terminal is lost when the agent restarts; its sub-tab offers a Reconnect button.

## Development

`make web-tests` runs the offline tests of the web front-end: the agent against a fake `sre`
(`tests/mock_sre.py`), the portal against that agent, the templates. `python3 -m sreweb.agent
--config agent.toml --listen 127.0.0.1:8451` and `python3 -m sreweb.portal --config web.toml
--listen 127.0.0.1:8450 --web-dir web` (from `src/`, in the venv) run both locally; with
`sre_exe` pointed at a wrapper of `tests/mock_sre.py` (`SRE_PUB_DIR` exported in the wrapper),
the whole site works without Docker. The French catalog is `locale/fr/LC_MESSAGES/sreweb.po`
(hand-maintained, `make web-translations`).
