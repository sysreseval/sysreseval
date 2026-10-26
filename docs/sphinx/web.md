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
- **`sre-web-tool`** is the command line next to the portal: `sre-web-tool …` lists and
  changes the pool of the running portal through its administration API (*The pool* below).
- The pool hosts share the lab tree as today (NFS, rsync or the Debian package) and, if the
  instructor wants `sre watch` / `sre sheet` / `sre outline` across the pool, an `archive_dirs`
  entry on a shared directory. The `hostname` of the archives is the pool host. The Watch page
  of the instructors needs none of that: each agent reads the archives of its own host
  (`params.archive_dirs`) on demand.
- Placement: a new project goes to the reachable host with the lowest `projects / max_projects`
  (then the lowest load); a host in exam mode is never used, a host with `instructors_only =
  true` never for a student (an instructor may also name the host on the Open page). A classroom
  workstation holds about thirty projects (210 containers in 3.4 GB).

The agent enforces what the `sre` CLI does not check: the exact running lab name and its owner
(a user only reaches their own projects, an instructor every project; the `wipe`, `exec` and
exam commands have no endpoint), `allow_connection` of the devices, `allow_self_grade`, the
user-allowed states, the `export_kathara_project` flag. Save and restore are not offered on the
web. An instructor acting on somebody else's project is served by a **privileged** `sre` (no
`--user`, their own login: `sre eval` without cooldown nor counter, `sre connect` to every listed
device, `sre state`, `sre export`), never by a command run as the student; the owner, instructor
or not, follows the student path.

## Installation

### From a checkout

`make venv` installs the Python dependencies (`aiohttp`, `jinja2`, `aiohttp-jinja2`, `ldap3`);
`make xterm` and `make novnc` (run by `make install`) download the terminal library and the
VNC viewer of the browser into `web/static/vendor/` (checksum-pinned, not committed). `scripts/install.sh` offers to install the
systemd units `sre-agent.service` and `sre-web.service` (disabled) and the example configuration
files `agent.toml` and `web.toml` in `/etc/sreweb/` (`params.agent_config_file` /
`params.web_config_file`; `--config` names another file).

On every pool host: write `/etc/sreweb/agent.toml` (root, mode 0600) with a long random token
(the example file listens on every interface, `0.0.0.0:8451`: `allowed_clients` and the mutual
TLS below keep the port to the portal), then `systemctl enable --now sre-agent`.
The unit starts the agent only when that file exists and `/etc/sreweb/DO_NOT_START_AGENT`
does not (`ConditionPathExists=`: one image for a whole classroom may ship the unit enabled, the
hosts without a configuration file, or with the marker, skip it without any failure; checked at
boot and on `systemctl start` / `restart`), and it does not restart the agent after a
configuration error (exit status 78, `EX_CONFIG`: a bad `agent.toml`, a missing certificate;
the message is in the journal, fix the file then `systemctl restart sre-agent`); five failed
starts within five minutes leave it stopped until the next boot or `systemctl reset-failed`.
For the Display tab (below), install `tigervnc-standalone-server` and `openbox`, create the
`sreweb-x11` system user (`scripts/install.sh` offers it) and set `[display] enabled = true`.
For a whole classroom, `scripts/make-web-hosts.sh` (see *A whole site at once* below) writes
the tokens, the certificates and the `[[hosts]]` entries from a list of machines.

On the portal host: create the `sre-web` system user (`adduser --system --group --no-create-home
--shell /usr/sbin/nologin sre-web`), write `/etc/sreweb/web.toml` (root:sre-web, mode 0640:
it holds the cookie secret and the agent tokens; the files it imports likewise), then
`systemctl enable --now sre-web`. Put a
reverse proxy doing TLS in front (`scripts/etc/sre-web-nginx.conf` is an nginx example,
`sre-web-apache.conf` an Apache one that also authenticates the users: the proxy mode below), or
give the portal its own certificate (`tls_cert` / `tls_key`).

### Debian packages

`sysreseval-agent` on every pool host (it depends on `sysreseval` and `sysreseval-web`, whose
code it shares), `sysreseval-web` on the portal host (it depends on nothing of SysResEval). The
units are `sysreseval-agent.service` and `sysreseval-web.service`, disabled by default (the
agent's with the conditions and restart rules above, on `/etc/sysreseval/agent.toml` and
`/etc/sysreseval/DO_NOT_START_AGENT`); the
configuration files are `/etc/sysreseval/agent.toml` and `/etc/sysreseval/web.toml` (examples in
`/usr/share/doc/sysreseval-*/examples/`); the postinst of `sysreseval-web` creates the `sre-web`
user and protects `web.toml` and `web.d/*.toml` when they exist.

The postinst of `sysreseval-agent` creates the `sreweb-x11` user of the virtual X desktops;
`tigervnc-standalone-server` and `openbox` are its Recommends (the Display tab is off until
`[display] enabled = true`).

## Configuration

### `agent.toml`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8451` | the address the portal reaches: `0.0.0.0:8451` in the example file (every interface, the Docker bridge the students' containers reach included: set `allowed_clients` and `tls_ca`), or a management interface the students do not reach |
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
| `[display]` | `enabled = false` | one virtual X desktop per project whose lab has an `x11_host` machine, shown in the Display tab (see *The Display tab* below): `user` (`sreweb-x11`, the unprivileged account the X processes run as), `xvnc_command` (`Xvnc`, TigerVNC), `window_manager_command` (`openbox`, `""` = none), `geometry` (`1280x800`), `depth` (`24`), `frame_rate` (`30`), `first_display` / `last_display` (`10` / `99`: display `:N` listens on TCP port 6000+N for the containers), `runtime_dir` (`/run/sre-agent`: the RFB sockets and X authority files), `start_timeout` (`10` s for the X server to come up) |

Durations are written as `90`, `"90s"`, `"30m"`, `"2h"` or `"1d"`. An unknown key is refused.
`import` (a path or a list of paths relative to `agent.toml`: a directory, a glob or a file)
merges other files into this one, as for `web.toml` below.

### `web.toml`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8450` | behind a reverse proxy: the loopback |
| `public_url` | none | the URL the users type (the `Origin` of the WebSockets is checked against it) |
| `secret` | required | signs the session cookies (32+ random characters) |
| `trusted_proxies` | `[]` | proxy mode: the addresses or networks of the reverse proxy, the only peers whose identity headers are trusted (the TCP peer address, never `X-Forwarded-For`); required in that mode. In every mode, the connection log takes the client address from the `X-Forwarded-For` header of these peers |
| `languages` | `["en", "fr"]` | the languages offered at login, the first one by default |
| `tls_cert`, `tls_key` | none | own TLS instead of a proxy |
| `[auth] mode` | `anonymous` | `anonymous`: a pseudonym `guest-xxxxxxxx` per browser (the user may type a display name); `ldap`: the directory account; `proxy`: the identity the reverse proxy passes in headers (below) |
| `[auth.ldap]` | | `uri`, then either `bind_dn_template = "uid={login},ou=people,…"` (bind as the user) or `search_base` + `search_filter` (+ `bind_dn` / `bind_password` of a service account) to find the user first; `attr_fullname` (`cn`), `attr_mail` (`mail`), `attr_group` (none; the attribute holding the student group, e.g. `departmentNumber`, its first value: the Group column and filter of the Watch page); the instructor tests (below): `instructor_groups` (DNs; `memberOf`, or `group_filter = "(member={dn})"`), `instructor_filter` (`"(gidNumber=2000)"`, `""` = none), `group_search_base` (none = no membership test) + `instructor_group_filter` (`"(&(objectClass=posixGroup)(gidNumber=2000)(memberUid={login}))"`); `start_tls`; `timeout`. Also read in proxy mode with `ldap_roles` |
| `[auth.proxy]` | | `header_login` (`X-Remote-User`), `header_fullname` (`X-Remote-Name`), `header_email` (`X-Remote-Email`), `header_groups` (`X-Remote-Groups`): the headers set by the proxy; `groups_separator` (`;`); `header_group` (none; the header holding the student group, e.g. `X-Remote-Group` from `departmentNumber`, its first value); `instructor_groups`: the values of the groups header giving the instructor role; `instructor_header` + `instructor_values` (e.g. `X-Remote-Gid` and `["2000"]`): a second header test; `ldap_roles` (`false`): the portal runs the tests of `[auth.ldap]` itself for the login the proxy gives, and reads its `attr_group`, the result cached per login for `ldap_roles_ttl` (`10m`); `logout_url`: where Logout sends the browser (none: no Logout button) |
| `[pool]` | | `idle_timeout_anonymous` (`2h`), `idle_timeout_authenticated` (`24h`): the idle timeout given to the agents per user, `0` = never; `poll_interval` (`2`): seconds between two polls of the agents; `ca`: the CA the agents' certificates are verified against (the system store without it); `client_cert`, `client_key`: the client certificate of the portal, presented to every agent; the elastic pool (below): `spare_projects` (`5`), `min_hosts_up` (`1`), `active_hours` (`07:00-20:00`, local time, `""` = always), `wake_timeout` (`180`), `wake_interval` (`30`), `wol_broadcast` (`255.255.255.255`), `idle_host_timeout` (`0` = never) |
| `[limits]` | | `eval_interval` (`10` s between two self-evaluations of a user), `start_interval` (`30` s between two starts), `login_per_minute` (`5` per client address), `max_answer_bytes` |
| `[admin]` | | `token`: the token of `sre-web-tool …` (32+ characters; none = the command is refused), accepted from the loopback only unless `listen_any = true`; `state_file`: the hosts added, removed, enabled and disabled by hand (`/var/lib/sre-web/pool.json` when that directory exists, else `pool.json` next to `web.toml`) |
| `[access_log]` | | the connection log (below): `file` (none; the absolute path of the log file, e.g. `/var/log/sre-web/access.log`, rotated daily), `keep` (`400` days of rotated files kept; `0` = no rotation, for logrotate), `journal` (`true`: the lines also go to the portal's own log: stderr, the journal, `docker logs`), `session_timeout` (`30m` of inactivity closes a session) |
| `[site]` | none | the institution shown next to the SRE logo in the header of every page, the login page included: `logo` (the absolute path of an image file, JPG / PNG / SVG…, readable by `sre-web`, served at `/site/logo`), `name` (a string, or one per language: `{ fr = "IUT de Démo", en = "Demo Institute" }`, the first configured language when the page's one is missing), `url` (the page the two link to; none: plain text) |
| `[[hosts]]` | required | one per pool host: `name` (what the URLs show), `url` of its agent, `token` of its `agent.toml`, `max_projects` (`25`); to wake it, `mac` (Wake-on-LAN) or `wake_command` (`{name}`, `{mac}` substituted); `power = true` lets the portal power it off; `enabled = false` keeps it polled without placing projects; `instructors_only = true` reserves it for the instructors' projects (a student is never placed there and does not see its labs; a project already running there stays reachable; outside the elastic pool, see *Reserved hosts*) |
| `import` | none | other files merged into this one before it is checked: a path or a list of paths, relative to the directory of `web.toml`: a directory (its `*.toml` files, by name), a glob pattern (`"web.d/*.toml"`, possibly matching nothing) or a file. Tables merge, `[[hosts]]` entries add up; a key given in two files is refused, naming both; an imported file cannot `import` |

`import = ["web.d"]` splits the configuration into `/etc/sysreseval/web.toml` and the `*.toml`
files of `/etc/sysreseval/web.d/`, read by name after it: a file per pool host, the secrets
apart. Nothing is silently overridden: a key given twice is an error naming both files, and an
error found after the merge names `web.toml`. The imported files hold the same secrets as
`web.toml` and need the same owner and mode (root:sre-web, 0640).

The full name and the e-mail of an LDAP account (`attr_fullname`, `attr_mail`) go into the
answers file of the projects like the GECOS fields do on a workstation, so `sre outline` and
`sre sheet` show them; an anonymous user is identified by the pseudonym and the display name.
The student group (`attr_group` in LDAP mode, `header_group` or `ldap_roles` + `attr_group` in
proxy mode; `departmentNumber` typically, its first value, capped at 64 characters) goes there
too under the key `group` (hence into the archives): the Watch page shows it and filters on it.
The agent writes that metadata as soon as a project is created, before any answer.

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
    AuthLDAPURL "ldaps://ldap.example.org/ou=people,dc=example,dc=org?uid,cn,mail,memberOf,gidNumber,departmentNumber?sub?(objectClass=inetOrgPerson)"
    AuthLDAPRemoteUserAttribute uid
    Require valid-user
    RequestHeader set X-Remote-User "expr=%{REMOTE_USER}"
    RequestHeader unset X-Remote-Name
    RequestHeader set X-Remote-Name "%{AUTHENTICATE_CN}e" env=AUTHENTICATE_CN
    RequestHeader unset X-Remote-Email
    RequestHeader set X-Remote-Email "%{AUTHENTICATE_MAIL}e" env=AUTHENTICATE_MAIL
    RequestHeader unset X-Remote-Groups
    RequestHeader set X-Remote-Groups "%{AUTHENTICATE_MEMBEROF}e" env=AUTHENTICATE_MEMBEROF
    RequestHeader unset X-Remote-Gid
    RequestHeader set X-Remote-Gid "%{AUTHENTICATE_GIDNUMBER}e" env=AUTHENTICATE_GIDNUMBER
    RequestHeader unset X-Remote-Group
    RequestHeader set X-Remote-Group "%{AUTHENTICATE_DEPARTMENTNUMBER}e" env=AUTHENTICATE_DEPARTMENTNUMBER
    RequestHeader unset Authorization
</Location>
ProxyPreserveHost On
ProxyPass        "/" "http://127.0.0.1:8450/" upgrade=websocket timeout=3600
ProxyPassReverse "/" "http://127.0.0.1:8450/"
```

The rules that keep this safe:

- The portal listens on the loopback (or on an address only the proxy reaches) and
  `trusted_proxies` holds the proxy's address as the portal sees it (`127.0.0.1` and `::1` for
  a proxy on the same host); the portal takes the TCP peer address, never `X-Forwarded-For`
  (the connection log alone reads that header, from these peers only, for the client address).
- The proxy sets the four headers on **every** request, replacing whatever the browser sent
  (`RequestHeader set` does; never pass a client header through), after the authentication
  (not `early`). An optional header is removed when the attribute is missing, or `mod_headers`
  writes the literal `(null)`, which the portal treats as empty.
- The attributes exported by `mod_authnz_ldap` (`AUTHENTICATE_CN`...) are those listed in the
  `AuthLDAPURL`; a multi-valued one is joined with `; ` (hence `groups_separator = ";"`). The
  groups header may carry any attribute, `memberOf` DNs or `eduPersonAffiliation` values:
  `instructor_groups` lists the values giving the instructor role; `instructor_header` /
  `instructor_values` test a second attribute the same way (`gidNumber` above, the primary
  group); `header_group` names the header carrying the student group (`departmentNumber`
  above). A group membership the proxy cannot export (a `posixGroup` listing its `memberUid`,
  without the memberof overlay) is tested by the portal itself with `ldap_roles = true` and the
  `[auth.ldap]` settings (see *Who is an instructor*). A long list of groups can
  exceed Apache's `LimitRequestFieldSize` (8190 bytes): raise it or export fewer attributes.
- `public_url` must be the `https://` URL the users type (the `Secure` flag of the language
  cookie, the `Origin` check of the WebSockets together with `ProxyPreserveHost On`).
- HTTP Basic authentication cannot be logged out of: the Logout button is hidden unless
  `logout_url` names a logout handler (`mod_auth_form`, sketched at the end of the example).
- `sre-web-tool …` talks to the loopback port directly, never through the proxy (the Basic
  authentication would refuse its bearer token).

### The connection log

`[access_log]` of `web.toml` makes the portal keep a log of its use: who connected from where
and for how long, which projects were opened, started, evaluated, closed. One `key=value` line
per event (a value with spaces or quotes is JSON-quoted, so a user agent or a display name
cannot forge a line), in the file named by `file` (rotated at midnight, `keep` days of
`access.log.YYYY-MM-DD` files kept; `keep = 0` leaves the rotation to logrotate, the file is
reopened when it moves) and, with `journal = true` (the default, and the whole log when no
file is set), in the portal's own log on stderr: the journal under systemd, `docker logs` in a
container. The unit creates `/var/log/sre-web` (`LogsDirectory=`); a container mounts a
directory for the file or writes it under `/var/lib/sre-web`. The lines of the file start with
a timestamp (`2026-10-26T09:12:03+0100`):

```
event=login login=alice addr=10.0.1.7 mode=ldap role=student anon=0 name="Alice Test"
event=session_open login=alice addr=10.0.1.7 role=student anon=0 name="Alice Test" ua="Mozilla/5.0 …"
event=start login=alice addr=10.0.1.7 lab=sre/dhcp.py instructor=0 host=a01 result=created rln=1761466323@@@dhcp@@@alice status=200 duration=12.4
event=project_open login=alice addr=10.0.1.7 host=a01 rln=1761466323@@@dhcp@@@alice
event=terminal_open login=alice addr=10.0.1.7 host=a01 rln=1761466323@@@dhcp@@@alice device=m1 join=- private=0
event=terminal_close login=alice addr=10.0.1.7 host=a01 rln=1761466323@@@dhcp@@@alice device=m1 join=- private=0 duration=612.3 code=1000
event=eval login=alice addr=10.0.1.7 host=a01 rln=1761466323@@@dhcp@@@alice status=200 duration=8.1
event=project_close login=alice addr=10.0.1.7 host=a01 rln=1761466323@@@dhcp@@@alice duration=1803.6 code=1001
event=stop login=alice addr=10.0.1.7 host=a01 rln=1761466323@@@dhcp@@@alice status=200 duration=3.0
event=logout login=alice addr=10.0.1.7 status=200 duration=0.0
event=session_close login=alice addr=10.0.1.7 reason=logout since=2026-10-26T09:11:50+0100 duration=1850 requests=14 projects=1761466323@@@dhcp@@@alice
```

A **session** is the requests of one login from one client address (`addr`): it opens at the
first request (`session_open`: role, pseudonym or not, name, user agent) and closes
(`session_close`) at a logout, after `session_timeout` without a request (`reason=idle`; the
duration then ends at the last request, not at the expiry) or when the portal stops
(`shutdown`); a session whose project page, terminal or desktop is still open never expires.
The closing line gives the start, the duration in seconds, the number of requests (the polls of
the pages and the keep-alive of a project are not counted) and the projects used. In proxy
mode there is no login: the first request of a user opens the session and the request following
a logout opens another one. The other events:

- `login` (`mode`: `anonymous` or `ldap`) and `login_failed` (`reason`: `password`,
  `rate_limited`, `directory` when the directory does not answer, `proxy_mode`);
- `start`: the lab, the host chosen, whether the instructor mode was asked, `result` (`created`,
  `flavor_form`, `flavor_error`, `error`) and `rln`, the running lab name of the new project;
- `project_open` / `project_close`: the project page, open as long as its events WebSocket is
  (`duration` in seconds, `code`: the WebSocket close code; `view=instructor` for the instructor
  view); `terminal_open` / `terminal_close` (`device`, `join`: the session joined, `private`)
  and `display_open` / `display_close` likewise; a socket refused before it opens (401, 403, 404)
  gives a close line with `status` instead of `code`;
- `eval`, `state` (`state`), `export`, `stop`, `display_start`: the HTTP status and the duration;
- `denied`: a call answered 401, 403 or 429 (`method`, `path`), `login=-` when nobody was logged
  in; `admin`: a call of `sre-web-tool` changing the pool.

The client address is the last entry of `X-Forwarded-For` when the TCP peer is one of
`trusted_proxies` (the Apache and nginx examples set that header), the peer address otherwise:
set `trusted_proxies` in every mode to log the real addresses behind a proxy. The login rate
limit (`[limits] login_per_minute`) counts per logged address too. The log holds personal data
(names, addresses, what was done when): `keep` is its retention, and the file is readable by
`sre-web` and root only (`/var/log/sre-web` is mode 0750).

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

### A whole site at once (`scripts/make-web-hosts.sh`)

`scripts/make-web-hosts.sh` writes everything the previous section asks for, for every pool
host of a site, from a list of its machines:

```
IP_MAC_FILE=ip_mac.txt OUT_DIR=/root/sre-pool REGEXP='^([a-z])[0-9]+$' ROOMS="a h" DISABLED_ROOMS=h \
    scripts/make-web-hosts.sh
```

The list has one `mac;ip;name` line per machine (`e4:54:e8:d1:6c:1c;10.0.128.1;a01`: the MAC
address for Wake-on-LAN, the IPv4 address the portal reaches its agent at, the name). A machine gets an
agent when its lower-cased name matches `REGEXP`; the first group of the expression, when there
is one, is its room, so that `ROOMS` selects the rooms joining the pool (empty: every qualified
machine) and `DISABLED_ROOMS` those whose hosts start with `enabled = false` (polled, no project
placed there until `sre-web-tool enable`). These five variables are required and have no
default; `AGENT_PORT` (8451), `MAX_PROJECTS` (25), `POWER` (`power = true` in the entries and
`allow_power_off = true` on the agents), `DOMAIN` (a `DNS:<name>.<domain>` SAN too),
`PORTAL_ADDRESS` (`allowed_clients` of the agents), `INSTRUCTOR_ROOMS` (the rooms whose hosts
get `instructors_only = true`), `TLS_DIR_ON_HOSTS` (`/etc/sreweb/tls`,
the paths written in the files) and `CA_KEY` / `CA_CRT` (both set: an existing CA copied into
`OUT_DIR` instead of a new one, so that the hosts of a new `OUT_DIR` are signed by the CA the
portal already knows; refused when `OUT_DIR` holds another CA) are optional.

In `OUT_DIR` (private keys and tokens: outside any repository) it writes, through `web-tls.sh`,
the CA and the portal's client certificate once, then per host a key and a certificate (SANs
`IP:<ip>` and `DNS:<name>`), a token in `<name>.token`, and:

- `hosts.toml`: the `[[hosts]]` entries, one room after the other, with the three `[pool]` TLS
  lines of `web.toml` in its header; a file of `web.d/` (`import = ["web.d"]`) or pasted at the
  end of `web.toml`;
- `agent-<name>.toml`: the host-specific lines of that host's `agent.toml` (`listen = "<ip>:8451"`,
  `token`, `tls_*`, and `allowed_clients` / `allow_power_off` when asked), to complete with the
  example file, whose own `listen` and `token` lines are then removed (a key given twice is
  refused).

Copy `<name>.crt`, `<name>.key` and `ca.crt` to `TLS_DIR_ON_HOSTS` of each host, and `ca.crt`,
`portal.crt`, `portal.key` to the portal's. Every run rewrites `hosts.toml` and the agent files, so
the rooms may change at any time; the CA and the portal's certificate are made once. The hosts'
keys, certificates and tokens are made anew on every run, to deploy again, unless the script is
run with `--keep`: the files already there are kept and only those of the new hosts are made (a
kept certificate that no longer names the address of its host is reported), so a room is added
without touching the hosts already deployed.

### A pool of workstations

The pool hosts are typically classroom workstations: off when nobody needs them (a nightly cron
shuts them down), woken by Wake-on-LAN, and sometimes used at the keyboard by a student. The
portal gives each host a **state** from the status of its agent, and `sre-web-tool list` shows
it:

| State | Meaning | New projects |
|---|---|---|
| `off` | the agent does not answer | no |
| `waking` | a wake was sent less than `wake_timeout` ago | no, but a start answers "a host is starting" (503, retried by the Open page) |
| `up` | the agent answers, the host is free | yes |
| `occupied` | the agent answers, the host is used locally (`occupied_check`) | no; the web projects already running there go on |
| `exam` | the agent answers, `exam.json` is on the host | no |
| `draining` | the portal asked the host to power off, or `sre-web-tool drain` | no; powered off once it is empty |
| `disabled` | `sre-web-tool disable`, or `enabled = false` | no |

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

**Reserved hosts.** A host with `instructors_only = true` never takes a student's project: an
instructor's goes there when they name it on the Open page (the *Host* select lists the
reserved hosts with their state and their projects) or by the automatic placement when it is
the least loaded host they may use. It is outside the elastic pool: its free slots count
neither as spare capacity nor towards `min_hosts_up`, the portal never wakes it by itself
(`sre-web-tool wake`, or its own boot; an instructor finds it greyed while it is off) and
powers it off when idle like any host with `power = true`, whatever the floor and the spare.
`list` shows `(instructors)` after its state.

**Going down.** When the agent's unit stops because the system halts (the nightly cron, a
`poweroff`), the agent closes the projects it manages as a Close would (the last evaluation,
then `sre stop`), concurrently, within `TimeoutStopSec`; the browsers see "project closed".
With `power = true` on the host and `allow_power_off = true` in its `agent.toml`, the portal
powers off an idle host itself: `idle_host_timeout` (0 by default: only the cron does it), above
`min_hosts_up` and as long as the spare capacity stays, or at once with `sre-web-tool poweroff`.

**By hand.** `sre-web-tool …` (`sbin/sre-web-tool` of a checkout, `/usr/sbin/sre-web-tool`
of the `sysreseval-web` package; `python3 -m sreweb.tool` from the sources) talks to the running
portal through its administration API (`[admin] token`, loopback only by default; `--config`,
`--url`, `--token` override the configuration):

```
sre-web-tool list                 # one line per host: state, projects/max, load, terminals, occupied by, uptime
sre-web-tool status               # spare capacity, hosts awake vs the floor, active hours, hosts waking
sre-web-tool add a03 --url https://10.0.0.13:8451 --token … [--mac … | --wake-command …] [--max-projects 25] [--power] [--instructors-only]
sre-web-tool remove a03 [--force] # refused while the host has projects (--force leaves them to the agent's idle reaper)
sre-web-tool disable a03 | enable a03 | wake a03 | poweroff a03 | drain a03
```

The additions, removals and enable / disable flags are kept in `[admin] state_file` and merged
with the `[[hosts]]` of `web.toml` at every start (`list` shows `config` or `added` per host); a
config host removed by hand comes back with `enable`. `--json` gives the raw rows.

## What the users see

- **Header**: the SRE logo and, with `[site]` in `web.toml`, the institution's logo and name
  next to it, on every page.
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
  A terminal is a session shared by its viewers: the live sessions of the project that are not
  on the page are listed under the bar with a Join button (the same shell for everybody, the
  last 64 KiB of output replayed to the newcomer, the pty sized to the smallest window), a
  sub-tab shows how many viewers its session has, and a session ends when its last viewer leaves
  (or when the shell exits). After a disconnection, Reconnect joins the same session again while
  another viewer kept it alive.

### Instructors

Who is an instructor is decided by the directory, the role being the OR of the tests configured
in `web.toml` (a test whose key is empty is skipped):

- `instructor_groups`: the user is a member of one of these groups (DNs), through the
  `memberOf` attribute of their entry or, with `group_filter = "(member={dn})"`, a search of the
  groups under `group_search_base` (`search_base` without it);
- `instructor_filter`: the user's own entry matches this LDAP filter (a BASE search on their
  DN), `"(gidNumber=2000)"` by default — the primary group; a site with the memberof overlay may
  write `"(memberOf=cn=teachers,ou=groups,dc=example,dc=org)"`; `""` disables the test;
- `group_search_base` + `instructor_group_filter`: a group found under that base names the user
  (`{login}` and `{dn}` are substituted, filter-escaped), by default a `posixGroup` of gid 2000
  listing the login in `memberUid` (the group search that needs no overlay; a `groupOfNames`
  site writes `"(&(cn=teachers)(member={dn}))"`); setting `group_search_base` enables the test.

In LDAP mode the portal runs them when the user logs in (the role is kept in the session cookie:
a change applies at the next login). In proxy mode the reverse proxy authenticates and the tests
are run on the request headers (`instructor_groups` on the groups header, `instructor_values` on
`instructor_header`: any attribute `mod_authnz_ldap` exports) and, with `ldap_roles = true`, by the
portal itself with the `[auth.ldap]` settings for the login the proxy gives (the service account
or an anonymous search finds the entry, then the same three tests; the entry's `attr_group` is
read at the same time, so with that key set the lookup runs for the users the headers already
made instructors too, who keep the role whatever the directory says), the result being cached
per login for `ldap_roles_ttl`; a directory failure makes the login a student without group for
a minute (logged once) rather than the site unavailable.

What an instructor gets:

- **Watch** (the link in the header, `/watch`): every running project of every reachable host,
  one row per project with its host, owner (the full name as a tooltip), the owner's student
  group when the site configures one (`attr_group` / `header_group`), lab, start time, the age
  of its last archived evaluation, its grade and mark (exo-eval scope, as `sre watch` shows
  them), its errors and warnings, its open terminals and whether the web or the Qt GUI runs it;
  sortable by any column, filtered by text (host, owner, group, lab) and, with a group source,
  by the select listing the groups of the rows (every group, one group, or *No group*: the
  projects started on the Qt GUI carry none), the chosen group kept in the URL (`?group=`, a
  bookmark per class group); refreshed every 5 s; a row whose last evaluation had errors is
  red, one without an evaluation younger than 15 minutes (or twice the lab's evaluation
  interval) is amber. Open goes to the project, Close stops it. The agents read the archives of
  their own host (`params.archive_dirs`) on demand, nothing is scanned while nobody watches.
- **Projects** stays the instructor's own projects (Watch holds the others).
- **A student's project**: every tab, the devices all open (the privileged `sre connect`), the
  answers read-only; the Terminals tab **joins the student's live terminals** when it opens (the
  instructor sees the student's shell and may type in it, the student sees the same; a closed
  sub-tab is not joined again), and the select offers a **private terminal** (the student does
  not see it in their list; what the instructor types there stays with them) or a shared one;
  the Evaluation tab opens on the **last archived evaluation** of the project (date, errors in
  the tooltip) and *Start evaluation* runs a privileged `sre eval` (no cooldown, nothing counted
  on the student's side, the exo-eval marks); the states apply through the privileged path too.
- **Instructor mode** on the Open page: the instructor's own project started with
  `sre start --instructor-mode` (the instructor texts kept in `info.json`, every state listed,
  the states logged): the *Instructor mode* button of the project page then shows the
  `instructor()` texts of the Informations and Questions tabs, every state and the Log tab, as in
  the Qt GUI. A student's project holds no instructor text (the CLI strips them), so the button
  does not appear there.
- **The host of a project**: the *Host* select of the Open page (shown when the pool has a host
  reserved for instructors, `instructors_only = true` in `[[hosts]]`) names one of them, with
  its state and its projects (greyed when off or full), or leaves the automatic placement: the
  least loaded host the instructor may use, reserved or shared. `POST /api/projects` takes the
  optional `host`; a student sending one gets 403.

### The Display tab

A lab machine declared `x11_host` draws its graphical applications (Wireshark, Firefox…) on
the X server of the host: on a workstation, the student's own desktop. A pool host has no X
server, so the agent runs one virtual desktop per project whose lab has such a machine: a
TigerVNC `Xvnc` with an `openbox` window manager, started as the unprivileged `sreweb-x11`
user right after `sre start`, shown in the **Display** tab by noVNC (`make novnc`). The
containers reach display `:N` on TCP port 6000+N of the host with the cookie of the project
(the core passes them `SRE_DISPLAY` and `SRE_XAUTH_COOKIE`, the `.bashrc` of the images ≥ 1.31
sets `DISPLAY` from them); the browser reaches the RFB Unix socket of the server through the
agent and the portal, as a WebSocket of binary frames. The desktop follows the size of the tab
(*Resize the desktop*; *Fit to window* scales it instead), the text box of the bar sends text to
the X clipboard and shows what the applications copy, *Reconnect* opens the stream again. The
number and the cookie of a project never change: a desktop that died, or that was lost when the
agent restarted (its X server is a child of the agent), is started again at the next use of the
tab, empty. `[display]` of `agent.toml` holds the geometry, the range of display numbers and
the commands.
  Session recording (`asciinema`) applies as on a workstation, since it happens in `sre connect`.
- The answers are saved as the user types (debounced), with the identity of the session.

## Security

- The agent refuses every request without its bearer token
  and the identity headers the portal adds (`X-SRE-Login`, `X-SRE-Fullname`, `X-SRE-Group`, …); the browser never talks to it.
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
- The connection log (`[access_log]`) keeps who did what from where: the sessions with their
  duration and projects, the logins and their failures, the denied calls, the administration
  calls. The only header it reads is `X-Forwarded-For`, from the peers of `trusted_proxies`,
  for the client address; the identity never comes from it.
- A project's owner is the third field of its running lab name; the portal and the agent both
  check it. An instructor (see *Instructors* above) reaches every project, but the agent never
  runs a command as the student for them: a non-owner's `eval`, `state`, `connect` and `export`
  are privileged `sre` calls under the instructor's own login, the answers are read-only, and a
  private terminal is listed to instructors only. The operations log of an instructor-mode
  project goes to the subscribers allowed to read it only.

**The virtual desktops.** Each `Xvnc` listens on TCP port 6000+N on every interface of the pool
host, protected by the MIT cookie of its project only, exactly like the X server of a workstation
configured for the labs (`installation.md`); an nftables rule such as
`nft add rule inet filter input tcp dport 6010-6099 iifname != "docker0" drop` keeps the other
hosts out. The RFB socket of a desktop is reachable by root only (the agent); the window manager
runs as `sreweb-x11` with no menu, no launcher and no key binding running a program of the host;
the browser reaches a desktop through the owner check of the portal and of the agent.

## Limitations

- The virtual X desktops die with the agent (a restart of its unit): they are started again,
  empty, at the next use of the Display tab; the applications shown must be launched again.
- The `ports` of the bridged machines are bound on the pool host and shown with its name.
- A host in exam mode (`exam.json`) is excluded from the pool: the exam mode of the web site is a
  later phase, as is the save of the terminal sessions across a restart of the agent.
- A terminal session ends when its last viewer leaves: a page reload loses it unless another
  viewer (an instructor who joined) keeps it alive, in which case Reconnect joins it again.
  A terminal is lost when the agent restarts; its sub-tab offers a Reconnect button.
- The replay a joining viewer gets may start inside an escape sequence; the next prompt or
  redraw of the application settles the display.
- The `[limits] eval_interval` of the portal (10 s between two evaluations of a login) also
  applies to an instructor evaluating several students' projects in a row.

## Development

`make web-tests` runs the offline tests of the web front-end: the agent against a fake `sre`
(`tests/mock_sre.py`), the portal against that agent, the templates. `python3 -m sreweb.agent
--config agent.toml --listen 127.0.0.1:8451` and `python3 -m sreweb.portal --config web.toml
--listen 127.0.0.1:8450 --web-dir web` (from `src/`, in the venv) run both locally; with
`sre_exe` pointed at a wrapper of `tests/mock_sre.py` (`SRE_PUB_DIR` exported in the wrapper),
the whole site works without Docker. The French catalog is `locale/fr/LC_MESSAGES/sreweb.po`
(hand-maintained, `make web-translations`).
