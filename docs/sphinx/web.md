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
- Placement: a new project goes to the host where its user has a local login session (the
  workstation they sit at, `follow_local_sessions`), else to the reachable host with the lowest
  `projects / max_projects` (then the lowest load); a host in exam mode is never used, a host
  with `instructors_only = true` never for a student (an instructor may also name the host on
  the Open page). A classroom workstation holds about thirty projects (210 containers in 3.4 GB).
- The lab list of the Open page comes from one host, the one a new project of the user would
  go to (every host of a pool serves the same lab tree; the next candidate is asked when it
  fails), and is kept `labs_cache_ttl` seconds (`60`) per role, since the reserved hosts are
  the instructors' only: opening the page costs one `sre list` per minute whatever the size of
  the pool.

The agent enforces what the `sre` CLI does not check: the exact running lab name (the CLI
resolves substrings) and its owner (a user only reaches their own projects, an instructor every
project; the CLI's own check, `params.check_project_owner`, lets a `--user` caller reach their
own projects and root's only, which is why an instructor is served by privileged calls; the
`wipe`, `stop-all`, `exec` and exam commands have no endpoint), `allow_connection` of the
devices, `allow_self_grade`, the
user-allowed states, the `export_schema_pdf` flag of the lab (the *Export Schema to PDF*
button). Save, restore and the Kathara export are not offered on the web. An instructor acting on
somebody else's project is served by a **privileged** `sre` (no `--user`, their own login:
`sre eval` without cooldown nor counter, `sre connect` to every listed device, `sre state`),
never by a command run as the student; the owner, instructor or not, follows the student path.

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
| `restart_command` | none | how the agent restarts itself on `sre-web-tool restart` (`POST /v1/restart`): by default `systemctl restart` of its own unit, read from `/proc/self/cgroup`; a command for an agent run otherwise (refused, 409, when neither applies) |
| `[timeouts]` | `start = 900`, `eval = 600`, `state = 600`, `stop = 300`, `list = 30` | seconds, per `sre` command (`export`, the timeout of the former Kathara export, is still accepted) |
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
| `[auth.proxy]` | | `header_login` (`X-Remote-User`), `header_fullname` (`X-Remote-Name`), `header_email` (`X-Remote-Email`), `header_groups` (`X-Remote-Groups`): the headers set by the proxy; `groups_separator` (`;`); `header_group` (none; the header holding the student group, e.g. `X-Remote-Group` from `departmentNumber`, its first value); `instructor_groups`: the values of the groups header giving the instructor role; `instructor_header` + `instructor_values` (e.g. `X-Remote-Gid` and `["2000"]`): a second header test; `ldap_roles` (`false`): the portal runs the tests of `[auth.ldap]` itself for the login the proxy gives, and reads its `attr_group`, the result cached per login for `ldap_roles_ttl` (`10m`); `ldap_groups` (`false`): the group part alone (`attr_group` of `[auth.ldap]` for a user whose group header is empty, and for the owners of the Watch page the agents know no group for; the roles stay those of the headers; `ldap_roles` implies it); `logout_url`: where Logout sends the browser (the `/apache-logout` location of the Apache example; none: no Logout button) |
| `[pool]` | | `idle_timeout_anonymous` (`2h`), `idle_timeout_authenticated` (`24h`): the idle timeout given to the agents per user, `0` = never; `poll_interval` (`2`): seconds between two polls of the agents; `ca`: the CA the agents' certificates are verified against (the system store without it); `client_cert`, `client_key`: the client certificate of the portal, presented to every agent; the elastic pool (below): `spare_projects` (`5`), `min_hosts_up` (`1`), `active_hours` (`07:00-20:00`, local time, `""` = always), `wake_timeout` (`180`), `wake_interval` (`30`), `wol_broadcast` (`255.255.255.255`), `idle_host_timeout` (`0` = never); `follow_local_sessions` (`true`): a user logged in at the keyboard of a pool host gets their new projects there whatever its load, below its `max_projects` (*Occupied hosts* below); `labs_cache_ttl` (`60`): seconds the lab list of the Open page, asked from one host, is kept per role (`0` = asked at every open) |
| `[limits]` | | `eval_interval` (`10` s between two self-evaluations of a user), `start_interval` (`30` s between two starts of a user; a start that created no project — the flavor form shown or refused, no host available, the agent not answering — gives the slot back at once), `login_per_minute` (`5` per client address), `max_answer_bytes` |
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
The student group (`attr_group` in LDAP mode, `header_group` or `ldap_roles` / `ldap_groups` +
`attr_group` in proxy mode; `departmentNumber` typically, its first value, capped at 64
characters) goes there too under the key `group` (hence into the archives): the Watch page shows
it and filters on it. With a directory the portal can read (`attr_group` in LDAP mode,
`ldap_roles` or `ldap_groups` in proxy mode), the Watch page also looks up the group of the
owners the agents know none for, first of all the projects started on the Qt GUI, whose answers
file never carries one: one cached lookup per login.
The agent writes that metadata as soon as a project is created, before any answer, and again
when the owner opens the project page and the file lacks it or holds other values (so a
project created by an older agent, or on the Qt GUI, gets its name and group then); a request
whose identity carries no full name or no group (a header the proxy did not set) never erases
the stored values.

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
# Logout: a location that knows no user, so the browser forgets the credentials it cached
ProxyPass "/apache-logout" !
<Location "/apache-logout">
    AuthBasicProvider file
    AuthUserFile /dev/null
    Require valid-user
    ErrorDocument 401 "<!DOCTYPE html>... You are logged out. <a href='/'>Log in again</a> ..."
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
- An HTTP Basic authentication has no session to end, but the browser forgets the credentials
  it cached as soon as the server refuses them: the `/apache-logout` location of the example
  knows no user (`mod_authn_file` on `/dev/null`, the realm inherited from the main location),
  so every request gets a 401 and the browser shows its password dialog once more; cancelling it
  displays the "logged out" page of the `ErrorDocument` (a password typed there is refused and
  the dialog comes back). `logout_url = "/apache-logout"` makes the Logout button appear; the
  button is hidden without it. A `mod_auth_form` login (sketched at the end of the example) has a
  real logout handler at the same URL.
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
event=start login=alice addr=10.0.1.7 lab=sre/dhcp.py instructor=0 host=a01 placement=load result=created rln=1761466323@@@dhcp@@@alice status=200 duration=12.4
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
- `start`: the lab, the host chosen and `placement`, why that host (`load`: the least loaded,
  `session`: the user is logged in at its keyboard, `named`: the instructor named it), whether
  the instructor mode was asked, `result` (`created`, `flavor_form`, `flavor_error`, `error`)
  and `rln`, the running lab name of the new project;
- `project_open` / `project_close`: the project page, open as long as its events WebSocket is
  (`duration` in seconds, `code`: the WebSocket close code; `view=instructor` for the instructor
  view); `terminal_open` / `terminal_close` (`device`, `join`: the session joined, `private`)
  and `display_open` / `display_close` likewise; a socket refused before it opens (401, 403, 404)
  gives a close line with `status` instead of `code`;
- `eval`, `state` (`state`), `stop`, `display_start`: the HTTP status and the duration;
- `denied`: a call answered 401, 403 or 429 (`method`, `path`), `login=-` when nobody was logged
  in; `admin`: a call of `sre-web-tool` changing the pool, or an action of the Pool page of an
  instructor (their `login`);
- the presentations (*Instructors* below): `present_start` (the instructor's `login`, `host`,
  `rln`, `audience`: the number of logins and groups chosen), `present_audience` (the audience
  changed), `present_stop`, and `present_open` (a student opened the presented page: their
  `login`, the `presenter`); the project calls a spectator makes keep their own events, their
  close lines carrying `spectator=1`. The presence socket every page keeps open and the view the
  presenter publishes are not logged.

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
get `instructors_only = true`) and `INSTRUCTOR_MACHINES` (the names of the hosts that get it on
their own, whatever their room), `TLS_DIR_ON_HOSTS` (`/etc/sreweb/tls`,
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
`portal.crt`, `portal.key` to the portal's. Every run computes `hosts.toml` and the agent files
from the variables of the moment, so the rooms, the disabled or reserved hosts may change at any
time, and compares them with the previous run: a file whose content did not change is left as it
is, the others are replaced, what changed is printed per host (`enabled`, `instructors_only`,
`allow_power_off`...) with the new hosts and those no longer selected, and the last line says
whether `hosts.toml` and which agent files are to deploy again; the CA and the portal's
certificate are made once. The hosts' keys, certificates and tokens are made anew on every run,
to deploy again, unless the script is run with `--keep`: the files already there are kept and
only those of the new hosts are made (a kept certificate that no longer names the address of its
host is reported), so a room is added, or a host disabled or reserved, without touching the
hosts already deployed.

### A pool of workstations

The pool hosts are typically classroom workstations: off when nobody needs them (a nightly cron
shuts them down), woken by Wake-on-LAN, and sometimes used at the keyboard by a student. The
portal gives each host a **state** from the status of its agent, and `sre-web-tool list` (or
the *Pool* page of the instructors) shows it:

| State | Meaning | New projects |
|---|---|---|
| `off` | the agent does not answer | no |
| `waking` | a wake was sent less than `wake_timeout` ago | no, but a start answers "a host is starting" (503, retried by the Open page) |
| `up` | the agent answers, the host is free | yes |
| `occupied` | the agent answers, the host is used locally (`occupied_check`) | only the new projects of the users logged in there (`follow_local_sessions`); the web projects already running there go on |
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
there and never powers it off. The web projects already running there continue. One exception,
`follow_local_sessions` (`true` by default): the user logged in at the keyboard of a pool host
gets their new projects on that host, whatever its load, so that a student working at a
classroom workstation uses their own machine through the web too. The agent names the sessions
in its status (`session:<login>`, the OCCUPIED column of `sre-web-tool list`; its
`occupied_check` must include the sessions) and the portal matches them against the login of
the identity, which must therefore be the Unix login of the workstation (the directory `uid`:
`AuthLDAPRemoteUserAttribute uid` in the Apache example; a `guest-…` pseudonym never matches).
The rule overrides the load and the occupation only: when the host is full (`max_projects`),
in exam mode, disabled, draining or reserved for the instructors, the normal placement applies,
and an instructor naming a host on the Open page is obeyed (they may name the host of their own
session). The `start` line of the connection log says `placement=session`.
`follow_local_sessions = false` restores the strict rule: nothing goes to an occupied host.

**Reserved hosts.** A host with `instructors_only = true` never takes a student's project: an
instructor's goes there when they name it on the Open page (the *Host* select lists the
reserved hosts with their state and their projects) or by the automatic placement when it is
the least loaded host they may use. It is outside the elastic pool: its free slots count
neither as spare capacity nor towards `min_hosts_up`, the portal never wakes it by itself
(`sre-web-tool wake`, or its own boot; an instructor finds it greyed while it is off) and
powers it off when idle like any host with `power = true`, whatever the floor and the spare.
`list` shows `(instructors)` after its state. A student logged in at the keyboard of a reserved
host is still placed elsewhere: `follow_local_sessions` never overrides the reservation.

**Going down.** When the agent's unit stops because the system halts (the nightly cron, a
`poweroff`), the agent closes the projects it manages as a Close would (the last evaluation,
then `sre stop`), concurrently, within `TimeoutStopSec`; the browsers see "project closed".
With `power = true` on the host and `allow_power_off = true` in its `agent.toml`, the portal
powers off an idle host itself: `idle_host_timeout` (0 by default: only the cron does it), above
`min_hosts_up` and as long as the spare capacity stays, or at once with `sre-web-tool poweroff`.

**Restarting the agents.** After an update of the tree the agents run the old Python code until
their unit is restarted: `sre-web-tool restart NAME`, or `restart --all` for every reachable host
(whatever its state), tells each agent to restart itself (`POST /v1/restart`). The agent answers
at once, lets its running `sre` commands end (a start, an evaluation; no new project is accepted
meanwhile), then runs `systemctl reset-failed` and `systemctl --no-block restart` on its own
unit (`sre-agent` or `sysreseval-agent`, read from `/proc/self/cgroup`; `restart_command` in
`agent.toml` replaces that for an agent run otherwise). The projects stay
(`close_projects_on_stop = "shutdown"`: a restart is not a shutdown; with `always` they are
closed), the open terminals and virtual desktops are lost, the project pages reconnect by
themselves. The stop is quick: the agent closes the project pages' WebSockets itself (aiohttp
would otherwise wait a minute for them) and `KillMode=mixed` ends what is left. `list` shows
`(restart)` after the state until the portal sees the agent's uptime reset (or gives up after
two minutes with a warning in its journal); the host takes no project meanwhile and keeps its
drain. `--wait` makes the tool wait for the agents to be back (`--timeout`, 180 s by default),
so a deployment script can chain it after the sync. A `DO_NOT_START_AGENT` marker written since
the start is honoured (that agent stops); code that no longer starts leaves the unit failed
after five attempts (`journalctl -u sre-agent`, then `systemctl reset-failed`). The portal
itself is restarted by hand (`systemctl restart sre-web`).

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
sre-web-tool restart a03 | --all [--wait] [--timeout 180]   # the agents restart themselves (new code), the projects stay
```

The additions, removals and enable / disable flags are kept in `[admin] state_file` and merged
with the `[[hosts]]` of `web.toml` at every start (`list` shows `config` or `added` per host); a
config host removed by hand comes back with `enable`. `--json` gives the raw rows. The
instructors have the same actions on the **Pool** page of the portal (`/pool`, see *Instructors*
below), except `add` and `remove`, which stay with the token.

## What the users see

- **Header**: the SRE logo and, with `[site]` in `web.toml`, the institution's logo and name
  next to it, on every page.
- **Login**: the directory account, or (anonymous mode) a display name and a language; in
  proxy mode the web server in front has already asked, there is no login page.
- **Projects**: the user's running projects on the whole pool (Open, Close), "Open a lab" (the
  lab tree with its titles, the Flavor form when the lab has one, the progress of the pulls and
  deploys). Logout asks what to do with the running projects: close them (each as a Close does:
  the last evaluation when the lab asks for it, then `sre stop`; the dialog waits for every
  answer) or leave them running; with no running project the button logs out at once.
- **A project**: the tabs of the Qt GUI. The schema is drawn by the agent (graphviz) with the
  same options (lines, spacing, order, icons); the questions and the forms are the same; the
  evaluation table has the same parts, subtotals, bonuses and colours; the terminals are
  `xterm.js` windows on `sre connect`: every Connect button opens a new one on its machine (like
  a new xterm in the Qt GUI: `gw`, `gw (2)`, …), the select of the Terminals tab opens one on
  any device (the machines open to the students and the managed switches), the × of a sub-tab
  closes it, `terminals_per_device` caps them; the Log tab appears for debug projects. *Export
  Schema to PDF* downloads the drawing of the Schema tab with its current options (never the
  hidden machines), rendered by the agent as the GUI's File → Export Schema to PDF does, unless
  the lab sets `export_schema_pdf = False`; the icons need `rsvg-convert` (`librsvg2-bin`) on the
  pool host, graphviz shapes otherwise. The Kathara export is not offered on the web.
  A terminal is a session shared by its viewers: the live sessions of the project that are not
  on the page are listed under the bar with a Join button (the same shell for everybody, the
  last 64 KiB of output replayed to the newcomer, the pty sized to the smallest window), a
  sub-tab shows how many viewers its session has, and a session ends when its last viewer leaves
  (or when the shell exits). After a disconnection, Reconnect joins the same session again while
  another viewer kept it alive.
- **A presentation**: when an instructor presents a project to the class (*Present* below), the
  page of every chosen student is covered by that project, read-only: every tab is there but
  nothing can be done on it, and the tab shown, the terminals open (the instructor's shells, in
  their exact size, at the largest font that fits), the question selected, the drawing options
  of the schema, the instructor texts and the virtual desktop (view-only) follow what the
  instructor does. The title bar of the presented project is coloured (lavender) and names the
  instructor presenting it. The student's own page is untouched underneath, terminals included:
  when the presentation ends it is back as it was.

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
a minute (logged once) rather than the site unavailable. `ldap_groups = true` does the group part
alone: the directory gives the group of a user whose header carries none, the roles stay those
of the headers (the production case: `gidNumber` exported by Apache, `departmentNumber` read
by the portal for the owners of the Qt GUI projects on the Watch page).

What an instructor gets:

- **Watch** (the link in the header, `/watch`): every running project of every reachable host,
  one row per project with its host, owner (the login), name (the full name of the answers
  metadata), the owner's student group when the site configures one (`attr_group` /
  `header_group`), lab, start time, the age
  of its last archived evaluation, its grade and mark (exo-eval scope, as `sre watch` shows
  them), its errors and warnings, its open terminals and whether the web or the Qt GUI runs it;
  sortable by any column, filtered by text (host, owner, group, lab) and, with a group source,
  by the select listing the groups of the rows (every group, one group, or *No group*: the
  projects started on the Qt GUI carry none unless the portal reads the directory, above), the
  chosen group kept in the URL (`?group=`, a
  bookmark per class group); refreshed every 5 s; a row whose last evaluation had errors is
  red, one without an evaluation younger than 15 minutes (or twice the lab's evaluation
  interval) is amber. Open goes to the project, Close stops it. The agents read the archives of
  their own host (`params.archive_dirs`) on demand, nothing is scanned while nobody watches.
  As in `sre watch`, the page also shows the details: a **click on a row** opens a dialog with
  the last archived evaluation of the project (the owner, the lab and the host in the title,
  the date of the evaluation, the table of its grade elements with the parts, the subtotals,
  the bonuses, the total and the mark, then the errors and the warnings of the run; *Open the
  project* goes to its page; Esc or *Close* goes back), and a **click on the lab cell** of a
  row opens the summary of that lab for the rows shown (the text filter and the group select
  apply, so a class group alone when wanted): a matrix with one row per project and one column
  per grade element (numbered, the element as the tooltip of the number, the parts as a header
  row; a cell is the grade, or the OK / MEH / FAIL letter, coloured like the evaluation table;
  Total and Mark last; a project never evaluated says so), the rows *Max*, *Average* and
  *Success* (how many of the evaluated projects got the full grade) below it, then the table of
  the elements with their maximum, minimum, average and distribution of the grades (`1.5(2)
  3(7)`), a subtotal row per part, as the lab summary of `sre watch`. The elements of the
  projects are matched by their title, whatever the language of each student. Both dialogs
  follow the polls: a new evaluation of the project, or of one of the projects of the lab,
  reloads the content, a project closed is said so. Reading the results of a student this way
  never counts as their activity (their project's idle clock is left alone).
- **Pool** (the link in the header, `/pool`): every host of the pool, one row per host with its
  state as `sre-web-tool list` shows it (the seconds and the failed attempts of a wake), its
  projects and terminals, its load, who occupies it, its uptime, its flags (reserved for
  instructors, power, drain, power off sent, restart sent), the agent's version and its last error, the line
  of `sre-web-tool status` above the table; the state cell is green (up), amber (waking,
  occupied, exam, draining) or grey (off, disabled); sortable by any column, filtered by host
  name (one or several words: the hosts whose name contains any of them, `a01 a02 h` for
  those two and every `h…` host), refreshed every 5 s. The buttons of a row are the commands
  of the tool: *Enable* / *Disable*, *Wake* (a host with a `mac` or a `wake_command`, while it
  is off), *Drain*, *Power off* (asked to confirm; allowed by the agent's `allow_power_off`,
  refused while the host has a project or a local session), each disabled with the reason as
  its tooltip when it does not apply. A checkbox per row (the one of the header ticks the hosts
  shown by the filter) selects hosts for the bar above the table: the count of the selected
  hosts (and how many the filter hides) and the same five buttons, each acting on every
  selected host its action applies to, one call per host run together (the tooltip says how
  many, the button is disabled when none; *Power off* asks once with the names; the failures
  come in one message, the selection stays). Adding and removing hosts, and restarting the
  agents (`restart`, shown as the flag *restart sent* while it lasts), stay with
  `sre-web-tool`. Every action, of a row or of the bar, is an `admin` line of the connection
  log with the instructor's login.
- **Projects** stays the instructor's own projects (Watch holds the others).
- **A student's project**: every tab, the devices all open (the privileged `sre connect`), the
  answers read-only; the top of the page (the site bar and the project bar) takes the **helper
  colour** (teal) on the instructor's browser only, a reminder that the project is not theirs
  (the student's page stays grey; the presentation colour replaces it while the project is
  presented); the Terminals tab **joins the student's live terminals** when it opens (the
  instructor sees the student's shell and may type in it, the student sees the same; a closed
  sub-tab is not joined again), and the select offers a **private terminal** (the student does
  not see it in their list; what the instructor types there stays with them) or a shared one;
  the Evaluation tab opens on the **last archived evaluation** of the project (date, errors in
  the tooltip), shows each new one by itself (the periodic evaluations of the lab, the student's
  own, another instructor's: the agent tells the open pages) and *Start evaluation* runs a
  privileged `sre eval` (no cooldown, nothing counted on the student's side, the exo-eval marks);
  the states apply through the privileged path too.
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
- **Present**: the *Present* button of a project page (the instructor's own project, or a
  student's) opens the list of the users connected to the site (a text filter, the student
  groups among them when the site configures one, *Select all*): the chosen students, one by one
  and by group (a group takes its members connected now and those connecting later), see the
  project read-only on their own browsers (above). The top of the page (the site bar, the
  project bar and the bar under it) then takes the presentation colour (lavender), a reminder
  that the students are watching, and that bar tells how many students are in the audience and
  how many are watching; *Edit audience* changes the list, *Stop presenting* ends it (so does
  closing the project) and the bars are grey again. The spectators follow the instructor's
  page: the tab, the terminals the instructor opens (joined read-only: the students see the same
  shell, cannot type, and do not change its size), the question, the schema options, the
  *Instructor mode* texts, the Display tab view-only, and the Evaluation tab shows them the last
  archived evaluation again after each evaluation of the project. A reloaded page goes on
  presenting; a page closed for a minute ends the presentation. A student is in one presentation
  at a time (the newest that includes them), and falls back to the previous one when it ends.

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
- A project's owner is the third field of its running lab name; the portal, the agent and, in
  user mode, the `sre` CLI itself (`params.check_project_owner`: the local GUI of a pool host
  lists and reaches the same projects as the CLI lets through) check it. An instructor (see
  *Instructors* above) reaches every project, but the agent never
  runs a command as the student for them: a non-owner's `eval`, `state` and `connect` are
  privileged `sre` calls under the instructor's own login, the answers are read-only, and a
  private terminal is listed to instructors only. The operations log of an instructor-mode
  project goes to the subscribers allowed to read it only.
- The spectators of a presentation reach the presented project through the portal only, on a
  short list of read-only calls (the project, its events, the schema, the last evaluation, the
  log, a terminal to *join*, the display), relayed to the agent under the presenter's identity
  (the agent trusts the portal for every identity anyway); everything else is refused, the
  portal never forwards what a spectator's browser sends on a terminal socket and the agent
  attaches a read-only client that cannot type nor resize, and the display socket of a spectator
  goes through a filter dropping the RFB input and resize messages (an unexpected message closes
  it). The presentations live in the portal's memory.

**The virtual desktops.** Each `Xvnc` listens on TCP port 6000+N on every interface of the pool
host, protected by the MIT cookie of its project only, exactly like the X server of a workstation
configured for the labs (`installation.md`); an nftables rule such as
`nft add rule inet filter input tcp dport 6010-6099 iifname != "docker0" drop` keeps the other
hosts out. The RFB socket of a desktop is reachable by root only (the agent); the window manager
runs as `sreweb-x11` with no menu, no launcher and no key binding running a program of the host;
the browser reaches a desktop through the owner check of the portal and of the agent.

## Limitations

- After an update of the tree, the portal and the agents must be restarted for the Python code
  (`sre-web-tool restart --all` for the agents, see *Restarting the agents* above; the
  templates are re-read when they change); the scripts and style sheets of `web/static` are
  served with `Cache-Control: no-cache`, so a browser revalidates them on every page load (an
  `ETag` answers 304 for an unchanged file) and never runs a script older than the page. A page
  loaded before the update keeps its scripts until it is reloaded.
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
- A presentation ends when the portal restarts (nothing is kept on disk); the agents log the
  spectators under the presenter's login (the connection log of the portal has the real ones); a
  spectator's terminal shows the presenter's grid at a smaller font when their window is smaller;
  a presented project never idles out while it is watched.

## Development

`make web-tests` runs the offline tests of the web front-end: the agent against a fake `sre`
(`tests/mock_sre.py`), the portal against that agent, the templates. `python3 -m sreweb.agent
--config agent.toml --listen 127.0.0.1:8451` and `python3 -m sreweb.portal --config web.toml
--listen 127.0.0.1:8450 --web-dir web` (from `src/`, in the venv) run both locally; with
`sre_exe` pointed at a wrapper of `tests/mock_sre.py` (`SRE_PUB_DIR` exported in the wrapper),
the whole site works without Docker. The French catalog is `locale/fr/LC_MESSAGES/sreweb.po`
(hand-maintained, `make web-translations`).

## Stress test

`scripts/web-stress.py` simulates a class of students on a portal through its HTTP / WebSocket
API, as the browser drives it: for each student (logins `stress001`, `stress002`...), the Projects
page (`GET /api/projects` every 5 s, the presence socket), the Open page (`GET /api/labs`),
`POST /api/projects` read as NDJSON until the `result` line (a 503 or 429 is retried after its
`retry_after`), the project page (the project JSON, the schema, the events socket kept open and
reconnected with the browser's backoff, `POST .../touch` every 60 s), a terminal on the first
device open to the student with a few commands typed (the echo of the first one is checked),
then, over `--hold` seconds, `--answers` saves and `--evals` self-evaluations, and finally the
stop. The students begin spread over `--ramp` seconds. `--instructor` adds an instructor on the
Watch page (`GET /api/watch`, the Pool page's calls, every 5 s), `--admin-token` samples
`GET /api/pool` every 5 s (the `reachable` flag and the project count of each host as the portal
sees them), `--probe` measures `GET /api/me` every 2 s. The tool needs Python 3.11 and aiohttp only
(the venv of the installation has them) and runs in **proxy authentication mode**: the identity
of each student travels in the `X-Remote-*` headers, so it must run on a host of
`trusted_proxies` (the portal's own host, against `http://127.0.0.1:8450`); the instructor is
made by `X-Remote-Gid: 2000` (`--instructor-header` / `--instructor-value` otherwise).

The summary on stdout gives, per phase (`start`, `project_get`, `events_ws`, `terminal_ws`,
`eval`, `stop`...), the number of calls, the errors, the latencies (p50 / p95 / max) and the
statuses, then the students completed, the checks failed (`own_projects_only`: a listing showed
another student's project; `project_listed`: the new project was missing from `GET /api/projects`;
`terminal_echo`; `eval_grades`; `events_stayed_open`; `no_unexpected_removed`; `stopped`), the
hosts used and the pool samples (the flips of `reachable` show the status polls timing out).
`--report FILE` writes everything as JSON (one entry per student), `--events FILE` a CSV
timeline (one line per request or socket event). The exit status is 0 when every student
completed with every check true. `--keep` leaves the projects running; `--cleanup` stops every
project of the synthetic logins (through the instructor identity) and exits.

### Stage 1: a fake pool, no Docker

`scripts/web-fake-pool.py` launches from the checkout N real agents whose `sre` is a wrapper of
`tests/mock_sre.py` (the projects are directories, the terminals `/bin/sh`, a start takes
7 × `--start-delay` seconds, an evaluation `--eval-delay`), and a real portal in proxy mode
trusting the loopback, with the production `[limits]` (`--start-interval` / `--eval-interval`
override them), `max_projects` per host and an admin token; then it runs the command given after
`--` with `SRE_STRESS_PORTAL`, `SRE_STRESS_ADMIN_TOKEN` and `SRE_STRESS_WORKDIR` in its environment
(the defaults of `--portal` and `--admin-token`) and stops everything:

```sh
venv/bin/python3 scripts/web-fake-pool.py --hosts 4 --max-projects 25 -- \
    venv/bin/python3 scripts/web-stress.py --users 100 --ramp 60 --hold 120 --instructor --probe \
        --report report.json --events events.csv
```

Without a command the pool stays up until Ctrl-C (`portal=... admin_token=... workdir=...` is
printed first), for runs by hand. The work directory (configs, `portal.log`, `access.log`, one
`agent.log` and `sre.log` per host) is removed at the end unless `--keep-workdir` or a daemon died.

### Stage 2: the production pool

On the portal's host, outside class hours, with the tool copied there (or `/opt/sre/scripts/`
once synced) and the venv of the installation:

1. **Preflight.** The portal must see the tool as a trusted peer: from the host itself when the
   portal container uses the host network (`docker inspect sre-web --format
   '{{.HostConfig.NetworkMode}}'`), from inside the container otherwise (`docker exec`). Read the
   admin token in `[admin]` of `web.toml`. `sre-web-tool status` and `list`: the hosts up and
   the spare slots; with fewer slots than students, the pool wakes hosts during the ramp
   (`wake_timeout`, the students refused with 503 "a host is starting" retry after the
   `retry_after` of the answer, 30 s). Check `ulimit -n` of the portal process (two relayed sockets per
   student). Note the `archive_dirs` of the hosts: every evaluation writes an archive there.
2. **Smoke run:** `web-stress.py --portal http://127.0.0.1:8450 --users 3 --hold 60 --lab sre/dhcp.py
   --instructor --admin-token ... --probe` must give 3 students completed and no check failed.
3. **Full run:** the same with `--users 100 --ramp 300 --hold 600 --report ... --events ...`.
   Meanwhile: `docker stats sre-web` (the CPU of one event loop, the memory), the connection log
   (`event=start ... result=`, `denied`, hosts unreachable), `sre-web-tool list` (states, projects
   per host), the journal of an agent (`journalctl -u sre-agent -f`), the probe's p95 in the summary.
4. **Cleanup:** `web-stress.py --cleanup ...` stops what a stopped run left (a Ctrl-C stops the
   students' projects by itself), then remove the archives of the synthetic logins
   (`*@@@stress0*` under `archive_dirs` on the hosts) and check `sre-web-tool list` is back to
   0 projects.

The reverse proxy and the directory are bypassed (the tool speaks to the portal), and
`follow_local_sessions` never applies (the synthetic logins have no local session).
