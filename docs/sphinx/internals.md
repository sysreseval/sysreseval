# Runtime & Internals

## Architecture

```{graphviz}
digraph architecture {
    rankdir=TB;
    graph [fontname="sans-serif", fontsize=11];
    node  [fontname="sans-serif", fontsize=11, shape=box,
           style="filled,rounded", margin="0.3,0.2"];
    edge  [fontname="sans-serif", fontsize=10];

    subgraph cluster_desktop {
        label="Student desktop";
        labeljust=l;
        style=dashed;
        color="#888888";
        bgcolor="#fafafa";
        margin=20;

        gui [label="sysreseval  (PySide6 GUI)\lsrc/sysreseval/\l    main_window.py · project_widget.py\l    view/: machines · questions · evaluations · schema\l",
             fillcolor="#dae8fc", color="#6c8ebf"];

        wrapper [label="sre-wrapper  (bin/sre-wrapper, C binary)\l    • sets USER_USERNAME env var\l    • sudo /opt/sre/sbin/sre --user ...\l",
                 fillcolor="#ffe6cc", color="#d6b656"];

        cli [label="sre CLI  (src/sre.py → src/SRE/)\lcommand/: start · eval · stop · watch · sheet · cat …\llib_sre.py: Data0 · NetScheme0 · Grade0 · Flavor0\l",
             fillcolor="#dae8fc", color="#6c8ebf"];

        docker [label="Kathara / Docker\lRunning containers  ↔  exetests.py  (in container)\l",
                fillcolor="#d5e8d4", color="#82b366"];

        gui     -> wrapper [label="  calls via sre-wrapper"];
        wrapper -> cli     [label="  setuid(sre_uid=1100)"];
        cli     -> docker;
    }
}
```

Every command that touches Docker runs as user `sre` (uid `1100`): `sre-wrapper` exports `USER_USERNAME` and calls `sudo sre --user`; the CLI then drops from root to `sre_uid`. How the drop happens depends on the project:

- **Non-privileged projects** (no machine has `privileged=True`): privileges are dropped **permanently** at start via `setuid(sre_uid)` / `setgid(docker_gid)` — the process can never regain root for the rest of its life.
- **Privileged projects** (at least one machine has `privileged=True`): privileges are dropped **temporarily** via `seteuid`/`setegid` only. Kathara requires the deploy/connect/exec paths to run as genuine root (to mount cgroups, attach a TTY to `/sbin/init`, etc.), so the CLI raises the effective uid back to 0 around those operations and lowers it again afterwards. Host-side subprocesses still drop to `sre_uid` in the child via `preexec_drop_to_sre()`, so user code on the host never runs as root.

## Filesystem layout

| Path | Description                                                                                                                                                                                                    |
|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `/opt/sre/` | Installation root                                                                                                                                                                                              |
| `/opt/sre/sbin/sre` | CLI binary                                                                                                                                                                                                     |
| `/opt/sre/bin/sre-wrapper` | C binary for student use (handles sudo)                                                                                                                                                                        |
| `/opt/sre/bin/sysreseval` | GUI launcher script                                                                                                                                                                                            |
| `/opt/sre/lab/` | Lab files                                                                                                                                                                                                      |
| `/opt/sre/lib/` | Shared libraries for project files (`ips.py`, `std.py`, `exetests.py`, `net_config.py`, `dhcp.py`, `ping.py`, `ssh.py`, `tls.py`, `grade_helpers.py`, `frr.py`, `state_helpers.py`, `pcap_gen.py`, `utils.py`) |
| `/opt/sre/graphics/` | SVG icons and logos                                                                                                                                                                                            |
| `/opt/sre/locale/` | Compiled gettext translations for the CLI                                                                                                                                                                      |
| `/var/lib/sre/` | Runtime state root (`sre_pub_dir`)                                                                                                                                                                             |
| `/var/lib/sre/exam.json` | Exam configuration (absent = no exam)                                                                                                                                                                          |
| `/var/lib/sre/projects/` | One directory per running lab instance                                                                                                                                                                         |
| `/var/lib/sre/archives/` | Default evaluation archive directory                                                                                                                                                                           |
| `/var/lib/sre/last_self_grades/` | Self-grade cooldown timestamps                                                                                                                                                                                 |
| `/home/sre/` | Shared directories for projects with `shared_path=True` (mode `0o777`, removed on stop/wipe)                                                                                                                   |

### Running lab directory

```
/var/lib/sre/projects/{timestamp}@@@{lab_name}@@@{username}/
├── .private/               mode 0o700
│   ├── data.json           serialized Data instance, mode 0o600
│   ├── srelab              symlink to the lab's srelab.py
│   ├── eval_in_progress    lock file (PID) during active eval
│   └── auto_eval.log       one ISO timestamp per student self-evaluation
├── info.json               public machine/question metadata (InfoLab)
├── scheme.svg              graphviz network diagram
├── answers/
│   ├── answers.json        student answers (updated by GUI)
│   └── cheat.json          instructor-provided answers (if any)
└── shared/                 mode 0o777 (only if shared_path=True)
```

## Configuration

### Constants (`src/SRE/params.py`)

| Constant | Value | Description |
|----------|-------|-------------|
| `sre_uid` | `1100` | UID of the `sre` system user |
| `docker_gid` | `988` | GID of the `docker` group |
| `max_docker_concurrency` | `16` | Max parallel Docker API calls during eval |
| `default_eval_interval_during_exams` | `60` | Default auto-eval period (s) |
| `default_exam_duration` | `90` | Default exam duration (min), used if `duration` absent from `exam.json` |
| `default_inactivity_threshold_in_watch_command` | `90` | `sre watch` inactivity alert threshold |
| `max_duration_between_exam_pre_start_and_start` | `60` | Window before `start_after` during which `pre-start-exam` fires (s) |
| `email_in_gecos_last_field` | `True` | Extract last GECOS sub-field as student email |
| `terminal_cmd_prefix` | `["/usr/bin/mate-terminal", "--"]` | External terminal emulator |
| `terminal_font_size` | `12` | Default terminal font size (pt) |
| `terminal_color_scheme` | `"black_on_white"` | Default terminal colors |
| `exam_only_affix` | `["_EXAM_", "_OLD_", "_DRAFT_", "_TESTS_"]` | Name substrings that hide labs from `sre list` |
| `authorized_src_dir` | `['/opt/sre/lab', '/home/etudiant']` | Allowed lab source directories |
| `hostname_keyword` / `login_keyword` / `fullname_keyword` / `email_keyword` / `language_keyword` | `"hostname"` / `"login"` / `"fullname"` / `"email"` / `"language"` | Keys used in `answers.json` and archive `answers` dict |

### Environment variables

#### GUI / wrapper → sre CLI

| Variable | Used by | Description |
|----------|---------|-------------|
| `USER_USERNAME` | sre CLI (with `--user`) | Student login name (set by `sre-wrapper` from the invoking `USER`) |
| `SRE_PUB_DIR` | sre CLI, GUI, tests | Override `/var/lib/sre` |
| `SRE_WRAPPER` | params.py | Override the sre-wrapper path |
| `LANG` | sre CLI | Loads French help strings when set to a French locale |

#### sre CLI → containers

Injected into machines at deploy / `exec` / state-transition time.

| Variable | Description |
|----------|-------------|
| `SRE_LAB_NAME` | Running lab name (`{timestamp}@@@{lab_name}@@@{username}`) — defined by `params.sre_name_env_variable` |
| `SRE_XAUTH_COOKIE` | X authority cookie forwarded into privileged containers so GUI apps can reach the host X server — defined by `params.sre_xauth_cookie_env_variable` |
| `SRE_HOST_IP` | Host IP reachable from containers (default `172.17.0.1`) — defined by `params.sre_host_ip_env_variable` |

### Locale

The CLI uses `gettext` (`locale/fr/LC_MESSAGES/sre.mo`); the GUI uses Qt `.qm` catalogs (`translations/sysreseval_fr.qm`). Both are regenerated by `make translations`.

## Dynamic module loading

Each lab is loaded at runtime via `importlib.util.spec_from_file_location('srelab', ...)`. The module path must sit under `params.authorized_src_dir` (`/opt/sre/lab/` or `/home/etudiant/`), and `/opt/sre/lib/` is prepended to `sys.path` so labs can `from ips import …`, `from net_config import …`, etc.

## Data serialization

`Data0` encodes to JSON/msgpack with a polymorphic envelope:

```json
{
  "__type__": "srelab.Data",
  "data": {
    "secret": "changeme",
    "ips":  {"router": "10.0.0.1/24"},
    "nets": {"lan1": "10.0.0.0/24"}
  }
}
```

| Value | Encoding |
|-------|----------|
| `IPv4Interface` inside `ips` container | `"10.0.0.1/24"` |
| `IPv4Network` inside `nets` container | `"10.0.0.0/24"` |
| `IPv4Address` (standalone field) | `{"__ip__": "10.0.0.1"}` |
| `IPv4Network` (standalone field) | `{"__net__": "10.0.0.0/24"}` |
| Nested `Data0` subclass | `{"__type__": "module.ClassName", "data": {...}}` |

`data.json` is saved mode `0o600` inside `.private/` (mode `0o700`).

## Test execution

`Grade.run_tests()` per step:

1. Call `grade()` to *register* tests (no execution).
2. Group commands per machine and encode them into one env var `EXETESTS@@@{timeout}:{cmd}@@@{timeout}:{cmd}@@@…`.
3. Run `exetests.py` inside each container; outputs are separated by a per-run UUID.
4. Parse outputs into `self._tests[(machine, step)][(command, timeout)]`; repeat until `step > max_step`; call `grade()` a final time to compute grades.

Up to 16 machines tested concurrently (`ThreadPoolExecutor`). Exit codes: `0`–`255` actual, `-1` = timeout.

## Progress reporting

`sre start` emits JSON lines to **stderr** so the GUI can render progress:

```json
{"phase": "pull",   "status": "start",    "image": "sre/base:1.10"}
{"phase": "pull",   "status": "progress", "image": "sre/base:1.10", "percent": 42}
{"phase": "pull",   "status": "end",      "image": "sre/base:1.10"}
{"phase": "deploy", "status": "start",    "total": 3}
{"phase": "deploy", "status": "progress", "current": 1, "total": 3}
{"phase": "deploy", "status": "end",      "total": 3}
```

## Security model

| Concern | Mechanism |
|---------|-----------|
| Allowed UIDs | `sre.py` checks `os.geteuid()` against `sre_uid` and 0; exits otherwise |
| Privilege drop | Root calls `_drop_permanently()`, which `sys.exit()`s on failure |
| Lab path whitelist | `utils.py` checks `current_srelab_file` is under `authorized_src_dir` |
| Eval lock | Lock file opened with `O_CREAT \| O_WRONLY \| O_NOFOLLOW`; `flock(LOCK_EX)` prevents concurrent evals and symlink attacks |
| Host commands drop privileges | `preexec_drop_to_sre()` is `preexec_fn` for every host-side `subprocess.run()` (eval, state transitions) |
| Shell injection | `tls.py` quotes with `shlex.quote()`; `state_helpers.py` writes passwords to `/tmp/.sre_chpasswd` (mode `0o600`); usernames passed via env vars |
| `data.json` secrecy | Mode `0o600` in `.private/` (mode `0o700`) |
| Unknown `__type__` deserialization | `Data0.from_dict()` / `unpack()` / `Flavor0` raise `ValueError` |
| Single GUI instance | PID file at `/tmp/sysreseval-{uid}.pid` kills the previous instance |
| Student command restrictions | `user_not_allowed()` / `user_not_allowed_in_exam_mode()` |
| State access control | `@sre_state(user_allowed=False)` blocks students from re-applying protected states |

## Archive format

Every evaluation writes a `zstandard`-compressed `msgpack` file with a `.zst` extension to `params.archive_dirs` (default `['/var/lib/sre/archives']`; labs may extend the list via a module-level `archive_dirs` attribute).

Filename: `{eval_date}_{running_lab_name}.zst` — `eval_date` is `YYYYmmddHHMMSS`, `running_lab_name` is `{timestamp}@@@{lab_name}@@@{username}`. The leading timestamp sorts chronologically with `ls`.

```
archive = {
    "running_lab_name": "{timestamp}@@@{lab_name}@@@{username}",
    "eval_date":        "20260615110042",
    "data_json":        "<JSON string>",        # serialized Data
    "tests": {
        ("router", 1): {("ping -c1 8.8.8.8", 5): ("64 bytes ...\n", 0), ...},
        ...
    },
    "errors":     ["error message", ...],
    "answers": {
        "<question_hash>":     "<student answer>",
        "hostname":            "pc-101",
        "login":               "alice",
        "fullname":            "Alice Martin",      # from GECOS, always present
        "email":               "alice@example.com", # when email_in_gecos_last_field=True
        "language":            "fr",
        "answers_updated_at":  "20260615110000",
        "auto_eval_count":     2,                   # self-evals before this one
        "exam_mode":           true,                # exam-mode only
        "exam_started_at":     "2026-06-15T09:00",  # exam-mode only
        "exam_duration":       120,                 # exam-mode only
        "exam_time_remaining": 3600,                # exam-mode only
    },
    "grade_list": [
        {"title": "Connectivity", "max_grade": 4, "grade": 4,
         "grade_letter": null, "description": ""},
        ...
    ],
    "total_grade":  14.0,
    "total_max":    20.0,
}
```

Archives are written by `sre eval`, `eval-all`, `eval-exam`, `end-exam`, `re-eval`, and consumed by `sre cat`, `sheet`, `outline`, `check-eval`, `watch` — see [CLI Reference](cli.md).
