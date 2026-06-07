# CLI Reference — `sre`

`sre --help` groups subcommands into five buckets: **dual** (admins + GUI via `sre-wrapper`), **admin-only**, **exam management**, **post-exam management**, and **internal** (GUI-only).

## Global options

```
sre [--user] [--debug] <subcommand> ...
```

| Option | Description |
|--------|-------------|
| `--user` | Set by `sre-wrapper`; reads student login from `USER_USERNAME` (else `LOGNAME`). Mutually exclusive with `--debug`. |
| `--debug` | Verbose diagnostics to stderr. |

Access is restricted to `root`, the `sre` user (`params.sre_uid = 1100`), members of `params.admin_uids`, or members of any `params.admin_gids` group. Non-privileged users may only run `cat`, `check-eval`, `re-eval`, `sheet`, and `outline`.

---

## Dual commands

### `sre start [-d data] [-p] [--flavor … | --flavor-json … | --set-flavor-name …] [--xauth-file <file>] <lab> [data_version]`

Starts a new lab instance, named `{timestamp}@@@{lab_name}@@@{username}`. Imports `srelab.py`, runs `Data.generate(flavor)` (or loads `-d data.json`), builds `NetScheme`, pulls images, deploys via Kathara, applies the `initial` state, and writes `info.json` + `scheme.svg`. See [Internals](internals.md) for file-transfer and progress mechanics.

| Argument / Option | Description |
|-------------------|-------------|
| `lab` | Lab name (from `sre list`) or, with `-p`, a filesystem path. |
| `-p` / `--path` | Treat `lab` as a path. |
| `-d` / `--data` | Reuse an existing `data.json` instead of generating one. |
| `data_version` | Optional seed for `Data.generate()` (privileged only; incompatible with `-d`). |
| `--flavor key:val …` | Flavor field values (e.g. `--flavor nb:3 mode:hard`). |
| `--flavor-json <json>` | Flavor as JSON dict (used by the GUI). |
| `--set-flavor-name <name>` | Use a named preset `Flavor` (privileged only). |
| `--xauth-file <file>` | Read `SRE_XAUTH_COOKIE` from an X authority file instead of the env var (privileged only; for `x11_host=True` machines). |

### `sre stop <running_lab>`

Undeploys containers and removes the project directory from `/var/lib/sre/projects/`.

### `sre wipe`

Stops every running Kathara lab and removes everything under `/var/lib/sre/projects/`.

### `sre connect [--shell <shell>] [--exec <argument…>] [--no-records] <running_lab> <device>`

Opens an external terminal connected to a container.

| Option | Description |
|--------|-------------|
| `--shell <shell>` | Override the machine default shell (privileged only). |
| `--exec <argument…>` | Run one command via the shell and return (consumes rest of argv). |
| `--no-records` | Do not record the terminal session (privileged only). |

### `sre eval [-p path] [--auto-eval] <running_lab>`

Evaluates a running lab. The atomic lock file `.private/eval_in_progress` prevents concurrent evals.

`--auto-eval` marks a *user-triggered self-evaluation* (sent by the GUI's *Start evaluation*). With `--user`, it enables the `delay_between_self_grade` cooldown (outside exam mode), appends a line to `.private/auto_eval.log`, and prints the result JSON. Without `--auto-eval`, a `--user` invocation runs silently — no cooldown, no log, no stdout. The `auto_eval_count` (lines in `.private/auto_eval.log` before this run) is assigned to `self.auto_eval_count` and embedded in the archive's `answers`. If the lab sets `no_mark_on_self_grade`, letter grades (OK/MEH/FAIL) replace numeric grades. Results are archived as `.zst` — see [Archive format](internals.md#archive-format).

### `sre state <running_lab> <state_name>`

Applies `NetScheme.<state_name>()` to a running lab. File operations registered via `file()` / `append_to_file()` are injected via in-memory tar archives sent to `container.put_archive("/")`.

---

## Admin-only commands

### `sre exec [--shell <shell>] <running_lab> <device> <command…>`

Runs `shell -c <command>` in a container and forwards stdout/stderr/exit code. Default shell is `params.default_exec_shell`.

### `sre eval-all [--display-grades / --no-display-grades]`

Evaluates every running lab instance concurrently. `--no-display-grades` suppresses the per-lab grade summary.

### `sre check [-p] <lab> [<state>]`

Validates a lab module without deploying: imports it, runs `Data.generate()`, builds `NetScheme`, runs `initial()`, calls `Grade.grade()`. With `state`, also validates that state method.

### `sre watch [--timeout <sec>] [--interval <sec>] <dir…>`

Live terminal dashboard scanning `<dir…>` for `.zst` archives. Default refresh: `params.default_dashboard_refresh_interval_in_watch_command`. `--timeout` is the inactivity-alert threshold (default 90 s).

**Columns** (from each archive):

| Column | Source |
|--------|--------|
| HOSTNAME / LOGIN | `answers["hostname"]` / `answers["login"]` |
| LAB NAME | Middle segment of `running_lab_name` |
| GRADE | `total_grade / total_max` |
| ERR | Length of `errors` |
| LAST EVAL | `eval_date` (`YYYYmmddHHMMSS`) |
| TIME REMAINING | `answers["exam_time_remaining"]` minus elapsed since `answers["answers_updated_at"]` |

**Keys**:

| Key | Context | Action |
|-----|---------|--------|
| `t` | Any | Toggle focus between Projects and Alerts |
| `↑` / `↓` | Projects / Alerts | Move selection |
| `P` | Projects | Dismiss selected project |
| `H` | Projects | Dismiss all projects from the selected hostname |
| `R` | Projects | Set a hostname regexp filter (empty = show all) |
| `U` | Either | Un-dismiss all |
| `d` / `Enter` | Alerts | Dismiss selected alert |
| `q` / `Ctrl-C` | Any | Quit |
| `?` | Any | Toggle help |

Dismissals self-expire: inactivity alerts return on new archives, error alerts return when the count changes.

### `sre preload-images [--random-delay <sec>] <file_or_dir…>`

Scans lab `.py` files for `image=` / `'image':` patterns and `docker pull`s each unique image. `--random-delay <sec>` waits 0–N seconds before pulling (smooths thundering-herd when invoked across many hosts).

### `sre make-titles [-o <file> | -r] <directory>`

Generates `titles.json` sidecars so the GUI shows friendly labels (e.g. `static_routing.py` → "Static routing"). Labs without a `title` attribute are skipped.

| Option | Description |
|--------|-------------|
| `-o, --output-file <file>` | Write all titles to `<file>` (incompatible with `-r`). |
| `-r, --recursive` | One `titles.json` per directory containing labs (incompatible with `-o`). |

Output keys match `sre list`: `"<name>.py"` for file labs, `"<dirname>"` for directory labs. Files are written atomically with sorted keys; stale entries are dropped at read time by `sre list --with-titles`.

```json
{
  "static_routing.py": {"en": "Static routing", "fr": "Routage statique"},
  "tp_ssh":           {"en": "SSH lab",         "fr": "TP SSH"}
}
```

Typical usage: `sudo /opt/sre/sbin/sre make-titles -r /opt/sre/lab`.

---

## Exam management

Exam state lives in `/var/lib/sre/exam.json` — see [Exam Reference](exam-reference.md) for the field schema. All field names are exposed as `params.exam_*` constants.

### `sre set-exam [options]`

Creates or updates `exam.json`. Only provided options are updated; existing fields are preserved.

| Option | Description |
|--------|-------------|
| `--labs <lab[:flavor]…>` | Authorised labs, optionally with a named flavor preset (e.g. `tp1:hard`). Required on first creation. |
| `--start-after <datetime>` | Exam opens after this moment. ISO (`2026-06-01T09:00`) or time-only (`09:00`, today). |
| `--end-before <datetime>` | Exam closes before this moment. |
| `--duration <minutes>` | Max duration; ends at `started_at + duration` or `end_before`, whichever first. Effective only once formally started. |
| `--eval-interval <seconds>` | Period between automatic evals (default 60). |
| `--record-sessions <bool>` | Record terminal sessions (`true`/`false`/`0`/`no`). |

### `sre del-exam`

Removes `exam.json` and wipes all running projects.

### `sre save-records -d <dir> [--only-last-record]`

Archives the `records/` directories of running projects as `.tar.gz` files in `<dir>`. `--only-last-record` deletes prior archives for the same project so only the latest remains.

---

## Post-exam management

Reads and transforms `.zst` evaluation archives — see [Archive format](internals.md#archive-format) for the schema.

### `sre cat [options] <file…>`

Prints archive contents. Without a field option, all fields are shown.

| Option | Shows |
|--------|-------|
| `--data` | `data_json` (serialized `Data`) |
| `--tests` | Raw test results per machine |
| `--errors` | Evaluation errors |
| `--answers` | Student answers |
| `--grades` | Grade list, total grade, total max |
| `--files` | Files saved in the archive |
| `--extract-files` | Extract saved files to the current directory |
| `--json` | Emit a single JSON dict per file on stdout |

### `sre check-eval [-s <srelab>] <file…>`

Diffs stored grades against a re-grade (same logic as `re-eval` but without writing files). Prints per-element changes plus a summary count. `-s` selects an updated `srelab.py` or directory; if omitted, uses each archive's `.private/srelab` symlink.

### `sre re-eval -s <srelab> -p <prefix> [-d <outdir>] [-r] <file_or_dir…>`

Re-grades archives with an updated `srelab.py`. Useful for fixing a grading bug post-exam.

| Option | Description |
|--------|-------------|
| `-s` / `--srelab` | Updated `srelab.py` or directory. |
| `-p` / `--prefix` | Prepended to each output archive filename. |
| `-d` / `--output-dir` | Output directory (default: current). |
| `-r` / `--recursive` | Recurse into subdirectories. |

### `sre sheet -o <output.ods> [-r] <file_or_dir…>`

Exports archives to a LibreOffice ODS spreadsheet. Per distinct lab name, three sheets are produced:

| Sheet | Content |
|-------|---------|
| `{lab_name}` | One row per archive: `login`, `fullname`, `email`, `hostname`, `eval_date`, `errors`, `total_grade`, `total_max`, `mark`, `maximum_mark`, then one column per grade element |
| `Questions {lab_name}` | Per-question: `max_grade`, `maximum grade`, `average`, `number of projects`, `projects grade 0` |
| `Sessions {lab_name}` | Per-student best score: `login`, `hostname`, `max score`, `sum of maxima`, then best score per question |

`fullname` and `email` come from the archive's `answers` (empty if absent).

### `sre outline [-o <summary.ods>] [-d <pdf_dir>] [-r] [--lang <lang>] [--no-timeline] [--remaining-time] [--users-file <file>] <file_or_dir…>`

Generates per-student PDF reports plus a summary ODS — best-graded archive per student. At least one of `-o` / `-d` is required.

| Option | Description |
|--------|-------------|
| `-o` / `--output-file` | Output `.ods` summary (omit to skip). |
| `-d` / `--pdf-directory` | Output dir for PDFs (omit to skip). |
| `-r` / `--recursive` | Recurse into subdirectories. |
| `--lang <lang>` | Force PDF language (e.g. `en`, `fr`). |
| `--no-timeline` | Omit the evaluation-history table. |
| `--remaining-time` | Include the time-remaining column in the history. |
| `--users-file <file>` | User list `LOGIN NAME EMAIL` (whitespace/CSV; `#` comments; <3-field lines skipped). |

Name / email resolution: `--users-file` (if provided) → `fullname` / `email` from archive answers. Columns appear only when at least one student has a non-empty value.

---

## Internal commands (GUI-only)

### `sre list [--with-titles]`

Prints a JSON array of lab names relative to `/opt/sre/lab/` (`s4/tp_ssh`, `s2/lab.py`, …). Labs whose components match `params.exam_only_affix` (`_EXAM_`, `_OLD_`, `_DRAFT_`, `_TESTS_`) are hidden.

With `--with-titles`, output becomes `[{"name": <path>, "title": <dict|null>}, …]` — titles come from per-directory `titles.json` (see `sre make-titles`); stale entries are dropped, and labs missing a title get `"title": null` (GUI then falls back to the filename).

### `sre export <running_lab> [--sep <N>] [--curved] [--shapes] [--reverse] [--random-seed <N>]`

Exports a running project as a Kathara zip archive, base64-encoded on stdout. Flags tune the embedded schema: `--sep` 0–9 (default 3), `--curved` for curved edges, `--shapes` for geometric nodes, `--reverse` to flip insertion order, `--random-seed` for node-order permutation.

### `sre pre-start-exam`

Stops non-exam projects, then starts all exam labs so images are pre-pulled. Called by the GUI ~60 s before `start_after`.

### `sre start-exam`

Stamps `started_at` in `exam.json`. Called by the GUI once `now ≥ start_after`.

### `sre eval-exam`

Evaluates every running exam project concurrently. Called by the GUI on a periodic timer (every `eval_interval`) and once at exam end.

### `sre end-exam`

Stamps `ended_at` and runs a final concurrent eval on every running exam project. Called by the GUI when the exam ends.
