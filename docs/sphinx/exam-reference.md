# Exam Reference

## `exam.json` — single source of truth

Lives at `/var/lib/sre/exam.json` (`params.sre_pub_dir + "/" + params.exam_json_name`). The same file must exist on every student PC — distribute via NFS, rsync, or any deployment mechanism. All field names are exposed as `params.exam_*` constants; never hard-code them.

| Field | Constant | Type | Meaning |
|-------|----------|------|---------|
| `labs` | `params.exam_labs` | `[[lab, flavor\|null], ...]` | Authorised labs + optional flavor preset (required) |
| `start_after` | `params.exam_start_after` | ISO datetime | Exam opens after this moment |
| `end_before` | `params.exam_end_before` | ISO datetime | Exam closes before this moment |
| `duration` | `params.exam_duration` | int (min) | Max duration; default `params.default_exam_duration = 90` |
| `eval_interval` | `params.exam_eval_interval` | int (s) | Auto-eval period; default `params.default_eval_interval_during_exams = 60` |
| `record_sessions` | `params.exam_record_sessions` | bool | Record terminal sessions; default `true` |
| `pre_start_date` | `params.exam_pre_start_date` | list[ISO] | Written by `pre-start-exam`; one entry per call |
| `started_at` | `params.exam_started_at` | ISO datetime | Written by `start-exam` |
| `ended_at` | `params.exam_ended_at` | ISO datetime | Written by `end-exam` |

The first six are set by the instructor (via `sre set-exam`); the last three are runtime state markers.

`labs` format: each entry is a two-element list `[lab_cli_arg, flavor_or_null]`, where `lab_cli_arg` is what `sre start` would receive (e.g. `s4/tp_ssh`) and the second element is the name of a `Flavor` preset or `null`:

```json
"labs": [["s4/tp_ssh", null], ["s4/tp_dhcp", "hard"]]
```

Legacy plain-string entries are still accepted on read; always unpack via `params.parse_lab_entry(entry)`.

## GUI exam logic

Each student GUI reads `exam.json` every second (`_update_exam_state`) and runs the same logic — there is no coordinator. The phase is computed from `exam.json` content alone (`_compute_exam_phase`):

- **Waiting** — `start_after` set, `now < start_after`, `started_at` not set.
- **Ended** — `end_before` set and `now ≥ end_before`, **or** `started_at` set and `now ≥ started_at + duration` (duration defaults to `params.default_exam_duration = 90`). The duration check fires only when `started_at` is set — without it, the exam was never formally started.
- Otherwise: **Active**.

`real_starting_time` (drives the countdown) = `started_at` if set, else `start_after` if set, else GUI process start time.

| Phase | Preconditions | Actions |
|-------|--------------|---------|
| Waiting | — | Show SRE logo + countdown to `start_after`. Once `now ≥ start_after − params.max_duration_between_exam_pre_start_and_start` (60 s) **and** `pre_start_date` is absent, fire `sre pre-start-exam` once (stops non-exam projects, starts exam labs, appends to `pre_start_date`). |
| Active | Exam containers up — one running project per lab in `labs`, no others (`_projects_ready`) | Fire `sre start-exam` once (stamps `started_at`; calls `pre-start-exam` internally if `pre_start_date` is missing). Show tabs + countdown. Every `eval_interval` s, fire `sre eval-exam` (skipped if previous still running). If `labs` changes, re-fire `sre pre-start-exam`. |
| Ended | — | Fire `sre end-exam` once (stamps `ended_at`, runs a final concurrent eval with `save-records --force`). Show "That's All Folks" until the instructor runs `sre del-exam`. |

## Commands

See [CLI Reference](cli.md) for `set-exam`, `del-exam`, `pre-start-exam`, `start-exam`, `eval-exam`, `end-exam`, `save-records`, `watch`, `cat`, `check-eval`, `re-eval`, `sheet`, `outline`.
