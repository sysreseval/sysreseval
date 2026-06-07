# Exam Administration

---

## Lifecycle at a glance

The model is **declarative**: the instructor writes a single file, `/var/lib/sre/exam.json`, and the GUI on each student PC does the rest. Two invariants make this work:

- **`exam.json` is the trigger.** Its presence puts the GUI in exam mode; its contents determine the current phase, the countdowns, and what to fire next. The instructor's only job is to create, edit, or delete this file — via `sre set-exam` and `sre del-exam`. The GUI polls it once per second and fires `pre-start-exam`, `start-exam`, `eval-exam`, and `end-exam` at the appropriate moments.
- **Every exam command is idempotent.** Each one can be re-run safely, which is what lets the GUI recover from transient failures and react to mid-exam edits. The instructor can extend the duration, add or remove a lab, or push back the end time at any point by editing `exam.json` (via `sre set-exam`); the change propagates within one second.




```
[Instructor]                          [GUI on each student PC, polling exam.json @ 1 Hz]
     │                                        │
     │  sre set-exam --labs tp1 \             │
     │    --start-after 09:00 \               │  ← exam.json appears
     │    --end-before  11:00 \               │
     │    --duration    120                   │
     │    --eval-interval 60                  │
     │                                        │
     │                            Phase: WAITING
     │                            • shows logo + countdown to 09:00
     │                            • ~60 s before start_after, sysreseval GUI fires
     │                              sre pre-start-exam (pulls images,
     │                              starts containers, writes pre_start_date)
     │                                        │
     ├── 09:00 ──────────────────────────────►│
     │                            Phase: ACTIVE
     │                            • once projects are up, sysreseval GUI fires
     │                              sre start-exam (stamps started_at)
     │                            • shows remaining-time countdown
     │                            • fires sre eval-exam every 60 s
     │                            • student works, may self-grade
     │                                        │
     ├── 11:00 (or started_at + 120 min) ────►│
     │                            Phase: ENDED
     │                            • sysreseval GUI fires sre end-exam once
     │                              (final concurrent eval + stamps ended_at)
     │                            • shows "That's All Folks"
     │                                        │
     │  sre del-exam                          │
     │  (removes exam.json, wipes projects)   │
     |  sre sheet / outline / re-eval         │  ← post-exam grading
```


---

## Setting up an exam — `sre set-exam`

```bash
# Minimal — one lab, hard end time. No start time means "open immediately".
sre set-exam --labs s4/tp_ssh --end-before 11:00

# With some more options example
sre set-exam \
  --labs s4/tp_ssh s4/tp_dhcp:hard \
  --start-after  2026-06-15T09:00 \
  --end-before   2026-06-15T11:00 \
  --duration     90 \
  --eval-interval 30
```

In this case, each student gets 90 minutes, but every exam ends at 11:00 — even for students who start after 9:30.

Behaviour:

- **Incremental updates.** Only the options provided on the command line are written; everything else is preserved. `sre set-exam --duration 150` extends an in-progress exam without touching `labs` or `start_after`.
- **First-time requirements.** If `exam.json` does not yet exist, `--labs` is required, and so is at least one of `--end-before` / `--duration` (otherwise the exam would never end).
- **Date formats.** Both `--start-after` and `--end-before` accept full datetimes (`2026-06-01T09:00`, `2026-06-01 09:00`, `2026-06-01T09:00:00`) and time-only (`09:00`, `09:00:00`) — time-only is combined with today's date.
- **Lab validation.** Each lab name is checked against `sre list` (`get_lab_list(include_exam_only_labs=True)`); absolute paths must lie under `params.authorized_src_dir` (`/opt/sre/lab/` or `/home/admin1/`, etc..).
- **Resetting `start_after` resets state.** Changing `--start-after` clears `pre_start_date` and `started_at` so the GUI re-triggers `pre-start-exam` and `start-exam` for the new run.
- **Mis-exam edits.** Anything in `exam.json` may be changed while the exam is running; the GUI picks up changes within 1 s.
- **relative duration change**. During an exam, `--duration +X` or `--duration -X` add or substract X minutes.
- 
| Option | Effect |
|--------|--------|
| `--labs <lab[:flavor] ...>` | Authorised labs; `:flavor` selects a named `Flavor` preset (e.g. `tp1:hard`). Required when creating. |
| `--start-after <dt>` | Exam opens after this moment. If omitted, the exam is considered open immediately. |
| `--end-before <dt>` | Exam closes after this moment, regardless of `started_at`. |
| `--duration <min>` | Hard cap on duration; the exam ends at `started_at + duration` *or* `end_before`, whichever fires first. Only effective once `started_at` is set. When updating an existing `exam.json` that already has a `duration` field, prefix the value with `+` or `-` to adjust the current duration (e.g. `--duration +30` adds 30 min, `--duration -15` subtracts 15 min). |
| `--eval-interval <sec>` | Automatic-eval period (default 60). |
| `--record-sessions <bool>` | Record terminal sessions (`true`/`false`/`0`/`no`). Default `true`. |

See [Exam Reference](exam-reference.md) for how the GUI drives the exam (phase computation and per-phase actions).

## Monitoring an exam

Once each student machine mirrors its archives into a shared directory subtree on the instructor's machine
(see the Installation chapter), `sre watch <directory>` provides a live dashboard of the exam:

- **Remaining time and latest grade** per student.
- **Inactivity alerts** when no new archive has appeared for a student in the last X seconds — usually a sign
  that `sysreseval` crashed or the machine was shut down.
- **Evaluation-error alerts** flagging any error raised by the last eval. A well-written lab should never
  produce errors; if a command is legitimately allowed to fail, pass `allow_error=True` to `Grade.cmd()`
  so the failure is not reported.

---

### Clean up after an exam

```bash
sre del-exam
```

Removes `exam.json` and wipes every running project. Archive directories are preserved.

Note: in exam mode, quitting the GUI does not stop the Docker containers (unlike normal mode), so the instructor
can keep them running afterwards — for instance to re-run a corrected version of the project if a bug surfaces during the exam.

---

## Exam-only labs

Lab names containing any substring from `params.exam_only_affix = ["_EXAM_", "_OLD_", "_DRAFT_", "_TESTS_"]` are hidden from `sysreseval`'s lab picker. 
This is how you keep an exam lab invisible until it appears in `exam.json`:

- `/opt/sre/lab/s4/ssh_EXAM_final.py` — hidden from listings, but allowed in `--labs`.
- `/opt/sre/lab/_DRAFT_/work_in_progress.py` — hidden in any subdirectory whose name contains a flagged affix.

`sre set-exam --labs ...` and all the commands from privileged users (`sre start...`) accept hidden labs of course.

---

## Post-exam workflow

### Inspect a single archive

```bash
sre cat --grades --answers /var/lib/sre/archives/20260615110000_*.zst
```

| Field option | Shows |
|--------------|-------|
| `--grades` | Per-element grades, total grade, max |
| `--answers` | Student answers (incl. login, hostname, fullname, email, exam timing) |
| `--errors` | Errors raised during grading |
| `--tests` | Raw test results per machine (large) |
| `--data` | Serialized `Data` instance for the lab |
| `--files` / `--extract-files` | List or extract files saved into the archive |
| `--json` | One JSON dict per file on stdout (script-friendly) |

### Re-grade with a corrected project file

If a grading bug surfaces during the exam, fix-it and re-grade every archive:

```bash
sre re-eval -s /opt/sre/lab/_EXAM_/ssh_corrected.py \
            -p corrected \
            -d /tmp/regraded \
            -r /home/a/results/
```

Output archives appear in `/tmp/regraded/` with the `corrected` prefix. Use `sre check-eval -s ...` first to preview the diff without writing any file.

This only works if the corrected project file does not require any **new** command to be run on the virtual machines:
re-evaluation replays the grading logic against the test output already stored in the archive, so a command that was never
executed during the exam (say, `ip route` on `m1`) cannot be recovered after the fact. Within that limit, fixing a grading
bug post-exam is straightforward.

To preview the impact of the correction on a single archive without writing anything, use:

```bash
sre check-eval --srelab corrected_project.py archive_file
```

which prints the diff between the stored grades and the re-graded ones.

The overall grade is computed by the `Grade0.mark_exo_eval()` method, which can be overridden to rescale or cap the final mark.
For example, to multiply every mark by 1.1 and round up to the next 0.1, override `mark_exo_eval()` in the lab's `Grade` class:

```python
def mark_exo_eval(self):
    if not self._grade_list or self._total_max == 0:
        return None
    import math
    return min(
        self._maximum_mark,
        math.ceil(10 * 1.1 * self._maximum_mark * self._total_grade / self._total_max) / 10,
    )
```




### Per-student PDF reports + summary spreadsheet

To create per-student PDF reports and a grade spreadsheet:

```bash
sre outline \
  -o /tmp/summary.ods \
  -d /tmp/reports \
  -r /var/lib/sre/archives/
```

Useful options:

- `--users-file <file>` — auxiliary `LOGIN NAME EMAIL` file (whitespace- or CSV-separated, `#` for comments) that supersedes the names and emails embedded in the archives. Handy when student logins are pseudonyms.
- `--remaining-time` — include each student's remaining exam time (from `exam_time_remaining` in the archive) in the summary.
- `--no-timeline` - omit the evaluation history table from PDF reports
- `--no-parts` - do not group PDF grade rows by GradePart (flat list, no subtotals)

### Export to a spreadsheet

To get a full sheet of all grades elements of all evaluations with per-question summary:

```bash
sre sheet -o /tmp/exam-results.ods -r /var/lib/sre/archives/
```




