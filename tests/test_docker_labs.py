"""
Docker test of the labs the students open (the lab files directly in `lab/sre/`, never its
sub-directories), with REAL containers: a project nobody touched is worth nothing, and the
reference solution of the lab (its `final` state) gives every point, the bonus ones included.

For each lab file the test drives the CLI as root, like `test_docker_lifecycle.py`:
`sre start sre/<file>` (the catalog name, the default flavor), `sre eval` (every grade element
at 0), `sre state … final`, `sre eval` again (every grade element at its maximum), `sre stop`.

Why per element and not on the mark: `Grade0.compute_total()` leaves the maximum of a bonus
element out of the total and caps the mark, so a mark equal to the maximum mark does not say
that a bonus was earned; and at the start a penalty must not cancel points given for nothing.

The labs are found when the tests are collected: a lab added to the directory is tested, and
no expected total is written here (the maxima are those of the evaluation itself).

Requirements — skipped otherwise: run as root, a reachable Docker daemon (python `docker`
package), the SRE images (a missing one is pulled by `sre start`), no exam configured on the
host.  Excluded from `make tests`; run with `make docker-tests`, or one lab alone with
`pytest tests/test_docker_labs.py -k dhcp`.  About two minutes for the six labs on a 12-core
workstation that has the images.

On a host whose engine is Podman (`make podman-tests`) the same procedure runs on Podman: what
is left of a project is asked of that engine.

Two environment variables, for a campaign over the labs (both engines, the drafts):
- `SRE_TEST_LABS=_DRAFT_misc` runs the lab files of that sub-directory of `lab/sre/` in place of
  the labs the students open;
- `SRE_TEST_LAB_RESULTS=<file>` appends one JSON line per lab to that file: the grade elements
  of both evaluations, the errors the commands logged, the time of each step, and the names a
  measure taken beside the test needs (the hash of the project, when it was at its `final`
  state).  The procedure then goes to its end before the test fails, where it otherwise stops
  at the first thing that is wrong: the verdict is the same, and the line is complete.
"""
import json
import os
import re
import socket
import time
from pathlib import Path

import pytest

from SRE import params

# Skipped as a whole, like test_docker_lifecycle.py (whose import below would skip the module
# too, under its own message): one line of the `-ra` summary of `make docker-tests`.
if os.geteuid() != 0:
    pytest.skip("Docker lab tests must run as root", allow_module_level=True)

from SRE.answers import answers_lock, consume_cheat_file, load_answers, merge_cheat, save_answers  # noqa: E402
from test_docker_lifecycle import PROJECTS, _lab_hash, _project_dirs, _sre, no_exam  # noqa: E402, F401  (no_exam: a fixture)

# The engine of the host, read when the module is collected (the fixture of conftest.py gives
# every test the Kathara one): it says who is asked what a stopped project left.
try:
    PODMAN = params.host_container_engine() == params.container_engine_podman
except ValueError:      # `sre start` will say it
    PODMAN = False
if PODMAN:
    from test_podman_lifecycle import _leftovers, projects  # noqa: E402, F401  (projects: a fixture)
else:
    from test_docker_lifecycle import _containers, _networks, docker_client, projects  # noqa: E402, F401  (fixtures)

# The labs: those the students open, or with SRE_TEST_LABS those of one sub-directory of them.
LABS_SUBDIR = os.environ.get('SRE_TEST_LABS', '').strip('/')
if LABS_SUBDIR and any(part in ('', '.', '..') for part in LABS_SUBDIR.split('/')):
    raise pytest.UsageError(f"SRE_TEST_LABS={LABS_SUBDIR!r}: a sub-directory of the labs is expected")
# the name `sre start` knows the directory by, and the directory itself
CATALOG = '/'.join(part for part in (params.shipped_lab_link_name, LABS_SUBDIR) if part)
LABS_DIR = Path(params.lab_dir) / CATALOG
# the file labs of the directory itself: `glob` does not enter the sub-directories
LABS = sorted(p.name for p in LABS_DIR.glob('*.py') if p.is_file())
# where the measures of each lab are recorded, if anywhere
RESULTS_FILE = os.environ.get('SRE_TEST_LAB_RESULTS')
LOGGED_ERRORS = 20          # lines of a command's stderr kept in a record, each cut at ...
LOGGED_ERROR_LENGTH = 300   # ... this many characters

FINAL_STATE = 'final'
START_TIMEOUT = 1800        # seconds: the first start on a host may pull the images
# The daemons `final` restarts need a moment before they answer as configured (the DHCP failover
# pair about ten seconds, bind9 and unbound a few): the evaluation is repeated until every
# element is at its maximum, at most this long after the state.
SETTLE_TIMEOUT = 120
SETTLE_INTERVAL = 10
STDERR_TAIL = 2000          # characters of a command's stderr quoted in a failure message

# a machine of the lab is privileged (read in the source, as `sre preload-images` reads the images)
PRIVILEGED_MACHINE = re.compile(r'''["']privileged["']\s*:\s*True\b''')


def _created_project(stderr):
    """The running lab name of the project `sre start` created, from its last progress event
    (`progress.emit_project_created`), or None."""
    for line in reversed(stderr.splitlines()):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get('phase') == 'project' and event.get('status') == 'created':
            return event.get('running_lab_name')
    return None


def _start(projects, lab):
    """`sre start sre/<lab>`, the project registered for the cleanup of the `projects` fixture:
    its name, its hash, and the stderr of the command.  The name comes from the progress event
    rather than from the projects directory alone: on a shared host somebody else may start a
    project meanwhile."""
    before = _project_dirs()
    r = _sre('start', f'{CATALOG}/{lab}', timeout=START_TIMEOUT)
    assert r.returncode == 0, f"sre start failed:\n{r.stderr[-3000:]}"
    running_lab_name = _created_project(r.stderr)
    if running_lab_name is None:
        new = _project_dirs() - before
        assert len(new) == 1, f"expected exactly one new project, got {new}:\n{r.stderr[-3000:]}"
        running_lab_name = new.pop()
    lab_hash = _lab_hash(running_lab_name)
    projects.append((running_lab_name, lab_hash))
    return running_lab_name, lab_hash, r.stderr


def _evaluate(running_lab_name):
    """One privileged `sre eval`: the grade elements of the evaluation that counts, with numbers
    (a self-evaluation of these labs gives letters and has a cooldown), and the stderr of the
    command (the test and state errors are logged there)."""
    r = _sre('eval', running_lab_name)
    assert r.returncode == 0, f"sre eval failed:\n{r.stderr[-3000:]}"
    elements = json.loads(r.stdout)['grades']
    assert elements, "the evaluation lists no grade element"
    return elements, r.stderr


def _take_cheat_answers(running_lab_name):
    """What the GUI and the web agent do after a state, and nothing does in a CLI-only run:
    the answers the state gives (`answers/cheat.json`, written by `sre state`) go into
    `answers/answers.json`, which `sre eval` reads.  No file: the lab has no question, or the
    web agent of a pool host took it first (it then writes the answers itself)."""
    try:
        cheat = consume_cheat_file(params.cheat_filename(running_lab_name))
    except FileNotFoundError:   # removed by the agent between our read and our unlink
        cheat = None
    if not cheat:
        return
    path = params.answers_filename(running_lab_name)
    with answers_lock(path):
        save_answers(path, merge_cheat(load_answers(path), cheat), atomic=True, mode=0o644,
                     owner=(params.sre_uid, params.docker_gid))


def _title(element):
    title = element['title']
    if isinstance(title, dict):     # a translated title
        return title.get('en') or next(iter(title.values()), '')
    return title


def _describe(elements):
    return '\n'.join(f"  {_title(e)}: {e['grade']} / {e['max_grade']}" + (" (bonus)" if e.get('bonus') else "")
                     for e in elements)


def _short_of_maximum(elements):
    """The elements that did not get their maximum; a bonus element is one of them like any other."""
    return [e for e in elements if e['grade'] != pytest.approx(e['max_grade'])]


def _logged_errors(stderr):
    """The lines of a command's stderr that tell of an error (a command of a state that failed, a
    test that could not run): the progress events of `sre start` are not among them."""
    lines = []
    for line in stderr.splitlines():
        if 'error' not in line.lower() or line.lstrip().startswith('{"phase"'):
            continue
        lines.append(line[:LOGGED_ERROR_LENGTH])
    return lines[:LOGGED_ERRORS]


def _recorded(elements):
    """The grade elements of an evaluation as a record keeps them."""
    return [{'title': _title(e), 'grade': e['grade'], 'max_grade': e['max_grade'], 'bonus': bool(e.get('bonus'))}
            for e in elements]


def _write_record(record):
    if RESULTS_FILE:
        with open(RESULTS_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')


@pytest.fixture
def leftovers(request):
    """``leftovers(lab_hash)``: what still carries the hash of a project, asked of the engine of
    the host (skipped without a reachable Docker daemon when the engine is Kathara)."""
    if PODMAN:
        return _leftovers
    client = request.getfixturevalue('docker_client')
    return lambda lab_hash: _containers(client, lab_hash) + _networks(client, lab_hash)


def test_the_labs_are_found():
    assert LABS, f"no lab file in {LABS_DIR}"


@pytest.mark.parametrize('lab', LABS)
def test_final_state_gives_every_point(leftovers, projects, no_exam, lab):
    if not params.allow_privileged_machines and PRIVILEGED_MACHINE.search((LABS_DIR / lab).read_text()):
        pytest.skip("params.allow_privileged_machines is False")
    record = {'lab': f'{CATALOG}/{lab}', 'host': socket.gethostname(), 'seconds': {}, 'errors': {},
              'engine': params.container_engine_podman if PODMAN else params.container_engine_kathara}
    try:
        _from_nothing_to_every_point(leftovers, projects, lab, record)
        record['outcome'] = 'passed'
    except BaseException as e:      # the test failed, or was interrupted: its record says where it was
        record['outcome'] = f"{type(e).__name__}: {str(e).strip().splitlines()[0] if str(e).strip() else ''}"[:LOGGED_ERROR_LENGTH]
        raise
    finally:
        _write_record(record)


def _from_nothing_to_every_point(leftovers, projects, lab, record):
    """The procedure of one lab.  *record* receives what it measures on the way.  With a results
    file it goes to its end whatever the evaluations give, and fails then."""
    def timed(step, since):
        record['seconds'][step] = round(time.monotonic() - since, 1)

    since = time.monotonic()
    running_lab_name, lab_hash, stderr = _start(projects, lab)
    timed('start', since)
    record.update(running_lab_name=running_lab_name, lab_hash=lab_hash)
    record['errors']['start'] = _logged_errors(stderr)

    # nothing done: nothing earned, element by element (a penalty must not hide points given for nothing)
    since = time.monotonic()
    elements, stderr = _evaluate(running_lab_name)
    timed('untouched', since)
    record['untouched'] = _recorded(elements)
    record['errors']['untouched'] = _logged_errors(stderr)
    assert sum(e['max_grade'] for e in elements) > 0, f"nothing to earn:\n{_describe(elements)}"
    earned = [e for e in elements if e['grade'] != 0]
    untouched = (f"points in a project nobody touched:\n{_describe(earned)}\n"
                 f"--- sre eval\n{stderr[-STDERR_TAIL:]}") if earned else None
    assert RESULTS_FILE or not earned, untouched

    # the reference solution and the answers it gives
    since = time.monotonic()
    r = _sre('state', running_lab_name, FINAL_STATE)
    timed('state', since)
    assert r.returncode == 0, r.stderr
    state_stderr = r.stderr
    record['errors']['state'] = _logged_errors(state_stderr)
    applied = time.monotonic()
    deadline = applied + SETTLE_TIMEOUT
    evaluations = 0
    while True:
        _take_cheat_answers(running_lab_name)
        since = time.monotonic()
        elements, stderr = _evaluate(running_lab_name)
        evaluations += 1
        short = _short_of_maximum(elements)
        if not short or time.monotonic() >= deadline:
            break
        time.sleep(SETTLE_INTERVAL)
    timed('final', since)                                   # the last evaluation ...
    record['seconds']['settled'] = round(since - applied, 1)    # ... which began this long after the state
    record.update(final=_recorded(elements), evaluations=evaluations, final_at=round(time.time(), 1))
    record['errors']['final'] = _logged_errors(stderr)
    total, maximum = sum(e['grade'] for e in elements), sum(e['max_grade'] for e in elements)
    after_final = (f"{total} / {maximum} after the state '{FINAL_STATE}', short of their maximum:\n"
                   f"{_describe(short)}\n"
                   f"--- sre state {FINAL_STATE}\n{state_stderr[-STDERR_TAIL:]}\n"
                   f"--- sre eval\n{stderr[-STDERR_TAIL:]}") if short else None
    assert RESULTS_FILE or not short, after_final

    record['stopping_at'] = round(time.time(), 1)
    since = time.monotonic()
    r = _sre('stop', running_lab_name)
    timed('stop', since)
    assert r.returncode == 0, r.stderr
    assert leftovers(lab_hash) == []
    assert not (PROJECTS / running_lab_name).exists()
    # with a results file the procedure went to its end: the verdict is the one it would have had
    problems = [problem for problem in (untouched, after_final) if problem]
    assert not problems, '\n'.join(problems)
