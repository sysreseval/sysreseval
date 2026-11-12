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
`pytest tests/test_docker_labs.py -k dhcp`.  A few minutes per lab.
"""
import json
import os
import re
import time
from pathlib import Path

import pytest

from SRE import params

# Skipped as a whole, like test_docker_lifecycle.py (whose import below would skip the module
# too, under its own message): one line of the `-ra` summary of `make docker-tests`.
if os.geteuid() != 0:
    pytest.skip("Docker lab tests must run as root", allow_module_level=True)

from SRE.answers import answers_lock, consume_cheat_file, load_answers, merge_cheat, save_answers  # noqa: E402
from test_docker_lifecycle import (  # noqa: E402, F401  (docker_client, projects, no_exam: fixtures)
    PROJECTS, _containers, _lab_hash, _networks, _project_dirs, _sre, docker_client, no_exam, projects)

LABS_DIR = Path(params.lab_dir) / params.shipped_lab_link_name
# the file labs of the directory itself: `glob` does not enter the sub-directories
LABS = sorted(p.name for p in LABS_DIR.glob('*.py') if p.is_file())

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
    """`sre start sre/<lab>`, the project registered for the cleanup of the `projects` fixture.
    The name comes from the progress event rather than from the projects directory alone: on a
    shared host somebody else may start a project meanwhile."""
    before = _project_dirs()
    r = _sre('start', f'{params.shipped_lab_link_name}/{lab}', timeout=START_TIMEOUT)
    assert r.returncode == 0, f"sre start failed:\n{r.stderr[-3000:]}"
    running_lab_name = _created_project(r.stderr)
    if running_lab_name is None:
        new = _project_dirs() - before
        assert len(new) == 1, f"expected exactly one new project, got {new}:\n{r.stderr[-3000:]}"
        running_lab_name = new.pop()
    lab_hash = _lab_hash(running_lab_name)
    projects.append((running_lab_name, lab_hash))
    return running_lab_name, lab_hash


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


def test_the_labs_are_found():
    assert LABS, f"no lab file in {LABS_DIR}"


@pytest.mark.parametrize('lab', LABS)
def test_final_state_gives_every_point(docker_client, projects, no_exam, lab):
    if not params.allow_privileged_machines and PRIVILEGED_MACHINE.search((LABS_DIR / lab).read_text()):
        pytest.skip("params.allow_privileged_machines is False")
    running_lab_name, lab_hash = _start(projects, lab)

    # nothing done: nothing earned, element by element (a penalty must not hide points given for nothing)
    elements, stderr = _evaluate(running_lab_name)
    assert sum(e['max_grade'] for e in elements) > 0, f"nothing to earn:\n{_describe(elements)}"
    earned = [e for e in elements if e['grade'] != 0]
    assert not earned, (f"points in a project nobody touched:\n{_describe(earned)}\n"
                        f"--- sre eval\n{stderr[-STDERR_TAIL:]}")

    # the reference solution and the answers it gives
    r = _sre('state', running_lab_name, FINAL_STATE)
    assert r.returncode == 0, r.stderr
    state_stderr = r.stderr
    deadline = time.monotonic() + SETTLE_TIMEOUT
    while True:
        _take_cheat_answers(running_lab_name)
        elements, stderr = _evaluate(running_lab_name)
        short = _short_of_maximum(elements)
        if not short or time.monotonic() >= deadline:
            break
        time.sleep(SETTLE_INTERVAL)
    total, maximum = sum(e['grade'] for e in elements), sum(e['max_grade'] for e in elements)
    assert not short, (f"{total} / {maximum} after the state '{FINAL_STATE}', short of their maximum:\n"
                       f"{_describe(short)}\n"
                       f"--- sre state {FINAL_STATE}\n{state_stderr[-STDERR_TAIL:]}\n"
                       f"--- sre eval\n{stderr[-STDERR_TAIL:]}")

    r = _sre('stop', running_lab_name)
    assert r.returncode == 0, r.stderr
    assert _containers(docker_client, lab_hash) == [] and _networks(docker_client, lab_hash) == []
    assert not (PROJECTS / running_lab_name).exists()
