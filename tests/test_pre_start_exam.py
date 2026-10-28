"""
`sre pre-start-exam` and the ownership check: in user mode with `params.check_project_owner` on,
the projects of other users are stopped too (the GUI only counts the caller's own tabs) and an
exam lab is started unless the caller, or root, already runs one; a privileged caller and the
check off keep the host-wide behaviour (every non-exam project stopped, an exam lab started only
when nobody runs it).  Nothing is deployed: the stop and the start are recorded.
"""
import json
from pathlib import Path

import pytest

from SRE import params
from SRE.command import pre_start_exam

EXAM_LAB = 'sre/dhcp.py'
OTHER_LAB_NAME = 'sre@other.py'


@pytest.fixture
def exam(tmp_pub_dir, monkeypatch):
    pub = Path(params.sre_pub_dir)
    pub.mkdir(parents=True, exist_ok=True)
    (pub / params.exam_json_name).write_text(json.dumps({params.exam_labs: [[EXAM_LAB, None]]}))
    Path(params.sre_projects_dir).mkdir()
    calls = {'stopped': [], 'started': []}

    def fake_stop(running_lab_name, lab_hash=None, multi_project=False):
        calls['stopped'].append(running_lab_name)
        return []

    monkeypatch.setattr(pre_start_exam, 'stop_running_lab', fake_stop)
    monkeypatch.setattr(pre_start_exam, 'do_action_start',
                        lambda lab_cli_arg, **kwargs: calls['started'].append(lab_cli_arg))
    return calls


def _project(owner, lab_name=None, ts='20260101000000'):
    if lab_name is None:
        lab_name = params.get_lab_name_from_cli_arg(EXAM_LAB, is_path=False)
    name = f'{ts}@@@{lab_name}@@@{owner}'
    d = Path(params.sre_projects_dir) / name
    d.mkdir()
    (d / params.info_json_name).write_text(json.dumps({'lab_name': lab_name, 'lab_hash': 'h-' + owner}))
    return name


def _pre_start_dates():
    return json.loads((Path(params.sre_pub_dir) / params.exam_json_name).read_text())[params.exam_pre_start_date]


class TestPreStartExam:
    def test_privileged_caller_keeps_any_exam_project(self, exam, mock_sre_args):
        _project('alice')
        _project('bob', ts='20260101000001')
        extra = _project('carol', OTHER_LAB_NAME, ts='20260101000002')
        pre_start_exam.action_pre_start_exam()
        assert exam['stopped'] == [extra] and exam['started'] == []
        assert len(_pre_start_dates()) == 1

    def test_user_mode_stops_other_users_projects_and_starts_the_lab(self, exam, mock_sre_args, monkeypatch):
        mock_sre_args.user = True
        monkeypatch.setattr(params.SRE, 'username', 'alice')
        other = _project('bob')
        extra = _project('carol', OTHER_LAB_NAME, ts='20260101000001')
        pre_start_exam.action_pre_start_exam()
        assert sorted(exam['stopped']) == sorted([other, extra]) and exam['started'] == [EXAM_LAB]

    @pytest.mark.parametrize('owner', ['alice', 'root'])
    def test_user_mode_keeps_an_own_or_root_owned_exam_project(self, exam, mock_sre_args, monkeypatch, owner):
        mock_sre_args.user = True
        monkeypatch.setattr(params.SRE, 'username', 'alice')
        _project(owner)
        pre_start_exam.action_pre_start_exam()
        assert exam['stopped'] == [] and exam['started'] == []

    def test_check_off_keeps_the_host_wide_behaviour(self, exam, mock_sre_args, monkeypatch):
        mock_sre_args.user = True
        monkeypatch.setattr(params.SRE, 'username', 'alice')
        monkeypatch.setattr(params, 'check_project_owner', False)
        _project('bob')
        pre_start_exam.action_pre_start_exam()
        assert exam['stopped'] == [] and exam['started'] == []

    def test_stop_errors_are_reported_at_the_end(self, exam, mock_sre_args, monkeypatch, capsys):
        monkeypatch.setattr(pre_start_exam, 'stop_running_lab',
                            lambda running_lab_name, lab_hash=None, multi_project=False: [f'{running_lab_name}: busy'])
        extra = _project('carol', OTHER_LAB_NAME)
        with pytest.raises(SystemExit) as e:
            pre_start_exam.action_pre_start_exam()
        assert e.value.code == 1 and f'{extra}: busy' in capsys.readouterr().err
        assert exam['started'] == [EXAM_LAB] and len(_pre_start_dates()) == 1
