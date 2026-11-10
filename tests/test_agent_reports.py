"""Tests of the reports of the Archives page on the agent side: the pure helpers of
``sreweb.agent.reports``, ``POST /v1/reports/{kind}`` on the fake sre (whose ``report`` answers a
zip of what it received), the mock's ``report`` itself, the runner's report limit and the
``[timeouts] report`` key."""
import asyncio
import io
import json
import re
import zipfile
from datetime import datetime

import pytest

from sreweb.agent import reports as R
from sreweb.agent.runner import SreRunner, REPORT_LIKE
from sreweb.config import agent_config_from_dict, DEFAULT_TIMEOUTS
from sreweb.identity import Identity
from test_agent_api import Harness, headers, ALICE, PROF, run
from test_mock_sre import run_mock

RLN = '20261025100000@@@sre@dhcp.py@@@alice'
RLN_BOB = '20261025110000@@@sre@dhcp.py@@@bob'
RLN_SSH = '20261025120000@@@s4@tp_ssh@@@bob'
PROF_FR = Identity(login='prof', role='instructor', language='fr')
NOW = datetime(2026, 10, 25, 10, 5)


def record(**over) -> dict:
    base = {'archive': f'20261025100500_{RLN}.zst', 'running_lab_name': RLN, 'lab': 'sre/dhcp.py',
            'eval_date': '2026-10-25T10:05:00+01:00', 'login': 'alice', 'fullname': 'Alice A', 'group': 'INFO1',
            'email': '', 'hostname': 'pool1', 'language': 'fr', 'exam': False, 'grade': 4.5, 'max_grade': 5.0,
            'mark': 18.0, 'maximum_mark': 20.0, 'error_count': 0, 'warning_count': 0, 'elements': [], 'parts': []}
    base.update(over)
    return base


def members(data: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


class TestHelpers:
    def test_parse_request(self):
        records, options = R.parse_report_request({'records': [record()], 'options': {'no_parts': True}})
        assert records == [record()] and options == {'no_parts': True}
        assert R.parse_report_request({'records': [record()]})[1] == {}
        assert R.parse_report_request({'records': [record()], 'options': None})[1] == {}
        for body in ([], {}, {'records': []}, {'records': 'x'}, {'records': [1]}, {'records': [record()], 'options': []},
                     {'records': [record()], 'options': {'bogus': True}}, {'records': [record()], 'options': {'no_parts': 1}}):
            with pytest.raises(ValueError):
                R.parse_report_request(body)

    def test_flags(self):
        every = {key: True for key in R.OPTION_FLAGS}
        assert R.report_flags('outline', every) == ['--separate-instances', '--bonus-in-prefix', '--no-timeline',
                                                    '--remaining-time', '--no-parts']
        assert R.report_flags('sheet', every) == ['--separate-instances', '--bonus-in-prefix']
        assert R.report_flags('summary', every) == ['--separate-instances', '--bonus-in-prefix']
        assert R.report_flags('outline', {'no_timeline': False, 'remaining_time': True}) == ['--remaining-time']
        assert R.report_flags('sheet', {}) == [] and R.report_flags('summary', {'no_parts': True}) == []

    def test_filename(self):
        assert R.report_filename('sheet', [record(), record(running_lab_name=RLN_BOB)], NOW) == 'evaluations_dhcp_20261025-1005.ods'
        assert R.report_filename('outline', [record()], NOW) == 'reports_dhcp_20261025-1005.zip'
        assert R.report_filename('summary', [record()], NOW) == 'summary_dhcp_20261025-1005.ods'
        # two labs: no lab part; a record without lab key falls back on the running lab name
        assert R.report_filename('sheet', [record(), record(running_lab_name=RLN_SSH, lab='')], NOW) == 'evaluations_20261025-1005.ods'
        assert R.report_filename('outline', [{'running_lab_name': RLN_SSH}], NOW) == 'reports_tp_ssh_20261025-1005.zip'
        # an odd lab name is made safe, cut to the limit
        odd = R.report_filename('sheet', [{'lab': 'x/é té "quoted"/' + 'a' * 80 + '.py'}], NOW)
        assert odd.startswith('evaluations_' + 'a' * 60 + '_2026') and '"' not in odd and ' ' not in odd
        assert R.report_filename('sheet', [{'lab': 'é té'}], NOW) == 'evaluations_t_20261025-1005.ods'


class TestMock:
    """The `report` of tests/mock_sre.py: what the agent tests rely on."""

    def test_sheet(self, tmp_path):
        body = json.dumps({'records': [record(), record(running_lab_name=RLN_BOB, login='bob')]}).encode()
        completed = run_mock(tmp_path, 'report', 'sheet', '--separate-instances', '--lang', 'fr', user=False, input=body)
        assert completed.returncode == 0, completed.stderr.decode()
        got = members(completed.stdout)
        assert got['mimetype'] == b'application/vnd.oasis.opendocument.spreadsheet'
        assert [r['login'] for r in json.loads(got['records.json'])] == ['alice', 'bob']
        assert got['flags.txt'].decode().splitlines() == ['--separate-instances', '--lang fr']
        assert not any(name.endswith('.pdf') for name in got)

    def test_outline_to_a_file(self, tmp_path):
        body = json.dumps({'records': [record(), record(running_lab_name=RLN_BOB, login='bob', hostname='pool2')]}).encode()
        target = tmp_path / 'out.zip'
        completed = run_mock(tmp_path, 'report', 'outline', '--no-parts', '-o', str(target), user=False, input=body)
        assert completed.returncode == 0 and completed.stdout == b''
        got = members(target.read_bytes())
        assert sorted(n for n in got if n.endswith('.pdf')) == ['alice__dhcp.pdf', 'bob__dhcp.pdf']
        assert got['outline.ods'] == b'ods' and got['flags.txt'] == b'--no-parts'

    def test_summary(self, tmp_path):
        body = json.dumps({'records': [record(), record(running_lab_name=RLN_BOB, login='bob')]}).encode()
        completed = run_mock(tmp_path, 'report', 'summary', '--separate-instances', user=False, input=body)
        assert completed.returncode == 0, completed.stderr.decode()
        got = members(completed.stdout)
        assert got['mimetype'] == b'application/vnd.oasis.opendocument.spreadsheet'
        assert got['flags.txt'] == b'--separate-instances'
        assert not any(name.endswith('.pdf') for name in got) and 'outline.ods' not in got

    def test_refusals(self, tmp_path):
        body = json.dumps({'records': [record()]}).encode()
        refused = run_mock(tmp_path, 'report', 'sheet', user=True, input=body)
        assert refused.returncode == 1 and b'not allowed' in refused.stderr
        empty = run_mock(tmp_path, 'report', 'sheet', user=False, input=b'{"records": []}')
        assert empty.returncode == 1 and b'no records to process' in empty.stderr
        junk = run_mock(tmp_path, 'report', 'sheet', user=False, input=b'{nope')
        assert junk.returncode == 1 and b'invalid JSON' in junk.stderr
        assert run_mock(tmp_path, 'report', 'pdf', user=False, input=body).returncode == 2
        failed = run_mock(tmp_path, 'report', 'sheet', user=False, input=body, extra_env={'MOCK_FAIL': 'report'})
        assert failed.returncode == 1 and b'mock failure' in failed.stderr


class TestApi:
    def test_guards(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                body = {'records': [record()]}
                assert (await h.client.post('/v1/reports/sheet', json=body, headers=headers(ALICE))).status == 403
                assert (await h.client.post('/v1/reports/pdf', json=body, headers=headers(PROF))).status == 404
                for bad in ({}, {'records': []}, {'records': [1]}, {'records': [record()], 'options': {'bogus': True}},
                            {'records': [record()], 'options': {'no_parts': 'yes'}}):
                    resp = await h.client.post('/v1/reports/sheet', json=bad, headers=headers(PROF))
                    assert resp.status == 400 and 'bad report request' in (await resp.json())['error'], bad
                resp = await h.client.post('/v1/reports/sheet', data=b'{nope', headers=headers(PROF))
                assert resp.status == 400
                assert h.calls() == []           # nothing reached sre
        run(go())

    def test_too_big(self, tmp_path, monkeypatch):
        monkeypatch.setattr(R, 'MAX_REPORT_BODY', 200)

        async def go():
            async with Harness(tmp_path) as h:
                body = json.dumps({'records': [record(fullname='x' * 300)]}).encode()
                resp = await h.client.post('/v1/reports/sheet', data=body, headers=headers(PROF))
                assert resp.status == 413 and 'too big' in (await resp.json())['error']
                small = json.dumps({'records': [{'running_lab_name': RLN}]}).encode()
                assert len(small) < 200
                assert (await h.client.post('/v1/reports/sheet', data=small, headers=headers(PROF))).status == 200
        run(go())

    def test_download(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                records = [record(), record(running_lab_name=RLN_BOB, login='bob')]
                resp = await h.client.post('/v1/reports/outline', headers=headers(PROF_FR),
                                           json={'records': records, 'options': {'separate_instances': True, 'no_parts': True}})
                assert resp.status == 200, await resp.text()
                assert resp.headers['Content-Type'] == 'application/zip'
                assert re.fullmatch(r'attachment; filename="reports_dhcp_\d{8}-\d{4}\.zip"', resp.headers['Content-Disposition'])
                got = members(await resp.read())
                assert json.loads(got['records.json']) == records
                assert got['flags.txt'].decode().splitlines() == ['--separate-instances', '--no-parts', '--lang fr']
                assert 'alice__dhcp__pool1__20261025100000.pdf' in got and 'outline.ods' in got
                # a privileged call in the instructor's language, the kind after the options
                entry = h.entries()[-1]
                assert entry['argv'] == ['report', '--lang', 'fr', '--separate-instances', '--no-parts', '--', 'outline']
                assert entry['user_mode'] is False and entry['env']['LOGNAME'] == 'prof' and 'SUDO_USER' not in entry['env']
                # a spreadsheet: the PDF options are left out
                resp = await h.client.post('/v1/reports/sheet', headers=headers(PROF),
                                           json={'records': records, 'options': {'no_parts': True, 'bonus_in_prefix': True}})
                assert resp.status == 200 and resp.headers['Content-Type'] == R.KINDS['sheet']
                assert resp.headers['Content-Disposition'].startswith('attachment; filename="evaluations_dhcp_')
                assert members(await resp.read())['flags.txt'].decode().splitlines() == ['--bonus-in-prefix', '--lang en']
                assert h.entries()[-1]['argv'] == ['report', '--lang', 'en', '--bonus-in-prefix', '--', 'sheet']
                # the summary spreadsheet alone: an ODS too, the PDF options left out
                resp = await h.client.post('/v1/reports/summary', headers=headers(PROF),
                                           json={'records': records, 'options': {'separate_instances': True, 'no_timeline': True}})
                assert resp.status == 200 and resp.headers['Content-Type'] == R.KINDS['summary'] == R.KINDS['sheet']
                assert re.fullmatch(r'attachment; filename="summary_dhcp_\d{8}-\d{4}\.ods"', resp.headers['Content-Disposition'])
                got = members(await resp.read())
                assert got['flags.txt'].decode().splitlines() == ['--separate-instances', '--lang en'] and 'outline.ods' not in got
                assert h.entries()[-1]['argv'] == ['report', '--lang', 'en', '--separate-instances', '--', 'summary']
        run(go())

    def test_failure_of_sre(self, tmp_path):
        async def go():
            async with Harness(tmp_path, mock_env={'MOCK_FAIL': 'report'}) as h:
                resp = await h.client.post('/v1/reports/sheet', json={'records': [record()]}, headers=headers(PROF))
                assert resp.status == 502 and 'mock failure' in (await resp.json())['error']
        run(go())


class TestRunnerLimit:
    def test_one_report_at_a_time(self):
        async def go():
            runner = SreRunner('/bin/true')
            assert 'report' in REPORT_LIKE
            held = await runner._acquire('prof', ['report', 'sheet'])
            assert runner._report_sem.locked() and runner.in_flight == 1
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(runner._acquire('other', ['report', 'outline']), 0.1)
            runner._release(held)
            assert not runner._report_sem.locked() and runner.in_flight == 0
            # the other limits are untouched by a report
            assert not runner._eval_sem.locked() and not runner._start_sem.locked()
        run(go())


class TestConfig:
    def test_timeout_key(self):
        assert DEFAULT_TIMEOUTS['report'] == 600.0
        cfg = agent_config_from_dict({'token': 't' * 32, 'timeouts': {'report': '15m'}}, sre_exe='/x', state_dir='/y')
        assert cfg.timeouts['report'] == 900 and cfg.timeouts['eval'] == 600
