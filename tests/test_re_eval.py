"""Tests for `sre re-eval` command (src/SRE/command/re_eval.py).

Focused on the auto_eval_count round-trip:
- archive's answers[auto_eval_count_keyword] must be visible as
  grade.auto_eval_count inside grade() during re-eval
- the re-saved archive must preserve the value in its answers section
"""
import hashlib
import json
import os
import stat
from pathlib import Path

import msgpack
import pytest
import zstandard as zstd

from SRE import params, web_updates
from SRE.command.re_eval import _load_srelab, action_re_eval
from SRE.common import TranslatedText, _tt_hash_str


_RUNNING_LAB_NAME = '20260101000000@@@auto_eval_count_lab@@@user'
_ARCHIVE_STEM = f'20260101000000_{_RUNNING_LAB_NAME}'


# srelab whose only grade element echoes self.auto_eval_count as its grade.
_AUTO_EVAL_COUNT_SRELAB = """\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0

@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)

class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='auto_eval_count',
                               grade=self.auto_eval_count, max_grade=100)
"""


def _read_archive(path):
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _make_archive(path, module, *, archived_count, stored_grade,
                  include_keyword=True, current_srelab_file=None,
                  exam_json=None, container_engine=None):
    """Build an archive whose grade_list element is locked at ``stored_grade``
    and whose answers section carries ``archived_count`` under
    ``params.auto_eval_count_keyword`` (unless ``include_keyword`` is False).
    Optional ``exam_json`` is embedded under ``params.exam_json_keyword``."""
    data = module.Data(value=42)
    if current_srelab_file is not None:
        object.__setattr__(data, '__current_srelab_file', current_srelab_file)

    net_scheme = module.NetScheme(data=data, running_lab_name=_RUNNING_LAB_NAME)
    grade = module.Grade(net_scheme=net_scheme)
    grade._default_language = 'en'

    grade.auto_eval_count = stored_grade
    grade.reset_before_grade()
    grade.grade()
    grade.compute_total()
    grade._eval_date = '2026-01-01T00:00:00'
    if include_keyword:
        grade._answers[params.auto_eval_count_keyword] = archived_count
    if exam_json is not None:
        grade._exam_json = exam_json
    grade._container_engine = container_engine      # what an evaluation notes of its project
    grade.save_tests_on_file(str(path))


# srelab in French with an English translation, whose two grade elements tell whether the
# answers of its two questions were found.  @GATEWAY_EN@ is the English title of the first one.
_QUESTIONS_SRELAB = """\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0, make_tr

default_language = 'fr'
tr = make_tr(default_language)
_TRANSLATIONS = {'en': {
    "Passerelle de m1": "@GATEWAY_EN@",
    "Plan d'adressage": "Addressing plan",
    "Adresse de m2 : @@{ip:[0-9.]+}@@": "Address of m2: @@{ip:[0-9.]+}@@",
}}

@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)

class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

class Grade(Grade0):
    def grade(self):
        super().grade()
        gateway = self.question_text(title=tr("Passerelle de m1"))
        plan = self.question_form(title=tr("Plan d'adressage"),
                                  description=tr("Adresse de m2 : @@{ip:[0-9.]+}@@"))
        self.add_grade_element(title='gateway', grade=1 if gateway == '10.0.0.254' else 0, max_grade=1)
        self.add_grade_element(title='plan', grade=1 if plan.get('ip') == '10.0.0.2' else 0, max_grade=1)
"""
GATEWAY_EN = "Gateway of m1"
QUESTIONS_ANSWERS = ('10.0.0.254', json.dumps({'ip': '10.0.0.2'}))     # the right ones


def questions_srelab(gateway_en: str = GATEWAY_EN) -> str:
    """The source of the questions lab, with *gateway_en* as English title of its first question."""
    return _QUESTIONS_SRELAB.replace('@GATEWAY_EN@', gateway_en)


def former_question_hashes(gateway_en: str = GATEWAY_EN) -> tuple:
    """``(text, form)``: the hashes the two questions of the questions lab had when every
    language of their texts counted, computed here from the texts."""
    gateway = TranslatedText({'fr': "Passerelle de m1", 'en': gateway_en})
    plan = TranslatedText({'fr': "Plan d'adressage", 'en': "Addressing plan"})
    address = TranslatedText({'fr': "Adresse de m2 : @@{ip:[0-9.]+}@@", 'en': "Address of m2: @@{ip:[0-9.]+}@@"})
    return (hashlib.sha256(_tt_hash_str(gateway).encode('UTF-8')).hexdigest(),
            hashlib.sha256((_tt_hash_str(plan) + '--' + _tt_hash_str(address)).encode('UTF-8')).hexdigest())


def make_questions_archive(path, module, *, former_hashes: bool, graded: bool, current_srelab_file=None):
    """An archive of the questions lab *module* holding the right answers, stored under the
    former hashes of the questions (*former_hashes*) or under their hashes; its stored grades
    count the answers (*graded*: 2 / 2) or not (0 / 2)."""
    data = module.Data(value=42)
    if current_srelab_file is not None:
        object.__setattr__(data, '__current_srelab_file', current_srelab_file)
    net_scheme = module.NetScheme(data=data, running_lab_name=_RUNNING_LAB_NAME)
    grade = module.Grade(net_scheme=net_scheme)
    grade._default_language = module.default_language
    grade.reset_before_grade()
    grade.grade()
    hashes = [q.question_hash for q in grade.get_questions_ordered()]
    if graded:
        grade._answers.update(zip(hashes, QUESTIONS_ANSWERS))
        grade.reset_before_grade()
        grade.grade()
    grade.compute_total()
    grade._eval_date = '2026-01-01T00:00:00'
    grade._answers = dict(zip(former_question_hashes() if former_hashes else hashes, QUESTIONS_ANSWERS))
    grade.save_tests_on_file(str(path))


@pytest.fixture
def srelab(tmp_path):
    p = tmp_path / 'srelab.py'
    p.write_text(_AUTO_EVAL_COUNT_SRELAB)
    return p


@pytest.fixture
def module(srelab):
    mod, _ = _load_srelab(str(srelab))
    return mod


class TestReEvalAutoEvalCount:
    """re-eval must load auto_eval_count from the archive's answers
    section into grade.auto_eval_count before grade() runs, and preserve
    the value in the re-saved archive's answers section."""

    def test_grade_uses_archived_count(self, mock_sre_args, tmp_path,
                                        module, srelab, capsys):
        """Archive answers has auto_eval_count=4; re-eval recomputes the
        grade element using auto_eval_count=4 → new stored grade == 4."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=4, stored_grade=0,
                      current_srelab_file=str(srelab))

        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False

        action_re_eval()

        new_path = out_dir / f'reeval_{_ARCHIVE_STEM}.zst'
        assert new_path.exists()
        archive = _read_archive(new_path)
        grade_list = list(archive['grade_list'])
        assert len(grade_list) == 1
        assert grade_list[0]['title'] == 'auto_eval_count'
        assert grade_list[0]['grade'] == 4
        assert grade_list[0]['max_grade'] == 100
        assert archive['total_grade_exo_eval'] == 4

    def test_count_preserved_in_new_archive_answers(self, mock_sre_args, tmp_path,
                                                     module, srelab, capsys):
        """The re-saved archive's answers section must still carry
        auto_eval_count_keyword with the original value."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=4, stored_grade=0,
                      current_srelab_file=str(srelab))

        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False

        action_re_eval()

        new_path = out_dir / f'reeval_{_ARCHIVE_STEM}.zst'
        archive = _read_archive(new_path)
        assert archive['answers'][params.auto_eval_count_keyword] == 4

    def test_defaults_to_zero_when_keyword_absent(self, mock_sre_args, tmp_path,
                                                   module, srelab, capsys):
        """Legacy archive without auto_eval_count → re-eval uses 0 → new
        grade = 0, and the new archive does not have the keyword either."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=4,
                      include_keyword=False, current_srelab_file=str(srelab))

        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False

        action_re_eval()

        new_path = out_dir / f'reeval_{_ARCHIVE_STEM}.zst'
        archive = _read_archive(new_path)
        grade_list = list(archive['grade_list'])
        assert grade_list[0]['grade'] == 0
        assert params.auto_eval_count_keyword not in archive['answers']


class TestReEvalQuestionHashes:
    """The answers of an archive are found by re-eval whatever the hashes they are stored
    under: those of the questions (their texts in the default language of the lab), or those
    the questions had when every language counted (the archives made before)."""

    @staticmethod
    def _lab(tmp_path, name: str, gateway_en: str = GATEWAY_EN) -> Path:
        path = tmp_path / name / 'srelab.py'
        path.parent.mkdir()
        path.write_text(questions_srelab(gateway_en))
        return path

    @staticmethod
    def _re_eval(mock_sre_args, tmp_path, srelab_file, in_archive) -> dict:
        """``{title: grade}`` of *in_archive* re-evaluated with *srelab_file*."""
        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab_file)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False
        action_re_eval()
        archive = _read_archive(out_dir / f'reeval_{_ARCHIVE_STEM}.zst')
        return {e['title']: e['grade'] for e in archive['grade_list']}

    def _archive(self, tmp_path, srelab_file, *, former_hashes: bool) -> Path:
        module, _ = _load_srelab(str(srelab_file))
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        make_questions_archive(in_archive, module, former_hashes=former_hashes, graded=False,
                               current_srelab_file=str(srelab_file))
        stored = _read_archive(in_archive)
        assert {e['title']: e['grade'] for e in stored['grade_list']} == {'gateway': 0, 'plan': 0}
        return in_archive

    def test_the_hashes_of_the_lab(self, tmp_path):
        module, _ = _load_srelab(str(self._lab(tmp_path, 'lab')))
        grade = module.Grade(net_scheme=module.NetScheme(data=module.Data(value=42),
                                                         running_lab_name=_RUNNING_LAB_NAME))
        grade._default_language = module.default_language
        grade.reset_before_grade()
        grade.grade()
        questions = grade.get_questions_ordered()
        assert tuple(q.legacy_hash for q in questions) == former_question_hashes()
        assert not {q.question_hash for q in questions} & set(former_question_hashes())

    def test_answers_under_the_hashes_of_the_questions(self, mock_sre_args, tmp_path, capsys):
        lab = self._lab(tmp_path, 'lab')
        in_archive = self._archive(tmp_path, lab, former_hashes=False)
        assert self._re_eval(mock_sre_args, tmp_path, lab, in_archive) == {'gateway': 1, 'plan': 1}

    def test_answers_under_the_former_hashes(self, mock_sre_args, tmp_path, capsys):
        lab = self._lab(tmp_path, 'lab')
        in_archive = self._archive(tmp_path, lab, former_hashes=True)
        assert set(_read_archive(in_archive)['answers']) >= set(former_question_hashes())
        assert self._re_eval(mock_sre_args, tmp_path, lab, in_archive) == {'gateway': 1, 'plan': 1}

    def test_a_translation_changed_since_the_archive(self, mock_sre_args, tmp_path, capsys):
        in_archive = self._archive(tmp_path, self._lab(tmp_path, 'lab'), former_hashes=False)
        corrected = self._lab(tmp_path, 'corrected', gateway_en="Default gateway of m1")
        assert self._re_eval(mock_sre_args, tmp_path, corrected, in_archive) == {'gateway': 1, 'plan': 1}

    def test_a_former_hash_still_depends_on_the_translations(self, mock_sre_args, tmp_path, capsys):
        # an archive made before the change of rule: the question whose translation changed
        # since is not matched (as it was not before), the untouched one is
        in_archive = self._archive(tmp_path, self._lab(tmp_path, 'lab'), former_hashes=True)
        corrected = self._lab(tmp_path, 'corrected', gateway_en="Default gateway of m1")
        assert self._re_eval(mock_sre_args, tmp_path, corrected, in_archive) == {'gateway': 0, 'plan': 1}


class TestReEvalExamJson:
    """re-eval must round-trip the archive's embedded exam.json verbatim.

    Re-evaluations typically run long after the exam, often on a different
    machine where /var/lib/sre/exam.json is absent or stale. The exam
    parameters captured at evaluation time must come from the archive, not
    from whatever happens to be on disk now.
    """

    _EXAM_JSON = {
        params.exam_start_after: '2026-01-01T08:00:00',
        params.exam_end_before:  '2026-01-01T12:00:00',
        params.exam_duration:    90,
        params.exam_started_at:  '2026-01-01T08:30:00',
        params.exam_labs:        [['auto_eval_count_lab', None]],
    }

    def _run_re_eval(self, mock_sre_args, tmp_path, srelab, in_archive):
        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False
        action_re_eval()
        return out_dir / f'reeval_{_ARCHIVE_STEM}.zst'

    def test_exam_json_preserved_in_new_archive(self, mock_sre_args, tmp_path,
                                                 tmp_pub_dir, module, srelab):
        """Archive embeds exam.json → re-eval preserves it verbatim."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0,
                      current_srelab_file=str(srelab),
                      exam_json=self._EXAM_JSON)

        new_path = self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive)
        archive = _read_archive(new_path)
        # msgpack returns tuples for lists with use_list=False; compare as JSON.
        import json
        assert json.loads(json.dumps(archive[params.exam_json_keyword])) == self._EXAM_JSON

    @pytest.mark.parametrize('engine', ['podman', 'kathara'])
    def test_the_engine_of_the_evaluation_is_kept(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab,
                                                  monkeypatch, engine):
        """A re-evaluation runs no machine: the new archive says which engine ran the project
        when it was evaluated, whatever the engine of the host that re-grades."""
        monkeypatch.setattr(params, 'container_engine', 'kathara')
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0, current_srelab_file=str(srelab),
                      container_engine=engine)
        assert _read_archive(in_archive)[params.archive_engine_keyword] == engine
        archive = _read_archive(self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive))
        assert archive[params.archive_engine_keyword] == engine

    def test_no_engine_when_the_archive_lacks_it(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab):
        """An archive written before the engine was recorded: the re-evaluation does not make one up."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0, current_srelab_file=str(srelab))
        assert params.archive_engine_keyword not in _read_archive(in_archive)
        archive = _read_archive(self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive))
        assert params.archive_engine_keyword not in archive

    def test_no_exam_json_when_archive_lacks_it(self, mock_sre_args, tmp_path,
                                                 tmp_pub_dir, module, srelab):
        """Archive without exam.json → re-eval must not introduce one."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0,
                      current_srelab_file=str(srelab))

        new_path = self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive)
        archive = _read_archive(new_path)
        assert params.exam_json_keyword not in archive

    def test_archive_exam_json_wins_over_live_file(self, mock_sre_args, tmp_path,
                                                    tmp_pub_dir, module, srelab):
        """The archive's exam.json must win over whatever is currently on disk.

        Simulate re-evaluating on a host whose /var/lib/sre/exam.json reflects
        a different (later) exam — the re-saved archive must still carry the
        original parameters captured when the eval first ran.
        """
        import json
        live_exam = {
            params.exam_start_after: '2099-12-31T23:59:59',
            params.exam_duration:    7,
            params.exam_labs:        [['some_other_lab', None]],
        }
        (tmp_pub_dir / params.exam_json_name).write_text(json.dumps(live_exam))

        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0,
                      current_srelab_file=str(srelab),
                      exam_json=self._EXAM_JSON)

        new_path = self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive)
        archive = _read_archive(new_path)
        assert json.loads(json.dumps(archive[params.exam_json_keyword])) == self._EXAM_JSON


class TestReEvalUpdateWeb:
    """``--update-web``: the results of each re-graded archive are queued for the web portal in
    the spool of the host (``web_updates``), under the name of the archive they come from —
    the name the portal knows the evaluation by — whatever the prefix and the output directory."""

    @pytest.fixture(autouse=True)
    def no_agent(self, tmp_path, monkeypatch):
        """Whether the test host runs a web agent must not change the output."""
        monkeypatch.setattr(params, 'agent_config_file', str(tmp_path / 'no-agent.toml'))

    def _run(self, mock_sre_args, tmp_path, srelab, in_archive, *, update_web=True):
        out_dir = tmp_path / 'out'
        out_dir.mkdir(exist_ok=True)
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False
        mock_sre_args.update_web = update_web
        action_re_eval()
        return out_dir

    def _archive(self, tmp_path, module, srelab, name=f'{_ARCHIVE_STEM}.zst'):
        in_archive = tmp_path / name
        _make_archive(in_archive, module, archived_count=4, stored_grade=0, current_srelab_file=str(srelab))
        return in_archive

    def test_queued_under_the_original_name(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab, capsys):
        in_archive = self._archive(tmp_path, module, srelab)
        out_dir = self._run(mock_sre_args, tmp_path, srelab, in_archive)

        assert (out_dir / f'reeval_{_ARCHIVE_STEM}.zst').exists()
        entries, more, last, dropped = web_updates.pending(params.web_updates_dir)
        assert (more, last, dropped) == (False, f'{_ARCHIVE_STEM}.zst', [])
        record = entries[0]['record']
        assert record[params.archive_keyword] == f'{_ARCHIVE_STEM}.zst'       # not 'reeval_…'
        assert record[params.running_lab_name_keyword] == _RUNNING_LAB_NAME
        assert (record['grade'], record['max_grade']) == (4.0, 100.0)          # the new grade
        assert [(e['grade'], e['max_grade']) for e in record['elements']] == [(4.0, 100.0)]
        assert record['eval_date'].startswith('2026-01-01T00:00:00')           # the original evaluation
        assert record[params.re_eval_date_keyword]
        out = capsys.readouterr()
        assert f"queued for the web portal: 1 evaluation(s) in {params.web_updates_dir}" in out.out
        assert "no web agent is configured on this host" in out.err

    def test_private_spool(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab):
        self._run(mock_sre_args, tmp_path, srelab, self._archive(tmp_path, module, srelab))
        spool = Path(params.web_updates_dir)
        assert stat.S_IMODE(spool.stat().st_mode) == 0o700
        assert [stat.S_IMODE(p.stat().st_mode) for p in spool.iterdir()] == [0o600]

    def test_no_warning_next_to_an_agent(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab, capsys,
                                         monkeypatch):
        agent_toml = tmp_path / 'agent.toml'
        agent_toml.write_text('')
        monkeypatch.setattr(params, 'agent_config_file', str(agent_toml))
        self._run(mock_sre_args, tmp_path, srelab, self._archive(tmp_path, module, srelab))
        assert capsys.readouterr().err == ''

    def test_nothing_queued_without_the_flag(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab, capsys):
        out_dir = self._run(mock_sre_args, tmp_path, srelab, self._archive(tmp_path, module, srelab),
                            update_web=False)
        assert (out_dir / f'reeval_{_ARCHIVE_STEM}.zst').exists()
        assert not Path(params.web_updates_dir).exists()
        assert 'web portal' not in capsys.readouterr().out

    def test_second_run_replaces_the_pending_update(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab):
        in_archive = self._archive(tmp_path, module, srelab)
        self._run(mock_sre_args, tmp_path, srelab, in_archive)
        first = web_updates.pending(params.web_updates_dir)[0]
        self._run(mock_sre_args, tmp_path, srelab, in_archive)
        second = web_updates.pending(params.web_updates_dir)[0]
        assert len(first) == len(second) == 1
        assert second[0]['token'] != first[0]['token']

    def test_updates_nobody_took_are_dropped(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab, capsys):
        """A queue nothing reads (no portal collecting from this host) does not grow for ever:
        the next run drops what the earlier ones left for more than a day, and says so."""
        in_archive = self._archive(tmp_path, module, srelab)
        assert web_updates.prepare(params.web_updates_dir) is None
        stale = Path(params.web_updates_dir) / web_updates.entry_name('20250101000000_' + _RUNNING_LAB_NAME + '.zst')
        stale.write_text('{}')
        old = stale.stat().st_mtime - params.web_updates_max_age - 60
        os.utime(stale, (old, old))
        self._run(mock_sre_args, tmp_path, srelab, in_archive)
        assert [p.name for p in Path(params.web_updates_dir).iterdir()] == [web_updates.entry_name(in_archive.name)]
        assert "warning: 1 update(s) queued more than 24 h ago were never taken by the portal: dropped" \
            in capsys.readouterr().err

    def test_a_file_not_named_as_an_archive_is_not_queued(self, mock_sre_args, tmp_path, tmp_pub_dir, module,
                                                         srelab, capsys):
        """The output of an earlier re-eval (``corrected…``) names no evaluation of the portal."""
        in_archive = self._archive(tmp_path, module, srelab, name=f'corrected{_ARCHIVE_STEM}.zst')
        out_dir = self._run(mock_sre_args, tmp_path, srelab, in_archive)
        assert (out_dir / f'reeval_corrected{_ARCHIVE_STEM}.zst').exists()      # re-graded all the same
        assert web_updates.pending_count(params.web_updates_dir) == 0
        out = capsys.readouterr()
        assert f"error: {in_archive} not queued for the web portal: its file name is not the one" in out.err
        assert "queued for the web portal: 0 evaluation(s)" in out.out

    def test_a_renamed_archive_is_not_queued(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab, capsys):
        """An archive under the name of another project would replace that project's evaluation."""
        other = '20260101000000_20260101000000@@@auto_eval_count_lab@@@somebody.zst'
        in_archive = self._archive(tmp_path, module, srelab, name=other)
        self._run(mock_sre_args, tmp_path, srelab, in_archive)
        assert web_updates.pending_count(params.web_updates_dir) == 0
        assert f"the archive is the one of the project {_RUNNING_LAB_NAME!r}" in capsys.readouterr().err

    def test_unusable_spool_quits_before_grading(self, mock_sre_args, tmp_path, tmp_pub_dir, module, srelab,
                                                 capsys):
        Path(params.web_updates_dir).write_text('')         # not a directory
        in_archive = self._archive(tmp_path, module, srelab)
        with pytest.raises(SystemExit) as exit_info:
            self._run(mock_sre_args, tmp_path, srelab, in_archive)
        assert exit_info.value.code == 1
        assert list((tmp_path / 'out').iterdir()) == []
        err = capsys.readouterr().err
        assert f"sre: --update-web: {params.web_updates_dir}: not a directory" in err
        assert "as root on a pool host" in err
