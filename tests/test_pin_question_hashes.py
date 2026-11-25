"""Tests for src/tools/pin_question_hashes.py (sbin/pin-question-hashes): hash="..." written on the
questions of a lab file."""
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from SRE.common import QuestionText
from SRE.lib_sre import Grade0

# The tool lives in src/tools/, outside the normal package tree.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'src' / 'tools'))
import pin_question_hashes as pq  # noqa: E402

WRAPPER = ROOT / 'sbin' / 'pin-question-hashes'
RUNNING_LAB = '20260101000000@@@test/test1@@@user'
HASH_RE = re.compile(r'hash="([0-9a-f]+)"')
needs_venv = pytest.mark.skipif(not (ROOT / 'venv' / 'bin' / 'activate').exists(), reason="the wrapper needs the venv")

# A French lab with English translations.  Data.generate() gives 1, 2, 3...: the texts using
# d.value differ from one generated Data to the next, and the first Data has the value 1.
HEAD = '''\
import itertools
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0, make_tr

default_language = 'fr'
tr = make_tr(default_language)
_TRANSLATIONS = {'en': {
    "Passerelle de m1": "Gateway of m1",
    "Plan d'adressage": "Addressing plan",
    "Adresse de m2 : @@{ip:[0-9.]+}@@": "Address of m2: @@{ip:[0-9.]+}@@",
}}
_VALUES = itertools.count(1)


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=next(_VALUES))


class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)


class Grade(Grade0):
    def grade(self):
        super().grade()
        d = self.get_data()
'''
INDENT = " " * 8

# a translated free-text question, a translated form, a question in one language
THREE_QUESTIONS = '''\
gateway = self.question_text(
    title=tr("Passerelle de m1"),
)
plan = self.question_form(
    section=self.section(0),
    title=tr("Plan d'adressage"),
    description=tr("Adresse de m2 : @@{ip:[0-9.]+}@@"),
)
self.question_text(title="Une langue")
'''


def lab_text(body: str) -> str:
    return HEAD + textwrap.indent(textwrap.dedent(body), INDENT)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def make_lab(tmp_path, body: str, name: str = "lab.py") -> Path:
    return _write(tmp_path / name, lab_text(body))


def body_of(path: Path) -> str:
    """The body of grade() after the head, dedented, its hashes replaced by H."""
    text = _read(path)
    assert text.startswith(HEAD)
    return HASH_RE.sub('hash="H"', textwrap.dedent(text[len(HEAD):]))


def questions(path: Path, value: int = 1) -> list:
    """The questions the lab file registers for Data(value=value)."""
    with pq.lab_module(_read(path), path) as module:
        net_scheme = module.NetScheme(data=module.Data(value=value), running_lab_name=RUNNING_LAB)
        grade = module.Grade(net_scheme=net_scheme)
        grade._default_language = module.default_language
        grade.grade()
        return grade.get_questions_ordered()


def hashes(path: Path, value: int = 1) -> list:
    return [q.question_hash for q in questions(path, value)]


def written(path: Path) -> list:
    """The hash="..." values of the file, in order."""
    return HASH_RE.findall(_read(path))


class TestModes:
    def test_current_hash(self, tmp_path, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        before = hashes(lab)
        assert pq.main([str(lab)]) == 0
        assert written(lab) == before
        assert hashes(lab) == before
        out = capsys.readouterr().out
        assert f"{lab}: 3 question call(s), 3 hash(es) added (current)" in out
        # the two translated questions had another hash when every language counted
        assert "2 of these questions had another hash in the releases up to 0.19.0" in out
        assert "--hash former" in out
        assert "1 file(s) modified out of 1 lab file(s)" in out

    def test_former_hash(self, tmp_path, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        before = questions(lab)
        former = [q.legacy_hash or q.question_hash for q in before]
        assert before[0].legacy_hash and before[1].legacy_hash and before[2].legacy_hash is None
        assert pq.main(["--hash", "former", str(lab)]) == 0
        assert written(lab) == former
        assert hashes(lab) == former
        # a question in one language has one hash: the same in both modes
        assert former[2] == before[2].question_hash
        assert former[0] != before[0].question_hash
        assert "releases up to 0.19.0" not in capsys.readouterr().out

    def test_random_hash(self, tmp_path, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        before = hashes(lab)
        assert pq.main(["--hash", "random", str(lab)]) == 0
        values = written(lab)
        assert len(values) == 3 and len(set(values)) == 3
        assert all(re.fullmatch(r"[0-9a-f]{16}", v) for v in values)
        assert not set(values) & set(before)
        assert hashes(lab) == values
        assert "random hashes: the answers already stored for these questions are no longer found" \
            in capsys.readouterr().out

    def test_a_random_hash_already_used_is_drawn_again(self, tmp_path, monkeypatch):
        lab = make_lab(tmp_path, '''\
            self.question_text(title="Un", hash="aaaaaaaaaaaaaaaa")
            self.question_text(title="Deux")
            self.question_text(title="Trois")
            ''')
        draws = iter(["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"])
        monkeypatch.setattr(pq.secrets, "token_hex", lambda n: next(draws))
        assert pq.main(["--hash", "random", str(lab)]) == 0
        assert written(lab) == ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"]

    def test_the_texts_can_change_afterwards(self, tmp_path):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        assert pq.main([str(lab)]) == 0
        pinned = hashes(lab)
        text = _read(lab)
        for old, new in (('"Passerelle de m1"', '"Routeur par défaut de m1"'), ('"Gateway of m1"', '"Default router"'),
                         ("Adresse de m2 :", "Adresse IPv4 de m2 :"), ('"Une langue"', '"Reformulée"')):
            assert old in text
            text = text.replace(old, new)
        _write(lab, text)
        after = questions(lab)
        assert [q.question_hash for q in after] == pinned
        assert after[0].title.resolve('fr') == "Routeur par défaut de m1"

    def test_a_second_run_changes_nothing(self, tmp_path, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        assert pq.main([str(lab)]) == 0
        text = _read(lab)
        capsys.readouterr()
        assert pq.main(["--hash", "random", str(lab)]) == 0
        assert _read(lab) == text
        out = capsys.readouterr().out
        assert "3 question call(s), 0 hash(es) added, 3 already set" in out
        assert "0 file(s) modified out of 1 lab file(s)" in out

    def test_a_lab_with_every_hash_is_not_run(self, tmp_path):
        text = lab_text('self.question_text(title="Un", hash="mine")\n').replace(
            "_VALUES = itertools.count(1)", "raise RuntimeError('the lab was run')")
        lab = _write(tmp_path / "lab.py", text)
        assert pq.main([str(lab)]) == 0
        assert _read(lab) == text


class TestInitialState:
    def test_the_initial_state_completes_the_data(self, tmp_path):
        """grade() may read what initial() puts in the Data: `sre start` applies that state before
        any evaluation, and so does the script."""
        text = lab_text('self.question_text(title="Mot : " + d.note["word"])\n')
        for old, new in (("    value: int = 0\n", "    value: int = 0\n    note: dict = None\n"),
                         ("        super().__init__(data=data, running_lab_name=running_lab_name)\n",
                          "        super().__init__(data=data, running_lab_name=running_lab_name)\n\n"
                          "    def initial(self):\n        self.data.note = {'word': 'mot'}\n")):
            assert old in text
            text = text.replace(old, new)
        lab = _write(tmp_path / "lab.py", text)
        assert pq.main([str(lab)]) == 0
        assert written(lab) == [QuestionText(title="Mot : mot", default_language='fr').question_hash]


class TestVariableQuestions:
    BODY = '''\
        self.question_form(
            title="Adresse",
            description="Adresse du poste {} : @@{{ip:[0-9.]+}}@@".format(d.value),
        )
        self.question_dummy(
            title="Consigne",
            description=f"Configurez le poste {d.value}.",
        )
        self.question_text(title="Fixe")
        '''

    def test_pinned_with_a_warning(self, tmp_path, capsys):
        lab = make_lab(tmp_path, self.BODY)
        before = hashes(lab)        # for the first generated Data (value 1)
        assert pq.main([str(lab)]) == 0
        assert written(lab) == before
        # the same hash whatever the Data from now on
        assert hashes(lab, value=1) == hashes(lab, value=99) == before
        out = capsys.readouterr().out
        assert "3 hash(es) added (current)" in out
        assert "question_form() 'Adresse': its text depends on the generated data: the answers already " \
               "stored for it are no longer found" in out
        # a display-only block stores no answer: nothing to warn about
        assert "Consigne" not in out and "Fixe" not in out

    def test_kept_with_the_flag(self, tmp_path, capsys):
        lab = make_lab(tmp_path, self.BODY)
        before = hashes(lab)
        assert pq.main(["--keep-variable", str(lab)]) == 0
        assert written(lab) == before[1:]
        assert body_of(lab).startswith('self.question_form(\n    title="Adresse",\n    description=')
        assert hashes(lab, value=1)[0] != hashes(lab, value=99)[0]      # still from its text
        out = capsys.readouterr().out
        assert "3 question call(s), 2 hash(es) added (current), 1 left without" in out
        assert "question_form() 'Adresse': its text depends on the generated data, left without hash= " \
               "(--keep-variable)" in out

    def test_random_mode_says_it_once(self, tmp_path, capsys):
        lab = make_lab(tmp_path, self.BODY)
        assert pq.main(["--hash", "random", str(lab)]) == 0
        out = capsys.readouterr().out
        assert "depends on the generated data" not in out
        assert out.count("no longer found") == 1


class TestCallsLeftAlone:
    def test_loop_condition_and_kwargs(self, tmp_path, capsys):
        body = '''\
            for name in ("a", "b"):
                self.question_text(title=f"Question {name}")
            if d.value < 0:
                self.question_text(title="Jamais")
            if d.value % 2:
                self.question_text(title="Impair")
            self.question_text(**{"title": "Par dictionnaire"})
            self.question_text(*["Par liste"])
            self.question_text(title="Avec", hash="mine")
            self.question_text(title="Sans")
            '''
        lab = make_lab(tmp_path, body)
        before = hashes(lab)
        assert pq.main([str(lab)]) == 0
        assert written(lab) == [before[-1]]
        assert body_of(lab) == textwrap.dedent(body).replace('title="Sans"', 'title="Sans", hash="H"')
        out = capsys.readouterr().out
        assert "7 question call(s), 1 hash(es) added (current), 1 already set, 5 left without" in out
        line = lab_text("").count("\n") + 1
        assert f"line {line + 1}: question_text() 'Question a': registers several questions" in out
        assert f"line {line + 3}: question_text(): not reached by grade() (another flavor, a condition)" in out
        assert f"line {line + 5}: question_text() 'Impair': not reached by grade() for every generated data" in out
        assert f"line {line + 6}: question_text() 'Par dictionnaire': no plain title argument" in out
        assert f"line {line + 7}: question_text() 'Par liste': no plain title argument" in out

    def test_helper_method(self, tmp_path, capsys):
        text = lab_text('''\
            self.ask("Une fois")
            self.ask_twice("Premier")
            self.ask_twice("Second")
            ''') + '''
    def ask(self, title):
        return self.question_text(title=title)

    def ask_twice(self, title):
        return self.question_text(title=title)
'''
        lab = _write(tmp_path / "lab.py", text)
        before = hashes(lab)
        assert pq.main([str(lab)]) == 0
        assert written(lab) == [before[0]]
        assert f'return self.question_text(title=title, hash="{before[0]}")' in _read(lab)
        assert "registers several questions (a loop, a helper method)" in capsys.readouterr().out

    def test_a_call_that_is_not_a_method_call_of_the_file(self, tmp_path, capsys):
        lab = make_lab(tmp_path, '''\
            ask = self.question_text
            ask(title="Par un alias")
            self.question_text(title="Directe")
            ''')
        before = hashes(lab)
        assert pq.main([str(lab)]) == 0
        assert written(lab) == [before[1]]
        out = capsys.readouterr().out
        line = lab_text("").count("\n") + 2
        assert f"question_text() called at line {line}: not a call this script can change" in out


LAYOUTS = {
    "one argument per line": ('''\
        self.question_form(
            section=self.section(0),
            title=tr("Plan d'adressage"),
            description=tr("Adresse de m2 : @@{ip:[0-9.]+}@@"),
        )
        ''', '''\
        self.question_form(
            section=self.section(0),
            title=tr("Plan d'adressage"),
            hash="H",
            description=tr("Adresse de m2 : @@{ip:[0-9.]+}@@"),
        )
        '''),
    "single line": ('''\
        self.question_text(title="Court")
        ''', '''\
        self.question_text(title="Court", hash="H")
        '''),
    "arguments after the title on its line": ('''\
        self.question_text(title="Court", description="Une aide", order=5)
        ''', '''\
        self.question_text(title="Court", hash="H", description="Une aide", order=5)
        '''),
    "positional title on the opening line": ('''\
        gateway = self.question_text(tr("Passerelle de m1"),
                                     description="Une aide")
        ''', '''\
        gateway = self.question_text(tr("Passerelle de m1"),
                                     hash="H",
                                     description="Une aide")
        '''),
    "positional title on its own line": ('''\
        gateway = self.question_text(
            "Passerelle",
            section=self.section(1),
        )
        ''', '''\
        gateway = self.question_text(
            "Passerelle",
            hash="H",
            section=self.section(1),
        )
        '''),
    "several positional arguments": ('''\
        self.question_dummy("Titre", "I. ", "Une description")
        ''', '''\
        self.question_dummy("Titre", "I. ", "Une description", hash="H")
        '''),
    "title last without trailing comma": ('''\
        self.question_text(
            title=tr("Passerelle de m1")
        )
        ''', '''\
        self.question_text(
            title=tr("Passerelle de m1"), hash="H"
        )
        '''),
    "title last with a trailing comma": ('''\
        self.question_text(description="Une aide",
                           title=tr("Passerelle de m1"),
                           )
        ''', '''\
        self.question_text(description="Une aide",
                           title=tr("Passerelle de m1"),
                           hash="H",
                           )
        '''),
    "comment after the title": ('''\
        self.question_text(
            title=tr("Passerelle de m1"),  # the gateway, as m1 sees it (a comma, and a parenthesis)
            description="Une aide",
        )
        ''', '''\
        self.question_text(
            title=tr("Passerelle de m1"),  # the gateway, as m1 sees it (a comma, and a parenthesis)
            hash="H",
            description="Une aide",
        )
        '''),
    "parenthesised title": ('''\
        self.question_text(title=(tr("Passerelle de m1")), description="Une aide")
        ''', '''\
        self.question_text(title=(tr("Passerelle de m1")), hash="H", description="Une aide")
        '''),
    "title over several lines": ('''\
        self.question_text(
            title=tr("Passerelle de m1")
                  + " (suite)",
            description="""Une aide
        sur deux lignes, avec une virgule""",
        )
        ''', '''\
        self.question_text(
            title=tr("Passerelle de m1")
                  + " (suite)",
            hash="H",
            description="""Une aide
        sur deux lignes, avec une virgule""",
        )
        '''),
    "a lambda and a call before the title": ('''\
        self.question_text(order=(lambda a, b: a + b)(1, 2), title="Court", description="x, y")
        ''', '''\
        self.question_text(order=(lambda a, b: a + b)(1, 2), title="Court", hash="H", description="x, y")
        '''),
    "accented characters before the call and in the title": ('''\
        réponse_été = self.question_text(title="Départ de l'été à Orléans", description="é")
        ''', '''\
        réponse_été = self.question_text(title="Départ de l'été à Orléans", hash="H", description="é")
        '''),
    "two calls on one line": ('''\
        a, b = self.question_text(title="Un"), self.question_text(title="Deux")
        ''', '''\
        a, b = self.question_text(title="Un", hash="H"), self.question_text(title="Deux", hash="H")
        '''),
}


class TestLayout:
    @pytest.mark.parametrize("name", LAYOUTS)
    def test_layout(self, tmp_path, name):
        body, expected = LAYOUTS[name]
        lab = make_lab(tmp_path, body)
        before = hashes(lab)
        assert pq.main(["--hash", "random", str(lab)]) == 0
        assert body_of(lab) == textwrap.dedent(expected)
        assert len(hashes(lab)) == len(before)

    def test_a_long_line_is_broken_under_the_first_argument(self, tmp_path):
        lab = make_lab(tmp_path, '''\
            self.question_dummy(section=self.section(1), title="Une question")
            self.question_dummy(
                section=self.section(1), title="Une autre question", description="Avec un texte assez long ici")
            self.question_dummy(section=self.section(1), title="Une dernière question", description="Un texte", order=900)
            ''')
        assert pq.main([str(lab)]) == 0     # 64 characters: past 120 columns on each of these lines
        assert body_of(lab) == textwrap.dedent('''\
            self.question_dummy(section=self.section(1), title="Une question",
                                hash="H")
            self.question_dummy(
                section=self.section(1), title="Une autre question",
                hash="H",
                description="Avec un texte assez long ici")
            self.question_dummy(section=self.section(1), title="Une dernière question",
                                hash="H",
                                description="Un texte", order=900)
            ''')
        assert all(len(line) <= pq.MAX_LINE for line in _read(lab).splitlines())

    def test_line_endings_kept(self, tmp_path):
        text = lab_text(THREE_QUESTIONS).replace("\n", "\r\n")
        lab = _write(tmp_path / "lab.py", text)
        assert pq.main([str(lab)]) == 0
        new = _read(lab)
        assert len(HASH_RE.findall(new)) == 3
        assert "\n" not in new.replace("\r\n", "")
        assert new.count("\r\n") == text.count("\r\n") + 2      # two hashes on a line of their own

    def test_tab_indentation_kept(self, tmp_path):
        text = lab_text(THREE_QUESTIONS).replace("    ", "\t")
        lab = _write(tmp_path / "lab.py", text)
        assert pq.main(["--hash", "random", str(lab)]) == 0
        assert '\t\t\ttitle=tr("Plan d\'adressage"),\n\t\t\thash="' in _read(lab)


class TestCommandLine:
    def test_dry_run_writes_nothing(self, tmp_path, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        text = _read(lab)
        assert pq.main(["-n", str(lab)]) == 0
        assert _read(lab) == text
        out = capsys.readouterr().out
        assert "3 hash(es) to add (current)" in out
        assert "1 file(s) to modify out of 1 lab file(s)" in out

    def test_diff(self, tmp_path, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        before = hashes(lab)
        assert pq.main(["-n", "--diff", str(lab)]) == 0
        out = capsys.readouterr().out
        assert f"--- {lab}\n+++ {lab}\n" in out
        assert f'+            hash="{before[0]}",\n' in out
        assert f'-        self.question_text(title="Une langue")\n' \
               f'+        self.question_text(title="Une langue", hash="{before[2]}")\n' in out

    def test_directories(self, tmp_path, capsys):
        top = make_lab(tmp_path / "labs", THREE_QUESTIONS, "top.py")
        below = make_lab(tmp_path / "labs", THREE_QUESTIONS, "sub/below.py")
        other = _write(tmp_path / "labs" / "helper.py", "x = 1\n")
        assert pq.main([str(tmp_path / "labs")]) == 0
        assert len(written(top)) == 3 and not written(below)
        assert "1 file(s) modified out of 1 lab file(s)" in capsys.readouterr().out
        assert pq.main(["-r", str(tmp_path / "labs")]) == 0
        assert len(written(below)) == 3
        out = capsys.readouterr().out
        assert "1 file(s) modified out of 2 lab file(s)" in out
        assert "helper.py" not in out and "top.py" not in out       # nothing to say about them
        assert _read(other) == "x = 1\n"

    def test_a_file_that_is_not_a_lab(self, tmp_path, capsys):
        other = _write(tmp_path / "helper.py", "def f(self):\n    self.question_text(title='x')\n")
        assert pq.main([str(other)]) == 0
        assert f"{other}: skipped, not a lab file" in capsys.readouterr().out
        assert "hash" not in _read(other)

    def test_errors_do_not_stop_the_other_files(self, tmp_path, capsys):
        broken = _write(tmp_path / "broken.py", lab_text(THREE_QUESTIONS).replace(
            "return cls(value=next(_VALUES))", "raise RuntimeError('no data')"))
        syntax = _write(tmp_path / "syntax.py", "class Grade(Grade0:\n")
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        assert pq.main([str(broken), str(syntax), str(tmp_path / "missing.py"), str(lab)]) == 1
        captured = capsys.readouterr()
        assert f"{broken}: cannot run the lab: RuntimeError: no data" in captured.err
        assert f"{syntax}: cannot parse" in captured.err
        assert "missing.py: no such file or directory" in captured.err
        assert "1 file(s) modified out of 1 lab file(s), 3 error(s)" in captured.out
        assert len(written(lab)) == 3
        assert "hash=" not in _read(broken)

    def test_grading_helpers_closed_to_the_caller(self, tmp_path, capsys, monkeypatch):
        """lib/ is closed to the students: a lab that cannot import its helpers is told why."""
        lab = _write(tmp_path / "lab.py", "import sre_helper_nobody_has\n" + lab_text(THREE_QUESTIONS))
        missing = f"{lab}: cannot run the lab: ModuleNotFoundError: No module named 'sre_helper_nobody_has'"
        assert pq.main([str(lab)]) == 1
        assert missing + "\n" in capsys.readouterr().err           # a readable lib/: nothing to add
        if os.geteuid() == 0:
            return                                                  # root reads a closed directory
        closed = tmp_path / "lib"
        closed.mkdir()
        closed.chmod(0)
        monkeypatch.setattr(pq.sre().params, "lib_dir", str(closed))
        try:
            assert pq.main([str(lab)]) == 1
        finally:
            closed.chmod(0o700)
        assert (f"{missing} ({closed}, the grading helpers the labs import, is not readable by this user: "
                "run the command as a user of its group, or as root)\n") in capsys.readouterr().err
        assert "hash=" not in _read(lab)

    def test_the_core_is_left_as_it_was(self, tmp_path):
        originals = [Grade0.__dict__[name] for name in pq.QUESTION_METHODS]
        marker = object()
        sys.modules["srelab"] = marker
        try:
            assert pq.main([str(make_lab(tmp_path, THREE_QUESTIONS))]) == 0
            broken = lab_text('self.question_text(title="Un")\nraise RuntimeError("grade")\n')
            assert pq.main([str(_write(tmp_path / "broken.py", broken))]) == 1
            assert sys.modules["srelab"] is marker
        finally:
            del sys.modules["srelab"]
        assert [Grade0.__dict__[name] for name in pq.QUESTION_METHODS] == originals


class TestCommand:
    """sbin/pin-question-hashes: the tool run with the Python of SRE, as the other lab-authoring tools."""

    def test_wrapper_is_executable(self):
        assert WRAPPER.is_file() and os.access(WRAPPER, os.X_OK)
        assert 'src/tools/pin_question_hashes.py' in WRAPPER.read_text()

    def test_the_tool_finds_sre_from_its_own_place(self):
        assert (pq.SRC_DIR / 'SRE' / 'lib_sre.py').is_file()

    @needs_venv
    def test_wrapper(self, tmp_path):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        before = hashes(lab)
        r = subprocess.run([str(WRAPPER), str(lab)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert f"{lab}: 3 question call(s), 3 hash(es) added (current)" in r.stdout
        assert written(lab) == before

    @needs_venv
    def test_wrapper_through_a_link(self, tmp_path):
        """As from /usr/local/sbin, where scripts/install.sh links the commands of sbin/."""
        link = tmp_path / "sbin" / WRAPPER.name
        link.parent.mkdir()
        link.symlink_to(WRAPPER)
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        r = subprocess.run([str(link), "-n", "lab.py"], capture_output=True, text=True, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        assert "lab.py: 3 question call(s), 3 hash(es) to add (current)" in r.stdout
        assert not written(lab)

    @needs_venv
    def test_wrapper_gives_the_exit_status(self, tmp_path):
        r = subprocess.run([str(WRAPPER), str(tmp_path / "missing.py")], capture_output=True, text=True)
        assert r.returncode == 1
        assert "missing.py: no such file or directory" in r.stderr


class TestChecks:
    """A result that is not the lab with its hashes is never written."""

    def test_a_wrong_value_is_refused(self, tmp_path, monkeypatch, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        text = _read(lab)
        edit = pq.hash_edit

        def wrong(source, call, argument, value):
            start, end, inserted = edit(source, call, argument, value)
            return start, end, inserted.replace(value, "0" * len(value))

        monkeypatch.setattr(pq, "hash_edit", wrong)
        assert pq.main([str(lab)]) == 1
        assert _read(lab) == text
        assert "the hash was not written as expected, file left unchanged" in capsys.readouterr().err

    def test_another_program_is_refused(self, tmp_path, monkeypatch, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        text = _read(lab)
        edit = pq.hash_edit

        def more(source, call, argument, value):
            start, end, inserted = edit(source, call, argument, value)
            return start, end, inserted.replace('hash="', 'order=7, hash="')

        monkeypatch.setattr(pq, "hash_edit", more)
        assert pq.main([str(lab)]) == 1
        assert _read(lab) == text
        assert "the changed file is another program, left unchanged" in capsys.readouterr().err

    def test_a_broken_result_is_refused(self, tmp_path, monkeypatch, capsys):
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        text = _read(lab)
        monkeypatch.setattr(pq, "hash_edit", lambda source, call, argument, value: (0, 0, "(\n"))
        assert pq.main([str(lab)]) == 1
        assert _read(lab) == text
        assert "the changed file does not parse, left unchanged" in capsys.readouterr().err

    def test_calls_found_by_their_line_without_columns(self, tmp_path, monkeypatch):
        """A Python run without column positions (-X no_debug_ranges) still matches the calls."""
        lab = make_lab(tmp_path, THREE_QUESTIONS)
        before = hashes(lab)
        position = pq.call_position
        monkeypatch.setattr(pq, "call_position", lambda frame: (position(frame)[0], None))
        assert pq.main([str(lab)]) == 0
        assert written(lab) == before
