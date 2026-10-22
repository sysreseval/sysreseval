"""Tests for src/tools/strip_instructor.py (sbin/strip-instructor): a lab file without its
instructor() calls."""
import ast
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# The tool lives in src/tools/, outside the normal package tree.
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'src' / 'tools'))
from strip_instructor import StripError, _instructor_names, _is_instructor_call, main, strip_source  # noqa: E402

TOOL = ROOT / 'src' / 'tools' / 'strip_instructor.py'
WRAPPER = ROOT / 'sbin' / 'strip-instructor'
FIXTURE_LAB = ROOT / 'tests' / 'labs' / 'instructor_test_lab.py'


def strip(source: str) -> str:
    return strip_source(textwrap.dedent(source).encode()).data.decode()


def dedent(source: str) -> str:
    return textwrap.dedent(source)


# ---------------------------------------------------------------------------
# The calls
# ---------------------------------------------------------------------------

class TestOperandOfPlus:
    @pytest.mark.parametrize('source, expected', [
        ('x = instructor(tr("note")) + tr("public")\n', 'x = tr("public")\n'),
        ('x = tr("public") + instructor(tr("note"), color="#00f")\n', 'x = tr("public")\n'),
        ('x = a + instructor(b) + c\n', 'x = a + c\n'),
        ('x = instructor(a) + b + c\n', 'x = b + c\n'),
        ('x = a + b + instructor(c)\n', 'x = a + b\n'),
        ('x = instructor(a) + instructor(b) + c\n', 'x = c\n'),
        ('x = a + instructor(b) + instructor(c)\n', 'x = a\n'),
        ('x = a + instructor(b) + c + instructor(d) + e\n', 'x = a + c + e\n'),
    ])
    def test_the_call_and_its_operator_are_removed(self, source, expected):
        assert strip(source) == expected

    @pytest.mark.parametrize('source, expected', [
        ('x = (instructor(a)) + (b)\n', 'x = (b)\n'),
        ('x = (a) + (instructor(b))\n', 'x = (a)\n'),
        ('x = ((a) + instructor(b)) + c\n', 'x = ((a)) + c\n'),
        ('x = (a + (instructor(b) + c))\n', 'x = (a + (c))\n'),
    ])
    def test_parentheses_stay_with_their_operand(self, source, expected):
        assert strip(source) == expected

    def test_multi_line_call_before_the_public_text(self):
        assert strip('''
            self.informations = instructor(tr("""
                ## Solution
                Do this.
                """, fr="""
                ## Solution
                Faire ceci.
                """)) + tr("""
                Public text.
                """)
            ''') == dedent('''
            self.informations = tr("""
                Public text.
                """)
            ''')

    def test_call_before_a_parenthesised_expression(self):
        assert strip('''
            self.informations = instructor(tr("note")) + (
                    no_tr("##")
                    + title
            )
            ''') == dedent('''
            self.informations = (
                    no_tr("##")
                    + title
            )
            ''')

    def test_operator_on_the_next_line(self):
        assert strip('''
            q(title=tr("Gateway") + instructor(tr(" (expected)")),
              description=tr("Which gateway?")
                          + instructor(tr("Any notation."), color="#1a4fa0", background="#e3edff"))
            ''') == dedent('''
            q(title=tr("Gateway"),
              description=tr("Which gateway?"))
            ''')

    def test_call_between_two_lines_of_a_chain(self):
        assert strip('''
            description = (
                intro
                + instructor(tr("note").format(n=n))
                + outro
            )
            ''') == dedent('''
            description = (
                intro
                + outro
            )
            ''')

    @pytest.mark.parametrize('source, expected', [
        ('x = instructor(a) + \\\n    b\n', 'x = b\n'),
        ('x = a + \\\n    instructor(b)\n', 'x = a\n'),
    ])
    def test_backslash_continuation(self, source, expected):
        assert strip(source) == expected

    def test_comment_between_operand_and_operator_goes_with_the_operator(self):
        assert strip('x = (a  # about + (the note\n     + instructor(b))\ny = 1  # kept\n') == 'x = (a)\ny = 1  # kept\n'

    def test_comment_after_the_operator(self):
        assert strip('x = (instructor(a) +  # note\n     b)\n') == 'x = (b)\n'

    def test_non_ascii_text_around(self):
        """AST offsets are UTF-8 byte offsets."""
        assert strip('x = "é→" + instructor("corrigé é") + "à"  # été\n') == 'x = "é→" + "à"  # été\n'


class TestOtherPositions:
    @pytest.mark.parametrize('source, expected', [
        ('self.informations = instructor(tr("note"))\n', "self.informations = ''\n"),
        ('f(instructor(a), k=instructor(b) + instructor(c))\n', "f('', k='')\n"),
        ('text += instructor("note")\n', "text += ''\n"),
        ('def f():\n    return instructor("note")\n', "def f():\n    return ''\n"),
        ('x = [a, instructor(b)]\n', "x = [a, '']\n"),
        ('x = instructor(a) * 2\n', "x = '' * 2\n"),
        ('x = (instructor(a))\n', "x = ('')\n"),
        ('x = instructor(a) if c else b\n', "x = '' if c else b\n"),
    ])
    def test_replaced_by_an_empty_string(self, source, expected):
        assert strip(source) == expected

    def test_nested_calls(self):
        assert strip('x = instructor(instructor(a) + b) + c\n') == 'x = c\n'

    def test_alias(self):
        source = 'from SRE.lib_sre import instructor as note, tr\nx = note("a") + "b" + note(note("c"))\n'
        assert strip(source) == 'from SRE.lib_sre import tr\nx = "b"\n'

    def test_attribute_call(self):
        assert strip('import SRE.lib_sre as lib\nx = lib.instructor("a") + "b"\n') == 'import SRE.lib_sre as lib\nx = "b"\n'

    def test_other_functions_are_left_alone(self):
        source = 'x = instructors("a") + tr("b") + self.instructor_mode\n'
        result = strip_source(source.encode())
        assert result.data.decode() == source and result.calls == 0

    def test_counts(self):
        result = strip_source(b'x = instructor(instructor(a)) + b\ny = instructor(c)\n')
        assert result.calls == 3 and result.translations == 0 and not result.warnings


# ---------------------------------------------------------------------------
# _TRANSLATIONS
# ---------------------------------------------------------------------------

LAB_WITH_TRANSLATIONS = '''
    from SRE.lib_sre import instructor, make_tr
    tr = make_tr('fr')
    _TRANSLATIONS = {
        'en': {
            'note': 'the note',
            'public': 'the public text',
            """note
    sur deux lignes""": """note
    on two lines""",
            'les deux': 'both',
        },
        'de': {
            'note': 'die Notiz',
            'public': 'der Text',
        },
    }
    x = instructor(tr("note")) + tr("public") + instructor(tr("""note
    sur deux lignes"""))
    y = instructor(tr("les deux")) + tr("les deux")
    '''


class TestTranslations:
    def test_entries_of_the_removed_texts_are_deleted_in_every_language(self):
        result = strip_source(dedent(LAB_WITH_TRANSLATIONS).encode())
        assert result.data.decode() == dedent('''
            from SRE.lib_sre import make_tr
            tr = make_tr('fr')
            _TRANSLATIONS = {
                'en': {
                    'public': 'the public text',
                    'les deux': 'both',
                },
                'de': {
                    'public': 'der Text',
                },
            }
            x = tr("public")
            y = tr("les deux")
            ''')
        assert result.translations == 3 and result.calls == 3

    def test_remaining_dict_is_the_original_without_the_notes(self):
        tree = ast.parse(strip(LAB_WITH_TRANSLATIONS))
        translations = next(ast.literal_eval(node.value) for node in tree.body
                            if isinstance(node, ast.Assign) and node.targets[0].id == '_TRANSLATIONS')
        assert translations == {'en': {'public': 'the public text', 'les deux': 'both'}, 'de': {'public': 'der Text'}}

    def test_entries_on_one_line(self):
        assert strip('''
            _TRANSLATIONS = {'en': {'a': 'A', 'note': 'N', 'b': 'B'}, 'de': {'note': 'N'}}
            x = tr("a") + instructor(tr("note")) + tr("b")
            ''') == dedent('''
            _TRANSLATIONS = {'en': {'a': 'A', 'b': 'B'}, 'de': {}}
            x = tr("a") + tr("b")
            ''')

    def test_dict_at_the_end_of_the_file(self):
        assert strip('''
            x = instructor(tr("note"))
            _TRANSLATIONS = {
                'en': {
                    'note': 'N',
                },
            }''') == dedent('''
            x = \'\'
            _TRANSLATIONS = {
                'en': {
                },
            }''')

    def test_inline_translations_go_with_the_call(self):
        assert strip('x = instructor(tr("note", fr="la note")) + tr("public", fr="public")\n') == \
            'x = tr("public", fr="public")\n'

    def test_non_literal_dict_is_reported(self):
        source = dedent('''
            _TRANSLATIONS = load_translations()
            x = instructor(tr("note")) + tr("public")
            ''')
        result = strip_source(source.encode())
        assert result.data.decode() == source.replace('instructor(tr("note")) + ', '')
        assert result.translations == 0
        assert len(result.warnings) == 1 and '_TRANSLATIONS is not a literal dict' in result.warnings[0]

    def test_no_warning_when_no_translated_text_is_removed(self):
        assert strip_source(b'_TRANSLATIONS = load()\nx = instructor("note") + tr("public")\n').warnings == []


# ---------------------------------------------------------------------------
# The import
# ---------------------------------------------------------------------------

class TestImport:
    @pytest.mark.parametrize('before, after', [
        ('from SRE.lib_sre import Data0, instructor, make_tr\n', 'from SRE.lib_sre import Data0, make_tr\n'),
        ('from SRE.lib_sre import instructor, make_tr\n', 'from SRE.lib_sre import make_tr\n'),
        ('from SRE.lib_sre import Data0, instructor\n', 'from SRE.lib_sre import Data0\n'),
        ('from SRE.lib_sre import (\n    Data0,\n    instructor,\n    make_tr,\n)\n',
         'from SRE.lib_sre import (\n    Data0,\n    make_tr,\n)\n'),
        ('from SRE.lib_sre import (\n    no_tr, make_tr, instructor,\n)\n',
         'from SRE.lib_sre import (\n    no_tr, make_tr,\n)\n'),
        ('from SRE.lib_sre import (Data0,\n                         instructor)\n', 'from SRE.lib_sre import (Data0)\n'),
        ('import os\nfrom SRE.instructor_text import instructor\nimport sys\n', 'import os\nimport sys\n'),
    ])
    def test_name_removed_when_unused(self, before, after):
        assert strip(before + 'x = instructor("note") + "public"\n') == after + 'x = "public"\n'

    def test_only_statement_of_a_block(self):
        source = 'if True:\n    from SRE.lib_sre import instructor\nx = instructor("a") + "b"\n'
        assert strip(source) == 'if True:\n    pass\nx = "b"\n'

    def test_kept_when_the_function_is_still_used(self):
        source = 'from SRE.lib_sre import instructor, tr\nmark = instructor\nx = instructor("a") + "b"\n'
        result = strip_source(source.encode())
        assert result.data.decode() == 'from SRE.lib_sre import instructor, tr\nmark = instructor\nx = "b"\n'
        assert result.import_removed is False

    def test_untouched_without_any_call(self):
        source = b'from SRE.lib_sre import instructor, tr\nx = tr("public")\n'
        result = strip_source(source)
        assert result.data == source and result.calls == 0


# ---------------------------------------------------------------------------
# Warnings and errors
# ---------------------------------------------------------------------------

class TestWarnings:
    def test_variable_only_used_by_the_removed_calls(self):
        result = strip_source(dedent('''
            note = tr("the solution")
            shared = tr("shared")
            x = tr("public") + instructor(note + shared + d.secret + str(n))
            y = shared
            ''').encode())
        assert len(result.warnings) == 1
        assert result.warnings[0].startswith("line 2: 'note' is only used inside instructor()")
        assert 'note = tr("the solution")' in result.data.decode()

    def test_loop_variables_are_not_reported(self):
        assert strip_source(b'for m in machines:\n    text = text + instructor(m)\n').warnings == []

    def test_wrapping_the_definition_removes_it(self):
        """What the warning suggests."""
        result = strip_source(b'note = instructor(tr("the solution"))\nx = tr("public") + instructor(note)\n')
        assert result.data == b"note = ''\nx = tr(\"public\")\n" and not result.warnings


class TestErrors:
    def test_file_that_does_not_parse(self):
        with pytest.raises(StripError, match='line 1'):
            strip_source(b'x = instructor(\n')

    def test_the_result_always_parses(self):
        for source in ('x = [instructor(a) + b for b in c if instructor(d) + b]\n',
                       'x = {instructor(a): instructor(b) + c}\n',
                       'x = f(*[instructor(a)], **{"k": b + instructor(c)})\n',
                       'x = lambda: instructor(a) + b\n',
                       '@deco(instructor(a) + b)\ndef f(p=instructor(c)): pass\n'):
            ast.parse(strip(source))


# ---------------------------------------------------------------------------
# Real files
# ---------------------------------------------------------------------------

class TestRealFiles:
    def test_fixture_lab(self):
        result = strip_source(FIXTURE_LAB.read_bytes())
        text = result.data.decode()
        assert result.calls == 4 and result.import_removed and not result.warnings
        assert 'from SRE.lib_sre import Data0, NetScheme0, Grade0, make_tr\n' in text
        for note in ('Solution', 'expected', 'attendu', 'Any notation', 'The mask is 24'):
            assert note not in text
        assert 'self.informations = tr("""\n            Configure the default route of the client.' in text
        assert 'title=tr("Gateway", fr="Passerelle"),' in text
        assert 'description=tr("Prefix length: @@{mask:[0-9]+}@@"))' in text

    @pytest.mark.parametrize('lab', sorted((ROOT / 'tests' / 'labs').glob('functional_test_lab.py'))
                             + sorted((ROOT / 'lab' / 'sre').glob('*.py')), ids=lambda p: p.name)
    def test_file_without_call_is_unchanged_and_others_still_parse(self, lab):
        data = lab.read_bytes()
        result = strip_source(data)
        if result.calls == 0:
            assert result.data == data
        else:
            # no call is left in the code: a docstring or a comment may still say "instructor()"
            # (the module docstring of lab/sre/dhcp.py does), so the stripped tree is checked,
            # not the bytes
            names = _instructor_names(ast.parse(data))
            stripped = ast.parse(result.data)
            assert not any(_is_instructor_call(node, names) for node in ast.walk(stripped))


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

SOURCE = 'from SRE.lib_sre import instructor, tr\nx = instructor(tr("note")) + tr("public")\n'
STRIPPED = 'from SRE.lib_sre import tr\nx = tr("public")\n'


@pytest.fixture
def project(tmp_path):
    path = tmp_path / 'project.py'
    path.write_text(SOURCE)
    return path


class TestCommandLine:
    def test_output_file(self, project, tmp_path, capsys):
        output = tmp_path / 'public.py'
        assert main([str(project), str(output)]) == 0
        assert output.read_text() == STRIPPED and project.read_text() == SOURCE
        assert capsys.readouterr().out == f"{output}: 1 instructor() call(s) removed.\n"

    def test_output_file_is_overwritten(self, project, tmp_path):
        output = tmp_path / 'public.py'
        output.write_text('old')
        assert main([str(project), str(output)]) == 0
        assert output.read_text() == STRIPPED

    def test_output_directory(self, project, tmp_path):
        directory = tmp_path / 'public'
        directory.mkdir()
        assert main([str(project), str(directory)]) == 0
        assert (directory / 'project.py').read_text() == STRIPPED and project.read_text() == SOURCE

    def test_in_place(self, project):
        project.chmod(0o640)
        assert main(['-i', str(project)]) == 0
        assert project.read_text() == STRIPPED
        assert stat.S_IMODE(project.stat().st_mode) == 0o640
        assert [p.name for p in project.parent.iterdir()] == ['project.py'], "no temporary file left"

    def test_in_place_leaves_a_file_without_call_untouched(self, tmp_path, capsys):
        path = tmp_path / 'plain.py'
        path.write_text('x = tr("public")\n')
        os.utime(path, (1, 1))
        assert main(['-i', str(path)]) == 0
        assert path.stat().st_mtime == 1
        assert capsys.readouterr().out == f"{path}: no instructor() call.\n"

    def test_file_without_call_is_copied(self, tmp_path):
        path = tmp_path / 'plain.py'
        path.write_text('x = tr("public")\n')
        assert main([str(path), str(tmp_path / 'copy.py')]) == 0
        assert (tmp_path / 'copy.py').read_text() == 'x = tr("public")\n'

    def test_summary_counts_the_translations(self, tmp_path, capsys):
        path = tmp_path / 'lab.py'
        path.write_text(dedent(LAB_WITH_TRANSLATIONS))
        assert main(['-i', str(path)]) == 0
        assert capsys.readouterr().out == f"{path}: 3 instructor() call(s) removed, 3 _TRANSLATIONS entries removed.\n"

    def test_warnings_go_to_stderr(self, tmp_path, capsys):
        path = tmp_path / 'lab.py'
        path.write_text('note = tr("solution")\nx = tr("public") + instructor(note)\n')
        assert main([str(path), str(tmp_path / 'out.py')]) == 0
        assert f"strip-instructor: {path}: warning: line 1: 'note' is only used inside" in capsys.readouterr().err

    @pytest.mark.parametrize('arguments', [['project.py'], ['-i', 'project.py', 'out.py'], []])
    def test_usage_errors(self, project, monkeypatch, capsys, arguments):
        monkeypatch.chdir(project.parent)
        with pytest.raises(SystemExit) as error:
            main(arguments)
        assert error.value.code == 2
        assert 'usage: strip-instructor' in capsys.readouterr().err
        assert project.read_text() == SOURCE and not (project.parent / 'out.py').exists()

    def test_output_is_the_project_file(self, project, capsys):
        assert main([str(project), str(project)]) == 1
        assert main([str(project), str(project.parent)]) == 1
        assert 'use -i' in capsys.readouterr().err
        assert project.read_text() == SOURCE

    def test_missing_project(self, tmp_path, capsys):
        assert main([str(tmp_path / 'missing.py'), str(tmp_path / 'out.py')]) == 1
        assert 'cannot read' in capsys.readouterr().err and not (tmp_path / 'out.py').exists()

    def test_missing_output_directory(self, project, tmp_path, capsys):
        assert main([str(project), str(tmp_path / 'missing' / 'out.py')]) == 1
        assert 'cannot write' in capsys.readouterr().err

    def test_invalid_file_writes_nothing(self, tmp_path, capsys):
        path = tmp_path / 'broken.py'
        path.write_text('x = instructor(\n')
        assert main([str(path), str(tmp_path / 'out.py')]) == 1
        assert main(['-i', str(path)]) == 1
        assert f"strip-instructor: {path}: line 1" in capsys.readouterr().err
        assert not (tmp_path / 'out.py').exists() and path.read_text() == 'x = instructor(\n'

    def test_tool_run_as_a_script(self, project, tmp_path):
        r = subprocess.run([sys.executable, str(TOOL), str(project), str(tmp_path / 'out.py')],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert (tmp_path / 'out.py').read_text() == STRIPPED

    def test_wrapper_is_executable(self):
        assert WRAPPER.is_file() and os.access(WRAPPER, os.X_OK)
        assert 'src/tools/strip_instructor.py' in WRAPPER.read_text()

    @pytest.mark.skipif(not (ROOT / 'venv' / 'bin' / 'activate').exists(), reason="the wrapper needs the venv")
    def test_wrapper(self, project):
        r = subprocess.run([str(WRAPPER), '-i', str(project)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert project.read_text() == STRIPPED


# ---------------------------------------------------------------------------
# --full: the states students cannot apply
# ---------------------------------------------------------------------------

def strip_full(source: str) -> str:
    return strip_source(textwrap.dedent(source).encode(), full=True).data.decode()


def with_final(code: str) -> tuple:
    """(source, expected) of a snippet preceded by a class holding one removed state."""
    return (f'class N:\n    @sre_state\n    def final(self): pass\n{dedent(code)}',
            f'class N:\n    pass\n')


FULL_LAB = '''
    from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, instructor, make_tr
    tr = make_tr('fr')
    _TRANSLATIONS = {
        'en': {
            'Solution complète': 'Full solution',
            'Panne': 'Fault',
            'Public': 'Public',
        },
    }
    SECRET = "ip route add default via 10.0.0.1"


    class NetScheme(NetScheme0):
        def __init__(self, data, running_lab_name):
            super().__init__(data=data, running_lab_name=running_lab_name)
            self.informations = tr("Public")

        def _addresses(self):
            self.cmd("pc", "ip addr add 10.0.0.2/24 dev eth0")

        def _solve(self):
            self.cmd("pc", "ip route add default via 10.0.0.1")

        @sre_state
        def initial(self):
            self._addresses()

        @sre_state(user_allowed=False)
        def restore(self):
            self._addresses()

        @sre_state(user_allowed=True,
                   description=tr("Panne"))
        def fault(self):
            self.cmd("pc", "ip route del default")

        @sre_state(user_allowed=False, description=tr("Solution complète"))
        def final(self):
            # the answer
            self._solve()
            self.file("pc", "/root/answer", SECRET)
            self.informations = instructor(tr("note"))


    class Grade(Grade0):
        def grade(self):
            super().grade()
            answers = {"gw": "10.0.0.1"}
            self.question_form(title=tr("Gateway"), description=tr("@@{gw:.*}@@"),
                               cheat_answers={"final": answers})
    '''

FULL_LAB_STRIPPED = '''
    from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr
    tr = make_tr('fr')
    _TRANSLATIONS = {
        'en': {
            'Panne': 'Fault',
            'Public': 'Public',
        },
    }
    SECRET = "ip route add default via 10.0.0.1"


    class NetScheme(NetScheme0):
        def __init__(self, data, running_lab_name):
            super().__init__(data=data, running_lab_name=running_lab_name)
            self.informations = tr("Public")

        def _addresses(self):
            self.cmd("pc", "ip addr add 10.0.0.2/24 dev eth0")

        def _solve(self):
            self.cmd("pc", "ip route add default via 10.0.0.1")

        @sre_state
        def initial(self):
            self._addresses()

        @sre_state(user_allowed=False)
        def restore(self):
            self._addresses()

        @sre_state(user_allowed=True,
                   description=tr("Panne"))
        def fault(self):
            self.cmd("pc", "ip route del default")


    class Grade(Grade0):
        def grade(self):
            super().grade()
            answers = {"gw": "10.0.0.1"}
            self.question_form(title=tr("Gateway"), description=tr("@@{gw:.*}@@"))
    '''


class TestFullStates:
    @pytest.mark.parametrize('decorator', ['@sre_state', '@sre_state()', '@sre_state(user_allowed=False)',
                                           '@sre_state(description="x")', '@sre_state(multi_pass=True)',
                                           '@sre_state(user_allowed=0)'])
    def test_removed_whatever_the_decorator_form(self, decorator):
        source = f'class N:\n    def a(self):\n        pass\n\n    {decorator}\n    def final(self):\n        pass\n'
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == 'class N:\n    def a(self):\n        pass\n'
        assert result.states == ['final'] and result.calls == 0 and not result.warnings

    @pytest.mark.parametrize('name, decorator', [
        ('initial', '@sre_state'), ('save', '@sre_state()'), ('restore', '@sre_state(user_allowed=False)'),
        ('final', '@sre_state(user_allowed=True)'), ('final', '@sre_state(user_allowed=True, description="x")'),
        ('final', '@sre_state(description="x",\n               user_allowed=True)'),
    ])
    def test_kept_states(self, name, decorator):
        source = f'class N:\n    {decorator}\n    def {name}(self):\n        pass\n'
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == source and result.states == [] and not result.warnings

    def test_whole_lab(self):
        result = strip_source(dedent(FULL_LAB).encode(), full=True)
        assert result.data.decode() == dedent(FULL_LAB_STRIPPED)
        assert result.states == ['final'] and result.calls == 1 and result.translations == 1
        assert result.cheat_entries == 1 and result.import_removed
        assert result.warnings == [
            "line 11: 'SECRET' is only used inside the removed states but defined outside: its definition is "
            "left in the file",
            "line 49: 'answers' is only used inside the removed cheat_answers but defined outside: its definition "
            "is left in the file",
            "line 22: the method '_solve' is only used inside the removed states: its definition is left in the file",
        ]

    def test_without_full_only_the_instructor_call_goes(self):
        result = strip_source(dedent(FULL_LAB).encode())
        assert result.states == [] and result.calls == 1 and result.cheat_entries == 0
        text = result.data.decode()
        assert 'def final(self):' in text and 'cheat_answers={"final": answers}' in text
        assert "self.informations = ''" in text and 'instructor' not in text.split('\n')[1]

    def test_nothing_to_remove(self):
        source = b'from SRE.lib_sre import sre_state\nclass N:\n    @sre_state\n    def initial(self): pass\n'
        result = strip_source(source, full=True)
        assert result.data == source and result.states == [] and not result.warnings

    def test_blank_lines_above_go_with_the_method(self):
        assert strip_full('''
            class N:
                def a(self): pass


                @sre_state
                def final(self): pass

                def b(self): pass
            ''') == dedent('''
            class N:
                def a(self): pass

                def b(self): pass
            ''')

    def test_first_method_of_the_class(self):
        assert strip_full('''
            class N:
                @sre_state
                def final(self):
                    pass

                def b(self): pass
            ''') == dedent('''
            class N:

                def b(self): pass
            ''')

    def test_last_method_keeps_the_separation_with_the_next_class(self):
        assert strip_full('''
            class N:
                def a(self): pass

                @sre_state
                def final(self): pass


            class G:
                pass
            ''') == dedent('''
            class N:
                def a(self): pass


            class G:
                pass
            ''')

    @pytest.mark.parametrize('source, expected', [
        ('class N(NetScheme0):\n    @sre_state()\n    def final(self):\n        pass\n', 'class N(NetScheme0):\n    pass\n'),
        ('class N:\n    @sre_state\n    def final(self): pass  # c\nx = 2\n', 'class N:\n    pass  # c\nx = 2\n'),
    ])
    def test_only_method_becomes_pass(self, source, expected):
        assert strip_source(source.encode(), full=True).data.decode() == expected

    def test_several_decorators_and_a_multi_line_one(self):
        assert strip_full('''
            class N:
                x = 1

                @other
                @sre_state(user_allowed=False,
                           description=tr("Solution"))
                def final(self):
                    pass
            ''') == dedent('''
            class N:
                x = 1
            ''')

    def test_two_states_removed_in_two_classes(self):
        result = strip_source(dedent('''
            class A:
                @sre_state
                def final(self): pass
            class B:
                @sre_state
                def ok(self): pass
                @sre_state
                def final(self): pass
            ''').encode(), full=True)
        assert result.data.decode() == '\nclass A:\n    pass\nclass B:\n    pass\n'
        assert result.states == ['final', 'ok']

    def test_alias_and_attribute_decorator(self):
        assert strip_full('''
            from SRE.lib_sre import sre_state as state
            import SRE.lib_sre as lib
            class N:
                @state
                def final(self): pass
                @lib.sre_state()
                def ok(self): pass
                def a(self): pass
            ''') == dedent('''
            import SRE.lib_sre as lib
            class N:
                def a(self): pass
            ''')

    def test_non_literal_user_allowed_is_kept_with_a_warning(self):
        source = 'class N:\n    @sre_state(user_allowed=FLAG)\n    def final(self): pass\n'
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == source and result.states == []
        assert result.warnings == ["line 3: the user_allowed value of the state 'final' is not a literal: the state is kept"]

    def test_translations_of_the_removed_state_only(self):
        assert strip_full('''
            _TRANSLATIONS = {'en': {'a': 'A', 'b': 'B', 'c': 'C'}}
            class N:
                @sre_state(description=tr("a"))
                def final(self):
                    self.cmd("m", tr("b"))
                @sre_state(user_allowed=True, description=tr("b"))
                def fault(self):
                    self.cmd("m", tr("c"))
            ''') == dedent('''
            _TRANSLATIONS = {'en': {'b': 'B', 'c': 'C'}}
            class N:
                @sre_state(user_allowed=True, description=tr("b"))
                def fault(self):
                    self.cmd("m", tr("c"))
            ''')

    def test_instructor_calls_inside_a_removed_state_go_with_it(self):
        result = strip_source(dedent('''
            from SRE.lib_sre import instructor, sre_state, tr
            class N:
                @sre_state
                def initial(self):
                    self.informations = tr("public")
                @sre_state
                def final(self):
                    self.informations = instructor(tr("note")) + tr("public") + instructor(tr("more"))
            ''').encode(), full=True)
        assert result.data.decode() == dedent('''
            from SRE.lib_sre import sre_state, tr
            class N:
                @sre_state
                def initial(self):
                    self.informations = tr("public")
            ''')
        assert result.calls == 2 and result.states == ['final']

    @pytest.mark.parametrize('before, after', [
        ('from SRE.lib_sre import NetScheme0, sre_state\n', 'from SRE.lib_sre import NetScheme0\n'),
        ('from SRE.lib_sre import a, instructor, sre_state\n', 'from SRE.lib_sre import a\n'),
        ('from SRE.lib_sre import instructor, sre_state, a\n', 'from SRE.lib_sre import a\n'),
        ('from SRE.lib_sre import instructor, a, sre_state\n', 'from SRE.lib_sre import a\n'),
        ('from SRE.lib_sre import (\n    instructor,\n    a,\n    sre_state,\n)\n', 'from SRE.lib_sre import (\n    a,\n)\n'),
        ('from SRE.lib_sre import (\n    instructor,\n    sre_state,\n)\n', ''),
    ])
    def test_sre_state_import_removed_when_no_state_is_left(self, before, after):
        source = before + 'class N:\n    @sre_state\n    def final(self):\n        x = instructor("n")\n'
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == after + 'class N:\n    pass\n' and result.import_removed

    def test_sre_state_import_kept_while_a_state_remains(self):
        source = 'from SRE.lib_sre import sre_state\nclass N:\n    @sre_state\n    def initial(self): pass\n    @sre_state\n    def final(self): pass\n'
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == 'from SRE.lib_sre import sre_state\nclass N:\n    @sre_state\n    def initial(self): pass\n'
        assert not result.import_removed

    def test_unused_sre_state_import_is_left_without_full(self):
        source = b'from SRE.lib_sre import sre_state, instructor\nx = instructor("a") + "b"\n'
        assert strip_source(source).data == b'from SRE.lib_sre import sre_state\nx = "b"\n'


class TestFullCheatAnswers:
    def test_last_keyword_after_a_parenthesised_value(self):
        source, prefix = with_final('''
            self.question_text(
                title=tr("Q"),
                description=(
                    tr("D")
                ),  # about D
                cheat_answers={"final": a},
            )
            ''')
        assert strip_source(source.encode(), full=True).data.decode() == prefix + dedent('''
            self.question_text(
                title=tr("Q"),
                description=(
                    tr("D")
                ),  # about D
            )
            ''')

    @pytest.mark.parametrize('call, expected', [
        ('q(a, cheat_answers={"final": x})\n', 'q(a)\n'),
        ('q(a, cheat_answers={"final": x}, b=1)\n', 'q(a, b=1)\n'),
        ('q(cheat_answers={"final": x}, b=1)\n', 'q(b=1)\n'),
        ('q(cheat_answers={"final": x})\n', 'q()\n'),
        ('q(a,\n  cheat_answers={"final": x},\n  b=1)\n', 'q(a,\n  b=1)\n'),
        ('q(a, cheat_answers={"final": x, "ok": y})\n', 'q(a, cheat_answers={"ok": y})\n'),
        ('q(a, cheat_answers={"ok": y, "final": x})\n', 'q(a, cheat_answers={"ok": y})\n'),
        ('q(a,\n  cheat_answers={"final": x}\n)\n', 'q(a,\n)\n'),
        ('q(a,\n  cheat_answers={"final": x})\n', 'q(a)\n'),
        ('q(a, cheat_answers={\n    "final": x,\n    "ok": y,\n})\n', 'q(a, cheat_answers={\n    "ok": y,\n})\n'),
        ('q(a, cheat_answers={"ok": y})\n', 'q(a, cheat_answers={"ok": y})\n'),
    ])
    def test_entry_or_whole_keyword(self, call, expected):
        source, prefix = with_final(call)
        assert strip_source(source.encode(), full=True).data.decode() == prefix + expected

    def test_entries_of_every_removed_state(self):
        source = 'class N:\n    @sre_state\n    def final(self): pass\n    @sre_state\n    def ok(self): pass\n' \
                 'q(a, cheat_answers={"final": x, "ok": y, "fault": z})\n'
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == 'class N:\n    pass\nq(a, cheat_answers={"fault": z})\n'
        assert result.cheat_entries == 2

    def test_non_literal_dict_is_reported(self):
        source, prefix = with_final('q(a, cheat_answers=answers)\n')
        result = strip_source(source.encode(), full=True)
        assert result.data.decode() == prefix + 'q(a, cheat_answers=answers)\n' and result.cheat_entries == 0
        assert result.warnings == ["line 4: cheat_answers is not a literal dict: the answers of the removed states, "
                                   "if any, are still in the file"]

    def test_untouched_without_full(self):
        source = 'class N:\n    @sre_state\n    def final(self): pass\nq(a, cheat_answers={"final": x})\n'
        assert strip_source(source.encode()).data.decode() == source


class TestFullReferences:
    def test_kept_method_using_a_removed_state_refuses_the_file(self):
        with pytest.raises(StripError, match=r"line 8: restore\(\) uses self.final while the state 'final' is removed"):
            strip_source(dedent('''
                class N:
                    @sre_state
                    def final(self):
                        pass
                    @sre_state
                    def restore(self):
                        self.final()
                ''').encode(), full=True)

    def test_classmethod_and_module_level(self):
        with pytest.raises(StripError, match=r"line 6: helper\(\) uses cls.final"):
            strip_source(b'class N:\n    @sre_state\n    def final(self): pass\n    @classmethod\n    def helper(cls):\n        return cls.final\n', full=True)

    def test_reference_inside_another_removed_state_is_fine(self):
        result = strip_source(dedent('''
            class N:
                @sre_state
                def final(self):
                    pass
                @sre_state
                def ok(self):
                    self.final()
            ''').encode(), full=True)
        assert result.data.decode() == '\nclass N:\n    pass\n' and result.states == ['final', 'ok']

    def test_other_attributes_of_the_same_name_are_fine(self):
        source = 'class N:\n    @sre_state\n    def final(self): pass\n    def a(self):\n        return other.final, self.final_text\n'
        assert strip_source(source.encode(), full=True).data.decode() == 'class N:\n' + source.split('pass\n', 1)[1]


class TestFullWarnings:
    def test_helper_method_only_the_removed_state_uses(self):
        result = strip_source(dedent('''
            class N:
                def _shared(self): pass
                def _solve(self): pass
                @sre_state
                def initial(self):
                    self._shared()
                @sre_state
                def final(self):
                    self._shared()
                    self._solve()
                    self.initial()
            ''').encode(), full=True)
        assert result.warnings == ["line 4: the method '_solve' is only used inside the removed states: its "
                                   "definition is left in the file"]

    def test_constant_and_cheat_variable(self):
        result = strip_source(dedent('''
            SECRET = "s"
            SHARED = "x"
            class N:
                @sre_state
                def initial(self):
                    self.cmd("m", SHARED)
                @sre_state
                def final(self):
                    self.cmd("m", SECRET + SHARED)
                    local = 1
                    self.cmd("m", str(local))
            def grade(self):
                answers = {"a": 1}
                self.q(cheat_answers={"final": answers})
            ''').encode(), full=True)
        assert result.warnings == [
            "line 2: 'SECRET' is only used inside the removed states but defined outside: its definition is left in the file",
            "line 14: 'answers' is only used inside the removed cheat_answers but defined outside: its definition is left in the file",
        ]

    def test_used_by_an_instructor_call_and_a_removed_state(self):
        result = strip_source(dedent('''
            from SRE.lib_sre import instructor, sre_state, tr
            NOTE = "n"
            class N:
                def __init__(self):
                    self.informations = instructor(NOTE) + tr("public")
                @sre_state
                def final(self):
                    self.cmd("m", NOTE)
            ''').encode(), full=True)
        assert result.warnings == ["line 3: 'NOTE' is only used inside instructor() and the removed states but defined "
                                   "outside: its definition is left in the file"]

    def test_instructor_only_variable_keeps_the_hint(self):
        result = strip_source(b'note = tr("s")\nx = tr("p") + instructor(note)\nclass N:\n    @sre_state\n    def final(self): pass\n', full=True)
        assert len(result.warnings) == 1 and result.warnings[0].endswith("(wrap the text in instructor() where it is assigned to remove it)")


class TestFullRealFiles:
    @pytest.mark.parametrize('lab', sorted((ROOT / 'tests' / 'labs').glob('*.py'))
                             + sorted((ROOT / 'lab' / 'sre').glob('*.py')), ids=lambda p: p.name)
    def test_no_removable_state_is_left(self, lab):
        from strip_instructor import _Stripper, _local_names, _state_decorator, KEPT_STATES
        data = lab.read_bytes()
        result = strip_source(data, full=True)
        tree = ast.parse(result.data)
        assert not _Stripper(result.data, tree).states_to_remove([])
        left = {fn.name for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef) for fn in cls.body
                if isinstance(fn, ast.FunctionDef) and _state_decorator(fn, _local_names(tree, 'sre_state'))}
        assert not (left & set(result.states))
        assert not set(result.states) & set(KEPT_STATES)
        # the file without --full is the same as before, whatever the states
        assert strip_source(data).states == []


class TestFullCommandLine:
    def test_summary(self, tmp_path, capsys):
        path, output = tmp_path / 'lab.py', tmp_path / 'out.py'
        path.write_text(dedent(FULL_LAB))
        assert main(['--full', str(path), str(output)]) == 0
        captured = capsys.readouterr()
        assert captured.out == (f"{output}: 1 instructor() call(s) removed, 1 _TRANSLATIONS entry removed, "
                                "1 state(s) removed (final), 1 cheat_answers entry removed.\n")
        assert captured.err.count('warning:') == 3 and output.read_text() == dedent(FULL_LAB_STRIPPED)

    def test_nothing_to_remove(self, tmp_path, capsys):
        path = tmp_path / 'lab.py'
        path.write_text('class N:\n    @sre_state\n    def initial(self): pass\n')
        assert main(['--full', '-i', str(path)]) == 0
        assert capsys.readouterr().out == f"{path}: no instructor() call, no state to remove.\n"

    @pytest.mark.parametrize('arguments', [['-f'], ['-fi'], ['-i', '-f']])
    def test_no_short_option(self, tmp_path, capsys, arguments):
        path = tmp_path / 'lab.py'
        source = 'class N:\n    @sre_state\n    def final(self): pass\n'
        path.write_text(source)
        with pytest.raises(SystemExit) as error:
            main(arguments + [str(path)] + ([str(tmp_path / 'out.py')] if '-i' not in ''.join(arguments) else []))
        assert error.value.code == 2
        err = capsys.readouterr().err
        assert 'error: -f is not an option: use --full' in err and '[-f]' not in err
        assert path.read_text() == source and not (tmp_path / 'out.py').exists()

    def test_refused_file_writes_nothing(self, tmp_path, capsys):
        path = tmp_path / 'lab.py'
        source = 'class N:\n    @sre_state\n    def final(self): pass\n    def a(self): self.final()\n'
        path.write_text(source)
        assert main(['--full', str(path), str(tmp_path / 'out.py')]) == 1
        assert main(['--full', '-i', str(path)]) == 1
        assert "a() uses self.final while the state 'final' is removed" in capsys.readouterr().err
        assert not (tmp_path / 'out.py').exists() and path.read_text() == source

    def test_state_directory_of_a_directory_lab_is_reported(self, tmp_path, capsys):
        lab_dir = tmp_path / 'mylab'
        lab_dir.mkdir()
        (lab_dir / 'final').mkdir()
        (lab_dir / 'initial').mkdir()
        source = 'class N:\n    @sre_state\n    def final(self): pass\n'
        for name, reported in (('srelab.py', True), ('other.py', False)):
            (lab_dir / name).write_text(source)
            assert main(['--full', str(lab_dir / name), str(tmp_path / 'out.py')]) == 0
            err = capsys.readouterr().err
            assert (f"warning: the directory '{lab_dir / 'final'}' holds the files of the removed state 'final'" in err) is reported
            assert 'initial' not in err
