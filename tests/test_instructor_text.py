"""Tests for SRE.instructor_text: the instructor() fragments of lab texts (kept in info.json only
for projects in instructor mode) and their rendering by markdown_to_html()."""
import textwrap

import markdown
import pytest

from SRE import params
from SRE.common import TranslatedText
from SRE.instructor_text import (has_instructor, instructor, instructor_context, markdown_to_html,
                                 rebalance_fragments, set_instructor_context, strip_instructor,
                                 unwrap_instructor)
from SRE.lib_sre import make_tr, no_tr

tr = make_tr('en')

BEGIN = params.instructor_begin_mark
ARGS_END = params.instructor_args_end_mark
END = params.instructor_end_mark
SPAN = (f'<span style="color:{params.instructor_text_color};'
        f'background-color:{params.instructor_background_color}">')


@pytest.fixture
def instructor_mode():
    set_instructor_context(True)


def reference_html(text: str) -> str:
    """The conversion of the GUI views before instructor() existed."""
    return markdown.markdown(textwrap.dedent(text).strip(), extensions=["fenced_code", "tables"])


class TestInstructorOutsideTheMode:
    def test_str_is_dropped(self):
        assert instructor("secret") == ''

    def test_translated_text_keeps_its_languages(self):
        result = instructor(tr("secret", fr="secret fr"))
        assert isinstance(result, TranslatedText)
        assert result == {'en': '', 'fr': ''}

    def test_neighbours_survive(self):
        """An empty TranslatedText() would swallow the plain strings added to it."""
        text = no_tr("**") + instructor(tr("secret")) + no_tr("**") + tr("public", fr="publique")
        assert text == {'en': '****public', 'fr': '****publique'}
        assert (instructor(tr("secret")) + tr("public")).resolve('en') == 'public'

    def test_invalid_colour_is_reported_in_every_mode(self):
        with pytest.raises(ValueError):
            instructor("x", color="red; font-size:99px")
        with pytest.raises(ValueError):
            instructor("x", background="#12")


class TestInstructorInTheMode:
    def test_str_is_marked(self, instructor_mode):
        assert instructor("secret") == f"{BEGIN};{ARGS_END}secret{END}"

    def test_colours_are_carried(self, instructor_mode):
        assert instructor("s", color="#00f", background="yellow") == f"{BEGIN}#00f;yellow{ARGS_END}s{END}"

    def test_every_language_is_marked(self, instructor_mode):
        result = instructor(tr("secret", fr="secret fr"))
        assert isinstance(result, TranslatedText)
        assert strip_instructor(result) == {'en': '', 'fr': ''}
        assert unwrap_instructor(result) == {'en': 'secret', 'fr': 'secret fr'}

    def test_concatenation_with_tr(self, instructor_mode):
        text = instructor(tr("note ", fr="note fr ")) + tr("public", fr="publique")
        assert unwrap_instructor(text) == {'en': 'note public', 'fr': 'note fr publique'}
        assert strip_instructor(text) == {'en': 'public', 'fr': 'publique'}

    def test_empty_text_gives_no_fragment(self, instructor_mode):
        assert instructor("") == ''

    def test_nested_calls_give_one_fragment(self, instructor_mode):
        nested = instructor(instructor("a") + "b", color="blue")
        assert nested == f"{BEGIN}blue;{ARGS_END}ab{END}"

    def test_context_is_per_thread(self, instructor_mode):
        import threading
        seen = []
        thread = threading.Thread(target=lambda: seen.append((instructor_context(), instructor("x"))))
        thread.start()
        thread.join()
        assert seen == [(False, '')]
        assert instructor_context() is True


class TestStripAndUnwrap:
    def test_text_without_mark_is_returned_as_is(self):
        text = "plain **text**"
        assert strip_instructor(text) is text and unwrap_instructor(text) is text
        assert not has_instructor(text)

    def test_strip_and_unwrap(self, instructor_mode):
        text = "a " + instructor("b") + " c " + instructor("d\ne")
        assert has_instructor(text)
        assert strip_instructor(text) == "a  c "
        assert unwrap_instructor(text) == "a b c d\ne"

    def test_unclosed_fragment_is_stripped_to_the_end(self, instructor_mode):
        text = "a " + instructor("b c")[:-1]
        assert strip_instructor(text) == "a "
        assert unwrap_instructor(text) == "a b c"

    def test_stray_marks_are_removed(self):
        assert strip_instructor(f"a{END}b{ARGS_END}c") == "abc"

    def test_non_text_values_are_untouched(self):
        assert strip_instructor(None) is None
        assert strip_instructor('') == ''

    def test_rebalance_fragments(self, instructor_mode):
        whole = "intro " + instructor("one FIELD two", color="blue") + " end"
        before, after = whole.split("FIELD")
        chunks = rebalance_fragments([before, after, "last"])
        assert chunks == [f"intro {BEGIN}blue;{ARGS_END}one {END}", f"{BEGIN}blue;{ARGS_END} two{END} end", "last"]
        assert [strip_instructor(chunk) for chunk in chunks] == ["intro ", " end", "last"]

    def test_rebalance_drops_empty_fragments(self, instructor_mode):
        whole = instructor("FIELD after")
        before, after = whole.split("FIELD")
        assert rebalance_fragments([before, after])[0] == ''


class TestMarkdownToHtml:
    def test_plain_text_is_converted_as_before(self):
        text = """
            # Title

            | a | b |
            |---|---|
            | 1 | 2 |

            ```
            code <x>
            ```
            """
        assert markdown_to_html(text) == reference_html(text)
        assert markdown_to_html(text, show_instructor=True) == reference_html(text)

    CASES = {
        'triple-quoted block then public text': lambda: instructor("""
            ## Solution
            - step **one**
            - step two

            ```
            ip a
            ```
            """) + """
            Public text
            second line
            """,
        'public text then block': lambda: """
            Public intro.
            """ + instructor("""
            Secret paragraph one.

            Secret paragraph two.
            """),
        'inline': lambda: "The password is " + instructor("hunter2") + " and that is it.\n\nNext paragraph",
        'inline at line start': lambda: instructor("Note:") + " public rest of the sentence",
        'list items': lambda: "- public a\n" + instructor("- secret b\n- secret c") + "\n- public d",
        'fenced code': lambda: instructor("```\ncode\n```") + "\npublic",
        'table': lambda: "| a | b |\n|---|---|\n| 1 | 2 |\n\n" + instructor("| c | d |\n|---|---|\n| 3 | 4 |"),
        'inside a list item': lambda: "- item " + instructor("(secret)") + "\n- other item\n",
        # the styles of the labs: public text at the margin, closing quotes indented
        'indented block before unindented text': lambda: instructor("""
            ### Notes
            - one
            - two
            """) + "## Title\n" + """
Public text at the margin.
            """,
        'unindented block after indented text': lambda: """
            Public text, indented.

            Second paragraph.
            """ + instructor("""
### Notes
- one
"""),
        'single line after indented closing quotes': lambda: """
Public text at the margin.

            """ + instructor("Note for the instructor."),
    }

    @pytest.mark.parametrize('name', sorted(CASES))
    def test_hidden_is_the_student_view(self, instructor_mode, name):
        """Button off: exactly what the text gives when instructor() returns ''."""
        text = self.CASES[name]()
        set_instructor_context(False)
        student_text = self.CASES[name]()
        assert not has_instructor(student_text)
        assert markdown_to_html(text) == reference_html(student_text)

    @pytest.mark.parametrize('name', sorted(CASES))
    def test_shown_has_no_mark_left(self, instructor_mode, name):
        html = markdown_to_html(self.CASES[name](), show_instructor=True)
        assert SPAN in html
        assert 'SREINSTRUCTOR' not in html and not has_instructor(html)
        assert '<p></p>' not in html

    def test_block_fragment_keeps_its_markdown(self, instructor_mode):
        html = markdown_to_html(self.CASES['triple-quoted block then public text'](), show_instructor=True)
        assert f'<h2>{SPAN}Solution</span></h2>' in html
        assert f'<li>{SPAN}step two</span></li>' in html
        assert f'<pre><code>{SPAN}ip a</span>\n</code></pre>' in html
        # the indented public text is still dedented: a paragraph, not a code block
        assert '<p>Public text\nsecond line</p>' in html

    def test_public_text_is_not_styled(self, instructor_mode):
        html = markdown_to_html(self.CASES['public text then block'](), show_instructor=True)
        assert '<p>Public intro.</p>' in html
        assert f'<p>{SPAN}Secret paragraph one.</span></p>' in html
        assert f'<p>{SPAN}Secret paragraph two.</span></p>' in html

    def test_inline_fragment(self, instructor_mode):
        html = markdown_to_html(self.CASES['inline'](), show_instructor=True)
        assert f'<p>The password is {SPAN}hunter2</span> and that is it.</p>' in html
        assert '<p>Next paragraph</p>' in html

    def test_inline_fragment_at_line_start(self, instructor_mode):
        html = markdown_to_html(self.CASES['inline at line start'](), show_instructor=True)
        assert html == f'<p>{SPAN}Note:</span> public rest of the sentence</p>'

    def test_list_items(self, instructor_mode):
        html = markdown_to_html(self.CASES['list items'](), show_instructor=True)
        assert html.count('<ul>') == 1 and html.count('<li>') == 4
        assert f'<li>{SPAN}secret b</span></li>' in html
        assert '<li>public d</li>' in html

    def test_fenced_code_closed_by_the_fragment_end(self, instructor_mode):
        html = markdown_to_html(self.CASES['fenced code'](), show_instructor=True)
        assert f'<pre><code>{SPAN}code</span>\n</code></pre>' in html
        assert 'public</p>' in html and '```' not in html

    def test_table_in_a_fragment(self, instructor_mode):
        html = markdown_to_html(self.CASES['table'](), show_instructor=True)
        assert html.count('<table>') == 2
        assert f'<td>{SPAN}3</span></td>' in html and '<td>1</td>' in html

    def test_fragment_inside_a_list_item_stays_in_it(self, instructor_mode):
        html = markdown_to_html(self.CASES['inside a list item'](), show_instructor=True)
        assert html.count('<ul>') == 1 and html.count('<li>') == 2
        assert f'<li>item {SPAN}(secret)</span>\n</li>' in html

    def test_fragment_is_dedented_on_its_own(self, instructor_mode):
        """An indented triple-quoted fragment next to public text written at the margin (the
        style of the labs) is neither a code block nor the cause of one."""
        html = markdown_to_html(self.CASES['indented block before unindented text'](), show_instructor=True)
        assert '<pre>' not in html
        assert f'<h3>{SPAN}Notes</span></h3>' in html
        assert f'<li>{SPAN}two</span>\n</li>' in html
        assert '<h2>Title</h2>' in html and '<p>Public text at the margin.</p>' in html

    def test_public_text_is_dedented_as_in_the_student_view(self, instructor_mode):
        html = markdown_to_html(self.CASES['unindented block after indented text'](), show_instructor=True)
        assert '<pre>' not in html
        assert '<p>Public text, indented.</p>' in html and '<p>Second paragraph.</p>' in html
        assert f'<h3>{SPAN}Notes</span></h3>' in html and f'<li>{SPAN}one</span></li>' in html

    def test_closing_quotes_indentation_does_not_shift_a_fragment(self, instructor_mode):
        html = markdown_to_html(self.CASES['single line after indented closing quotes'](), show_instructor=True)
        assert '<pre>' not in html
        assert html == f'<p>Public text at the margin.</p>\n<p>{SPAN}Note for the instructor.</span></p>'

    def test_colours_of_the_call(self, instructor_mode):
        text = instructor("a", color="#0000ff") + " " + instructor("b", background="yellow")
        html = markdown_to_html(text, show_instructor=True)
        assert f'<span style="color:#0000ff;background-color:{params.instructor_background_color}">a</span>' in html
        assert f'<span style="color:{params.instructor_text_color};background-color:yellow">b</span>' in html

    def test_default_colours_of_the_caller(self, instructor_mode):
        html = markdown_to_html(instructor("a"), show_instructor=True, color="green", background="#eee")
        assert html == '<p><span style="color:green;background-color:#eee">a</span></p>'

    def test_forged_colour_is_ignored(self):
        """info.json could be edited by hand: a colour never reaches the style attribute unchecked."""
        text = f'{BEGIN}red" onclick="x;{ARGS_END}a{END}'
        html = markdown_to_html(text, show_instructor=True)
        assert html == f'<p>{SPAN}a</span></p>'

    def test_unclosed_fragment_runs_to_the_end(self, instructor_mode):
        html = markdown_to_html("a " + instructor("b")[:-1] + "\n\nc", show_instructor=True)
        assert f'{SPAN}b</span>' in html and f'<p>{SPAN}c</span></p>' in html
