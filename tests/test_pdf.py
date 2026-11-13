"""Tests for SRE.pdf: Unicode fonts in generated PDFs and the core-font fallback."""
import os
import re

import pytest

from SRE import params
from SRE.pdf import SrePDF, _CELL_RE, _flatten_cell, markdown_to_html

needs_fonts = pytest.mark.skipif(
    not os.path.isfile(params.pdf_font_files['']) or not os.path.isfile(params.pdf_mono_font_files['']),
    reason='PDF fonts not installed (make fonts)')

MARKDOWN = """
    Mise en œuvre… a → b — l’adresse **gras œ** *ital œ* `code → ─` ⚠️

    ```
    mount <serveur>:/export /mnt   # ─ →
    ```

    | col | flèche → |
    |-----|----------|
    | œ   | `x`      |
    """


@pytest.fixture
def no_fonts(tmp_path, monkeypatch):
    """No TrueType font can be loaded: core Helvetica / Courier only."""
    monkeypatch.setattr(params, 'pdf_font_files', {'': str(tmp_path / 'missing.ttf')})
    monkeypatch.setattr(params, 'pdf_mono_font_files', {'': str(tmp_path / 'missing-mono.ttf')})


def _render(pdf: SrePDF) -> bytes:
    pdf.add_page()
    pdf.set_font(pdf.text_font, 'B', 16)
    pdf.cell(0, 10, 'Mise en œuvre → NFS ⚠️', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font(pdf.text_font, size=11)
    pdf.write_html(markdown_to_html(MARKDOWN), tag_styles=pdf.html_tag_styles())
    pdf.set_font(pdf.text_font, 'I', 10)
    pdf.multi_cell(0, 6, 'Quelle est l’adresse… 日本 ?')
    return bytes(pdf.output())


class TestMarkdownToHtml:
    def test_same_extensions_as_the_gui(self):
        html = markdown_to_html(MARKDOWN)
        assert '<pre><code>mount &lt;serveur&gt;:/export' in html
        assert '<table>' in html

    def test_instructor_fragments_are_left_out(self):
        from SRE.instructor_text import instructor, set_instructor_context
        set_instructor_context(True)
        assert markdown_to_html(instructor("**secret** ") + "public") == '<p>public</p>'

    def test_anchors_and_in_document_links_become_plain_text(self):
        """fpdf2 raises on an <a> without href and on a link to a named destination it does not
        know: the anchors and the links of a numbered course are stripped, the numbers stay."""
        from SRE.informations import resolve_informations
        course, _ = resolve_informations("**TOC**\n\n@@toc@@\n\n## @@sec:a@@ Title `code`\n\nsee @@ref:a@@ and "
                                         "[external](https://example.org/)")
        html = markdown_to_html(course)
        assert '<a id=' not in html and 'href="#' not in html
        assert '<h2>1. Title <code>code</code></h2>' in html
        assert '<li>1. Title <code>code</code></li>' in html
        assert '<p>see 1 and <a href="https://example.org/">external</a></p>' in html
        pdf = SrePDF()
        pdf.add_page()
        pdf.set_font(pdf.text_font, size=11)
        pdf.write_html(html, tag_styles=pdf.html_tag_styles())
        assert bytes(pdf.output()).startswith(b'%PDF')


TABLE = """
Outside: *italic*, **bold**, `code`, [link](https://example.org/doc).

| Whole | Mixed | Centre |
|-------|-------|:------:|
| **bold** | text with *italic*, **bold** and `code` | x |
| *italic* | `code` then text | **`both`** |
| `code` | a [link](https://example.org/doc), <https://example.org/> | one<br>two |
| plain | a &lt; b &amp; c | |
"""


class TestTableCells:
    """fpdf2 builds a table cell from one piece of text and raises NotImplementedError on a second
    one (`Unsupported nested HTML tags inside <td> element`): `sre export` failed on every course
    with an inline tag next to other text in a cell."""

    def test_a_cell_is_one_piece_of_text(self):
        html = markdown_to_html(TABLE)
        cells = re.findall(r'<t[dh]\b[^>]*>(.*?)</t[dh]>', html, flags=re.S)
        assert len(cells) == 15
        for cell in cells:
            assert re.fullmatch(r'[^<]*|<(b|i|code)>[^<]*</\1>', cell), cell

    def test_a_cell_that_is_one_element_keeps_its_style(self):
        html = markdown_to_html(TABLE)
        assert '<td><b>bold</b></td>' in html
        assert '<td><i>italic</i></td>' in html
        assert '<td><code>code</code></td>' in html

    def test_a_mixed_cell_becomes_its_text(self):
        html = markdown_to_html(TABLE)
        assert '<td>text with italic, bold and code</td>' in html
        assert '<td>code then text</td>' in html
        assert '<td style="text-align: center;">both</td>' in html
        assert '<td>a &lt; b &amp; c</td>' in html

    def test_links_and_line_breaks(self):
        html = markdown_to_html(TABLE)
        # the address follows the text, unless the text already shows it
        assert '<td>a link (https://example.org/doc), https://example.org/</td>' in html
        assert '<td style="text-align: center;">one\ntwo</td>' in html

    def test_the_rest_of_the_text_is_untouched(self):
        from SRE.instructor_text import markdown_to_html as gui_html
        paragraph = ('<p>Outside: <em>italic</em>, <strong>bold</strong>, <code>code</code>, '
                     '<a href="https://example.org/doc">link</a>.</p>')
        html = markdown_to_html(TABLE)
        assert paragraph in html and paragraph in gui_html(TABLE)
        assert '<th style="text-align: center;">Centre</th>' in html
        assert html.count('<tr>') == gui_html(TABLE).count('<tr>') == 5
        plain = "| a | b |\n|---|---|\n| 1 | 2 |"
        assert markdown_to_html(plain) == gui_html(plain)

    def test_an_image_in_a_cell_is_left_to_fpdf(self):
        html = '<table><tr><td>see <img src="x.png"> here</td></tr></table>'
        assert _CELL_RE.sub(_flatten_cell, html) == html

    @pytest.mark.parametrize('with_fonts', [True, False])
    def test_render(self, tmp_path, monkeypatch, with_fonts):
        """The texts and the whole-cell styles reach the cells fpdf2 draws."""
        import fpdf.table
        from fpdf.enums import TextEmphasis
        if not with_fonts:
            monkeypatch.setattr(params, 'pdf_font_files', {'': str(tmp_path / 'missing.ttf')})
            monkeypatch.setattr(params, 'pdf_mono_font_files', {'': str(tmp_path / 'missing-mono.ttf')})
        cells = {}
        original = fpdf.table.Row.cell

        def spy(self, *args, **kwargs):
            cells[kwargs['text']] = kwargs.get('style')
            return original(self, *args, **kwargs)
        monkeypatch.setattr(fpdf.table.Row, 'cell', spy)
        pdf = SrePDF()
        pdf.add_page()
        pdf.set_font(pdf.text_font, size=11)
        pdf.write_html(markdown_to_html(TABLE), tag_styles=pdf.html_tag_styles())
        assert bytes(pdf.output()).startswith(b'%PDF')
        assert list(cells) == ['Whole', 'Mixed', 'Centre',
                               'bold', 'text with italic, bold and code', 'x',
                               'italic', 'code then text', 'both',
                               'code', 'a link (https://example.org/doc), https://example.org/', 'one\ntwo',
                               'plain', 'a < b & c', '']
        assert cells['bold'].emphasis == TextEmphasis.B
        assert cells['italic'].emphasis == TextEmphasis.I
        assert cells['code'].family == pdf.mono_font
        assert cells['text with italic, bold and code'] is None and cells['code then text'] is None


@needs_fonts
class TestUnicodeFonts:
    def test_fonts_are_registered(self):
        pdf = SrePDF()
        assert pdf.text_font not in ('Helvetica', 'Courier')
        assert pdf.mono_font not in ('Helvetica', 'Courier')

    def test_text_is_kept(self):
        pdf = SrePDF()
        pdf.set_font(pdf.text_font, size=11)
        assert pdf.normalize_text('œuvre → … — ’ € ─') == 'œuvre → … — ’ € ─'

    def test_variation_selector_is_dropped(self):
        pdf = SrePDF()
        pdf.set_font(pdf.text_font, size=11)
        assert pdf.normalize_text('⚠️') == '⚠'

    def test_unknown_glyph_becomes_question_mark(self):
        pdf = SrePDF()
        pdf.set_font(pdf.text_font, size=11)
        assert pdf.normalize_text('a 日 b\n') == 'a ? b\n'

    def test_core_font_on_unicode_pdf_is_reduced_to_latin1(self):
        pdf = SrePDF()
        pdf.set_font('Helvetica', size=11)
        assert pdf.normalize_text('œ →') == 'oe ->'

    def test_render(self):
        assert _render(SrePDF()).startswith(b'%PDF')

    def test_regular_file_alone_serves_every_style(self, monkeypatch):
        monkeypatch.setattr(params, 'pdf_font_files', {'': params.pdf_font_files['']})
        monkeypatch.setattr(params, 'pdf_mono_font_files', {'': params.pdf_mono_font_files['']})
        pdf = SrePDF()
        assert pdf.text_font != 'Helvetica'
        assert _render(pdf).startswith(b'%PDF')

    def test_missing_mono_font_only(self, tmp_path, monkeypatch):
        monkeypatch.setattr(params, 'pdf_mono_font_files', {'': str(tmp_path / 'missing.ttf')})
        pdf = SrePDF()
        assert pdf.text_font != 'Helvetica'
        assert pdf.mono_font == 'Courier'
        assert _render(pdf).startswith(b'%PDF')


class TestCoreFontFallback:
    def test_core_fonts_are_used(self, no_fonts):
        pdf = SrePDF()
        assert (pdf.text_font, pdf.mono_font) == ('Helvetica', 'Courier')

    def test_text_is_reduced_to_latin1(self, no_fonts):
        pdf = SrePDF()
        pdf.set_font(pdf.text_font, size=11)
        assert pdf.normalize_text('Réseau : œuvre… a → b — l’été') == "Réseau : oeuvre... a -> b - l'été"
        assert pdf.normalize_text('Dvořák ⚠️ 日') == 'Dvorák /!\\ ?'

    def test_render(self, no_fonts):
        assert _render(SrePDF()).startswith(b'%PDF')
