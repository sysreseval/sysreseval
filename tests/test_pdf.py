"""Tests for SRE.pdf: Unicode fonts in generated PDFs and the core-font fallback."""
import os

import pytest

from SRE import params
from SRE.pdf import SrePDF, markdown_to_html

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
