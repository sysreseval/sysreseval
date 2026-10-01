"""PDF generation shared by ``sre export`` and ``sre outline``.

The core fonts of fpdf (Helvetica, Courier) only accept Latin-1 text and raise on anything else.
`SrePDF` embeds the TrueType fonts of ``params.pdf_font_files`` / ``params.pdf_mono_font_files``
when they are installed (``make fonts``) and never raises on a character a font cannot draw.
"""
import os
import textwrap
import unicodedata

import markdown as _md
from fpdf import FPDF

from . import params

_FONT_STYLES = ('', 'B', 'I', 'BI')
_TEXT_FAMILY = 'srepdf'
_MONO_FAMILY = 'srepdfmono'

# Variation selectors and zero-width characters: no glyph of their own.
_INVISIBLE = dict.fromkeys([0xFE0E, 0xFE0F, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF])

# ASCII rendering of the usual non-Latin-1 characters, for the core fonts.
_LATIN1_FALLBACK = str.maketrans({
    'œ': 'oe', 'Œ': 'OE', '…': '...', '—': '-', '–': '-', '−': '-', '‑': '-',
    '‘': "'", '’': "'", '‚': "'", '“': '"', '”': '"', '„': '"',
    '→': '->', '←': '<-', '↔': '<->', '⇒': '=>', '⇐': '<=', '⇔': '<=>',
    '≤': '<=', '≥': '>=', '≠': '!=', '≡': '==', '•': '*', '◦': 'o', '€': 'EUR',
    '✓': 'v', '✔': 'v', '✗': 'x', '✘': 'x', '⚠': '/!\\',
    ' ': ' ', ' ': ' ',
    '─': '-', '━': '-', '│': '|', '┃': '|',
    '┌': '+', '┐': '+', '└': '+', '┘': '+', '├': '+', '┤': '+', '┬': '+', '┴': '+', '┼': '+',
})


def _latin1(text: str) -> str:
    """Reduce *text* to Latin-1: known symbols get an ASCII form, accented letters lose the
    accents Latin-1 does not have, anything else becomes '?'."""
    out = []
    for char in text.translate(_LATIN1_FALLBACK):
        if ord(char) < 256:
            out.append(char)
        else:
            base = unicodedata.normalize('NFKD', char).encode('latin-1', errors='ignore').decode('latin-1')
            out.append(base or '?')
    return ''.join(out)


def markdown_to_html(text: str) -> str:
    """Convert lab markdown to HTML the way the GUI views do."""
    return _md.markdown(textwrap.dedent(text).strip(), extensions=["fenced_code", "tables"])


class SrePDF(FPDF):
    """FPDF with Unicode fonts. Use ``text_font`` / ``mono_font`` as the family of ``set_font()``:
    they name the embedded TrueType fonts, or Helvetica / Courier when these are not installed."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._glyphs: set[int] = set()
        self.text_font = self._register_family(_TEXT_FAMILY, params.pdf_font_files) or 'Helvetica'
        self.mono_font = self._register_family(_MONO_FAMILY, params.pdf_mono_font_files) or 'Courier'
        unicode_families = [f for f in (self.text_font, self.mono_font) if f in (_TEXT_FAMILY, _MONO_FAMILY)]
        if unicode_families:
            # A character missing from one family is drawn with the other one.
            self.set_fallback_fonts(unicode_families, exact_match=False)

    def _register_family(self, family: str, files: dict) -> str | None:
        """Register the four styles of *family*; return None when its regular file cannot be loaded."""
        regular = files.get('')
        try:
            for style in _FONT_STYLES:
                fname = files.get(style)
                if not fname or not os.path.isfile(fname):
                    fname = regular
                self.add_font(family, style, fname)
            self._glyphs.update(self.fonts[family].cmap)
        except Exception:
            return None
        return family

    def normalize_text(self, text: str) -> str:
        # Called by fpdf for every piece of text, with the font that will draw it already set.
        text = text.translate(_INVISIBLE)
        if self.is_ttf_font:
            text = ''.join(c if ord(c) in self._glyphs or c.isspace() else '?' for c in text)
        else:
            text = _latin1(text)
        return super().normalize_text(text)

    def html_tag_styles(self) -> dict:
        """``tag_styles`` for ``write_html()``: code and preformatted blocks in ``mono_font``
        (the default is the core Courier font)."""
        from fpdf.fonts import FontFace, TextStyle
        return {
            "code": FontFace(family=self.mono_font),
            "pre": TextStyle(font_family=self.mono_font, t_margin=4 + 7 / 30),
        }
