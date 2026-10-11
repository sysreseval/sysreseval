"""Tests for SRE.informations (the engine numbering the sections of a course, resolving the
references and building the table of contents) and lib/informations.py (the functions a lab
calls, which only emit the markers)."""
import textwrap

import pytest

from SRE.common import TranslatedText
from SRE.informations import (Numbering, has_markers, outline, resolve_informations, resolve_text)
from SRE.instructor_text import instructor, set_instructor_context
from SRE.lib_sre import make_tr, no_tr
from informations import info_ref, info_subtitle, info_tag, info_toc

tr = make_tr('fr')

COURSE = textwrap.dedent("""
    ## Lab title

    **Sommaire**

    @@toc@@

    ## @@sec:why@@ Why

    See section @@ref:transport@@ and @@ref:lease:title@@. @@tag:ports@@ Ports 67 and 68.

    ## @@sec:dora@@ Dora

    ### @@sec:transport@@ Transport

    ```
    ## @@sec@@ a code sample, not a section @@ref:nowhere@@
    ```

    ### @@sec@@ Other messages

    ## @@sec:lease@@ Lease
    """)


def resolve(text):
    return resolve_informations(text)[0]


class TestNumbering:
    def test_headers_are_numbered_with_anchors(self):
        text = resolve(COURSE)
        assert '## <a id="why"></a>1. Why' in text
        assert '## <a id="dora"></a>2. Dora' in text
        assert '### <a id="transport"></a>2.1. Transport' in text
        assert '### <a id="sec.2.2"></a>2.2. Other messages' in text
        assert '## <a id="lease"></a>3. Lease' in text
        assert '## Lab title' in text  # no marker: not numbered

    def test_no_marker_is_left(self):
        assert not has_markers(resolve(COURSE).replace('```\n## @@sec@@ a code sample, not a section @@ref:nowhere@@\n```', ''))

    def test_sub_counters_reset(self):
        text = resolve("## @@sec@@ A\n### @@sec@@ A1\n### @@sec@@ A2\n## @@sec@@ B\n### @@sec@@ B1\n")
        assert '1.1. A1' in text and '1.2. A2' in text and '2. B' in text and '2.1. B1' in text

    def test_three_levels(self):
        text = resolve("## @@sec@@ A\n### @@sec@@ B\n#### @@sec@@ C\n")
        assert '#### <a id="sec.1.1.1"></a>1.1.1. C' in text

    def test_fenced_code_is_left_alone(self):
        text = resolve(COURSE)
        assert '## @@sec@@ a code sample, not a section @@ref:nowhere@@' in text

    def test_header_hashes_without_space(self):
        assert resolve("##@@sec@@Title") == '##<a id="sec.1"></a>1. Title'

    def test_outline(self):
        _, numbering = resolve_informations(COURSE)
        assert outline(numbering) == ['1. Why  [why]', '2. Dora  [dora]', '    2.1. Transport  [transport]',
                                      '    2.2. Other messages', '3. Lease  [lease]']
        assert [s.number for s in numbering.sections()] == ['1', '2', '2.1', '2.2', '3']
        assert set(numbering.targets()) == {'why', 'dora', 'transport', 'lease', 'ports'}


class TestNumberingErrors:
    @pytest.mark.parametrize('text, message', [
        ("text @@sec@@ Title", "must open the text of a markdown header"),
        ("# @@sec@@ Title", "lab title"),
        ("## @@sec@@", "without a title"),
        ("## @@sec@@ A\n#### @@sec@@ C", "level 3 but no level 2"),
        ("### @@sec@@ C", "level 2 but no level 1"),
        ("## @@sec:x@@ A\n## @@sec:x@@ B", "defined twice"),
        ("## @@sec:x@@ A\n@@tag:x@@", "defined twice"),
        ("## @@sec:a b@@ A", "invalid tag"),
        ("@@tag@@", "expected @@tag:name@@"),
        ("@@toc:x@@", "expected @@toc@@ or @@toc:depth@@"),
        ("@@ref:x:y@@", "expected @@ref:tag@@"),
        ("see @@ref:nowhere@@", "unknown tag 'nowhere'"),
        ("@@tag:early@@\n## @@sec@@ A\n\n@@ref:early@@", "before the first numbered section"),
    ])
    def test_reported_as_value_error(self, text, message):
        with pytest.raises(ValueError, match=message):
            resolve_informations(text)


class TestReferencesAndAnchors:
    def test_reference_is_a_link_in_the_course(self):
        text = resolve(COURSE)
        assert 'See section [2.1](#transport) and [3. Lease](#lease).' in text

    def test_forward_reference(self):
        assert resolve("see @@ref:late@@\n\n## @@sec:late@@ Late") .startswith('see [1](#late)')

    def test_tag_anchor_takes_the_number_of_its_section(self):
        text = resolve(COURSE)
        assert '<a id="ports"></a> Ports 67 and 68.' in text
        _, numbering = resolve_informations(COURSE)
        assert numbering.targets()['ports'].number == '1'
        assert resolve_text("@@ref:ports@@ / @@ref:ports:title@@", numbering) == '1 / 1. Why'

    def test_question_text_gets_bare_numbers(self):
        _, numbering = resolve_informations(COURSE)
        assert resolve_text("section @@ref:transport@@ (@@ref:dora:title@@)", numbering) == 'section 2.1 (2. Dora)'
        assert resolve_text("section @@ref:transport@@", numbering, links=True) == 'section [2.1](#transport)'

    def test_question_text_refuses_sections(self):
        _, numbering = resolve_informations(COURSE)
        for marker in ('## @@sec@@ T', '@@tag:t@@', '@@toc@@'):
            with pytest.raises(ValueError, match='only allowed in the informations'):
                resolve_text(marker, numbering)

    def test_question_text_unknown_tag(self):
        _, numbering = resolve_informations(COURSE)
        with pytest.raises(ValueError, match="unknown tag 'x'"):
            resolve_text("@@ref:x@@", numbering)

    def test_text_without_marker_is_unchanged(self):
        assert resolve_text("plain {braces} @@{field:[0-9]+}@@", Numbering()) == "plain {braces} @@{field:[0-9]+}@@"
        assert resolve("plain") == "plain"


class TestTableOfContents:
    def test_nested_list_of_links(self):
        text = resolve(COURSE)
        assert ("- [1. Why](#why)\n"
                "- [2. Dora](#dora)\n"
                "    - [2.1. Transport](#transport)\n"
                "    - [2.2. Other messages](#sec.2.2)\n"
                "- [3. Lease](#lease)\n") in text

    def test_depth(self):
        text = resolve(COURSE.replace('@@toc@@', '@@toc:1@@'))
        assert "- [1. Why](#why)\n- [2. Dora](#dora)\n- [3. Lease](#lease)\n" in text
        assert '2.1. Transport](#' not in text.split('## <a id="why">')[0]

    def test_marker_alone_on_its_line_keeps_the_blank_lines_around(self):
        text = resolve("**Sommaire**\n\n@@toc@@\n\n## @@sec@@ A\n")
        assert text == '**Sommaire**\n\n- [1. A](#sec.1)\n\n## <a id="sec.1"></a>1. A\n'

    def test_marker_inside_a_paragraph_gets_a_block(self):
        text = resolve("Sommaire : @@toc@@ fin\n\n## @@sec@@ A\n")
        assert text.startswith('Sommaire : \n\n- [1. A](#sec.1)\n\n fin')

    def test_indentation_of_the_marker_line(self):
        """An indented triple-quoted course: the list keeps the common margin dedent() removes."""
        text = resolve("    **Sommaire**\n\n    @@toc@@\n\n    ## @@sec@@ A\n    ### @@sec@@ B\n")
        assert "    - [1. A](#sec.1)\n        - [1.1. B](#sec.1.1)\n" in text
        assert textwrap.dedent(text).startswith('**Sommaire**\n\n- [1. A]')

    def test_no_section_no_list(self):
        assert resolve("a\n\n@@toc@@\n\nb") == "a\n\n\n\nb"


class TestTranslatedText:
    def test_every_language_is_numbered(self):
        text = (no_tr("## ") + tr("TP", en="Lab") + no_tr("\n")
                + info_toc() + info_subtitle(tr("Pourquoi", en="Why"), tag="why")
                + tr("voir @@ref:why:title@@", en="see @@ref:why:title@@"))
        resolved, numbering = resolve_informations(text)
        assert isinstance(resolved, TranslatedText)
        assert '## <a id="why"></a>1. Pourquoi' in resolved['fr'] and 'voir [1. Pourquoi](#why)' in resolved['fr']
        assert '## <a id="why"></a>1. Why' in resolved['en'] and 'see [1. Why](#why)' in resolved['en']
        assert numbering.languages == ['fr', 'en']
        assert numbering.targets('en')['why'].title == 'Why'
        assert numbering.targets('de')['why'].title == 'Pourquoi'  # unknown language: the default one

    def test_question_resolved_per_language(self):
        _, numbering = resolve_informations(info_subtitle(tr("Pourquoi", en="Why"), tag="why"))
        question = resolve_text(tr("section @@ref:why:title@@", en="section @@ref:why:title@@"), numbering)
        assert question == {'fr': 'section 1. Pourquoi', 'en': 'section 1. Why'}

    def test_missing_translation_falls_back_with_the_same_numbers(self):
        """A block without an English text takes the French one (TranslatedText.__add__)."""
        text = info_subtitle(tr("A", en="A")) + tr("## @@sec:b@@ B") + tr("x @@ref:b@@", en="y @@ref:b@@")
        resolved, _ = resolve_informations(text)
        assert '2. B' in resolved['fr'] and '2. B' in resolved['en']
        assert resolved['en'].endswith('y [2](#b)')

    def test_languages_out_of_step(self):
        text = TranslatedText({'fr': "## @@sec:a@@ A\n## @@sec:b@@ B", 'en': "## @@sec:a@@ A\n## B"})
        with pytest.raises(ValueError, match="languages 'fr' and 'en' differ"):
            resolve_informations(text)

    def test_empty_text(self):
        resolved, numbering = resolve_informations(TranslatedText())
        assert resolved == {} and numbering.sections() == [] and numbering.targets() == {}


class TestInstructorFragments:
    @pytest.fixture(autouse=True)
    def instructor_mode(self):
        set_instructor_context(True)
        yield
        set_instructor_context(False)

    def test_markers_inside_a_fragment_are_dropped(self):
        public = "## @@sec:a@@ A\n\n@@toc@@\n"
        secret = instructor("\n### @@sec:sol@@ Solution @@tag:spot@@\n\nsee @@ref:a@@\n\n@@toc@@\n")
        resolved, numbering = resolve_informations(public + secret)
        assert '### Solution ' in resolved and '1.1' not in resolved
        assert 'see [1](#a)' in resolved  # a reference is resolved inside the fragment
        assert [s.number for s in numbering.sections()] == ['1']
        assert set(numbering.targets()) == {'a'}
        # the student's numbering (no fragment at all) is the same
        set_instructor_context(False)
        assert outline(resolve_informations(public + instructor("### @@sec@@ Solution"))[1]) == outline(numbering)

    def test_has_markers(self):
        assert has_markers("x @@ref:a@@") and has_markers({'en': '@@toc@@'})
        assert not has_markers("```\n@@toc@@\n```") and not has_markers({'en': 'plain'}) and not has_markers(3)


class TestLibFunctions:
    def test_info_subtitle(self):
        assert info_subtitle("Title") == "\n\n## @@sec@@ Title\n\n"
        assert info_subtitle("Title", level=2, tag="x") == "\n\n### @@sec:x@@ Title\n\n"
        assert info_subtitle(tr("Titre", en="Title"), tag="t") == {'fr': "\n\n## @@sec:t@@ Titre\n\n",
                                                                   'en': "\n\n## @@sec:t@@ Title\n\n"}
        for level in (0, 6, '1', True):
            with pytest.raises(ValueError):
                info_subtitle("T", level=level)
        with pytest.raises(ValueError, match='invalid tag'):
            info_subtitle("T", tag="a.b")

    def test_info_tag_ref_toc(self):
        assert info_tag("x") == "@@tag:x@@"
        assert info_ref("x") == "@@ref:x@@" and info_ref("x", title=True) == "@@ref:x:title@@"
        assert info_toc() == "\n\n@@toc@@\n\n" and info_toc(depth=2) == "\n\n@@toc:2@@\n\n"
        for bad in (0, '1', True):
            with pytest.raises(ValueError):
                info_toc(depth=bad)
        with pytest.raises(ValueError):
            info_ref("")

    def test_composition_with_tr_texts(self):
        text = tr("Voir ", en="See ") + info_ref("x") + tr(".", en=".")
        assert text == {'fr': 'Voir @@ref:x@@.', 'en': 'See @@ref:x@@.'}
