"""Numbered sections, cross-references and table of contents of ``self.informations``.

The sections of a course are numbered by hand today (``## 7. Routes``), with a hand-written
table of contents and mentions such as ``(section 7)``: inserting a section means renumbering
all of that in every language.  This module gives the writer four functions that emit *markers*;
the numbers, the links and the table of contents are computed when ``info.json`` is written
(``Grade0.save_lab_info()``), so there is nothing else to call, and ``sre check`` validates the
markers and prints the numbered outline of the course.

Usage, in ``NetScheme.__init__``::

    from informations import info_subtitle, info_tag, info_ref, info_toc

    self.informations = (
        no_tr("## ") + title + no_tr("\\n")
        + tr("**Sommaire**\\n") + info_toc()
        + info_subtitle(tr("À quoi sert DHCP"), tag="why")
        + tr(\"\"\"
    Pour communiquer ... (voir la section @@ref:lease@@).

    ### @@sec@@ Transport et adresses

    Le client ... @@tag:ports@@ les ports 67 et 68 ...
    \"\"\")
        + info_subtitle(tr("La vie d'un bail"), tag="lease")
        + tr(\"\"\"...\"\"\")
    )

and in ``Grade.grade()``::

    description=tr("Configurez le relais (section @@ref:relay@@ des Informations) ...")

The functions return plain strings (a ``tr()`` title keeps its languages), to be added with ``+``
like any text.  The markers they return may also be typed by hand inside a ``tr()`` block, which
is the natural way for a sub-section or a reference in the middle of a long text:

======================================  ====================================  ==========================================
function                                marker                                resolved form in the course
======================================  ====================================  ==========================================
``info_subtitle(title, level=1, tag)``  ``## @@sec@@ Title``                  ``## <a id="sec.2"></a>2. Title``
                                        ``### @@sec:tag@@ Title``             ``### <a id="tag"></a>2.1. Title``
``info_tag(tag)``                       ``@@tag:tag@@``                       ``<a id="tag"></a>`` (number: its section)
``info_ref(tag)``                       ``@@ref:tag@@``                       ``[2.1](#tag)``
``info_ref(tag, title=True)``           ``@@ref:tag:title@@``                 ``[2.1. Title](#tag)``
``info_toc(depth=None)``                ``@@toc@@`` / ``@@toc:depth@@``       nested bullet list of ``[2.1. Title](#tag)``
======================================  ====================================  ==========================================

Rules:

- the level of a typed header is its number of ``#`` minus one (``##``: level 1); a ``#`` header
  is the lab title and is never numbered; a header without a marker is not numbered either;
- a tag is made of letters, digits, ``_`` and ``-`` (English, like the identifiers of the lab);
  it must be unique, and a level cannot be skipped (no ``####`` right after a ``##``);
- in a question text only ``@@ref@@`` is allowed, and it gives the bare number (``2.1``): the
  browser of a question has no anchor to scroll to;
- the headers are numbered ``1.``, ``2.1.``, ``2.1.3.``; a reference is the number without the
  final dot; the table of contents lists every level (``info_toc(depth=1)`` for the first one);
- a marker inside a fenced code block is left as it is;
- do not number a header inside ``instructor()``: the numbers must be the same in and out of the
  instructor mode, so a ``@@sec@@``, ``@@tag@@`` or ``@@toc@@`` standing inside an instructor
  fragment is dropped (``@@ref@@`` is resolved there);
- a text that gets a ``@@ref@@`` through ``TranslatedText.format()`` must hold no literal brace;
  type the marker inside the ``tr()`` text instead;
- the languages of a ``tr()`` course must declare the same sections and tags in the same order
  (``sre check`` reports a translation that missed a header).

Errors (bad tag, unknown tag, level jump, ``@@sec@@`` outside a header...) are :class:`ValueError`
raised when the text is resolved, reported by ``sre check``.  :func:`resolve_informations` and
:func:`resolve_text` (the engine, ``SRE.informations``) are re-exported for a lab that needs the
resolved text itself, for instance to write the course into a machine.
"""
from SRE.informations import check_tag, resolve_informations, resolve_text  # noqa: F401 (re-exported)

__all__ = ['info_subtitle', 'info_tag', 'info_ref', 'info_toc', 'resolve_informations', 'resolve_text']

_MAX_LEVEL = 5  # '######' is the deepest markdown header


def info_subtitle(title, level: int = 1, tag: str = ""):
    """A numbered header of *level* (1: ``##``, 2: ``###``...) with *title* (a ``str`` or a
    ``tr()`` text), standing in a paragraph of its own; *tag* names the section for
    :func:`info_ref`."""
    if not isinstance(level, int) or isinstance(level, bool) or not 1 <= level <= _MAX_LEVEL:
        raise ValueError(f"info_subtitle(): level must be an integer from 1 to {_MAX_LEVEL}, not {level!r}")
    marker = f"@@sec:{check_tag(tag)}@@" if tag else "@@sec@@"
    return "\n\n" + "#" * (level + 1) + " " + marker + " " + title + "\n\n"


def info_tag(tag: str) -> str:
    """An anchor at this spot, named *tag*: a reference to it gives the number of the section it
    stands in and scrolls the course to the spot."""
    return f"@@tag:{check_tag(tag)}@@"


def info_ref(tag: str, title: bool = False) -> str:
    """The number of the section tagged *tag* (``2.1``), followed by its title with *title*
    (``2.1. Title``); a link to the section in the course."""
    return f"@@ref:{check_tag(tag)}:title@@" if title else f"@@ref:{check_tag(tag)}@@"


def info_toc(depth=None) -> str:
    """The table of contents of the course, in a paragraph of its own: every numbered section, or
    the sections of the first *depth* levels."""
    if depth is None:
        return "\n\n@@toc@@\n\n"
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1:
        raise ValueError(f"info_toc(): depth must be a positive integer, not {depth!r}")
    return f"\n\n@@toc:{depth}@@\n\n"
