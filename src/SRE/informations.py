"""Numbered sections, cross-references and table of contents of ``self.informations``.

The sections of a course are numbered by hand otherwise (``## 7. Routes``), with a hand-written
table of contents and mentions such as ``(section 7)``: inserting a section means renumbering
all of that in every language.  A lab calls four functions, imported from ``SRE.lib_sre`` like
``tr()`` and ``instructor()``, which only emit plain-text *markers*; the numbers, the links and
the table of contents are computed when ``info.json`` is written (``Grade0.save_lab_info()``:
:func:`resolve_informations` on the course, then :func:`resolve_text` on the question texts with
the numbering of the course), so there is nothing else to call, and ``sre check`` validates the
markers and prints the numbered outline of the course (:func:`outline`).

Usage, in ``NetScheme.__init__``::

    from SRE.lib_sre import tr, no_tr, info_subtitle, info_tag, info_ref, info_toc

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
  final dot; the table of contents lists every level (``info_toc(depth=1)`` for the first one),
  as a nested markdown bullet list indented like the line of its marker;
- a marker inside a fenced code block is left as it is;
- do not number a header inside ``instructor()``: the numbers must be the same in and out of the
  instructor mode, so a ``@@sec@@``, ``@@tag@@`` or ``@@toc@@`` standing inside an instructor
  fragment is dropped (``@@ref@@`` is resolved there);
- a text that gets a ``@@ref@@`` through ``TranslatedText.format()`` must hold no literal brace;
  type the marker inside the ``tr()`` text instead;
- the languages of a ``tr()`` course must declare the same sections and tags in the same order
  (``sre check`` reports a translation that missed a header).

Errors are reported as :class:`ValueError` when the text is resolved (by ``sre check``, or by
``sre start`` like any lab bug): a ``@@sec@@`` outside a header line, a ``#`` header, a level
jump, a tag defined twice, an unknown tag, a numbered header without a title, a ``@@sec@@`` /
``@@tag@@`` / ``@@toc@@`` in a question text, and languages of one ``TranslatedText`` whose
sections or tags differ.  A question hash is computed from the marked title, so a renumbering
never changes it.

This module imports nothing from SRE but ``instructor_text``.
"""
import re

from .instructor_text import fragment_spans

TAG_RE = re.compile(r'[A-Za-z0-9_-]+')
MARKER_RE = re.compile(r'@@(?P<kind>sec|tag|ref|toc)(?::(?P<args>[^@\n]*))?@@')
# what stands before a @@sec@@ marker on its line: the hashes of a markdown header
_HEADER_RE = re.compile(r'[ \t]*(?P<hashes>#{1,6})[ \t]*')
_FENCE_RE = re.compile(r'^[ \t]*(?P<fence>`{3,}|~{3,})', re.MULTILINE)
AUTO_ANCHOR_PREFIX = 'sec.'  # id of an untagged section: 'sec.2.1' ('.' never occurs in a tag)


def check_tag(tag: str) -> str:
    """*tag* when it is a valid tag name, else :class:`ValueError`."""
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise ValueError(f"invalid tag {tag!r}: letters, digits, '_' and '-' only")
    return tag


class Target:
    """What a tag refers to: a section (*level* set) or a plain ``@@tag@@`` anchor (*level* None,
    *number* and *title* those of the section it stands in)."""

    __slots__ = ('number', 'title', 'anchor', 'level', 'tag')

    def __init__(self, number: str, title: str, anchor: str, level, tag):
        self.number = number
        self.title = title
        self.anchor = anchor
        self.level = level
        self.tag = tag

    @property
    def label(self) -> str:
        """``2.1. Title``: the entry of the table of contents, the reference with a title."""
        return f"{self.number}. {self.title}"

    def __repr__(self):
        return f"Target({self.number!r}, {self.title!r}, anchor={self.anchor!r}, level={self.level}, tag={self.tag!r})"


class Numbering:
    """The sections and the tags of a course, per language; the first language added is the
    default one, used for a language the course does not have and for plain strings."""

    def __init__(self):
        self._languages = {}  # lang -> (sections, targets)

    def add(self, lang, sections: list, targets: dict) -> None:
        self._languages[lang] = (sections, targets)

    @property
    def languages(self) -> list:
        return list(self._languages)

    def _entry(self, lang):
        if lang in self._languages:
            return self._languages[lang]
        if self._languages:
            return next(iter(self._languages.values()))
        return [], {}

    def sections(self, lang=None) -> list:
        """The numbered sections, in text order (:class:`Target` objects)."""
        return self._entry(lang)[0]

    def targets(self, lang=None) -> dict:
        """``tag -> Target`` of every tagged section and anchor."""
        return self._entry(lang)[1]

    def check_consistent(self) -> None:
        """Every language must declare the same sections (levels and tags) and anchors, in the
        same order, else :class:`ValueError` (a translation missed a header)."""
        reference = None
        for lang, (sections, targets) in self._languages.items():
            signature = _signature(sections, targets)
            if reference is None:
                reference = (lang, signature)
            elif signature != reference[1]:
                raise ValueError(
                    f"the numbered sections and tags of the languages {reference[0]!r} and {lang!r} "
                    f"differ: {_describe(reference[1])} / {_describe(signature)}")


def _signature(sections, targets):
    items = [('sec', s.level, s.tag) for s in sections]
    items += [('tag', None, t.tag) for t in targets.values() if t.level is None]
    return tuple(items)


def _describe(signature) -> str:
    return ', '.join(f"{kind}{':' + tag if tag else ''}{'(' + str(level) + ')' if level else ''}"
                     for kind, level, tag in signature) or 'none'


class _Marker:
    __slots__ = ('kind', 'args', 'start', 'end', 'text', 'in_fragment', 'replacement', 'depth', 'indent', 'alone')

    def __init__(self, match, in_fragment: bool):
        self.kind = match.group('kind')
        self.args = match.group('args')
        self.start, self.end = match.span()
        self.text = match.group()
        self.in_fragment = in_fragment
        self.replacement = None
        self.depth = None
        self.indent = ''
        self.alone = False  # nothing else on its line


def _code_spans(text: str) -> list:
    """``(start, end)`` of the fenced code blocks of *text* (an unclosed fence runs to the end)."""
    spans = []
    opened = None  # (fence string, start offset)
    for match in _FENCE_RE.finditer(text):
        fence = match.group('fence')
        if opened is None:
            opened = (fence, match.start())
        elif fence[0] == opened[0][0] and len(fence) >= len(opened[0]):
            spans.append((opened[1], match.end()))
            opened = None
    if opened is not None:
        spans.append((opened[1], len(text)))
    return spans


def _inside(position: int, spans: list) -> bool:
    return any(start <= position < end for start, end in spans)


def _markers(text: str) -> list:
    """The markers of *text* outside its fenced code blocks, in text order."""
    code = _code_spans(text)
    fragments = fragment_spans(text)
    return [_Marker(match, _inside(match.start(), fragments))
            for match in MARKER_RE.finditer(text) if not _inside(match.start(), code)]


def _line_bounds(text: str, position: int):
    start = text.rfind('\n', 0, position) + 1
    end = text.find('\n', position)
    return start, len(text) if end < 0 else end


def _skip_blanks(text: str, position: int) -> int:
    while position < len(text) and text[position] in ' \t':
        position += 1
    return position


def _parse_ref(marker: _Marker):
    """``(tag, with_title)`` of a @@ref@@ marker."""
    args = marker.args or ''
    tag, _, option = args.partition(':')
    if option not in ('', 'title'):
        raise ValueError(f"invalid marker {marker.text}: expected @@ref:tag@@ or @@ref:tag:title@@")
    return check_tag(tag), option == 'title'


def _number_course(text: str):
    """First pass over a course: its markers with the replacement of every @@sec@@ / @@tag@@ (the
    numbering), the sections in order and the ``tag -> Target`` map."""
    markers = _markers(text)
    sections = []
    targets = {}
    counters = []
    current = None  # the section an anchor stands in

    def register(tag, target):
        if tag in targets:
            raise ValueError(f"tag {tag!r} is defined twice")
        targets[tag] = target

    for marker in markers:
        line_start, line_end = _line_bounds(text, marker.start)
        marker.indent = text[line_start:_skip_blanks(text, line_start)]
        marker.alone = not (text[line_start:marker.start].strip() or text[marker.end:line_end].strip())
        if marker.kind == 'sec':
            after = _skip_blanks(text, marker.end)
            if marker.in_fragment:
                marker.start, marker.end, marker.replacement = marker.start, after, ''
                continue
            header = _HEADER_RE.fullmatch(text, line_start, marker.start)
            if header is None:
                raise ValueError(f"{marker.text} must open the text of a markdown header "
                                 f"('## {marker.text} Title'): {text[line_start:line_end].strip()!r}")
            level = len(header.group('hashes')) - 1
            title = text[after:line_end].strip()
            if level == 0:
                raise ValueError(f"a '#' header is the lab title and cannot be numbered: use '##' "
                                 f"for level 1 ({title!r})")
            if not title:
                raise ValueError(f"numbered header without a title: {text[line_start:line_end].strip()!r}")
            if level > len(counters) + 1:
                raise ValueError(f"section {title!r} is at level {level} but no level {level - 1} "
                                 f"section opened before it")
            counters = counters[:level - 1] + [(counters[level - 1] + 1) if level <= len(counters) else 1]
            number = '.'.join(str(n) for n in counters)
            tag = check_tag(marker.args) if marker.args is not None else None
            current = Target(number, title, tag or f"{AUTO_ANCHOR_PREFIX}{number}", level, tag)
            sections.append(current)
            if tag:
                register(tag, current)
            marker.end = after
            marker.replacement = f'<a id="{current.anchor}"></a>{number}. '
        elif marker.kind == 'tag':
            if marker.args is None:
                raise ValueError(f"invalid marker {marker.text}: expected @@tag:name@@")
            tag = check_tag(marker.args)
            if marker.in_fragment:
                marker.replacement = ''
                continue
            register(tag, Target(current.number if current else '', current.title if current else '',
                                 tag, None, tag))
            marker.replacement = f'<a id="{tag}"></a>'
        elif marker.kind == 'toc':
            if marker.args is not None and not marker.args.isdigit():
                raise ValueError(f"invalid marker {marker.text}: expected @@toc@@ or @@toc:depth@@")
            if marker.in_fragment:
                marker.replacement = ''
                continue
            marker.depth = int(marker.args) if marker.args is not None else None
            if marker.alone:
                marker.start = line_start  # the list lines carry the indentation themselves
        else:
            _parse_ref(marker)  # validated now, resolved by the second pass
    return markers, sections, targets


def _reference(marker: _Marker, targets: dict, links: bool) -> str:
    tag, with_title = _parse_ref(marker)
    target = targets.get(tag)
    if target is None:
        raise ValueError(f"unknown tag {tag!r} in {marker.text}")
    if not target.number:
        raise ValueError(f"{marker.text}: the anchor {tag!r} stands before the first numbered section")
    label = target.label if with_title else target.number
    return f"[{label}](#{target.anchor})" if links else label


def _toc(sections: list, depth, indent: str, alone: bool) -> str:
    """The nested bullet list of the sections of the first *depth* levels, every line indented
    like the line of the marker; a marker standing inside a paragraph gets a block of its own."""
    lines = [f"{indent}{'    ' * (s.level - 1)}- [{s.label}](#{s.anchor})"
             for s in sections if depth is None or s.level <= depth]
    if not lines:
        return ''
    body = '\n'.join(lines)
    return body if alone else f"\n\n{body}\n\n"


def _substitute(text: str, markers: list) -> str:
    pieces = []
    position = 0
    for marker in markers:
        pieces.append(text[position:marker.start])
        pieces.append(marker.replacement)
        position = marker.end
    pieces.append(text[position:])
    return ''.join(pieces)


def _resolve_course(text: str):
    markers, sections, targets = _number_course(text)
    for marker in markers:
        if marker.kind == 'ref':
            marker.replacement = _reference(marker, targets, links=True)
        elif marker.kind == 'toc' and marker.replacement is None:
            marker.replacement = _toc(sections, marker.depth, marker.indent, marker.alone)
    return _substitute(text, markers), sections, targets


def _resolve_refs(text: str, targets: dict, links: bool) -> str:
    markers = _markers(text)
    for marker in markers:
        if marker.kind != 'ref':
            raise ValueError(f"{marker.text} is only allowed in the informations text "
                             f"(a question text may hold @@ref@@ only)")
        marker.replacement = _reference(marker, targets, links)
    return _substitute(text, markers)


def resolve_informations(text):
    """``(resolved text, numbering)`` of a course: *text* is a ``str`` or a ``TranslatedText``
    (resolved language by language, which must agree on the sections)."""
    numbering = Numbering()
    if isinstance(text, dict):
        result = {}
        for lang, value in text.items():
            result[lang], sections, targets = _resolve_course(value)
            numbering.add(lang, sections, targets)
        numbering.check_consistent()
        return type(text)(result), numbering
    resolved, sections, targets = _resolve_course(text)
    numbering.add('', sections, targets)
    return resolved, numbering


def resolve_text(text, numbering: Numbering, links: bool = False):
    """*text* (``str`` or ``TranslatedText``: a question title or description, a state
    description) with its ``@@ref@@`` markers resolved against *numbering*; a reference is a link
    only with *links* (the browser showing the text must hold the anchors of the course)."""
    if isinstance(text, dict):
        return type(text)({lang: _resolve_refs(value, numbering.targets(lang), links)
                           for lang, value in text.items()})
    return _resolve_refs(text, numbering.targets(), links)


def has_markers(text) -> bool:
    """True when *text* (``str`` or dict of strings) holds a marker outside its code blocks."""
    if isinstance(text, dict):
        return any(has_markers(value) for value in text.values())
    return isinstance(text, str) and bool(_markers(text))


def outline(numbering: Numbering, lang=None) -> list:
    """One line per numbered section, indented by level, the tag between brackets: what
    ``sre check`` prints."""
    return [f"{'    ' * (s.level - 1)}{s.number}. {s.title}{f'  [{s.tag}]' if s.tag else ''}"
            for s in numbering.sections(lang)]


# ── the functions a lab calls (re-exported by SRE.lib_sre) ─────────────────────────────────

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
