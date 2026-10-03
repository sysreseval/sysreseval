"""Instructor-only fragments of lab texts (instructor mode).

A lab wraps the notes meant for the instructor in :func:`instructor`, usually around a ``tr()``
string of ``self.informations`` or of a question::

    self.informations = instructor(tr("Solution: ...")) + tr("Public text")

Outside the instructor mode (``sre start --instructor-mode``, ``sre set-instructor-mode``) the
function returns an empty text, so nothing of it reaches ``info.json``, which students can read.
In instructor mode the text is kept between private-use marks::

    <begin><color>;<background><args end><content><end>      (``params.instructor_*_mark``)

The marks live inside the string values because the ``TranslatedText`` operators and the JSON
serialisation only keep plain strings.  The GUI then either removes the fragments (button off:
the student's view) or draws them in colour (:func:`markdown_to_html`).

The mode of the project being handled is a thread-local flag (``sre eval-all`` evaluates several
projects in one process, one thread each), set by ``NetScheme0.__init__`` and ``Grade0``.

This module imports nothing from SRE but ``params``: ``common``, ``utils``, ``lib_sre``, ``pdf``
and the GUI views all use it.
"""
import re
import textwrap
import threading

from . import params

_BEGIN = params.instructor_begin_mark
_ARGS_END = params.instructor_args_end_mark
_END = params.instructor_end_mark
_MARKS = _BEGIN + _ARGS_END + _END

# the opening mark of a fragment (group 1: "<color>;<background>") or its closing mark
_MARK_RE = re.compile(f"{_BEGIN}([^{_MARKS}\n]*){_ARGS_END}|{_END}")
# a whole fragment; an unclosed one runs to the end of the text
_FRAGMENT_RE = re.compile(f"{_BEGIN}[^{_MARKS}\n]*{_ARGS_END}.*?(?:{_END}|\\Z)", re.DOTALL)
_EMPTY_FRAGMENT_RE = re.compile(f"{_BEGIN}[^{_MARKS}\n]*{_ARGS_END}(\\s*){_END}")
_STRAY_MARK_RE = re.compile(f"[{_MARKS}]")
_COLOR_RE = re.compile(r"#[0-9a-fA-F]{3,8}|[a-zA-Z]+")

_MARKDOWN_EXTENSIONS = ["fenced_code", "tables"]
# what the marks become while markdown runs: plain words it leaves alone
_TOKEN_RE = re.compile(r"SREINSTRUCTOR(B|E)(\d+)X")
_HTML_TAG_RE = re.compile(r"(<[^>]+>)")
_EMPTY_PARAGRAPH_RE = re.compile(r"<p>\s*</p>\n?")

_context = threading.local()


def set_instructor_context(active: bool) -> None:
    """Tell :func:`instructor` whether the project handled by this thread is in instructor mode."""
    _context.active = bool(active)


def instructor_context() -> bool:
    return getattr(_context, 'active', False)


def _check_color(value, name: str) -> str:
    if value is None:
        return ''
    if not isinstance(value, str) or not _COLOR_RE.fullmatch(value):
        raise ValueError(f"instructor(): invalid {name} {value!r} (expected '#rrggbb' or a colour name)")
    return value


def instructor(text, color: str | None = None, background: str | None = None):
    """Mark *text* (a ``str`` or a ``tr()`` text) as visible in instructor mode only.

    Outside the instructor mode the result is an empty text of the same kind, so the argument is
    ignored.  In instructor mode the GUI shows the text in ``params.instructor_text_color`` on
    ``params.instructor_background_color`` while its *Instructor mode* button is on; *color* and
    *background* (``'#rrggbb'`` or a colour name) override them for this text.

    Call it from ``NetScheme.__init__`` (after ``super().__init__()``) or from ``Grade.grade()``:
    the mode is not known when the lab module is imported.  It is meant for ``self.informations``
    and the titles and descriptions of the questions; a fragment holds inline text or whole
    markdown blocks, and no ``@@{...}@@`` form field.
    """
    args = f"{_check_color(color, 'color')};{_check_color(background, 'background')}"
    if isinstance(text, dict):
        return type(text)({lang: _wrap(value, args) for lang, value in text.items()})
    return _wrap(text, args)


def _wrap(text, args: str) -> str:
    if not instructor_context():
        return ''
    text = unwrap_instructor(str(text))  # a nested call gives one fragment
    if not text:
        return ''
    return f"{_BEGIN}{args}{_ARGS_END}{text}{_END}"


def has_instructor(text) -> bool:
    """True when *text* (``str`` or dict of strings) holds an instructor mark."""
    if isinstance(text, dict):
        return any(has_instructor(value) for value in text.values())
    return isinstance(text, str) and _STRAY_MARK_RE.search(text) is not None


def _map(text, convert):
    if isinstance(text, dict):
        return type(text)({lang: _map(value, convert) for lang, value in text.items()})
    if isinstance(text, str) and _STRAY_MARK_RE.search(text) is not None:
        return _STRAY_MARK_RE.sub('', convert(text))
    return text


def strip_instructor(text):
    """*text* (``str`` or dict of strings) without its instructor fragments: what a student sees."""
    return _map(text, lambda value: _FRAGMENT_RE.sub('', value))


def unwrap_instructor(text):
    """*text* (``str`` or dict of strings) without the marks, the instructor content kept."""
    return _map(text, lambda value: _MARK_RE.sub('', value))


def rebalance_fragments(chunks) -> list:
    """Make every chunk of a split text self-contained: a fragment still open at the end of a
    chunk is closed there and reopened, with the same colours, at the start of the next one."""
    result = []
    opened = None  # opening mark of the fragment left open by the previous chunk
    for chunk in chunks:
        if opened is not None:
            chunk = opened + chunk
        opened = None
        for mark in _MARK_RE.finditer(chunk):
            opened = None if mark.group() == _END else mark.group()
        if opened is not None:
            chunk += _END
        result.append(_EMPTY_FRAGMENT_RE.sub(r"\1", chunk))
    return result


def markdown_to_html(text: str, show_instructor: bool = False,
                     color: str | None = None, background: str | None = None) -> str:
    """Convert lab markdown to HTML (the one conversion of the GUI views and of the PDFs).

    The instructor fragments are removed unless *show_instructor*; they are then drawn in
    *color* on *background* (``params.instructor_*_color`` by default, or the colours given to
    :func:`instructor`)."""
    import markdown

    if not has_instructor(text):
        return markdown.markdown(textwrap.dedent(text).strip(), extensions=_MARKDOWN_EXTENSIONS)
    if not show_instructor:
        return markdown.markdown(textwrap.dedent(strip_instructor(text)).strip(),
                                 extensions=_MARKDOWN_EXTENSIONS)

    styles = []  # "<color>;<background>" of each fragment, in text order

    def token(mark):
        if mark.group() == _END:
            return "SREINSTRUCTORE0X"
        styles.append(mark.group(1))
        return f"SREINSTRUCTORB{len(styles) - 1}X"

    source = _MARK_RE.sub(token, '\n'.join(_hoist_marks(_dedent(text))))
    html = markdown.markdown(_STRAY_MARK_RE.sub('', source).strip(), extensions=_MARKDOWN_EXTENSIONS)
    return _style_fragments(html, styles,
                            _valid_color(color, params.instructor_text_color),
                            _valid_color(background, params.instructor_background_color))


def _valid_color(value, default: str) -> str:
    return value if isinstance(value, str) and _COLOR_RE.fullmatch(value) else default


def _common_margin(indentations: list) -> str:
    margin = indentations[0]
    for indentation in indentations[1:]:
        length = 0
        while length < min(len(margin), len(indentation)) and margin[length] == indentation[length]:
            length += 1
        margin = margin[:length]
    return margin


def _dedent(text: str) -> list:
    """Lines of *text* dedented for markdown.  The public text and every fragment are dedented on
    their own, each one the way ``textwrap.dedent()`` would dedent it alone: the public text is
    laid out as in the student's view, and a fragment written as an indented triple-quoted block
    does not depend on the indentation of the text around it (it would otherwise become a code
    block, or turn the public text into one).  A mark never counts as indentation, and the
    whitespace standing before a mark that opens a line is the end of the previous region: it is
    dropped.  The first visible line loses all its indentation, as ``strip()`` does."""
    parsed = []  # per line: (marks opening it, region of its first visible character, indentation, rest)
    region = None  # None: public text, n: the n-th fragment
    fragments = 0
    for line in text.split('\n'):
        position = 0
        indentation_start = 0
        leading = []
        while True:
            while position < len(line) and line[position] in ' \t':
                position += 1
            mark = _MARK_RE.match(line, position)
            if mark is None:
                break
            leading.append(mark.group())
            position = indentation_start = mark.end()
            if mark.group() == _END:
                region = None
            else:
                fragments += 1
                region = fragments
        parsed.append((leading, region, line[indentation_start:position], line[position:]))
        for mark in _MARK_RE.finditer(line, position):
            if mark.group() == _END:
                region = None
            else:
                fragments += 1
                region = fragments

    indentations = {}
    for _, line_region, indentation, rest in parsed:
        if rest:
            indentations.setdefault(line_region, []).append(indentation)
    margins = {line_region: _common_margin(values) for line_region, values in indentations.items()}

    result = []
    first = True
    for leading, line_region, indentation, rest in parsed:
        if not rest:
            result.append(''.join(leading))
        elif first:
            result.append(''.join(leading) + rest)
            first = False
        else:
            result.append(''.join(leading) + indentation[len(margins[line_region]):] + rest)
    return result


def _split_edge_marks(line: str):
    """``(leading marks, core, trailing marks)`` of a line with visible text: the marks standing
    before its first and after its last visible character are taken out of it."""
    spans = [mark.span() for mark in _MARK_RE.finditer(line)]
    leading = []
    position = 0
    first = 0
    while True:
        while position < len(line) and line[position] in ' \t':
            position += 1
        if first < len(spans) and spans[first][0] == position:
            leading.append(line[spans[first][0]:spans[first][1]])
            position = spans[first][1]
            first += 1
        else:
            break
    start = position
    trailing = []
    end = len(line)
    last = len(spans) - 1
    while True:
        stop = end
        while stop > start and line[stop - 1] in ' \t':
            stop -= 1
        if last >= first and spans[last][1] == stop:
            trailing.insert(0, line[spans[last][0]:spans[last][1]])
            end = spans[last][0]
            last -= 1
        else:
            break
    core = line[start:end]
    return leading, core.rstrip(' \t') if trailing else core, trailing


def _indentation(line: str) -> str:
    return line[:len(line) - len(line.lstrip(' \t'))]


def _hoist_marks(lines: list) -> list:
    """Move the marks standing at the edges of a line, or alone on a line, to lines of their own
    so that the markdown block of that line (header, list item, code fence, table row...) is
    still recognised.  A mark next to a blank line becomes a paragraph of its own, which
    :func:`_style_fragments` removes; a mark inside a line stays where it is."""
    visible = [_MARK_RE.sub('', line) for line in lines]
    blank = [not line.strip() for line in visible]
    filled = [i for i in range(len(lines)) if not blank[i]]
    result = []
    for i, line in enumerate(lines):
        if blank[i]:
            marks = [mark.group() for mark in _MARK_RE.finditer(line)]
            result.append('')
            if marks:
                # indentation of the block it sits next to (the following one when there is one)
                neighbour = next((j for j in filled if j > i), filled[-1] if filled else None)
                indent = _indentation(visible[neighbour]) if neighbour is not None else ''
                for mark in marks:
                    result += [indent + mark, '']
            continue
        indent = _indentation(visible[i])
        leading, core, trailing = _split_edge_marks(line)
        for mark in leading:
            result.append(indent + mark)
            if i == 0 or blank[i - 1]:
                result.append('')
        result.append(indent + core)
        for mark in trailing:
            if i == len(lines) - 1 or blank[i + 1]:
                result.append('')
            result.append(indent + mark)
    return result


def _style_fragments(html: str, styles: list, color: str, background: str) -> str:
    """Replace the tokens left in *html* by the styling of the text between them: every run of
    text of a fragment gets its own ``<span>``, so a fragment may cover several blocks."""
    result = []
    style = None  # CSS of the fragment being walked through

    def consume(piece: str, is_text: bool):
        nonlocal style
        position = 0
        for token in _TOKEN_RE.finditer(piece):
            emit(piece[position:token.start()], is_text)
            if token.group(1) == 'B':
                number = int(token.group(2))
                fragment_color, _, fragment_background = (
                    styles[number] if number < len(styles) else '').partition(';')
                style = (f"color:{_valid_color(fragment_color, color)};"
                         f"background-color:{_valid_color(fragment_background, background)}")
            else:
                style = None
            position = token.end()
        emit(piece[position:], is_text)

    def emit(segment: str, is_text: bool):
        text = segment.strip()
        if is_text and style is not None and text:
            start = segment.index(text)  # the whitespace around the text stays out of the span
            result.append(f'{segment[:start]}<span style="{style}">{text}</span>{segment[start + len(text):]}')
        else:
            result.append(segment)

    for index, piece in enumerate(_HTML_TAG_RE.split(html)):
        consume(piece, is_text=index % 2 == 0)
    return _EMPTY_PARAGRAPH_RE.sub('', ''.join(result)).rstrip('\n')
