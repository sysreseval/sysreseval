"""Per-project log of the operations executed by ``sre state`` and ``sre eval``.

Written only for debug projects (``sre start --debug-project``, marker ``.private/debug_project``)
into ``<project dir>/operations.log`` (:func:`params.operations_log_filename`), in the public
project directory so that the GUI (student uid) can tail it in its "Log" tab.

Format: one header line per run, preceded by a blank line unless the file is empty::

    === 2026-10-02 15:01:02  state final
    step1 - on m1 : cat /etc/hostname
        m1
        exit code 0
    step1 - on m2 : file /etc/hosts (0o644 root:root, 230 B)
    step2 - on host : ./gen.sh
        exit code 0

Every entry starts with ``step<N> - on <machine|host> : <operation>``; the output of a command is
indented below it (capped at ``params.operations_log_max_output_chars``) and its exit code comes
last (``-1`` = timeout, ``-2`` = error, ``no result`` when exetests returned nothing for it).
A file operation (file, append, copy from/to host) is followed by the indented content it wrote
(same cap; ``(binary content not shown)`` when it is not UTF-8 text).  An evaluation ends with
the grade elements and the totals of both scopes::

    grade - [Routing] default route on m1 : 1 / 2 (self-eval only)
    total - self-eval : 3 / 5, mark 12 / 20
    total - exo-eval : 2 / 3, mark 13.4 / 20

Each entry is one ``write()`` on an ``O_APPEND`` descriptor, so entries of concurrent writers
(``sre state`` and a background ``sre eval`` of the same project) interleave but never mix, and a
lock keeps the batch of one machine contiguous when state ops run in one thread per machine.
Logging is best effort: an OS error disables the instance after one line on stderr.
"""
import datetime
import os
import threading

from . import params
from .utils import log_error

INDENT = "    "
HOST = "host"
BINARY_CONTENT = "(binary content not shown)"


def _now() -> datetime.datetime:
    return datetime.datetime.now()


def format_header(title: str, now: datetime.datetime | None = None, leading_newline: bool = False) -> str:
    """``=== <YYYY-mm-dd HH:MM:SS>  <title>`` line (``now`` defaults to the current time)."""
    if now is None:
        now = _now()
    return ("\n" if leading_newline else "") + f"=== {now.strftime('%Y-%m-%d %H:%M:%S')}  {title}\n"


def format_op(step: int, where: str, text: str) -> str:
    """``step<N> - on <where> : <text>`` line."""
    return f"step{step} - on {where} : {text}\n"


def format_exit_code(code: int | None) -> str:
    if code is None:
        return "no result"
    if code == -1:
        return "exit code -1 (timeout)"
    if code == -2:
        return "exit code -2 (error)"
    return f"exit code {code}"


def _indented(text: str, max_chars: int | None = None) -> list[str]:
    """Lines of *text* indented for the log: trailing newlines stripped, text capped at *max_chars*
    (``params.operations_log_max_output_chars`` by default) and followed by a truncation line."""
    if max_chars is None:
        max_chars = params.operations_log_max_output_chars
    text = (text or '').rstrip('\n')
    truncated = 0
    if max_chars is not None and len(text) > max_chars:
        truncated = len(text) - max_chars
        text = text[:max_chars]
    lines = [f"{INDENT}{line}\n" for line in text.split('\n')] if text else []
    if truncated:
        lines.append(f"{INDENT}... ({truncated} more characters truncated)\n")
    return lines


def format_cmd(step: int, where: str, command: str, output, code: int | None, max_chars: int | None = None) -> str:
    """Operation line of a command followed by its indented output and its exit code line."""
    if isinstance(output, bytes):
        output = output.decode('utf-8', 'replace')
    return ''.join([format_op(step, where, command), *_indented(output, max_chars),
                    f"{INDENT}{format_exit_code(code)}\n"])


def format_content(content, max_chars: int | None = None) -> str:
    """Indented text of a file content (bytes or str), written below the line of a file operation.
    Content that is not UTF-8 text gives one ``(binary content not shown)`` line, empty content
    nothing."""
    if isinstance(content, (bytes, bytearray)):
        try:
            content = bytes(content).decode('utf-8')
        except UnicodeDecodeError:
            return f"{INDENT}{BINARY_CONTENT}\n"
    if not content:
        return ''
    if '\x00' in content:
        return f"{INDENT}{BINARY_CONTENT}\n"
    return ''.join(_indented(content, max_chars))


def _fmt_num(value) -> str:
    """A grade value: whole numbers without decimal point, ``None`` as ``?``."""
    if value is None:
        return "?"
    try:
        if value == int(value):
            return str(int(value))
    except (TypeError, ValueError, OverflowError):
        pass
    return str(value)


def format_grade(title, grade, max_grade, part: str | None = None, scope: str | None = None) -> str:
    """``grade - [<part>] <title> : <grade> / <max> (<scope>)`` line of a grade element; the part
    and the scope label only when given."""
    title = str(title).replace('\n', ' ')
    head = f"[{str(part).replace(chr(10), ' ')}] " if part else ""
    tail = f" ({scope})" if scope else ""
    return f"grade - {head}{title} : {_fmt_num(grade)} / {_fmt_num(max_grade)}{tail}\n"


def format_total(label: str, total, total_max, mark, maximum_mark=None) -> str:
    """``total - <label> : <total> / <max>, mark <mark> / <maximum>`` line; a letter mark has no
    maximum, ``no mark`` when there is nothing to grade (*mark* is ``None``)."""
    if mark is None:
        mark_text = "no mark"
    elif maximum_mark is not None:
        mark_text = f"mark {_fmt_num(mark)} / {_fmt_num(maximum_mark)}"
    else:
        mark_text = f"mark {mark}"
    return f"total - {label} : {_fmt_num(total)} / {_fmt_num(total_max)}, {mark_text}\n"


def describe_file(verb: str, filename: str, permissions: int | None, owner: str | None, size: int) -> str:
    """``<verb> <filename> (0o644 root:root, 230 B)``; permissions / owner only when given."""
    attrs = []
    if permissions is not None:
        attrs.append(f"{permissions:#o}")
    if owner:
        attrs.append(owner)
    head = " ".join(attrs)
    return f"{verb} {filename} ({head + ', ' if head else ''}{size} B)"


class OperationsLog:
    """Append-only operations log of one running project (see the module docstring).

    ``enabled=False`` gives a null object whose methods return at once; the file is opened on
    the first write, so a disabled or never-written log leaves no file behind.
    """

    HOST = HOST  # the ``where`` of host-side operations

    def __init__(self, running_lab_name: str | None, enabled: bool):
        self._enabled = bool(enabled)
        self._path = params.operations_log_filename(running_lab_name) if self._enabled else None
        self._fd = None
        self._needs_separator = False  # True once the file has content (blank line before a header)
        self._lock = threading.Lock()

    @classmethod
    def disabled(cls) -> "OperationsLog":
        return _DISABLED

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def path(self) -> str | None:
        return self._path

    def begin(self, title: str) -> None:
        """Start a run: ``state <name>`` or ``evaluation``."""
        self._write(lambda: format_header(title, leading_newline=self._needs_separator))

    def op(self, step: int, where: str, text: str, content=None) -> None:
        """One operation without output (file, append, copy, callback, error...).  *content* (bytes
        or str) is what a file operation wrote: it goes below the line, see :func:`format_content`."""
        self._write(lambda: format_op(step, where, text)
                    + (format_content(content) if content is not None else ''))

    def cmd(self, step: int, where: str, command: str, output, code: int | None) -> None:
        """One executed command with its output and exit code."""
        self._write(lambda: format_cmd(step, where, command, output, code))

    def cmds(self, step: int, where: str, entries) -> None:
        """Several commands of one machine and step, ``(command, output, code)`` tuples, written as
        one contiguous block."""
        entries = list(entries)
        if not entries:
            return
        self._write(lambda: ''.join(format_cmd(step, where, c, o, k) for c, o, k in entries))

    def lines(self, lines) -> None:
        """Preformatted lines (each one ending with a newline), written as one contiguous block."""
        text = ''.join(lines)
        if not text:
            return
        self._write(lambda: text)

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    # -- internals -------------------------------------------------------------------------

    def _write(self, make_text) -> None:
        if not self._enabled:
            return
        with self._lock:
            if not self._enabled:
                return
            try:
                if self._fd is None:
                    self._open_locked()
                data = make_text().encode('utf-8', 'replace')
                while data:
                    written = os.write(self._fd, data)
                    data = data[written:]
                self._needs_separator = True
            except OSError as e:
                log_error(f"operations log: {self._path}: {e} (logging disabled)")
                self._enabled = False
                self._close_locked()

    def _open_locked(self) -> None:
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        try:
            os.fchmod(fd, 0o644)  # readable by the GUI whatever the umask
            if os.geteuid() == 0:
                # created while the euid is raised (privileged lab): keep it appendable by sre
                os.fchown(fd, params.sre_uid, -1)
            self._needs_separator = os.fstat(fd).st_size > 0
        except OSError:
            os.close(fd)
            raise
        self._fd = fd

    def _close_locked(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


_DISABLED = OperationsLog(None, enabled=False)
