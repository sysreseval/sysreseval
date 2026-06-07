import ctypes
import ctypes.util
import fcntl
import os

from PySide6.QtWidgets import QApplication, QTabWidget, QWidget
from PySide6.QtCore import QProcess, Qt, QTimer
from PySide6.QtGui import QClipboard, QColor

from SRE import params
from sysreseval import settings

# ---------------------------------------------------------------------------
# PTY paste helper
# ---------------------------------------------------------------------------

# TIOCGPTN: get PTY slave number — succeeds only on a PTY master fd.
# Used to identify the PTY master among xterm's open fds.
_TIOCGPTN = 0x80045430

# pidfd_getfd syscall number (x86-64 / arm64 Linux).
# Falls back to the raw syscall when os.pidfd_getfd is absent (Python < 3.12 builds).
_SYS_pidfd_getfd = 438
_libc = ctypes.CDLL("libc.so.6", use_errno=True)


def _pidfd_getfd(pidfd: int, targetfd: int) -> int:
    """Dup targetfd from the process referred to by pidfd into the current process."""
    if hasattr(os, "pidfd_getfd"):
        return os.pidfd_getfd(pidfd, targetfd)
    fd = _libc.syscall(_SYS_pidfd_getfd, pidfd, targetfd, 0)
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return fd


def _pty_paste(xterm_pid: int, text: str) -> bool:
    """Write `text` to xterm's PTY master so it appears as typed input.

    Uses os.pidfd_getfd() to dup fds from xterm's process and probes each
    with TIOCGPTN to identify the PTY master without re-opening /dev/ptmx
    (which would create a new, unconnected PTY pair).
    Requires Python ≥ 3.9 and Linux ≥ 5.6.
    """
    try:
        pidfd = os.pidfd_open(xterm_pid)
    except (OSError, AttributeError):
        return False
    try:
        fd_dir = f"/proc/{xterm_pid}/fd"
        try:
            fd_nums = [int(e.name) for e in os.scandir(fd_dir)]
        except OSError:
            return False

        master_fd = None
        for fd_n in fd_nums:
            try:
                fd = _pidfd_getfd(pidfd, fd_n)
            except OSError:
                continue
            try:
                fcntl.ioctl(fd, _TIOCGPTN, bytearray(4))
                master_fd = fd  # TIOCGPTN succeeded → this is the PTY master
                break
            except OSError:
                os.close(fd)

        if master_fd is None:
            return False
        try:
            os.write(master_fd, text.encode("utf-8", errors="replace"))
            return True
        finally:
            os.close(master_fd)
    finally:
        os.close(pidfd)


# ---------------------------------------------------------------------------
# X11 key-event constants
# ---------------------------------------------------------------------------
_XK_Insert      = 0xff63
_XK_Shift_L     = 0xffe1
_ShiftMask      = 1
_KeyPress       = 2
_KeyRelease     = 3
_KeyPressMask   = 1
_KeyReleaseMask = 2
_RevertToParent = 1


class _XKeyEvent(ctypes.Structure):
    _fields_ = [
        ("type",        ctypes.c_int),
        ("serial",      ctypes.c_ulong),
        ("send_event",  ctypes.c_int),
        ("display",     ctypes.c_void_p),
        ("window",      ctypes.c_ulong),
        ("root",        ctypes.c_ulong),
        ("subwindow",   ctypes.c_ulong),
        ("time",        ctypes.c_ulong),
        ("x",           ctypes.c_int),
        ("y",           ctypes.c_int),
        ("x_root",      ctypes.c_int),
        ("y_root",      ctypes.c_int),
        ("state",       ctypes.c_uint),
        ("keycode",     ctypes.c_uint),
        ("same_screen", ctypes.c_int),
    ]


def _x11_query(parent_wid: int):
    """Return (lib, dpy, children_list). Caller must XCloseDisplay(dpy)."""
    lib = ctypes.cdll.LoadLibrary("libX11.so.6")
    dpy = lib.XOpenDisplay(None)
    if not dpy:
        return lib, None, []
    root = ctypes.c_ulong()
    parent = ctypes.c_ulong()
    children_ptr = ctypes.POINTER(ctypes.c_ulong)()
    nchildren = ctypes.c_uint()
    lib.XQueryTree(
        dpy, parent_wid,
        ctypes.byref(root), ctypes.byref(parent),
        ctypes.byref(children_ptr), ctypes.byref(nchildren),
    )
    children = [children_ptr[i] for i in range(nchildren.value)]
    if nchildren.value:
        lib.XFree(children_ptr)
    return lib, dpy, children


def _x11_resize_children(parent_wid: int, w: int, h: int):
    try:
        lib, dpy, children = _x11_query(parent_wid)
        if not dpy:
            return
        for wid in children:
            lib.XMoveResizeWindow(dpy, wid, 0, 0, w, h)
        lib.XFlush(dpy)
        lib.XCloseDisplay(dpy)
    except Exception:
        pass


def _x11_get_children(parent_wid: int) -> list[int]:
    try:
        lib, dpy, children = _x11_query(parent_wid)
        if dpy:
            lib.XCloseDisplay(dpy)
        return children
    except Exception:
        return []


def _x11_type_text(wid: int, text: str) -> bool:
    """Type `text` into X11 window `wid` character by character.

    Focuses `wid` via XSetInputFocus, then sends each printable ASCII
    character as a real key event (XTestFakeKeyEvent via libXtst when
    available, XSendEvent otherwise).  No X11 selection is involved, so
    there are no timing issues with PRIMARY/CLIPBOARD ownership.
    Returns True if at least the focus + flush succeeded.
    """
    try:
        lib = ctypes.cdll.LoadLibrary("libX11.so.6")
        dpy = lib.XOpenDisplay(None)
        if not dpy:
            return False
        root = lib.XDefaultRootWindow(dpy)

        lib.XSetInputFocus(dpy, wid, _RevertToParent, 0)
        lib.XSync(dpy, 0)

        # XkbKeycodeToKeysym returns KeySym (unsigned long); set restype to
        # avoid truncation on 64-bit systems.
        lib.XkbKeycodeToKeysym.restype = ctypes.c_ulong

        try:
            xtst = ctypes.cdll.LoadLibrary("libXtst.so.6")
            use_xtest = True
        except OSError:
            use_xtest = False

        shift_kc = lib.XKeysymToKeycode(dpy, _XK_Shift_L)

        for char in text:
            cp = ord(char)
            if char == '\n':
                keysym = 0xff0d        # XK_Return
            elif char == '\t':
                keysym = 0xff09        # XK_Tab
            elif 0x20 <= cp <= 0x7e:
                keysym = cp            # printable ASCII keysym == codepoint
            else:
                continue               # skip non-ASCII

            keycode = lib.XKeysymToKeycode(dpy, keysym)
            if not keycode:
                continue

            # Shift is needed when the unshifted keysym for this keycode
            # differs from what we want (e.g. 'A' vs 'a').
            need_shift = lib.XkbKeycodeToKeysym(dpy, keycode, 0, 0) != keysym

            if use_xtest:
                if need_shift:
                    xtst.XTestFakeKeyEvent(dpy, shift_kc, 1, 0)
                xtst.XTestFakeKeyEvent(dpy, keycode, 1, 0)
                xtst.XTestFakeKeyEvent(dpy, keycode, 0, 0)
                if need_shift:
                    xtst.XTestFakeKeyEvent(dpy, shift_kc, 0, 0)
            else:
                # XSendEvent fallback (requires XTerm*allowSendEvents: true)
                evt = _XKeyEvent()
                evt.type        = _KeyPress
                evt.serial      = 0
                evt.send_event  = 1
                evt.display     = dpy
                evt.window      = wid
                evt.root        = root
                evt.subwindow   = 0
                evt.time        = 0
                evt.x = evt.y = evt.x_root = evt.y_root = 1
                evt.same_screen = 1
                evt.keycode     = keycode
                evt.state       = _ShiftMask if need_shift else 0
                lib.XSendEvent(dpy, wid, True, _KeyPressMask, ctypes.byref(evt))
                evt.type = _KeyRelease
                lib.XSendEvent(dpy, wid, True, _KeyReleaseMask, ctypes.byref(evt))

        lib.XFlush(dpy)
        lib.XCloseDisplay(dpy)
        return True
    except Exception:
        return False


class TerminalWidget(QWidget):
    def __init__(self, project_name: str, machine_name: str, parent=None):
        super().__init__(parent)
        self._project_name = project_name
        self._machine_name = machine_name
        self._process = QProcess(self)
        self._xterm_wid: int = 0
        self.setAttribute(Qt.WA_NativeWindow, True)

    def showEvent(self, event):
        super().showEvent(event)
        if self._process.state() == QProcess.NotRunning:
            wid = int(self.winId())
            scheme = settings.get_color_scheme()
            fg, bg = ("white", "black") if scheme == "white_on_black" else ("black", "white")
            self._process.start("xterm", [
                "-into", str(wid),
                "-fa", "Monospace",
                "-fs", str(settings.get_font_size()),
                "-fg", fg, "-bg", bg,
                "-xrm", "XTerm*allowSendEvents: true",
                "-xrm", "XTerm.VT100.translations: #override Ctrl Shift <Key>C: copy-selection(CLIPBOARD)\\n Ctrl Shift <Key>V: insert-selection(CLIPBOARD)\\n",
                "-e", params.sre_wrapper, "connect",
                self._project_name, self._machine_name,
            ])
            QTimer.singleShot(300, self._sync_size)
            QTimer.singleShot(500, self._find_xterm_wid)

    def _find_xterm_wid(self):
        children = _x11_get_children(int(self.winId()))
        if children:
            self._xterm_wid = children[0]
        elif self._process.state() != QProcess.NotRunning:
            QTimer.singleShot(300, self._find_xterm_wid)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_size()

    def _sync_size(self):
        if self._process.state() != QProcess.NotRunning:
            s = self.size()
            _x11_resize_children(int(self.winId()), s.width(), s.height())

    def kill(self):
        if self._process.state() != QProcess.NotRunning:
            self._process.kill()

    def copy(self):
        """Copy xterm's current selection (X11 PRIMARY) into the Qt clipboard."""
        text = QApplication.clipboard().text(QClipboard.Mode.Selection)
        if text:
            QApplication.clipboard().setText(text, QClipboard.Mode.Clipboard)

    def paste(self):
        """Paste Qt clipboard text into xterm.

        Primary method: write directly to xterm's PTY master via
        /proc/{pid}/fd/ — reliable, no X11 selection or focus needed.
        Fallback: X11 PRIMARY selection + Shift+Insert key event.
        """
        text = QApplication.clipboard().text(QClipboard.Mode.Clipboard)
        if not text:
            return
        pid = self._process.processId()
        try:
            pty_ok = pid > 0 and _pty_paste(pid, text)
        except Exception:
            pty_ok = False
        if pty_ok:
            return
        # X11 fallback
        if not self._xterm_wid:
            children = _x11_get_children(int(self.winId()))
            if children:
                self._xterm_wid = children[0]
        if not self._xterm_wid:
            return
        vt_children = _x11_get_children(self._xterm_wid)
        target_wid = vt_children[0] if vt_children else self._xterm_wid
        try:
            _x11_type_text(target_wid, text)
        except Exception:
            pass


class TerminalsView(QTabWidget):
    def __init__(self, project_name: str, machines: list, debug_project: bool = False, parent=None):
        super().__init__(parent)
        self._project_name = project_name
        self._debug_project = debug_project
        self.setTabsClosable(False)
        self._machine_tabs: set = set()
        self.update_data(machines)

    def update_data(self, machines: list):
        for machine in machines:
            name = machine.get("name", "")
            if not name or name in self._machine_tabs:
                continue
            if not self._debug_project and not machine.get("allow_connection"):
                continue
            self._machine_tabs.add(name)
            idx = self.addTab(TerminalWidget(self._project_name, name, self), name)
            if self._debug_project:
                if machine.get("hidden"):
                    self.tabBar().setTabTextColor(idx, QColor("red"))
                elif not machine.get("allow_connection"):
                    self.tabBar().setTabTextColor(idx, QColor("orange"))

    def kill_terminals(self):
        for i in range(self.count()):
            w = self.widget(i)
            if isinstance(w, TerminalWidget):
                w.kill()

    def active_terminal(self) -> "TerminalWidget | None":
        w = self.currentWidget()
        return w if isinstance(w, TerminalWidget) else None
