import datetime
import enum
import fnmatch
import re as _re
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import math

from dataclasses import asdict

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple

import zstandard as zstd

from pathlib import Path

import msgpack
import json
import random
from netaddr import EUI
from dataclasses import dataclass, fields
from ipaddress import (
    ip_address,
    ip_network,
    IPv4Address, IPv6Address,
    IPv4Interface,
    IPv4Network, IPv6Network
)

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from . import params
from .common import (QuestionText, QuestionDummy, GradeElement, GradePart, InfoMachine, InfoLab, InfoInterface,
                     TranslatedText, _tt_hash_str)
from .utils import log_error, error_quit, log_debug
from .params import SRE


class ErrorCategory(enum.Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"


def write_error(string):
    print(string, file=sys.stderr)


def _lookup_translations(caller_globals: dict, text: str, inline: dict) -> dict:
    """Merge ``_TRANSLATIONS`` from a module's globals with inline kwargs.

    Inline kwargs take priority.  ``None`` values in ``_TRANSLATIONS`` are
    skipped (they mark strings not yet translated).
    """
    result = {}
    for lang, strings in caller_globals.get('_TRANSLATIONS', {}).items():
        val = strings.get(text)
        if val is not None and lang not in inline:
            result[lang] = val
    result.update(inline)
    return result


def tr(text: str, **langs) -> TranslatedText:
    """Build a TranslatedText with 'en' as the default language key.

    Looks up the caller module's ``_TRANSLATIONS`` dict for any language not
    already supplied as a keyword argument.  Inline kwargs take priority.
    ``None`` values in ``_TRANSLATIONS`` are skipped (placeholder for
    untranslated strings).

    ``_TRANSLATIONS`` must be defined **before** the first ``tr()`` call in
    the file, because module-level expressions are evaluated at import time.

    Usage in lab files::

        title = tr("My lab")              # translation from _TRANSLATIONS
        title = tr("My lab", fr="Mon TP") # inline, retro-compatible

    For labs whose primary language is not English, use :func:`make_tr` instead.
    """
    merged = _lookup_translations(sys._getframe(1).f_globals, text, langs)
    return TranslatedText({'en': text, **merged})


def make_tr(default_lang: str, translations: dict | None = None):
    """Return a tr() function bound to *default_lang* as the first-positional language.

    If *translations* is supplied explicitly it is used directly (no frame
    inspection).  Otherwise the caller module's globals are inspected for a
    ``_TRANSLATIONS`` dict at each call.

    In both cases ``_TRANSLATIONS`` (or the dict passed as *translations*) must
    be defined **before** the first ``tr()`` call in the file, because
    module-level expressions are evaluated at import time.

    Usage with explicit dict (no frame inspection)::

        _TRANSLATIONS = {'fr': {"Mon TP": "My lab"}}
        tr = make_tr('fr', translations=_TRANSLATIONS)
        title = tr("Mon TP")   # 'en' from _TRANSLATIONS

    Usage with frame inspection::

        tr = make_tr('fr')
        _TRANSLATIONS = {'en': {"Mon TP": "My lab"}}  # must come before tr() calls
        title = tr("Mon TP")
    """
    if translations is not None:
        _wrapped = {'_TRANSLATIONS': translations}

        def _tr(text: str, **langs) -> TranslatedText:
            merged = _lookup_translations(_wrapped, text, langs)
            return TranslatedText({default_lang: text, **merged})
    else:
        caller_globals = sys._getframe(1).f_globals

        def _tr(text: str, **langs) -> TranslatedText:
            merged = _lookup_translations(caller_globals, text, langs)
            return TranslatedText({default_lang: text, **merged})

    return _tr


def no_tr(text: str) -> str:
    """Marker for prepare-sre-translations: leave this string untranslated.

    Identity passthrough at runtime (returns *text* unchanged). It is purely a
    hint to the translation tooling so the wrapped string is never wrapped in
    tr() nor registered in _TRANSLATIONS — use it for short internal labels
    (e.g. grade-element titles) that are not natural-language prose.
    """
    return text


_PORT_WILDCARD_RE = _re.compile(r'^(\d*)(X+):(\d+)(?:/(\w+))?$', _re.IGNORECASE)


def _is_port_free(port: int, proto: str) -> bool:
    sock_type = socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as s:
        try:
            s.bind(('', port))
            return True
        except OSError:
            return False


def _resolve_port(spec: str, used: set) -> str:
    """Resolve a port spec, replacing trailing X wildcards with a free host port.

    E.g. '80XX:80/tcp' -> '8042:80/tcp' (first free port in 8000-8099).
    Specs without wildcards are returned unchanged.
    `used` is updated in-place to track ports already allocated in this call.
    """
    m = _PORT_WILDCARD_RE.match(spec)
    if not m:
        return spec
    prefix_str, x_str, container_port, proto = m.group(1), m.group(2), m.group(3), (m.group(4) or 'tcp').lower()
    range_size = 10 ** len(x_str)
    base = (int(prefix_str) if prefix_str else 0) * range_size
    for offset in range(range_size):
        host_port = base + offset
        key = (host_port, proto)
        if key not in used and _is_port_free(host_port, proto):
            used.add(key)
            return f"{host_port}:{container_port}/{proto}"
    error_quit(f"no free {proto} port in range {base}-{base + range_size - 1}")


def _resolve_xauth_cookie():
    """Return the validated hex X11 magic cookie from $SRE_XAUTH_COOKIE, or None.

    The env var is set by sre-wrapper (from `xauth list`) and preserved across
    sudo via env_keep.  When `sre start --xauth-file <file>` is used,
    action_start parses that file early (with privileges) and overrides this
    env var with the file's cookie before NetScheme is built.
    """
    cookie = os.environ.get(params.sre_xauth_cookie_env_variable)
    return cookie if cookie and _re.fullmatch(r'[0-9A-Fa-f]+', cookie) else None


class _AppendOp:
    """A file-append operation registered via NetScheme0.append_to_file()."""
    __slots__ = ('filename', 'content', 'permissions', 'owner', 'mtime')

    def __init__(self, filename: str, content: bytes,
                 permissions: int | None, owner: str | None, mtime: float | None):
        self.filename = filename
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.mtime = mtime


class _IdempotentAppendOp:
    """An idempotent file-append operation registered via NetScheme0.idempotent_append_to_file().

    Appends content only if the file does not already end with it.
    Optionally sets permissions, ownership, and mtime regardless of whether content was appended.
    """
    __slots__ = ('filename', 'content', 'permissions', 'owner', 'mtime')

    def __init__(self, filename: str, content: bytes,
                 permissions: int | None, owner: str | None, mtime: float | None):
        self.filename = filename
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.mtime = mtime


class _FileOp:
    """A file-write operation registered via NetScheme0.file()."""
    __slots__ = ('filename', 'content', 'permissions', 'owner', 'mtime')

    def __init__(self, filename: str, content: bytes, permissions: int, owner: str, mtime: float):
        self.filename = filename
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.mtime = mtime


class _HostCmdOp:
    """A host-side command registered via NetScheme0.host_cmd()."""
    __slots__ = ('command',)

    def __init__(self, command: str):
        self.command = command


class _CpFromHostOp:
    """A deferred file-copy-from-host operation; file is read at execution time."""
    __slots__ = ('src_path', 'dest', 'permissions', 'owner', 'mtime')

    def __init__(self, src_path, dest: str, permissions, owner: str, mtime):
        self.src_path = src_path
        self.dest = dest
        self.permissions = permissions
        self.owner = owner
        self.mtime = mtime


class _CpToHostOp:
    """Copy a file from a container to the host files_dir."""
    __slots__ = ('src_path', 'dest_path', 'permissions')

    def __init__(self, src_path: str, dest_path: str, permissions: int = None):
        self.src_path = src_path  # absolute path inside the container
        self.dest_path = dest_path  # resolved absolute path on the host
        self.permissions = permissions  # mode to chmod on the host (None = leave as-is)


class _HostCallbackOp:
    """A host-side Python callback registered via NetScheme0.host_callback()."""
    __slots__ = ('callback',)

    def __init__(self, callback):
        self.callback = callback


class _IPv4InterfaceContainer:
    """Holds named IPv4Interface attributes. Automatically available as Data0.ips."""

    def __setattr__(self, name, value):
        if not isinstance(value, IPv4Interface):
            raise TypeError(f"{name}: expected IPv4Interface, got {type(value).__name__}")
        super().__setattr__(name, value)

    def __getitem__(self, name):
        return getattr(self, name)

    def to_dict(self):
        return {k: str(v) for k, v in self.__dict__.items()}


class _IPv4NetContainer:
    """Holds named IPv4Network attributes. Automatically available as Data0.nets."""

    def __setattr__(self, name, value):
        if not isinstance(value, IPv4Network):
            raise TypeError(f"{name}: expected IPv4Network, got {type(value).__name__}")
        super().__setattr__(name, value)

    def __getitem__(self, name):
        return getattr(self, name)

    def to_dict(self):
        return {k: str(v) for k, v in self.__dict__.items()}


class _MacContainer:
    """Holds named EUI MAC address attributes. Automatically available as Data0.macs."""

    def __setattr__(self, name, value):
        if not isinstance(value, EUI):
            raise TypeError(f"{name}: expected EUI, got {type(value).__name__}")
        super().__setattr__(name, value)

    def __getitem__(self, name):
        return getattr(self, name)

    def to_dict(self):
        return {k: str(v) for k, v in self.__dict__.items()}


@dataclass
class Flavor0:
    """Base class for optional lab-parameterisation dataclasses.

    Subclass with ``@dataclass(slots=True)`` and declare your fields.  If the
    module defines ``flavor_form_at_startup = True``, the GUI renders the
    ``flavor_form`` string (containing ``@@{field:regex}@@`` markers) as a form
    before starting the lab.

    Named presets can be attached as class attributes, e.g.::

        Flavor.easy = Flavor(nb=1)

    and referenced on the CLI with ``--set-flavor-name easy``.

    Override :meth:`allowed_by_user` to restrict which values students may choose.
    """

    _registry = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        key = f"{cls.__module__}.{cls.__qualname__}"
        cls._type_key = key
        Flavor0._registry[key] = cls

    def to_dict(self):
        """Serialise dataclass fields to a plain dict using :meth:`Data0._encode_value`."""
        return {f.name: Data0._encode_value(getattr(self, f.name)) for f in fields(self)}

    @classmethod
    def from_dict(cls, d):
        """Reconstruct a ``Flavor0`` instance from a dict produced by :meth:`to_dict`."""
        decoded = {k: Data0._decode_value(v) for k, v in d.items()}
        return cls(**decoded)  # type: ignore[call-arg]

    @classmethod
    def from_form_dict(cls, d: dict):
        """Build a Flavor from form field values (strings from text inputs, bools from
        submit buttons). Declared dataclass fields are coerced to their declared type.
        Extra keys in d (form fields not declared in the dataclass) are set as plain
        attributes on the instance so that allowed_by_user() can read them.
        """
        from typing import get_type_hints
        hints = get_type_hints(cls)
        declared = {f.name for f in fields(cls)}
        coerced = {}
        for f in fields(cls):
            v = d.get(f.name)
            if v is None:
                continue
            t = hints.get(f.name, str)
            if not isinstance(t, type) or isinstance(v, t):
                coerced[f.name] = v
            elif t == bool:
                coerced[f.name] = str(v).lower() in ('true', '1', 'yes')
            elif t == int:
                coerced[f.name] = int(v)
            elif t == float:
                coerced[f.name] = float(v)
            else:
                coerced[f.name] = str(v)
        obj = cls(**coerced)
        for k, v in d.items():
            if k not in declared:
                setattr(obj, k, v)
        return obj

    def allowed_by_user(self) -> Tuple[bool, str]:
        """Return ``(True, "")`` if the student may use this flavor; ``(False, reason)`` otherwise.

        Override in subclasses to restrict which values students can choose.
        """
        return True, ""


class Data0:
    """Base class for lab-specific parameter dataclasses.

    Subclass with ``@dataclass(slots=True)`` and declare your fields normally.
    Three dynamic containers are injected automatically into every instance by
    ``__post_init__``:

    * ``self.ips``  — :class:`_IPv4InterfaceContainer`: named ``IPv4Interface`` values
    * ``self.nets`` — :class:`_IPv4NetContainer`: named ``IPv4Network`` values
    * ``self.macs`` — :class:`_MacContainer`: named ``EUI`` MAC-address values

    The class-level ``_registry`` maps ``"module.ClassName"`` keys to concrete
    subclasses so that ``from_dict``/``unpack``/``from_json`` can reconstruct the
    correct type from serialised data without knowing it in advance.

    Override ``generate(flavor=None)`` as a ``@classmethod`` to produce a fresh
    randomised instance.  The result is serialised to ``data.json`` at lab start
    and reloaded for each evaluation.
    """

    _registry = {}
    _rng = random.Random()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        key = f"{cls.__module__}.{cls.__qualname__}"
        cls._type_key = key
        Data0._registry[key] = cls

    def __post_init__(self):
        """Inject ``ips``, ``nets``, ``macs``, and ``flavor`` into every instance.

        Called automatically by the dataclass ``__init__``.  Uses
        ``object.__setattr__`` so the injection works even when the subclass
        declares ``slots=True``.
        """
        # Inject ips/nets/flavor into __dict__ (available even with slots=True subclasses
        # because Data0 itself has no __slots__, so __dict__ is always inherited).
        object.__setattr__(self, 'ips', _IPv4InterfaceContainer())
        object.__setattr__(self, 'nets', _IPv4NetContainer())
        object.__setattr__(self, 'macs', _MacContainer())
        object.__setattr__(self, 'flavor', None)
        object.__setattr__(self, '__flavor_name', None)
        object.__setattr__(self, '__current_srelab_file', None)

    # ---------------- lifecycle hooks ----------------
    @classmethod
    def compute_pre_generate(cls, flavor=None):
        """Hook called just before generate() and after JSON/msgpack deserialization.

        Override in a subclass to set class-level derived state from *flavor*.
        The default implementation is a no-op (fully retro-compatible).
        """
        pass

    def compute_post_generate(self):
        """Hook called after generate() and after JSON/msgpack deserialization.

        Override in a subclass to set instance-level derived state from data fields.
        The default implementation is a no-op (fully retro-compatible).
        """
        pass

    # ---------------- dict conversion ----------------
    def to_dict(self):
        """Serialise to a plain dict (JSON-safe).

        Dataclass fields are encoded via :meth:`_encode_value`.  ``ips``, ``nets``,
        and ``macs`` are stored as nested dicts of strings.  An attached ``Flavor``
        is stored under the ``"flavor"`` key with its type key.
        """
        result = {}
        for f in fields(self):
            v = getattr(self, f.name)
            result[f.name] = self._encode_value(v)
        result['ips'] = self.ips.to_dict()
        result['nets'] = self.nets.to_dict()
        result['macs'] = self.macs.to_dict()
        if self.flavor is not None:
            result['flavor'] = {"__flavor_type__": self.flavor._type_key, "data": self.flavor.to_dict()}
        flavor_name = getattr(self, '__flavor_name', None)
        if flavor_name is not None:
            result['__flavor_name'] = flavor_name
        current_srelab_file = getattr(self, '__current_srelab_file', None)
        if current_srelab_file is not None:
            result['__current_srelab_file'] = current_srelab_file
        return result

    @classmethod
    def from_dict(cls, d):
        """Reconstruct a ``Data0`` instance from a plain dict produced by :meth:`to_dict`.

        The concrete subclass is resolved from ``d["__type__"]`` when *cls* is
        ``Data0`` itself; otherwise the calling class is used directly.
        Raises ``ValueError`` for unknown type keys.
        """
        d = dict(d)
        ips_data = d.pop('ips', {})
        nets_data = d.pop('nets', {})
        macs_data = d.pop('macs', {})
        flavor_data = d.pop('flavor', None)
        flavor_name = d.pop('__flavor_name', None)
        current_srelab_file = d.pop('__current_srelab_file', None)
        decoded = {k: cls._decode_value(v) for k, v in d.items()}
        obj = cls(**decoded)
        for k, v in ips_data.items():
            setattr(obj.ips, k, IPv4Interface(v))
        for k, v in nets_data.items():
            setattr(obj.nets, k, IPv4Network(v))
        for k, v in macs_data.items():
            setattr(obj.macs, k, EUI(v))
        if flavor_data is not None:
            flavor_key = flavor_data.get("__flavor_type__")
            if flavor_key not in Flavor0._registry:
                raise ValueError(f"unknown Flavor0 type: {flavor_key!r}")
            flavor_cls = Flavor0._registry[flavor_key]
            object.__setattr__(obj, 'flavor', flavor_cls.from_dict(flavor_data["data"]))
        object.__setattr__(obj, '__flavor_name', flavor_name)
        object.__setattr__(obj, '__current_srelab_file', current_srelab_file)
        return obj

    # ---------------- value encoding ----------------
    @staticmethod
    def _encode_value(v):
        """Encode a field value for JSON/msgpack storage.

        * ``IPv4Address`` / ``IPv6Address`` → ``{"__ip__": "..."}``
        * ``IPv4Network`` / ``IPv6Network`` → ``{"__net__": "..."}``
        * nested ``Data0`` → ``{"__type__": "...", "data": {...}}``
        * all other values are returned unchanged.
        """
        if isinstance(v, (IPv4Address, IPv6Address)):
            return {"__ip__": str(v)}
        if isinstance(v, (IPv4Network, IPv6Network)):
            return {"__net__": str(v)}

        if isinstance(v, Data0):
            return {
                "__type__": v._type_key,
                "data": v.to_dict()
            }
        return v

    @staticmethod
    def _decode_value(v):
        """Decode a value produced by :meth:`_encode_value` back to its Python type."""
        if isinstance(v, dict):
            if "__ip__" in v:
                return ip_address(v["__ip__"])
            if "__net__" in v:
                return ip_network(v["__net__"])
            if "__type__" in v:
                type_key = v["__type__"]
                if type_key not in Data0._registry:
                    raise ValueError(f"unknown Data0 type: {type_key!r}")
                return Data0._registry[type_key].from_dict(v["data"])
        return v

    # ---------------- msgpack ----------------
    def pack(self):
        """Serialise to a msgpack binary blob (includes type key for polymorphic reload)."""
        return msgpack.packb(
            {
                "__type__": self._type_key,
                "data": self.to_dict()
            },
            use_bin_type=True
        )

    @classmethod
    def unpack(cls, blob):
        """Deserialise a msgpack blob produced by :meth:`pack`.  Raises ``ValueError`` for unknown types."""
        obj = msgpack.unpackb(blob, raw=False)
        type_key = obj.get("__type__")
        if type_key not in Data0._registry:
            raise ValueError(f"unknown Data0 type: {type_key!r}")
        result = Data0._registry[type_key].from_dict(obj["data"])
        type(result).compute_pre_generate(result.flavor)
        result.compute_post_generate()
        return result

    # ---------------- JSON ----------------
    def to_json(self):
        """Serialise to a JSON string (includes type key for polymorphic reload)."""
        return json.dumps({
            "__type__": self._type_key,
            "data": self.to_dict()
        })

    @classmethod
    def from_json(cls, s):
        """Deserialise a JSON string produced by :meth:`to_json`."""
        obj = json.loads(s)
        concrete = Data0._registry[obj["__type__"]]
        result = concrete.from_dict(obj["data"])
        type(result).compute_pre_generate(result.flavor)
        result.compute_post_generate()
        return result

    @classmethod
    def load_from_json_file(cls, filename):
        """
        Load a Data0-derived object from a JSON file.
        The concrete class is resolved automatically.
        """

        path = Path(filename)
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
        concrete = Data0._registry[obj["__type__"]]
        result = concrete.from_dict(obj["data"])
        type(result).compute_pre_generate(result.flavor)
        result.compute_post_generate()
        return result

    def save_to_json_file(self, filename):
        """Write the instance to *filename* as JSON, mode 0o600 (lab secrets stay private)."""
        path = Path(filename)
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "__type__": self._type_key,
                    "data": self.to_dict()
                },
                f,
                indent=2  # optional but operationally useful
            )


def sre_state(fn=None, *, user_allowed=False, description=''):
    def decorator(f):
        f._is_sre_state = True
        f._sre_state_user_allowed = user_allowed
        f._sre_state_description = description
        return f

    if fn is not None:
        return decorator(fn)
    return decorator


class NetScheme0:
    """Base class for lab network topology definitions.

    Subclasses declare the topology as class-level dicts and implement state
    methods decorated with :func:`sre_state`.

    Class-level attributes:

    * ``_machine_specs`` — ``{name: {Machine kwargs}}`` — one entry per container.
    * ``_network_specs`` — ``{net_name: {color: ...}}`` — optional display hints.
    * ``_topology``      — ``{net_name: [machine, ...]}`` or ``{net_name: {machine: iface}}``
      — which machines connect to each network and on which interface.

    If any of these three attributes is not defined in the subclass (neither as a class
    variable nor as a property), the corresponding attribute is read from ``data``
    (``data.topology``, ``data.machine_specs``, ``data.network_specs``).
    Explicit subclass definitions always take precedence.

    Instance attributes set by ``__init__``:

    * ``self.data`` — the ``Data0`` instance for this lab run.
    * ``self.informations`` — Markdown text shown in the Informations tab (set this in ``__init__``).
    * Named machine and network objects (e.g. ``self.router``, ``self.lan``).

    The ``initial`` state method is always called at ``sre start``.  Additional
    states are applied with ``sre state <lab> <state_name>``.
    """

    _machine_specs = {}
    _network_specs = {}  # {net_name: {'color': ...}} — optional colors for networks
    _topology = {}  # {net_name: [m, ...] or {m: iface, ...}} — mixed allowed

    def _resolve_spec(self, attr: str, data_attr: str):
        """Return the topology/spec dict for *attr*.

        Resolution order:
        1. If the concrete subclass (or any class before ``NetScheme0`` in the MRO)
           defines *attr* as a class variable or property, return that value.
        2. Otherwise look for *data_attr* on ``self.data`` (checks instance attributes
           first, then class-level attributes set e.g. by ``compute_pre_generate``).
        3. If neither source provides the attribute, return the ``NetScheme0`` default
           (an empty dict), which is equivalent to "no topology/specs defined".
        """
        for cls in type(self).__mro__:
            if cls is NetScheme0:
                break
            if attr in cls.__dict__:
                return getattr(self, attr)
        return getattr(self.data, data_attr, getattr(NetScheme0, attr))

    def __init__(self, data, running_lab_name, lab_hash=None):
        """Build all ``Machine``, ``Network``, and ``NetAdapter`` objects from the class-level specs.

        Args:
            data: a ``Data0`` instance containing lab-specific parameters.
            running_lab_name: the runtime identifier ``{ts}@@@{lab}@@@{user}``.
            lab_hash: optional Kathara lab hash (resolved lazily if omitted).
        """
        self.data = data
        self.running_lab_name = running_lab_name
        self.debug_project = os.path.exists(params.debug_project_marker_filename(running_lab_name))
        self.lab_name = params.get_lab_name_from_running_lab_name(running_lab_name)
        self.lab_hash = lab_hash
        self.current_srelab_file = params.get_current_srelab_file_from_running_lab_name(running_lab_name)
        self.informations = ""

        _machine_specs = self._resolve_spec('_machine_specs', 'machine_specs')
        _network_specs = self._resolve_spec('_network_specs', 'network_specs')
        _topology = self._resolve_spec('_topology', 'topology')

        for name, parameters in _machine_specs.items():
            setattr(self, name, Machine(name=name, **parameters))

        # Create networks from _network_specs (with optional color), then remaining from _topology
        for name, parameters in _network_specs.items():
            setattr(self, name, Network(name=name, **parameters))

        for net_name in _topology:
            if not hasattr(self, net_name):
                setattr(self, net_name, Network(name=net_name))

        # Create NetAdapters from _topology.
        # Each value is either a list (auto interface) or a dict {machine: iface_spec}.
        # iface_spec can be: None (auto), an int, or a (int, mac) tuple.
        # Interface auto-assignment counts prior connections per machine across all networks.
        _iface_counter: dict[str, int] = {}
        for net_name, machines in _topology.items():
            net = getattr(self, net_name)
            if isinstance(machines, dict):
                items = machines.items()
            else:
                items = ((m, None) for m in machines)
            for mname, iface_spec in items:
                machine = getattr(self, mname)
                if isinstance(iface_spec, tuple):
                    iface, mac = iface_spec
                else:
                    iface, mac = iface_spec, None
                if iface is None:
                    iface = _iface_counter.get(mname, 0)
                _iface_counter[mname] = max(_iface_counter.get(mname, 0), iface) + 1
                NetAdapter(network=net, machine=machine, interface=iface, mac=mac)

        self._ops: dict[str, list] = {}  # machine → [str | _FileOp, ...]
        self._host_ops: dict[int, list] = {}

        self.net_config = None

    def host_interfaces_from_topology(self) -> dict:
        """Return {machine_name: [net_name, ...]} derived from the resolved topology."""
        topology = self._resolve_spec('_topology', 'topology')
        result = {}
        for net_name, machines in topology.items():
            names = machines.keys() if isinstance(machines, dict) else machines
            for mname in names:
                result.setdefault(mname, []).append(net_name)
        return result

    @sre_state(user_allowed=False)
    def initial(self):
        pass

    @classmethod
    def get_state_methods(cls):
        """Return a sorted list of all ``@sre_state``-decorated method names in this class hierarchy."""
        names = set()
        for klass in cls.__mro__:
            for name, fn in klass.__dict__.items():
                if callable(fn) and getattr(fn, '_is_sre_state', False):
                    names.add(name)
        return sorted(names)

    @classmethod
    def is_state_user_allowed(cls, state):
        """Return ``True`` if *state* was decorated with ``@sre_state(user_allowed=True)``."""
        for klass in cls.__mro__:
            fn = klass.__dict__.get(state)
            if fn is not None and getattr(fn, '_is_sre_state', False):
                return getattr(fn, '_sre_state_user_allowed', False)
        return False

    @classmethod
    def get_user_allowed_states(cls):
        """Return ``{state_name: description}`` for all user-allowed states."""
        result = {}
        for state in cls.get_state_methods():
            for klass in cls.__mro__:
                fn = klass.__dict__.get(state)
                if fn is not None and getattr(fn, '_is_sre_state', False):
                    if getattr(fn, '_sre_state_user_allowed', False):
                        result[state] = getattr(fn, '_sre_state_description', '')
                    break
        return result

    def get_data(self):
        return self.data

    def get_machine(self, machine_name):
        """Return the :class:`Machine` with *machine_name*, or ``None`` if not found."""
        if not hasattr(self, machine_name):
            return None
        machine = getattr(self, machine_name)
        if not isinstance(machine, Machine):
            return None
        return machine

    def get_network(self, network_name):
        """Return the :class:`Network` with *network_name*, or ``None`` if not found."""
        if not hasattr(self, network_name):
            return None
        machine = getattr(self, network_name)
        if not isinstance(machine, Network):
            return None
        return machine

    def get_machines(self):
        for _, value in self.__dict__.items():
            if isinstance(value, Machine):
                yield value

    def get_machine_names(self):
        return [m.name for m in self.get_machines()]

    def has_privileged_machines(self):
        return any(m.privileged for m in self.get_machines())

    def get_accessible_machine_names(self):
        return [m.name for m in self.get_machines()
                if not m.hidden and m.allow_connection]

    def get_visible_machine_names(self):
        return [m.name for m in self.get_visibles_machines()]

    def get_visibles_machines(self):
        for _, value in self.__dict__.items():
            if isinstance(value, Machine):
                if not value.hidden:
                    yield value

    def get_networks(self):
        for _, value in self.__dict__.items():
            if isinstance(value, Network):
                yield value

    def get_topology(self):
        return self._resolve_spec('_topology', 'topology')

    def get_machine_specs(self):
        return self._resolve_spec('_machine_specs', 'machine_specs')

    def get_network_specs(self):
        return self._resolve_spec('_network_specs', 'network_specs')

    def cmd(self, machine, command, step=1):
        """Register a shell command to execute inside *machine*'s container at *step*."""
        if SRE.args.debug:
            print(f"[state] [{machine}] CMD (step={step}): {command}", file=sys.stderr)
        self._ops.setdefault(step, {}).setdefault(machine, []).append(command)

    def host_cmd(self, command, step=1):
        """Register a shell command to execute on the **host** (not inside a container) at *step*.

        Requires ``params.execute_commands_on_host`` to be enabled; aborts otherwise.
        """
        if params.execute_commands_on_host is False:
            sys.exit("host_cmd() is disabled by params.execute_commands_on_host")
        if SRE.args.debug:
            print(f"[state] HOST_CMD (step={step}): {command}", file=sys.stderr)
        self._host_ops.setdefault(step, []).append(_HostCmdOp(command))

    def host_callback(self, callback, step=1):
        """Register a Python callable to invoke on the host at *step* (called with no arguments)."""
        if SRE.args.debug:
            print(f"[state] HOST_CALLBACK (step={step}): {getattr(callback, '__name__', repr(callback))}",
                  file=sys.stderr)
        self._host_ops.setdefault(step, []).append(_HostCallbackOp(callback))

    def cp_from_host(self, src: str, machine: str, dest: str, owner: str = "root:root", permissions: int = None,
                     mtime: float = None, step=1):
        """Register a file copy from the host into *machine*'s container at *step*.

        *src* may be relative (resolved against ``params.files_dir``).
        *dest* is the absolute path inside the container.
        """
        orig_path = Path(src)
        if not orig_path.is_absolute():
            orig_path = Path(params.files_dir(self.running_lab_name)) / orig_path
        if SRE.args.debug:
            print(f"[state] [{machine}] CP (step={step}): {orig_path} -> {dest} (owner={owner})", file=sys.stderr)
        self._ops.setdefault(step, {}).setdefault(machine, []).append(
            _CpFromHostOp(orig_path, dest, permissions, owner, mtime)
        )

    def cp_to_host(self, machine: str, path: str, dest: str, permissions: int = None, step=1):
        """Copy file `path` from `machine` to the host files_dir.

        Args:
            machine:     container name
            path:        absolute path of the file inside the container
            dest:        relative destination path inside params.files_dir(running_lab_name)
            permissions: file mode to apply on the host copy (default: None, leave as written)
            step:        execution step (default 1)
        """
        files_dir = Path(params.files_dir(self.running_lab_name)).resolve()
        dest_path = (files_dir / dest).resolve()
        if not dest_path.is_relative_to(files_dir):
            error_quit(f"cp_to_host: dest '{dest}' is outside files_dir '{files_dir}'")
        if SRE.args.debug:
            print(f"[state] [{machine}] CP_TO_HOST (step={step}): {path} -> {dest_path}", file=sys.stderr)
        self._ops.setdefault(step, {}).setdefault(machine, []).append(
            _CpToHostOp(path, str(dest_path), permissions)
        )

    def file(self, machine, filename, content, permissions=0o644, owner="root:root", mtime=None, step=1):
        """Register a file to create/overwrite on `machine` during the current state.

        Args:
            machine:     machine name (str)
            filename:    absolute path inside the container (e.g. "/etc/myconfig")
            content:     file content (str or bytes)
            permissions: octal mode (default 0o644)
            owner:       "user:group" string (default "root:root")
            mtime:       modification time as a Unix timestamp (float); defaults to now
            step:        execution step (default 1); higher steps run after lower ones
        """
        import time as _time
        raw = content.encode() if isinstance(content, str) else content
        if SRE.args.debug:
            print(
                f"[state] [{machine}] FILE (step={step}): {filename} (permissions={permissions:#o}, owner={owner}, size={len(raw)}B)",
                file=sys.stderr)
        self._ops.setdefault(step, {}).setdefault(machine, []).append(
            _FileOp(filename, raw, permissions, owner, mtime if mtime is not None else _time.time())
        )

    def append_to_file(self, machine, filename, content, permissions=None, owner=None, mtime=None, step=1):
        """Append content to a file on `machine`; create the file if it does not exist.

        Args:
            machine:     machine name (str)
            filename:    absolute path inside the container (e.g. "/etc/hosts")
            content:     content to append (str or bytes)
            permissions: octal mode to set after appending (default: leave unchanged)
            owner:       "user:group" to set after appending (default: leave unchanged)
            mtime:       modification time as a Unix timestamp (default: leave unchanged)
            step:        execution step (default 1); higher steps run after lower ones
        """
        raw = content.encode() if isinstance(content, str) else content
        if SRE.args.debug:
            print(f"[state] [{machine}] APPEND (step={step}): {filename} (size={len(raw)}B)", file=sys.stderr)
        self._ops.setdefault(step, {}).setdefault(machine, []).append(
            _AppendOp(filename, raw, permissions, owner, mtime)
        )

    def idempotent_append_to_file(self, machine, filename, content, permissions=None, owner=None, mtime=None, step=1):
        """Append content to a file on `machine` only if the file does not already end with it.

        Idempotent version of append_to_file: safe to call multiple times — the content
        is appended at most once per application.  If permissions, owner, or mtime are
        provided they are applied regardless of whether content was appended.

        Args:
            machine:     machine name (str)
            filename:    absolute path inside the container (e.g. "/etc/hosts")
            content:     content to append (str or bytes)
            permissions: octal mode to set after the check (default: leave unchanged)
            owner:       "user:group" to set after the check (default: leave unchanged)
            mtime:       modification time as a Unix timestamp (default: leave unchanged)
            step:        execution step (default 1); higher steps run after lower ones
        """
        raw = content.encode() if isinstance(content, str) else content
        if SRE.args.debug:
            print(f"[state] [{machine}] IDEMPOTENT_APPEND (step={step}): {filename} (size={len(raw)}B)",
                  file=sys.stderr)
        self._ops.setdefault(step, {}).setdefault(machine, []).append(
            _IdempotentAppendOp(filename, raw, permissions, owner, mtime)
        )

    def compute_state_ops(self, state):
        self._ops = {}
        self._host_ops = {}
        if not hasattr(self, state):
            error_quit(f"state method {state} does not exist")
        method = getattr(self, state)
        if not callable(method):
            error_quit(f"state method {state} not callable")
        try:
            method()
        except Exception as e:
            error_quit(f"error during {state} execution: {e}")
        return self._ops, self._host_ops

    def get_new_lab_from_scheme(self):
        lab = Lab(name=self.running_lab_name)
        abb_lab_name = params.get_abbreviated_lab_name_from_running_lab_name(self.running_lab_name)
        _used_ports: set = set()
        xauth_cookie = _resolve_xauth_cookie()
        for m in self.get_machines():
            m.ports = [_resolve_port(p, _used_ports) for p in m.ports]
            m.envs[f"{params.sre_name_env_variable}={abb_lab_name}"] = True
            if m.x11_host:
                m.envs[f"{params.sre_host_ip_env_variable}={params.sre_host_ip}"] = True
                if xauth_cookie:
                    m.envs[f"{params.sre_xauth_cookie_env_variable}={xauth_cookie}"] = True
            volumes = []
            if len(m.volumes) > 0:
                has_private_volume = False
                for v in m.volumes:
                    if len(v) > 2 and v[3] == 'private':
                        has_private_volume = True
                        break

                if has_private_volume and params.disable_volume_mount_on_root_partition:
                    private_mount_dir = self.get_private_mount_dir()
                    p = Path(private_mount_dir)
                    while not p.exists():
                        p = p.parent
                    if os.stat(p).st_dev == os.stat('/').st_dev:
                        error_quit(
                            f"Machine '{m.name}': private mount dir '{private_mount_dir}' is on the root partition (disable_volume_mount_on_root_partition=True)")

                for v in m.volumes:
                    if len(v) > 2 and v[3] == 'private':
                        if v[0].startswith('/'):
                            error_quit(f"volume {v[0]} is private and have an absolute path")
                        v_host = f"{self.get_private_mount_dir()}/{v[0]}"
                        os.makedirs(v_host, exist_ok=True)
                        os.chmod(v_host, 0o777)
                    else:
                        if v[0].startswith('/'):
                            v_host = v[0]
                        else:
                            v_host = f"{self.get_user_public_dir()}/{v[0]}"
                            os.makedirs(v_host, exist_ok=True)
                            os.chmod(v_host, 0o777)
                    if v[2] not in ['rw', 'ro']:
                        error_quit(f"volume mode {v[2]} not supported (only rw and ro)")

                    volumes.append(f"{v_host}|{v[1]}|{v[2]}")
            lab.new_machine(m.name,
                            exec_commands=m.exec_commands,
                            sysctls=m.sysctls,
                            envs=m.envs,
                            ports=m.ports,
                            ulimits=m.ulimits,
                            volumes=volumes,
                            shell=m.kathara_shell,
                            image=m.image,
                            bridged=m.bridged,
                            privileged=m.privileged,
                            entrypoint=m.entrypoint,
                            )
            for net, netAdapter in m.net_adapters.items():
                lab.connect_machine_to_link(m.name, net.name, machine_iface_number=netAdapter.interface,
                                            mac_address=str(netAdapter.mac).replace('-',
                                                                                    ':').lower() if netAdapter.mac is not None else None)
        self.lab_hash = lab.hash
        return lab

    def get_lab_hash(self):
        if self.lab_hash is None:
            lab = Lab(name=self.running_lab_name)
            self.lab_hash = lab.hash
        return self.lab_hash

    def get_lab_from_kathara(self):
        lab_hash = self.get_lab_hash()
        return Kathara.get_instance().get_lab_from_api(lab_hash=lab_hash)

    def get_public_lab_dir(self):
        return params.public_lab_dir(self.running_lab_name)

    def get_private_lab_dir(self):
        return params.private_lab_dir(self.running_lab_name)

    def get_files_dir(self):
        return params.files_dir(self.running_lab_name)

    def get_private_mount_dir(self):
        return params.private_mount_dir(self.running_lab_name)

    def get_user_public_dir(self):
        try:
            return Path(params.link_to_user_public_dir(self.running_lab_name)).readlink()
        except OSError:
            return Path(params.link_to_user_public_dir(self.running_lab_name))

    def get_shared_dir(self):
        return f"{self.get_user_public_dir()}/{params.shared_dir_name}"

    def answers_dir(self):
        return params.answers_dir(self.running_lab_name)

    def answers_file(self):
        return params.answers_filename(self.running_lab_name)


class NetAdapter:
    def __init__(self, network, machine, interface, mac=None, addresses=None):
        if addresses is None:
            addresses = []
        if not isinstance(machine, Machine):
            raise ValueError("machine must an object of class Machine")
        if not isinstance(network, Network):
            raise ValueError("network must be an instance of Network")
        if mac is not None:
            first_byte = int(str(mac).replace('-', ':').split(':')[0], 16)
            if first_byte & 1:
                raise ValueError(
                    f"MAC address {mac} on machine '{machine.name}': "
                    f"multicast bit (LSB of first byte) is set — use a unicast address "
                    f"(first byte must be even, e.g. replace '{hex(first_byte)}' with '{hex(first_byte & 0xfe)}')."
                )
        self.network = network
        self.machine = machine
        self.interface = interface
        self.mac = mac
        self.addresses = addresses
        machine.net_adapters[network] = self
        network.net_adapters[machine] = self


class Network:
    def __init__(self, name, color=None, shape=None):
        self.name = name
        self.color = color
        self.shape = shape
        self.net_adapters = {}

    def get_machines(self):
        for m in self.net_adapters.keys():
            yield m


class Machine:
    def __init__(self, name, image=params.default_docker_image, bridged=False, x11_host=False, mem="",
                 cpus=None, ipv6=None,
                 exec_commands=[],
                 sysctls={},
                 envs={},
                 ports=None, ulimits={}, volumes=[],
                 shell=None,
                 kathara_shell=None,
                 privileged=None, entrypoint=None, args=[],
                 hidden=False,
                 allow_connection=True,
                 color=None,
                 shape=None):
        if ports is None:
            ports = []
        self.name = name
        self.image = image
        self.bridged = bridged
        self.x11_host = x11_host
        self.mem = mem
        self.cpus = cpus
        self.ipv6 = ipv6
        self.exec_commands = exec_commands
        self.sysctls = sysctls
        # Copy: the constructor's mutable default {} is shared across Machines;
        # post-construction mutations in get_new_lab_from_scheme (e.g. SRE_HOST_IP
        # for x11_host machines) must not leak into machines that didn't opt in.
        self.envs = dict(envs)
        self.ports = ports
        self.ulimits = ulimits
        self.volumes = volumes
        self.shell = shell
        self.kathara_shell = kathara_shell
        self.privileged = privileged
        self.entrypoint = entrypoint
        self.args = args
        self.hidden = hidden
        self.allow_connection = allow_connection
        self.shape = shape
        self.color = color

        self.net_adapters = {}

        if params.disable_volume_mount_on_root_partition:
            for v in self.volumes:
                v_host = v[0]
                if v_host.startswith('/'):
                    p = Path(v_host)
                    while not p.exists():
                        p = p.parent
                    if os.stat(p).st_dev == os.stat('/').st_dev:
                        error_quit(
                            f"Machine '{self.name}': volume host path '{v_host}' is on the root partition (disable_volume_mount_on_root_partition=True)")

        if self.privileged and not params.allow_privileged_machines:
            error_quit(
                f"Machine '{self.name}': privileged mode is disabled (allow_privileged_machines=False). Can't run in privileged mode")

        if not self.bridged and len(self.ports) > 0:
            error_quit("To add ports in a machine, you need to activate bridged mode")


class Grade0:
    """Base class for lab evaluation logic.

    Subclasses override :meth:`grade` to *register* tests and questions.  The
    actual execution happens later in :meth:`run_tests`, which drives a
    multi-step loop:

    1. Call :meth:`grade` to register commands (they return placeholder values).
    2. Execute all registered commands in containers (via :mod:`exetests`).
    3. Repeat for each additional step (``self.max_step``).
    4. Call :meth:`grade` a final time — commands now return real results.
    5. Save the archive.

    Key instance attributes available inside ``grade()``:

    * ``self.data`` — the ``Data0`` instance (via ``net_scheme``).
    * ``self.step`` — current step number (1-based).
    * ``self.max_step`` — highest step number registered so far.
    """

    def __init__(self, net_scheme):
        self.net_scheme = net_scheme
        self.archive_dirs = []
        self.files_to_save_in_archives = []
        self._tests = None
        self._allow_errors_in_tests = None
        self.step = 0
        self.max_step = 1
        self._questions = None
        self._questions_order = None
        self._questions_current_order = None
        self._cheat_answers = {}
        self._answers = {}
        self._grade_list = []
        self._grades = {}
        self._grade_parts: list[GradePart] = []
        self._errors = []
        self._total_grade_self_eval = 0
        self._total_max_self_eval = 0
        self._total_grade_exo_eval = 0
        self._total_max_exo_eval = 0
        self._maximum_mark = params.default_maximum_mark
        self._use_numerical_marks = params.use_numerical_marks_by_default
        self._display_marks_in_auto_evaluations = params.display_marks_in_auto_evaluations_by_default
        self._mark_self_eval = None
        self._mark_exo_eval = None
        self._section_counter = []
        self.section_fmt = [('R', 1), ('N', 1), ('l', 2), ('N', 3)]
        self._eval_date = None
        self._re_eval_date = None
        self._default_language = 'en'
        self.auto_eval_count = 0
        self._exam_json = None
        self.full_reset()

    def full_reset(self):
        """Reset all state including tests and answers (called from ``__init__``)."""
        self.step = 0
        self.max_step = 1
        self._tests = {}  # keys : (machine,step)->(cmd, timeout)->(result, code))
        self._allow_errors_in_tests = {}
        self._host_tests = {}  # step -> {(command, timeout): (result, code)}
        self._allow_errors_in_host_tests = {}  # (step, command, timeout) -> True
        self._answers = {}  # hash -> answer
        self._eval_date = None
        self.reset_before_grade()

    def reset_before_grade(self):
        """Clear questions, grade list, and section counters before each call to :meth:`grade`."""
        self._questions = dict()  # hash->Question
        self._questions_order = dict()  # order -> [Question1, Question2, ...]
        self._questions_current_order = 100
        self._cheat_answers = {}  # state->(question_hash->answer)
        self._grade_list = []
        self._grades = dict()  # title -> GradeElement
        self._grade_parts = []
        self._section_counter = []

    def grade(self):
        """Override to register tests, questions, and grade elements.

        Called multiple times during :meth:`run_tests` — once per step plus a
        final time when all results are available.  Do **not** produce side-effects
        here; only call ``self.test()``, ``self.question_*()`` and
        ``self.add_grade_element()`` / ``self.set_grade()``.
        """
        self._grade_list = []
        self._grade_parts = []

    def _compute_mark(self, total_grade, total_max):
        """Compute a mark from a ``(total_grade, total_max)`` pair.

        Returns ``None`` if ``total_max == 0``.
        Numerical mode (default): rounded to one decimal, scaled to ``_maximum_mark``.
        Letter mode: A+/A/B/C/D/F.
        """
        if total_max == 0:
            return None
        if self._use_numerical_marks:
            return math.ceil(10 * self._maximum_mark * total_grade / total_max) / 10
        else:
            ratio = total_grade / total_max
            if ratio >= 18 / 20:
                return "A+"
            elif ratio >= 16 / 20:
                return "A"
            elif ratio >= 14 / 20:
                return "B"
            elif ratio >= 12 / 20:
                return "C"
            elif ratio >= 10 / 20:
                return "D"
            else:
                return "F"

    def mark_self_eval(self):
        """Final mark over elements visible in self-eval (scope & SELF_EVAL_SCOPE)."""
        return self._compute_mark(self._total_grade_self_eval, self._total_max_self_eval)

    def mark_exo_eval(self):
        """Final mark over elements visible in non-auto eval / outline / sheet."""
        return self._compute_mark(self._total_grade_exo_eval, self._total_max_exo_eval)

    def get_data(self):
        return self.net_scheme.get_data()

    def get_errors(self):
        return self._errors

    def get_grade_list(self):
        return self._grade_list

    def get_grade_parts(self):
        return self._grade_parts

    def get_answers(self):
        return self._answers

    def get_cheat_answers(self, state: str):
        return self._cheat_answers.get(state)

    def get_tests(self):
        return self._tests

    def get_exetests_strings(self, step: int):
        result = dict()
        for (machine, step1) in self._tests.keys():
            if step != step1:
                continue
            result[machine] = params.exetests_separator.join(
                [f"{timeout}:{cmd}" for (cmd, timeout) in self._tests[(machine, step)].keys()])
        return result

    def get_running_lab_name(self):
        return self.net_scheme.running_lab_name

    def increment_section_counter(self, level: int):
        if len(self._section_counter) < level + 1:
            self._section_counter += [0 for i in range(level + 1 - len(self._section_counter))]
        else:
            self._section_counter = self._section_counter[:(level + 1)]
        self._section_counter[level] += 1

    def set_section_counter(self, level: int, value: int):
        if len(self._section_counter) < level + 1:
            self._section_counter += [0 for i in range(level + 1 - len(self._section_counter))]
        else:
            self._section_counter = self._section_counter[:(level + 1)]
        self._section_counter[level] = value

    def section(self, level: int = 0, fmt=None, show: int = None, pad: str = None):
        self.increment_section_counter(level)
        return self.current_section(level, fmt, show, pad)

    def current_section(self, level: int = 0, fmt=None, show: int = None, pad: str = None):
        # fmt is a list of (type, depth[, prefix]) tuples, one per level.
        # type: R=ROMAN, r=roman, L=Letters, l=letters, N=number
        # depth: how many consecutive counters to display, ending at this level
        # prefix: optional string prepended to the result (default: '')
        # e.g. [('R',1),('N',2,' ')] → level 0: "I." / level 1: " I.1."
        if fmt is None:
            fmt = self.section_fmt

        def _to_roman(n: int) -> str:
            vals = [
                (1000, 'M'), (900, 'CM'), (500, 'D'), (400, 'CD'),
                (100, 'C'), (90, 'XC'), (50, 'L'), (40, 'XL'),
                (10, 'X'), (9, 'IX'), (5, 'V'), (4, 'IV'), (1, 'I'),
            ]
            result = ''
            for value, numeral in vals:
                while n >= value:
                    result += numeral
                    n -= value
            return result

        def _to_capital_letter(n: int) -> str:
            result = ''
            while n > 0:
                n, r = divmod(n - 1, 26)
                result = chr(ord('A') + r) + result
            return result

        def _to_lowercase_letter(n: int) -> str:
            result = ''
            while n > 0:
                n, r = divmod(n - 1, 26)
                result = chr(ord('a') + r) + result
            return result

        def _convert(n: int, fmt_type: str) -> str:
            match fmt_type:
                case 'R':
                    return _to_roman(n)
                case 'r':
                    return _to_roman(n).lower()
                case 'L':
                    return _to_capital_letter(n)
                case 'l':
                    return _to_lowercase_letter(n)
                case _:
                    return str(n)

        entry = fmt[level] if level < len(fmt) else ('N', level + 1)
        _, depth = entry[:2]
        prefix = pad if pad is not None else (entry[2] if len(entry) > 2 else '')
        if show is not None:
            depth = show
        start = max(0, level - depth + 1)
        parts = [_convert(self._section_counter[j] if j < len(self._section_counter) else 0,
                          fmt[j][0] if j < len(fmt) else 'N')
                 for j in range(start, level + 1)]
        return prefix + ".".join(parts) + ". "

    def load_answers(self):
        """Load student answers from ``answers.json`` into ``self._answers``."""
        self._answers = {}
        try:
            fd = os.open(params.answers_filename(running_lab_name=self.get_running_lab_name()),
                         os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as f:
                self._answers = json.load(f)
        except (OSError, json.JSONDecodeError):
            self._answers = {}

    def get_questions_ordered(self):
        q = []
        for _, v in sorted(self._questions_order.items()):
            q += v
        return q

    def export_questions(self):
        pass

    def test_host(self, command, step=1, timeout: int = params.default_timeout, default_value='',
                  default_code: int = 0, allow_error: bool = False):
        """Register and retrieve the result of a host-side test command.

        On the first call (registration pass) returns *default_value* / *default_code*.
        On subsequent calls (result pass) returns the actual ``(stdout, exit_code)``.
        Set *allow_error* to suppress error recording on non-zero exit.
        """
        if params.execute_commands_on_host is False:
            sys.exit("test_host() is disabled by params.execute_commands_on_host")
        if self.max_step < step:
            self.max_step = step
        if step not in self._host_tests:
            self._host_tests[step] = {}
        if allow_error and (step, command, timeout) not in self._allow_errors_in_host_tests:
            self._allow_errors_in_host_tests[(step, command, timeout)] = True
        if (command, timeout) not in self._host_tests[step]:
            self._host_tests[step][(command, timeout)] = (default_value, default_code)
            return default_value, default_code
        return self._host_tests[step][(command, timeout)]

    def test(self, machine_name, command, step=1, timeout: int = params.default_timeout, default_value='',
             default_code: int = 0, allow_error: bool = False):
        """Register and retrieve the result of a command executed inside *machine_name*.

        On the first call (registration pass) returns *default_value* / *default_code*.
        On subsequent calls (result pass) returns the actual ``(stdout, exit_code)``.
        *timeout* is in seconds.  Set *allow_error* to suppress error recording.
        """
        if self.max_step < step:
            self.max_step = step
        if (machine_name, step) not in self._tests:
            self._tests[(machine_name, step)] = {}
        if allow_error and (machine_name, step, command, timeout) not in self._allow_errors_in_tests:
            self._allow_errors_in_tests[(machine_name, step, command, timeout)] = True
        if (command, timeout) not in self._tests[(machine_name, step)]:
            self._tests[(machine_name, step)][(command, timeout)] = (default_value, default_code)
            return default_value, default_code
        return self._tests[(machine_name, step)][(command, timeout)]

    @staticmethod
    def _apply_section(section: str, title) -> TranslatedText:
        """Prepend *section* to every language value in *title*."""
        tt = TranslatedText.from_value(title)
        if not section:
            return tt
        return TranslatedText({lang: section + text for lang, text in tt.items()})

    def question_text(self, title, section='', description='', hash=None, order=None, default_answer='',
                      cheat_answers=None):
        """Register a free-text question and return the student's current answer string.

        Returns *default_answer* if the student has not answered yet.
        *cheat_answers* maps state names to answer strings used in automated testing.
        """
        title = self._apply_section(section, title)
        if order is None:
            order1 = self._questions_current_order
            self._questions_current_order = ((self._questions_current_order // 100) + 1) * 100
        else:
            order1 = order

        q = QuestionText(title, description, hash, order1)
        if order1 not in self._questions_order:
            self._questions_order[order1] = []
        self._questions_order[order1].append(q)

        if q.question_hash in self._questions:
            write_error(f"Duplicate question hash {q.question_hash}")
        self._questions[q.question_hash] = q

        if cheat_answers is not None:
            for state, answer in cheat_answers.items():
                if state not in self._cheat_answers:
                    self._cheat_answers[state] = {}
                self._cheat_answers[state][q.question_hash] = answer

        if q.question_hash in self._answers:
            return self._answers[q.question_hash]
        return default_answer

    _FORM_FIELD_RE = _re.compile(r'@@\{([^:}]+):([^}]*)\}@@')

    def question_form(self, title, section='', description='', hash=None, order=None, cheat_answers=None):
        """Register a form question with inline @@{field_name:regex}@@ fields.

        Returns the student's answers as a dict {field_name: value}, or {} if none yet.
        cheat_answers format: {state_name: {field_name: value, ...}}
        """
        title = self._apply_section(section, title)
        from .common import QuestionForm

        # The @@{field:regex}@@ markers are language-independent, so when the
        # description is a TranslatedText (wrapped in tr()) extract fields from
        # its resolved string. The full TranslatedText is still stored on the
        # question for per-language rendering.
        desc_str = (description.resolve('')
                    if isinstance(description, TranslatedText) else description)

        fields = []
        for m in self._FORM_FIELD_RE.finditer(desc_str):
            name, spec = m.group(1), m.group(2)
            if spec.startswith('>') or '>>>' in spec:
                raw = spec[1:] if spec.startswith('>') else spec
                fields.append({"name": name, "choices": [
                    c.strip().split('>>>')[1].strip() if '>>>' in c.strip() else c.strip()
                    for c in raw.split('|')
                ]})
            elif spec.startswith('?'):
                default = spec[1:].strip().lower() not in ('', 'false')
                fields.append({"name": name, "checkbox": default})
            else:
                fields.append({"name": name, "regex": spec})

        if order is None:
            order1 = self._questions_current_order
            self._questions_current_order = ((self._questions_current_order // 100) + 1) * 100
        else:
            order1 = order

        q = QuestionForm(title, description, hash, order1, fields)
        if order1 not in self._questions_order:
            self._questions_order[order1] = []
        self._questions_order[order1].append(q)

        if q.question_hash in self._questions:
            write_error(f"Duplicate question hash {q.question_hash}")
        self._questions[q.question_hash] = q

        if cheat_answers is not None:
            for state, field_answers in cheat_answers.items():
                if state not in self._cheat_answers:
                    self._cheat_answers[state] = {}
                self._cheat_answers[state][q.question_hash] = json.dumps(
                    field_answers, ensure_ascii=False
                )

        if q.question_hash in self._answers:
            try:
                return json.loads(self._answers[q.question_hash])
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    def question_dummy(self, title, section='', description='', hash=None, order=None):
        """Register a display-only block (no answer widget shown to the student)."""
        title = self._apply_section(section, title)
        if order is None:
            order1 = self._questions_current_order
            self._questions_current_order = ((self._questions_current_order // 100) + 1) * 100
        else:
            order1 = order

        q = QuestionDummy(title, description, hash, order1)
        if order1 not in self._questions_order:
            self._questions_order[order1] = []
        self._questions_order[order1].append(q)

        if q.question_hash in self._questions:
            write_error(f"Duplicate question hash {q.question_hash}")
        self._questions[q.question_hash] = q

    def add_grade_part(self, title, description=''):
        """Register a new :class:`GradePart` group and return it.

        Pass the returned object to ``add_grade_element(..., grade_part=...)``
        to associate elements with this part.  Parts are displayed in
        registration order (with a subtotal row per part) in the GUI
        evaluation view and in ``sre outline`` PDFs.
        """
        if description:
            description = TranslatedText.from_value(description, self._default_language)
        gp = GradePart(title=title, description=description)
        if any(p.title == title for p in self._grade_parts):
            write_error(f"Duplicate grade part title = {title}")
        self._grade_parts.append(gp)
        return gp

    def add_grade_element(self, title, max_grade, description='', grade=0, scope=params.BOTH_EVAL_SCOPE,
                          grade_part=None):
        """Add a graded rubric item.  Initial *grade* defaults to 0; use :meth:`set_grade` to update it.

        ``scope`` is a bitmask: ``SELF_EVAL_SCOPE`` (1) for self-eval only,
        ``EXO_EVAL_SCOPE`` (2) for non-auto eval / outline / sheet only,
        ``BOTH_EVAL_SCOPE`` (3, default) for both audiences.

        ``grade_part`` optionally associates this element with a
        :class:`GradePart` previously returned by :meth:`add_grade_part`.
        """
        if scope not in params.grade_scopes:
            raise ValueError(f"Invalid scope {scope!r}; expected one of {params.grade_scopes}")
        if description:
            description = TranslatedText.from_value(description, self._default_language)
        grade_part_title = None
        if grade_part is not None:
            if not isinstance(grade_part, GradePart):
                raise TypeError(f"grade_part must be a GradePart, got {type(grade_part).__name__}")
            if grade_part not in self._grade_parts:
                write_error(f"Unregistered grade part {grade_part.title!r} passed to add_grade_element")
            grade_part_title = grade_part.title
        g = GradeElement(title=title, max_grade=max_grade, description=description, grade=grade, scope=scope,
                         grade_part=grade_part_title)
        self._grade_list.append(g)
        key = _tt_hash_str(title)
        if key in self._grades:
            write_error(f"Duplicate grade title = {title}")
        self._grades[key] = g

    def set_grade(self, title, grade):
        """Set the numeric *grade* for the element previously registered under *title*."""
        self._grades[_tt_hash_str(title)].grade = grade

    def save_lab_info(self):
        debug_project = os.path.exists(
            params.debug_project_marker_filename(self.net_scheme.running_lab_name)
        )
        if debug_project:
            visible_machines = list(self.net_scheme.get_machines())
        else:
            visible_machines = [m for m in self.net_scheme.get_machines() if not m.hidden]
        lab_hash = self.net_scheme.get_lab_hash()

        def _get_stats(m):
            s = next(Kathara.get_instance().get_machine_stats(lab_hash=lab_hash, machine_name=m.name), None)
            return m, s

        stats_map = {}
        with ThreadPoolExecutor(max_workers=min(params.max_docker_concurrency, len(visible_machines))) as executor:
            for m, s in executor.map(_get_stats, visible_machines):
                stats_map[m.name] = (m, s)

        info_machines = []
        for m in visible_machines:
            m, s = stats_map[m.name]
            interfaces = []
            for net, netAdapter in m.net_adapters.items():
                interfaces.append(InfoInterface(network=net.name, interface_name=f"eth{netAdapter.interface}"))
            info_machines.append(
                InfoMachine(name=m.name, status=s.status if s is not None else "", hidden=m.hidden,
                            bridged=m.bridged,
                            x11_host=m.x11_host,
                            ports=m.ports,
                            allow_connection=m.allow_connection,
                            color=m.color or "",
                            shape=m.shape or "",
                            interfaces=interfaces))

        network_colors = {
            net.name: net.color
            for m in visible_machines
            for net in m.net_adapters
            if net.color
        }
        network_shapes = {
            net.name: net.shape
            for m in visible_machines
            for net in m.net_adapters
            if net.shape
        }

        module_rvlab = sys.modules[params.srelab_py_name.removesuffix(".py")]
        default_language = getattr(module_rvlab, 'default_language', 'en')
        self._default_language = default_language
        show_nat_network = getattr(module_rvlab, 'show_nat_network', params.default_show_nat_network)
        nat_network_name = getattr(module_rvlab, 'host_network_name', params.default_host_network_name)
        nat_network_color = getattr(module_rvlab, 'host_network_color', params.default_host_network_color)
        host_network_exploded = getattr(module_rvlab, 'host_network_exploded',
                                        params.default_host_network_exploded)
        host_network_edge_relative_length = float(getattr(
            module_rvlab, 'host_network_edge_relative_length',
            params.default_host_network_edge_relative_length))
        schema_splines = getattr(module_rvlab, 'schema_splines', params.graphviz_default_splines)
        schema_overlap = getattr(module_rvlab, 'schema_overlap', params.graphviz_default_overlap)

        if self.step == 0:
            self.grade()
            self.step += 1

        questions = self.get_questions_ordered()

        if hasattr(module_rvlab, 'title'):
            title = module_rvlab.title
        else:
            lab_name = params.get_lab_name_from_running_lab_name(self.get_running_lab_name())
            title = lab_name.removesuffix('.py')
        title = TranslatedText.from_value(title, default_language)

        if hasattr(module_rvlab, 'delay_between_self_grade'):
            delay_between_self_grade = module_rvlab.delay_between_self_grade
        else:
            delay_between_self_grade = 0

        if hasattr(module_rvlab, 'allow_self_grade'):
            allow_self_grade = module_rvlab.allow_self_grade
        else:
            allow_self_grade = False

        if debug_project:
            delay_between_self_grade = 0
            allow_self_grade = True
        if hasattr(module_rvlab, 'export_kathara_project'):
            export_kathara_project = module_rvlab.export_kathara_project
        else:
            export_kathara_project = False

        eval_interval_without_exam_mode = getattr(module_rvlab, 'eval_interval_without_exam_mode', params.default_eval_interval_without_exam_mode)
        eval_before_exit = getattr(module_rvlab, 'eval_before_exit', False)

        informations = TranslatedText.from_value(self.net_scheme.informations, default_language)
        for q in questions:
            q.title = TranslatedText.from_value(q.title, default_language)
            q.description = TranslatedText.from_value(q.description, default_language)

        net_scheme_cls = type(self.net_scheme)
        if debug_project:
            user_allowed_states_raw = {}
            for state in net_scheme_cls.get_state_methods():
                desc = ''
                for klass in net_scheme_cls.__mro__:
                    fn = klass.__dict__.get(state)
                    if fn is not None and getattr(fn, '_is_sre_state', False):
                        desc = getattr(fn, '_sre_state_description', '')
                        break
                user_allowed_states_raw[state] = desc
        else:
            user_allowed_states_raw = (
                net_scheme_cls.get_user_allowed_states()
                if getattr(module_rvlab, 'allow_user_states', False) else {}
            )
        user_allowed_states = {
            state: TranslatedText.from_value(desc, default_language) if desc else desc
            for state, desc in user_allowed_states_raw.items()
        }

        if debug_project:
            module_allows_user_states = getattr(module_rvlab, 'allow_user_states', False)
            admin_only_states = [
                state for state in user_allowed_states_raw
                if not module_allows_user_states
                or not net_scheme_cls.is_state_user_allowed(state)
            ]
        else:
            admin_only_states = []

        info = InfoLab(lab_name=self.net_scheme.lab_name, lab_hash=self.net_scheme.lab_hash,
                       title=title, machines=info_machines, delay_between_self_grade=delay_between_self_grade,
                       questions=questions, informations=informations,
                       export_kathara_project=export_kathara_project, allow_self_grade=allow_self_grade,
                       debug_project=debug_project,
                       eval_interval_without_exam_mode=eval_interval_without_exam_mode,
                       eval_before_exit=eval_before_exit,
                       default_language=default_language,
                       user_allowed_states=user_allowed_states,
                       admin_only_states=admin_only_states,
                       network_colors=network_colors,
                       network_shapes=network_shapes,
                       show_nat_network=show_nat_network,
                       nat_network_name=nat_network_name,
                       nat_network_color=nat_network_color,
                       host_network_exploded=host_network_exploded,
                       host_network_edge_relative_length=host_network_edge_relative_length,
                       schema_splines=schema_splines,
                       schema_overlap=schema_overlap)

        info_json = info.to_json()
        info_filename = params.info_filename(self.net_scheme.running_lab_name)

        save_info_json = None
        try:
            with open(info_filename, "r") as f:
                save_info_json = f.read()
        except FileNotFoundError:
            pass
        if save_info_json == info_json:
            return

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            dir=Path(self.net_scheme.get_public_lab_dir()).parent)
        with open(temp_file.name, "w") as f:
            print(info_json, file=f)
            f.flush()
            os.fsync(f.fileno())
            os.chmod(temp_file.name, 0o644)
        os.replace(temp_file.name, info_filename)

    def add_error(self, error, category=ErrorCategory.ERROR, step: int = 1):
        if self.step != step:
            return
        log_error(error)
        self._errors.append((category.value, error))

    def add_warning(self, warning, step: int = 1):
        self.add_error(warning, category=ErrorCategory.WARNING, step=step)

    @staticmethod
    def run_tests_on_machine(machine_name, machine, exetests):
        environment = {params.exetests_env_name: exetests}
        code, output = machine.api_object.exec_run([params.exetests_machines_path],
                                                   stdin=False,
                                                   stdout=True,
                                                   stderr=False,
                                                   tty=False,
                                                   environment=environment,
                                                   )
        return machine_name, code, output

    def run_tests(self):
        self._tests = {}
        self._section_counter = []
        lab = self.net_scheme.get_lab_from_kathara()
        self._errors = []
        self.load_answers()
        self._eval_date = datetime.datetime.now().isoformat()

        while self.step <= self.max_step:
            self.reset_before_grade()
            self.grade()
            self.step += 1
            tests = self.get_tests()
            exetests_by_machine = self.get_exetests_strings(self.step)
            if SRE.args.debug and self.step <= self.max_step:
                log_debug(f"Commands step {self.step} (after running grade on step {self.step - 1}):")
                for machine, cmds in exetests_by_machine.items():
                    c = cmds.split(params.exetests_separator)
                    c1 = " - ".join(c)
                    log_debug(f"{machine}: {c1}")

            results = {}
            with ThreadPoolExecutor(
                    max_workers=max(1, min(params.max_docker_concurrency, len(lab.machines)))) as executor:
                futures_to_machines = {
                    executor.submit(
                        Grade0.run_tests_on_machine,
                        machine_name,
                        machine,
                        exetests_by_machine[machine_name],
                    ): machine_name
                    for machine_name, machine in lab.machines.items()
                    if machine_name in exetests_by_machine and len(exetests_by_machine[machine_name]) > 0
                }
                for future in as_completed(futures_to_machines):
                    machine_name = futures_to_machines[future]
                    try:
                        machine_name, code, output = future.result()
                        results[machine_name] = (code, output)
                    except Exception as e:
                        self.add_error(f"error during test execution on machine {machine_name}: {e}", step=self.step)
                        continue

            for machine_name, (exetests_code, output) in results.items():
                if (machine_name, self.step) not in self._tests:
                    self._tests[(machine_name, self.step)] = {}
                if exetests_code != 0:
                    self.add_error(
                        f"exetests error on {machine_name}: {exetests_by_machine[machine_name]} -- return code {exetests_code}",
                        step=self.step)
                output1 = output.decode("utf-8")
                separator, _, rest = output1.partition("\n")
                output2 = rest.split(f"\n{separator}\n")
                for i in range(0, len(output2), 2):
                    ligne1 = ""
                    try:
                        ligne1, date1, result = output2[i].split("\n", 2)
                    except ValueError:
                        result = ""
                    if not ligne1:
                        continue
                    timeout_s, cmd = ligne1.split(":", 1)
                    timeout = int(timeout_s)
                    date2, code_s = output2[i + 1].split("\n", 1)
                    try:
                        code = int(code_s.strip())
                    except ValueError:
                        code = -2
                        self.add_error(f"test error on {machine_name}:{self.step}:{cmd} illegal error code",
                                       step=self.step)
                    if code != 0:
                        if not self._allow_errors_in_tests.get((machine_name, self.step, cmd, timeout), False):
                            self.add_error(f"test error on {machine_name}:{cmd} code={code}", step=self.step)
                    self._tests[(machine_name, self.step)][cmd, timeout] = (result, code)
            if SRE.args.debug:
                for machine_name in lab.machines:
                    if (machine_name, self.step) not in self._tests:
                        continue
                    for (cmd, timeout) in self._tests[(machine_name, self.step)]:
                        log_debug(f"machine {machine_name} - step {self.step} - command {cmd} - timeout {timeout}:")
                        result, code = self._tests[(machine_name, self.step)][cmd, timeout]
                        log_debug(result)
                        log_debug(f"-------- exit code {code}\n")

            host_step_cmds = self._host_tests.get(self.step, {})
            if host_step_cmds:
                def _run_host_cmd(cmd, t):
                    from .utils_privileges import preexec_drop_to_sre
                    run_cmd = shlex.split(cmd) if params.execute_commands_on_host == "split" else cmd
                    use_shell = params.execute_commands_on_host == "shell"
                    try:
                        proc = subprocess.run(
                            run_cmd, shell=use_shell, capture_output=True, text=True,
                            timeout=t if t > 0 else None,
                            preexec_fn=preexec_drop_to_sre,
                        )
                        return cmd, t, proc.stdout, proc.returncode
                    except subprocess.TimeoutExpired:
                        return cmd, t, '', -1
                    except Exception:
                        return cmd, t, '', -2

                with ThreadPoolExecutor(max_workers=min(params.max_docker_concurrency,
                                                        len(host_step_cmds))) as executor:
                    futures = {executor.submit(_run_host_cmd, cmd, t): (cmd, t)
                               for (cmd, t) in host_step_cmds}
                    for future in as_completed(futures):
                        cmd, t, result, code = future.result()
                        if code != 0:
                            if not self._allow_errors_in_host_tests.get((self.step, cmd, t), False):
                                self.add_error(f"host test error: {cmd} code={code}", step=self.step)
                        self._host_tests[self.step][(cmd, t)] = (result, code)
                        if SRE.args.debug:
                            log_debug(f"host - step {self.step} - command {cmd} - timeout {t}:")
                            log_debug(result)
                            log_debug(f"-------- exit code {code}\n")

        if SRE.args.debug and len(self._errors) > 0:
            log_debug(f"{len(self._errors)} errors:\n " + "\n".join(f"[{e[0]}] {e[1]}" for e in self._errors))
        self.compute_total()
        self._mark_self_eval = self.mark_self_eval()
        self._mark_exo_eval = self.mark_exo_eval()
        # log_error(f"DEBUG _tests at save: {len(self._tests)} machine-step entries")
        # for (machine, step), cmds in self._tests.items():
        #     for (cmd, timeout), (result, code) in cmds.items():
        #         log_error(f"  [{machine}][step={step}] cmd={cmd!r} result_len={len(result)} code={code}")

    def compute_total(self):
        """Accumulate per-scope totals in one pass; BOTH-scope elements contribute to both."""
        self._total_grade_self_eval = 0
        self._total_max_self_eval = 0
        self._total_grade_exo_eval = 0
        self._total_max_exo_eval = 0
        for g in self._grade_list:
            if g.scope & params.SELF_EVAL_SCOPE:
                self._total_grade_self_eval += g.grade
                self._total_max_self_eval += g.max_grade
            if g.scope & params.EXO_EVAL_SCOPE:
                self._total_grade_exo_eval += g.grade
                self._total_max_exo_eval += g.max_grade

    def save_tests(self):
        now = datetime.datetime.now()
        if self._exam_json is None:
            exam_path = Path(params.sre_pub_dir) / params.exam_json_name
            try:
                self._exam_json = json.loads(exam_path.read_text())
            except FileNotFoundError:
                pass
            except Exception as e:
                log_error(f"can't read {exam_path}: {e}")
        for d1 in self.archive_dirs:
            d = Path(d1).expanduser().resolve()
            try:
                if not d.exists():
                    os.mkdir(d, 0o700)
                else:
                    os.listdir(d)  # trigger mount / catch stale handle early
                    permissions = os.stat(d).st_mode
                    if permissions != 0o700:
                        os.chmod(d, 0o700)
                filename = d / params.get_archive_name(self.net_scheme.running_lab_name, now)
                self.save_tests_on_file(str(filename))
            except Exception as e:
                log_error(f"can't save archive to {d}: {e}")

    def save_tests_on_file(self, filename: str):
        files_content = {}
        if self.files_to_save_in_archives:
            fdir = Path(params.files_dir(self.get_running_lab_name()))
            if fdir.is_dir():
                for pattern in self.files_to_save_in_archives:
                    for fpath in fdir.iterdir():
                        if fpath.is_file() and fnmatch.fnmatch(fpath.name, pattern):
                            try:
                                files_content[fpath.name] = fpath.read_bytes()
                            except Exception:
                                pass
        archive = {
            params.running_lab_name_keyword: self.get_running_lab_name(),
            params.eval_date_keyword: self._eval_date,
            params.re_eval_date_keyword: self._re_eval_date,
            'data_json': self.get_data().to_json(),
            'tests': self.get_tests(),
            'errors': self.get_errors(),
            'answers': self.get_answers(),
            'grade_list': [asdict(e) for e in self._grade_list],
            'grade_parts': [asdict(p) for p in self._grade_parts],
            'total_grade_self_eval': self._total_grade_self_eval,
            'total_max_self_eval': self._total_max_self_eval,
            'mark_self_eval': self._mark_self_eval,
            'total_grade_exo_eval': self._total_grade_exo_eval,
            'total_max_exo_eval': self._total_max_exo_eval,
            'mark_exo_eval': self._mark_exo_eval,
            'maximum_mark': self._maximum_mark,
            'files': files_content,
        }
        if self._exam_json is not None:
            archive[params.exam_json_keyword] = self._exam_json
        cctx = zstd.ZstdCompressor(level=6)
        with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=os.path.dirname(filename),
                delete=False
        ) as f:
            with cctx.stream_writer(f) as compressor:
                packed = msgpack.packb(archive, use_bin_type=True)
                compressor.write(packed)
            # f.flush()
            # os.fsync(f.fileno())
            temp_name = f.name
        os.replace(temp_name, filename)
