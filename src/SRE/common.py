import hashlib
import json
from dataclasses import dataclass, asdict, field
from typing import List

import msgpack
from enum import Enum


class TranslatedText(dict):
    """A dict subclass holding translations keyed by language code (e.g. 'en', 'fr').

    Use ``resolve(lang)`` to get the text for a specific language, falling back to the
    first available translation.  ``from_value`` ensures backward-compat with plain strings.
    """

    def resolve(self, lang: str, fallback: str = '') -> str:
        return self.get(lang) or next(iter(self.values()), fallback)

    def resolve_priority(self, langs: list, fallback: str = '') -> str:
        """Return the first translation found in the priority list, or first available."""
        for lang in langs:
            if self.get(lang):
                return self[lang]
        return next(iter(self.values()), fallback)

    def __add__(self, other) -> 'TranslatedText':
        if isinstance(other, str):
            return TranslatedText({lang: self[lang] + other for lang in self})
        if not isinstance(other, TranslatedText):
            return NotImplemented
        if not self:
            return TranslatedText(other)
        if not other:
            return TranslatedText(self)
        # Merge mismatched language sets gracefully (partial translations): take
        # the union of languages, falling back to each side's default-language
        # (first-key) value for a language that side lacks.
        self_default = next(iter(self.values()))
        other_default = next(iter(other.values()))
        langs = list(dict.fromkeys((*self, *other)))
        return TranslatedText({
            lang: self.get(lang, self_default) + other.get(lang, other_default)
            for lang in langs
        })

    def __radd__(self, other) -> 'TranslatedText':
        if isinstance(other, str):
            return TranslatedText({lang: other + self[lang] for lang in self})
        return NotImplemented

    def format(self, **kwargs) -> 'TranslatedText':
        """Apply str.format(**kwargs) to every language value."""
        return TranslatedText({lang: text.format(**kwargs) for lang, text in self.items()})

    @classmethod
    def from_value(cls, v, default_lang: str = 'en') -> 'TranslatedText':
        if isinstance(v, cls):
            return v
        if isinstance(v, dict):
            return cls(v)
        return cls({default_lang: str(v)}) if v else cls()


def _tt_hash_str(v) -> str:
    """Stable string representation of a TranslatedText (or plain str) for hashing."""
    return json.dumps(dict(sorted(TranslatedText.from_value(v).items())), ensure_ascii=False)


class QuestionType(Enum):
    DUMMY = 0
    TEXT = 1
    FORM = 2


class Question:
    """Abstract base for all question types (TEXT, FORM, DUMMY)."""

    def __init__(self, title, description, question_hash, order, question_type):
        self.title = title
        self.description = description
        self.question_hash = question_hash
        self.order = order
        self.question_type = question_type



@dataclass
class QuestionText(Question):
    """A free-text answer question.  Hash is derived from *title* if not provided."""

    title: TranslatedText | str
    description: TranslatedText | str
    question_hash: str
    order: int
    question_type: int = QuestionType.TEXT.value

    def __init__(self, title, description='', question_hash=None, order=None, **kwargs):
        super().__init__(title, description, question_hash, order, question_type=QuestionType.TEXT)
        if question_hash is None:
            self.question_hash = hashlib.sha256(_tt_hash_str(title).encode('UTF-8')).hexdigest()
        else:
            self.question_hash = question_hash
        self.question_type = QuestionType.TEXT.value

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_data: str) -> "QuestionText":
        d = json.loads(json_data)
        if isinstance(d.get('title'), dict):
            d['title'] = TranslatedText(d['title'])
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)


@dataclass
class QuestionDummy(Question):
    """A display-only block (no answer input).  Hash derived from title + description."""

    title: TranslatedText | str
    description: TranslatedText | str
    question_hash: str
    order: int
    question_type: int = QuestionType.DUMMY.value

    def __init__(self, title, description, question_hash=None, order=None, **kwargs):
        super().__init__(title, description, question_hash, order, question_type=QuestionType.DUMMY)
        if question_hash is None:
            self.question_hash = hashlib.sha256(
                (_tt_hash_str(title) + '--' + _tt_hash_str(description)).encode('UTF-8')
            ).hexdigest()
        else:
            self.question_hash = question_hash
        self.question_type = QuestionType.DUMMY.value

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_data: str) -> "QuestionDummy":
        d = json.loads(json_data)
        if isinstance(d.get('title'), dict):
            d['title'] = TranslatedText(d['title'])
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)


@dataclass
class QuestionForm(Question):
    """A structured-form question with ``@@{field:regex}@@`` inline markers.

    ``fields`` is a list of dicts, each either ``{"name": str, "regex": str}``
    for a text input or ``{"name": str, "choices": [...]}`` for a dropdown.
    """

    title: TranslatedText | str
    description: TranslatedText | str
    question_hash: str
    order: int
    fields: list  # [{"name": str, "regex": str}, ...]
    question_type: int = QuestionType.FORM.value

    def __init__(self, title, description, question_hash=None, order=None, fields=None, **kwargs):
        super().__init__(title, description, question_hash, order, question_type=QuestionType.FORM)
        if question_hash is None:
            self.question_hash = hashlib.sha256(
                (_tt_hash_str(title) + '--' + _tt_hash_str(description)).encode('UTF-8')
            ).hexdigest()
        else:
            self.question_hash = question_hash
        self.fields = fields or []
        self.question_type = QuestionType.FORM.value

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_data: str) -> "QuestionForm":
        d = json.loads(json_data)
        if isinstance(d.get('title'), dict):
            d['title'] = TranslatedText(d['title'])
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)


@dataclass
class GradeElement:
    """One entry in a grade rubric.

    Either numeric (``grade`` / ``max_grade``) or letter-graded (``grade_letter`` ∈ OK/MEH/FAIL).
    Call ``to_grade_letter()`` to convert a numeric element to its letter equivalent.

    ``scope`` is a bitmask: bit 0 (SELF_EVAL_SCOPE=1) makes the element visible in
    user-triggered self-eval (``sre eval --auto-eval``); bit 1 (EXO_EVAL_SCOPE=2)
    makes it visible in non-user-triggered eval, ``sre outline`` and ``sre sheet``.
    Default 3 (BOTH_EVAL_SCOPE) means visible in both.
    """

    title: str
    max_grade: float | None = None
    grade: float | None = None
    grade_letter: str | None = None
    description: TranslatedText | str = ""
    scope: int = 3
    grade_part: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "GradeElement":
        d = dict(d)
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)

    def pack(self) -> bytes:
        return msgpack.packb(self.to_dict(), use_bin_type=True)

    @classmethod
    def unpack(cls, data: bytes) -> "GradeElement":
        return cls.from_dict(msgpack.unpackb(data, raw=False))

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, s: str) -> "GradeElement":
        d = json.loads(s)
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)

    def to_grade_letter(self) -> "GradeElement":
        if self.grade == self.max_grade:
            letter = "OK"
        elif self.grade is not None and self.grade != 0:
            letter = "MEH"
        else:
            letter = "FAIL"
        return GradeElement(title=self.title, max_grade=None, grade=None, grade_letter=letter,
                            description=self.description, scope=self.scope,
                            grade_part=self.grade_part)


@dataclass
class GradePart:
    """A named group of GradeElements with a shared title and description.

    Lab code registers parts via ``Grade.add_grade_part()`` and associates
    each :class:`GradeElement` with one via the ``grade_part=`` kwarg on
    ``add_grade_element``.  The element stores the part's *title* (not the
    object) so it serializes cleanly to JSON / msgpack.
    """

    title: str
    description: TranslatedText | str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "GradePart":
        d = dict(d)
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)

    def pack(self) -> bytes:
        return msgpack.packb(self.to_dict(), use_bin_type=True)

    @classmethod
    def unpack(cls, data: bytes) -> "GradePart":
        return cls.from_dict(msgpack.unpackb(data, raw=False))

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, s: str) -> "GradePart":
        d = json.loads(s)
        if isinstance(d.get('description'), dict):
            d['description'] = TranslatedText(d['description'])
        return cls(**d)


@dataclass
class InfoInterface:
    """Network interface descriptor stored inside ``InfoMachine``."""

    network: str
    interface_name: str

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_data: str) -> "InfoInterface":
        return cls(**json.loads(json_data))


@dataclass
class InfoMachine:
    """Runtime snapshot of a single container, written to ``info.json`` by the CLI and read by the GUI."""

    name: str
    status: str
    allow_connection: bool
    hidden: bool
    interfaces: List[InfoInterface]
    ports: List[str]
    bridged: bool
    x11_host: bool = False
    color: str = ""
    shape: str = ""

    def to_json(self):
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_data: str) -> "InfoMachine":
        return cls(**json.loads(json_data))


@dataclass
class InfoLab:
    """Full lab metadata written to ``info.json`` at ``sre start`` and polled by the GUI every second.

    ``informations`` (not ``description``) holds the Markdown lab description.
    ``questions`` is a list of ``QuestionText | QuestionDummy | QuestionForm`` instances.
    """

    lab_name: str
    lab_hash: str
    title: TranslatedText
    informations: TranslatedText
    export_kathara_project: bool
    allow_self_grade: bool
    machines: List[InfoMachine]
    questions: List[Question]
    delay_between_self_grade: int
    eval_interval_without_exam_mode: int
    eval_before_exit: bool
    user_allowed_states: dict
    debug_project: bool = False
    admin_only_states: list = field(default_factory=list)
    default_language: str = ''
    network_colors: dict = field(default_factory=dict)
    network_shapes: dict = field(default_factory=dict)
    show_nat_network: bool = False
    nat_network_name: str = ''
    nat_network_color: str = ''
    host_network_exploded: bool = False
    host_network_edge_relative_length: float = 1.0
    schema_splines: str = 'curved'
    schema_overlap: str = 'prism'

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)

    @classmethod
    def from_json(cls, s: str) -> "InfoLab":
        d = json.loads(s)

        def _wrap_q(item: dict) -> dict:
            item = dict(item)
            item['title'] = TranslatedText.from_value(item.get('title', ''))
            item['description'] = TranslatedText.from_value(item.get('description', ''))
            return item

        return cls(
            lab_name=d["lab_name"],
            lab_hash=d["lab_hash"],
            title=TranslatedText.from_value(d["title"]),
            informations=TranslatedText.from_value(d.get("informations", "")),
            export_kathara_project=d.get("export_kathara_project", True),
            allow_self_grade=d.get("allow_self_grade", False),
            debug_project=d.get("debug_project", False),
            delay_between_self_grade=d.get("delay_between_self_grade", 0),
            eval_interval_without_exam_mode=d.get("eval_interval_without_exam_mode", 0),
            eval_before_exit=d.get("eval_before_exit", False),
            user_allowed_states=d.get("user_allowed_states", {}),
            admin_only_states=list(d.get("admin_only_states", []) or []),
            default_language=d.get("default_language", ''),
            network_colors=d.get("network_colors", {}),
            network_shapes=d.get("network_shapes", {}),
            show_nat_network=d.get("show_nat_network", False),
            nat_network_name=d.get("nat_network_name", ''),
            nat_network_color=d.get("nat_network_color", ''),
            host_network_exploded=d.get("host_network_exploded", False),
            host_network_edge_relative_length=float(d.get("host_network_edge_relative_length", 1.0)),
            schema_splines=d.get("schema_splines", "curved"),
            schema_overlap=d.get("schema_overlap", "prism"),
            machines=[InfoMachine(**item) for item in d["machines"]],
            questions=[
                QuestionDummy(**_wrap_q(item)) if item.get("question_type") == QuestionType.DUMMY.value
                else QuestionForm(**_wrap_q(item)) if item.get("question_type") == QuestionType.FORM.value
                else QuestionText(**_wrap_q(item))
                for item in d["questions"]
            ],
        )
