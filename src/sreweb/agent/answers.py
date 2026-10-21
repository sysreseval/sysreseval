"""``answers/answers.json`` of a project, written by the agent on behalf of a browser user.

The Qt GUI writes the file itself on every keystroke, with the identity of the desktop session;
here the browser sends the changed answers (``PUT``) and the agent merges them under the
project's answers lock, adds the metadata from the identity the portal relayed
(``SRE.answers.with_metadata``) and the hostname of the pool host, and writes the file atomically,
readable by the ``sre`` user that evaluates (``Grade0.load_answers``).  ``cheat.json`` written by
``sre state`` is merged the same way at the next tick and pushed to the open pages.
"""
import json
import logging
import socket

from SRE import params
from SRE import answers as A
from SRE.common import QuestionType
from SRE.form_spec import parse_form_description, coerce_answers

from .access import AccessError
from .registry import Project, Registry, EVENT_ANSWERS
from ..identity import Identity

log = logging.getLogger('sreweb.agent')

HASH_LENGTH = 64   # sha256 hex


class AnswersStore:
    def __init__(self, registry: Registry, *, hostname: str | None = None, pub_dir: str | None = None,
                 owner: tuple[int, int] | None = None, mode: int = 0o644):
        self.registry = registry
        self.hostname = hostname or socket.gethostname()
        self.pub_dir = pub_dir or params.sre_pub_dir
        self.owner = owner if owner is not None else (params.sre_uid, params.docker_gid)
        self.mode = mode
        registry.tick_hooks.append(self.consume_cheat)

    @staticmethod
    def path(project: Project):
        return project.answers_path

    def read(self, project: Project) -> dict:
        return A.load_answers(self.path(project))

    @staticmethod
    def _questions_by_hash(project: Project) -> dict:
        return {q.get('question_hash'): q for q in project.info.get('questions', []) or []}

    def normalize(self, project: Project, patch: dict) -> dict:
        """The answers of a ``PUT`` as they are stored: text answers as strings, form answers as
        the JSON-encoded string of their ``{field: value}`` dict (what the Qt GUI writes);
        unknown question hashes are refused."""
        questions = self._questions_by_hash(project)
        default_language = project.info.get('default_language', 'en') or 'en'
        result = {}
        for q_hash, value in patch.items():
            q = questions.get(q_hash)
            if not isinstance(q_hash, str) or len(q_hash) != HASH_LENGTH or q is None:
                raise AccessError(400, f"unknown question {q_hash!r}")
            if q.get('question_type') == QuestionType.FORM.value:
                if isinstance(value, str):
                    try:
                        value = json.loads(value)
                    except ValueError:
                        raise AccessError(400, f"bad form answer for {q_hash}")
                if not isinstance(value, dict):
                    raise AccessError(400, f"bad form answer for {q_hash}")
                description = q.get('description', '')
                if isinstance(description, dict):
                    description = description.get(default_language) or next(iter(description.values()), '')
                chunks = parse_form_description(description or '')
                result[q_hash] = json.dumps(coerce_answers(chunks, value), ensure_ascii=False)
            else:
                if not isinstance(value, str):
                    raise AccessError(400, f"bad answer for {q_hash}")
                result[q_hash] = value
        return result

    def _with_metadata(self, answers: dict, identity: Identity) -> dict:
        return A.with_metadata(answers, hostname=self.hostname, login=identity.login, fullname=identity.fullname,
                               email=identity.email or None, language=identity.language,
                               exam_data=A.read_exam_json(self.pub_dir))

    def _save(self, project: Project, data: dict):
        A.save_answers(self.path(project), data, atomic=True, owner=self.owner, mode=self.mode)

    async def put(self, project: Project, patch: dict, identity: Identity) -> dict:
        """Merge *patch* (``{question_hash: answer}``) into the file and return its new content."""
        normalized = self.normalize(project, patch)
        async with project.answers_lock:
            answers = self.read(project)
            answers.update(normalized)
            data = self._with_metadata(answers, identity)
            self._save(project, data)
        project.touch()
        return data

    async def rewrite(self, project: Project, identity: Identity) -> dict:
        """Write the file again with the current metadata (a new language, the exam fields)."""
        async with project.answers_lock:
            data = self._with_metadata(self.read(project), identity)
            self._save(project, data)
        return data

    async def consume_cheat(self, project: Project) -> dict | None:
        """Tick hook: merge ``cheat.json`` (written by ``sre state``) into the answers, delete it
        and push the new answers to the open pages."""
        cheat_path = project.cheat_path
        async with project.answers_lock:
            try:
                cheat = A.consume_cheat_file(cheat_path)
            except (OSError, ValueError) as e:
                log.warning("cannot read %s: %s", cheat_path, e)
                return None
            if cheat is None:
                return None
            answers = A.merge_cheat(self.read(project), cheat)
            try:
                self._save(project, answers)
            except OSError as e:
                log.warning("cannot write the answers of %s: %s", project.rln, e)
                return None
        await self.registry.broadcast(project, {'t': EVENT_ANSWERS, 'answers': self.public(answers, project)})
        return answers

    @staticmethod
    def public(answers: dict, project: Project) -> dict:
        """The answers sent to the browser: the question entries only (the metadata stays)."""
        hashes = {q.get('question_hash') for q in project.info.get('questions', []) or []}
        return {k: v for k, v in answers.items() if k in hashes}
