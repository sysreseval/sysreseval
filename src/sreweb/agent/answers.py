"""``answers/answers.json`` of a project, written by the agent on behalf of a browser user.

The Qt GUI writes the file itself on every keystroke, with the identity of the desktop session;
here the browser sends the changed answers (``PUT``) and the agent merges them under the
project's answers lock, adds the metadata from the identity the portal relayed
(``SRE.answers.with_metadata``: login, full name, e-mail, student group, language...) and the
hostname of the pool host, and writes the file atomically, readable by the ``sre`` user that
evaluates (``Grade0.load_answers``).  The metadata alone is written as soon as a project is
created (``rewrite``), so the Watch page names the owner before the first answer, and again
when the owner opens the project page and the file lacks it or holds other values
(``refresh``: the project of an older agent or of the Qt GUI gets its full name and group
then); an empty full name or group never replaces a stored one.  An instructor helping a
student writes in the student's file too (``put`` by a non-owner): the stored metadata is kept
as it is (``_kept_metadata``: the student's login, full name, e-mail, group and language, never
the instructor's), only the update time and the exam fields are new.  Every ``put`` is pushed to
the open pages of the project (the ``answers`` event), so the student's page shows what the
instructor types and the instructor's page what the student types.  ``cheat.json`` written by
``sre state`` is merged the same way at the next tick and pushed too.

The Qt GUI of the same student, logged in on the host, may write the file too (a project
started there and opened in a browser, or the other way round).  The file it created keeps its
owner, so that it goes on writing it (``_owner_of``: an agent writing ``sre:docker`` over the
student's file left the GUI unable to save, every answer typed there afterwards was lost, until
2026-11-03), and what it wrote is pushed to the open pages: ``watch_file``, a tick hook, compares
the file's signature with the one of the agent's last write or read (``Project.answers_sig``).
Every read-merge-write here is done under the advisory lock on the ``answers/`` directory the
GUI takes too (``SRE.answers.AnswersLock``, waited for without blocking the loop: ``_locked``),
so that a write of the GUI at the same moment is not undone.
"""
import asyncio
import contextlib
import json
import logging
import os
import socket
import stat
import time

from SRE import params
from SRE import answers as A
from SRE.common import QuestionType
from SRE.form_spec import parse_form_description, coerce_answers

from .access import AccessError
from .exam import exam_json_data
from .registry import Project, Registry, EVENT_ANSWERS
from ..identity import Identity

log = logging.getLogger('sreweb.agent')

HASH_LENGTH = 64   # sha256 hex
LOCK_TIMEOUT = 2.0   # s: the GUI holds the file lock for a millisecond; a stopped one must not block the agent


class AnswersStore:
    def __init__(self, registry: Registry, *, hostname: str | None = None, pub_dir: str | None = None,
                 owner: tuple[int, int] | None = None, mode: int = 0o644):
        self.registry = registry
        self.hostname = hostname or socket.gethostname()
        self.pub_dir = pub_dir or params.sre_pub_dir
        self.owner = owner if owner is not None else (params.sre_uid, params.docker_gid)
        self.mode = mode
        registry.on_added.append(self.note_signature)
        registry.tick_hooks.append(self.consume_cheat)
        registry.tick_hooks.append(self.watch_file)

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

    @staticmethod
    def _stored(answers: dict, key: str) -> str:
        return str(answers.get(key, '') or '')

    def _exam_data(self, project: Project) -> dict | None:
        """The ``exam.json``-shaped dict of the exam fields: the host's ``exam.json`` when it
        exists (the host-wide exam mode), else the exam of the project (``exam.py``), else
        ``None`` (no exam)."""
        data = A.read_exam_json(self.pub_dir)
        if data is not None:
            return data
        return exam_json_data(project.exam) if project.exam is not None else None

    def _with_metadata(self, project: Project, answers: dict, identity: Identity) -> dict:
        """*answers* with the metadata of *identity*: its full name and group when it gives
        them, else the stored ones (a request without the header must not erase what an
        earlier one wrote), like the e-mail."""
        return A.with_metadata(answers, hostname=self.hostname, login=identity.login,
                               fullname=identity.fullname or self._stored(answers, params.fullname_keyword),
                               email=identity.email or None, language=identity.language,
                               exam_data=self._exam_data(project),
                               group=identity.group or self._stored(answers, params.group_keyword))

    def _kept_metadata(self, project: Project, answers: dict, identity: Identity | None) -> dict:
        """*answers* with the stored metadata written again: the file of a student written by
        an instructor (*identity*) keeps the student's login (the owner of the project when the
        file has none), full name, e-mail, group and language (the writer's language when the
        file has none, the lab's without a writer); the update time and the exam fields are new."""
        fallback_language = identity.language if identity is not None \
            else (project.info.get('default_language') or 'en')
        return A.with_metadata(answers, hostname=self.hostname,
                               login=self._stored(answers, params.login_keyword) or project.owner,
                               fullname=self._stored(answers, params.fullname_keyword),
                               email=self._stored(answers, params.email_keyword) or None,
                               language=self._stored(answers, params.language_keyword) or fallback_language,
                               exam_data=self._exam_data(project),
                               group=self._stored(answers, params.group_keyword))

    def metadata_stale(self, answers: dict, identity: Identity) -> bool:
        """The file lacks the metadata a current agent writes (``login``, ``group``: the file of
        the Qt GUI or of an older agent), or *identity* gives a full name or a group other than
        the stored one (an empty value does not count).  The login is never compared: the Qt GUI
        may write the Unix login of the same person."""
        if params.login_keyword not in answers or params.group_keyword not in answers:
            return True
        return bool(identity.fullname and identity.fullname != self._stored(answers, params.fullname_keyword)
                    or identity.group and identity.group != self._stored(answers, params.group_keyword))

    def _owner_of(self, path) -> tuple[int, int]:
        """The owner to give the file: the one of the existing regular file (the Qt GUI of the
        student created it and must go on writing it), else ``sre:docker``."""
        try:
            st = os.lstat(path)
        except OSError:
            return self.owner
        return (st.st_uid, st.st_gid) if stat.S_ISREG(st.st_mode) else self.owner

    def _save(self, project: Project, data: dict):
        path = self.path(project)
        project.answers_sig = A.save_answers(path, data, atomic=True, owner=self._owner_of(path), mode=self.mode)

    @contextlib.asynccontextmanager
    async def _locked(self, project: Project):
        """The lock on the ``answers/`` directory shared with the Qt GUI
        (``SRE.answers.AnswersLock``) around a read-merge-write, waited for with the loop
        running; given up after ``LOCK_TIMEOUT`` with a warning, the write done anyway."""
        lock = A.AnswersLock(self.path(project))
        deadline = time.monotonic() + LOCK_TIMEOUT
        try:
            while True:
                try:
                    if lock.try_acquire():
                        break
                except OSError:
                    break               # no answers/ directory yet: nothing to share
                if time.monotonic() >= deadline:
                    log.warning("answers of %s: the file lock was not obtained in %.0f s, writing anyway",
                                project.rln, LOCK_TIMEOUT)
                    break
                await asyncio.sleep(lock.POLL)
            yield
        finally:
            lock.release()

    def note_signature(self, project: Project):
        """``on_added`` hook: the file as it is when the project is found."""
        project.answers_sig = A.file_signature(self.path(project))

    async def watch_file(self, project: Project):
        """Tick hook: when another program replaced or rewrote the file (the Qt GUI of the
        student on this host), push its answers to the open pages of the project."""
        async with project.answers_lock:
            sig = A.file_signature(self.path(project))
            if sig == project.answers_sig:
                return
            if sig is None or not project.subscribers:
                project.answers_sig = sig
                return
            answers = self.read(project)
            if not answers and sig[2] > 0:
                return              # unreadable, or being replaced: again at the next tick
            project.answers_sig = sig
        await self.registry.broadcast(project, {'t': EVENT_ANSWERS, 'answers': self.public(answers, project)})

    async def put(self, project: Project, patch: dict, identity: Identity) -> dict:
        """Merge *patch* (``{question_hash: answer}``) into the file, push the new answers to
        the open pages of the project and return the file's new content.  The owner's metadata
        comes from *identity*; a non-owner (an instructor helping) leaves the stored one alone."""
        normalized = self.normalize(project, patch)
        async with project.answers_lock, self._locked(project):
            answers = self.read(project)
            answers.update(normalized)
            if identity.login == project.owner:
                data = self._with_metadata(project, answers, identity)
            else:
                data = self._kept_metadata(project, answers, identity)
            self._save(project, data)
        project.touch()
        await self.registry.broadcast(project, {'t': EVENT_ANSWERS, 'answers': self.public(data, project)})
        return data

    async def rewrite(self, project: Project, identity: Identity) -> dict:
        """Write the file again with the current metadata: at the creation of the project (the
        file then holds the metadata alone), or for a new language, the exam fields..."""
        async with project.answers_lock, self._locked(project):
            data = self._with_metadata(project, self.read(project), identity)
            self._save(project, data)
        return data

    async def rewrite_kept(self, project: Project) -> dict:
        """Write the file again with its stored metadata and fresh exam fields: the exam of
        the project changed (``PUT`` / ``DELETE …/exam``, its end), whoever asked."""
        async with project.answers_lock, self._locked(project):
            data = self._kept_metadata(project, self.read(project), None)
            self._save(project, data)
        return data

    async def refresh(self, project: Project, identity: Identity) -> dict:
        """The content of the file, written again first when its metadata is stale
        (:meth:`metadata_stale`): the owner opening the project page."""
        answers = self.read(project)
        if not self.metadata_stale(answers, identity):
            return answers
        return await self.rewrite(project, identity)

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
            async with self._locked(project):
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
