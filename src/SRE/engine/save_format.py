"""The inner archive of a save file (`params.save_kathara_name`), in the format of the Kathara fork.

The Kathara engine has the fork write and read it (`save_lab` / `restore_lab`); an engine that
does it by itself uses this module, so that a file saved with one engine restores with the
other.  Nothing here runs a command or names an engine: the names of the members, the paths a
filesystem diff leaves out, the choice of the paths to archive, the manifest, and the reading of
an archive that may come from anywhere (a save file can be supplied by a student).

The archive is a plain tar:

- `manifest.json`: `save_mode` (`diff` or `full`), and per machine its `name`, `original_image`
  (the image the machine was created from, spelled as Docker does) and `deletions` (the paths of
  that image the machine no longer has).  A restore given the lab reads nothing else;
- `images/<machine>.diff.tar` (mode `diff`): one entry per added or changed path that has no
  other changed path below it, named relative to `/`.  A directory is an entry of its own, without
  its content;
- `images/<machine>.tar` (mode `full`): a whole image.
"""
import io
import json
import os
import posixpath
import re
import shutil
import tarfile
from dataclasses import dataclass, field

from .base import EngineError

MANIFEST_MEMBER = "manifest.json"
FORMAT_VERSION = 1
MODE_DIFF = "diff"
MODE_FULL = "full"

#: The name Kathara gives the lab it rebuilds from the running containers, kept in the manifest.
RECONSTRUCTED_LAB_NAME = "reconstructed_lab"

#: What a filesystem diff never holds: the files the engine writes itself in a machine, the mount
#: points, and what does not outlive a machine.  The lists of the fork (`_DIFF_EXCLUDED_EXACT`,
#: `_DIFF_EXCLUDED_PREFIXES` of its `DockerManager`): they must stay the same on both sides.
EXCLUDED_EXACT = frozenset({"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/mtab", "/.dockerenv",
                            "/hosthome", "/shared", "/hostlab"})
EXCLUDED_PREFIXES = ("/dev/", "/proc/", "/sys/", "/run/", "/tmp/", "/hosthome/", "/shared/", "/hostlab/")

_IMAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*\Z")
_DOCKER_HUB = "docker.io/"
_DOCKER_HUB_LIBRARY = "docker.io/library/"


def is_excluded(path: str) -> bool:
    """Whether a filesystem diff leaves *path* out."""
    return path in EXCLUDED_EXACT or path.startswith(EXCLUDED_PREFIXES)


def diff_member(machine: str) -> str:
    """The member holding the filesystem diff of a machine."""
    return f"images/{machine}.diff.tar"


def docker_image_name(image: str) -> str:
    """An image name as Docker spells it (`sysreseval/base13:1.37`, `debian:13`), from the fully
    qualified name another engine gives (`docker.io/sysreseval/base13:1.37`)."""
    for prefix in (_DOCKER_HUB_LIBRARY, _DOCKER_HUB):
        if image.startswith(prefix):
            return image[len(prefix):]
    return image


def mount_points(destinations) -> list[str]:
    """The places of a machine where something of the host is mounted (its shared directory, its
    volumes), as normalised absolute paths.  They are not files of the machine: the save file
    carries the directories of the host apart, and the new machine gets its own."""
    points = set()
    for destination in destinations or ():
        if isinstance(destination, str) and destination.startswith("/") and "\0" not in destination:
            point = posixpath.normpath(destination)
            if point not in ("/", "//"):
                points.add(point)
    return sorted(points)


def under_a_mount(path, points) -> bool:
    """Whether *path* (text or bytes, from `/`) is one of the mount *points* or lies below one."""
    if isinstance(path, bytes):
        return any(path == point.encode() or path.startswith(point.encode() + b"/") for point in points)
    return any(path == point or path.startswith(point + "/") for point in points)


def paths_to_save(changed, added, deleted, mounts=()) -> tuple[list[str], list[str]]:
    """What the diff of a machine holds, from the paths its engine reports as changed, added and
    deleted since its image: `(the paths to archive, the deletions)`, both sorted.

    A path is archived when no reported path lies below it (a directory whose content changed is
    not an entry: its content is), whatever that other path is — a deleted or a left-out one
    counts, as in the fork.  The mount points *mounts* of the machine and what lies below them
    are left out like the paths the format excludes."""
    def left_out(path):
        return is_excluded(path) or under_a_mount(path, mounts)
    there = {path for path in (*changed, *added) if _is_a_path(path)}
    gone = {path for path in deleted if _is_a_path(path)}
    above = set()
    for path in there | gone:
        parent = posixpath.dirname(path)
        while parent not in above and parent not in ("", "/"):
            above.add(parent)
            parent = posixpath.dirname(parent)
    archived = sorted(path for path in there if path not in above and not left_out(path))
    deletions = sorted(path for path in gone if _is_text(path) and not left_out(path))
    return archived, deletions


def _is_a_path(path) -> bool:
    return isinstance(path, str) and path.startswith("/") and path != "/" and "\0" not in path


def _is_text(path: str) -> bool:
    """Whether a path can be written in a manifest: a name that is not UTF-8 cannot (a reader
    of the manifest could not even write it back), so its deletion is not recorded."""
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def member_names(paths) -> bytes:
    """The paths to archive as `tar --null -T -` reads them: relative to `/`, each ended by a
    null byte.  A name that is not UTF-8 gets its bytes back (they travel as surrogate escapes)."""
    return b"".join(path[1:].encode("utf-8", errors="surrogateescape") + b"\0" for path in paths)


def manifest(lab_hash: str, machines) -> dict:
    """The manifest of a filesystem-diff save.  *machines*: `(name, original image, deletions)`
    per machine.  The keys are those of the fork; the topology it also stores is left empty,
    SRE's restore taking it from the lab."""
    return {
        "save_format_version": FORMAT_VERSION,
        "lab": {"name": RECONSTRUCTED_LAB_NAME, "hash": lab_hash, "description": None, "version": None,
                "author": None, "email": None, "web": None, "general_options": {},
                "global_machine_metadata": {}},
        "machines": [{"name": name, "meta": {"image": image}, "interfaces": [],
                      "original_image": image, "deletions": list(deletions)}
                     for name, image, deletions in sorted(machines)],
        "links": [],
        "save_mode": MODE_DIFF,
    }


def _add_file(tar: tarfile.TarFile, name: str, source, size: int):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    tar.addfile(info, source)


def write_empty_diff(path: str):
    """The diff of a machine that changed nothing: a tar without any member."""
    with tarfile.open(path, "w"):
        pass


def write_archive(path: str, manifest_dict: dict, diffs: dict):
    """Write the archive: the manifest, then the diff of each machine (*diffs*: machine name →
    the path of its diff tar)."""
    data = json.dumps(manifest_dict, indent=2).encode("utf-8")
    with tarfile.open(path, "w") as tar:
        _add_file(tar, MANIFEST_MEMBER, io.BytesIO(data), len(data))
        for machine in sorted(diffs):
            with open(diffs[machine], "rb") as source:
                _add_file(tar, diff_member(machine), source, os.fstat(source.fileno()).st_size)


@dataclass
class SavedMachine:
    """What a save file holds of a machine."""
    image: str                                      # as Docker spells it
    deletions: list = field(default_factory=list)   # absolute paths
    has_diff: bool = False


def _invalid(reason: str) -> EngineError:
    return EngineError(f"not a valid save file: {reason}")


def _deletions_of(value) -> list[str]:
    """The deletions of a manifest that can be applied: absolute paths, written the short way,
    none of them a path a diff leaves out."""
    if not isinstance(value, list):
        raise _invalid("the deletions of a machine are not a list")
    kept = set()
    for path in value:
        if not _is_a_path(path) or not _is_text(path):
            continue
        path = posixpath.normpath(path)
        if path.startswith("//"):
            path = path[1:]
        if path != "/" and not is_excluded(path):
            kept.add(path)
    return sorted(kept)


def read_archive(path: str) -> tuple[str, dict]:
    """Read the manifest of an archive: `(save mode, {machine name: SavedMachine})`.  The file is
    not trusted: an `EngineError` says what is wrong with it."""
    try:
        with tarfile.open(path, "r") as tar:
            members = {member.name: member for member in tar.getmembers()}
            member = members.get(MANIFEST_MEMBER)
            if member is None or not member.isfile():
                raise _invalid(f"no {MANIFEST_MEMBER}")
            manifest_dict = json.loads(tar.extractfile(member).read().decode("utf-8"))
    except (tarfile.TarError, OSError, ValueError, EOFError) as e:
        raise _invalid(str(e)) from None
    if not isinstance(manifest_dict, dict) or not isinstance(manifest_dict.get("machines"), list):
        raise _invalid("no list of machines")
    mode = MODE_DIFF if manifest_dict.get("save_mode") == MODE_DIFF else MODE_FULL
    machines = {}
    for entry in manifest_dict["machines"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise _invalid("a machine without a name")
        name = entry["name"]
        if mode != MODE_DIFF:
            machines[name] = SavedMachine(image="")
            continue
        image = entry.get("original_image")
        if not isinstance(image, str) or not _IMAGE_NAME.match(image):
            raise _invalid(f"no image for machine '{name}'")
        diff = members.get(diff_member(name))
        machines[name] = SavedMachine(image=image, deletions=_deletions_of(entry.get("deletions", [])),
                                      has_diff=diff is not None and diff.isfile())
    return mode, machines


def extract_diff(path: str, machine: str, destination: str):
    """Copy the filesystem diff of a machine out of the archive, into the file *destination*."""
    try:
        with tarfile.open(path, "r") as tar:
            source = tar.extractfile(diff_member(machine))
            if source is None:
                raise tarfile.TarError("not a file")
            with open(destination, "wb") as out:
                shutil.copyfileobj(source, out)
    except (tarfile.TarError, KeyError, OSError, EOFError) as e:
        raise _invalid(f"the files of machine '{machine}': {e}") from None


def _as_bytes(names) -> list[bytes]:
    """Names read from a tar, sorted, as the bytes they were (a name that is not UTF-8 was read
    with surrogate escapes)."""
    return [name.encode("utf-8", errors="surrogateescape") for name in sorted(names)]


def diff_members(path: str) -> tuple[list[bytes], list[bytes]]:
    """The paths the diff tar *path* holds, from `/`: `(those that are not directories, the
    directories)`, the directories being those it has an entry for and every directory one of its
    entries lies in, parents first.

    Whoever unpacks it over an image needs them.  The paths of a diff come from a walk of the
    machine: none goes through a symbolic link, so each of those directories was a real one in
    the machine.  The image may have a file or a link there, or a directory where the archive
    has a file, and the archive of the fork does not say that the old one must go first."""
    others, directories = set(), set()
    try:
        with tarfile.open(path, "r:") as tar:
            for member in tar:
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                name = name.strip("/")
                if name in ("", "."):
                    continue
                name = "/" + name
                (directories if member.isdir() else others).add(name)
                parent = posixpath.dirname(name)
                while parent != "/" and parent not in directories:
                    directories.add(parent)
                    parent = posixpath.dirname(parent)
        return _as_bytes(others - directories), _as_bytes(directories)
    except (tarfile.TarError, OSError, EOFError, UnicodeError) as e:
        raise _invalid(f"the files of a machine: {e}") from None
