"""What changed in a directory tree since another one: the changes of a machine since its image.

A standalone program (standard library only, nothing of SRE): the Podman engine runs it with
`python -I` inside the user namespace of its account, on the mounted filesystem of a machine and
the mounted image the machine was created from:

    tree_changes.py NEW OLD UID_SHIFT GID_SHIFT [DIRECTORY NOT ENTERED]...

It prints one JSON object, `{"changed": [...], "added": [...], "deleted": [...]}`, of paths
starting at `/`.  Why not `podman diff`: it fails on a machine where a file became a directory
with something in it, reports a directory that became a file as merely changed, and takes
seconds for a few thousand new files.

The two trees are only looked at (`lstat`, `readlink`, one extended attribute): nothing is
opened and no symbolic link is followed, the machine being a student's.

- a path of NEW that OLD has not is *added*, with everything below it;
- a path of OLD that NEW has not is *deleted* (the path alone, not what was below);
- a directory that became something else, or the reverse, is *deleted* and *added*: whoever puts
  the changes back must remove the old one first;
- a path both have is *changed* when its type, mode, owner or group differ, and for anything but
  a directory its size, modification time, link target, device numbers or file capabilities.
  A file rewritten with the same size and the same time is not seen: the comparison Docker makes
  on the storage drivers that cannot tell it what a container wrote.

UID_SHIFT / GID_SHIFT: what is added to an id of OLD in NEW (a machine runs in a range of ids of
its own, where its image is stored as it is).
"""
import errno
import json
import os
import stat
import struct
import sys

_USAGE = "usage: tree_changes.py NEW OLD UID_SHIFT GID_SHIFT [DIRECTORY NOT ENTERED]..."
_CAPABILITY = "security.capability"
_NANOSECONDS = 1_000_000_000


def _entries(directory: bytes) -> dict:
    """`{name: lstat result}` of a directory; an entry that goes away meanwhile is left out."""
    found = {}
    with os.scandir(directory) as iterator:
        for entry in iterator:
            try:
                found[entry.name] = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                pass
    return found


def capability_of(path: bytes):
    """The file capabilities of a file, in a form that compares across user namespaces (the
    version and the id of the root they are relative to left out), or None."""
    try:
        data = os.getxattr(path, _CAPABILITY, follow_symlinks=False)
    except (OSError, AttributeError):       # none, or a system without this call
        return None
    if len(data) < 20:
        return data
    (magic,) = struct.unpack_from("<I", data)
    return magic & 0x00FFFFFF, data[4:20]


def _same_time(new: int, old: int) -> bool:
    """Two modification times in nanoseconds: equal, or equal to the second when one of them
    has no fraction (a filesystem or an archive that only keeps seconds)."""
    if new == old:
        return True
    return new // _NANOSECONDS == old // _NANOSECONDS and (new % _NANOSECONDS == 0 or old % _NANOSECONDS == 0)


def same(new, old, new_path: bytes, old_path: bytes, uid_shift: int, gid_shift: int,
         capability=capability_of) -> bool:
    """Whether two entries of the same name are the same thing."""
    if new.st_mode != old.st_mode or new.st_uid - uid_shift != old.st_uid or new.st_gid - gid_shift != old.st_gid:
        return False
    mode = new.st_mode
    if stat.S_ISDIR(mode):
        return True
    if stat.S_ISLNK(mode):
        return os.readlink(new_path) == os.readlink(old_path)
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return new.st_rdev == old.st_rdev
    if stat.S_ISREG(mode):
        if new.st_size != old.st_size or not _same_time(new.st_mtime_ns, old.st_mtime_ns):
            return False
        if mode & 0o111:
            return capability(new_path) == capability(old_path)
    return True


def _below(root: bytes, path: bytes, not_entered: frozenset, found: list):
    """Append every path below the directory *path* of the tree *root*."""
    stack = [path]
    while stack:
        directory = stack.pop()
        if directory in not_entered:
            continue
        try:
            entries = _entries(root + directory)
        except (FileNotFoundError, NotADirectoryError):
            continue
        for name, status in entries.items():
            child = directory + b"/" + name
            found.append(child)
            if stat.S_ISDIR(status.st_mode):
                stack.append(child)


def changes(new_root, old_root, uid_shift: int = 0, gid_shift: int = 0, not_entered=(),
            capability=capability_of) -> dict:
    """The changes of the tree *new_root* since the tree *old_root*: the paths `changed`, `added`
    and `deleted`, as strings starting at `/` (a name that is not text keeps its bytes as
    surrogate escapes).  *not_entered*: directories whose content is not looked at."""
    new_root, old_root = os.fsencode(new_root).rstrip(b"/"), os.fsencode(old_root).rstrip(b"/")
    not_entered = frozenset(os.fsencode(path) for path in not_entered)
    changed, added, deleted = [], [], []
    stack = [b""]
    while stack:
        directory = stack.pop()
        try:
            new_entries = _entries(new_root + directory + b"/")
        except (FileNotFoundError, NotADirectoryError):
            if not directory:
                raise       # the tree itself: no answer is not "no change"
            continue        # gone since its parent was read: a later save will tell
        old_entries = _entries(old_root + directory + b"/")
        for name, new in new_entries.items():
            path = directory + b"/" + name
            old = old_entries.pop(name, None)
            is_directory = stat.S_ISDIR(new.st_mode)
            if old is None or is_directory != stat.S_ISDIR(old.st_mode):
                if old is not None:
                    deleted.append(path)
                added.append(path)
                if is_directory:
                    _below(new_root, path, not_entered, added)
                continue
            try:
                if not same(new, old, new_root + path, old_root + path, uid_shift, gid_shift, capability):
                    changed.append(path)
            except OSError as e:
                if e.errno not in (errno.ENOENT, errno.EINVAL):
                    raise
                changed.append(path)        # changed while it was looked at
            if is_directory and path not in not_entered:
                stack.append(path)
        deleted.extend(directory + b"/" + name for name in old_entries)
    return {"changed": sorted(map(os.fsdecode, changed)), "added": sorted(map(os.fsdecode, added)),
            "deleted": sorted(map(os.fsdecode, deleted))}


def main(arguments) -> int:
    if len(arguments) < 4:
        print(_USAGE, file=sys.stderr)
        return 2
    new_root, old_root, uid_shift, gid_shift = arguments[0], arguments[1], int(arguments[2]), int(arguments[3])
    json.dump(changes(new_root, old_root, uid_shift, gid_shift, arguments[4:]), sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
