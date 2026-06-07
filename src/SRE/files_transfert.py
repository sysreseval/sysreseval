import io
import os
import shlex
import tarfile
import tempfile
from pathlib import Path

from . import params

# def copy_state_files0(lab, state, srelab_dir):
#     for machine_name, machine in lab.machines.items():
#         tar_data = pack_state_data(state, machine_name, srelab_dir)
#         if tar_data:
#             machine.api_object.put_archive("/", tar_data)
#             code = machine.api_object.exec_run(
#                 f"sh -c \"(cd /hostlab/{machine_name}/{state}/ && tar c .) | (cd / && tar xhf - --no-same-owner)\"",
#                 tty=True
#             )
#             print(code)
#         code = machine.api_object.exec_run(
#             f"sh -c \"touch /AAAA\"",
#             tty=True
#         )
#         print(code)


def _force_root(tarinfo):
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = "root"
    tarinfo.gname = "root"
    return tarinfo


def put_file_in_container(machine_api, op):
    """Write a single _FileOp into a running container via put_archive + chown.

    put_archive uses the tar entry's numeric uid/gid (defaults to 0/root) and
    ignores uname/gname, so ownership is applied separately with chown.

    Bind-mounted files (e.g. /etc/hosts) cannot have their inode replaced by
    put_archive.  When that fails we fall back to writing the content in-place
    via exec_run using a base64-encoded payload.
    """
    import base64 as _b64
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tar:
        info = tarfile.TarInfo(name=op.filename.lstrip("/"))
        info.size = len(op.content)
        info.mode = op.permissions
        info.mtime = int(op.mtime)
        tar.addfile(info, io.BytesIO(op.content))
    buf.seek(0)
    try:
        machine_api.put_archive("/", buf)
    except Exception:
        # Fallback: write in-place so the inode is preserved (required for
        # bind-mounted files like /etc/hosts whose inode cannot be unlinked).
        b64 = _b64.b64encode(op.content).decode("ascii")
        qf = shlex.quote(op.filename)
        machine_api.exec_run(
            ["sh", "-c",
             f"printf '%s' '{b64}' | base64 -d > {qf}"
             f" && chmod {op.permissions:o} {qf}"
             f" && chown {shlex.quote(op.owner)} {qf}"
             f" && touch -d '@{int(op.mtime)}' {qf}"],
            workdir="/",
        )
        return
    machine_api.exec_run(["chown", op.owner, op.filename], workdir="/")


def append_to_file_in_container(machine_api, op):
    """Append content to a file in a running container via exec_run.

    Uses '>>' so the file is created if it does not exist.
    Optionally sets permissions, ownership, and mtime when provided.
    Always operates in-place so bind-mounted files (e.g. /etc/hosts) are handled correctly.
    """
    import base64 as _b64
    b64 = _b64.b64encode(op.content).decode("ascii")
    qf = shlex.quote(op.filename)
    parts = [f"printf '%s' '{b64}' | base64 -d >> {qf}"]
    if op.permissions is not None:
        parts.append(f"chmod {op.permissions:o} {qf}")
    if op.owner is not None:
        parts.append(f"chown {shlex.quote(op.owner)} {qf}")
    if op.mtime is not None:
        parts.append(f"touch -d '@{int(op.mtime)}' {qf}")
    machine_api.exec_run(["sh", "-c", " && ".join(parts)], workdir="/")


def idempotent_append_to_file_in_container(machine_api, op):
    """Append content to a file in a running container only if the file does not already end with it.

    Uses base64 encoding to safely compare binary content.  Optionally sets permissions,
    ownership, and mtime when provided (applied regardless of whether content was appended).
    """
    import base64 as _b64
    b64 = _b64.b64encode(op.content).decode("ascii")
    qf = shlex.quote(op.filename)
    # Shell one-liner:
    # - compute the expected byte length from the b64 string
    # - compare the last N bytes of the file (base64-encoded, newlines stripped) with the expected b64
    # - append only if they differ (or the file does not exist)
    check_and_append = (
        f"b64='{b64}';"
        f" qf={qf};"
        f" len=$(printf '%s' \"$b64\" | base64 -d | wc -c);"
        f" [ \"$(tail -c \"$len\" \"$qf\" 2>/dev/null | base64 | tr -d '\\n')\" = \"$b64\" ]"
        f" || printf '%s' \"$b64\" | base64 -d >> \"$qf\""
    )
    parts = [check_and_append]
    if op.permissions is not None:
        parts.append(f"chmod {op.permissions:o} {qf}")
    if op.owner is not None:
        parts.append(f"chown {shlex.quote(op.owner)} {qf}")
    if op.mtime is not None:
        parts.append(f"touch -d '@{int(op.mtime)}' {qf}")
    machine_api.exec_run(["sh", "-c", " && ".join(parts)], workdir="/")


def deploy_exetests(lab):
    """Deploy exetests.py into all containers (used by standalone labs with no srelab_dir)."""
    for machine_name, machine in lab.machines.items():
        with tempfile.TemporaryFile() as f:
            with tarfile.open(fileobj=f, mode="w|") as tar:
                tar.add(params.exetests_path, arcname=params.exetests_machines_path, filter=_force_root)
            f.seek(0)
            machine.api_object.put_archive("/", f)


def copy_state_files(lab, state, srelab_dir):
    for machine_name, machine in lab.machines.items():
        src_machine_dir = Path(f"{srelab_dir}/{state}/{machine_name}").resolve()
        src_all_dir = Path(f"{srelab_dir}/{state}/all").resolve()
        if (not os.path.exists(src_machine_dir)) and (not os.path.exists(src_all_dir)) and (state != "initial"):
            continue
        with tempfile.TemporaryFile() as f:
            with tarfile.open(fileobj=f, mode="w|") as tar:
                if os.path.exists(src_machine_dir):
                    for item in src_machine_dir.iterdir():
                        tar.add(item, arcname=item.name, filter=_force_root)
                if os.path.exists(src_all_dir):
                    for item in src_all_dir.iterdir():
                        tar.add(item, arcname=item.name, filter=_force_root)
                if state == "initial":
                    tar.add(params.exetests_path, arcname=params.exetests_machines_path, filter=_force_root)
            f.seek(0)
            machine.api_object.put_archive("/", f)
