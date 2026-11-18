"""The agent side of a publication: one report and its manifest in the seat's outbox.

The outbox is a setgid directory (2750) whose group is the publisher's only
read grant. Exported files are 0640 in that group whatever the umask, and the
manifest appears last, by a no-replace link: its existence is the submit, and a
queued job is never replaced.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

EXPORT_MODE = 0o640


class SubmitRefused(Exception):
    """The export would not be readable by the publisher, or the job is already queued."""


def submit(
    outbox: Path,
    *,
    job_id: str,
    content: bytes,
    extension: str,
    target: str,
    expected_gid: int | None = None,
) -> Path:
    directory = os.stat(outbox)
    mode = stat.S_IMODE(directory.st_mode)
    if not (mode & stat.S_ISGID and mode & 0o050 == 0o050):
        raise SubmitRefused("outbox_not_group_readable")
    if expected_gid is not None and directory.st_gid != expected_gid:
        raise SubmitRefused("outbox_group_mismatch")
    manifest_path = outbox / f"{job_id}.json"
    if os.path.lexists(manifest_path):
        raise SubmitRefused("job_already_submitted")

    report_name = f"{job_id}.{extension}"
    report = _export(outbox, report_name, content, directory.st_gid)
    os.replace(report, outbox / report_name)
    manifest = {
        "job_id": job_id,
        "file": report_name,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "target": target,
    }
    staged = _export(
        outbox, manifest_path.name, json.dumps(manifest, sort_keys=True).encode(), directory.st_gid
    )
    try:
        os.link(staged, manifest_path)
    except FileExistsError:
        raise SubmitRefused("job_already_submitted") from None
    finally:
        os.unlink(staged)
    _fsync_directory(outbox)
    return manifest_path


def _export(outbox: Path, name: str, content: bytes, gid: int) -> Path:
    """Write a 0640 temporary in the outbox and check the publisher's group can read it."""
    path = outbox / f".{name}.tmp"
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, EXPORT_MODE)
    try:
        os.fchmod(handle, EXPORT_MODE)
        written = 0
        while written < len(content):
            written += os.write(handle, content[written:])
        os.fsync(handle)
        info = os.fstat(handle)
    finally:
        os.close(handle)
    if info.st_gid != gid or stat.S_IMODE(info.st_mode) != EXPORT_MODE:
        os.unlink(path)
        raise SubmitRefused("export_not_group_readable")
    return path


def _fsync_directory(path: Path) -> None:
    handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)
