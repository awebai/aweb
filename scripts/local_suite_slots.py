"""Shared host admission for local service-backed tests (docs/local-suite-slots.md)."""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from enum import StrEnum
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import time
from typing import Iterator, TextIO

SLOT_DIRECTORY = Path("/private/tmp/aweb-local-suite-slots")


class SuiteLabel(StrEnum):
    SERVER = "server"
    REGISTRY = "registry"
    USER_PATHS = "user-paths"
    PORTABLE = "portable"


class Scope(StrEnum):
    WHOLE = "whole"
    FOCUSED = "focused"


def pytest_scope(arguments: list[str]) -> Scope:
    """Classify explicit pytest selections for slot metadata."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in ("-k", "-m", "--deselect"):
            if index + 1 < len(arguments) and arguments[index + 1].strip():
                return Scope.FOCUSED
            index += 2
            continue
        if argument.startswith(("-k", "-m")) and len(argument) > 2:
            return Scope.FOCUSED
        if argument.startswith("--deselect=") and argument.partition("=")[2].strip():
            return Scope.FOCUSED
        if argument == "--":
            return (
                Scope.FOCUSED
                if any(
                    str(Path(path)) not in (".", "tests")
                    for path in arguments[index + 1 :]
                )
                else Scope.WHOLE
            )
        if not argument.startswith("-"):
            if str(Path(argument)) not in (".", "tests"):
                return Scope.FOCUSED
        elif "=" not in argument and argument not in (
            "-q",
            "-v",
            "-vv",
            "-vvv",
            "-s",
            "-x",
            "--verbose",
            "--quiet",
            "--disable-warnings",
            "--collect-only",
            "--co",
            "--lf",
            "--ff",
        ):
            # Consume a possible value, never the next option: that option may
            # itself own a report path which must not become a test selector.
            if index + 1 < len(arguments) and not arguments[index + 1].startswith("-"):
                index += 1
        index += 1
    return Scope.WHOLE


def slot_file(path: Path) -> TextIO:
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o666
    )
    stream = os.fdopen(descriptor, "r+", encoding="utf-8")
    try:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(
                f"Unsafe local suite slot {path}. Ask the host operator to restore the shared slot directory."
            )
        if stat.S_IMODE(info.st_mode) != 0o666:
            os.fchmod(stream.fileno(), 0o666)
        return stream
    except BaseException:
        stream.close()
        raise


def holder_description(stream: TextIO, *, number: int) -> str:
    stream.seek(0)
    try:
        value = json.loads(stream.read(4096))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return f"slot {number}: holder metadata being published"
    if not isinstance(value, dict) or not isinstance(value.get("pid"), int):
        return f"slot {number}: holder metadata unavailable"
    return (
        f"slot {number}: {value.get('owner')!r} {value.get('repo')!r}/"
        f"{value.get('label')!r} pid={value['pid']} SHA={value.get('source_sha')!r}"
    )


def acquire_slot(slots: list[TextIO]) -> tuple[int, TextIO]:
    """Take any available slot, with the shared two-second wait and minute status."""
    next_report = 0.0
    while True:
        holders = []
        for number, stream in enumerate(slots):
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                holders.append(holder_description(stream, number=number))
                continue
            return number, stream
        now = time.monotonic()
        if now >= next_report:
            print(
                f"Waiting for local suite slot ({len(slots)} busy): "
                + "; ".join(holders),
                flush=True,
            )
            next_report = now + 60
        # flock cannot wait on any of several files. No service work runs during admission.
        time.sleep(2)


def write_holder(
    stream: TextIO, *, root: Path, label: SuiteLabel, scope: Scope
) -> None:
    source = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if source.returncode:
        raise ValueError(
            f"Cannot identify local suite source HEAD (git exit {source.returncode}, stderr={source.stderr[:512]!r}). "
            "Restore this checkout's Git HEAD and rerun the local target."
        )
    stream.seek(0)
    json.dump(
        {
            "pid": os.getpid(),
            "repo": "aweb",
            "source_sha": source.stdout.strip(),
            "label": label.value,
            "scope": scope.value,
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "owner": os.environ.get("OATS_INSTANCE", root.name),
        },
        stream,
    )
    stream.write("\n")
    stream.truncate()
    stream.flush()


@contextmanager
def suite_slot(*, scope: Scope, label: SuiteLabel, root: Path) -> Iterator[None]:
    """Hold admission through caller cleanup; kernel locks alone own occupancy."""
    try:
        count = int(os.environ.get("AWEB_LOCAL_SUITE_SLOTS", "3"))
    except ValueError as error:
        raise ValueError(
            "Invalid local suite slot count. Set AWEB_LOCAL_SUITE_SLOTS to the host-wide positive count (default 3)."
        ) from error
    if count < 1:
        raise ValueError(
            "Invalid local suite slot count. Set AWEB_LOCAL_SUITE_SLOTS to the host-wide positive count (default 3)."
        )
    SLOT_DIRECTORY.mkdir(mode=0o777, parents=False, exist_ok=True)
    info = SLOT_DIRECTORY.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(
            "Unsafe shared local suite directory. Ask the host operator to restore /private/tmp/aweb-local-suite-slots and rerun."
        )
    if stat.S_IMODE(info.st_mode) != 0o777:
        SLOT_DIRECTORY.chmod(0o777)
    with ExitStack() as files:
        slots = [
            files.enter_context(slot_file(SLOT_DIRECTORY / f"slot-{i}.lock"))
            for i in range(count)
        ]
        number, stream = acquire_slot(slots)
        write_holder(stream, root=root, label=label, scope=scope)
        print(
            f"Local suite slot {number} acquired: {label.value} pid={os.getpid()}",
            flush=True,
        )
        try:
            yield
        finally:
            # Never unlink a lock file: a different inode would permit another holder.
            fcntl.flock(stream, fcntl.LOCK_UN)
            print(f"Local suite slot {number} released: {label.value}", flush=True)
