"""Live worker/test diagnostics and graceful pytest termination for the local runner."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
import json
import os
from pathlib import Path
import signal
from typing import Iterator
from types import FrameType

import pytest


PREVIOUS_SIGTERM = pytest.StashKey[
    Callable[[int, FrameType | None], None] | signal.Handlers | int | None
]()


class Phase(StrEnum):
    COLLECTION = "collection"
    SETUP = "setup"
    CALL = "call"
    TEARDOWN = "teardown"
    IDLE = "idle"


def record(
    *, nodeid: str, phase: Phase, details: dict[str, object] | None = None
) -> None:
    directory = Path(os.environ["AWEB_LOCAL_PROGRESS_DIR"])
    worker = os.environ.get("PYTEST_XDIST_WORKER", "controller")
    value = {
        "worker": worker,
        "pid": os.getpid(),
        "nodeid": nodeid,
        "phase": phase.value,
        "utc": datetime.now(timezone.utc).isoformat(),
        **(details or {}),
    }
    encoded = (json.dumps(value) + "\n").encode()
    descriptor = os.open(
        directory / "progress.jsonl",
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)
    temporary = directory / f".worker-{worker}-{os.getpid()}.json"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
    temporary.replace(directory / f"worker-{worker}.json")


def terminate_pytest(_number: int, _frame: object) -> None:
    """Let pytest finalize its own JUnit after the launcher requests termination."""
    raise KeyboardInterrupt


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    if not os.environ.get("AWEB_LOCAL_PROGRESS_DIR"):
        raise pytest.UsageError(
            "Local progress requires its owned output directory. Run make test-server-local."
        )
    config.stash[PREVIOUS_SIGTERM] = signal.signal(signal.SIGTERM, terminate_pytest)


def pytest_unconfigure(config: pytest.Config) -> None:
    previous = config.stash.get(PREVIOUS_SIGTERM, None)
    if previous is not None:
        signal.signal(signal.SIGTERM, previous)


def pytest_sessionstart(session: pytest.Session) -> None:
    record(nodeid="", phase=Phase.COLLECTION)


def pytest_collection_finish(session: pytest.Session) -> None:
    record(nodeid="", phase=Phase.IDLE)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: pytest.Item) -> Iterator[None]:
    try:
        yield
    finally:
        record(nodeid=item.nodeid, phase=Phase.IDLE)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    record(nodeid=item.nodeid, phase=Phase.SETUP)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item: pytest.Item) -> None:
    record(nodeid=item.nodeid, phase=Phase.CALL)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item) -> None:
    record(nodeid=item.nodeid, phase=Phase.TEARDOWN)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    # Worker reports retain durations for every phase, including partial runs.
    if os.environ.get("PYTEST_XDIST_WORKER") or not hasattr(report, "worker_id"):
        record(
            nodeid=report.nodeid,
            phase=Phase(report.when),
            details={"outcome": report.outcome, "duration": report.duration},
        )
