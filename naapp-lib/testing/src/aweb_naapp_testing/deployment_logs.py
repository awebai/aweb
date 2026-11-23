"""The processes a deployed end-to-end test runs, each writing to a log file.

Loaded as a pytest plugin (``-p aweb_naapp_testing.deployment_logs``, as
``scripts/e2e/naapp-e2e.sh`` does), it adds to a failed test's report what each
process wrote during that test, with tokens and keys redacted.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

# How long a process may take to stop after SIGTERM; one that has to be killed
# fails its deployment.
STOP_TIMEOUT_SECONDS = 10

_LONG_RUN = re.compile(r"[A-Za-z0-9_+-]{20,}")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
# A name spelled in words, as in a traceback. A random token holds a digit or a capital.
_WORDS = re.compile(r"[a-z_-]+")


def redacted(text: str) -> str:
    """``text`` without its long opaque runs: tokens, keys, signatures."""

    def shown(match: re.Match[str]) -> str:
        run = match[0]
        return run if _UUID.fullmatch(run) or _WORDS.fullmatch(run) else "<redacted>"

    return _LONG_RUN.sub(shown, text)


@dataclass
class _Log:
    name: str
    path: Path
    # Where the current test's output starts.
    start: int = 0

    def text(self) -> str:
        with self.path.open("rb") as log:
            log.seek(self.start)
            return redacted(log.read().decode(errors="replace"))


_running: list[_Log] = []
# What processes that stopped during the current test wrote in it.
_stopped: list[tuple[str, str]] = []


@contextmanager
def logged_process(
    args: Sequence[str],
    *,
    name: str,
    log_path: Path,
    env: Mapping[str, str],
    pass_fds: Sequence[int],
    stop_codes: Sequence[int],
) -> Iterator[None]:
    """``args`` running with its output in ``log_path``, stopped with SIGTERM.

    A process that has to be killed, or exits with none of ``stop_codes``,
    fails with its output, redacted.
    """
    with log_path.open("wb") as output:
        proc = subprocess.Popen(
            args, env=env, pass_fds=pass_fds, stdout=output, stderr=subprocess.STDOUT
        )
    log = _Log(name, log_path)
    _running.append(log)
    try:
        yield
    finally:
        proc.terminate()
        killed = False
        try:
            proc.wait(timeout=STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=STOP_TIMEOUT_SECONDS)
            killed = True
        _running.remove(log)
        _stopped.append((name, log.text()))
        if killed or proc.returncode not in stop_codes:
            stopped = (
                f"did not stop within {STOP_TIMEOUT_SECONDS} s of SIGTERM and was killed"
                if killed
                else f"exited with {proc.returncode}"
            )
            log.start = 0
            raise RuntimeError(f"{name} {stopped}; its output:\n{log.text()}")


def pytest_runtest_logstart() -> None:
    _stopped.clear()
    for log in _running:
        log.start = log.path.stat().st_size


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport() -> Iterator[None]:
    outcome = yield
    report = outcome.get_result()
    if report.failed:
        for name, text in [*_stopped, *((log.name, log.text()) for log in _running)]:
            report.sections.append((f"{name} output (redacted)", text))
