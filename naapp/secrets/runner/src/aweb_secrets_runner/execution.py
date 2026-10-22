"""Bounded local execution of a freshly checked job; no service authority."""

import asyncio
import codecs
import os
import signal
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from aweb_secrets_values.credential_shapes import has_credential_shape

from .errors import Refused
from .jobs import CredentialInput, PreparedJob, RunnerConfig


@dataclass(repr=False)
class _Capture:
    limit: int
    used: int = 0
    truncated: bool = False
    invalid: bool = False
    buffers: list[bytearray] = field(default_factory=lambda: [bytearray(), bytearray()])
    cut: list[bool] = field(default_factory=lambda: [False, False])
    decoders: list[Any] = field(
        default_factory=lambda: [codecs.getincrementaldecoder("utf-8")("strict") for _ in range(2)]
    )

    def feed(self, index: int, chunk: bytes) -> None:
        if not self.invalid:
            try:
                self.decoders[index].decode(chunk)
            except UnicodeError:
                self.invalid = True
        room = self.limit - self.used
        kept = chunk[:room]
        self.buffers[index].extend(kept)
        self.used += len(kept)
        if len(kept) < len(chunk):
            self.cut[index] = self.truncated = True

    def finish(self, index: int) -> None:
        if not self.invalid:
            try:
                self.decoders[index].decode(b"", final=True)
            except UnicodeError:
                self.invalid = True


class _Child(asyncio.SubprocessProtocol):
    def __init__(self, capture: _Capture) -> None:
        self.capture = capture
        self.done: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.exited: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    def process_exited(self) -> None:
        self.exited.set_result(None)

    def pipe_data_received(self, fd: int, data: bytes) -> None:
        self.capture.feed(fd - 1, data)

    def pipe_connection_lost(self, fd: int, exc: Exception | None) -> None:
        if fd in (1, 2):
            self.capture.finish(fd - 1)
        if exc is not None:
            self.capture.invalid = True

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            self.capture.invalid = True
        self.done.set_result(None)


def _scalar_prefix(raw: bytes, bound: int) -> bytes:
    # Only an incomplete final scalar may be discarded: callers validate the
    # original stream strictly before any inspection/report construction.
    return raw[:bound].decode("utf-8", errors="ignore").encode("utf-8")


def _report(job: PreparedJob, capture: _Capture, exit_code: int) -> dict[str, Any]:
    count = 0
    streams = []
    withheld = capture.invalid
    try:
        for index, buffer in enumerate(capture.buffers):
            body = _scalar_prefix(bytes(buffer), len(buffer))
            body, found = job.known.redact(body)
            count += found
            if capture.cut[index]:
                body, found = job.known.redact_tail(body)
            else:
                body, found = job.known.redact_json(body)
            count += found
            withheld |= has_credential_shape(body)
            streams.append(body)
    except (ValueError, UnicodeError, RecursionError):
        withheld = True
    truncated = capture.truncated
    if withheld:
        streams = [b"", b""]
    else:
        # Replacement markers can expand output. Reapply the shared bound to
        # the redacted bytes, keeping scalar boundaries and never raw prefixes.
        room = job.output_max_bytes
        for index, body in enumerate(streams):
            if len(body) > room:
                streams[index] = _scalar_prefix(body, room)
                truncated = True
            room -= len(streams[index])
    return {
        "exit_code": exit_code,
        "stdout": streams[0].decode("utf-8"),
        "stderr": streams[1].decode("utf-8"),
        "truncated": truncated,
        "result_withheld": withheld,
        "redaction_count": count,
    }


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        raise Refused("job_cleanup_failed") from None


async def _started(callback: Callable[[int], Awaitable[None]], pid: int) -> None:
    try:
        await callback(pid)
    except Exception:
        # Reporting uncertainty is dealt with by the durable dispatch protocol;
        # it must not leak a network exception or stall/duplicate execution.
        pass


async def _stop(process: asyncio.SubprocessTransport, child: _Child) -> None:
    try:
        _kill_group(process.get_pid())
    finally:
        # Join the actual child watcher before closing transports. Pipe closure
        # alone can complete connection_lost while the leader is still alive.
        await asyncio.shield(child.exited)
        process.close()
        await asyncio.shield(child.done)


async def execute(
    config: RunnerConfig,
    *,
    job_id: str,
    digest: str,
    runner_id: str,
    params: dict[str, Any],
    credentials: list[CredentialInput],
    expires_at: float,
    started: Callable[[int], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Run once after the caller's durable replay acceptance, returning safe fields.

    The caller owns assignment verification and the journal. OCI execution is
    refused until its pinned-image runtime is composed; it never falls back to
    a host executable.
    """
    job = config.prepare(
        job_id=job_id, digest=digest, runner_id=runner_id, params=params, credentials=credentials
    )
    return await _execute_prepared(job, expires_at=expires_at, started=started)


async def _execute_prepared(
    job: PreparedJob,
    *,
    expires_at: float,
    started: Callable[[int], Awaitable[None]] | None = None,
    umask: int = -1,
) -> dict[str, Any]:
    """Shared bounded capture/report path after local runtime checks and opening."""
    # Preparation includes disk reads/hash checks. Sample after that last wait.
    if time.time() >= expires_at:
        raise Refused("assignment_expired")
    capture = _Capture(job.output_max_bytes)
    child = _Child(capture)
    creation = asyncio.create_task(
        asyncio.get_running_loop().subprocess_exec(
            lambda: child,
            *job.argv,
            cwd=job.cwd,
            env=job.env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            umask=umask,
        )
    )
    try:
        process, _ = await asyncio.shield(creation)
    except asyncio.CancelledError:
        process, _ = await creation
        await _stop(process, child)
        raise
    except (OSError, ValueError):
        raise Refused("job_start_failed") from None
    observer = asyncio.create_task(_started(started, process.get_pid())) if started else None
    timed_out = False
    try:
        async with asyncio.timeout(job.timeout_s):
            await asyncio.shield(child.done)
    except TimeoutError:
        timed_out = True
    finally:
        try:
            # Descendants may have closed the pipes while continuing to run.
            await _stop(process, child)
        finally:
            # Closing our pipe transports also bounds a descendant that escaped
            # the group and retained a writer. This is not a sandbox.
            if observer:
                observer.cancel()
            if observer:
                await asyncio.gather(observer, return_exceptions=True)
    exit_code = process.get_returncode()
    assert exit_code is not None
    return _report(job, capture, -signal.SIGKILL if timed_out else exit_code)
