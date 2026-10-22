"""Credential-bearing rootless OCI execution; not yet composed into the worker."""

import asyncio
import json
import os
import secrets
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from .errors import Refused
from .execution import _execute_prepared
from .jobs import CredentialInput, RunnerConfig, _open_job
from .oci_prepare import RuncPreparation
from .oci_recovery import stop_container
from .oci_workspace import mark_container, read_marker


async def execute_oci(
    runtime: RuncPreparation,
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
    """Open only after public runtime checks, then stop/reap before private cleanup.

    The worker caller still owns service verification/durable journal acceptance.
    This local function confers no authority, and the worker OCI guard stays closed.
    """
    if any(not isinstance(item, CredentialInput) for item in credentials):
        raise Refused("credential_invalid")
    if runtime.supervisor is None or runtime.supervisor.path != Path(sys.executable):
        raise Refused("runner_runtime_unavailable")
    try:
        refs = tuple(item.secret_ref for item in credentials)
        inputs = config.inputs(
            job_id=job_id, digest=digest, runner_id=runner_id, params=params, credential_refs=refs
        )
        async with runtime.prepare(inputs) as bundle:
            runtime.supervisor.check()
            supervisor = runtime.supervisor.path
            # Unpacking can wait. Recheck the current config using the frozen original
            # parameters, never mutable caller input, immediately before opening.
            current = config.inputs(
                job_id=job_id,
                digest=digest,
                runner_id=runner_id,
                params=inputs.params,
                credential_refs=refs,
            )
            if current != inputs:
                raise Refused("config_changed")
            if time.time() >= expires_at:
                raise Refused("assignment_expired")
            container = "job-" + secrets.token_hex(16)
            mark_container(
                bundle.directory.parent,
                engine=bundle.engine,
                sha256=runtime.engine.sha256,
                container=container,
            )
            job = _open_job(inputs, credentials)
            path = bundle.directory / "config.json"
            configuration = json.loads(path.read_bytes())
            configuration["process"]["env"] = [f"{name}={value}" for name, value in job.env.items()]
            fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(json.dumps(configuration, separators=(",", ":")).encode())
            finally:
                os.close(fd)
            pid_file = bundle.directory.parent / "init.pid"
            process = replace(
                job,
                argv=(
                    str(supervisor),
                    "-I",
                    "-m",
                    "aweb_secrets_runner.oci_watchdog",
                    "--work",
                    str(bundle.directory.parent),
                    "--timeout",
                    str(job.timeout_s),
                    "--expires-at",
                    str(expires_at),
                ),
                # This is control/cleanup allowance, not the job execution
                # budget. The independent helper enforces the original n.
                timeout_s=job.timeout_s + 125,
                cwd=str(bundle.directory),
                env={},
            )

            async def observed_start(pid: int) -> None:
                while not pid_file.exists():
                    await asyncio.sleep(0.01)
                if started:
                    await started(pid)

            try:
                report = await _execute_prepared(
                    process, expires_at=expires_at, started=observed_start, umask=0o077
                )
                # The qualified runc writes this only after its initial launch
                # handshake succeeds. A failure before that is not a job exit.
                if not read_marker(bundle.directory.parent)["stopped"]:
                    raise Refused("oci_supervisor_failed")
                if not pid_file.exists():
                    if report["exit_code"] == 124:
                        raise Refused("assignment_expired")
                    raise Refused("job_start_failed")
                return report
            finally:
                if any(bundle.state.iterdir()):
                    # runc's container init has its own session; killing the CLI
                    # group alone cannot stop it. Kill the namespace's processes,
                    # then delete/reap runtime state before the bundle may disappear.
                    await stop_container(runtime.engine, bundle.state, container)
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused("oci_execution_failed") from None
