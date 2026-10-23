"""Local independent deadline supervisor. Args and environment contain no values."""

import argparse
import asyncio
import math
import os
import signal
import time
from pathlib import Path
from typing import NoReturn

from .errors import Refused
from .oci_platform import require_memory_directory
from .oci_prepare import BinaryPin
from .oci_recovery import stop_container
from .oci_workspace import mark_stopped, read_marker


async def supervise(work: Path, timeout_s: int, expires_at: float) -> int:
    # Starts before hashing/spawning. Network state and worker survival cannot
    # reset this original local job budget.
    deadline = time.monotonic() + timeout_s
    require_memory_directory(work)
    marker = read_marker(work)
    if not marker["prepared"] or marker["container"] is None or marker["stopped"]:
        raise Refused("oci_supervisor_failed")
    engine = BinaryPin(Path(marker["engine"]["path"]), marker["engine"]["sha256"])
    executable = engine.check()
    container = marker["container"]
    state = require_memory_directory(work / "state")
    root = ("--root", str(state), "--rootless=true", "--log", "/dev/null")
    # Isolated interpreter startup and engine hashing can wait too. Sample
    # signed assignment expiry again at this actual runtime launch boundary.
    if time.time() >= expires_at:
        mark_stopped(work, engine=executable, sha256=engine.sha256, container=container)
        raise Refused("assignment_expired")
    if time.monotonic() >= deadline:
        mark_stopped(work, engine=executable, sha256=engine.sha256, container=container)
        raise Refused("job_start_failed")
    creation = asyncio.create_task(
        asyncio.create_subprocess_exec(
            str(executable),
            *root,
            "run",
            "--pid-file",
            str(work / "init.pid"),
            "--bundle",
            str(work / "bundle"),
            container,
            env={},
            stdin=asyncio.subprocess.DEVNULL,
            # The runner's already-bounded capture owns the inherited pipes.
            stdout=None,
            stderr=None,
            umask=0o077,
        )
    )
    expired = False
    process = None
    try:
        async with asyncio.timeout(max(0, deadline - time.monotonic())):
            process = await asyncio.shield(creation)
            status = await process.wait()
    except TimeoutError:
        expired = True
        status = -signal.SIGKILL
    finally:
        if process is None:
            process = await creation
        # Reap this exact launcher first, so it cannot create state AFTER the
        # namespace check. The engine kills any existing container init/children.
        if process.returncode is None:
            process.kill()
        await process.wait()
        if any(state.iterdir()):
            await stop_container(engine, state, container)
        mark_stopped(work, engine=executable, sha256=engine.sha256, container=container)
    return -signal.SIGKILL if expired else status


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise Refused("oci_supervisor_failed")


def main() -> int:
    try:
        parser = _Parser(add_help=False)
        parser.add_argument("--work", required=True, type=Path)
        parser.add_argument("--timeout", required=True, type=int)
        parser.add_argument("--expires-at", required=True, type=float)
        args = parser.parse_args()
        if not 1 <= args.timeout <= 3600 or not math.isfinite(args.expires_at):
            raise Refused("oci_supervisor_failed")
        code = asyncio.run(supervise(args.work, args.timeout, args.expires_at))
        if code < 0:
            os.kill(os.getpid(), -code)
        return code
    except Refused as error:
        return 124 if error.code == "assignment_expired" else 125
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        # The parent requires a completed-stop receipt before accepting a job
        # result. No exception/body/path/credential is reflected here.
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
