"""RunnerLauncher adapter for the reviewed, no-argument HO6 sudo command."""

from __future__ import annotations

import asyncio
import json
import pwd
import signal

from runner_harness import Invocation, ProcessIdentity, RunnerHarnessError
from runner_supervisor import MAX_REQUEST, PREFIX, Policy

COMMAND = (
    "/usr/bin/sudo",
    "-n",
    "-u",
    "aweb-runner",
    "--",
    str(PREFIX / "bin" / "aweb-secrets-supervisor"),
)


async def _frame(process):
    line = await process.stdout.readline()
    if not line or len(line) > 256:
        raise RunnerHarnessError("runner_supervisor_failed")
    try:
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError):
        raise RunnerHarnessError("runner_supervisor_failed") from None


class _Process:
    def __init__(self, process, identity):
        self._process, self._identity = process, identity
        self.pid = identity.pid
        self._returncode = None
        self._done = asyncio.create_task(self._wait())

    @property
    def returncode(self):
        return self._returncode

    async def identity(self):
        return self._identity

    async def _wait(self):
        try:
            result = await _frame(self._process)
            if set(result) != {"exit"} or type(result["exit"]) is not int:
                raise RunnerHarnessError("runner_supervisor_failed")
            if await self._process.wait() != 0:
                raise RunnerHarnessError("runner_supervisor_failed")
            self._returncode = result["exit"]
            return self._returncode
        finally:
            self._process.stdin.close()

    async def wait(self):
        return await asyncio.shield(self._done)

    async def signal(self, number):
        if number not in (signal.SIGTERM, signal.SIGINT):
            raise RunnerHarnessError("runner_signal_invalid")
        if self._done.done():
            return
        try:
            self._process.stdin.write(json.dumps({"signal": int(number)}).encode() + b"\n")
            await self._process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            await self.wait()


class SupervisedLauncher:
    """Default command grants no privilege until the operator installs its rule.

    command/policy injection exercises the real protocol under the test's existing
    UID. Deployment uses the constants, without a shell, env override or argv.
    """

    def __init__(self, *, command=COMMAND, policy=None):
        self._command = command
        self._policy = policy

    async def uid_for(self, user):
        if user != "aweb-runner":
            raise RunnerHarnessError("runner_configuration_unavailable")
        return pwd.getpwnam(user).pw_uid

    async def launch(self, invocation: Invocation):
        process = None
        try:
            policy = Policy.deployed() if self._policy is None else self._policy
            command = invocation.argv[1]
            ca = "--ca-file" in invocation.argv
            if invocation.argv != policy.argv(command, ca=ca):
                raise ValueError
            request: dict[str, object] = {"command": command}
            if ca:
                request["ca"] = True
            if command == "register":
                raw = invocation.stdin
                if raw is None or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
                    raise ValueError
                request["code"] = raw[:-1].decode("utf-8")
            elif invocation.stdin is not None:
                raise ValueError
            # Use the same request validator, but send no paths or origin.
            policy.request(request)
            frame = json.dumps(request, separators=(",", ":")).encode()
            if len(frame) > MAX_REQUEST:
                raise ValueError
            process = await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                limit=1024,
            )
            assert process.stdin is not None
            process.stdin.write(frame + b"\n")
            await process.stdin.drain()
            identity = await _frame(process)
            if (
                set(identity) != {"pid", "uid"}
                or type(identity["pid"]) is not int
                or identity["pid"] <= 0
                or type(identity["uid"]) is not int
                or identity["uid"] != policy.runner_uid
                or await _frame(process) != {"exec": True}
            ):
                raise ValueError
            return _Process(process, ProcessIdentity(**identity))
        except BaseException as error:
            if process is not None:
                assert process.stdin is not None
                process.stdin.close()  # EOF tells the guardian to stop/reap.
                await asyncio.shield(process.wait())
            if isinstance(error, asyncio.CancelledError):
                raise
            raise RunnerHarnessError("runner_launch_failed") from None
