"""S19's single runner lifecycle, with an operator-supplied process boundary.

The default adapter refuses. No sudo, user creation, setuid or container command
is inferred from RUNNER_USER. An enabled adapter must implement the operator's
reviewed UID/ownership/signal contract and observe the actual worker, not its
launch monitor. Local process-boundary tests are not separate-user acceptance.
"""

from __future__ import annotations

import asyncio
import math
import os
import signal
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit


class RunnerHarnessError(RuntimeError):
    """A fixed harness code; never a command's body, code, or exception text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _path(path: Path) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or ".." in path.parts
        or "\0" in str(path)
    ):
        raise RunnerHarnessError("runner_configuration_unavailable")
    return path


@dataclass(frozen=True)
class RunnerInputs:
    binary: Path
    config_file: Path
    user: str
    state_dir: Path

    def __post_init__(self) -> None:
        for path in (self.binary, self.config_file, self.state_dir):
            _path(path)
        if not isinstance(self.user, str) or not self.user or any(c in self.user for c in "\0\r\n"):
            raise RunnerHarnessError("runner_configuration_unavailable")

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> RunnerInputs:
        """Missing explicit release configuration fails, never skips a journey."""
        environment = os.environ if environment is None else environment
        try:
            return cls(
                Path(environment["AWEB_SECRETS_E2E_RUNNER_BINARY"]),
                Path(environment["AWEB_SECRETS_E2E_RUNNER_CONFIG_FILE"]),
                environment["AWEB_SECRETS_E2E_RUNNER_USER"],
                Path(environment["AWEB_SECRETS_E2E_RUNNER_STATE_DIR"]),
            )
        except (KeyError, TypeError, ValueError):
            raise RunnerHarnessError("runner_configuration_unavailable") from None


@dataclass(frozen=True)
class Invocation:
    argv: tuple[str, ...]
    user: str
    stdin: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int


class ProcessControl(Protocol):
    """Own one actual child/worker; expose no stdout, stderr or private state.

    identity() reports kernel-observed PID/UID, not values copied from argv or
    requested-user configuration. Signal and wait address this same worker.
    The adapter owns partial-launch cleanup if launch is cancelled or fails.
    """

    @property
    def pid(self) -> int: ...

    @property
    def returncode(self) -> int | None: ...

    async def identity(self) -> ProcessIdentity: ...

    async def wait(self) -> int: ...

    async def signal(self, number: signal.Signals) -> None: ...


class RunnerLauncher(Protocol):
    """The ONE swappable OS boundary, unavailable until operator provisioning.

    uid_for resolves the provisioned user's UID in the execution environment.
    launch applies the reviewed dedicated-user/ownership/isolation policy,
    passes stdin privately, and suppresses all command streams. No enrollment
    code enters argv, environment, logs or diagnostics. Containers use an init
    if the worker would be PID1. Config agent_uids must be actual agent UIDs.
    """

    async def uid_for(self, user: str) -> int: ...

    async def launch(self, invocation: Invocation) -> ProcessControl: ...


class UnavailableLauncher:
    async def uid_for(self, user: str) -> int:
        raise RunnerHarnessError("runner_launch_unavailable")

    async def launch(self, invocation: Invocation) -> ProcessControl:
        raise RunnerHarnessError("runner_launch_unavailable")


@dataclass(frozen=True)
class RunningRunner:
    pid: int
    uid: int
    _process: ProcessControl = field(repr=False)

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    async def wait(self, *, timeout: float | None = None) -> int:
        try:
            async with asyncio.timeout(timeout):
                return await self._process.wait()
        except TimeoutError:
            raise
        except Exception:
            raise RunnerHarnessError("runner_process_failed") from None

    async def stop(self, number: signal.Signals = signal.SIGTERM, *, timeout: float = 10) -> int:
        if number not in (signal.SIGTERM, signal.SIGINT):
            raise RunnerHarnessError("runner_signal_invalid")
        try:
            async with asyncio.timeout(timeout):
                if self.returncode is None:
                    await self._process.signal(number)
                return await self._process.wait()
        except TimeoutError:
            raise RunnerHarnessError("runner_stop_timeout") from None
        except Exception:
            raise RunnerHarnessError("runner_process_failed") from None


class RunnerHarness:
    """Register once, preflight, start and explicitly restart the same journal.

    This does not provision a user, author job pins, interpret credentials or
    implement a claim/report loop. M7 owns those commands; M9 reuses this fixture.
    Supplying an adapter alone is not release acceptance: the operator contract,
    actual dedicated UID and real S13/runner/vault/logs journey remain required.
    """

    def __init__(
        self,
        inputs: RunnerInputs,
        *,
        launcher: RunnerLauncher | None = None,
        ca_file: Path | None = None,
        command_timeout: float = 30,
    ) -> None:
        self.inputs = inputs
        self._launcher = UnavailableLauncher() if launcher is None else launcher
        self._ca_file = None if ca_file is None else _path(ca_file)
        if not math.isfinite(command_timeout) or command_timeout <= 0:
            raise RunnerHarnessError("runner_configuration_unavailable")
        self._timeout = command_timeout
        self._lock = asyncio.Lock()
        self.running: RunningRunner | None = None

    @classmethod
    def from_env(
        cls,
        *,
        launcher: RunnerLauncher | None = None,
        ca_file: Path | None = None,
    ) -> RunnerHarness:
        return cls(RunnerInputs.from_env(), launcher=launcher, ca_file=ca_file)

    def _idle(self) -> None:
        if self.running is not None and self.running.returncode is None:
            raise RunnerHarnessError("runner_already_running")

    def _invocation(self, command: str, *args: str, stdin: bytes | None = None) -> Invocation:
        return Invocation((str(self.inputs.binary), command, *args), self.inputs.user, stdin)

    async def _spawn(self, invocation: Invocation) -> RunningRunner:
        try:
            async with asyncio.timeout(self._timeout):
                expected_uid = await self._launcher.uid_for(self.inputs.user)
                if type(expected_uid) is not int or expected_uid < 0:
                    raise RunnerHarnessError("runner_identity_mismatch")
                process = await self._launcher.launch(invocation)
                try:
                    identity = await process.identity()
                    if (
                        type(identity.pid) is not int
                        or identity.pid <= 0
                        or identity.pid != process.pid
                        or type(identity.uid) is not int
                        or identity.uid != expected_uid
                    ):
                        raise RunnerHarnessError("runner_identity_mismatch")
                except BaseException:
                    # This is the adapter's owned handle, never an agent PID.
                    await RunningRunner(process.pid, expected_uid, process).stop()
                    raise
                return RunningRunner(identity.pid, identity.uid, process)
        except RunnerHarnessError:
            raise
        except Exception:
            # Transport/launcher failures may contain stdin or private streams.
            raise RunnerHarnessError("runner_launch_failed") from None

    async def _command(self, invocation: Invocation) -> None:
        process = await self._spawn(invocation)
        try:
            code = await process.wait(timeout=self._timeout)
        except asyncio.CancelledError:
            await process.stop()
            raise
        except Exception:
            await process.stop()
            raise RunnerHarnessError("runner_command_failed") from None
        if code != 0:
            raise RunnerHarnessError("runner_command_failed")

    async def register(self, origin: str, *, code: str, ca_file: Path | None = None) -> None:
        """No code in argv/env/output; public registration output is suppressed too."""
        try:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError
            if not isinstance(code, str) or not code or any(c in code for c in "\0\r\n"):
                raise ValueError
            incoming = (code + "\n").encode("utf-8")
            if len(incoming) > 255:
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise RunnerHarnessError("runner_registration_input_invalid") from None
        selected_ca = self._ca_file if ca_file is None else _path(ca_file)
        args: tuple[str, ...] = ("--origin", origin, "--state-dir", str(self.inputs.state_dir))
        if selected_ca is not None:
            args += ("--ca-file", str(selected_ca))
        async with self._lock:
            self._idle()
            await self._command(self._invocation("register", *args, stdin=incoming))

    async def doctor(self) -> None:
        async with self._lock:
            self._idle()
            await self._doctor()

    async def _doctor(self) -> None:
        await self._command(self._invocation("doctor", *self._paths()))

    def _paths(self) -> tuple[str, ...]:
        return ("--config", str(self.inputs.config_file), "--state-dir", str(self.inputs.state_dir))

    async def _start(self) -> RunningRunner:
        self._idle()
        await self._doctor()
        args = self._paths()
        if self._ca_file is not None:
            args += ("--ca-file", str(self._ca_file))
        self.running = await self._spawn(self._invocation("run", *args))
        return self.running

    async def start(self) -> RunningRunner:
        async with self._lock:
            return await self._start()

    async def restart(self) -> RunningRunner:
        """Explicit operator/test action; preserves every private state file."""
        async with self._lock:
            if self.running is not None:
                await self.running.stop()
            return await self._start()
