"""Real local process-control checks, not dedicated-user/runner acceptance.

The injected test adapter starts a small Python process under our existing UID.
It does not impersonate an agent/runner user or exercise M7's worker protocol.
"""

import asyncio
import os
import pwd
import secrets
import signal
import sys
from dataclasses import replace

import pytest
from runner_harness import (
    ProcessIdentity,
    RunnerHarness,
    RunnerHarnessError,
    RunnerInputs,
)

CHILD = """
import os, signal, sys
for number in (signal.SIGTERM, signal.SIGINT):
    signal.signal(number, lambda number, frame: sys.exit(128 + number))
print(str(os.getpid()) + ' ' + str(os.geteuid()), flush=True)
data = sys.stdin.buffer.read()
if sys.argv[1] == 'register':
    if not data.endswith(b'\\n') or data.count(b'\\n') != 1:
        sys.exit(9)
    if data.strip().decode() in [*sys.argv, *os.environ.values()]:
        sys.exit(10)
    os.write(1, data)
    os.write(2, data)
if sys.argv[1] == 'run':
    while True:
        signal.pause()
sys.exit(int(sys.argv[2]))
"""


class LocalProcess:
    def __init__(self, process, identity):
        self.process, self.observed = process, identity
        self.pid = process.pid

    @property
    def returncode(self):
        return self.process.returncode

    async def identity(self):
        # These values came from the child's kernel calls, never invocation arguments.
        return self.observed

    async def wait(self):
        return await self.process.wait()

    async def signal(self, number):
        if self.returncode is None:
            self.process.send_signal(number)


class LocalAdapter:
    """An unprivileged test of the injected process boundary, not a release launcher."""

    def __init__(self, *, code=0, wrong_identity=None, hold_command=False):
        self.code, self.wrong_identity = code, wrong_identity
        self.hold_command = hold_command
        self.invocations, self.processes, self.drains = [], [], []

    async def uid_for(self, user):
        return pwd.getpwnam(user).pw_uid

    async def launch(self, invocation):
        self.invocations.append(invocation)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            CHILD,
            "run" if self.hold_command else invocation.argv[1],
            str(self.code),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        pid, uid = map(int, (await process.stdout.readline()).split())
        observed = ProcessIdentity(
            pid + int(self.wrong_identity == "pid"), uid + int(self.wrong_identity == "uid")
        )

        async def discard():
            while await process.stdout.read(4096):
                pass

        self.drains.append(asyncio.create_task(discard()))
        if invocation.stdin is not None:
            process.stdin.write(invocation.stdin)
            await process.stdin.drain()
        process.stdin.close()
        handle = LocalProcess(process, observed)
        self.processes.append(handle)
        return handle

    async def close(self):
        for process in self.processes:
            await process.signal(signal.SIGTERM)
            await process.wait()
        await asyncio.gather(*self.drains)


def inputs(tmp_path):
    return RunnerInputs(
        binary=tmp_path / "runner",
        config_file=tmp_path / "config.json",
        user=pwd.getpwuid(os.geteuid()).pw_name,
        state_dir=tmp_path / "private-state",
    )


def test_four_inputs_are_explicit_and_missing_configuration_is_not_skipped(tmp_path):
    selected = inputs(tmp_path)
    environment = {
        "AWEB_SECRETS_E2E_RUNNER_BINARY": str(selected.binary),
        "AWEB_SECRETS_E2E_RUNNER_CONFIG_FILE": str(selected.config_file),
        "AWEB_SECRETS_E2E_RUNNER_USER": selected.user,
        "AWEB_SECRETS_E2E_RUNNER_STATE_DIR": str(selected.state_dir),
    }
    assert RunnerInputs.from_env(environment) == selected
    for key in environment:
        with pytest.raises(RunnerHarnessError) as refused:
            RunnerInputs.from_env({k: v for k, v in environment.items() if k != key})
        assert refused.value.code == "runner_configuration_unavailable"


async def test_default_launcher_refuses_without_spawning_any_process(tmp_path):
    harness = RunnerHarness(inputs(tmp_path))
    with pytest.raises(RunnerHarnessError) as refused:
        await harness.start()
    assert refused.value.code == "runner_launch_unavailable"
    assert harness.running is None


async def test_registration_is_one_private_stdin_line_and_has_no_output(tmp_path, capfd):
    adapter = LocalAdapter()
    harness = RunnerHarness(inputs(tmp_path), launcher=adapter)
    code = secrets.token_urlsafe(24)
    try:
        await harness.register("https://secrets.example", code=code, ca_file=tmp_path / "ca")
        invocation = adapter.invocations[0]
        assert invocation.argv == (
            str(harness.inputs.binary),
            "register",
            "--origin",
            "https://secrets.example",
            "--state-dir",
            str(harness.inputs.state_dir),
            "--ca-file",
            str(tmp_path / "ca"),
        )
        assert invocation.stdin == (code + "\n").encode()
        assert code not in repr(invocation) + repr(harness)
    finally:
        await adapter.close()
    captured = capfd.readouterr()
    assert code not in captured.out + captured.err


@pytest.mark.parametrize("code", ["", "one\ntwo", "one\rtwo", "one\x00two", "\ud800"])
async def test_invalid_registration_input_never_reaches_adapter(tmp_path, code):
    adapter = LocalAdapter()
    with pytest.raises(RunnerHarnessError) as refused:
        await RunnerHarness(inputs(tmp_path), launcher=adapter).register(
            "https://secrets.example", code=code
        )
    assert refused.value.code == "runner_registration_input_invalid"
    assert adapter.invocations == []


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
async def test_actual_pid_uid_stop_and_restart_keep_the_same_journal(tmp_path, number):
    adapter = LocalAdapter()
    selected = inputs(tmp_path)
    selected.state_dir.mkdir(mode=0o700)
    journal = selected.state_dir / "journal.sqlite3"
    journal.write_bytes(os.urandom(24))
    before = journal.read_bytes()
    harness = RunnerHarness(selected, launcher=adapter, ca_file=tmp_path / "ca")
    try:
        first = await harness.start()
        assert first.pid == adapter.processes[-1].pid
        assert first.uid == os.geteuid()
        assert first.returncode is None
        assert await first.stop(number) == 128 + number
        assert await first.wait() == 128 + number
        second = await harness.restart()
        assert second.pid != first.pid
        assert second.uid == first.uid
        assert [i.argv[1] for i in adapter.invocations] == ["doctor", "run", "doctor", "run"]
        assert all(i.stdin is None for i in adapter.invocations)
        assert all(str(selected.state_dir) in i.argv for i in adapter.invocations)
        assert "--ca-file" not in adapter.invocations[0].argv
        assert "--ca-file" in adapter.invocations[1].argv
        assert journal.read_bytes() == before
    finally:
        await adapter.close()


@pytest.mark.parametrize("wrong_identity", ["pid", "uid"])
async def test_failed_identity_verification_stops_the_created_process(tmp_path, wrong_identity):
    adapter = LocalAdapter(wrong_identity=wrong_identity)
    try:
        with pytest.raises(RunnerHarnessError) as refused:
            await RunnerHarness(inputs(tmp_path), launcher=adapter).doctor()
        assert refused.value.code == "runner_identity_mismatch"
        assert adapter.processes[0].returncode is not None
    finally:
        await adapter.close()


async def test_failed_doctor_never_starts_worker_or_exposes_streams(tmp_path):
    adapter = LocalAdapter(code=7)
    harness = RunnerHarness(inputs(tmp_path), launcher=adapter)
    try:
        with pytest.raises(RunnerHarnessError) as refused:
            await harness.start()
        assert refused.value.code == "runner_command_failed"
        assert [i.argv[1] for i in adapter.invocations] == ["doctor"]
        assert harness.running is None
    finally:
        await adapter.close()


async def test_second_start_refuses_until_original_worker_stops(tmp_path):
    adapter = LocalAdapter()
    harness = RunnerHarness(inputs(tmp_path), launcher=adapter)
    try:
        await harness.start()
        with pytest.raises(RunnerHarnessError) as refused:
            await harness.start()
        assert refused.value.code == "runner_already_running"
        assert [i.argv[1] for i in adapter.invocations] == ["doctor", "run"]
    finally:
        await adapter.close()


def test_relative_or_nul_paths_are_constant_errors(tmp_path):
    for path in ("relative", "/a/../b", "/bad\x00path"):
        with pytest.raises(RunnerHarnessError) as refused:
            replace(inputs(tmp_path), binary=type(tmp_path)(path))
        assert str(refused.value) == "runner_configuration_unavailable"


async def test_command_timeout_stops_the_owned_child_before_returning(tmp_path):
    adapter = LocalAdapter(hold_command=True)
    try:
        harness = RunnerHarness(inputs(tmp_path), launcher=adapter, command_timeout=0.2)
        with pytest.raises(RunnerHarnessError) as refused:
            await harness.doctor()
        assert refused.value.code == "runner_command_failed"
        assert adapter.processes[0].returncode == 143
    finally:
        await adapter.close()


async def test_unsupported_stop_signal_leaves_worker_running(tmp_path):
    adapter = LocalAdapter()
    try:
        running = await RunnerHarness(inputs(tmp_path), launcher=adapter).start()
        with pytest.raises(RunnerHarnessError) as refused:
            await running.stop(signal.SIGKILL)
        assert refused.value.code == "runner_signal_invalid"
        assert running.returncode is None
    finally:
        await adapter.close()


async def test_launcher_exception_cannot_expose_private_stdin(tmp_path):
    class BrokenAdapter(LocalAdapter):
        async def launch(self, invocation):
            raise OSError(invocation.stdin)

    code = secrets.token_urlsafe(24)
    with pytest.raises(RunnerHarnessError) as refused:
        await RunnerHarness(inputs(tmp_path), launcher=BrokenAdapter()).register(
            "https://secrets.example", code=code
        )
    assert refused.value.code == "runner_launch_failed"
    assert code not in str(refused.value) + repr(refused.value)
    assert refused.value.__suppress_context__
