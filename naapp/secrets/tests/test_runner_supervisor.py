"""Real local subprocess checks; the installed sudo/separate-UID proof is separate."""

import asyncio
import hashlib
import json
import os
import secrets
import shutil
import signal
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from runner_harness import Invocation, RunnerHarnessError
from runner_supervisor import Policy
from supervised_launcher import SupervisedLauncher

WORKER = """
import hashlib, json, os, signal, sys, time
from pathlib import Path
state = Path(sys.argv[sys.argv.index('--state-dir') + 1])
command = sys.argv[1]
if command == 'register':
    code = sys.stdin.buffer.read()
    assert code.endswith(b'\\n') and code.count(b'\\n') == 1
    assert code.strip().decode() not in [*sys.argv, *os.environ.values()]
    (state / 'registered').write_text(hashlib.sha256(code).hexdigest())
    print(code.decode(), flush=True)
    print(code.decode(), file=sys.stderr, flush=True)
    sys.exit(0)
if command == 'doctor':
    sys.exit(7)
for number in (signal.SIGTERM, signal.SIGINT):
    signal.signal(number, lambda n, f: sys.exit(128 + n))
(state / 'ready').write_text(json.dumps({'pid': os.getpid(), 'uid': os.geteuid(),
                                       'cwd': os.getcwd()}))
while True:
    time.sleep(.05)
"""


PYTHON = str(Path(sys.executable).resolve())


@pytest.fixture
def world(tmp_path):
    # The deployment policy checks all ancestors; tmp itself is intentionally
    # outside this existing-UID protocol test's boundary.
    prefix = tmp_path / "prefix"
    (prefix / "bin").mkdir(parents=True)
    # Candidate Python may be root-owned while the test prefix is user-owned.
    # Install the real executable under that prefix with its protected UID.
    python = Path(PYTHON)
    if python.stat().st_uid != os.geteuid():
        installed = prefix / "runtime" / "bin" / python.name
        installed.parent.mkdir(parents=True)
        shutil.copyfile(python, installed)
        installed.chmod(0o755)
        python = installed
    state = prefix / "runner-state"
    state.mkdir(mode=0o700)
    config = prefix / "runner-config.json"
    config.write_text("{}")
    config.chmod(0o600)
    (prefix / "supervisor-config.json").write_text(
        json.dumps({"origin": "https://service.example"})
    )
    binary = prefix / "bin" / "aweb-secrets-runner"
    binary.write_text(f"#!{python} -I\n" + WORKER)
    binary.chmod(0o755)
    (prefix / "bin" / "aweb-secrets-supervisor").write_text(f"#!{python} -I\n")
    policy = Policy(
        prefix,
        os.geteuid(),
        os.geteuid(),
        ancestor_root=prefix,
        interpreter=python,
        python_paths=(str(prefix),),
    )
    module_dir = Path(__file__).resolve().parents[1] / "e2e"
    bootstrap = (
        f"import sys; sys.path.insert(0, {str(module_dir)!r}); "
        "from runner_supervisor import Policy, supervise; "
        f"raise SystemExit(supervise(Policy({str(prefix)!r}, {os.geteuid()}, "
        f"{os.geteuid()}, ancestor_root={str(prefix)!r}, interpreter={str(python)!r}, "
        f"python_paths=({str(prefix)!r},))))"
    )
    command = (sys.executable, "-I", "-c", bootstrap)
    launcher = SupervisedLauncher(command=command, policy=policy)
    return policy, launcher, command


async def ready(path):
    async with asyncio.timeout(5):
        while not path.exists():
            await asyncio.sleep(0.01)
    return json.loads(path.read_text())


async def test_private_registration_and_observable_command_exit(world, capfd):
    policy, launcher, _ = world
    code = (secrets.token_urlsafe(24) + "\n").encode()
    process = await launcher.launch(Invocation(policy.argv("register"), "unused", code))
    assert await process.wait() == 0
    assert (policy.state / "registered").read_text() == hashlib.sha256(code).hexdigest()
    process = await launcher.launch(Invocation(policy.argv("doctor"), "unused"))
    assert await process.wait() == 7
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
async def test_controls_address_actual_worker_and_reap_it(world, number):
    policy, launcher, _ = world
    process = await launcher.launch(Invocation(policy.argv("run"), "unused"))
    observed = await ready(policy.state / "ready")
    identity = await process.identity()
    assert (identity.pid, identity.uid) == (observed["pid"], os.geteuid())
    assert observed["cwd"] == "/"
    await process.signal(number)
    assert await process.wait() == 128 + number
    with pytest.raises(ProcessLookupError):
        os.kill(identity.pid, 0)


async def test_driver_eof_terminates_and_reaps_worker(world):
    policy, _, command = world
    driver = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    driver.stdin.write(b'{"command":"run"}\n')
    await driver.stdin.drain()
    identity = json.loads(await driver.stdout.readline())
    assert json.loads(await driver.stdout.readline()) == {"exec": True}
    await ready(policy.state / "ready")
    driver.stdin.close()
    assert json.loads(await driver.stdout.readline()) == {"exit": 143}
    assert await driver.wait() == 0
    with pytest.raises(ProcessLookupError):
        os.kill(identity["pid"], 0)


async def test_supervisor_death_does_not_orphan_worker(world):
    policy, _, command = world
    driver = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    driver.stdin.write(b'{"command":"run"}\n')
    await driver.stdin.drain()
    identity = json.loads(await driver.stdout.readline())
    await driver.stdout.readline()
    await ready(policy.state / "ready")
    driver.kill()  # Exact process started by this test; guardian reaps its worker.
    await driver.wait()
    async with asyncio.timeout(5):
        while True:
            try:
                os.kill(identity["pid"], 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.01)


async def test_exec_failure_is_failed_launch(world):
    policy, launcher, _ = world
    binary = policy.prefix / "bin" / "aweb-secrets-runner"
    binary.chmod(0o644)  # Safe ownership/shebang, but exec itself refuses.
    with pytest.raises(RunnerHarnessError):
        await launcher.launch(Invocation(policy.argv("run"), "unused"))


async def test_stubborn_worker_is_killed_after_grace_and_reaped(world):
    policy, launcher, _ = world
    binary = policy.prefix / "bin" / "aweb-secrets-runner"
    binary.write_text(
        binary.read_text().replace(
            "signal.signal(number, lambda n, f: sys.exit(128 + n))",
            "signal.signal(number, signal.SIG_IGN)",
        )
    )
    process = await launcher.launch(Invocation(policy.argv("run"), "unused"))
    await ready(policy.state / "ready")
    await process.signal(signal.SIGTERM)
    async with asyncio.timeout(6):
        assert await process.wait() == -signal.SIGKILL
    with pytest.raises(ProcessLookupError):
        os.kill(process.pid, 0)


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
async def test_signals_to_supervisor_reach_its_owned_worker(world, number):
    policy, _, command = world
    driver = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    driver.stdin.write(b'{"command":"run"}\n')
    await driver.stdin.drain()
    await driver.stdout.readline()
    await driver.stdout.readline()
    await ready(policy.state / "ready")
    driver.send_signal(signal.SIGHUP)
    await asyncio.sleep(0.1)
    assert driver.returncode is None
    driver.send_signal(number)
    assert json.loads(await driver.stdout.readline()) == {"exit": 128 + number}
    assert await driver.wait() == 0


@pytest.mark.parametrize(
    "payload",
    [
        b'{"command":"run","path":"/bin/sh"}\n',
        b'{"command":"register","origin":"https://other.example","code":"unused"}\n',
        b'{"command":"run","command":"doctor"}\n',
        b'{"command":"shell"}\n',
        b"X" * 4097 + b"\n",
    ],
)
async def test_unknown_duplicate_oversized_requests_never_spawn(world, payload):
    policy, _, command = world
    driver = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await driver.communicate(payload)
    assert driver.returncode != 0
    assert stdout == stderr == b""
    assert not (policy.state / "ready").exists()


def test_policy_rejects_symlink_and_writable_runtime(world):
    policy, _, _ = world
    policy.check()
    module = policy.prefix / "module.pth"
    module.write_text("import os")
    module.chmod(0o666)
    with pytest.raises(ValueError):
        policy.check()
    module.unlink()
    module.symlink_to(policy.prefix / "runner-config.json")
    with pytest.raises(ValueError):
        policy.check()


def test_external_python_base_and_venv_configuration_refuse(world):
    policy, _, _ = world
    policy.check()
    # Use the actual host base outside this protocol fixture's prefix.
    with pytest.raises(ValueError):
        replace(policy, python_paths=(str(policy.prefix), sys.base_prefix)).check()
    with pytest.raises(ValueError):
        replace(policy, python_paths=None).check()
    (policy.prefix / "pyvenv.cfg").write_text(f"home = {sys.base_prefix}\n")
    with pytest.raises(ValueError):
        policy.check()
