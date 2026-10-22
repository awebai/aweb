"""Focused local TLS/S0/HPKE/OCI worker composition, not dedicated-user S19."""

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import unittest
from datetime import UTC, datetime, timedelta

import pytest
import test_lifecycle
from test_registration import service as _service
from test_worker import configured as configured_tls

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.http import RunnerHTTP
from aweb_secrets_runner.jobs import RunnerConfig, job_digest
from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.protocol import canonical
from aweb_secrets_runner.worker import Worker

service = _service

pytestmark = pytest.mark.skipif(
    os.environ.get("AWEB_SECRETS_OCI_PROOF") != "1", reason="explicit Linux OCI proof"
)


class NativeFixture(unittest.TestCase):
    """Reuse actual runtime helpers with synchronous unittest cleanup semantics."""

    command = test_lifecycle.LifecycleTests.command
    inputs = test_lifecycle.LifecycleTests.inputs
    config = test_lifecycle.LifecycleTests.config
    observe_container = test_lifecycle.LifecycleTests.observe_container
    assert_reaped = test_lifecycle.LifecycleTests.assert_reaped
    setUp = test_lifecycle.LifecycleTests.setUp


@pytest.fixture
def native():
    case = NativeFixture()
    case.setUp()
    try:
        yield case
    finally:
        assert case.doCleanups()


def runtime_spec(native):
    runtime = {"kind": "runc", "images": str(native.layout), "workspace": str(native.workspace)}
    for key in ("engine", "unpacker", "supervisor"):
        pin = getattr(native.runtime, key)
        runtime[key] = {"path": str(pin.path), "sha256": pin.sha256}
    return runtime


def configured(service, tmp_path, native, *, script=None, timeout=5):
    identity, _, journal, marker, state, document, signed, _ = configured_tls(service, tmp_path)
    _, body = native.config(
        script or 'printf "%s\\n" "$PASSWORD"; /bin/busybox pwd', timeout=timeout
    )
    body["runner_ids"] = [identity.runner_id]
    path = native.root / "runner.json"
    value = json.loads(path.read_bytes())
    value["jobs"]["fixture"] = {"digest": job_digest(body), "definition": body}
    runtime = runtime_spec(native)
    value["runtime"] = runtime
    path.write_bytes(canonical(value))
    document["params"] = {}
    document["assignment"]["job_digest"] = job_digest(body)
    document["assignment"]["params_sha256"] = hashlib.sha256(canonical({})).hexdigest()
    state["raw"] = signed()
    return identity, RunnerConfig.load(path), journal, marker, state, document, signed, path


def test_real_tls_assignment_is_journaled_run_redacted_and_durably_acknowledged(
    service, tmp_path, native
):
    identity, config, journal, marker, state, _, _, _ = configured(service, tmp_path, native)

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert await Worker(identity, config, journal, client, runtime=config.runtime()).step()

    asyncio.run(scenario())
    assert not marker.exists()  # The previous host-exec fixture was never run.
    report = json.loads(state["reports"][0])
    assert report["exit_code"] == 0 and report["redaction_count"] >= 1
    assert "/pinned-work" in report["stdout"]
    assert state["secret"] not in json.dumps(report)
    assert journal.pending_results() == ()
    assert list(native.workspace.iterdir()) == []
    for path in service["state_dir"].iterdir():
        assert state["secret"].encode() not in path.read_bytes()


def test_configured_runtime_preserves_the_host_exec_path(service, tmp_path, native):
    identity, _, journal, marker, state, _, _, path = configured_tls(service, tmp_path)
    document = json.loads(path.read_bytes())
    document["runtime"] = runtime_spec(native)
    path.write_bytes(canonical(document))
    config = RunnerConfig.load(path)

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert await Worker(identity, config, journal, client, runtime=config.runtime()).step()

    asyncio.run(scenario())
    assert marker.read_bytes() == b"ran\n"
    assert len(state["reports"]) == 1 and journal.pending_results() == ()
    assert list(native.workspace.iterdir()) == []


def test_saved_oci_report_retries_exact_bytes_before_claim_without_reexecution(
    service, tmp_path, native
):
    identity, config, journal, _, state, _, _, _ = configured(service, tmp_path, native)
    state["fail_result"] = True

    async def fail():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused, match="runner_unavailable"):
                await Worker(identity, config, journal, client, runtime=config.runtime()).step()

    asyncio.run(fail())
    saved = Journal(journal.path).pending_results()[0].body
    state["fail_result"] = False
    before = len(service["requests"])

    async def retry():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert not await Worker(
                identity, config, Journal(journal.path), client, runtime=config.runtime()
            ).step()

    asyncio.run(retry())
    assert [path.rsplit("/", 1)[-1] for path, _ in service["requests"][before:]] == [
        "result",
        "claim",
    ]
    assert state["reports"] == [saved, saved]
    assert list(native.workspace.iterdir()) == []


@pytest.mark.parametrize(
    "defect,code",
    [
        ("runtime", "runner_runtime_unavailable"),
        ("slot", "credential_invalid"),
        ("expired", "assignment_expired"),
    ],
)
def test_refused_oci_assignment_never_opens_or_reports(service, tmp_path, native, defect, code):
    identity, config, journal, _, state, document, signed, _ = configured(service, tmp_path, native)
    runtime = config.runtime()
    if defect == "runtime":
        runtime = None
    elif defect == "slot":
        document["credentials"][0]["secret_ref"] = "wrong-slot"
        document["assignment"]["credentials_sha256"] = hashlib.sha256(
            canonical(document["credentials"])
        ).hexdigest()
    else:
        now = datetime.now(UTC)
        document["assignment"]["issued_at"] = (now - timedelta(minutes=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        document["assignment"]["expires_at"] = (now - timedelta(minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    state["raw"] = signed()

    async def refused():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused, match=code):
                await Worker(identity, config, journal, client, runtime=runtime).step()

    asyncio.run(refused())
    assert state["reports"] == [] and journal.pending_results() == ()
    assert list(native.workspace.iterdir()) == []


def command(service, path):
    return [
        sys.executable,
        "-m",
        "aweb_secrets_runner",
        "run",
        "--config",
        str(path),
        "--state-dir",
        str(service["state_dir"]),
        "--ca-file",
        str(service["ca_file"]),
    ]


def test_real_run_command_executes_oci_then_restarts_without_rerunning(service, tmp_path, native):
    _, _, journal, _, state, _, _, path = configured(service, tmp_path, native)
    args = command(service, path)
    for _attempt in range(2):
        state["idle"].clear()
        process = subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            assert state["idle"].wait(5)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 143 and stdout == stderr == b""
            assert len(state["reports"]) == 1
            assert journal.pending_results() == ()
            assert list(native.workspace.iterdir()) == []
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


@pytest.mark.parametrize("hard", [False, True])
def test_real_worker_death_stops_oci_and_restart_refuses_accepted_replay(
    service, tmp_path, native, hard
):
    _, _, journal, _, state, _, _, path = configured(
        service, tmp_path, native, script="/bin/busybox sleep 30 & wait", timeout=2 if hard else 30
    )
    args = command(service, path)
    process = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    pids = []
    try:
        assert state["started"].wait(5)

        async def observe():
            await native.observe_container(asyncio.Event(), pids)

        asyncio.run(observe())
        process.send_signal(signal.SIGKILL if hard else signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == (-signal.SIGKILL if hard else 143)
        assert stdout == stderr == b""
        asyncio.run(native.assert_reaped(pids))
        assert state["reports"] == [] and journal.pending_results() == ()
        restarted = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        assert restarted.returncode == 1 and restarted.stderr == b"assignment_replayed\n"
        assert restarted.stdout == b""
        assert list(native.workspace.iterdir()) == []
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        from aweb_secrets_runner.oci_recovery import recover

        asyncio.run(recover(native.runtime))
