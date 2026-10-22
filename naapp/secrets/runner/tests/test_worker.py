"""Real TLS, signed assignments, HPKE, journal and child-process composition.

This local same-UID harness is not the separate-user S19 release acceptance.
"""

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from aweb_secrets_values import encode_value
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_execution import RUNNER, configuration
from test_registration import invoke
from test_registration import service as _service

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.http import RunnerHTTP
from aweb_secrets_runner.jobs import RunnerConfig, job_digest
from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.protocol import canonical, decode64, encode64, public_did
from aweb_secrets_runner.state import IdentityStore
from aweb_secrets_runner.worker import Worker

DISPATCH = "dsp_" + "a" * 22
HEADERS = {"Cache-Control": "no-store", "Content-Type": "application/json"}
service = _service


def configured(service, tmp_path, *, source=None):  # noqa: F811
    signing = Ed25519PrivateKey.generate()
    service["response"].update(runner_id=RUNNER, service_kid=public_did(signing.public_key()))
    identity = invoke(service)
    service["requests"].clear()
    service["raw_requests"].clear()
    marker = tmp_path / "executions"
    journal_path = service["state_dir"] / "journal.sqlite3"
    path, body = configuration(
        tmp_path,
        source
        or (
            f"import os,sqlite3\nwith sqlite3.connect({str(journal_path)!r}) as db:\n"
            f'    assert db.execute("SELECT dispatch_id FROM dispatches").fetchone()[0] == {DISPATCH!r}\n'
            f'with open({str(marker)!r},"ab") as f: f.write(b"ran\\n")\n'
            'print(os.environ["CREDENTIAL"])\n'
        ),
    )
    secret = os.urandom(24).hex()
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    credentials = [
        {
            "secret_ref": "db",
            "sealed": encode64(
                suite.encrypt(
                    encode_value("basic", {"username": "", "password": secret}),
                    identity.encryption_key.public_key(),
                    DISPATCH.encode(),
                )
            ),
        }
    ]
    params = {"arg": "literal"}
    now = datetime.now(UTC).replace(microsecond=0)
    assignment = {
        "v": 1,
        "type": "aweb.secrets.runner-assignment",
        "origin": identity.origin,
        "service_kid": identity.service_kid,
        "runner_id": identity.runner_id,
        "dispatch_id": DISPATCH,
        "job_id": "fixture",
        "job_digest": job_digest(body),
        "params_sha256": hashlib.sha256(canonical(params)).hexdigest(),
        "credentials_sha256": hashlib.sha256(canonical(credentials)).hexdigest(),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    document = {"assignment": assignment, "params": params, "credentials": credentials}

    def signed():
        return canonical(
            {
                **document,
                "signature": encode64(
                    signing.sign(b"aweb.secrets.runner-assignment/1\n" + canonical(assignment))
                ),
            }
        )

    journal = Journal(journal_path)
    state = {
        "raw": signed(),
        "reports": [],
        "acked": False,
        "fail_result": False,
        "idle": Event(),
        "started": Event(),
        "secret": secret,
        "nonces": [],
    }

    def respond(path, raw, headers):
        encoded, signature = headers["X-AWEB-Secrets-Runner-Request"].split(".")
        payload = decode64(encoded)
        identity.signing_key.public_key().verify(
            decode64(signature), b"aweb.secrets.runner-request/1\n" + payload
        )
        binding = json.loads(payload)
        assert binding["path"] == path and binding["body_sha256"] == hashlib.sha256(raw).hexdigest()
        assert binding["nonce"] not in state["nonces"]
        state["nonces"].append(binding["nonce"])
        if path.endswith("/claim"):
            if state.pop("lose_claim", False):
                service["disconnect"] = True
            if state["acked"]:
                state["idle"].set()
                return 204, b"", HEADERS
            return 200, state["raw"], HEADERS
        if path.endswith("/started"):
            state["started"].set()
            if state.get("fail_started"):
                return 503, b'{"detail":{"code":"runner_unavailable"}}', HEADERS
            return 204, b"", HEADERS
        assert path.endswith("/result")
        # Save-before-send is observed through a separate real SQLite connection.
        assert Journal(journal_path).pending_results()[0].body == raw
        assert secret.encode() not in raw
        state["reports"].append(raw)
        if state.pop("fail_result_once", False) or state["fail_result"]:
            return 503, b'{"detail":{"code":"runner_unavailable"}}', HEADERS
        state["acked"] = True
        return 204, b"", HEADERS

    service["respond"] = respond
    return identity, RunnerConfig.load(path), journal, marker, state, document, signed, path


def test_real_worker_verifies_opens_executes_sanitizes_saves_and_acknowledges(service, tmp_path):  # noqa: F811
    identity, config, journal, marker, state, _, _, _ = configured(service, tmp_path)

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert await Worker(identity, config, journal, client).step()

    asyncio.run(scenario())
    assert marker.read_bytes() == b"ran\n"
    report = json.loads(state["reports"][0])
    assert report["exit_code"] == 0 and report["redaction_count"] >= 1
    assert "[REDACTED:db]" in report["stdout"]
    assert journal.pending_results() == ()
    for private_file in service["state_dir"].iterdir():
        assert state["secret"].encode() not in private_file.read_bytes()


def test_lost_claim_response_retries_stored_assignment_without_a_second_execution(
    service, tmp_path
):  # noqa: F811
    identity, config, journal, marker, state, _, _, _ = configured(service, tmp_path)
    state["lose_claim"] = True
    state["fail_started"] = True

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            worker = Worker(identity, config, journal, client)
            with pytest.raises(Refused, match="runner_unavailable"):
                await worker.step()
            assert not marker.exists()
            assert await worker.step()

    asyncio.run(scenario())
    assert marker.read_bytes() == b"ran\n"
    assert len(state["reports"]) == 1
    assert journal.pending_results() == ()


def test_uncertain_result_reopens_and_flushes_identical_bytes_before_next_claim(service, tmp_path):  # noqa: F811
    identity, config, journal, marker, state, _, _, _ = configured(service, tmp_path)
    state["fail_result"] = True

    async def failed():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused, match="runner_unavailable"):
                await Worker(identity, config, journal, client).step()

    asyncio.run(failed())
    assert marker.read_bytes() == b"ran\n"
    saved = Journal(journal.path).pending_results()[0].body
    state["fail_result"] = False
    before = len(service["requests"])

    async def retry():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            assert not await Worker(identity, config, Journal(journal.path), client).step()

    asyncio.run(retry())
    assert [path.rsplit("/", 1)[-1] for path, _ in service["requests"][before:]] == [
        "result",
        "claim",
    ]
    assert state["reports"] == [saved, saved]
    assert marker.read_bytes() == b"ran\n"
    assert journal.pending_results() == ()


def test_replayed_accepted_assignment_never_executes_again(service, tmp_path):  # noqa: F811
    identity, config, journal, marker, state, _, _, _ = configured(service, tmp_path)

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            worker = Worker(identity, config, journal, client)
            await worker.step()
            state["acked"] = False  # Stored assignment returned again after uncertainty.
            with pytest.raises(Refused, match="assignment_replayed"):
                await worker.step()

    asyncio.run(scenario())
    assert marker.read_bytes() == b"ran\n"
    assert len(state["reports"]) == 1


@pytest.mark.parametrize(
    "defect,code",
    [
        ("signature", "assignment_invalid"),
        ("pin", "job_not_allowed"),
        ("params", "params_invalid"),
        ("slot", "credential_invalid"),
        ("expired", "assignment_expired"),
    ],
)
def test_refusal_never_spawns_or_fabricates_a_result(service, tmp_path, defect, code):  # noqa: F811
    identity, config, journal, marker, state, doc, signed, _ = configured(service, tmp_path)
    if defect == "signature":
        broken = json.loads(state["raw"])
        broken["signature"] = encode64(os.urandom(64))
        state["raw"] = canonical(broken)
    else:
        if defect == "pin":
            doc["assignment"]["job_digest"] = "0" * 64
        elif defect == "params":
            doc["params"]["arg"] = "-unsafe"
            doc["assignment"]["params_sha256"] = hashlib.sha256(
                canonical(doc["params"])
            ).hexdigest()
        elif defect == "slot":
            doc["credentials"][0]["secret_ref"] = "other"
            doc["assignment"]["credentials_sha256"] = hashlib.sha256(
                canonical(doc["credentials"])
            ).hexdigest()
        else:
            doc["assignment"]["issued_at"] = "2000-01-01T00:00:00Z"
            doc["assignment"]["expires_at"] = "2000-01-01T00:05:00Z"
        state["raw"] = signed()

    async def scenario():
        async with RunnerHTTP(identity, ca_file=service["ca_file"]) as client:
            with pytest.raises(Refused, match=code):
                await Worker(identity, config, journal, client).step()

    asyncio.run(scenario())
    assert not marker.exists() and state["reports"] == []
    assert journal.pending_results() == ()
    with sqlite3.connect(journal.path) as db:
        assert db.execute("SELECT count(*) FROM dispatches").fetchone()[0] == (
            0 if defect in {"signature", "expired"} else 1
        )


@pytest.mark.parametrize("retry", [False, True])
def test_real_run_command_and_second_worker_exclusion(service, tmp_path, retry):  # noqa: F811
    _, _, journal, marker, state, _, _, config_path = configured(service, tmp_path)
    state["fail_result_once"] = retry
    command = [
        sys.executable,
        "-m",
        "aweb_secrets_runner",
        "run",
        "--config",
        str(config_path),
        "--state-dir",
        str(service["state_dir"]),
        "--ca-file",
        str(service["ca_file"]),
    ]
    with IdentityStore(service["state_dir"]).worker_lock():
        rejected = subprocess.run(command, capture_output=True, timeout=5)
    assert rejected.returncode == 1 and rejected.stderr == b"runner_busy\n"
    assert service["requests"] == []
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        assert state["idle"].wait(5)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 143 and stdout == stderr == b""
        assert marker.read_bytes() == b"ran\n"
        assert journal.pending_results() == ()
        if retry:
            assert len(state["reports"]) == 2
            assert state["reports"][0] == state["reports"][1]
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


@pytest.mark.parametrize("stop,exit_code", [(signal.SIGTERM, 143), (signal.SIGINT, 130)])
def test_signal_cleans_real_job_without_rearming_or_fabricating_result(
    service, tmp_path, stop, exit_code
):
    marker = tmp_path / "executions"
    source = (
        f'import os,time\nwith open({str(marker)!r},"w") as f: f.write(str(os.getpid()))\n'
        "time.sleep(30)\n"
    )
    _, _, journal, _, state, _, _, config_path = configured(service, tmp_path, source=source)
    command = [
        sys.executable,
        "-m",
        "aweb_secrets_runner",
        "run",
        "--config",
        str(config_path),
        "--state-dir",
        str(service["state_dir"]),
        "--ca-file",
        str(service["ca_file"]),
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        assert state["started"].wait(5)
        deadline = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < deadline:
            Event().wait(0.01)
        pid = int(marker.read_text())
        process.send_signal(stop)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == exit_code and stdout == stderr == b""
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        assert state["reports"] == [] and journal.pending_results() == ()
        restarted = subprocess.run(command, capture_output=True, timeout=5)
        assert restarted.returncode == 1 and restarted.stderr == b"assignment_replayed\n"
        assert int(marker.read_text()) == pid
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
