"""Real child processes; parameters and credentials never become shell text."""

import asyncio
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest
from aweb_secrets_values import encode_value

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.execution import execute
from aweb_secrets_runner.jobs import RunnerConfig, job_digest
from aweb_secrets_runner.protocol import canonical

RUNNER = "rnr_Unqp9DFTnajhUdVDTR1eYQ"


def configuration(tmp_path, source, *, output_max=4096, timeout=5):
    program = Path(sys.executable).resolve()
    script = tmp_path / "job.py"
    script.write_text(source)
    body = {
        "v": 1,
        "job_id": "fixture",
        "runner_ids": [RUNNER],
        "kind": "exec",
        "exec": {
            "path": str(program),
            "sha256": hashlib.sha256(program.read_bytes()).hexdigest(),
            "files": [
                {"path": str(script), "sha256": hashlib.sha256(script.read_bytes()).hexdigest()}
            ],
        },
        "oci": None,
        "argv": [str(script), "--", {"$param": "arg", "slot": "positional"}],
        "env": {"CREDENTIAL": {"$credential": "db", "field": "password"}},
        "cwd": str(tmp_path),
        "timeout_s": timeout,
        "output": {"max_bytes": output_max, "projection": ["/exit_code", "/stdout", "/stderr"]},
        "params": {"arg": {"schema": {"type": "string", "maxLength": 256}, "charset": None}},
        "credentials": [{"secret_ref": "db", "delivery": "durable", "mint": None}],
        "allow_durable": True,
    }
    path = tmp_path / "config.json"
    path.write_bytes(
        canonical(
            {
                "v": 1,
                "agent_uids": [os.geteuid() + 1],
                "jobs": {"fixture": {"digest": job_digest(body), "definition": body}},
            }
        )
    )
    return path, body


def run_job(path, body, *, arg="literal", credential="fixture-password", started=None):
    return asyncio.run(
        execute(
            RunnerConfig.load(path),
            job_id="fixture",
            digest=job_digest(body),
            runner_id=RUNNER,
            params={"arg": arg},
            credentials=[encode_value("basic", {"username": "", "password": credential})],
            expires_at=time.time() + 300,
            started=started,
        )
    )


def test_real_process_gets_only_declared_environment_and_literal_arguments(tmp_path, monkeypatch):
    source = """import json,os,sys
print(json.dumps({"inherited":os.environ.get("INHERITED_FIXTURE"),"arg":sys.argv[-1],"credential_present":"CREDENTIAL" in os.environ}))
"""
    path, body = configuration(tmp_path, source)
    monkeypatch.setenv("INHERITED_FIXTURE", "must-not-be-in-job")
    arg = "; touch " + str(tmp_path / "must-not-exist")
    report = run_job(path, body, arg=arg)
    assert report["exit_code"] == 0
    result = json.loads(report["stdout"])
    assert result == {"inherited": None, "arg": arg, "credential_present": True}
    assert not (tmp_path / "must-not-exist").exists()
    assert report["redaction_count"] == 0 and not report["result_withheld"]


def test_local_known_encodings_are_redacted_before_the_report(tmp_path):
    source = """import os,sys,base64
value=os.environ["CREDENTIAL"]
print(value)
print(base64.b64encode(value.encode()).decode(),file=sys.stderr)
"""
    path, body = configuration(tmp_path, source)
    credential = os.urandom(24).hex()
    report = run_job(path, body, credential=credential)
    assert credential not in repr(report)
    assert "[REDACTED:db]" in report["stdout"] and "[REDACTED:db]" in report["stderr"]
    assert report["redaction_count"] >= 2 and not report["result_withheld"]


def test_unknown_credential_shape_withholds_both_streams(tmp_path):
    path, body = configuration(tmp_path, 'print(\'{"password":"unexpected-value"}\')')
    report = run_job(path, body)
    assert report["stdout"] == report["stderr"] == ""
    assert report["result_withheld"]


def test_bounded_output_drains_both_pipes_and_preserves_scalar_boundaries(tmp_path):
    path, body = configuration(
        tmp_path,
        """import sys
sys.stdout.write("é"*50000)
sys.stderr.write("😀"*50000)
""",
        output_max=41,
    )
    report = run_job(path, body)
    assert report["exit_code"] == 0
    assert len(report["stdout"].encode()) + len(report["stderr"].encode()) <= 41
    assert report["truncated"]
    assert "�" not in report["stdout"] + report["stderr"]


def test_timeout_kills_the_job_and_bounds_execution(tmp_path):
    path, body = configuration(tmp_path, "import time; time.sleep(30)", timeout=1)
    before = time.monotonic()
    report = run_job(path, body)
    assert time.monotonic() - before < 5
    assert report["exit_code"] != 0


def test_started_is_observation_after_a_real_spawn(tmp_path):
    release = tmp_path / "release"
    path, body = configuration(
        tmp_path,
        f"""import pathlib,time
while not pathlib.Path({str(release)!r}).exists():
    time.sleep(0.01)
print("finished")
""",
    )
    seen = []

    async def started(pid):
        os.kill(pid, 0)
        seen.append(pid)
        release.touch()

    assert run_job(path, body, started=started)["exit_code"] == 0
    assert len(seen) == 1


def test_invalid_utf8_is_withheld_even_beyond_capture_limit(tmp_path):
    path, body = configuration(tmp_path, 'import os;os.write(1,b"x"*10000+b"\\xff")', output_max=10)
    report = run_job(path, body)
    assert report["result_withheld"] and report["truncated"]
    assert report["stdout"] == report["stderr"] == ""


def test_truncated_known_prefix_never_reaches_the_report(tmp_path):
    path, body = configuration(tmp_path, 'import os;print(os.environ["CREDENTIAL"])', output_max=9)
    report = run_job(path, body, credential="unique-credential-canary")
    assert "unique" not in report["stdout"] + report["stderr"]
    assert report["redaction_count"] >= 1 and report["truncated"]


def test_expired_assignment_does_not_start_a_process(tmp_path):
    marker = tmp_path / "executed"
    path, body = configuration(tmp_path, f"from pathlib import Path;Path({str(marker)!r}).touch()")
    with pytest.raises(Refused, match="assignment_expired"):
        asyncio.run(
            execute(
                RunnerConfig.load(path),
                job_id="fixture",
                digest=job_digest(body),
                runner_id=RUNNER,
                params={"arg": "literal"},
                credentials=[encode_value("basic", {"username": "", "password": "fixture"})],
                expires_at=time.time() - 1,
            )
        )
    assert not marker.exists()


def test_started_network_wait_does_not_extend_the_job_deadline(tmp_path):
    path, body = configuration(tmp_path, "import time;time.sleep(30)", timeout=1)

    async def started(pid):
        await asyncio.Event().wait()

    before = time.monotonic()
    assert run_job(path, body, started=started)["exit_code"] != 0
    assert time.monotonic() - before < 5


def test_cancellation_kills_and_reaps_the_real_child(tmp_path):
    path, body = configuration(tmp_path, "import time;time.sleep(30)")

    async def scenario():
        ready = asyncio.Event()
        seen = []

        async def started(pid):
            seen.append(pid)
            ready.set()

        task = asyncio.create_task(
            execute(
                RunnerConfig.load(path),
                job_id="fixture",
                digest=job_digest(body),
                runner_id=RUNNER,
                params={"arg": "literal"},
                credentials=[encode_value("basic", {"username": "", "password": "fixture"})],
                expires_at=time.time() + 300,
                started=started,
            )
        )
        await asyncio.wait_for(ready.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(ProcessLookupError):
            os.kill(seen[0], 0)

    asyncio.run(scenario())


def test_timeout_covers_descendants_holding_the_output_pipes(tmp_path):
    path, body = configuration(
        tmp_path,
        f"""import subprocess
subprocess.Popen([{sys.executable!r},"-c","import time;time.sleep(30)"])
""",
        timeout=1,
    )
    before = time.monotonic()
    report = run_job(path, body)
    assert time.monotonic() - before < 5
    assert report["exit_code"] != 0


def test_an_escaped_pipe_holder_cannot_stall_the_runner(tmp_path):
    marker = tmp_path / "escaped-pid"
    child = f"import os,pathlib,time;pathlib.Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(30)"
    path, body = configuration(
        tmp_path,
        f"""import subprocess
subprocess.Popen([{sys.executable!r},"-c",{child!r}],start_new_session=True)
""",
        timeout=1,
    )
    before = time.monotonic()
    try:
        report = run_job(path, body)
        assert time.monotonic() - before < 5
        assert report["exit_code"] != 0
    finally:
        # A trusted job can escape its process group: this test owns and reaps
        # that fixture separately. The runner bounds its own pipe lifetime.
        if marker.exists():
            try:
                os.kill(int(marker.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
