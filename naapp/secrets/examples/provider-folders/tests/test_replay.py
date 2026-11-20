import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
import pytest

from replay import TOKEN_ENV, ExitCode, RunRefused, load_config, main, run
from submit import submit
from tests.outbox import provision_outbox
from tests.standin import TOKEN, OneDriveStandIn
from tests.tls import APPROOT, GraphListener, make_ca_and_server_cert

HERE = Path(__file__).resolve().parents[1]
ORIGIN = "https://graph.standin.invalid"
SEAT = "fictional-seat"


@pytest.fixture
def standin():
    return OneDriveStandIn()


@pytest.fixture
def outbox_dir(tmp_path):
    path = tmp_path / "outbox"
    path.mkdir()
    provision_outbox(path)
    return path


@pytest.fixture
def config_body(tmp_path, outbox_dir, standin):
    return {
        "seat": SEAT,
        "state_dir": str(tmp_path / "publisher-state"),
        "outbox": str(outbox_dir),
        "max_bytes": 20 * 1024 * 1024,
        "extensions": ["docx", "md", "pdf", "txt"],
        "destination": {
            "drive_id": standin.approot["parentReference"]["driveId"],
            "folder_id": standin.approot["id"],
        },
        "graph_origin": ORIGIN,
        "ca_bundle": None,
        "output_max_bytes": 65536,
    }


def write_config(tmp_path, body) -> Path:
    path = tmp_path / "publisher.json"
    path.write_text(json.dumps(body))
    return path


def replay(tmp_path, body, standin, token=TOKEN):
    requests = []

    def handle(request):
        requests.append(request)
        return standin.handle(request)

    config = load_config(write_config(tmp_path, body))
    client = httpx.Client(transport=httpx.MockTransport(handle))
    code, output = run(config, client, token)
    assert len(output) <= config.output_max_bytes
    return code, json.loads(output), requests


def queue(outbox_dir, content=b"# Synthetic brief\n", target="summary.md"):
    job_id = str(uuid.uuid4())
    submit(outbox_dir, job_id=job_id, content=content, extension="md", target=target)
    return job_id


def outcomes(report):
    return {receipt["job_id"]: receipt["outcome"] for receipt in report["receipts"]}


def test_a_run_publishes_every_queued_job_and_a_second_run_writes_nothing(
    tmp_path, config_body, outbox_dir, standin
):
    first = queue(outbox_dir, b"# One\n", "one.md")
    second = queue(outbox_dir, b"# Two\n", "two.md")

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.OK
    assert report["outcome"] == "ok" and report["reason"] is None
    assert outcomes(report) == {first: "published", second: "published"}
    assert sorted(item["name"] for item in standin.items.values()) == ["one.md", "two.md"]

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.OK
    assert outcomes(report) == {first: "already_published", second: "already_published"}
    assert standin.committed_uploads == 2


def test_a_refused_job_with_none_uncertain_exits_refused(
    tmp_path, config_body, outbox_dir, standin
):
    published = queue(outbox_dir, b"# Same\n", "same.md")
    duplicate = queue(outbox_dir, b"# Same\n", "same.md")

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.REFUSED
    assert report["outcome"] == "refused"
    receipts = {receipt["job_id"]: receipt for receipt in report["receipts"]}
    assert {receipts[published]["outcome"], receipts[duplicate]["outcome"]} == {
        "published",
        "refused",
    }
    assert len(standin.items) == 1


def test_uncertain_wins_over_refused(tmp_path, config_body, outbox_dir, standin):
    refused = queue(outbox_dir, b"# Refused\n", "refused.md")
    manifest = outbox_dir / f"{refused}.json"
    manifest.write_text(json.dumps({**json.loads(manifest.read_text()), "size": 1}))
    uncertain = queue(outbox_dir, b"# Lost answer\n", "lost.md")
    standin.lose_next_commit_response = True

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.UNCERTAIN
    assert report["outcome"] == "uncertain"
    assert outcomes(report) == {refused: "refused", uncertain: "uncertain"}

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.REFUSED
    assert outcomes(report) == {refused: "refused", uncertain: "already_published"}
    assert standin.committed_uploads == 1


@pytest.mark.parametrize(
    "token",
    [None, "", "\n", f"{TOKEN}\n", "two words", "x" * 16385, "tok\x01en", "tok@en", "to=ken"],
    ids=[
        "missing",
        "empty",
        "blank",
        "newline",
        "whitespace",
        "oversized",
        "control",
        "symbol",
        "inner-pad",
    ],
)
def test_an_unusable_token_refuses_the_run_before_any_provider_call(
    tmp_path, config_body, outbox_dir, standin, token
):
    queue(outbox_dir)

    code, report, requests = replay(tmp_path, config_body, standin, token)

    assert code is ExitCode.RUN_REFUSED
    assert report == {
        "v": 1,
        "outcome": "run_refused",
        "reason": "token_unavailable",
        "receipts": [],
    }
    assert requests == []


def test_the_bearer_goes_only_to_the_configured_origin(tmp_path, config_body, outbox_dir, standin):
    job_id = queue(outbox_dir)

    code, report, requests = replay(tmp_path, config_body, standin)

    assert code is ExitCode.OK
    assert outcomes(report) == {job_id: "published"}
    bearer = [request for request in requests if "Authorization" in request.headers]
    assert bearer and all(
        f"{request.url.scheme}://{request.url.host}" == ORIGIN for request in bearer
    )
    assert any(request.url.host != "graph.standin.invalid" for request in requests)


def test_a_destination_other_than_the_configured_one_refuses_the_run_before_any_write(
    tmp_path, config_body, outbox_dir, standin
):
    queue(outbox_dir)
    body = {**config_body, "destination": {"drive_id": "other-drive", "folder_id": "OTHER"}}

    code, report, requests = replay(tmp_path, body, standin)

    assert code is ExitCode.RUN_REFUSED
    assert report["reason"] == "destination_mismatch"
    assert standin.items == {}
    assert [request.method for request in requests] == ["GET"]


def test_an_unreadable_ledger_refuses_the_run(tmp_path, config_body, outbox_dir, standin):
    queue(outbox_dir)
    state = Path(config_body["state_dir"])
    state.mkdir()
    (state / "ledger.json").write_text("{not json")

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.RUN_REFUSED
    assert report["reason"] == "ledger_unreadable"
    assert standin.items == {}


def test_a_denied_token_refuses_the_run(tmp_path, config_body, outbox_dir, standin):
    queue(outbox_dir)
    standin.deny_all = True

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.RUN_REFUSED
    assert report["reason"] == "provider_denied"


def test_an_unavailable_provider_before_any_job_refuses_the_run(
    tmp_path, config_body, outbox_dir, standin
):
    queue(outbox_dir)
    standin.malformed_next = "approot"

    code, report, _ = replay(tmp_path, config_body, standin)

    assert code is ExitCode.RUN_REFUSED
    assert report["reason"] == "provider_unavailable"
    assert standin.items == {}


def test_output_over_the_bound_fails_the_run_with_a_summary_never_truncated_json(
    tmp_path, config_body, outbox_dir, standin
):
    jobs = [queue(outbox_dir, f"# Report {n}\n".encode(), f"report-{n}.md") for n in range(8)]
    body = {**config_body, "output_max_bytes": 512}

    code, report, _ = replay(tmp_path, body, standin)

    assert code is ExitCode.OUTPUT_TOO_LARGE
    assert report == {
        "v": 1,
        "outcome": "output_too_large",
        "reason": None,
        "counts": {"published": len(jobs)},
    }
    assert len(standin.items) == len(jobs)


@pytest.mark.parametrize(
    "origin",
    [
        "http://graph.standin.invalid",
        "https://graph.standin.invalid/v1.0",
        "https://graph.standin.invalid/",
        "https://user@graph.standin.invalid",
        "https://graph.standin.invalid?x=1",
        "https://graph.standin.invalid#x",
        "https://graph.standin.invalid:0",
        "https://graph.standin.invalid:99999",
        "HTTPS://graph.standin.invalid",
        "https://",
        "graph.standin.invalid",
        7,
    ],
)
def test_the_graph_origin_must_be_a_bare_https_origin(tmp_path, config_body, origin):
    with pytest.raises(RunRefused, match="config_invalid"):
        load_config(write_config(tmp_path, {**config_body, "graph_origin": origin}))


def test_a_graph_origin_may_name_a_port(tmp_path, config_body):
    body = {**config_body, "graph_origin": "https://graph.standin.invalid:8443"}
    assert load_config(write_config(tmp_path, body)).graph_origin == body["graph_origin"]


@pytest.mark.parametrize(
    "change",
    [
        {"seat": "Not A Slug"},
        {"state_dir": "relative/state"},
        {"outbox": "relative/outbox"},
        {"ca_bundle": "relative/ca.pem"},
        {"max_bytes": 0},
        {"max_bytes": True},
        {"extensions": "md"},
        {"extensions": ["md", ".pdf"]},
        {"destination": {"drive_id": "d"}},
        {"output_max_bytes": 511},
        {"unexpected": 1},
    ],
)
def test_an_invalid_config_is_refused(tmp_path, config_body, change):
    with pytest.raises(RunRefused, match="config_invalid"):
        load_config(write_config(tmp_path, {**config_body, **change}))


def test_a_config_without_a_field_is_refused(tmp_path, config_body):
    del config_body["ca_bundle"]
    with pytest.raises(RunRefused, match="config_invalid"):
        load_config(write_config(tmp_path, config_body))


def run_cli(*args, env=None):
    return subprocess.run(
        [sys.executable, "-I", str(HERE / "replay.py"), *args],
        capture_output=True,
        text=True,
        cwd="/",
        env=env or {},
        timeout=60,
    )


def test_the_cli_runs_isolated_and_refuses_a_missing_token_with_exit_5(tmp_path, config_body):
    result = run_cli("--config", str(write_config(tmp_path, config_body)))

    assert result.returncode == ExitCode.RUN_REFUSED == 5
    assert json.loads(result.stdout)["reason"] == "token_unavailable"
    assert result.stderr == ""


def test_the_cli_refuses_an_unreadable_config_with_exit_5(tmp_path):
    result = run_cli("--config", str(tmp_path / "missing.json"))

    assert result.returncode == 5
    assert json.loads(result.stdout) == {
        "v": 1,
        "outcome": "run_refused",
        "reason": "config_invalid",
        "receipts": [],
    }


def test_the_cli_without_a_config_argument_is_a_usage_error():
    assert run_cli().returncode == 2


def test_the_cli_refuses_an_unreadable_ca_bundle_with_exit_5(tmp_path, config_body):
    body = {**config_body, "ca_bundle": str(tmp_path / "missing-ca.pem")}

    result = run_cli("--config", str(write_config(tmp_path, body)))

    assert result.returncode == ExitCode.RUN_REFUSED
    assert json.loads(result.stdout)["reason"] == "config_invalid"
    assert result.stderr == ""


def test_a_vendored_file_cannot_shadow_a_standard_library_module(tmp_path, config_body):
    install = tmp_path / "install"
    install.mkdir()
    for name in ("replay.py", "publisher.py", "onedrive.py", "hashes.py"):
        shutil.copy2(HERE / name, install / name)
    (install / "vendor").mkdir()
    (install / "vendor" / "json.py").write_text("raise SystemExit(97)\n")

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(install / "replay.py"),
            "--config",
            str(write_config(tmp_path, config_body)),
        ],
        capture_output=True,
        text=True,
        cwd="/",
        timeout=60,
    )

    assert result.returncode == ExitCode.RUN_REFUSED
    assert json.loads(result.stdout)["reason"] == "token_unavailable"


def run_cli_with_env(config_path, env):
    return subprocess.run(
        [sys.executable, "-I", str(HERE / "replay.py"), "--config", str(config_path)],
        capture_output=True,
        text=True,
        cwd="/",
        env={TOKEN_ENV: TOKEN, **env},
        timeout=60,
    )


@pytest.fixture
def tls_listener(tmp_path):
    ca, cert, key = make_ca_and_server_cert(tmp_path)
    with GraphListener(cert, key) as listener:
        yield ca, listener


def tls_config(config_body, listener, ca_bundle):
    return {
        **config_body,
        "graph_origin": f"https://localhost:{listener.port}",
        "destination": {
            "drive_id": APPROOT["parentReference"]["driveId"],
            "folder_id": APPROOT["id"],
        },
        "ca_bundle": ca_bundle,
    }


def test_a_configured_ca_bundle_reaches_a_tls_origin_it_vouches_for(
    tmp_path, config_body, tls_listener
):
    ca, listener = tls_listener

    result = run_cli_with_env(
        write_config(tmp_path, tls_config(config_body, listener, str(ca))), {}
    )

    assert result.returncode == ExitCode.OK, result.stdout + result.stderr
    assert json.loads(result.stdout)["outcome"] == "ok"
    assert listener.requests and all(auth == f"Bearer {TOKEN}" for *_, auth in listener.requests)


def test_without_a_ca_bundle_the_environment_cannot_choose_the_trust_root(
    tmp_path, config_body, tls_listener
):
    ca, listener = tls_listener
    environment = {"SSL_CERT_FILE": str(ca), "SSL_CERT_DIR": str(ca.parent)}

    result = run_cli_with_env(
        write_config(tmp_path, tls_config(config_body, listener, None)), environment
    )

    assert result.returncode == ExitCode.RUN_REFUSED, result.stdout + result.stderr
    assert json.loads(result.stdout)["reason"] == "provider_unavailable"
    assert listener.requests == []


def test_tls_session_keys_are_never_logged_even_without_isolated_mode(
    tmp_path, config_body, tls_listener
):
    ca, listener = tls_listener
    keylog = tmp_path / "keys.log"
    config_path = write_config(tmp_path, tls_config(config_body, listener, str(ca)))

    result = subprocess.run(
        [sys.executable, str(HERE / "replay.py"), "--config", str(config_path)],
        capture_output=True,
        text=True,
        cwd="/",
        env={TOKEN_ENV: TOKEN, "SSLKEYLOGFILE": str(keylog)},
        timeout=60,
    )

    assert result.returncode == ExitCode.OK, result.stdout + result.stderr
    assert listener.requests
    assert not keylog.exists()


def test_the_token_is_removed_from_the_environment_before_anything_else(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)

    code = main(["--config", str(tmp_path / "missing.json")])

    assert code == ExitCode.RUN_REFUSED
    assert TOKEN_ENV not in os.environ
    assert TOKEN not in capsys.readouterr().out


def test_the_token_never_appears_in_output_or_receipts(tmp_path, config_body, tls_listener):
    ca, listener = tls_listener
    body = tls_config(config_body, listener, str(ca))
    queue(Path(body["outbox"]))
    listener_state = Path(body["state_dir"])

    result = run_cli_with_env(write_config(tmp_path, body), {})

    assert listener.requests
    written = "".join(path.read_text() for path in listener_state.rglob("*") if path.is_file())
    assert written and TOKEN not in written
    assert TOKEN not in result.stdout and TOKEN not in result.stderr
