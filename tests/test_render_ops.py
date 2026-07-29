from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from email.message import Message
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from scripts import render_ops

_SHA_A = "a" * 40


def health_payload(git_sha: str | None = _SHA_A) -> dict:
    return {"status": "ok", "service": "library", "build": {"git_sha": git_sha}}


def health_bytes(git_sha: str | None = _SHA_A) -> bytes:
    return json.dumps(health_payload(git_sha), separators=(",", ":")).encode()


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    """Evidence tests require a private temporary root outside the repository."""
    with tempfile.TemporaryDirectory(prefix="library-render-ops-tests-") as directory:
        path = Path(directory).resolve(strict=True)
        path.chmod(0o700)
        yield path


def test_repo_identifies_production_without_treating_render_blueprint_as_authority() -> None:
    repo_root = Path(__file__).parents[1]
    render_blueprint = (repo_root / "render.yaml").read_text(encoding="utf-8")
    operations_doc = (repo_root / "docs" / "production-operations.md").read_text(
        encoding="utf-8"
    )
    production = render_ops.ProductionConfig.load(repo_root / "ops" / "render-production.json")

    assert "NOT the production topology authority" in render_blueprint
    assert "Folio" in render_blueprint
    assert "c621010" in render_blueprint
    assert "ops/render-production.json" in render_blueprint
    assert "Credential-less topology boundary" in operations_doc
    assert (
        "CI cannot prove the reviewed artifact is the one currently live or that Cloudflare "
        "and Render accept the production client; production smoke cannot substitute for "
        "source-level customer journeys."
    ) in operations_doc
    assert "named protected integration smoke" in operations_doc
    for identity_value in (
        production.service_id,
        production.service_name,
        production.region,
        production.origin_url,
        production.public_url,
    ):
        assert f"`{identity_value}`" in operations_doc


@pytest.fixture
def config(tmp_path: Path) -> render_ops.ProductionConfig:
    path = tmp_path / "production.json"
    path.write_text(
        json.dumps(
            {
                "service_id": "srv-abc123",
                "service_name": "library",
                "region": "virginia",
                "repo": "https://github.com/awebai/library",
                "branch": "main",
                "origin_url": "https://library-origin.example",
                "public_url": "https://library.example",
                "health_path": "/health",
            }
        )
    )
    return render_ops.ProductionConfig.load(path)


def write_config(path: Path, config: render_ops.ProductionConfig) -> None:
    path.write_text(
        json.dumps(
            {
                key: getattr(config, key)
                for key in (
                    "service_id",
                    "service_name",
                    "region",
                    "repo",
                    "branch",
                    "origin_url",
                    "public_url",
                    "health_path",
                )
            }
        )
    )


def health_proof_args(config_path: Path, evidence_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        config=str(config_path),
        evidence_dir=str(evidence_path),
        expected_commit=_SHA_A,
        allow_legacy_missing_build_for=_SHA_A,
    )


def service(config: render_ops.ProductionConfig) -> dict:
    return {
        "id": config.service_id,
        "name": config.service_name,
        "repo": config.repo,
        "branch": config.branch,
        "autoDeploy": "no",
        "suspended": "not_suspended",
        "serviceDetails": {"region": config.region, "url": config.origin_url},
    }


def deploy(deploy_id: str, commit: str, status: str = "live") -> dict:
    return {"id": deploy_id, "status": status, "commit": {"id": commit}}


def test_load_api_key_requires_private_file(tmp_path: Path) -> None:
    path = tmp_path / "render.env"
    path.write_text("RENDER_API_KEY=secret-value\n")
    path.chmod(0o644)
    with pytest.raises(render_ops.OpsError, match="group/world"):
        render_ops.load_api_key(path)
    path.chmod(0o600)
    assert render_ops.load_api_key(path) == "secret-value"
    link = tmp_path / "linked.env"
    link.symlink_to(path)
    with pytest.raises(render_ops.OpsError, match="symlink"):
        render_ops.load_api_key(link)


def test_git_repo_canonicalization_accepts_https_and_ssh_forms() -> None:
    assert render_ops.canonical_git_repo("git@github.com:awebai/library.git") == (
        render_ops.canonical_git_repo("https://github.com/awebai/library")
    )


def test_render_client_deploy_uses_exact_clear_cache_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, *args) -> bytes:
            return json.dumps(
                {"id": "dep-created", "commit": {"id": "b" * 40}, "status": "build_in_progress"}
            ).encode()

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["method"] = request.method
        seen["payload"] = json.loads(request.data)
        seen["authorization"] = request.get_header("Authorization")
        return Response()

    monkeypatch.setattr(render_ops, "urlopen", fake_urlopen)
    client = render_ops.RenderClient("private-token")
    result = client.deploy("srv-abc123", "b" * 40)
    assert result["id"] == "dep-created"
    assert seen == {
        "url": "https://api.render.com/v1/services/srv-abc123/deploys",
        "method": "POST",
        "payload": {"clearCache": "clear", "commitId": "b" * 40},
        "authorization": "Bearer private-token",
    }


def test_render_api_failure_never_exposes_key(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(request, timeout):
        raise HTTPError(request.full_url, 403, "denied", {}, None)

    monkeypatch.setattr(render_ops, "urlopen", fail)
    with pytest.raises(render_ops.OpsError) as raised:
        render_ops.RenderClient("do-not-print-this").service("srv-abc123")
    assert "do-not-print-this" not in str(raised.value)


def test_health_rejects_redirected_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return "https://library.example/health"

        def read(self, *args) -> bytes:
            return health_bytes()

    monkeypatch.setattr(
        render_ops, "open_health_url", lambda url, timeout, user_agent: Response()
    )
    with pytest.raises(render_ops.OpsError, match="redirected away"):
        render_ops.verify_health(
            "https://library-origin.example/health", expected_commit=_SHA_A
        )


def test_health_requires_exact_approved_build_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return "https://library.example/health"

        def read(self, *args) -> bytes:
            return json.dumps(
                {
                    "status": "ok",
                    "service": "library",
                    "build": {"git_sha": "b" * 40},
                }
            ).encode()

    monkeypatch.setattr(
        render_ops, "open_health_url", lambda url, timeout, user_agent: Response()
    )

    with pytest.raises(render_ops.TransientHealthError, match="observed.*expected"):
        render_ops.verify_health(
            "https://library.example/health",
            expected_commit="a" * 40,
        )


def test_health_readiness_retries_a_valid_stale_commit_then_matches(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
) -> None:
    class Response:
        status = 200

        def __init__(self, url: str, git_sha: str) -> None:
            self.url = url
            self.git_sha = git_sha

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return self.url

        def read(self, *args) -> bytes:
            return health_bytes(self.git_sha)

    calls: list[str] = []

    def stale_then_current(url: str, timeout: float, user_agent: str):
        calls.append(url)
        return Response(url, "b" * 40 if len(calls) == 1 else _SHA_A)

    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(render_ops, "open_health_url", stale_then_current)

    result = render_ops.verify_health_surfaces(
        config,
        expected_commit=_SHA_A,
        readiness_timeout=10,
        retry_interval=1,
        sleep=sleep,
        monotonic=lambda: now[0],
    )

    assert result == {"origin": health_payload(), "public": health_payload()}
    assert calls == [
        f"{config.origin_url}/health",
        f"{config.origin_url}/health",
        f"{config.public_url}/health",
    ]
    assert now[0] == 1


def test_health_null_build_identity_is_never_accepted_by_missing_build_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return "https://library.example/health"

        def read(self, *args) -> bytes:
            return b'{"status":"ok","service":"library","build":{"git_sha":null}}'

    monkeypatch.setattr(
        render_ops, "open_health_url", lambda url, timeout, user_agent: Response()
    )

    with pytest.raises(render_ops.OpsError, match="null build identity"):
        render_ops.verify_health(
            "https://library.example/health",
            expected_commit="a" * 40,
        )
    with pytest.raises(render_ops.OpsError, match="null build identity"):
        render_ops.verify_health(
            "https://library.example/health",
            expected_commit="a" * 40,
            allow_legacy_missing_build=True,
        )


def test_health_missing_build_requires_separate_explicit_legacy_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return "https://library.example/health"

        def read(self, *args) -> bytes:
            return b'{"status":"ok","service":"library"}'

    monkeypatch.setattr(
        render_ops, "open_health_url", lambda url, timeout, user_agent: Response()
    )
    with pytest.raises(render_ops.OpsError, match="missing build identity"):
        render_ops.verify_health(
            "https://library.example/health", expected_commit=_SHA_A
        )
    assert render_ops.verify_health(
        "https://library.example/health",
        expected_commit=_SHA_A,
        allow_legacy_missing_build=True,
    ) == {"status": "ok", "service": "library"}


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "ok", "service": "library", "build": {"git_sha": "a" * 39}},
        {
            "status": "ok",
            "service": "library",
            "build": {"git_sha": _SHA_A, "unapproved": True},
        },
        {
            "status": "ok",
            "service": "library",
            "build": {"git_sha": _SHA_A},
            "unapproved": True,
        },
    ],
)
def test_health_rejects_malformed_or_unapproved_build_payload(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict,
) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return "https://library.example/health"

        def read(self, *args) -> bytes:
            return json.dumps(payload).encode()

    monkeypatch.setattr(
        render_ops, "open_health_url", lambda url, timeout, user_agent: Response()
    )

    with pytest.raises(render_ops.OpsError):
        render_ops.verify_health(
            "https://library.example/health", expected_commit=_SHA_A
        )


def test_health_readiness_retries_transient_http_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Response:
        status = 200

        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return self.url

        def read(self, *args) -> bytes:
            return health_bytes()

    calls: list[str] = []

    def fake_urlopen(url: str, timeout: float, user_agent: str):
        calls.append(url)
        if len(calls) == 1:
            raise HTTPError(url, 503, "warming", {}, None)
        return Response(url)

    now = [0.0]
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(render_ops, "open_health_url", fake_urlopen)
    result = render_ops.verify_health_surfaces(
        config,
        expected_commit=_SHA_A,
        readiness_timeout=20,
        retry_interval=5,
        sleep=fake_sleep,
        monotonic=lambda: now[0],
    )
    assert result["origin"] == health_payload()
    assert result["public"] == health_payload()
    assert calls == [
        f"{config.origin_url}/health",
        f"{config.origin_url}/health",
        f"{config.public_url}/health",
    ]
    assert sleeps == [5]
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events == [
        {
            "health": "not_ready",
            "attempt": 1,
            "elapsed_seconds": 0.0,
            "retry_in_seconds": 5,
            "exhausted": False,
            "error": f"health check failed for {config.origin_url}/health: HTTP 503",
        },
        {"health": "ready", "attempts": 2, "elapsed_seconds": 5.0},
    ]


def test_health_readiness_fails_closed_after_bound(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    now = [0.0]
    sleeps: list[float] = []

    def transient(url: str, **kwargs):
        raise render_ops.TransientHealthError("still warming")

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(render_ops, "verify_health", transient)
    with pytest.raises(render_ops.OpsError, match="after 11 seconds and 3 attempts"):
        render_ops.verify_health_surfaces(
            config,
            expected_commit=_SHA_A,
            readiness_timeout=11,
            retry_interval=5,
            sleep=fake_sleep,
            monotonic=lambda: now[0],
        )
    assert sleeps == [5, 5, 1]


def test_health_readiness_does_not_retry_permanent_http_error(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    calls = 0

    def forbidden(url: str, timeout: float, user_agent: str):
        nonlocal calls
        calls += 1
        raise HTTPError(url, 403, "forbidden", {}, None)

    sleeps: list[float] = []
    monkeypatch.setattr(render_ops, "open_health_url", forbidden)
    with pytest.raises(render_ops.OpsError, match="HTTP 403"):
        render_ops.verify_health_surfaces(
            config, expected_commit=_SHA_A, sleep=sleeps.append
        )
    assert calls == 1
    assert sleeps == []


def test_health_readiness_does_not_retry_wrong_payload(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return f"{config.origin_url}/health"

        def read(self, *args) -> bytes:
            return b'{"status":"ok","service":"other"}'

    calls = 0

    def wrong(url: str, timeout: float, user_agent: str):
        nonlocal calls
        calls += 1
        return Response()

    sleeps: list[float] = []
    monkeypatch.setattr(render_ops, "open_health_url", wrong)
    with pytest.raises(render_ops.OpsError, match="unexpected Library health payload"):
        render_ops.verify_health_surfaces(
            config, expected_commit=_SHA_A, sleep=sleeps.append
        )
    assert calls == 1
    assert sleeps == []


def test_health_redirect_location_is_never_requested() -> None:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            if self.path == "/health":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(health_bytes())

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/health"
        with pytest.raises(render_ops.OpsError, match="HTTP 302"):
            render_ops.verify_health(url, expected_commit=_SHA_A)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert requests == ["/health"]


def test_health_sends_explicit_gate_user_agent() -> None:
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.headers.get("User-Agent", ""))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(health_bytes())

        def log_message(self, format: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        render_ops.verify_health(
            f"http://127.0.0.1:{server.server_port}/health", expected_commit=_SHA_A
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert seen == ["aweb-library-deploy-gate/1.0"]


def test_health_403_persists_bounded_allowlisted_evidence_before_raise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    body = b"error code: 1010"
    headers = Message()
    headers.add_header("Content-Type", "text/plain")
    headers.add_header("Server", "cloudflare")
    headers.add_header("CF-Ray", "ray-id")
    headers.add_header("Set-Cookie", "must-not-persist")

    def blocked(url: str, timeout: float, user_agent: str):
        raise HTTPError(url, 403, "Forbidden", headers, BytesIO(body))

    monkeypatch.setattr(render_ops, "open_health_url", blocked)
    evidence_path = tmp_path / "evidence"
    evidence = render_ops.HealthEvidenceRun(evidence_path, label="test")
    with pytest.raises(render_ops.OpsError, match="HTTP 403"):
        render_ops.verify_health(
            "https://library.example/health",
            expected_commit=_SHA_A,
            user_agent="Python-urllib/3.12",
            evidence=evidence,
        )
    artifact = json.loads((evidence_path / "002.json").read_text())
    assert artifact["status"] == 403
    assert artifact["body_preview"] == "error code: 1010"
    assert artifact["body_complete"] is True
    assert artifact["response_headers"] == {
        "cf-ray": ["ray-id"],
        "content-type": ["text/plain"],
        "server": ["cloudflare"],
    }
    assert artifact["omitted_response_header_names"] == ["set-cookie"]
    assert "must-not-persist" not in (evidence_path / "002.json").read_text()
    assert evidence_path.stat().st_mode & 0o777 == 0o700
    assert (evidence_path / "002.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(render_ops.OpsError, match="must not already exist"):
        render_ops.HealthEvidenceRun(evidence_path, label="duplicate")
    evidence.close()


def test_evidence_refuses_inside_repo_from_subdirectory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(render_ops.REPOSITORY_ROOT / "scripts")
    path = render_ops.REPOSITORY_ROOT / ".pytest-inside-evidence"
    with pytest.raises(render_ops.OpsError, match="outside the repository"):
        render_ops.HealthEvidenceRun(path, label="test")
    assert not path.exists()


def test_evidence_no_replace_preserves_existing_destination(tmp_path: Path) -> None:
    evidence = render_ops.HealthEvidenceRun(tmp_path / "evidence", label="test")
    destination = evidence.path / "002.json"
    destination.write_text("preserve", encoding="utf-8")
    with pytest.raises(render_ops.OpsError, match="must not already exist"):
        evidence.record({"probe_kind": "test"})
    assert destination.read_text(encoding="utf-8") == "preserve"
    evidence.close()


def test_evidence_enforces_exact_modes_under_restrictive_umask(tmp_path: Path) -> None:
    previous = os.umask(0o777)
    try:
        evidence = render_ops.HealthEvidenceRun(tmp_path / "evidence", label="test")
    finally:
        os.umask(previous)
    assert evidence.path.stat().st_mode & 0o777 == 0o700
    assert (evidence.path / "001.json").stat().st_mode & 0o777 == 0o600
    evidence.close()


def test_evidence_refuses_symlink_component(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    symlink_parent = tmp_path / "linked"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(render_ops.OpsError, match="without symlink components"):
        render_ops.HealthEvidenceRun(symlink_parent / "evidence", label="test")


def test_evidence_rejects_non_private_parent_mode(tmp_path: Path) -> None:
    parent = tmp_path / "shared-parent"
    parent.mkdir(mode=0o750)
    parent.chmod(0o750)
    evidence_path = parent / "evidence"
    with pytest.raises(render_ops.OpsError, match="operator-owned with exact mode 0700"):
        render_ops.HealthEvidenceRun(evidence_path, label="test")
    assert not evidence_path.exists()


def test_evidence_rejects_parent_not_owned_by_operator(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parent = tmp_path / "other-owner-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    actual_euid = os.geteuid()
    monkeypatch.setattr(render_ops.os, "geteuid", lambda: actual_euid + 1)
    evidence_path = parent / "evidence"
    with pytest.raises(render_ops.OpsError, match="operator-owned with exact mode 0700"):
        render_ops.HealthEvidenceRun(evidence_path, label="test")
    assert not evidence_path.exists()


def test_evidence_detects_swap_during_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parent = tmp_path / "private-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    evidence_path = parent / "evidence"
    moved = parent / "created-original"
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "evidence" and flags & os.O_DIRECTORY and dir_fd is not None and not swapped:
            swapped = True
            evidence_path.rename(moved)
            evidence_path.mkdir(mode=0o700)
            evidence_path.chmod(0o700)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(render_ops.os, "open", swapping_open)
    with pytest.raises(render_ops.OpsError, match="changed during creation"):
        render_ops.HealthEvidenceRun(evidence_path, label="test")
    assert not (evidence_path / "001.json").exists()
    assert not (moved / "001.json").exists()


def test_evidence_detects_swap_during_terminal_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = render_ops.HealthEvidenceRun(tmp_path / "evidence", label="test")
    moved = tmp_path / "moved"
    real_link = os.link
    swapped = False

    def swapping_link(src, dst, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            evidence.path.rename(moved)
            evidence.path.mkdir(mode=0o700)
            evidence.path.chmod(0o700)
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(render_ops.os, "link", swapping_link)
    with pytest.raises(render_ops.OpsError, match="path changed"):
        evidence.finish({"probe_kind": "run-outcome", "outcome": "passed"})
    assert not (evidence.path / "002.json").exists()
    assert (moved / "002.json").exists()


def test_evidence_detects_parent_swap(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    evidence = render_ops.HealthEvidenceRun(parent / "evidence", label="test")
    moved = tmp_path / "moved-parent"
    parent.rename(moved)
    parent.mkdir()
    with pytest.raises(render_ops.OpsError, match="parent path changed"):
        evidence.record({"probe_kind": "test"})
    assert not (parent / "evidence" / "002.json").exists()
    assert not (moved / "evidence" / "002.json").exists()
    evidence.close()


def test_evidence_detects_directory_swap(tmp_path: Path) -> None:
    evidence = render_ops.HealthEvidenceRun(tmp_path / "evidence", label="test")
    moved = tmp_path / "moved"
    evidence.path.rename(moved)
    evidence.path.mkdir()
    with pytest.raises(render_ops.OpsError, match="path changed"):
        evidence.record({"probe_kind": "test"})
    assert not (evidence.path / "002.json").exists()
    assert not (moved / "002.json").exists()
    evidence.close()


def test_header_evidence_has_one_total_bound_and_control_safe_preview() -> None:
    class Headers:
        def items(self):
            values = [(f"X-Omitted-{index}-" + "n" * 300, "secret") for index in range(100)]
            values.extend(("Server", "") for _ in range(100))
            values.append(("Location", "https://user:secret@example.test:bad/a?token=x"))
            return values

    event = render_ops._health_event(
        url="https://library.example/health",
        user_agent="test",
        started_wall="2026-01-01T00:00:00+00:00",
        started_mono=0.0,
        status=403,
        headers=Headers(),
        body=b"safe\x00\x1bunsafe",
        body_complete=True,
        phase="test",
    )
    header_size = render_ops._header_evidence_size(
        event["response_headers"],
        event["omitted_response_header_names"],
        event["omitted_response_header_count"],
    )
    assert header_size <= render_ops.HEALTH_HEADER_CAPTURE_LIMIT
    assert event["response_headers_complete"] is False
    assert "\x00" not in event["body_preview"]
    assert "\x1b" not in event["body_preview"]
    assert "secret" not in json.dumps(event["response_headers"])


def test_header_evidence_exact_boundary() -> None:
    base_size = render_ops._header_evidence_size({"server": [""]}, [], 0)
    exact_value = "x" * (render_ops.HEALTH_HEADER_CAPTURE_LIMIT - base_size)
    exact_headers = Message()
    exact_headers.add_header("Server", exact_value)
    captured, omitted, omitted_count, complete = render_ops._health_headers(exact_headers)
    assert render_ops._header_evidence_size(captured, omitted, omitted_count) == (
        render_ops.HEALTH_HEADER_CAPTURE_LIMIT
    )
    assert complete is True

    oversized_headers = Message()
    oversized_headers.add_header("Server", exact_value + "x")
    captured, omitted, omitted_count, complete = render_ops._health_headers(oversized_headers)
    assert render_ops._header_evidence_size(captured, omitted, omitted_count) <= (
        render_ops.HEALTH_HEADER_CAPTURE_LIMIT
    )
    assert complete is False


def test_verifier_identity_is_repo_anchored_and_rejects_dirty_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    script = repo / "scripts" / "render_ops.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('clean')\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
        check=True,
    )
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    identity = render_ops._verifier_identity(repo_root=repo, script_path=script)
    assert len(identity["verifier_source_sha"]) == 40
    assert identity["verifier_script_sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()

    script.write_text("print('dirty')\n", encoding="utf-8")
    with pytest.raises(render_ops.OpsError, match="tracked changes"):
        render_ops._verifier_identity(repo_root=repo, script_path=script)


def test_config_digest_uses_same_snapshot_as_parsed_config(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig, tmp_path: Path
) -> None:
    path = tmp_path / "production.json"
    write_config(path, config)
    expected_snapshot = path.read_bytes()
    loaded = render_ops.ProductionConfig.load(path)
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )
    evidence = render_ops._command_health_evidence(
        SimpleNamespace(evidence_dir=str(tmp_path / "evidence")),
        label="test",
        config=loaded,
    )
    manifest = json.loads((evidence.path / "001.json").read_text())
    assert manifest["run_metadata"]["config_sha256"] == hashlib.sha256(
        expected_snapshot
    ).hexdigest()
    evidence.close()


def test_health_proof_records_terminal_outcome_for_each_failure_stage(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig, tmp_path: Path
) -> None:
    config_path = tmp_path / "production.json"
    write_config(config_path, config)
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )

    monkeypatch.setattr(
        render_ops,
        "verify_health",
        lambda *args, **kwargs: (_ for _ in ()).throw(render_ops.TransientHealthError("dns")),
    )
    baseline_dir = tmp_path / "baseline-failure"
    with pytest.raises(render_ops.TransientHealthError):
        render_ops.command_health_client_proof(
            health_proof_args(config_path, baseline_dir)
        )
    baseline_artifacts = [
        json.loads(path.read_text()) for path in sorted(baseline_dir.glob("*.json"))
    ]
    baseline_outcomes = [
        item for item in baseline_artifacts if item["probe_kind"] == "run-outcome"
    ]
    assert len(baseline_outcomes) == 1
    assert baseline_outcomes[0] is baseline_artifacts[-1]
    assert baseline_outcomes[0]["outcome"] == "failed"
    assert baseline_outcomes[0]["stage"] == "blocked-baseline"

    calls = 0

    def gate_failure(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise render_ops.PermanentHealthHTTPError("expected", status=403)
        raise render_ops.TransientHealthError("tls")

    monkeypatch.setattr(render_ops, "verify_health", gate_failure)
    gate_dir = tmp_path / "gate-failure"
    with pytest.raises(render_ops.TransientHealthError):
        render_ops.command_health_client_proof(
            health_proof_args(config_path, gate_dir)
        )
    gate_outcome = json.loads((gate_dir / "002.json").read_text())
    assert gate_outcome["outcome"] == "failed"
    assert gate_outcome["stage"] == "honest-gate"


@pytest.mark.parametrize(
    ("stage", "failure"),
    [
        ("blocked-baseline", render_ops.OpsError("wrong baseline payload")),
        ("blocked-baseline", render_ops.PermanentHealthHTTPError("wrong status", status=401)),
        ("honest-gate", render_ops.TransientHealthError("transport")),
        ("honest-gate", render_ops.PermanentHealthHTTPError("HTTP", status=401)),
        ("honest-gate", render_ops.OpsError("wrong payload")),
    ],
)
def test_health_proof_has_one_last_terminal_outcome_for_contract_and_http_failures(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
    tmp_path: Path,
    stage: str,
    failure: Exception,
) -> None:
    config_path = tmp_path / "production.json"
    write_config(config_path, config)
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )
    calls = 0

    def fail_at_stage(*args, **kwargs):
        nonlocal calls
        calls += 1
        if stage == "honest-gate" and calls == 1:
            raise render_ops.PermanentHealthHTTPError("expected", status=403)
        raise failure

    monkeypatch.setattr(render_ops, "verify_health", fail_at_stage)
    evidence_path = tmp_path / "evidence"
    with pytest.raises(type(failure)):
        render_ops.command_health_client_proof(
            health_proof_args(config_path, evidence_path)
        )
    artifacts = [json.loads(path.read_text()) for path in sorted(evidence_path.glob("*.json"))]
    outcomes = [item for item in artifacts if item["probe_kind"] == "run-outcome"]
    assert len(outcomes) == 1
    assert outcomes[0] is artifacts[-1]
    assert outcomes[0]["outcome"] == "failed"
    assert outcomes[0]["stage"] == stage


@pytest.mark.parametrize(
    ("body_kind", "expected_complete", "expected_outcome"),
    [("exact", True, "red-green-pass"), ("oversized", False, "failed"), ("interrupted", False, "failed")],
)
def test_health_proof_body_bounds_and_terminal_outcome(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
    tmp_path: Path,
    body_kind: str,
    expected_complete: bool,
    expected_outcome: str,
) -> None:
    config_path = tmp_path / "production.json"
    write_config(config_path, config)
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )
    exact = b'{"status":"ok","service":"library"}'
    exact += b" " * (render_ops.HEALTH_BODY_CAPTURE_LIMIT - len(exact))
    captured = exact if body_kind != "interrupted" else b'{"status":"ok"}'

    class Response:
        status = 200
        headers = Message()

        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return self.url

        def read(self, limit: int) -> bytes:
            if body_kind == "interrupted":
                raise IncompleteRead(captured, 20)
            if body_kind == "oversized":
                return exact + b"x"
            return exact

    blocked_headers = Message()
    blocked_headers.add_header("Content-Type", "text/plain")
    blocked_headers.add_header("Server", "cloudflare")

    def open_for_proof(url: str, timeout: float, user_agent: str):
        if user_agent == render_ops.BLOCKED_BASELINE_USER_AGENT:
            raise HTTPError(url, 403, "Forbidden", blocked_headers, BytesIO(b"error code: 1010"))
        return Response(url)

    monkeypatch.setattr(render_ops, "open_health_url", open_for_proof)
    evidence_path = tmp_path / "evidence"
    args = health_proof_args(config_path, evidence_path)
    if expected_outcome == "red-green-pass":
        render_ops.command_health_client_proof(args)
    else:
        with pytest.raises(render_ops.OpsError, match="exceeded evidence bound"):
            render_ops.command_health_client_proof(args)
    artifacts = [json.loads(path.read_text()) for path in sorted(evidence_path.glob("*.json"))]
    response = [item for item in artifacts if item.get("phase") == "response"][-1]
    assert response["captured_body_bytes"] == len(captured)
    assert response["captured_body_sha256"] == hashlib.sha256(captured).hexdigest()
    assert response["body_complete"] is expected_complete
    outcomes = [item for item in artifacts if item["probe_kind"] == "run-outcome"]
    assert len(outcomes) == 1
    assert outcomes[0] is artifacts[-1]
    assert outcomes[0]["outcome"] == expected_outcome


def test_health_proof_cross_minute_has_one_failed_terminal_outcome(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig, tmp_path: Path
) -> None:
    config_path = tmp_path / "production.json"
    write_config(config_path, config)
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )

    class CrossMinuteDateTime:
        calls = 0

        @classmethod
        def now(cls, tz):
            cls.calls += 1
            minute = 0 if cls.calls == 1 else 1
            return dt.datetime(2026, 1, 1, 0, minute, tzinfo=dt.UTC)

    calls = 0

    def red_then_green(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise render_ops.PermanentHealthHTTPError("expected", status=403)
        return {"status": "ok", "service": "library"}

    monkeypatch.setattr(render_ops, "datetime", CrossMinuteDateTime)
    monkeypatch.setattr(render_ops, "verify_health", red_then_green)
    evidence_path = tmp_path / "evidence"
    with pytest.raises(render_ops.OpsError, match="crossed a UTC minute"):
        render_ops.command_health_client_proof(
            health_proof_args(config_path, evidence_path)
        )
    artifacts = [json.loads(path.read_text()) for path in sorted(evidence_path.glob("*.json"))]
    outcomes = [item for item in artifacts if item["probe_kind"] == "run-outcome"]
    assert len(outcomes) == 1
    assert outcomes[0] is artifacts[-1]
    assert outcomes[0]["outcome"] == "failed"
    assert outcomes[0]["stage"] == "freshness"


def test_health_client_proof_rejects_mismatched_legacy_pin_before_request(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig, tmp_path: Path
) -> None:
    config_path = tmp_path / "production.json"
    write_config(config_path, config)
    args = health_proof_args(config_path, tmp_path / "evidence")
    args.allow_legacy_missing_build_for = "b" * 40
    called = False

    def must_not_request(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("request ran with a mismatched legacy pin")

    monkeypatch.setattr(render_ops, "verify_health", must_not_request)
    with pytest.raises(render_ops.OpsError, match="does not match the approved target"):
        render_ops.command_health_client_proof(args)
    assert called is False
    assert not (tmp_path / "evidence").exists()


def test_health_client_proof_requires_same_path_red_then_green(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig, tmp_path: Path
) -> None:
    config_path = tmp_path / "production.json"
    write_config(config_path, config)
    evidence_path = tmp_path / "proof"
    calls: list[tuple[str, str, str, bool]] = []

    def proof_health(
        url: str,
        *,
        expected_commit: str,
        allow_legacy_missing_build: bool,
        user_agent: str,
        evidence,
    ):
        calls.append((url, user_agent, expected_commit, allow_legacy_missing_build))
        evidence.record(
            {
                "probe_kind": "test-health",
                "user_agent": user_agent,
                "status": 403 if user_agent == render_ops.BLOCKED_BASELINE_USER_AGENT else 200,
            }
        )
        if user_agent == render_ops.BLOCKED_BASELINE_USER_AGENT:
            raise render_ops.PermanentHealthHTTPError(
                f"health check failed for {url}: HTTP 403", status=403
            )
        return {"status": "ok", "service": "library"}

    monkeypatch.setattr(render_ops, "verify_health", proof_health)
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )
    args = health_proof_args(config_path, evidence_path)
    result = render_ops.command_health_client_proof(args)
    expected_url = f"{config.public_url}/health"
    assert calls == [
        (expected_url, "Python-urllib/3.12", _SHA_A, True),
        (expected_url, "aweb-library-deploy-gate/1.0", _SHA_A, True),
    ]
    assert result["baseline_user_agent_status"] == 403
    assert result["gate_user_agent_status"] == 200
    artifacts = [json.loads(path.read_text()) for path in sorted(evidence_path.glob("*.json"))]
    outcomes = [item for item in artifacts if item["probe_kind"] == "run-outcome"]
    assert len(outcomes) == 1
    assert outcomes[0] is artifacts[-1]
    assert outcomes[0]["outcome"] == "red-green-pass"


def test_health_invalid_utf8_is_bounded_transient(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    class Response:
        status = 200

        def __init__(self, url: str, body: bytes) -> None:
            self.url = url
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return self.url

        def read(self, *args) -> bytes:
            return self.body

    calls = 0

    def fake_open(url: str, timeout: float, user_agent: str):
        nonlocal calls
        calls += 1
        body = b"\xff" if calls == 1 else health_bytes()
        return Response(url, body)

    now = [0.0]

    def fake_sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(render_ops, "open_health_url", fake_open)
    result = render_ops.verify_health_surfaces(
        config,
        expected_commit=_SHA_A,
        readiness_timeout=10,
        retry_interval=1,
        sleep=fake_sleep,
        monotonic=lambda: now[0],
    )
    assert result["public"] == health_payload()
    assert calls == 3
    assert now[0] == 1


def test_health_interrupted_body_read_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self) -> str:
            return "https://library.example/health"

        def read(self, *args) -> bytes:
            raise IncompleteRead(b"partial", 20)

    monkeypatch.setattr(
        render_ops, "open_health_url", lambda url, timeout, user_agent: Response()
    )
    with pytest.raises(render_ops.OpsError, match="exceeded evidence bound"):
        render_ops.verify_health(
            "https://library.example/health", expected_commit=_SHA_A
        )


def test_health_late_public_success_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = [0.0]
    calls: list[tuple[str, float]] = []

    def late_public(url: str, **kwargs):
        timeout = kwargs["timeout"]
        calls.append((url, timeout))
        if url.startswith(config.origin_url):
            now[0] = 89.0
        else:
            assert timeout == 1.0
            now[0] = 91.0
        return health_payload()

    monkeypatch.setattr(render_ops, "verify_health", late_public)
    with pytest.raises(render_ops.OpsError, match="after 90 seconds and 1 attempts"):
        render_ops.verify_health_surfaces(
            config,
            expected_commit=_SHA_A,
            monotonic=lambda: now[0],
            sleep=lambda _: None,
        )
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events == [
        {
            "health": "not_ready",
            "attempt": 1,
            "elapsed_seconds": 91.0,
            "retry_in_seconds": 0.0,
            "exhausted": True,
            "error": "health readiness deadline elapsed after public check",
        }
    ]
    assert len(calls) == 2


def test_health_deadline_crossing_before_origin_never_starts_request(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    times = iter([0.0, 91.0])
    calls = 0

    def must_not_run(url: str, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("health request started after deadline")

    monkeypatch.setattr(render_ops, "verify_health", must_not_run)
    with pytest.raises(render_ops.OpsError, match="after 90 seconds and 0 attempts"):
        render_ops.verify_health_surfaces(
            config, expected_commit=_SHA_A, monotonic=lambda: next(times)
        )
    assert calls == 0


def test_health_final_transient_attempt_is_logged_as_exhausted(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = [0.0]

    def consumes_deadline(url: str, **kwargs):
        now[0] = 90.0
        raise render_ops.TransientHealthError("request timed out")

    monkeypatch.setattr(render_ops, "verify_health", consumes_deadline)
    with pytest.raises(render_ops.OpsError, match="after 90 seconds and 1 attempts"):
        render_ops.verify_health_surfaces(
            config, expected_commit=_SHA_A, monotonic=lambda: now[0]
        )
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events == [
        {
            "health": "not_ready",
            "attempt": 1,
            "elapsed_seconds": 90.0,
            "retry_in_seconds": 0.0,
            "exhausted": True,
            "error": "request timed out",
        }
    ]


def test_validate_service_fails_on_topology_drift(config: render_ops.ProductionConfig) -> None:
    observed = service(config)
    observed["serviceDetails"]["region"] = "oregon"
    with pytest.raises(render_ops.OpsError, match="region"):
        render_ops.validate_service(observed, config)


def test_current_live_rejects_active_or_unknown_deploy() -> None:
    for status in ("created", "build_in_progress"):
        with pytest.raises(render_ops.OpsError, match="another deploy"):
            render_ops.current_live(
                [deploy("dep-new", "a" * 40, status), deploy("dep-live", "b" * 40)]
            )
    with pytest.raises(render_ops.OpsError, match="unknown Render deploy state"):
        render_ops.current_live(
            [deploy("dep-new", "a" * 40, "future_state"), deploy("dep-live", "b" * 40)]
        )


class FakeClient:
    def __init__(
        self,
        config: render_ops.ProductionConfig,
        rollback: dict,
        *,
        current: dict | None = None,
    ) -> None:
        self.config = config
        self.rollback_artifact = rollback
        self.current = current or rollback
        self.final_live: dict | None = None
        self.posts: list[tuple[str, str]] = []

    def service(self, service_id: str) -> dict:
        assert service_id == self.config.service_id
        return service(self.config)

    def deploys(self, service_id: str, limit: int = 20) -> list[dict]:
        if self.final_live is not None:
            return [self.final_live, {**self.current, "status": "deactivated"}]
        artifacts = [self.current]
        if self.rollback_artifact["id"] != self.current["id"]:
            artifacts.append(self.rollback_artifact)
        return artifacts

    def deploy(self, service_id: str, commit: str) -> dict:
        self.posts.append(("deploy", commit))
        self.final_live = deploy("dep-created", commit)
        return deploy("dep-created", commit, "build_in_progress")

    def rollback(self, service_id: str, deploy_id: str) -> dict:
        self.posts.append(("rollback", deploy_id))
        self.final_live = deploy("dep-rolled", render_ops.deploy_commit(self.rollback_artifact))
        return deploy(
            "dep-rolled", render_ops.deploy_commit(self.rollback_artifact), "update_in_progress"
        )

    def deploy_by_id(self, service_id: str, deploy_id: str) -> dict:
        if deploy_id == self.rollback_artifact["id"]:
            return self.rollback_artifact
        if deploy_id == self.current["id"]:
            return self.current
        raise AssertionError(deploy_id)


class RecordingEvidence:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> None:
        self.events.append(event)

    def finish(self, event: dict) -> None:
        self.record(event)


def stub_command_evidence(monkeypatch: pytest.MonkeyPatch) -> RecordingEvidence:
    evidence = RecordingEvidence()
    monkeypatch.setattr(render_ops, "_command_health_evidence", lambda *args, **kwargs: evidence)
    return evidence


def common_args(config: render_ops.ProductionConfig) -> SimpleNamespace:
    return SimpleNamespace(
        apply=True,
        confirm_service_id=config.service_id,
        commit="b" * 40,
        rollback_commit="a" * 40,
        rollback_deploy_id="dep-rollback",
        current_commit="b" * 40,
        current_deploy_id="dep-candidate",
        allow_legacy_missing_build_for="",
        repo_root=".",
        timeout=30,
    )


@pytest.mark.parametrize("command_name", ["deploy", "rollback"])
@pytest.mark.parametrize("invalid_kind", ["relative", "existing", "inside-repo", "symlink"])
def test_invalid_evidence_path_prevents_every_mutation_call(
    monkeypatch: pytest.MonkeyPatch,
    config: render_ops.ProductionConfig,
    tmp_path: Path,
    command_name: str,
    invalid_kind: str,
) -> None:
    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    client = FakeClient(config, artifact, current=deploy("dep-candidate", "b" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )
    if invalid_kind == "relative":
        evidence_path = Path("relative-evidence")
    elif invalid_kind == "existing":
        evidence_path = tmp_path / "existing"
        evidence_path.mkdir()
    elif invalid_kind == "inside-repo":
        evidence_path = render_ops.REPOSITORY_ROOT / f".pytest-evidence-{tmp_path.name}"
    else:
        real_parent = tmp_path / "real"
        real_parent.mkdir()
        linked_parent = tmp_path / "linked"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        evidence_path = linked_parent / "evidence"
    args = common_args(config)
    args.evidence_dir = str(evidence_path)
    command = render_ops.command_deploy if command_name == "deploy" else render_ops.command_rollback
    with pytest.raises(render_ops.OpsError):
        command(args)
    assert client.posts == []
    assert not (
        invalid_kind == "inside-repo" and evidence_path.exists()
    ), "inside-repository evidence path was created"


def test_deploy_persists_initial_manifest_before_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig, tmp_path: Path
) -> None:
    evidence_path = tmp_path / "evidence"

    class ManifestClient(FakeClient):
        def deploy(self, service_id: str, commit: str) -> dict:
            assert (evidence_path / "001.json").exists()
            return super().deploy(service_id, commit)

    client = ManifestClient(config, deploy("dep-rollback", "a" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    monkeypatch.setattr(
        render_ops,
        "_verifier_identity",
        lambda: {
            "verifier_source_sha": "a" * 40,
            "verifier_script_sha256": "b" * 64,
            "verifier_script_path": "scripts/render_ops.py",
        },
    )
    monkeypatch.setattr(render_ops, "verify_git_target", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        render_ops,
        "wait_for_deploy",
        lambda c, cfg, deploy_id, commit, timeout_seconds: deploy(deploy_id, commit),
    )
    monkeypatch.setattr(
        render_ops, "verify_health_surfaces", lambda cfg, **kwargs: {"ok": True}
    )
    args = common_args(config)
    args.evidence_dir = str(evidence_path)
    render_ops.command_deploy(args)
    assert client.posts == [("deploy", "b" * 40)]


def test_deploy_requires_apply(config: render_ops.ProductionConfig) -> None:
    args = common_args(config)
    args.apply = False
    with pytest.raises(render_ops.OpsError, match="--apply"):
        render_ops._confirm_apply(args, config)


def test_command_deploy_pins_rollback_and_clears_through_client(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    evidence = stub_command_evidence(monkeypatch)
    artifact = deploy("dep-rollback", "a" * 40)
    client = FakeClient(config, artifact)
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    monkeypatch.setattr(render_ops, "verify_git_target", lambda root, commit, **kwargs: None)
    monkeypatch.setattr(
        render_ops,
        "wait_for_deploy",
        lambda c, cfg, deploy_id, commit, timeout_seconds: deploy(deploy_id, commit),
    )
    health_checks = []
    monkeypatch.setattr(
        render_ops,
        "verify_health_surfaces",
        lambda cfg, **kwargs: health_checks.append(kwargs) or {"ok": True},
    )
    result = render_ops.command_deploy(common_args(config))
    assert client.posts == [("deploy", "b" * 40)]
    assert result["rollback"]["id"] == "dep-rollback"
    assert result["deploy"]["id"] == "dep-created"
    assert health_checks == [{"expected_commit": "b" * 40, "evidence": evidence}]


def test_command_rollback_uses_exact_artifact(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    evidence = stub_command_evidence(monkeypatch)
    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    current = deploy("dep-candidate", "b" * 40)
    client = FakeClient(config, artifact, current=current)
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    monkeypatch.setattr(
        render_ops,
        "wait_for_deploy",
        lambda c, cfg, deploy_id, commit, timeout_seconds: deploy(deploy_id, commit),
    )
    health_checks = []
    monkeypatch.setattr(
        render_ops,
        "verify_health_surfaces",
        lambda cfg, **kwargs: health_checks.append(kwargs) or {"ok": True},
    )
    args = common_args(config)
    args.allow_legacy_missing_build_for = "a" * 40
    result = render_ops.command_rollback(args)
    assert client.posts == [("rollback", "dep-rollback")]
    assert result["rollback_deploy"]["commit"] == "a" * 40
    assert health_checks == [
        {
            "expected_commit": "a" * 40,
            "allow_legacy_missing_build": True,
            "evidence": evidence,
        }
    ]


def test_command_rollback_rejects_legacy_missing_flag_for_a_different_commit_before_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    current = deploy("dep-candidate", "b" * 40)
    client = FakeClient(config, artifact, current=current)
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    args = common_args(config)
    args.allow_legacy_missing_build_for = "c" * 40

    with pytest.raises(render_ops.OpsError, match="does not match the approved target"):
        render_ops.command_rollback(args)

    assert client.posts == []


def test_command_rollback_requires_exact_artifact(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    stub_command_evidence(monkeypatch)
    artifact = deploy("dep-rollback", "c" * 40, "deactivated")
    client = FakeClient(config, artifact, current=deploy("dep-candidate", "b" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    with pytest.raises(render_ops.OpsError, match="approved artifact"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == []


def test_command_rollback_rejects_failed_artifact_before_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    stub_command_evidence(monkeypatch)
    artifact = deploy("dep-rollback", "a" * 40, "build_failed")
    client = FakeClient(config, artifact, current=deploy("dep-candidate", "b" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    with pytest.raises(render_ops.OpsError, match="not known-good"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == []


def test_command_rollback_detects_competing_deploy_after_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    stub_command_evidence(monkeypatch)

    class ConcurrentClient(FakeClient):
        def deploys(self, service_id: str, limit: int = 20) -> list[dict]:
            artifacts = super().deploys(service_id, limit)
            if self.final_live is not None:
                artifacts.append(deploy("dep-competing", "c" * 40, "created"))
            return artifacts

    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    client = ConcurrentClient(config, artifact, current=deploy("dep-candidate", "b" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    monkeypatch.setattr(
        render_ops,
        "wait_for_deploy",
        lambda c, cfg, deploy_id, commit, timeout_seconds: deploy(deploy_id, commit),
    )
    with pytest.raises(render_ops.OpsError, match="another deploy"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == [("rollback", "dep-rollback")]


def test_command_rollback_rejects_unpinned_current_live(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    stub_command_evidence(monkeypatch)
    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    client = FakeClient(config, artifact, current=deploy("dep-other", "c" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    with pytest.raises(render_ops.OpsError, match="approved artifact"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == []


def test_command_verify_requires_exact_current_live(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    evidence = stub_command_evidence(monkeypatch)
    artifact = deploy("dep-candidate", "b" * 40)
    client = FakeClient(config, artifact)
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    health_checks = []
    monkeypatch.setattr(
        render_ops,
        "verify_health_surfaces",
        lambda cfg, **kwargs: health_checks.append(kwargs) or {"ok": True},
    )
    args = SimpleNamespace(deploy_id="dep-candidate", commit="b" * 40)
    result = render_ops.command_verify(args)
    assert result["deploy"]["status"] == "live"
    assert health_checks == [{"expected_commit": "b" * 40, "evidence": evidence}]


def test_command_wait_is_restartable(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    artifact = deploy("dep-candidate", "b" * 40)
    client = FakeClient(config, artifact)
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    monkeypatch.setattr(
        render_ops,
        "wait_for_deploy",
        lambda c, cfg, deploy_id, commit, timeout_seconds: artifact,
    )
    args = SimpleNamespace(deploy_id="dep-candidate", commit="b" * 40, timeout=30)
    assert render_ops.command_wait(args)["deploy"]["id"] == "dep-candidate"


def test_make_mutation_recipe_does_not_shell_interpolate_values() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            "make",
            "-n",
            "prod-deploy",
            "PROD_COMMIT='; echo INJECTED; #'",
            "ROLLBACK_DEPLOY_ID=dep-x",
            f"ROLLBACK_COMMIT={'a' * 40}",
            "CONFIRM_SERVICE_ID=srv-x",
            "APPLY=1",
        ],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    )
    assert "INJECTED" not in completed.stdout
    recipe_lines = [
        line for line in completed.stdout.splitlines() if not line.startswith("make[")
    ]
    assert recipe_lines == [
        "git fetch --quiet origin",
        "uv run python scripts/render_ops.py deploy",
    ]


def test_wait_rejects_failure_state(config: render_ops.ProductionConfig) -> None:
    class FailedClient:
        def deploy_by_id(self, service_id: str, deploy_id: str) -> dict:
            return deploy(deploy_id, "b" * 40, "build_failed")

    with pytest.raises(render_ops.OpsError, match="build_failed"):
        render_ops.wait_for_deploy(
            FailedClient(), config, "dep-created", "b" * 40, timeout_seconds=1, interval_seconds=0
        )


def test_wait_rejects_commit_change(config: render_ops.ProductionConfig) -> None:
    class ChangedClient:
        def deploy_by_id(self, service_id: str, deploy_id: str) -> dict:
            return deploy(deploy_id, "c" * 40, "live")

    with pytest.raises(render_ops.OpsError, match="commit changed"):
        render_ops.wait_for_deploy(
            ChangedClient(), config, "dep-created", "b" * 40, timeout_seconds=1, interval_seconds=0
        )
