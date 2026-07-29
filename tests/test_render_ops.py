from __future__ import annotations

import json
import subprocess
import threading
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

        def read(self) -> bytes:
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

        def read(self) -> bytes:
            return health_bytes()

    monkeypatch.setattr(render_ops, "open_health_url", lambda url, timeout: Response())
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

        def read(self) -> bytes:
            return json.dumps(
                {
                    "status": "ok",
                    "service": "library",
                    "build": {"git_sha": "b" * 40},
                }
            ).encode()

    monkeypatch.setattr(render_ops, "open_health_url", lambda url, timeout: Response())

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

        def read(self) -> bytes:
            return health_bytes(self.git_sha)

    calls: list[str] = []

    def stale_then_current(url: str, timeout: float):
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


def test_health_null_build_identity_requires_explicit_exact_legacy_action(
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

        def read(self) -> bytes:
            return b'{"status":"ok","service":"library","build":{"git_sha":null}}'

    monkeypatch.setattr(render_ops, "open_health_url", lambda url, timeout: Response())

    with pytest.raises(render_ops.OpsError, match="null build identity"):
        render_ops.verify_health(
            "https://library.example/health",
            expected_commit="a" * 40,
        )
    assert render_ops.verify_health(
        "https://library.example/health",
        expected_commit="a" * 40,
        allow_legacy_null_build=True,
    )["build"] == {"git_sha": None}


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

        def read(self) -> bytes:
            return json.dumps(payload).encode()

    monkeypatch.setattr(render_ops, "open_health_url", lambda url, timeout: Response())

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

        def read(self) -> bytes:
            return health_bytes()

    calls: list[str] = []

    def fake_urlopen(url: str, timeout: float):
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

    def forbidden(url: str, timeout: float):
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

        def read(self) -> bytes:
            return b'{"status":"ok","service":"other"}'

    calls = 0

    def wrong(url: str, timeout: float):
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

        def read(self) -> bytes:
            return self.body

    calls = 0

    def fake_open(url: str, timeout: float):
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

        def read(self) -> bytes:
            raise IncompleteRead(b"partial", 20)

    monkeypatch.setattr(render_ops, "open_health_url", lambda url, timeout: Response())
    with pytest.raises(render_ops.TransientHealthError, match="IncompleteRead"):
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


def common_args(config: render_ops.ProductionConfig) -> SimpleNamespace:
    return SimpleNamespace(
        apply=True,
        confirm_service_id=config.service_id,
        commit="b" * 40,
        rollback_commit="a" * 40,
        rollback_deploy_id="dep-rollback",
        current_commit="b" * 40,
        current_deploy_id="dep-candidate",
        allow_legacy_null_build_for="",
        repo_root=".",
        timeout=30,
    )


def test_deploy_requires_apply(config: render_ops.ProductionConfig) -> None:
    args = common_args(config)
    args.apply = False
    with pytest.raises(render_ops.OpsError, match="--apply"):
        render_ops._confirm_apply(args, config)


def test_command_deploy_pins_rollback_and_clears_through_client(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
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
    assert health_checks == [{"expected_commit": "b" * 40}]


def test_command_rollback_uses_exact_artifact(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
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
    args.allow_legacy_null_build_for = "a" * 40
    result = render_ops.command_rollback(args)
    assert client.posts == [("rollback", "dep-rollback")]
    assert result["rollback_deploy"]["commit"] == "a" * 40
    assert health_checks == [
        {"expected_commit": "a" * 40, "allow_legacy_null_build": True}
    ]


def test_command_rollback_rejects_legacy_null_flag_for_a_different_commit_before_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    current = deploy("dep-candidate", "b" * 40)
    client = FakeClient(config, artifact, current=current)
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    args = common_args(config)
    args.allow_legacy_null_build_for = "c" * 40

    with pytest.raises(render_ops.OpsError, match="does not match the approved target"):
        render_ops.command_rollback(args)

    assert client.posts == []


def test_command_rollback_requires_exact_artifact(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    artifact = deploy("dep-rollback", "c" * 40, "deactivated")
    client = FakeClient(config, artifact, current=deploy("dep-candidate", "b" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    with pytest.raises(render_ops.OpsError, match="approved artifact"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == []


def test_command_rollback_rejects_failed_artifact_before_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
    artifact = deploy("dep-rollback", "a" * 40, "build_failed")
    client = FakeClient(config, artifact, current=deploy("dep-candidate", "b" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    with pytest.raises(render_ops.OpsError, match="not known-good"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == []


def test_command_rollback_detects_competing_deploy_after_mutation(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
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
    artifact = deploy("dep-rollback", "a" * 40, "deactivated")
    client = FakeClient(config, artifact, current=deploy("dep-other", "c" * 40))
    monkeypatch.setattr(render_ops, "_client", lambda args: (client, config))
    with pytest.raises(render_ops.OpsError, match="approved artifact"):
        render_ops.command_rollback(common_args(config))
    assert client.posts == []


def test_command_verify_requires_exact_current_live(
    monkeypatch: pytest.MonkeyPatch, config: render_ops.ProductionConfig
) -> None:
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
    assert health_checks == [{"expected_commit": "b" * 40}]


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
    assert completed.stdout.splitlines() == [
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
