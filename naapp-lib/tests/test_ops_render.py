from __future__ import annotations

import json
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aweb_naapp.ops import render
from aweb_naapp.ops.render import OpsError, ProductionConfig, RenderClient

SERVICE_ID = "srv-folio0000000000000000"
LIVE_COMMIT = "a" * 40
LIVE_DEPLOY = "dep-live0001"
EARLIER_COMMIT = "b" * 40
EARLIER_DEPLOY = "dep-earlier01"


@dataclass
class FakeRender:
    """The Render API and the deployed service, served over real HTTP on loopback."""

    service: dict[str, Any]
    deploys: list[dict[str, Any]]
    health_status: int = 200
    requests: list[tuple[str, str, Any]] = field(default_factory=list)
    polls_until_live: int = 1
    _counter: int = 0

    def handle(self, method: str, path: str, body: Any) -> tuple[int, Any]:
        self.requests.append((method, path, body))
        base = f"/v1/services/{SERVICE_ID}"
        if method == "GET" and path == "/health":
            return self.health_status, {"status": "ok"}
        if method == "GET" and path == base:
            return 200, self.service
        if method == "GET" and path.startswith(f"{base}/deploys?"):
            return 200, [{"deploy": deploy, "cursor": "x"} for deploy in self.deploys]
        if method == "GET" and path.startswith(f"{base}/deploys/"):
            deploy = self._find(path.rsplit("/", 1)[1])
            if deploy is None:
                return 404, {}
            if deploy["status"] == "build_in_progress":
                deploy["_polls"] = deploy.get("_polls", 0) + 1
                if deploy["_polls"] >= self.polls_until_live:
                    for other in self.deploys:
                        if other["status"] == "live":
                            other["status"] = "deactivated"
                    deploy["status"] = "live"
            return 200, deploy
        if method == "POST" and path == f"{base}/deploys":
            return 201, self._create(str(body["commitId"]))
        if method == "POST" and path == f"{base}/rollback":
            target = self._find(str(body["deployId"]))
            if target is None:
                return 404, {}
            return 201, self._create(target["commit"]["id"])
        return 404, {}

    def _find(self, deploy_id: str) -> dict[str, Any] | None:
        return next((deploy for deploy in self.deploys if deploy["id"] == deploy_id), None)

    def _create(self, commit: str) -> dict[str, Any]:
        self._counter += 1
        deploy = {"id": f"dep-new{self._counter:04d}", "status": "build_in_progress", "commit": {"id": commit}}
        self.deploys.insert(0, deploy)
        return deploy

    def posts(self) -> list[tuple[str, Any]]:
        return [(path, body) for method, path, body in self.requests if method == "POST"]


@pytest.fixture()
def fake() -> Iterator[tuple[FakeRender, str]]:
    state = FakeRender(service={}, deploys=[])

    class Handler(BaseHTTPRequestHandler):
        def _respond(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else None
            status, payload = state.handle(self.command, self.path, body)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = _respond
        do_POST = _respond

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    yield state, origin
    server.shutdown()
    server.server_close()


def _config(origin: str) -> ProductionConfig:
    return ProductionConfig(
        service_id=SERVICE_ID,
        service_name="folio",
        region="oregon",
        repo="https://github.com/awebai/aweb",
        branch="main",
        root_dir="",
        dockerfile_path="./naapp/folio/Dockerfile",
        docker_context=".",
        origin_url=origin,
        public_url=origin,
        health_path="/health",
    )


def _matching_service(config: ProductionConfig) -> dict[str, Any]:
    return {
        "id": config.service_id,
        "name": config.service_name,
        "repo": config.repo,
        "branch": config.branch,
        "rootDir": config.root_dir,
        "autoDeploy": "no",
        "suspended": "not_suspended",
        "serviceDetails": {
            "region": config.region,
            "url": config.origin_url,
            "envSpecificDetails": {
                "dockerfilePath": config.dockerfile_path,
                "dockerContext": config.docker_context,
            },
        },
    }


def _ready(fake: tuple[FakeRender, str]) -> tuple[FakeRender, ProductionConfig, RenderClient]:
    state, origin = fake
    config = _config(origin)
    state.service = _matching_service(config)
    state.deploys = [
        {"id": LIVE_DEPLOY, "status": "live", "commit": {"id": LIVE_COMMIT}},
        {"id": EARLIER_DEPLOY, "status": "deactivated", "commit": {"id": EARLIER_COMMIT}},
    ]
    return state, config, RenderClient("test-key", base_url=f"{origin}/v1")


def _write_config(tmp_path: Path, **overrides: str) -> Path:
    raw = {
        "service_id": SERVICE_ID,
        "service_name": "folio",
        "region": "oregon",
        "repo": "https://github.com/awebai/aweb",
        "branch": "main",
        "root_dir": "",
        "dockerfile_path": "./naapp/folio/Dockerfile",
        "docker_context": ".",
        "origin_url": "https://folio.onrender.com",
        "public_url": "https://folio.aweb.ai",
        "health_path": "/health",
    }
    raw.update(overrides)
    path = tmp_path / "render-production.json"
    path.write_text(json.dumps(raw))
    return path


def test_config_accepts_the_repository_root_as_root_dir(tmp_path: Path) -> None:
    config = ProductionConfig.load(_write_config(tmp_path))
    assert config.root_dir == ""
    assert config.dockerfile_path == "./naapp/folio/Dockerfile"


@pytest.mark.parametrize(
    "overrides",
    [
        {"service_id": "folio"},
        {"origin_url": "http://folio.onrender.com"},
        {"public_url": "http://folio.aweb.ai"},
        {"health_path": "health"},
        {"root_dir": "/naapp/folio"},
        {"root_dir": "../elsewhere"},
        {"dockerfile_path": "../Dockerfile"},
        {"docker_context": "/"},
    ],
)
def test_config_refuses_an_unsafe_value(tmp_path: Path, overrides: dict[str, str]) -> None:
    with pytest.raises(OpsError):
        ProductionConfig.load(_write_config(tmp_path, **overrides))


def test_config_refuses_unknown_or_missing_fields(tmp_path: Path) -> None:
    path = _write_config(tmp_path, extra="x")
    with pytest.raises(OpsError):
        ProductionConfig.load(path)
    raw = json.loads(path.read_text())
    del raw["extra"], raw["docker_context"]
    path.write_text(json.dumps(raw))
    with pytest.raises(OpsError):
        ProductionConfig.load(path)


def test_status_reports_the_live_deploy_of_the_pinned_service(fake) -> None:
    state, config, client = _ready(fake)
    result = render.status(client, config)
    assert result["live_deploy"]["id"] == LIVE_DEPLOY
    assert result["live_deploy"]["commit"] == LIVE_COMMIT
    assert state.posts() == []


@pytest.mark.parametrize(
    ("path", "value", "named"),
    [
        (("rootDir",), "naapp/folio", "rootDir"),
        (("serviceDetails", "envSpecificDetails", "dockerfilePath"), "./Dockerfile", "dockerfilePath"),
        (("serviceDetails", "envSpecificDetails", "dockerContext"), "./naapp/folio", "dockerContext"),
        (("autoDeploy",), "yes", "autoDeploy"),
        (("serviceDetails", "region"), "virginia", "region"),
    ],
)
def test_status_fails_closed_when_the_service_differs_from_the_manifest(fake, path, value, named) -> None:
    state, config, client = _ready(fake)
    target = state.service
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(OpsError, match=named):
        render.status(client, config)


def test_status_treats_an_absent_root_dir_as_the_repository_root(fake) -> None:
    state, config, client = _ready(fake)
    del state.service["rootDir"]
    assert render.status(client, config)["live_deploy"]["id"] == LIVE_DEPLOY


def test_status_fails_closed_on_a_null_root_dir(fake) -> None:
    state, config, client = _ready(fake)
    state.service["rootDir"] = None
    with pytest.raises(OpsError, match="rootDir"):
        render.status(client, config)


def test_status_refuses_while_another_deploy_is_in_progress(fake) -> None:
    state, config, client = _ready(fake)
    state.deploys.insert(0, {"id": "dep-busy0001", "status": "build_in_progress", "commit": {"id": "c" * 40}})
    with pytest.raises(OpsError, match="active"):
        render.status(client, config)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


@pytest.fixture()
def checkout(tmp_path: Path) -> tuple[Path, str]:
    """A real clone whose origin is a bare repository standing in for the remote."""
    remote = tmp_path / "aweb.git"
    _git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    _git(tmp_path, "clone", str(remote), str(work))
    _git(work, "-c", "user.email=t@example.test", "-c", "user.name=t", "commit", "--allow-empty", "-m", "c")
    _git(work, "push", "origin", "HEAD:main")
    _git(work, "fetch", "origin")
    return work, _git(work, "rev-parse", "HEAD")


def test_deploy_ships_the_exact_reviewed_commit_and_waits_for_it_live(fake, checkout) -> None:
    state, config, client = _ready(fake)
    work, commit = checkout
    config = replace(config, repo=str(work.parent / "aweb.git"))
    state.service["repo"] = config.repo

    result = render.deploy(
        client, config, commit=commit, rollback_deploy_id=LIVE_DEPLOY, rollback_commit=LIVE_COMMIT,
        repo_root=work, timeout_seconds=10, interval_seconds=0,
    )

    assert state.posts() == [(f"/v1/services/{SERVICE_ID}/deploys", {"clearCache": "clear", "commitId": commit})]
    assert result["deploy"]["commit"] == commit
    assert result["deploy"]["status"] == "live"
    assert result["rollback"]["id"] == LIVE_DEPLOY


def test_deploy_refuses_a_commit_that_is_not_the_remote_branch_tip(fake, checkout) -> None:
    state, config, client = _ready(fake)
    work, _commit = checkout
    config = replace(config, repo=str(work.parent / "aweb.git"))
    state.service["repo"] = config.repo
    with pytest.raises(OpsError, match="origin/main"):
        render.deploy(
            client, config, commit="d" * 40, rollback_deploy_id=LIVE_DEPLOY, rollback_commit=LIVE_COMMIT,
            repo_root=work, timeout_seconds=10, interval_seconds=0,
        )
    assert state.posts() == []


def test_deploy_refuses_when_the_live_deploy_is_not_the_named_rollback_artifact(fake, checkout) -> None:
    state, config, client = _ready(fake)
    work, commit = checkout
    config = replace(config, repo=str(work.parent / "aweb.git"))
    state.service["repo"] = config.repo
    with pytest.raises(OpsError, match="approved artifact"):
        render.deploy(
            client, config, commit=commit, rollback_deploy_id=EARLIER_DEPLOY, rollback_commit=EARLIER_COMMIT,
            repo_root=work, timeout_seconds=10, interval_seconds=0,
        )
    assert state.posts() == []


def test_rollback_redeploys_the_earlier_artifact_and_never_rebuilds_a_commit(fake) -> None:
    state, config, client = _ready(fake)

    result = render.rollback(
        client, config, rollback_deploy_id=EARLIER_DEPLOY, rollback_commit=EARLIER_COMMIT,
        current_deploy_id=LIVE_DEPLOY, current_commit=LIVE_COMMIT, timeout_seconds=10, interval_seconds=0,
    )

    assert state.posts() == [(f"/v1/services/{SERVICE_ID}/rollback", {"deployId": EARLIER_DEPLOY})]
    assert result["rollback_deploy"]["commit"] == EARLIER_COMMIT
    assert result["rollback_deploy"]["status"] == "live"


def test_rollback_cannot_be_asked_to_deploy_a_commit(fake) -> None:
    state, config, client = _ready(fake)
    with pytest.raises(OpsError, match="deploy ID"):
        render.rollback(
            client, config, rollback_deploy_id=EARLIER_COMMIT, rollback_commit=EARLIER_COMMIT,
            current_deploy_id=LIVE_DEPLOY, current_commit=LIVE_COMMIT, timeout_seconds=10, interval_seconds=0,
        )
    assert state.posts() == []


def test_rollback_refuses_an_artifact_whose_commit_differs(fake) -> None:
    state, config, client = _ready(fake)
    with pytest.raises(OpsError, match="approved artifact"):
        render.rollback(
            client, config, rollback_deploy_id=EARLIER_DEPLOY, rollback_commit="e" * 40,
            current_deploy_id=LIVE_DEPLOY, current_commit=LIVE_COMMIT, timeout_seconds=10, interval_seconds=0,
        )
    assert state.posts() == []


def test_verify_confirms_the_live_commit_and_health(fake) -> None:
    state, config, client = _ready(fake)
    result = render.verify(client, config, deploy_id=LIVE_DEPLOY, commit=LIVE_COMMIT)
    assert result["deploy"]["commit"] == LIVE_COMMIT
    assert result["health"] == {config.origin_url + "/health": 200}
    assert state.posts() == []


def test_verify_fails_when_a_different_commit_is_live(fake) -> None:
    _state, config, client = _ready(fake)
    with pytest.raises(OpsError, match="approved artifact"):
        render.verify(client, config, deploy_id=LIVE_DEPLOY, commit=EARLIER_COMMIT)


def test_verify_fails_when_health_is_not_ok(fake) -> None:
    state, config, client = _ready(fake)
    state.health_status = 503
    with pytest.raises(OpsError, match="health"):
        render.verify(client, config, deploy_id=LIVE_DEPLOY, commit=LIVE_COMMIT)


def test_wait_stops_on_a_failed_build(fake) -> None:
    state, config, client = _ready(fake)
    state.deploys.insert(0, {"id": "dep-failed01", "status": "build_failed", "commit": {"id": "c" * 40}})
    with pytest.raises(OpsError, match="build_failed"):
        render.wait_for_deploy(client, config, "dep-failed01", "c" * 40, timeout_seconds=10, interval_seconds=0)


def test_mutations_require_apply_and_the_exact_service_id(tmp_path: Path) -> None:
    config = ProductionConfig.load(_write_config(tmp_path))
    with pytest.raises(OpsError, match="--apply"):
        render.confirm_apply(config, apply=False, confirm_service_id=SERVICE_ID)
    with pytest.raises(OpsError, match="service-ID"):
        render.confirm_apply(config, apply=True, confirm_service_id="srv-other")
    render.confirm_apply(config, apply=True, confirm_service_id=SERVICE_ID)


def test_api_key_file_must_be_private(tmp_path: Path) -> None:
    key_file = tmp_path / "env"
    key_file.write_text("RENDER_API_KEY=k\n")
    key_file.chmod(0o644)
    with pytest.raises(OpsError, match="accessible"):
        render.load_api_key(key_file)
    key_file.chmod(0o600)
    assert render.load_api_key(key_file) == "k"


def _cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    import os
    import sys

    clean = {key: value for key, value in os.environ.items() if key not in {"APPLY", "CONFIRM_SERVICE_ID"}}
    clean.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "aweb_naapp.ops", *args], text=True, capture_output=True, env=clean
    )


@pytest.mark.parametrize("command", ["deploy", "rollback"])
def test_cli_refuses_a_mutation_without_apply_before_reading_any_key(tmp_path: Path, command: str) -> None:
    result = _cli("--config", str(_write_config(tmp_path)), "--env-file", str(tmp_path / "absent"), command)
    assert result.returncode == 2
    assert "--apply" in result.stderr
    assert result.stdout == ""


def test_cli_reports_a_missing_key_file_as_one_error(tmp_path: Path) -> None:
    result = _cli("--config", str(_write_config(tmp_path)), "--env-file", str(tmp_path / "absent"), "status")
    assert result.returncode == 2
    assert result.stderr.startswith("ERROR: Render env file not found")
