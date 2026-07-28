from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from scripts import render_ops


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
            return b'{"status":"ok","service":"library"}'

    monkeypatch.setattr(render_ops, "urlopen", lambda url, timeout: Response())
    with pytest.raises(render_ops.OpsError, match="redirected away"):
        render_ops.verify_health("https://library-origin.example/health")


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
    monkeypatch.setattr(render_ops, "verify_health_surfaces", lambda cfg: {"ok": True})
    result = render_ops.command_deploy(common_args(config))
    assert client.posts == [("deploy", "b" * 40)]
    assert result["rollback"]["id"] == "dep-rollback"
    assert result["deploy"]["id"] == "dep-created"


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
    monkeypatch.setattr(render_ops, "verify_health_surfaces", lambda cfg: {"ok": True})
    result = render_ops.command_rollback(common_args(config))
    assert client.posts == [("rollback", "dep-rollback")]
    assert result["rollback_deploy"]["commit"] == "a" * 40


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
    monkeypatch.setattr(render_ops, "verify_health_surfaces", lambda cfg: {"ok": True})
    args = SimpleNamespace(deploy_id="dep-candidate", commit="b" * 40)
    result = render_ops.command_verify(args)
    assert result["deploy"]["status"] == "live"


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
