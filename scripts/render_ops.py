#!/usr/bin/env python3
"""Fail-closed Render production operations for Library.

All production mutations require --apply and an exact service-ID confirmation.
The API key is loaded from a mode-0600 env file and is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_BASE = "https://api.render.com/v1"
IN_PROGRESS_STATUSES = {
    "created",
    "build_in_progress",
    "update_in_progress",
    "pre_deploy_in_progress",
}
FAILURE_STATUSES = {"build_failed", "update_failed", "pre_deploy_failed", "canceled"}
TERMINAL_STATUSES = {"live", "deactivated", *FAILURE_STATUSES}
KNOWN_STATUSES = {*IN_PROGRESS_STATUSES, *TERMINAL_STATUSES}
ROLLBACK_ARTIFACT_STATUSES = {"live", "deactivated"}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DEPLOY_RE = re.compile(r"^dep-[a-z0-9]+$")
SERVICE_RE = re.compile(r"^srv-[a-z0-9]+$")


class OpsError(RuntimeError):
    """A safe-to-print operational failure."""


@dataclass(frozen=True)
class ProductionConfig:
    service_id: str
    service_name: str
    region: str
    repo: str
    branch: str
    origin_url: str
    public_url: str
    health_path: str

    @classmethod
    def load(cls, path: Path) -> ProductionConfig:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            config = cls(**raw)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise OpsError(f"invalid production config: {path}") from exc
        if not SERVICE_RE.fullmatch(config.service_id):
            raise OpsError("production config has an invalid Render service ID")
        if not config.origin_url.startswith("https://") or not config.public_url.startswith(
            "https://"
        ):
            raise OpsError("production URLs must use https")
        if not config.health_path.startswith("/"):
            raise OpsError("health_path must be absolute")
        return config


def load_api_key(path: Path) -> str:
    try:
        if path.is_symlink():
            raise OpsError("Render env file must not be a symlink")
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError as exc:
        raise OpsError(f"Render env file not found: {path}") from exc
    if mode & 0o077:
        raise OpsError(f"Render env file must not be group/world accessible (mode {mode:03o})")
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpsError(f"Render env file cannot be read: {path}") from exc
    values: list[str] = []
    for raw in contents.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if line.startswith("RENDER_API_KEY="):
            value = line.split("=", 1)[1].strip().strip("'\"")
            values.append(value)
    if len(values) != 1 or not values[0]:
        raise OpsError("Render env file must contain exactly one nonempty RENDER_API_KEY")
    return values[0]


class RenderClient:
    def __init__(self, api_key: str, *, base_url: str = API_BASE, timeout: float = 30.0) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self._base_url}{path}",
            method=method,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise OpsError(f"Render API {method} {path} failed with HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise OpsError(f"Render API {method} {path} failed: {type(exc).__name__}") from exc

    def service(self, service_id: str) -> dict[str, Any]:
        return _unwrap(self.request("GET", f"/services/{service_id}"), "service")

    def deploys(self, service_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        response = self.request("GET", f"/services/{service_id}/deploys?limit={limit}")
        return [_unwrap(item, "deploy") for item in response]

    def deploy(self, service_id: str, commit: str) -> dict[str, Any]:
        return _unwrap(
            self.request(
                "POST",
                f"/services/{service_id}/deploys",
                {"clearCache": "clear", "commitId": commit},
            ),
            "deploy",
        )

    def rollback(self, service_id: str, deploy_id: str) -> dict[str, Any]:
        return _unwrap(
            self.request("POST", f"/services/{service_id}/rollback", {"deployId": deploy_id}),
            "deploy",
        )

    def deploy_by_id(self, service_id: str, deploy_id: str) -> dict[str, Any]:
        return _unwrap(self.request("GET", f"/services/{service_id}/deploys/{deploy_id}"), "deploy")


def _unwrap(value: Any, key: str) -> Any:
    if isinstance(value, dict) and key in value:
        return value[key]
    return value


def deploy_commit(deploy: dict[str, Any]) -> str:
    commit = deploy.get("commit") or {}
    return str(commit.get("id") or deploy.get("commitId") or "")


def safe_deploy(deploy: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": deploy.get("id"),
        "status": deploy.get("status"),
        "commit": deploy_commit(deploy),
        "created_at": deploy.get("createdAt"),
        "finished_at": deploy.get("finishedAt"),
    }


def validate_service(service: dict[str, Any], config: ProductionConfig) -> None:
    details = service.get("serviceDetails") or {}
    observed = {
        "id": service.get("id"),
        "name": service.get("name"),
        "region": details.get("region"),
        "repo": service.get("repo"),
        "branch": service.get("branch"),
        "url": details.get("url"),
        "suspended": service.get("suspended"),
        "autoDeploy": service.get("autoDeploy"),
    }
    expected = {
        "id": config.service_id,
        "name": config.service_name,
        "region": config.region,
        "repo": config.repo,
        "branch": config.branch,
        "url": config.origin_url,
        "suspended": "not_suspended",
        "autoDeploy": "no",
    }
    mismatches = [key for key in expected if observed[key] != expected[key]]
    if mismatches:
        raise OpsError(f"Render service does not match production config: {', '.join(mismatches)}")


def require_commit(value: str, field: str = "commit") -> str:
    if not COMMIT_RE.fullmatch(value):
        raise OpsError(f"{field} must be a full lowercase 40-character Git SHA")
    return value


def require_deploy_id(value: str, field: str = "deploy ID") -> str:
    if not DEPLOY_RE.fullmatch(value):
        raise OpsError(f"{field} is invalid")
    return value


def canonical_git_repo(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("git@github.com:"):
        normalized = f"github.com/{normalized.removeprefix('git@github.com:')}"
    elif normalized.startswith("https://") or normalized.startswith("ssh://"):
        normalized = normalized.split("://", 1)[1]
    return normalized.removesuffix(".git").rstrip("/")


def verify_git_target(
    repo_root: Path, commit: str, *, expected_repo: str, expected_branch: str
) -> None:
    require_commit(commit)
    remote_ref = f"origin/{expected_branch}"
    try:
        origin_url = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        remote_commit = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", remote_ref],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise OpsError("failed to verify local Git target") from exc
    if canonical_git_repo(origin_url) != canonical_git_repo(expected_repo):
        raise OpsError("local origin remote is not the configured production repository")
    if remote_commit != commit:
        raise OpsError(f"{remote_ref} is {remote_commit}, not the approved target {commit}")


def current_live(deploys: list[dict[str, Any]]) -> dict[str, Any]:
    unknown = [deploy for deploy in deploys if deploy.get("status") not in KNOWN_STATUSES]
    if unknown:
        raise OpsError(
            f"refusing unknown Render deploy state {unknown[0].get('status')!r}: "
            f"{unknown[0].get('id')}"
        )
    active = [deploy for deploy in deploys if deploy.get("status") in IN_PROGRESS_STATUSES]
    if active:
        raise OpsError(f"another deploy is active: {active[0].get('id')}")
    live = [deploy for deploy in deploys if deploy.get("status") == "live"]
    if len(live) != 1:
        raise OpsError(f"expected exactly one live deploy, found {len(live)}")
    return live[0]


def require_deploy(deploy: dict[str, Any], *, deploy_id: str, commit: str) -> None:
    if deploy.get("id") != deploy_id or deploy_commit(deploy) != commit:
        raise OpsError("deploy ID/commit does not match the approved artifact")


def require_rollback_artifact(deploy: dict[str, Any], *, deploy_id: str, commit: str) -> None:
    require_deploy(deploy, deploy_id=deploy_id, commit=commit)
    if deploy.get("status") not in ROLLBACK_ARTIFACT_STATUSES:
        raise OpsError(f"rollback artifact is not known-good: {deploy.get('status')}")


def wait_for_deploy(
    client: RenderClient,
    config: ProductionConfig,
    deploy_id: str,
    expected_commit: str,
    *,
    timeout_seconds: int = 900,
    interval_seconds: float = 10.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_status = ""
    while time.monotonic() < deadline:
        deploy = client.deploy_by_id(config.service_id, deploy_id)
        if deploy_commit(deploy) != expected_commit:
            raise OpsError("Render deploy commit changed while waiting")
        status = str(deploy.get("status") or "")
        if status != last_status:
            print(json.dumps({"deploy_id": deploy_id, "status": status, "commit": expected_commit}))
            last_status = status
        if status == "live":
            return deploy
        if status in FAILURE_STATUSES or status == "deactivated":
            raise OpsError(f"Render deploy entered failure state: {status}")
        if status not in IN_PROGRESS_STATUSES:
            raise OpsError(f"Render deploy entered unknown state: {status!r}")
        sleep(interval_seconds)
    raise OpsError(f"timed out waiting for Render deploy {deploy_id}")


def verify_health(url: str, *, timeout: float = 20.0) -> dict[str, Any]:
    try:
        with urlopen(url, timeout=timeout) as response:
            if response.geturl() != url:
                raise OpsError(f"health check redirected away from exact surface {url}")
            if response.status != 200:
                raise OpsError(f"health check returned HTTP {response.status}")
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise OpsError(f"health check failed for {url}: {type(exc).__name__}") from exc
    if payload != {"status": "ok", "service": "library"}:
        raise OpsError(f"unexpected Library health payload from {url}")
    return payload


def verify_health_surfaces(config: ProductionConfig) -> dict[str, Any]:
    origin = verify_health(f"{config.origin_url}{config.health_path}")
    public = verify_health(f"{config.public_url}{config.health_path}")
    return {"origin": origin, "public": public}


def _client(args: argparse.Namespace) -> tuple[RenderClient, ProductionConfig]:
    config = ProductionConfig.load(Path(args.config))
    api_key = load_api_key(Path(args.env_file).expanduser())
    return RenderClient(api_key), config


def _confirm_apply(args: argparse.Namespace, config: ProductionConfig) -> None:
    if not args.apply:
        raise OpsError("mutation refused: pass --apply (Makefile requires APPLY=1)")
    if args.confirm_service_id != config.service_id:
        raise OpsError("mutation refused: exact service-ID confirmation does not match")


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    service = client.service(config.service_id)
    validate_service(service, config)
    deploys = client.deploys(config.service_id)
    live = current_live(deploys)
    details = service.get("serviceDetails") or {}
    return {
        "service": {
            "id": service.get("id"),
            "name": service.get("name"),
            "region": details.get("region"),
            "origin_url": details.get("url"),
            "public_url": config.public_url,
            "auto_deploy": service.get("autoDeploy"),
        },
        "live_deploy": safe_deploy(live),
    }


def command_deploy(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    _confirm_apply(args, config)
    commit = require_commit(args.commit)
    rollback_commit = require_commit(args.rollback_commit, "rollback commit")
    rollback_id = require_deploy_id(args.rollback_deploy_id, "rollback deploy ID")
    if args.timeout <= 0:
        raise OpsError("timeout must be positive")
    verify_git_target(
        Path(args.repo_root),
        commit,
        expected_repo=config.repo,
        expected_branch=config.branch,
    )
    service = client.service(config.service_id)
    validate_service(service, config)
    live = current_live(client.deploys(config.service_id))
    require_rollback_artifact(live, deploy_id=rollback_id, commit=rollback_commit)
    created = client.deploy(config.service_id, commit)
    deploy_id = require_deploy_id(str(created.get("id") or ""), "created deploy ID")
    if deploy_commit(created) != commit:
        raise OpsError("Render created a deploy for the wrong commit")
    finished = wait_for_deploy(client, config, deploy_id, commit, timeout_seconds=args.timeout)
    final_live = current_live(client.deploys(config.service_id))
    require_deploy(final_live, deploy_id=deploy_id, commit=commit)
    health = verify_health_surfaces(config)
    return {"deploy": safe_deploy(finished), "rollback": safe_deploy(live), "health": health}


def command_wait(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    deploy_id = require_deploy_id(args.deploy_id)
    commit = require_commit(args.commit)
    if args.timeout <= 0:
        raise OpsError("timeout must be positive")
    validate_service(client.service(config.service_id), config)
    finished = wait_for_deploy(client, config, deploy_id, commit, timeout_seconds=args.timeout)
    return {"deploy": safe_deploy(finished)}


def command_verify(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    deploy_id = require_deploy_id(args.deploy_id)
    commit = require_commit(args.commit)
    validate_service(client.service(config.service_id), config)
    artifact = client.deploy_by_id(config.service_id, deploy_id)
    require_deploy(artifact, deploy_id=deploy_id, commit=commit)
    if artifact.get("status") != "live":
        raise OpsError(f"expected deploy is not live: {artifact.get('status')}")
    live = current_live(client.deploys(config.service_id))
    require_deploy(live, deploy_id=deploy_id, commit=commit)
    return {"deploy": safe_deploy(artifact), "health": verify_health_surfaces(config)}


def command_rollback(args: argparse.Namespace) -> dict[str, Any]:
    client, config = _client(args)
    _confirm_apply(args, config)
    rollback_commit = require_commit(args.rollback_commit, "rollback commit")
    rollback_id = require_deploy_id(args.rollback_deploy_id, "rollback deploy ID")
    current_commit = require_commit(args.current_commit, "current live commit")
    current_id = require_deploy_id(args.current_deploy_id, "current live deploy ID")
    if args.timeout <= 0:
        raise OpsError("timeout must be positive")
    service = client.service(config.service_id)
    validate_service(service, config)
    live = current_live(client.deploys(config.service_id))
    require_deploy(live, deploy_id=current_id, commit=current_commit)
    if current_id == rollback_id:
        raise OpsError("current live deploy and rollback artifact must be different")
    artifact = client.deploy_by_id(config.service_id, rollback_id)
    require_rollback_artifact(artifact, deploy_id=rollback_id, commit=rollback_commit)
    created = client.rollback(config.service_id, rollback_id)
    created_id = require_deploy_id(str(created.get("id") or ""), "created rollback deploy ID")
    if deploy_commit(created) != rollback_commit:
        raise OpsError("Render created a rollback for the wrong commit")
    finished = wait_for_deploy(
        client, config, created_id, rollback_commit, timeout_seconds=args.timeout
    )
    final_live = current_live(client.deploys(config.service_id))
    require_deploy(final_live, deploy_id=created_id, commit=rollback_commit)
    health = verify_health_surfaces(config)
    return {"rollback_deploy": safe_deploy(finished), "health": health}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", default=os.environ.get("PROD_CONFIG", "ops/render-production.json"))
    p.add_argument("--env-file", default=os.environ.get("RENDER_ENV_FILE", "~/.aweb-render/env"))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    deploy = sub.add_parser("deploy")
    deploy.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    deploy.add_argument("--rollback-deploy-id", default=os.environ.get("ROLLBACK_DEPLOY_ID", ""))
    deploy.add_argument("--rollback-commit", default=os.environ.get("ROLLBACK_COMMIT", ""))
    deploy.add_argument("--repo-root", default=".")
    deploy.add_argument("--confirm-service-id", default=os.environ.get("CONFIRM_SERVICE_ID", ""))
    deploy.add_argument("--timeout", type=int, default=900)
    deploy.add_argument("--apply", action="store_true", default=os.environ.get("APPLY") == "1")
    wait = sub.add_parser("wait")
    wait.add_argument("--deploy-id", default=os.environ.get("PROD_DEPLOY_ID", ""))
    wait.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    wait.add_argument("--timeout", type=int, default=900)
    verify = sub.add_parser("verify")
    verify.add_argument("--deploy-id", default=os.environ.get("PROD_DEPLOY_ID", ""))
    verify.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--rollback-deploy-id", default=os.environ.get("ROLLBACK_DEPLOY_ID", ""))
    rollback.add_argument("--rollback-commit", default=os.environ.get("ROLLBACK_COMMIT", ""))
    rollback.add_argument("--current-deploy-id", default=os.environ.get("CURRENT_DEPLOY_ID", ""))
    rollback.add_argument("--current-commit", default=os.environ.get("CURRENT_COMMIT", ""))
    rollback.add_argument("--confirm-service-id", default=os.environ.get("CONFIRM_SERVICE_ID", ""))
    rollback.add_argument("--timeout", type=int, default=900)
    rollback.add_argument("--apply", action="store_true", default=os.environ.get("APPLY") == "1")
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "status":
            result = command_status(args)
        elif args.command == "deploy":
            result = command_deploy(args)
        elif args.command == "wait":
            result = command_wait(args)
        elif args.command == "verify":
            result = command_verify(args)
        elif args.command == "rollback":
            result = command_rollback(args)
        else:  # pragma: no cover
            raise OpsError("unsupported command")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except OpsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
