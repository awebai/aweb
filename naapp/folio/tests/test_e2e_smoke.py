from __future__ import annotations

import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.e2e


@dataclass(frozen=True)
class E2EStack:
    host: str
    awid_url: str
    postgres_url: str
    compose: list[str]


def e2e_stack(env: Mapping[str, str]) -> E2EStack:
    """The docker-compose stack `make e2e` brings up, as the NAAPP_E2E_* names place it.

    A gate passes a compose project, the host its published ports are reached at, and
    free host ports; a local run gets the fixed values docker-compose.e2e.yml defaults to.
    """
    host = env.get("NAAPP_E2E_HOST", "127.0.0.1")
    project = env.get("NAAPP_E2E_PROJECT", "folio-e2e")
    awid_port = env.get("NAAPP_E2E_AWID_PORT", "18010")
    postgres_port = env.get("NAAPP_E2E_POSTGRES_PORT", "55432")
    return E2EStack(
        host=host,
        awid_url=f"http://{host}:{awid_port}",
        postgres_url=f"postgresql://folio:folio@{host}:{postgres_port}/folio",
        compose=["docker", "compose", "-p", project, "-f", "docker-compose.e2e.yml"],
    )


STACK = e2e_stack(os.environ)
AWID_URL = STACK.awid_url
# Same-operator credential shared with the e2e awid service (docker-compose.e2e.yml).
AWID_SERVICE_TOKEN = os.environ.get(
    "FOLIO_E2E_AWID_SERVICE_TOKEN", "folio-e2e-awid-service-token-0123456789abcdef"
)
POSTGRES_URL = STACK.postgres_url
COMPOSE = STACK.compose


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class RecordingProxy(ThreadingHTTPServer):
    backend_origin: str
    last_request: CapturedRequest | None

    def __init__(self, server_address: tuple[str, int], backend_origin: str) -> None:
        super().__init__(server_address, _RecordingProxyHandler)
        self.backend_origin = backend_origin.rstrip("/")
        self.last_request = None


class _RecordingProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def proxy(self) -> RecordingProxy:
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook
        self._proxy()

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _proxy(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length) if length else b""
        headers = {key: value for key, value in self.headers.items()}
        self.proxy.last_request = CapturedRequest(
            method=self.command,
            path=self.path,
            headers=headers,
            body=body,
        )

        forward_headers = {
            key: value
            for key, value in headers.items()
            if key.lower() not in {"host", "content-length", "connection", "accept-encoding"}
        }
        try:
            with httpx.Client(timeout=15.0, follow_redirects=False) as client:
                upstream = client.request(
                    self.command,
                    f"{self.proxy.backend_origin}{self.path}",
                    headers=forward_headers,
                    content=body,
                )
        except Exception as exc:  # pragma: no cover - diagnostic path only
            response = str(exc).encode("utf-8", errors="replace")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            self.close_connection = True
            return

        self.send_response(upstream.status_code)
        for key, value in upstream.headers.items():
            if key.lower() in {"content-length", "connection", "transfer-encoding", "content-encoding"}:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(upstream.content)))
        self.end_headers()
        self.wfile.write(upstream.content)
        self.close_connection = True


@dataclass(frozen=True)
class RunningFolio:
    origin: str
    backend_origin: str
    proxy: RecordingProxy

    @property
    def last_request(self) -> CapturedRequest:
        captured = self.proxy.last_request
        assert captured is not None
        return captured


@dataclass(frozen=True)
class AWWorkspace:
    path: Path
    env: dict[str, str]


@dataclass(frozen=True)
class E2ETeam:
    workspace: AWWorkspace
    namespace: str
    team: str
    team_id: str
    alias: str
    address: str
    did_key: str
    certificate_id: str


def _require_e2e_enabled() -> None:
    if os.environ.get("FOLIO_E2E") != "1":
        pytest.skip("set FOLIO_E2E=1 or run `make e2e` to execute docker-backed e2e tests")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_http_ok(url: str, *, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=2.0)
            if response.status_code < 500:
                return
        except Exception as exc:  # pragma: no cover - only used for diagnostics
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for {url}: {last_error}")


def _compose(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [*COMPOSE, *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "docker compose command failed\n"
            f"cmd: {' '.join([*COMPOSE, *args])}\n"
            f"exit: {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
        )
    return result


def _run_aw(workspace: AWWorkspace, *args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["aw", "--json", *args],
        cwd=workspace.path,
        env=workspace.env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "aw command failed\n"
            f"cmd: aw --json {' '.join(args)}\n"
            f"exit: {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
        )
    return result


def _run_aw_json(workspace: AWWorkspace, *args: str) -> dict[str, Any]:
    result = _run_aw(workspace, *args)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"aw command did not emit JSON: {result.stdout}\n{result.stderr}") from exc
    assert isinstance(payload, dict)
    return payload


def _aw_request(
    team: E2ETeam,
    method: str,
    url: str,
    *,
    body: str | None = None,
    body_file: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    args = ["aw", "id", "request", method, url, "--team-auth", "--raw"]
    if body is not None:
        args.extend(["--body", body])
    if body_file is not None:
        args.extend(["--body-file", str(body_file)])
    return subprocess.run(
        args,
        cwd=team.workspace.path,
        env=team.workspace.env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _assert_aw_success(result: subprocess.CompletedProcess[str], *, context: str) -> str:
    assert result.returncode == 0, (
        f"aw id request failed: {context}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}\n"
    )
    return result.stdout


def _assert_aw_status(result: subprocess.CompletedProcess[str], status: int, *, context: str) -> None:
    assert result.returncode != 0, f"expected HTTP {status} failure for {context}, got success: {result.stdout}"
    assert f"HTTP {status}" in result.stderr, (
        f"expected HTTP {status} for {context}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}\n"
    )


def _aw_json(result: subprocess.CompletedProcess[str], *, context: str) -> Any:
    stdout = _assert_aw_success(result, context=context)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON for {context}: {stdout}") from exc


@contextmanager
def _running_folio(*, awid_service_token: str | None) -> Iterator[RunningFolio]:
    _require_e2e_enabled()
    _wait_http_ok(f"{AWID_URL}/health")

    backend_port = _free_port()
    proxy_port = _free_port()
    backend_origin = f"http://127.0.0.1:{backend_port}"
    proxy_origin = f"http://127.0.0.1:{proxy_port}"
    env = os.environ.copy()
    env.update(
        {
            "FOLIO_DATABASE_URL": POSTGRES_URL,
            "FOLIO_AWID_REGISTRY_URL": AWID_URL,
            "FOLIO_AUTH_CACHE_TTL_SECONDS": "2",
            "FOLIO_PUBLIC_ORIGIN": proxy_origin,
        }
    )
    env.pop("FOLIO_AWID_SERVICE_TOKEN", None)
    if awid_service_token is not None:
        env["FOLIO_AWID_SERVICE_TOKEN"] = awid_service_token
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "folio.api:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(backend_port),
        ],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proxy = RecordingProxy(("127.0.0.1", proxy_port), backend_origin)
    thread = threading.Thread(target=proxy.serve_forever, name="folio-e2e-proxy", daemon=True)
    thread.start()
    try:
        _wait_http_ok(f"{proxy_origin}/health")
        yield RunningFolio(origin=proxy_origin, backend_origin=backend_origin, proxy=proxy)
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        failed = proc.returncode not in (0, -15, -9, None)
        stdout = proc.stdout.read() if failed and proc.stdout else ""
        stderr = proc.stderr.read() if failed and proc.stderr else ""
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        if failed:
            raise RuntimeError(f"uvicorn exited with {proc.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}")


@pytest.fixture(scope="session")
def folio() -> Iterator[RunningFolio]:
    with _running_folio(awid_service_token=AWID_SERVICE_TOKEN) as running:
        yield running


@pytest.fixture(scope="session")
def folio_without_awid_service_token() -> Iterator[RunningFolio]:
    with _running_folio(awid_service_token=None) as running:
        yield running


@pytest.fixture(scope="session")
def folio_origin(folio: RunningFolio) -> str:
    return folio.origin


def aw_workspace_env(*, home: Path) -> dict[str, str]:
    """Environment for a disposable aw workspace, free of the caller's own aw identity
    and config selection."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AW_"))}
    env.update(
        {
            "HOME": str(home),
            "AWEB_URL": "http://127.0.0.1:1",
            "AWID_REGISTRY_URL": AWID_URL,
            "NO_COLOR": "1",
        }
    )
    return env


@pytest.fixture()
def aw_workspace_factory(tmp_path: Path) -> Callable[[str], AWWorkspace]:
    _require_e2e_enabled()

    def make(name: str) -> AWWorkspace:
        workspace = tmp_path / name / "workspace"
        home = tmp_path / name / "home"
        workspace.mkdir(parents=True)
        home.mkdir(parents=True)
        return AWWorkspace(path=workspace, env=aw_workspace_env(home=home))

    return make


@pytest.fixture()
def aw_workspace(aw_workspace_factory: Callable[[str], AWWorkspace]) -> AWWorkspace:
    return aw_workspace_factory("primary")


def _write_workspace_binding(workspace: AWWorkspace, *, team_id: str, alias: str, cert_path: str) -> None:
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    workspace_id = str(uuid.uuid4())
    (workspace.path / ".aw" / "workspace.yaml").write_text(
        f"""aweb_url: http://127.0.0.1:1
memberships:
    - team_id: {team_id}
      alias: {alias}
      workspace_id: {workspace_id}
      cert_path: {cert_path}
      joined_at: \"{now}\"
human_name: e2e
agent_type: agent
workspace_path: {workspace.path}
updated_at: \"{now}\"
""",
        encoding="utf-8",
    )


def _provision_team(workspace: AWWorkspace, *, alias: str = "alice") -> E2ETeam:
    unique = uuid.uuid4().hex[:12]
    namespace = f"folio-{unique}.test"
    team = "default"
    address = f"{namespace}/{alias}"

    _run_aw(
        workspace,
        "id",
        "create",
        "--domain",
        namespace,
        "--name",
        alias,
        "--registry",
        AWID_URL,
        "--skip-dns-verify",
    )
    _run_aw(
        workspace,
        "id",
        "team",
        "create",
        "--namespace",
        namespace,
        "--name",
        team,
        "--registry",
        AWID_URL,
    )
    add_member = _run_aw_json(
        workspace,
        "id",
        "team",
        "add-member",
        "--namespace",
        namespace,
        "--team",
        team,
        "--member",
        address,
    )
    certificate_id = str(add_member["certificate_id"])
    fetch_cert = _run_aw_json(
        workspace,
        "id",
        "team",
        "fetch-cert",
        "--namespace",
        namespace,
        "--team",
        team,
        "--cert-id",
        certificate_id,
        "--registry",
        AWID_URL,
    )
    team_id = f"{team}:{namespace}"
    _run_aw(workspace, "id", "team", "switch", team_id)
    _write_workspace_binding(
        workspace,
        team_id=team_id,
        alias=alias,
        cert_path=str(fetch_cert["cert_path"]),
    )
    cert = _run_aw_json(workspace, "id", "cert", "show")
    return E2ETeam(
        workspace=workspace,
        namespace=namespace,
        team=team,
        team_id=team_id,
        alias=alias,
        address=address,
        did_key=str(cert["member_did_key"]),
        certificate_id=certificate_id,
    )


def _provision_real_team_certificate(workspace: AWWorkspace) -> str:
    return _provision_team(workspace).team_id


def _create_document(folio: RunningFolio, team: E2ETeam, *, slug: str, title: str, body: str) -> dict[str, Any]:
    payload = json.dumps({"slug": slug, "title": title, "body": body}, separators=(",", ":"))
    result = _aw_request(team, "POST", f"{folio.origin}/v1/documents", body=payload)
    data = _aw_json(result, context=f"create document {slug}")
    assert isinstance(data, dict)
    return data


def _get_document(folio: RunningFolio, team: E2ETeam, slug: str) -> dict[str, Any]:
    result = _aw_request(team, "GET", f"{folio.origin}/v1/documents/{slug}")
    data = _aw_json(result, context=f"get document {slug}")
    assert isinstance(data, dict)
    return data


def _list_documents(folio: RunningFolio, team: E2ETeam) -> list[dict[str, Any]]:
    result = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
    data = _aw_json(result, context="list documents")
    assert isinstance(data, list)
    return data


def _append_version(folio: RunningFolio, team: E2ETeam, *, slug: str, body: str, tmp_path: Path) -> dict[str, Any]:
    body_file = tmp_path / f"{slug}-{uuid.uuid4().hex}.txt"
    body_file.write_text(body, encoding="utf-8")
    result = _aw_request(team, "POST", f"{folio.origin}/v1/documents/{slug}/versions", body_file=body_file)
    data = _aw_json(result, context=f"append version {slug}")
    assert isinstance(data, dict)
    return data


def _list_versions(folio: RunningFolio, team: E2ETeam, slug: str) -> list[dict[str, Any]]:
    result = _aw_request(team, "GET", f"{folio.origin}/v1/documents/{slug}/versions")
    data = _aw_json(result, context=f"list versions {slug}")
    assert isinstance(data, list)
    return data


def _get_billing(folio: RunningFolio, team: E2ETeam) -> dict[str, Any]:
    result = _aw_request(team, "GET", f"{folio.origin}/v1/billing")
    data = _aw_json(result, context="get billing")
    assert isinstance(data, dict)
    return data


def test_health_endpoints_are_public(folio: RunningFolio) -> None:
    for path in ("/health", "/live", "/ready"):
        response = httpx.get(f"{folio.origin}{path}", timeout=10.0)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "ok" and body["service"] == "folio", body
        assert "git_sha" in body["build"], body
    checks = httpx.get(f"{folio.origin}/health", timeout=10.0).json()["checks"]
    assert checks["database"]["ok"] and checks["outbox"]["ok"], checks


def test_no_envelope_fails_closed(folio_origin: str) -> None:
    response = httpx.get(f"{folio_origin}/v1/documents", timeout=10.0)
    assert response.status_code == 401, response.text


def test_well_known_manifest_is_public_and_byte_stable(folio: RunningFolio) -> None:
    from aweb_naapp.manifest import canonical_bytes
    from manifest_config import served_manifest

    # Public discovery doc: no team-auth envelope, still 200.
    response = httpx.get(f"{folio.origin}/.well-known/aweb-app.json", timeout=10.0)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    # The real server fills the declared kid from its configured key once at
    # startup, and both discovery paths serve those exact deployment bytes.
    assert response.content == canonical_bytes(served_manifest(folio.origin))
    assert httpx.get(f"{folio.origin}/aweb-app.json", timeout=10.0).content == response.content
    again = httpx.get(f"{folio.origin}/.well-known/aweb-app.json", timeout=10.0)
    assert again.content == response.content


def test_real_aw_team_auth_smoke(folio: RunningFolio, aw_workspace: AWWorkspace) -> None:
    team = _provision_team(aw_workspace)
    result = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
    assert _assert_aw_success(result, context="list documents smoke").strip() == "[]"


def test_private_team_member_authenticates_without_the_awid_service_token(
    folio_without_awid_service_token: RunningFolio, aw_workspace: AWWorkspace
) -> None:
    # Without a service token Folio checks the member's certificate through
    # AWID's per-certificate status, which a private team's members can use too.
    team = _provision_team(aw_workspace)
    result = _aw_request(team, "GET", f"{folio_without_awid_service_token.origin}/v1/documents")
    assert _assert_aw_success(result, context="private team without service token").strip() == "[]"


@contextmanager
def _running_coordination_server(tmp_path: Path) -> Iterator[str]:
    """Real aweb using this stack's disposable PG/Redis, for grant/custody auth."""
    port = _free_port()
    origin = f"http://127.0.0.1:{port}"
    redis_port = _compose("port", "redis", "6379").stdout.strip().rsplit(":", 1)[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AW_", "AWID_"))}
    env.update(
        AWEB_DATABASE_URL=POSTGRES_URL,
        AWEB_REDIS_URL=f"redis://{STACK.host}:{redis_port}/0",
        AWEB_PUBLIC_ORIGIN=origin,
        AWID_REGISTRY_URL=AWID_URL,
        AWID_SERVICE_TOKEN=AWID_SERVICE_TOKEN,
    )
    # Use the locked server source environment, not an installed aweb artifact.
    project = Path(__file__).resolve().parents[3] / "server"
    with (tmp_path / "coordination.log").open("w+") as log:
        proc = subprocess.Popen(
            ["uv", "run", "--offline", "--frozen", "--project", str(project),
             "aweb", "serve", "--host", "127.0.0.1", "--port", str(port)],
            env=env, stdout=log, stderr=log,
        )
        try:
            _wait_http_ok(f"{origin}/health")
            yield origin
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
            # uv may report forwarded SIGTERM as 128 + SIGTERM.
            if proc.returncode not in (0, -15, 143, None):
                log.seek(0)
                raise AssertionError(f"coordination server exit {proc.returncode}: {log.read()}")


def test_install_after_mint_uses_replacement_grant(
    folio: RunningFolio, aw_workspace: AWWorkspace, tmp_path: Path,
) -> None:
    team = _provision_team(aw_workspace)
    resident_home = aw_workspace.path / ".aw"
    before_home = tmp_path / "before-install"
    replacement_home = tmp_path / "after-install"
    instance = tmp_path / "instance"
    instance.mkdir()
    with _running_coordination_server(tmp_path) as origin:
        aw_workspace.env["AWEB_URL"] = origin
        _run_aw(aw_workspace, "workspace", "connect", "--service", origin, "--team", team.team_id)
        with (tmp_path / "custody.log").open("w+") as log:
            custody = subprocess.Popen(
                ["aw", "--identity-home", str(resident_home), "custody", "serve"],
                cwd=aw_workspace.path, env=aw_workspace.env, stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 30
                while True:
                    status = subprocess.run(
                        ["aw", "--identity-home", str(resident_home), "--json", "custody", "status"],
                        cwd=instance, env=aw_workspace.env, text=True, capture_output=True, timeout=5,
                    )
                    if status.returncode == 0:
                        break
                    assert time.monotonic() < deadline, status.stderr
                    assert custody.poll() is None, "custody exited before readiness"
                    time.sleep(.05)
                minted = _run_aw_json(aw_workspace, "id", "grant", "mint", "--bundle", "normal-agent", "--ttl", "30m", "--custody-socket", "auto", "--out", str(before_home))
                assert minted["apps"] == []
                assert minted["custody_socket_path"] == json.loads(status.stdout)["socket_path"]
                before_material = {
                    p.name: hashlib.sha256(p.read_bytes()).digest()
                    for p in before_home.iterdir() if p.is_file()
                }
                grant_env = dict(aw_workspace.env, AWEB_IDENTITY_HOME=str(before_home))
                grant = AWWorkspace(path=instance, env=grant_env)
                manifest = folio.origin
                refused = subprocess.run(
                    ["aw", "plugin", "install", manifest], cwd=instance, env=grant_env,
                    text=True, capture_output=True, timeout=30,
                )
                assert refused.returncode != 0 and "app_management_denied" in refused.stderr
                installed = _run_aw_json(aw_workspace, "--identity-home", str(resident_home), "plugin", "install", manifest)
                assert installed["approved"] and installed["existing_grants_unchanged"]
                assert installed["identity_home"] == str(resident_home)
                assert installed["active_grants"] == 1
                assert installed["grant_restart_command"] == [
                    "env", "AWEB_IDENTITY_HOME=<new-grant-home>", "<agent-command>",
                ]
                assert installed["oats_renew_restart_command"] == [
                    "oats", "session", "restart", "--home", "<instance-home>",
                ]
                updated = _run_aw(aw_workspace, "--json=false", "plugin", "update", "folio")
                assert "1 active grant" in updated.stdout
                assert "do not gain tools from this install or update" in updated.stdout
                commands = [shlex.split(line.strip()) for line in updated.stdout.splitlines()
                            if line.startswith("  ")]
                assert installed["grant_refresh_command"] in commands
                assert installed["grant_restart_command"] in commands
                assert installed["oats_renew_restart_command"] in commands
                payload = tmp_path / "document with space.json"
                payload.write_text(json.dumps(dict(slug="grant-install", title="Grant install", body="first")))
                denied = subprocess.run(
                    ["aw", "folio", "create", "--body-file", str(payload)], cwd=instance,
                    env=grant_env, text=True, capture_output=True, timeout=30,
                )
                assert denied.returncode != 0 and "app_tool_denied" in denied.stderr
                # Follow the machine-readable action; never modify the old grant.
                action = installed["grant_refresh_command"]
                assert action[0] == "aw" and action[-1] == "<new-grant-home>"
                action[-1] = str(replacement_home)
                ttl_index = action.index("--ttl") + 1
                assert action[ttl_index] == "<ttl>"
                action[ttl_index] = "15m"
                replacement = _run_aw_json(aw_workspace, *action[1:])
                assert replacement["grant_id"] != minted["grant_id"]
                assert replacement["custody_socket_path"] == minted["custody_socket_path"]
                expires = datetime.fromisoformat(replacement["expires_at"].replace("Z", "+00:00"))
                assert timedelta(0) < expires - datetime.now(UTC) <= timedelta(minutes=15)
                assert "folio" in {app["app_id"] for app in replacement["apps"]}
                grant = AWWorkspace(path=instance, env=dict(grant.env, AWEB_IDENTITY_HOME=str(replacement_home)))
                # Follow the printed shell instructions, replacing the WHOLE
                # quoted placeholder and preserving the spaced path argument.
                restart_template = next(
                    line.strip() for line in updated.stdout.splitlines()
                    if line.startswith("  ") and shlex.split(line.strip()) == installed["grant_restart_command"]
                )
                assert "including its surrounding quotes" in updated.stdout
                restart_shell = restart_template.replace(
                    shlex.quote("AWEB_IDENTITY_HOME=<new-grant-home>"),
                    shlex.quote(f"AWEB_IDENTITY_HOME={replacement_home}"),
                ).replace(
                    shlex.quote("<agent-command>"),
                    shlex.join(["aw", "--json", "folio", "create", "--body-file", str(payload)]),
                )
                launched = subprocess.run(
                    ["sh", "-c", restart_shell], cwd=instance, env=grant_env,
                    text=True, capture_output=True, timeout=30,
                )
                assert launched.returncode == 0, launched.stderr
                created = json.loads(launched.stdout)
                # JSON uses argument elements, never a joined command string.
                restart_argv = [installed["grant_restart_command"][0],
                                f"AWEB_IDENTITY_HOME={replacement_home}",
                                "aw", "--json", "folio", "show", "--slug", "grant-install"]
                resumed = subprocess.run(
                    restart_argv, cwd=instance, env=grant_env,
                    text=True, capture_output=True, timeout=30,
                )
                assert resumed.returncode == 0, resumed.stderr
                assert json.loads(resumed.stdout)["body"] == "first"
                assert created["slug"] == "grant-install" and created["body"] == "first"
                body = tmp_path / "append.md"
                body.write_text("second\n")
                appended = _run_aw_json(grant, "folio", "append", "--slug", "grant-install", "--body-file", str(body), "--json=true")
                assert appended["current_version"] == 2
                shown = _run_aw_json(grant, "folio", "show", "--slug", "grant-install", "--json=false")
                assert shown["body"] == "second\n" and shown["latest"]["created_by_did_key"] == team.did_key
                _run_aw(aw_workspace, "id", "grant", "revoke", minted["grant_id"])
                active = _run_aw_json(aw_workspace, "plugin", "update", "folio")
                assert active["active_grants"] == 1  # revoked grants are excluded
                _run_aw(aw_workspace, "id", "grant", "revoke", replacement["grant_id"])
                inactive = _run_aw_json(aw_workspace, "plugin", "update", "folio")
                assert inactive["active_grants"] == 0
                quiet = _run_aw(aw_workspace, "--json=false", "plugin", "update", "folio")
                assert "active grant" not in quiet.stdout
                assert not (instance / ".aw").exists()
                assert not (replacement_home / "signing.key").exists()
                assert before_material == {
                    p.name: hashlib.sha256(p.read_bytes()).digest()
                    for p in before_home.iterdir() if p.is_file()
                }
            finally:
                custody.terminate()
                try:
                    custody.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    custody.kill()
                    custody.wait(timeout=10)
    # The advisory read must not turn a completed install into a failure when
    # the real coordination server is down, nor report an unknown count as zero.
    offline = _run_aw_json(aw_workspace, "plugin", "update", "folio")
    assert offline["approved"] and offline["grant_check_error"] == "unavailable"
    assert "active_grants" not in offline


def test_document_endpoints_versions_raw_utf8_and_attribution(
    folio: RunningFolio,
    aw_workspace: AWWorkspace,
    tmp_path: Path,
) -> None:
    team = _provision_team(aw_workspace)

    created = _create_document(folio, team, slug="handoff", title="Handoff", body="first")
    assert created["slug"] == "handoff"
    assert created["body"] == "first"
    assert created["current_version"] == 1
    assert created["latest"]["created_by_did_key"] == team.did_key
    assert created["latest"]["created_by_alias"] == team.alias
    assert created["latest"]["certificate_id"] == team.certificate_id

    listed = _list_documents(folio, team)
    assert [(item["slug"], item["current_version"]) for item in listed] == [("handoff", 1)]

    fetched = _get_document(folio, team, "handoff")
    assert fetched["body"] == "first"

    appended = _append_version(folio, team, slug="handoff", body="second plain text\nnot json", tmp_path=tmp_path)
    assert appended["body"] == "second plain text\nnot json"
    assert appended["current_version"] == 2
    assert appended["latest"]["created_by_did_key"] == team.did_key
    assert appended["latest"]["created_by_alias"] == team.alias
    assert appended["latest"]["certificate_id"] == team.certificate_id

    assert _get_billing(folio, team) == {
        "team_id": team.team_id,
        "usage": {"documents": 1, "max_versions_per_doc": 2},
    }

    versions = _list_versions(folio, team, "handoff")
    assert [item["version_number"] for item in versions] == [2, 1]
    assert all(item["body"] is None for item in versions)
    assert all(item["created_by_did_key"] == team.did_key for item in versions)
    assert all(item["created_by_alias"] == team.alias for item in versions)
    assert all(item["certificate_id"] == team.certificate_id for item in versions)

    bad_body = tmp_path / "invalid-utf8.bin"
    bad_body.write_bytes(b"\xff")
    bad = _aw_request(team, "POST", f"{folio.origin}/v1/documents/handoff/versions", body_file=bad_body)
    _assert_aw_status(bad, 400, context="append invalid UTF-8")


def test_team_scoping_and_body_named_team_cannot_bypass_certificate_scope(
    folio: RunningFolio,
    aw_workspace_factory: Callable[[str], AWWorkspace],
) -> None:
    first = _provision_team(aw_workspace_factory("first"), alias="alice")
    second = _provision_team(aw_workspace_factory("second"), alias="bob")
    _create_document(folio, first, slug="secret", title="Secret", body="first team only")

    assert _list_documents(folio, second) == []
    second_read = _aw_request(second, "GET", f"{folio.origin}/v1/documents/secret")
    _assert_aw_status(second_read, 404, context="second team reads first team document")
    second_append = _aw_request(second, "POST", f"{folio.origin}/v1/documents/secret/versions", body="oops")
    _assert_aw_status(second_append, 404, context="second team appends first team document")

    payload = json.dumps(
        {"team_id": first.team_id, "slug": "intruder", "title": "Intruder", "body": "body-named team"},
        separators=(",", ":"),
    )
    created_by_second = _aw_json(
        _aw_request(second, "POST", f"{folio.origin}/v1/documents", body=payload),
        context="body-named team create",
    )
    assert created_by_second["slug"] == "intruder"
    assert _get_document(folio, second, "intruder")["body"] == "body-named team"
    first_intruder = _aw_request(first, "GET", f"{folio.origin}/v1/documents/intruder")
    _assert_aw_status(first_intruder, 404, context="body-named team did not write first team")


def test_revoked_certificate_fails_after_awid_revocation_cache_refresh(
    folio: RunningFolio,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    assert _list_documents(folio, team) == []

    _run_aw(
        aw_workspace,
        "id",
        "team",
        "remove-member",
        "--namespace",
        team.namespace,
        "--team",
        team.team,
        "--member",
        team.address,
        "--registry",
        AWID_URL,
    )
    time.sleep(2.2)
    revoked = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
    _assert_aw_status(revoked, 401, context="revoked certificate")


def test_awid_unavailable_honors_cache_then_fails_closed(
    folio: RunningFolio,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    assert _list_documents(folio, team) == []

    # Killed rather than stopped: a graceful stop can outlast the 2 s cache TTL
    # under load, which would expire the facts before the cached request.
    _compose("kill", "awid")
    try:
        cached = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
        assert _assert_aw_success(cached, context="cached request while awid stopped").strip() == "[]"

        time.sleep(2.2)
        expired = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
        _assert_aw_status(expired, 503, context="cache expired while awid stopped")
    finally:
        _compose("start", "awid")
        _wait_http_ok(f"{AWID_URL}/health", timeout_seconds=60.0)


def _replay_headers(captured: CapturedRequest) -> dict[str, str]:
    return {
        key: value
        for key, value in captured.headers.items()
        if key.lower() not in {"host", "content-length", "connection", "accept-encoding"}
    }


def test_replay_negatives_reject_path_method_and_audience(
    folio: RunningFolio,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    original = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
    assert _assert_aw_success(original, context="original signed request").strip() == "[]"
    captured = folio.last_request
    headers = _replay_headers(captured)

    path_replay = httpx.request(
        captured.method,
        f"{folio.origin}/v1/documents/replayed",
        headers=headers,
        content=captured.body,
        timeout=10.0,
    )
    assert path_replay.status_code == 401, path_replay.text

    method_replay = httpx.request(
        "POST",
        f"{folio.origin}{captured.path}",
        headers=headers,
        content=captured.body,
        timeout=10.0,
    )
    assert method_replay.status_code == 401, method_replay.text

    wrong_aud = _aw_request(team, "GET", f"{folio.backend_origin}/v1/documents")
    _assert_aw_status(wrong_aud, 401, context="signed audience for backend host")


def test_real_aw_usage_is_measured_not_capped(
    folio: RunningFolio, aw_workspace: AWWorkspace, tmp_path: Path
) -> None:
    team = _provision_team(aw_workspace)

    for index in range(4):
        created = _create_document(
            folio,
            team,
            slug=f"note-{index}",
            title=f"Note {index}",
            body="hello",
        )
        assert created["slug"] == f"note-{index}"
    for version in range(2, 52):
        appended = _append_version(folio, team, slug="note-0", body=f"v{version}", tmp_path=tmp_path)
        assert appended["current_version"] == version

    assert _get_billing(folio, team) == {
        "team_id": team.team_id,
        "usage": {"documents": 4, "max_versions_per_doc": 51},
    }
