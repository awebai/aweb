from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.e2e

AWID_URL = os.environ.get("LIBRARY_E2E_AWID_URL", "http://127.0.0.1:18010")
POSTGRES_URL = os.environ.get(
    "LIBRARY_E2E_DATABASE_URL",
    "postgresql://library:library@127.0.0.1:55432/library",
)
COMPOSE = ["docker", "compose", "-p", "library-e2e", "-f", "docker-compose.e2e.yml"]


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
class RunningLibrary:
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
    if os.environ.get("LIBRARY_E2E") != "1":
        pytest.skip("set LIBRARY_E2E=1 or run `make e2e` to execute docker-backed e2e tests")


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


@pytest.fixture(scope="session")
def library() -> Iterator[RunningLibrary]:
    _require_e2e_enabled()
    _wait_http_ok(f"{AWID_URL}/health")

    backend_port = _free_port()
    proxy_port = _free_port()
    backend_origin = f"http://127.0.0.1:{backend_port}"
    proxy_origin = f"http://127.0.0.1:{proxy_port}"
    env = os.environ.copy()
    env.update(
        {
            "LIBRARY_DATABASE_URL": POSTGRES_URL,
            "LIBRARY_AWID_REGISTRY_URL": AWID_URL,
            "LIBRARY_AUTH_CACHE_TTL_SECONDS": "2",
            "LIBRARY_PUBLIC_ORIGIN": proxy_origin,
        }
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "library.api:create_app",
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
    thread = threading.Thread(target=proxy.serve_forever, name="library-e2e-proxy", daemon=True)
    thread.start()
    try:
        _wait_http_ok(f"{proxy_origin}/health")
        yield RunningLibrary(origin=proxy_origin, backend_origin=backend_origin, proxy=proxy)
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
        if proc.returncode not in (0, -15, -9, None):
            stdout = proc.stdout.read() if proc.stdout else ""
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"uvicorn exited with {proc.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}")


@pytest.fixture(scope="session")
def library_origin(library: RunningLibrary) -> str:
    return library.origin


@pytest.fixture()
def aw_workspace_factory(tmp_path: Path) -> Callable[[str], AWWorkspace]:
    _require_e2e_enabled()

    def make(name: str) -> AWWorkspace:
        workspace = tmp_path / name / "workspace"
        home = tmp_path / name / "home"
        workspace.mkdir(parents=True)
        home.mkdir(parents=True)
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "AWEB_URL": "http://127.0.0.1:1",
                "AWID_REGISTRY_URL": AWID_URL,
                "NO_COLOR": "1",
            }
        )
        return AWWorkspace(path=workspace, env=env)

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
    namespace = f"library-{unique}.test"
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


def test_health_endpoints_are_public(library: RunningLibrary) -> None:
    for path in ("/health", "/live", "/ready"):
        response = httpx.get(f"{library.origin}{path}", timeout=10.0)
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "ok", "service": "library"}


def test_public_blueprint_catalog_needs_no_auth(library: RunningLibrary) -> None:
    # Blueprints are the public catalog.
    blueprints = httpx.get(f"{library.origin}/v1/blueprints", timeout=10.0)
    assert blueprints.status_code == 200, blueprints.text
    assert blueprints.json() == []
    assert httpx.get(f"{library.origin}/v1/blueprints/none", timeout=10.0).status_code == 404


def test_shelf_and_team_routes_without_envelope_fail_closed(library_origin: str) -> None:
    # The shelf is private: shelf reads + team writes require a certificate.
    assert httpx.get(f"{library_origin}/v1/shelf", timeout=10.0).status_code == 401
    assert httpx.get(f"{library_origin}/v1/proposals", timeout=10.0).status_code == 401


def test_manifest_is_public_and_byte_stable(library: RunningLibrary) -> None:
    from library.aweb_manifest import MANIFEST_PATH

    committed = MANIFEST_PATH.read_bytes()
    for path in ("/.well-known/aweb-app.json", "/aweb-app.json"):
        response = httpx.get(f"{library.origin}{path}", timeout=10.0)
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/json")
        assert response.content == committed


def test_real_aw_team_auth_reaches_team_scoped_routes(library: RunningLibrary, aw_workspace: AWWorkspace) -> None:
    team = _provision_team(aw_workspace)
    # Public catalog read with team auth still works (a JSON array; may be non-empty
    # if earlier tests published blueprints into the shared catalog).
    blueprints = _aw_request(team, "GET", f"{library.origin}/v1/blueprints")
    assert isinstance(json.loads(_assert_aw_success(blueprints, context="list blueprints smoke")), list)
    # A valid certificate passes auth: get-binding for an unbound agent is a real
    # 404 (not 401), proving auth + the live endpoint.
    binding = _aw_request(team, "GET", f"{library.origin}/v1/agents/agent-1/profile-binding")
    _assert_aw_status(binding, 404, context="authenticated get-binding for unbound agent")
    # proposals list for a fresh team is an empty list (live, team-scoped).
    proposals = _aw_request(team, "GET", f"{library.origin}/v1/proposals")
    assert _assert_aw_success(proposals, context="list proposals smoke").strip() == "[]"


def test_revoked_certificate_fails_after_awid_revocation_cache_refresh(
    library: RunningLibrary,
    aw_workspace: AWWorkspace,
) -> None:
    team = _provision_team(aw_workspace)
    # Valid certificate authenticates and reaches the live endpoint.
    assert _assert_aw_success(
        _aw_request(team, "GET", f"{library.origin}/v1/proposals"),
        context="valid certificate reaches proposals",
    ).strip() == "[]"

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
    revoked = _aw_request(team, "GET", f"{library.origin}/v1/proposals")
    _assert_aw_status(revoked, 401, context="revoked certificate")
