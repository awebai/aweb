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

AWID_URL = os.environ.get("FOLIO_E2E_AWID_URL", "http://127.0.0.1:18010")
POSTGRES_URL = os.environ.get(
    "FOLIO_E2E_DATABASE_URL",
    "postgresql://folio:folio@127.0.0.1:55432/folio",
)
COMPOSE = ["docker", "compose", "-p", "folio-e2e", "-f", "docker-compose.e2e.yml"]


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


@pytest.fixture(scope="session")
def folio() -> Iterator[RunningFolio]:
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
        if proc.returncode not in (0, -15, -9, None):
            stdout = proc.stdout.read() if proc.stdout else ""
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"uvicorn exited with {proc.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}")


@pytest.fixture(scope="session")
def folio_origin(folio: RunningFolio) -> str:
    return folio.origin


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
        assert response.json() == {"status": "ok", "service": "folio"}


def test_no_envelope_fails_closed(folio_origin: str) -> None:
    response = httpx.get(f"{folio_origin}/v1/documents", timeout=10.0)
    assert response.status_code == 401, response.text


def test_real_aw_team_auth_smoke(folio: RunningFolio, aw_workspace: AWWorkspace) -> None:
    team = _provision_team(aw_workspace)
    result = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
    assert _assert_aw_success(result, context="list documents smoke").strip() == "[]"


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

    billing = _get_billing(folio, team)
    assert billing["team_id"] == team.team_id
    assert billing["tier"] == "free"
    assert billing["caps"]["max_documents"] >= 1
    assert billing["caps"]["max_versions_per_doc"] >= 2
    assert billing["usage"] == {"documents": 1, "max_versions_per_doc": 2}

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

    _compose("stop", "awid")
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


def test_real_aw_free_document_cap_and_billing(folio: RunningFolio, aw_workspace: AWWorkspace) -> None:
    team = _provision_team(aw_workspace)

    for index in range(3):
        created = _create_document(
            folio,
            team,
            slug=f"note-{index}",
            title=f"Note {index}",
            body="hello",
        )
        assert created["slug"] == f"note-{index}"

    billing = _get_billing(folio, team)
    assert billing["team_id"] == team.team_id
    assert billing["tier"] == "free"
    assert billing["caps"] == {"max_documents": 3, "max_versions_per_doc": 50}
    assert billing["usage"] == {"documents": 3, "max_versions_per_doc": 1}

    blocked = _aw_request(
        team,
        "POST",
        f"{folio.origin}/v1/documents",
        body=json.dumps({"slug": "note-3", "title": "Note 3", "body": "blocked"}),
    )
    assert blocked.returncode != 0
    error_text = blocked.stdout + blocked.stderr
    assert "free_tier_limit_exceeded" in error_text
    assert "documents" in error_text
    assert "subscriptions are not yet available" in error_text
