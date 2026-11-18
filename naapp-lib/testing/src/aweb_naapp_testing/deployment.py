"""A naapp deployed for an end-to-end test: the app, a team's coordination
server and a team that installed the app through the real ``aw`` binary.

The docker-compose stack ``make e2e`` brings up holds AWID, Postgres and Redis.
The app runs from this checkout under uvicorn behind a TLS recording proxy,
because the server fetches an app's manifest only over HTTPS. The server runs
from this checkout's locked ``server`` project with its manifest fetcher pinned
to exactly the app's origin. A team installs the app as an operator would:
``aw id team set-server``, ``aweb install-admin grant`` and
``aw plugin install``.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPMethod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from awid.signing import load_signing_key_pem
from nacl.signing import SigningKey

from aweb_naapp_testing.network import local_address, make_certificates

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
# The locked server source environment runs the stack server, not an installed aweb artifact.
STACK_SERVER = REPOSITORY_ROOT / "scripts" / "e2e" / "stack_server.py"
SERVER_PROJECT = REPOSITORY_ROOT / "server"


@dataclass(frozen=True)
class E2EStack:
    host: str
    awid_url: str
    postgres_url: str
    compose: list[str]
    redis_url: str | None = None


def candidate_hostname(project: str, service: str) -> str:
    helper = REPOSITORY_ROOT / "scripts/candidate-network.py"
    return subprocess.check_output(
        [sys.executable, str(helper), "hostname", project, service], text=True
    ).strip()


def e2e_stack(env: Mapping[str, str], *, project: str, database: str) -> E2EStack:
    """The docker-compose stack ``make e2e`` brings up, as the NAAPP_E2E_* names place it.

    ``project`` is the app's default compose project and ``database`` the
    stack's Postgres user, password and database name. Host runs use the
    published ports. A candidate runner joins this stack's network and uses its
    real service endpoints, avoiding Desktop's host port path.
    """
    host = env.get("NAAPP_E2E_HOST", "127.0.0.1")
    project = env.get("NAAPP_E2E_PROJECT", project)
    awid_port = env.get("NAAPP_E2E_AWID_PORT", "18010")
    postgres_port = env.get("NAAPP_E2E_POSTGRES_PORT", "55432")
    container_network = env.get("NAAPP_E2E_CONTAINER_NETWORK") == "1"
    credentials = f"{database}:{database}"
    return E2EStack(
        host=host,
        awid_url=(
            f"http://{candidate_hostname(project, 'awid')}:8010"
            if container_network
            else f"http://{host}:{awid_port}"
        ),
        postgres_url=(
            f"postgresql://{credentials}@{candidate_hostname(project, 'postgres')}:5432/{database}"
            if container_network
            else f"postgresql://{credentials}@{host}:{postgres_port}/{database}"
        ),
        compose=["docker", "compose", "-p", project, "-f", "docker-compose.e2e.yml"],
        redis_url=f"redis://{candidate_hostname(project, 'redis')}:6379/0"
        if container_network
        else None,
    )


def compose(stack: E2EStack, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [*stack.compose, *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "docker compose command failed\n"
            f"cmd: {' '.join([*stack.compose, *args])}\n"
            f"exit: {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}\n"
        )
    return result


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

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook
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
            if key.lower() in {
                "content-length",
                "connection",
                "transfer-encoding",
                "content-encoding",
            }:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(upstream.content)))
        self.end_headers()
        self.wfile.write(upstream.content)
        self.close_connection = True


@dataclass(frozen=True)
class CoordinationServer:
    """A team's coordination server and the environment its operator CLI runs in."""

    origin: str
    env: dict[str, str]


@dataclass(frozen=True)
class RunningApp:
    origin: str
    backend_origin: str
    proxy: RecordingProxy
    app_id: str
    ca_file: Path | None = None
    server: CoordinationServer | None = None

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


def wait_http_ok(url: str, *, timeout_seconds: float = 30.0, ca_file: Path | None = None) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    last_response: tuple[int, str] | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                url,
                timeout=2.0,
                verify=ssl.create_default_context(cafile=str(ca_file)) if ca_file else True,
            )
            if response.status_code < 500:
                return
            last_response = (response.status_code, response.text[:512])
        except Exception as exc:  # pragma: no cover - only used for diagnostics
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for {url}: error={last_error}, response={last_response}")


def run_aw(workspace: AWWorkspace, *args: str) -> subprocess.CompletedProcess[str]:
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


def run_aw_json(workspace: AWWorkspace, *args: str) -> dict[str, Any]:
    result = run_aw(workspace, *args)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"aw command did not emit JSON: {result.stdout}\n{result.stderr}"
        ) from exc
    assert isinstance(payload, dict)
    return payload


def aw_request(
    team: E2ETeam,
    method: HTTPMethod,
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


def assert_aw_success(result: subprocess.CompletedProcess[str], *, context: str) -> str:
    assert result.returncode == 0, (
        f"aw id request failed: {context}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
    )
    return result.stdout


def assert_aw_status(
    result: subprocess.CompletedProcess[str], status: int, *, context: str
) -> None:
    assert result.returncode != 0, (
        f"expected HTTP {status} failure for {context}, got success: {result.stdout}"
    )
    assert f"HTTP {status}" in result.stderr, (
        f"expected HTTP {status} for {context}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}\n"
    )


def aw_json(result: subprocess.CompletedProcess[str], *, context: str) -> Any:
    stdout = assert_aw_success(result, context=context)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON for {context}: {stdout}") from exc


def aw_workspace_env(*, home: Path, awid_url: str) -> dict[str, str]:
    """Environment for a disposable aw workspace, free of the caller's own aw identity
    and config selection."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AW_"))}
    env.update(
        {
            "HOME": str(home),
            "AWEB_URL": "http://127.0.0.1:1",
            "AWID_REGISTRY_URL": awid_url,
            "NO_COLOR": "1",
        }
    )
    return env


def aw_workspace_factory(tmp_path: Path, *, awid_url: str) -> Callable[[str], AWWorkspace]:
    def make(name: str) -> AWWorkspace:
        workspace = tmp_path / name / "workspace"
        home = tmp_path / name / "home"
        workspace.mkdir(parents=True)
        home.mkdir(parents=True)
        return AWWorkspace(path=workspace, env=aw_workspace_env(home=home, awid_url=awid_url))

    return make


def _write_workspace_binding(
    workspace: AWWorkspace, *, team_id: str, alias: str, cert_path: str
) -> None:
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


def provision_team(
    workspace: AWWorkspace,
    *,
    awid_url: str,
    namespace_prefix: str,
    alias: str = "alice",
) -> E2ETeam:
    """A new namespace and team at ``awid_url``, with ``alias`` as its one member,
    bound to ``workspace``. The team has no server and installs nothing."""
    unique = uuid.uuid4().hex[:12]
    namespace = f"{namespace_prefix}-{unique}.test"
    team = "default"
    address = f"{namespace}/{alias}"

    run_aw(
        workspace,
        "id",
        "create",
        "--domain",
        namespace,
        "--name",
        alias,
        "--registry",
        awid_url,
        "--skip-dns-verify",
    )
    run_aw(
        workspace,
        "id",
        "team",
        "create",
        "--namespace",
        namespace,
        "--name",
        team,
        "--registry",
        awid_url,
    )
    add_member = run_aw_json(
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
    fetch_cert = run_aw_json(
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
        awid_url,
    )
    team_id = f"{team}:{namespace}"
    run_aw(workspace, "id", "team", "switch", team_id)
    _write_workspace_binding(
        workspace, team_id=team_id, alias=alias, cert_path=str(fetch_cert["cert_path"])
    )
    cert = run_aw_json(workspace, "id", "cert", "show")
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


def team_signing_key(team: E2ETeam) -> SigningKey:
    """The team controller key ``aw id team create`` stored for ``team``."""
    home = Path(team.workspace.env["HOME"])
    found = sorted(home.rglob(f"team-keys/{team.namespace}/{team.team}.key"))
    assert len(found) == 1, f"expected one team key for {team.team_id} under {home}, found {found}"
    return SigningKey(load_signing_key_pem(found[0].read_bytes()))


@contextmanager
def running_app(
    *,
    name: str,
    factory: str,
    env_for: Callable[[str], Mapping[str, str]],
    drop_env: Sequence[str] = (),
    tls_dir: Path | None = None,
) -> Iterator[RunningApp]:
    """The app's ``factory`` under uvicorn behind a recording proxy.

    ``env_for`` receives the proxy's public origin and returns the app's own
    settings. The app id is the one its served manifest names. With ``tls_dir`` the proxy serves HTTPS on this host's routable
    address with a disposable CA (the real egress guard never permits
    loopback), and every resident client in this process trusts that CA.
    """
    with ExitStack() as setup:
        listener = setup.enter_context(socket.socket())
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        backend_port = listener.getsockname()[1]
        backend_origin = f"http://127.0.0.1:{backend_port}"
        address = "127.0.0.1"
        certificates = None
        if tls_dir is not None:
            address = local_address()
            tls_dir.mkdir()
            certificates = make_certificates(tls_dir, [f"{name}-install.test"], [address])
        proxy = setup.enter_context(RecordingProxy((address, 0), backend_origin))
        if certificates:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(certificates.cert_file, certificates.key_file)
            proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
        proxy_origin = (
            f"{'https' if certificates else 'http'}://{address}:{proxy.server_address[1]}"
        )
        env = os.environ.copy()
        for variable in drop_env:
            env.pop(variable, None)
        env.update(env_for(proxy_origin))
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", factory, "--factory", "--fd", str(listener.fileno())],
            env=env,
            pass_fds=(listener.fileno(),),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listener.close()
        thread = threading.Thread(target=proxy.serve_forever, name=f"{name}-e2e-proxy", daemon=True)
        thread.start()
        setup_error: Exception | None = None
        try:
            ca_file = certificates.ca_file if certificates else None
            with pytest.MonkeyPatch.context() as patch:
                # Only this host's own test listener bypasses the public egress proxy.
                for variable in ("NO_PROXY", "no_proxy"):
                    patch.setenv(
                        variable, ",".join(filter(None, (os.environ.get(variable), address)))
                    )
                if ca_file is not None:
                    # All resident clients trust the disposable deployment's CA.
                    # Keep earlier session deployments trusted when another starts.
                    previous = os.environ.get("SSL_CERT_FILE")
                    bundle = ca_file.with_name("client-ca-bundle.pem")
                    bundle.write_bytes(
                        (Path(previous).read_bytes() if previous else b"") + ca_file.read_bytes()
                    )
                    patch.setenv("SSL_CERT_FILE", str(bundle))
                    patch.setenv("GODEBUG", "x509sslcertoverrideplatform=1")
                try:
                    wait_http_ok(f"{proxy_origin}/health", ca_file=ca_file)
                except Exception as exc:
                    setup_error = exc
                    raise
                manifest = httpx.get(
                    f"{proxy_origin}/aweb-app.json",
                    timeout=10.0,
                    verify=ssl.create_default_context(cafile=str(ca_file)) if ca_file else True,
                )
                manifest.raise_for_status()
                yield RunningApp(
                    origin=proxy_origin,
                    backend_origin=backend_origin,
                    proxy=proxy,
                    app_id=_served_app_id(manifest.json()),
                    ca_file=ca_file,
                )
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
            show_logs = failed or setup_error is not None
            stdout = proc.stdout.read() if show_logs and proc.stdout else ""
            stderr = proc.stderr.read() if show_logs and proc.stderr else ""
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            if show_logs:
                raise RuntimeError(
                    f"uvicorn exited with {proc.returncode}; setup error: {setup_error}\n"
                    f"stdout:\n{stdout}\nstderr:\n{stderr}"
                ) from setup_error


def _served_app_id(manifest: object) -> str:
    """The app id a served manifest names."""
    app = manifest.get("app") if isinstance(manifest, dict) else None
    app_id = app.get("id") if isinstance(app, dict) else None
    if not isinstance(app_id, str) or not app_id:
        raise AssertionError(f"the served manifest names no app id: {manifest!r}")
    return app_id


@contextmanager
def running_coordination_server(
    tmp_path: Path,
    *,
    stack: E2EStack,
    awid_service_token: str,
    app_origin: str,
    ca_file: Path,
) -> Iterator[CoordinationServer]:
    """Real aweb, with the real HTTPS fetcher pinned to this test origin."""
    with ExitStack() as setup:
        listener = setup.enter_context(socket.socket())
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        redis_url = stack.redis_url
        if redis_url is None:
            redis_port = compose(stack, "port", "redis", "6379").stdout.strip().rsplit(":", 1)[1]
            redis_url = f"redis://{stack.host}:{redis_port}/0"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AWEB_", "AW_", "AWID_"))}
        env.update(
            AWEB_DATABASE_URL=stack.postgres_url,
            AWEB_REDIS_URL=redis_url,
            AWEB_PUBLIC_ORIGIN=origin,
            AWID_REGISTRY_URL=stack.awid_url,
            AWID_SERVICE_TOKEN=awid_service_token,
        )
        with (tmp_path / "coordination.log").open("w+") as log:
            proc = subprocess.Popen(
                [
                    "uv",
                    "run",
                    "--offline",
                    "--frozen",
                    "--project",
                    str(SERVER_PROJECT),
                    "python",
                    str(STACK_SERVER),
                    "--app-origin",
                    app_origin,
                    "--ca-file",
                    str(ca_file),
                    "--user-agent",
                    "naapp-install-test/1",
                    "--fd",
                    str(listener.fileno()),
                ],
                env=env,
                stdout=log,
                stderr=log,
                pass_fds=(listener.fileno(),),
            )
            listener.close()
            try:
                wait_http_ok(f"{origin}/health")
                yield CoordinationServer(origin=origin, env=env)
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
                    raise AssertionError(
                        f"coordination server exit {proc.returncode}: {log.read()}"
                    )


def configure_app_client(workspace: AWWorkspace, app: RunningApp) -> None:
    """Lets ``workspace``'s aw reach the app's disposable TLS origin, and every
    other running app's: it trusts the process's bundle of their CAs."""
    assert app.ca_file is not None
    bundle = Path(os.environ["SSL_CERT_FILE"])
    assert app.ca_file.read_bytes() in bundle.read_bytes(), f"{bundle} lacks {app.ca_file}"
    workspace.env["SSL_CERT_FILE"] = str(bundle)
    workspace.env["GODEBUG"] = "x509sslcertoverrideplatform=1"
    for variable in ("NO_PROXY", "no_proxy"):
        workspace.env[variable] = os.environ.get(variable, "")


def publish_team_server(team: E2ETeam, origin: str, *, awid_url: str) -> None:
    published = run_aw_json(
        team.workspace,
        "id",
        "team",
        "set-server",
        "--team",
        team.team,
        "--namespace",
        team.namespace,
        "--url",
        origin,
        "--registry",
        awid_url,
    )
    assert published["status"] == "published" and published["server_url"] == origin


def grant_install_admin(team: E2ETeam, server: CoordinationServer) -> None:
    started = time.monotonic()
    try:
        operator = subprocess.run(
            [
                "uv",
                "run",
                "--offline",
                "--frozen",
                "--project",
                str(SERVER_PROJECT),
                "aweb",
                "install-admin",
                "grant",
                "--team-id",
                team.team_id,
                "--principal-did",
                team.did_key,
                "--role",
                "owner",
            ],
            env=server.env,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        # TimeoutExpired retains bytes even when run uses text=True.
        stdout = (exc.stdout or b"").decode(errors="replace")
        stderr = (exc.stderr or b"").decode(errors="replace")
        raise AssertionError(
            f"install-admin grant timed out after {elapsed:.2f}s\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from exc
    assert operator.returncode == 0, operator.stdout + operator.stderr


def connect_team_server(team: E2ETeam, app: RunningApp, *, awid_url: str) -> None:
    """Connects ``team`` to the deployment's server, publishes that server as the
    team's and makes the member an install admin: everything an install needs."""
    assert app.server is not None
    team.workspace.env["AWEB_URL"] = app.server.origin
    configure_app_client(team.workspace, app)
    run_aw(
        team.workspace,
        "workspace",
        "connect",
        "--service",
        app.server.origin,
        "--team",
        team.team_id,
    )
    publish_team_server(team, app.server.origin, awid_url=awid_url)
    grant_install_admin(team, app.server)


def install_app(
    team: E2ETeam, app: RunningApp, *, grant_scopes: Sequence[str] = ()
) -> dict[str, Any]:
    """Installs the app for ``team`` through ``aw plugin install`` and checks the
    server reports it active; ``grant_scopes`` narrows the grant."""
    assert app.server is not None
    args = ["plugin", "install", app.origin]
    for scope in grant_scopes:
        args.extend(["--grant-scope", scope])
    installed = run_aw_json(team.workspace, *args)
    assert installed["approved"], installed
    apps = aw_json(
        aw_request(
            team, HTTPMethod.GET, app.server.origin + "/v1/apps/installed?team_id=" + team.team_id
        ),
        context=f"installed {app.app_id}",
    )
    assert any(
        entry["app_id"] == app.app_id
        and entry["state"] == "active"
        and entry["origin"] == app.origin
        and entry["installation_id"]
        for entry in apps["apps"]
    ), apps
    return installed


def uninstall_app(team: E2ETeam, app: RunningApp) -> None:
    run_aw(team.workspace, "plugin", "uninstall", app.app_id)
