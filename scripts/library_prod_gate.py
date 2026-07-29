#!/usr/bin/env python3
"""Run the reviewed Library production compatibility gate from an isolated home.

The script prints only sanitized metadata and harness provenance. It never prints raw
responses, auth state, headers, or harness stderr.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

RUNTIMES = ("claude-code", "pi")
REQUIRED_PUBLIC_URL = "https://library.aweb.ai"
REQUIRED_ORIGIN_URL = "https://library-02jf.onrender.com"
REQUIRED_AW_PATH = Path("/opt/homebrew/bin/aw")
REQUIRED_AW_SHA256 = "e546aa12294e61c95d02cd0a69a613b115ea72cc43f7716e193dc4ef342d6815"
REQUIRED_AW_VERSION_OUTPUT = "aw 1.34.0\n  commit: 82d7ca0\n  built:  2026-07-27T20:23:38Z\n"
REQUIRED_CLAUDE_PATH = Path("/opt/homebrew/bin/claude")
REQUIRED_CLAUDE_SHA256 = "8addc857f3fe64d5a0368af9ee50321b50afb4a6918ba3ef018ab84f5dbbe081"
REQUIRED_CLAUDE_MAGIC = bytes.fromhex("cffaedfe")  # 64-bit little-endian Mach-O
REQUIRED_PI_PATH = Path("/opt/homebrew/bin/pi")
REQUIRED_PI_SHA256 = "af302f231437eaf6f37691bce4b34234fcb626bcb5eb3910d4fc3f6519bf78ca"
REQUIRED_NODE_PATH = Path("/opt/homebrew/bin/node")
REQUIRED_NODE_SHA256 = "70851490e028b3d699a8d6d4e1de909af2a989359ae807974c92af9c6580a8e8"
HARNESS_PATH = "/opt/homebrew/bin:/usr/bin:/bin"
HARNESS_ENV_KEYS = ("HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TERM", "SHELL")
IGNORED_AUTH_FILES = (
    "interaction-log.jsonl",
    "channel-delivered-ids.json",
    "chat-delivered-ids.json",
    "chat-delivered-ids.json.lock",
)
PROMPT = (
    "From the project instructions automatically loaded at startup, print only "
    "the first Markdown title and the profile provenance line immediately below it."
)


class GateError(RuntimeError):
    pass


def _https_authority(url: str, *, label: str) -> tuple[str, int, str]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise GateError(f"{label} must be an https origin without path, query, or credentials")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise GateError(f"{label} has an invalid port") from exc
    host = parsed.hostname
    authority_host = f"[{host}]" if ":" in host else host
    return host, port, f"{authority_host}:{port}"


def _resolve_stream_addresses(
    host: str, port: int, *, label: str
) -> tuple[tuple[int, int, int, tuple[Any, ...], str], ...]:
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise GateError(f"failed to resolve {label}") from exc
    addresses: dict[
        tuple[int, tuple[Any, ...]], tuple[int, int, int, tuple[Any, ...], str]
    ] = {}
    for family, socktype, protocol, _, sockaddr in results:
        normalized_ip = str(ipaddress.ip_address(sockaddr[0]))
        key = (family, tuple(sockaddr))
        addresses[key] = (family, socktype, protocol, tuple(sockaddr), normalized_ip)
    if not addresses:
        raise GateError(f"{label} resolved to no stream addresses")
    return tuple(sorted(addresses.values(), key=lambda item: (item[4], item[0])))


class _OriginProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        allowed_authority: str,
        selected_origin: tuple[int, int, int, tuple[Any, ...], str],
        public_ips: frozenset[str],
    ) -> None:
        self.allowed_authority = allowed_authority
        self.selected_origin = selected_origin
        self.public_ips = public_ips
        self._connection_attempts = 0
        self._successful_connections = 0
        self._peer_ip = ""
        self._connection_lock = threading.Lock()
        super().__init__(address, _OriginProxyHandler)

    @property
    def connection_attempts(self) -> int:
        with self._connection_lock:
            return self._connection_attempts

    @property
    def successful_connections(self) -> int:
        with self._connection_lock:
            return self._successful_connections

    @property
    def peer_ip(self) -> str:
        with self._connection_lock:
            return self._peer_ip

    def record_connection_attempt(self) -> None:
        with self._connection_lock:
            self._connection_attempts += 1

    def record_successful_connection(self, peer_ip: str) -> None:
        with self._connection_lock:
            self._successful_connections += 1
            self._peer_ip = peer_ip

    def connect_to_selected_origin(self) -> tuple[socket.socket, str]:
        family, socktype, protocol, sockaddr, selected_ip = self.selected_origin
        upstream = socket.socket(family, socktype, protocol)
        upstream.settimeout(10)
        try:
            upstream.connect(sockaddr)
            peer_ip = str(ipaddress.ip_address(upstream.getpeername()[0]))
            if peer_ip != selected_ip or peer_ip in self.public_ips:
                raise OSError("origin socket peer did not match the selected generated address")
            return upstream, peer_ip
        except OSError:
            upstream.close()
            raise


class _OriginProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _OriginProxyServer = self.server  # type: ignore[assignment]
        server.record_connection_attempt()
        request = b""
        try:
            while b"\r\n\r\n" not in request:
                chunk = self.request.recv(4096)
                if not chunk or len(request) + len(chunk) > 16384:
                    self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    return
                request += chunk
            request_line = request.split(b"\r\n", 1)[0].decode("ascii")
        except (OSError, UnicodeDecodeError):
            return
        parts = request_line.split()
        if len(parts) != 3 or parts[0] != "CONNECT" or parts[1] != server.allowed_authority:
            try:
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return

        try:
            upstream, peer_ip = server.connect_to_selected_origin()
        except OSError:
            try:
                self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return
        with upstream:
            try:
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                server.record_successful_connection(peer_ip)
                self._relay(upstream)
            except OSError:
                return

    def _relay(self, upstream: socket.socket) -> None:
        peers = (self.request, upstream)
        while True:
            readable, _, _ = select.select(peers, (), (), 35)
            if not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = upstream if source is self.request else self.request
                destination.sendall(data)


class OriginConnectTunnel:
    """Route canonical TLS bytes to one captured generated-origin address."""

    def __init__(self, *, canonical_url: str, origin_url: str) -> None:
        public_host, public_port, self._allowed_authority = _https_authority(
            canonical_url, label="canonical public URL"
        )
        origin_host, origin_port, _ = _https_authority(origin_url, label="generated origin URL")
        public_addresses = _resolve_stream_addresses(
            public_host, public_port, label="canonical public URL"
        )
        origin_addresses = _resolve_stream_addresses(
            origin_host, origin_port, label="generated origin URL"
        )
        public_ips = frozenset(item[4] for item in public_addresses)
        origin_ips = frozenset(item[4] for item in origin_addresses)
        if public_ips & origin_ips:
            raise GateError(
                "generated-origin and canonical-public DNS addresses overlap; "
                "origin bypass cannot be proven"
            )
        self._public_ips = public_ips
        self._selected_origin = origin_addresses[0]
        self._server: _OriginProxyServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> OriginConnectTunnel:
        self._server = _OriginProxyServer(
            ("127.0.0.1", 0),
            allowed_authority=self._allowed_authority,
            selected_origin=self._selected_origin,
            public_ips=self._public_ips,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="library-origin-connect-tunnel",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise GateError("origin tunnel is not running")
        host, port = self._server.server_address
        return str(host), int(port)

    @property
    def proxy_url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    @property
    def selected_origin_ip(self) -> str:
        return self._selected_origin[4]

    @property
    def connection_attempts(self) -> int:
        if self._server is None:
            return 0
        return self._server.connection_attempts

    @property
    def successful_connections(self) -> int:
        if self._server is None:
            return 0
        return self._server.successful_connections

    @property
    def peer_ip(self) -> str:
        if self._server is None:
            return ""
        return self._server.peer_ip


def origin_proxy_environment(proxy_url: str) -> dict[str, str]:
    environment = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        environment.pop(key, None)
    environment["HTTPS_PROXY"] = proxy_url
    environment["NO_PROXY"] = ""
    return environment


def validate_relative_paths(paths: list[str]) -> None:
    for value in paths:
        parts = value.split("/")
        invalid = (
            not value
            or value.strip() != value
            or any(unicodedata.category(char) == "Cc" for char in value)
            or "\\" in value
            or value.startswith("/")
            or "://" in value
            or value.startswith("git@")
            or "//" in value
            or value.endswith("/")
            or any(part in {"", ".", ".."} for part in parts)
        )
        if invalid:
            raise GateError("materialize response contains a noncanonical or unsafe managed path")


def ref_from_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(payload, dict):
        raise GateError("materialize response is not a JSON object")
    files = payload.get("home_files")
    if not isinstance(files, list) or not files:
        raise GateError("materialize response has no home_files")
    paths = [str(entry.get("path") or "") for entry in files]
    validate_relative_paths(paths)
    try:
        entry = next(item for item in files if item.get("path") == ".aw/profile/ref.json")
        ref = json.loads(entry["content_utf8"])
    except (StopIteration, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise GateError("materialize response has no valid ref.json") from exc
    return ref, paths


def validate_profile_pin(
    ref: dict[str, Any], *, expected_version: str, expected_digest: str
) -> None:
    if ref.get("profile_ref") != "developer":
        raise GateError("profile_ref is not developer")
    if ref.get("profile_version") != expected_version:
        raise GateError("profile_version does not match the approved gate pin")
    if ref.get("profile_digest") != expected_digest:
        raise GateError("profile_digest does not match the approved gate pin")


def validate_candidate_payload(
    payload: dict[str, Any],
    runtime: str,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    ref, paths = ref_from_payload(payload)
    managed = ref.get("managed_set")
    validate_profile_pin(ref, expected_version=expected_version, expected_digest=expected_digest)
    if ref.get("runtime_kind") != runtime:
        raise GateError(f"candidate runtime_kind does not match {runtime}")
    if not isinstance(managed, list) or not managed or not all(isinstance(p, str) for p in managed):
        raise GateError("candidate managed_set is missing")
    validate_relative_paths(managed)
    if len(paths) != len(set(paths)) or len(managed) != len(set(managed)):
        raise GateError("candidate response contains duplicate managed paths")
    if managed != paths:
        mismatch = next(
            (
                index
                for index, pair in enumerate(zip(managed, paths, strict=False))
                if pair[0] != pair[1]
            ),
            min(len(managed), len(paths)),
        )
        raise GateError(f"candidate managed_set is not positionally identical at index {mismatch}")
    return sanitized_summary("raw-candidate", runtime, ref, len(managed))


def validate_recovery_payload(
    payload: dict[str, Any],
    runtime: str,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    ref, _ = ref_from_payload(payload)
    validate_profile_pin(ref, expected_version=expected_version, expected_digest=expected_digest)
    if "runtime_kind" in ref or "managed_set" in ref:
        raise GateError("rollback fingerprint is not the known pre-fix behavior")
    return sanitized_summary("raw-recovery", runtime, ref, 0)


def validate_materialized_ref(
    path: Path,
    runtime: str,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    try:
        ref = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"strict client did not write a valid ref.json for {runtime}") from exc
    managed = ref.get("managed_set")
    validate_profile_pin(ref, expected_version=expected_version, expected_digest=expected_digest)
    if ref.get("runtime_kind") != runtime:
        raise GateError(f"strict client ref.json mismatch for {runtime}")
    if (
        not isinstance(managed, list)
        or not managed
        or not all(isinstance(p, str) for p in managed)
        or len(managed) != len(set(managed))
    ):
        raise GateError(f"strict client managed_set invalid for {runtime}")
    validate_relative_paths(managed)
    verify_managed_paths(path.parents[2], managed, runtime)
    return sanitized_summary("released-strict-client", runtime, ref, len(managed))


def verify_managed_paths(home: Path, managed: list[str], runtime: str) -> None:
    home_resolved = home.resolve(strict=True)
    for relative in managed:
        requested = home / relative
        try:
            resolved = requested.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise GateError(
                f"strict client managed path requested at {requested} is missing or broken "
                f"for {runtime}"
            ) from exc
        try:
            resolved.relative_to(home_resolved)
        except ValueError as exc:
            raise GateError(
                f"strict client managed path requested at {requested} resolves outside "
                f"generated home {home_resolved}: {resolved}"
            ) from exc


def sanitized_summary(gate: str, runtime: str, ref: dict[str, Any], count: int) -> dict[str, Any]:
    return {
        "gate": gate,
        "runtime_kind": runtime,
        "profile_ref": ref.get("profile_ref"),
        "profile_version": ref.get("profile_version"),
        "source_blueprint_ref": ref.get("source_blueprint_ref"),
        "source_blueprint_version": ref.get("source_blueprint_version"),
        "managed_set_count": count,
    }


def verify_file_artifact(
    path: Path, *, expected_path: Path, expected_sha256: str, label: str
) -> None:
    if path != expected_path:
        raise GateError(f"{label} path must be exactly {expected_path}")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise GateError(f"failed to hash {label}") from exc
    if digest != expected_sha256:
        raise GateError(f"{label} SHA-256 does not match the reviewed artifact")


def verify_native_claude(path: Path) -> None:
    try:
        with path.open("rb") as artifact:
            magic = artifact.read(4)
    except OSError as exc:
        raise GateError("failed to inspect Claude Code executable shape") from exc
    if magic != REQUIRED_CLAUDE_MAGIC:
        raise GateError("Claude Code artifact is not the reviewed native Mach-O executable")


def verify_released_aw(aw_bin: Path) -> None:
    verify_file_artifact(
        aw_bin,
        expected_path=REQUIRED_AW_PATH,
        expected_sha256=REQUIRED_AW_SHA256,
        label="released aw binary",
    )
    try:
        completed = subprocess.run(
            [str(aw_bin), "version"],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("failed to identify the released aw binary") from exc
    if completed.stdout != REQUIRED_AW_VERSION_OUTPUT:
        raise GateError(
            "released aw version/commit/build metadata does not match the reviewed artifact"
        )


def run_checked(
    command: list[str],
    *,
    cwd: Path,
    stdout: Path,
    stderr: Path,
    label: str,
    env: dict[str, str] | None = None,
) -> None:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        completed = subprocess.run(command, cwd=cwd, stdout=out, stderr=err, check=False, env=env)
    if completed.returncode != 0:
        raise GateError(
            f"{label} exited {completed.returncode}; stderr was captured without printing"
        )


def raw_materialize(
    aw_bin: Path,
    source_home: Path,
    public_url: str,
    runtime: str,
    root: Path,
    *,
    origin_tunnel: OriginConnectTunnel | None = None,
) -> dict[str, Any]:
    request = root / f"raw-{runtime}.request.json"
    response = root / f"raw-{runtime}.response.json"
    stderr = root / f"raw-{runtime}.stderr"
    request.write_text(
        json.dumps({"profile_ref": "developer", "runtime_kind": runtime, "target": "local"}) + "\n",
        encoding="utf-8",
    )
    if origin_tunnel is not None and (
        origin_tunnel.connection_attempts != 0 or origin_tunnel.successful_connections != 0
    ):
        raise GateError("origin tunnel must be unused before each functional probe")
    run_checked(
        [
            str(aw_bin),
            "id",
            "request",
            "POST",
            f"{public_url}/v1/materialize",
            "--team-auth",
            "--body-file",
            str(request),
            "--raw",
        ],
        cwd=source_home,
        stdout=response,
        stderr=stderr,
        label=f"raw materialize {runtime}",
        env=(
            origin_proxy_environment(origin_tunnel.proxy_url)
            if origin_tunnel is not None
            else None
        ),
    )
    if stderr.read_text(encoding="utf-8", errors="replace") != "HTTP 200\n":
        raise GateError(f"raw materialize {runtime} did not return exact HTTP 200")
    if origin_tunnel is not None and (
        origin_tunnel.connection_attempts != 1
        or origin_tunnel.successful_connections != 1
        or origin_tunnel.peer_ip != origin_tunnel.selected_origin_ip
    ):
        raise GateError(
            f"raw materialize {runtime} did not traverse exactly one pinned origin socket"
        )
    try:
        return json.loads(response.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateError(f"raw materialize {runtime} returned invalid JSON") from exc


def clone_auth_home(source_home: Path, destination: Path) -> None:
    source_aw = source_home / ".aw"
    if not source_aw.is_dir():
        raise GateError("source home has no .aw directory")
    shutil.copytree(source_aw, destination / ".aw")
    shutil.rmtree(destination / ".aw" / "profile", ignore_errors=True)
    for relative in IGNORED_AUTH_FILES:
        (destination / ".aw" / relative).unlink(missing_ok=True)


def strict_materialize(
    aw_bin: Path,
    home: Path,
    runtime: str,
    root: Path,
    *,
    expected_version: str,
    expected_digest: str,
) -> dict[str, Any]:
    run_checked(
        [
            str(aw_bin),
            "library",
            "materialize",
            "--profile_ref",
            "developer",
            "--runtime_kind",
            runtime,
            "--target",
            "local",
        ],
        cwd=home,
        stdout=root / f"strict-{runtime}.stdout",
        stderr=root / f"strict-{runtime}.stderr",
        label=f"released strict client {runtime}",
    )
    return validate_materialized_ref(
        home / ".aw" / "profile" / "ref.json",
        runtime,
        expected_version=expected_version,
        expected_digest=expected_digest,
    )


def require_recovery_rejection(
    aw_bin: Path, home: Path, runtime: str, root: Path
) -> dict[str, Any]:
    stdout = root / f"recovery-strict-{runtime}.stdout"
    stderr = root / f"recovery-strict-{runtime}.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        completed = subprocess.run(
            [
                str(aw_bin),
                "library",
                "materialize",
                "--profile_ref",
                "developer",
                "--runtime_kind",
                runtime,
                "--target",
                "local",
            ],
            cwd=home,
            stdout=out,
            stderr=err,
            check=False,
        )
    expected_error = (
        f'library materialize response runtime_kind "{runtime}" does not match ref.json ""'
    )
    captured_error = stderr.read_text(encoding="utf-8", errors="replace")
    if completed.returncode != 1 or expected_error not in captured_error:
        raise GateError(
            f"rollback strict client did not produce the expected schema rejection for {runtime}"
        )
    return {
        "gate": "released-strict-client-recovery",
        "runtime_kind": runtime,
        "exit": completed.returncode,
    }


def expected_provenance(ref_path: Path) -> str:
    ref = json.loads(ref_path.read_text(encoding="utf-8"))
    return (
        f"> Profile {ref['profile_ref']} v{ref['profile_version']} · blueprint "
        f"{ref['source_blueprint_ref']} v{ref['source_blueprint_version']}"
    )


def controlled_harness_environment() -> dict[str, str]:
    environment = {key: os.environ[key] for key in HARNESS_ENV_KEYS if key in os.environ}
    environment["PATH"] = HARNESS_PATH
    return environment


def run_harness(
    home: Path,
    runtime: str,
    root: Path,
    claude_bin: Path,
    pi_bin: Path,
    node_bin: Path,
) -> dict[str, Any]:
    if runtime == "claude-code":
        command = [
            str(claude_bin),
            "--print",
            "--no-session-persistence",
            "--tools",
            "",
            "--model",
            "haiku",
            PROMPT,
        ]
    else:
        command = [
            str(node_bin),
            str(pi_bin),
            "--provider",
            "openai-codex",
            "--model",
            "gpt-5.6-sol",
            "--thinking",
            "off",
            "--print",
            "--no-session",
            "--approve",
            "--no-tools",
            "--no-extensions",
            PROMPT,
        ]
    stdout = root / f"harness-{runtime}.stdout"
    stderr = root / f"harness-{runtime}.stderr"
    harness_env = controlled_harness_environment()
    run_checked(
        command,
        cwd=home,
        stdout=stdout,
        stderr=stderr,
        label=f"{runtime} harness",
        env=harness_env,
    )
    lines = [
        line.strip() for line in stdout.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    provenance = expected_provenance(home / ".aw" / "profile" / "ref.json")
    if "# Developer" not in lines or provenance not in lines:
        raise GateError(f"{runtime} harness did not load expected project instructions")
    return {
        "gate": "real-harness",
        "runtime_kind": runtime,
        "exit": 0,
        "title": "# Developer",
        "provenance": provenance,
    }


def run_candidate(args: argparse.Namespace, root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    homes: dict[str, Path] = {}
    for runtime in RUNTIMES:
        with OriginConnectTunnel(
            canonical_url=args.public_url, origin_url=args.origin_url
        ) as origin_tunnel:
            payload = raw_materialize(
                REQUIRED_AW_PATH,
                args.source_home,
                args.public_url,
                runtime,
                root,
                origin_tunnel=origin_tunnel,
            )
            summary = validate_candidate_payload(
                payload,
                runtime,
                expected_version=args.expected_profile_version,
                expected_digest=args.expected_profile_digest,
            )
            summary["gate"] = "raw-candidate-origin"
            summary["transport_route"] = "generated-origin-direct"
            summary["transport_peer_ip"] = origin_tunnel.peer_ip
            summaries.append(summary)
    for runtime in RUNTIMES:
        payload = raw_materialize(
            REQUIRED_AW_PATH, args.source_home, args.public_url, runtime, root
        )
        summary = validate_candidate_payload(
            payload,
            runtime,
            expected_version=args.expected_profile_version,
            expected_digest=args.expected_profile_digest,
        )
        summary["gate"] = "raw-candidate-public"
        summaries.append(summary)
    for runtime in RUNTIMES:
        home = root / f"home-{runtime}"
        home.mkdir()
        clone_auth_home(args.source_home, home)
        summaries.append(
            strict_materialize(
                REQUIRED_AW_PATH,
                home,
                runtime,
                root,
                expected_version=args.expected_profile_version,
                expected_digest=args.expected_profile_digest,
            )
        )
        homes[runtime] = home
    for runtime in RUNTIMES:
        summaries.append(
            run_harness(
                homes[runtime],
                runtime,
                root,
                REQUIRED_CLAUDE_PATH,
                REQUIRED_PI_PATH,
                REQUIRED_NODE_PATH,
            )
        )
    return summaries


def run_recovery(args: argparse.Namespace, root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for runtime in RUNTIMES:
        payload = raw_materialize(
            REQUIRED_AW_PATH, args.source_home, args.public_url, runtime, root
        )
        summaries.append(
            validate_recovery_payload(
                payload,
                runtime,
                expected_version=args.expected_profile_version,
                expected_digest=args.expected_profile_digest,
            )
        )
        home = root / f"home-{runtime}"
        home.mkdir()
        clone_auth_home(args.source_home, home)
        summaries.append(require_recovery_rejection(REQUIRED_AW_PATH, home, runtime, root))
    return summaries


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("candidate", "legacy-aasb"))
    source_home = os.environ.get("AW_SOURCE_HOME")
    p.add_argument("--source-home", type=Path, default=Path(source_home) if source_home else None)
    p.add_argument("--public-url", default=REQUIRED_PUBLIC_URL)
    p.add_argument("--origin-url", default=REQUIRED_ORIGIN_URL)
    p.add_argument(
        "--expected-profile-version",
        default=os.environ.get("EXPECTED_PROFILE_VERSION", ""),
    )
    p.add_argument(
        "--expected-profile-digest",
        default=os.environ.get("EXPECTED_PROFILE_DIGEST", ""),
    )
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.source_home is None or not args.source_home.is_absolute():
            raise GateError("AW_SOURCE_HOME/--source-home must be an absolute path")
        if args.public_url != REQUIRED_PUBLIC_URL:
            raise GateError(f"production public URL must be exactly {REQUIRED_PUBLIC_URL}")
        if args.origin_url != REQUIRED_ORIGIN_URL:
            raise GateError(f"production origin URL must be exactly {REQUIRED_ORIGIN_URL}")
        if not args.expected_profile_version:
            raise GateError("EXPECTED_PROFILE_VERSION/--expected-profile-version is required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_profile_digest):
            raise GateError(
                "EXPECTED_PROFILE_DIGEST/--expected-profile-digest must be sha256-pinned"
            )
        verify_released_aw(REQUIRED_AW_PATH)
        if args.mode == "candidate":
            verify_file_artifact(
                REQUIRED_CLAUDE_PATH,
                expected_path=REQUIRED_CLAUDE_PATH,
                expected_sha256=REQUIRED_CLAUDE_SHA256,
                label="Claude Code binary",
            )
            verify_native_claude(REQUIRED_CLAUDE_PATH)
            verify_file_artifact(
                REQUIRED_PI_PATH,
                expected_path=REQUIRED_PI_PATH,
                expected_sha256=REQUIRED_PI_SHA256,
                label="Pi entry script",
            )
            verify_file_artifact(
                REQUIRED_NODE_PATH,
                expected_path=REQUIRED_NODE_PATH,
                expected_sha256=REQUIRED_NODE_SHA256,
                label="Node interpreter",
            )
        with tempfile.TemporaryDirectory(prefix="library-prod-gate-") as temporary:
            root = Path(temporary)
            summaries = (
                run_candidate(args, root) if args.mode == "candidate" else run_recovery(args, root)
            )
        for summary in summaries:
            print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        print(f"PASS: Library production {args.mode} gate")
        return 0
    except GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
