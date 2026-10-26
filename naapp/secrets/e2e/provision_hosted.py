"""Provision the dedicated hosted HO6 team; never use a customer team.

Public-contract implementation agreed with the hosted owner (5e9902a0).
Credentials, cookies, codes and complete HTTP responses are never diagnostics.
An intent journal makes an uncertain remote side effect refuse on rerun.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import fcntl
import hashlib
import json
import logging
import os
import secrets
import socket
import stat
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from release_environment import PREFIX, _https

OWNER_FILE = PREFIX + "CLOUD_OWNER_LOGIN_FILE"


class ProvisioningError(Exception):
    """A fixed, value-free failure code, never a remote response or exception."""


def private_bytes(path: Path, code: str) -> bytes:
    try:
        if not path.is_absolute():
            raise ValueError
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 65536
            ):
                raise ValueError
            data = source.read(65537)
            if len(data) > 65536:
                raise ValueError
            return data
    except (OSError, ValueError):
        raise ProvisioningError(code) from None


@dataclass(frozen=True)
class OwnerLogin:
    email: str = field(repr=False)
    password: str = field(repr=False)

    @classmethod
    def read(cls, path: Path) -> OwnerLogin:
        code = "owner_login_file_invalid"
        try:
            text = private_bytes(path, code).decode("utf-8")
            if text.startswith("\ufeff"):
                raise ValueError
            lines = text.removesuffix("\n").split("\n")
            if len(lines) != 2 or any(
                not line or line != line.strip() or "\r" in line for line in lines
            ):
                raise ValueError
            return cls(*lines)
        except (ValueError, UnicodeError):
            raise ProvisioningError(code) from None


def atomic_write(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


class StateStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.data: dict[str, Any] = {}
        self._lock: int | None = None

    @property
    def reserved_paths(self) -> tuple[Path, ...]:
        return tuple(
            self.directory / name
            for name in (
                ".controller.lock",
                "controller-state.json",
                "runtime.json",
                "agent-a.access-token",
                "agent-b.access-token",
            )
        )

    def __enter__(self) -> StateStore:
        try:
            if not self.directory.is_absolute():
                raise ValueError
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise ValueError
        except (OSError, ValueError):
            raise ProvisioningError("state_directory_invalid") from None
        try:
            fd = os.open(
                self.directory / ".controller.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                os.close(fd)
                raise ProvisioningError("state_file_invalid")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise ProvisioningError("state_busy") from None
            self._lock = fd
            path = self.directory / "controller-state.json"
            if path.exists() or path.is_symlink():
                self.data = json.loads(private_bytes(path, "state_file_invalid"))
                if not isinstance(self.data, dict) or self.data.get("v") != 1:
                    raise ProvisioningError("state_file_invalid")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_: Any) -> None:
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None

    def save(self) -> None:
        atomic_write(self.directory / "controller-state.json", json.dumps(self.data).encode())

    def begin(self, origin: str) -> bool:
        """Return True only for completed state eligible for refresh."""
        if self.data:
            if self.data.get("origin") != origin:
                raise ProvisioningError("state_origin_mismatch")
            if self.data.get("status") != "ready":
                raise ProvisioningError("provisioning_incomplete")
            return True
        # An unrelated artifact must not be silently adopted or overwritten.
        if any(path.exists() or path.is_symlink() for path in self.reserved_paths[2:]):
            raise ProvisioningError("state_directory_not_empty")
        self.data = {"v": 1, "origin": origin, "status": "in_progress", "step": "start"}
        self.save()
        return False

    def before(self, step: str) -> None:
        self.data.update(status="in_progress", step=step)
        self.save()
        (self.directory / "runtime.json").unlink(missing_ok=True)

    def publish(self) -> dict[str, str]:
        if self.data.get("status") != "ready":
            raise ProvisioningError("outputs_not_ready")
        outputs = {
            PREFIX + "TEAM_ID": self.data["team_id"],
            PREFIX + "MCP_URL": self.data["origin"] + "/mcp/",
        }
        for agent in ("a", "b"):
            path = self.directory / f"agent-{agent}.access-token"
            atomic_write(path, self.data["pairs"][agent]["access_token"].encode())
            outputs[PREFIX + f"AGENT_{agent.upper()}_ID"] = self.data["agents"][agent]["agent_id"]
            outputs[PREFIX + f"AGENT_{agent.upper()}_MCP_TOKEN_FILE"] = str(path)
        atomic_write(self.directory / "runtime.json", json.dumps(outputs).encode())
        return outputs


def text(body: Any, name: str) -> str:
    if not isinstance(body, dict) or not isinstance(body.get(name), str) or not body[name]:
        raise ProvisioningError("response_invalid")
    return body[name]


def public_uuid(body: Any, name: str) -> str:
    value = text(body, name)
    try:
        uuid.UUID(value)
    except ValueError:
        raise ProvisioningError("response_invalid") from None
    return value


def consent_code(location: str, redirect: str, expected_state: str) -> str:
    try:
        parts = urlsplit(location)
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        query = parse_qs(parts.query, keep_blank_values=True)
        if (
            base != redirect
            or parts.fragment
            or set(query) != {"code", "state"}
            or len(query["code"]) != 1
            or not query["code"][0]
            or query["state"] != [expected_state]
        ):
            raise ValueError
        return query["code"][0]
    except (KeyError, ValueError):
        raise ProvisioningError("consent_response_invalid") from None


def identity_from_result(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("isError"):
        raise ProvisioningError("whoami_invalid")
    candidates = [result.get("structuredContent")]
    candidates.extend(
        item.get("text")
        for item in result.get("content", [])
        if isinstance(item, dict) and item.get("type") == "text"
    )
    found = []
    for candidate in candidates:
        try:
            if isinstance(candidate, dict) and "result" in candidate:
                candidate = candidate["result"]
            if isinstance(candidate, str):
                candidate = json.loads(candidate)
            if (
                isinstance(candidate, dict)
                and isinstance(candidate.get("team_id"), str)
                and isinstance(candidate.get("agent_id"), str)
            ):
                found.append(candidate)
        except (ValueError, TypeError):
            continue
    if not found or any(item != found[0] for item in found):
        raise ProvisioningError("whoami_invalid")
    return found[0]


def mcp_client_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers=headers, timeout=timeout, auth=auth, trust_env=False, follow_redirects=False
    )


async def whoami(origin: str, pair: dict[str, Any]) -> dict[str, Any]:
    # Each call has its own bearer transport; no owner cookies or other agent.
    async with streamablehttp_client(
        origin + "/mcp/",
        headers={"Authorization": "Bearer " + text(pair, "access_token")},
        httpx_client_factory=mcp_client_factory,
        timeout=30,
        sse_read_timeout=30,
    ) as (read, write, _):
        async with ClientSession(read, write) as client:
            await client.initialize()
            result = await client.call_tool("whoami", {})
            return identity_from_result(result.model_dump(by_alias=True, exclude_none=True))


async def request(
    client: httpx.AsyncClient, method: str, path: str, status: int, **kwargs: Any
) -> dict:
    response = await client.request(method, path, **kwargs)
    if response.status_code != status:
        raise ProvisioningError("remote_request_refused")
    try:
        body = response.json()
    except ValueError:
        raise ProvisioningError("response_invalid") from None
    if not isinstance(body, dict):
        raise ProvisioningError("response_invalid")
    return body


def token_pair(body: dict) -> dict[str, Any]:
    if (
        text(body, "token_type").lower() != "bearer"
        or text(body, "scope") != "mcp"
        or type(body.get("expires_in")) is not int
        or body["expires_in"] <= 0
    ):
        raise ProvisioningError("token_response_invalid")
    return {
        **{name: text(body, name) for name in ("access_token", "refresh_token")},
        "expires_at": time.time() + body["expires_in"],
    }


async def authorize_agent(
    owner: httpx.AsyncClient, oauth: httpx.AsyncClient, store: StateStore, agent: str, label: str
) -> None:
    origin = store.data["origin"]
    agent_id = store.data["agents"][agent]["agent_id"]
    # Own the exact loopback port before registration. Never follow the redirect.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as callback:
        callback.bind(("127.0.0.1", 0))
        callback.listen(1)
        redirect = f"http://localhost:{callback.getsockname()[1]}/callback"
        store.before("oauth_register_" + agent)
        registered = await request(
            oauth,
            "POST",
            "/oauth/register",
            201,
            json={
                "client_name": f"S19 proof {agent.upper()} {label}",
                "redirect_uris": [redirect],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mcp",
            },
        )
        client_id = text(registered, "client_id")
        store.data["agents"][agent].update(client_id=client_id, redirect_uri=redirect)
        store.save()
        resource = origin + "/mcp/a/" + agent_id
        metadata = await request(
            oauth, "GET", "/.well-known/oauth-protected-resource/mcp/a/" + agent_id, 200
        )
        if metadata.get("resource") != resource:
            raise ProvisioningError("oauth_resource_mismatch")
        verifier = secrets.token_urlsafe(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        state = secrets.token_urlsafe(32)
        store.before("oauth_consent_" + agent)
        approved = await owner.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "scope": "mcp",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "approve": "true",
                "aweb_agent": agent_id,
            },
        )
        if approved.status_code != 303:
            raise ProvisioningError("consent_refused")
        code = consent_code(approved.headers.get("location", ""), redirect, state)
        store.before("oauth_exchange_" + agent)
        pair = token_pair(
            await request(
                oauth,
                "POST",
                "/oauth/token",
                200,
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": redirect,
                    "code_verifier": verifier,
                    "resource": resource,
                },
            )
        )
        store.data["pairs"][agent] = pair
        store.save()


async def bootstrap(
    owner: httpx.AsyncClient, oauth: httpx.AsyncClient, store: StateStore, login: OwnerLogin
) -> None:
    store.before("owner_login")
    signed_in = await request(
        owner, "POST", "/api/v1/login", 200, json={"email": login.email, "password": login.password}
    )
    user = signed_in.get("user")
    if not isinstance(user, dict) or text(user, "email").casefold() != login.email.casefold():
        raise ProvisioningError("owner_identity_mismatch")
    store.data["owner_id"] = public_uuid(user, "id")
    label = uuid.uuid4().hex[:16]
    store.data.update(label=label, agents={}, pairs={})
    store.before("team_create")
    team = await request(
        owner,
        "POST",
        "/api/v1/teams",
        200,
        json={"name": "S19 proof " + label, "slug": "s19-proof-" + label},
    )
    cloud_id, canonical = public_uuid(team, "id"), text(team, "aweb_team_id")
    store.data.update(cloud_team_id=cloud_id, team_id=canonical)
    store.before("role_create")
    role = await request(
        owner,
        "POST",
        "/api/v1/roles",
        200,
        headers={"X-Team-ID": cloud_id},
        json={
            "bundle": {
                "roles": {
                    "s19-proof": {"title": "S19 proof", "playbook_md": "Dedicated S19 test role"}
                },
                "adapters": {},
            }
        },
    )
    role_id = public_uuid(role, "team_roles_id")
    if role.get("team_id") != canonical:
        raise ProvisioningError("role_team_mismatch")
    store.data["role_id"] = role_id
    store.before("role_activate")
    activated = await request(
        owner, "POST", f"/api/v1/roles/{role_id}/activate", 200, headers={"X-Team-ID": cloud_id}
    )
    if activated.get("activated") is not True or activated.get("active_team_roles_id") != role_id:
        raise ProvisioningError("role_activation_invalid")
    for agent in ("a", "b"):
        store.before("agent_create_" + agent)
        created = await request(
            owner,
            "POST",
            "/api/v1/identities/create-permanent-custodial",
            200,
            json={
                "team_id": cloud_id,
                "name": f"s19-proof-{agent}-{label}",
                "human_name": "S19 proof " + agent.upper(),
                "identity_scope": "global",
                "role_name": "s19-proof",
            },
        )
        if (
            created.get("team_id") != cloud_id
            or created.get("created") is not True
            or created.get("custody") != "custodial"
            or created.get("identity_scope") != "global"
        ):
            raise ProvisioningError("agent_creation_invalid")
        # Deliberately do not persist the API key or the complete response.
        store.data["agents"][agent] = {"agent_id": public_uuid(created, "agent_id")}
        store.save()
    if store.data["agents"]["a"]["agent_id"] == store.data["agents"]["b"]["agent_id"]:
        raise ProvisioningError("agents_not_distinct")
    for agent in ("a", "b"):
        await authorize_agent(owner, oauth, store, agent, label)


async def _provision(origin: str, directory: Path, owner_path: Path | None) -> dict[str, str]:
    if not _https(origin, origin=True):
        raise ProvisioningError("cloud_origin_invalid")
    origin = origin.rstrip("/")
    store = StateStore(directory)
    if owner_path is not None and any(
        owner_path.resolve() == path.resolve()
        or (owner_path.exists() and path.exists() and owner_path.samefile(path))
        for path in store.reserved_paths
    ):
        raise ProvisioningError("owner_login_state_conflict")
    with store:
        login = None
        if not store.data:
            if owner_path is None:
                raise ProvisioningError(OWNER_FILE + "_required")
            login = OwnerLogin.read(owner_path)
        refresh = store.begin(origin)
        # Owner cookies never share a client with registration/token or MCP.
        async with (
            httpx.AsyncClient(
                base_url=origin, trust_env=False, follow_redirects=False, timeout=30
            ) as owner,
            httpx.AsyncClient(
                base_url=origin, trust_env=False, follow_redirects=False, timeout=30
            ) as oauth,
        ):
            if refresh:
                for agent in ("a", "b"):
                    current = store.data["pairs"][agent]
                    client_id = text(store.data["agents"][agent], "client_id")
                    store.before("oauth_refresh_" + agent)
                    pair = token_pair(
                        await request(
                            oauth,
                            "POST",
                            "/oauth/token",
                            200,
                            data={
                                "grant_type": "refresh_token",
                                "client_id": client_id,
                                "refresh_token": text(current, "refresh_token"),
                            },
                        )
                    )
                    store.data["pairs"][agent] = pair
                    store.save()
            else:
                assert login is not None
                await bootstrap(owner, oauth, store, login)
            for agent in ("a", "b"):
                store.before("whoami_" + agent)
                identity = await whoami(origin, store.data["pairs"][agent])
                if (
                    identity["team_id"] != store.data["team_id"]
                    or identity["agent_id"] != store.data["agents"][agent]["agent_id"]
                ):
                    raise ProvisioningError("whoami_identity_mismatch")
            store.data.update(status="ready", step="verified")
            store.save()
            return store.publish()


async def provision(origin: str, directory: Path, owner_path: Path | None) -> dict[str, str]:
    __tracebackhide__ = True
    try:
        return await _provision(origin, directory, owner_path)
    except ProvisioningError as error:
        failure = str(error)
    except Exception:
        failure = "provisioning_failed"
    # Raise outside the handlers: no retained inner traceback with credential
    # locals can leak into a consuming S19 pytest failure.
    raise ProvisioningError(failure) from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cloud-origin", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    for name in ("httpx", "httpcore", "mcp"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        owner = os.environ.get(OWNER_FILE)
        asyncio.run(provision(args.cloud_origin, args.state_dir, Path(owner) if owner else None))
    except ProvisioningError as error:
        failure = str(error)
    except Exception:
        # Never serialize SDK/HTTP exceptions, responses, cookies or local paths.
        failure = "provisioning_failed"
    else:
        print("Provisioning outputs ready.")
        return 0
    print("Provisioning refused: " + failure, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
