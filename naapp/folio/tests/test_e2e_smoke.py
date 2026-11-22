from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from aweb_naapp_testing import deployment
from aweb_naapp_testing.deployment import (
    AWWorkspace,
    CapturedRequest,
    E2ETeam,
    RunningApp,
    compose,
    configure_app_client,
    connect_team_server,
    coordination_listener,
    e2e_stack,
    grant_install_admin,
    install_app,
    provision_team,
    publish_team_server,
    running_app,
    running_coordination_server,
    wait_http_ok,
)

pytestmark = pytest.mark.e2e

STACK = e2e_stack(os.environ, project="folio-e2e", database="folio")
AWID_URL = STACK.awid_url
# Same-operator credential shared with the e2e awid service (docker-compose.e2e.yml).
AWID_SERVICE_TOKEN = os.environ.get(
    "FOLIO_E2E_AWID_SERVICE_TOKEN", "folio-e2e-awid-service-token-0123456789abcdef"
)
POSTGRES_URL = STACK.postgres_url

# The names Folio's e2e modules import for a deployment and its aw calls.
RunningFolio = RunningApp
_run_aw = deployment.run_aw
_run_aw_json = deployment.run_aw_json
_aw_request = deployment.aw_request
_assert_aw_success = deployment.assert_aw_success
_assert_aw_status = deployment.assert_aw_status
_aw_json = deployment.aw_json


def _require_e2e_enabled() -> None:
    if os.environ.get("FOLIO_E2E") != "1":
        pytest.skip("set FOLIO_E2E=1 or run `make e2e` to execute docker-backed e2e tests")


@contextmanager
def _running_folio(
    *,
    awid_service_token: str | None,
    tls_dir: Path,
    app_id: str = "folio",
) -> Iterator[RunningFolio]:
    """Folio behind TLS on this host."""
    _require_e2e_enabled()
    wait_http_ok(f"{AWID_URL}/health")

    def settings(origin: str) -> dict[str, str]:
        values = {
            "FOLIO_DATABASE_URL": POSTGRES_URL,
            "FOLIO_AWID_REGISTRY_URL": AWID_URL,
            "FOLIO_AUTH_CACHE_TTL_SECONDS": "2",
            "FOLIO_PUBLIC_ORIGIN": origin,
            "FOLIO_APP_ID": app_id,
        }
        if awid_service_token is not None:
            values["FOLIO_AWID_SERVICE_TOKEN"] = awid_service_token
        return values

    with running_app(
        name="folio",
        factory="folio.api:create_app",
        env_for=settings,
        drop_env=("FOLIO_AWID_SERVICE_TOKEN",),
        tls_dir=tls_dir,
    ) as app:
        yield app


@pytest.fixture(scope="module")
def folio(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningFolio]:
    with _installed_deployment(tmp_path_factory.mktemp("folio-e2e"), AWID_SERVICE_TOKEN) as running:
        yield running


@pytest.fixture(scope="module")
def folio_without_awid_service_token(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningFolio]:
    with _installed_deployment(tmp_path_factory.mktemp("folio-private-e2e"), None) as running:
        yield running


@contextmanager
def _installed_deployment(tmp_path: Path, service_token: str | None) -> Iterator[RunningFolio]:
    """Folio plus the coordination server its teams install it through."""
    with (
        coordination_listener() as (listener, server_origin),
        _running_folio(
            awid_service_token=service_token,
            tls_dir=tmp_path / "tls",
            app_id="folio-e2e",
        ) as running,
    ):
        assert running.ca_file is not None
        with running_coordination_server(
            tmp_path,
            listener=listener,
            stack=STACK,
            awid_service_token=AWID_SERVICE_TOKEN,
            app_origin=running.origin,
            ca_file=running.ca_file,
        ) as server:
            yield replace(running, server=server)


@pytest.fixture(scope="module")
def folio_origin(folio: RunningFolio) -> str:
    return folio.origin


@pytest.fixture()
def aw_workspace_factory(tmp_path: Path) -> Callable[[str], AWWorkspace]:
    _require_e2e_enabled()
    return deployment.aw_workspace_factory(tmp_path, awid_url=AWID_URL)


@pytest.fixture()
def aw_workspace(aw_workspace_factory: Callable[[str], AWWorkspace]) -> AWWorkspace:
    return aw_workspace_factory("primary")


def _provision_team(
    workspace: AWWorkspace, *, alias: str = "alice", folio: RunningFolio | None = None,
) -> E2ETeam:
    """A new team with ``alias`` as its member; with ``folio``, the team also
    installs that deployment through its coordination server."""
    team = provision_team(workspace, awid_url=AWID_URL, namespace_prefix="folio", alias=alias)
    if folio is not None:
        connect_team_server(team, folio, awid_url=AWID_URL)
        install_app(team, folio)
    return team


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
        assert body["status"] == "ok" and body["service"] == folio.app_id, body
        assert "git_sha" in body["build"], body
    checks = httpx.get(f"{folio.origin}/health", timeout=10.0).json()["checks"]
    assert checks == {"database": "ok", "outbox": "ok"}, checks


def test_no_envelope_fails_closed(folio_origin: str) -> None:
    response = httpx.get(f"{folio_origin}/v1/documents", timeout=10.0)
    assert response.status_code == 401, response.text


def test_manifest_catalog_is_public_and_variants_byte_stable(folio: RunningFolio) -> None:
    from aweb_naapp.manifest import canonical_bytes
    from manifest_config import served_manifest

    # Catalog discovery is public and pins the deployment's filled v2 bytes.
    catalog = httpx.get(f"{folio.origin}/.well-known/aweb-app-versions.json", timeout=10.0)
    assert catalog.status_code == 200, catalog.text
    variant = catalog.json()["variants"][0]
    assert catalog.json()["app_id"] == folio.app_id
    assert variant["manifest_version"] == 2
    assert variant["url"] == "/manifests/v2.json"
    response = httpx.get(f"{folio.origin}{variant['url']}", timeout=10.0)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    # The real server fills the declared kid from its configured key once at
    # startup, and both discovery paths serve those exact deployment bytes.
    expected = served_manifest(folio.origin)
    expected["app"]["id"] = folio.app_id
    assert response.content == canonical_bytes(expected)
    assert variant["digest"] == "sha256:" + hashlib.sha256(response.content).hexdigest()
    assert httpx.get(f"{folio.origin}/aweb-app.json", timeout=10.0).content == response.content
    again = httpx.get(f"{folio.origin}{variant['url']}", timeout=10.0)
    assert again.content == response.content
    assert httpx.get(f"{folio.origin}/.well-known/aweb-app.json", timeout=10.0).status_code == 404


def test_real_aw_team_auth_smoke(folio: RunningFolio, aw_workspace: AWWorkspace) -> None:
    team = _provision_team(aw_workspace, folio=folio)
    result = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
    assert _assert_aw_success(result, context="list documents smoke").strip() == "[]"


def test_local_member_installs_folio_without_global_identity_metadata(
    folio: RunningFolio, aw_workspace: AWWorkspace, tmp_path: Path,
) -> None:
    controller = _provision_team(aw_workspace)
    assert folio.server is not None
    aw_workspace.env["AWEB_URL"] = folio.server.origin
    invite = _run_aw_json(
        aw_workspace, "id", "team", "invite", "--namespace", controller.namespace,
        "--team", controller.team, "--member-local",
    )
    member_path = tmp_path / "local-member"
    member_path.mkdir()
    # A same-machine controller invite uses the real controller and AWID. The
    # member owns a fresh signing key and certificate, with no global metadata.
    workspace = AWWorkspace(path=member_path, env=dict(aw_workspace.env))
    configure_app_client(workspace, folio)
    _run_aw(workspace, "id", "team", "accept-invite", invite["token"], "--local", "--name", "bob")
    assert not (member_path / ".aw" / "identity.yaml").exists()
    assert (member_path / ".aw" / "signing.key").is_file()
    _run_aw(
        workspace,
        "workspace",
        "connect",
        "--service",
        folio.server.origin,
        "--team",
        controller.team_id,
    )
    cert = _run_aw_json(workspace, "id", "cert", "show")
    member = replace(
        controller,
        workspace=workspace,
        alias="bob",
        address="",
        did_key=str(cert["member_did_key"]),
        certificate_id=str(cert["certificate_id"]),
    )
    publish_team_server(controller, folio.server.origin, awid_url=AWID_URL)
    grant_install_admin(member, folio.server)
    installed = _run_aw_json(workspace, "plugin", "install", folio.origin)
    assert installed["approved"], installed
    receipt = _aw_json(
        _aw_request(
            member, "GET", folio.server.origin + "/v1/apps/installed?team_id=" + member.team_id
        ),
        context="local member installation",
    )
    assert any(
        app["app_id"] == folio.app_id
        and app["state"] == "active"
        and app["installation_id"]
        and app["digest"]
        and app["origin_verified"]
        for app in receipt["apps"]
    ), receipt
    result = _aw_request(member, "GET", folio.origin + "/v1/documents")
    assert _assert_aw_success(result, context="local member Folio tools").strip() == "[]"


def test_private_team_member_authenticates_without_the_awid_service_token(
    folio_without_awid_service_token: RunningFolio, aw_workspace: AWWorkspace
) -> None:
    # Without a service token Folio checks the member's certificate through
    # AWID's per-certificate status, which a private team's members can use too.
    team = _provision_team(aw_workspace, folio=folio_without_awid_service_token)
    result = _aw_request(team, "GET", f"{folio_without_awid_service_token.origin}/v1/documents")
    assert _assert_aw_success(result, context="private team without service token").strip() == "[]"


def test_install_after_mint_uses_replacement_grant(
    aw_workspace: AWWorkspace, tmp_path: Path,
) -> None:
    team = _provision_team(aw_workspace)
    resident_home = aw_workspace.path / ".aw"
    before_home = tmp_path / "before-install"
    replacement_home = tmp_path / "after-install"
    instance = tmp_path / "instance"
    instance.mkdir()
    # A reachable TLS deployment has its own identity, never the hosted id.
    app_id = "folio-install"
    with (
        coordination_listener() as (listener, origin),
        _running_folio(
            awid_service_token=AWID_SERVICE_TOKEN,
            tls_dir=tmp_path / "tls",
            app_id=app_id,
        ) as folio,
    ):
        assert folio.ca_file is not None
        with running_coordination_server(
            tmp_path,
            listener=listener,
            stack=STACK,
            awid_service_token=AWID_SERVICE_TOKEN,
            app_origin=folio.origin,
            ca_file=folio.ca_file,
        ) as server:
            aw_workspace.env["AWEB_URL"] = origin
            configure_app_client(aw_workspace, folio)
            _run_aw(
                aw_workspace, "workspace", "connect", "--service", origin, "--team", team.team_id
            )
            publish_team_server(team, origin, awid_url=AWID_URL)
            grant_install_admin(team, server)
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
                    updated = _run_aw(aw_workspace, "--json=false", "plugin", "update", app_id)
                    commands = [shlex.split(line.strip()) for line in updated.stdout.splitlines()
                                if line.startswith("  ")]
                    assert installed["grant_refresh_command"] in commands
                    assert installed["grant_restart_command"] in commands
                    assert installed["oats_renew_restart_command"] in commands
                    payload = tmp_path / "document with space.json"
                    payload.write_text(json.dumps(dict(slug="grant-install", title="Grant install", body="first")))
                    denied = subprocess.run(
                        ["aw", app_id, "create", "--body-file", str(payload)], cwd=instance,
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
                    assert app_id in {app["app_id"] for app in replacement["apps"]}
                    grant = AWWorkspace(path=instance, env=dict(grant.env, AWEB_IDENTITY_HOME=str(replacement_home)))
                    # Follow the printed shell instructions, replacing the WHOLE
                    # quoted placeholder and preserving the spaced path argument.
                    restart_template = next(
                        line.strip() for line in updated.stdout.splitlines()
                        if line.startswith("  ") and shlex.split(line.strip()) == installed["grant_restart_command"]
                    )
                    restart_shell = restart_template.replace(
                        shlex.quote("AWEB_IDENTITY_HOME=<new-grant-home>"),
                        shlex.quote(f"AWEB_IDENTITY_HOME={replacement_home}"),
                    ).replace(
                        shlex.quote("<agent-command>"),
                        shlex.join(["aw", "--json", app_id, "create", "--body-file", str(payload)]),
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
                                    "aw", "--json", app_id, "show", "--slug", "grant-install"]
                    resumed = subprocess.run(
                        restart_argv, cwd=instance, env=grant_env,
                        text=True, capture_output=True, timeout=30,
                    )
                    assert resumed.returncode == 0, resumed.stderr
                    assert json.loads(resumed.stdout)["body"] == "first"
                    assert created["slug"] == "grant-install" and created["body"] == "first"
                    body = tmp_path / "append.md"
                    body.write_text("second\n")
                    appended = _run_aw_json(grant, app_id, "append", "--slug", "grant-install", "--body-file", str(body), "--json=true")
                    assert appended["current_version"] == 2
                    shown = _run_aw_json(grant, app_id, "show", "--slug", "grant-install", "--json=false")
                    assert shown["body"] == "second\n" and shown["latest"]["created_by_did_key"] == team.did_key
                    _run_aw(aw_workspace, "id", "grant", "revoke", minted["grant_id"])
                    active = _run_aw_json(aw_workspace, "plugin", "update", app_id)
                    assert active["active_grants"] == 1  # revoked grants are excluded
                    _run_aw(aw_workspace, "id", "grant", "revoke", replacement["grant_id"])
                    inactive = _run_aw_json(aw_workspace, "plugin", "update", app_id)
                    assert inactive["active_grants"] == 0
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


def test_document_endpoints_versions_raw_utf8_and_attribution(
    folio: RunningFolio,
    aw_workspace: AWWorkspace,
    tmp_path: Path,
) -> None:
    team = _provision_team(aw_workspace, folio=folio)

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
    first = _provision_team(aw_workspace_factory("first"), folio=folio, alias="alice")
    second = _provision_team(aw_workspace_factory("second"), folio=folio, alias="bob")
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
    team = _provision_team(aw_workspace, folio=folio)
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
    team = _provision_team(aw_workspace, folio=folio)
    assert _list_documents(folio, team) == []

    # Killed rather than stopped: a graceful stop can outlast the 2 s cache TTL
    # under load, which would expire the facts before the cached request.
    compose(STACK, "kill", "awid")
    try:
        cached = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
        assert _assert_aw_success(cached, context="cached request while awid stopped").strip() == "[]"

        time.sleep(2.2)
        expired = _aw_request(team, "GET", f"{folio.origin}/v1/documents")
        _assert_aw_status(expired, 503, context="cache expired while awid stopped")
    finally:
        compose(STACK, "start", "awid")
        wait_http_ok(f"{AWID_URL}/health", timeout_seconds=60.0)


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
    team = _provision_team(aw_workspace, folio=folio)
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
    team = _provision_team(aw_workspace, folio=folio)

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
