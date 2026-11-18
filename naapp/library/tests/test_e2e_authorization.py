"""Library admits a member only for a team that installed it and granted the
operation's scopes, and only with a certificate the registry published.

Real AWID (the compose stack), a real coordination server and real Library
behind TLS; teams install Library with the real ``aw plugin install``.
"""

from __future__ import annotations

import json
import os
import secrets
import ssl
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import replace
from http import HTTPMethod
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing import Member
from aweb_naapp_testing.deployment import (
    AWWorkspace,
    E2ETeam,
    RunningApp,
    assert_aw_status,
    aw_json,
    aw_request,
    aw_workspace_factory,
    connect_team_server,
    e2e_stack,
    install_app,
    provision_team,
    running_app,
    running_coordination_server,
    team_signing_key,
    uninstall_app,
    wait_http_ok,
)
from test_library_contract_e2e import _blueprint_payload

pytestmark = pytest.mark.e2e

STACK = e2e_stack(os.environ, project="library-e2e", database="library")
AWID_SERVICE_TOKEN = os.environ.get(
    "LIBRARY_E2E_AWID_SERVICE_TOKEN", "library-e2e-awid-service-token-0123456789abcdef"
)
# The grant cache follows the server's freshness window, at most a minute.
GRANT_WINDOW_SECONDS = 75.0


def _require_e2e_enabled() -> None:
    if os.environ.get("LIBRARY_E2E") != "1":
        pytest.skip("set LIBRARY_E2E=1 or run `make e2e` to execute docker-backed e2e tests")


@pytest.fixture(scope="module")
def deployment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningApp]:
    _require_e2e_enabled()
    wait_http_ok(f"{STACK.awid_url}/health")
    directory = tmp_path_factory.mktemp("library-authorization")
    grant_key = directory / "grant-read.hex"
    grant_key.write_text(secrets.token_hex(32))
    grant_key.chmod(0o600)

    def settings(origin: str) -> dict[str, str]:
        return {
            "LIBRARY_DATABASE_URL": STACK.postgres_url,
            "LIBRARY_AWID_REGISTRY_URL": STACK.awid_url,
            "LIBRARY_AWID_SERVICE_TOKEN": AWID_SERVICE_TOKEN,
            "LIBRARY_AUTH_CACHE_TTL_SECONDS": "2",
            "LIBRARY_PUBLIC_ORIGIN": origin,
            "LIBRARY_APP_ID": "library-e2e",
            "LIBRARY_APP_KEY_FILES": json.dumps({"library:grant-read-1": str(grant_key)}),
        }

    with running_app(
        name="library",
        factory="library.api:create_app",
        env_for=settings,
        drop_env=("LIBRARY_AWID_SERVICE_TOKEN", "LIBRARY_APP_KEY_FILES", "LIBRARY_APP_ID"),
        tls_dir=directory / "tls",
    ) as app:
        assert app.ca_file is not None
        with running_coordination_server(
            directory,
            stack=STACK,
            awid_service_token=AWID_SERVICE_TOKEN,
            app_origin=app.origin,
            ca_file=app.ca_file,
        ) as server:
            yield replace(app, server=server)


@pytest.fixture()
def workspaces(tmp_path: Path) -> Callable[[str], AWWorkspace]:
    _require_e2e_enabled()
    return aw_workspace_factory(tmp_path, awid_url=STACK.awid_url)


def _team(workspaces: Callable[[str], AWWorkspace], name: str, app: RunningApp) -> E2ETeam:
    team = provision_team(
        workspaces(name), awid_url=STACK.awid_url, namespace_prefix="library-authz"
    )
    connect_team_server(team, app, awid_url=STACK.awid_url)
    return team


def _publish(team: E2ETeam, app: RunningApp, blueprint_ref: str):
    body = json.dumps(_blueprint_payload(blueprint_ref=blueprint_ref), separators=(",", ":"))
    return aw_request(team, HTTPMethod.POST, f"{app.origin}/v1/blueprints/import", body=body)


def _catalog_has(app: RunningApp, blueprint_ref: str) -> bool:
    response = httpx.get(
        f"{app.origin}/v1/blueprints/{blueprint_ref}", timeout=10.0, verify=_verify(app)
    )
    return response.status_code == 200


def _verify(app: RunningApp) -> ssl.SSLContext | bool:
    return ssl.create_default_context(cafile=str(app.ca_file)) if app.ca_file else True


def _ref() -> str:
    return f"example.authz-{uuid.uuid4().hex[:8]}"


def test_a_team_that_never_installed_library_cannot_publish(
    deployment: RunningApp,
    workspaces: Callable[[str], AWWorkspace],
) -> None:
    team = _team(workspaces, "uninstalled", deployment)
    blueprint_ref = _ref()

    assert_aw_status(
        _publish(team, deployment, blueprint_ref), 403, context="publish without an install"
    )
    assert not _catalog_has(deployment, blueprint_ref)
    assert_aw_status(
        aw_request(team, HTTPMethod.GET, f"{deployment.origin}/v1/shelf"),
        403,
        context="shelf read without an install",
    )


def test_an_install_without_library_write_cannot_write(
    deployment: RunningApp,
    workspaces: Callable[[str], AWWorkspace],
) -> None:
    team = _team(workspaces, "read-only", deployment)
    install_app(team, deployment, grant_scopes=("library:read",))
    blueprint_ref = _ref()

    assert_aw_status(
        _publish(team, deployment, blueprint_ref), 403, context="publish with library:read only"
    )
    assert not _catalog_has(deployment, blueprint_ref)
    assert_aw_status(
        aw_request(team, HTTPMethod.POST, f"{deployment.origin}/v1/team/register", body="{}"),
        403,
        context="register with library:read only",
    )
    shelf = aw_json(
        aw_request(team, HTTPMethod.GET, f"{deployment.origin}/v1/shelf"),
        context="shelf with library:read",
    )
    assert isinstance(shelf, dict)


def test_an_uninstalled_team_is_refused(
    deployment: RunningApp,
    workspaces: Callable[[str], AWWorkspace],
) -> None:
    team = _team(workspaces, "uninstalling", deployment)
    install_app(team, deployment)
    aw_json(
        aw_request(team, HTTPMethod.GET, f"{deployment.origin}/v1/proposals"),
        context="installed member reads",
    )

    uninstall_app(team, deployment)

    deadline = time.monotonic() + GRANT_WINDOW_SECONDS
    while True:
        refused = aw_request(team, HTTPMethod.GET, f"{deployment.origin}/v1/proposals")
        if refused.returncode != 0 or time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    assert_aw_status(refused, 403, context="member of a team that uninstalled Library")
    blueprint_ref = _ref()
    assert_aw_status(
        _publish(team, deployment, blueprint_ref), 403, context="publish after uninstall"
    )
    assert not _catalog_has(deployment, blueprint_ref)


def test_a_team_signed_certificate_the_registry_never_published_is_unauthenticated(
    deployment: RunningApp,
    workspaces: Callable[[str], AWWorkspace],
) -> None:
    team = _team(workspaces, "unpublished-cert", deployment)
    install_app(team, deployment)
    # Signed by the team's real controller key, never registered at AWID.
    unpublished = Member(
        team_id=team.team_id,
        team_key=team_signing_key(team),
        certificate_id=str(uuid.uuid4()),
        alias="unpublished",
    )
    response = httpx.get(
        f"{deployment.origin}/v1/shelf",
        headers=unpublished.headers(aud=deployment.origin, method="GET", path="/v1/shelf"),
        timeout=10.0,
        verify=_verify(deployment),
    )
    assert response.status_code == 401, response.text


def test_a_granted_member_publishes_shelves_and_materializes(
    deployment: RunningApp,
    workspaces: Callable[[str], AWWorkspace],
) -> None:
    team = _team(workspaces, "granted", deployment)
    install_app(team, deployment)
    blueprint_ref = _ref()

    published = aw_json(_publish(team, deployment, blueprint_ref), context="granted publish")
    assert published["blueprint_ref"] == blueprint_ref
    assert _catalog_has(deployment, blueprint_ref)
    shelved = aw_json(
        aw_request(
            team,
            HTTPMethod.POST,
            f"{deployment.origin}/v1/shelf/import",
            body=json.dumps({"source_blueprint_ref": blueprint_ref, "profile_ref": "developer"}),
        ),
        context="granted import to shelf",
    )
    assert shelved["created"] is True
    materialized = aw_json(
        aw_request(
            team,
            HTTPMethod.POST,
            f"{deployment.origin}/v1/materialize",
            body=json.dumps(
                {"profile_ref": "developer", "runtime_kind": "claude-code", "target": "local"}
            ),
        ),
        context="granted materialize",
    )
    assert materialized["source_blueprint_ref"] == blueprint_ref
    assert materialized["home_files"]
