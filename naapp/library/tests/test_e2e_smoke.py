"""Library on a real stack: real AWID (the compose stack), a real coordination
server and real Library behind TLS. Each team installs Library with the real
``aw plugin install`` before it calls a member route; no path signs in with a
bare certificate.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from http import HTTPMethod
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing.deployment import (
    AWWorkspace,
    E2ETeam,
    RunningApp,
    assert_aw_status,
    assert_aw_success,
    aw_request,
    aw_workspace_factory,
    connect_team_server,
    coordination_listener,
    e2e_stack,
    install_app,
    provision_team,
    run_aw,
    running_app,
    running_coordination_server,
    wait_http_ok,
)

pytestmark = pytest.mark.e2e

STACK = e2e_stack(os.environ, project="library-e2e", database="library")
AWID_URL = STACK.awid_url
# Same-operator credential shared with the e2e awid service (docker-compose.e2e.yml).
AWID_SERVICE_TOKEN = os.environ.get(
    "LIBRARY_E2E_AWID_SERVICE_TOKEN", "library-e2e-awid-service-token-0123456789abcdef"
)
E2E_BUILD_SHA = "0123456789abcdef0123456789abcdef01234567"
# A deployment on this host's address is not the hosted origin, so it needs its own app id.
E2E_APP_ID = "library-e2e"
# Library's own settings the caller's environment must not leak into a deployment.
_DEPLOYMENT_SETTINGS = (
    "RENDER_SERVICE_ID",
    "RENDER_SERVICE_NAME",
    "RENDER_EXTERNAL_HOSTNAME",
    "RENDER_GIT_REPO_SLUG",
    "RENDER_GIT_BRANCH",
    "RENDER_GIT_COMMIT",
    "LIBRARY_GIT_SHA",
    "LIBRARY_AWID_SERVICE_TOKEN",
    "LIBRARY_APP_KEY_FILES",
    "LIBRARY_APP_ID",
)


def require_e2e_enabled() -> None:
    if os.environ.get("LIBRARY_E2E") != "1":
        pytest.skip("set LIBRARY_E2E=1 or run `make e2e` to execute docker-backed e2e tests")


@contextmanager
def running_library(
    directory: Path,
    *,
    awid_service_token: str | None,
    registry_url: str = AWID_URL,
) -> Iterator[RunningApp]:
    """Library behind TLS on this host, reading AWID at ``registry_url``."""
    require_e2e_enabled()
    wait_http_ok(f"{registry_url}/health")
    directory.mkdir(parents=True)
    grant_key = directory / "grant-read.hex"
    grant_key.write_text(secrets.token_hex(32))
    grant_key.chmod(0o600)

    def settings(origin: str) -> dict[str, str]:
        values = {
            "RENDER_GIT_COMMIT": E2E_BUILD_SHA,
            "LIBRARY_DATABASE_URL": STACK.postgres_url,
            "LIBRARY_AWID_REGISTRY_URL": registry_url,
            "LIBRARY_AUTH_CACHE_TTL_SECONDS": "2",
            "LIBRARY_PUBLIC_ORIGIN": origin,
            "LIBRARY_APP_ID": E2E_APP_ID,
            "LIBRARY_APP_KEY_FILES": json.dumps({"library:grant-read-1": str(grant_key)}),
        }
        if awid_service_token is not None:
            values["LIBRARY_AWID_SERVICE_TOKEN"] = awid_service_token
        return values

    with running_app(
        name="library",
        factory="library.api:create_app",
        env_for=settings,
        drop_env=_DEPLOYMENT_SETTINGS,
        tls_dir=directory / "tls",
    ) as app:
        yield app


@contextmanager
def library_deployment(directory: Path, *, awid_service_token: str | None) -> Iterator[RunningApp]:
    """Library plus the coordination server its teams install it through."""
    with (
        coordination_listener() as (listener, server_origin),
        running_library(
            directory, awid_service_token=awid_service_token
        ) as app,
    ):
        assert app.ca_file is not None
        with running_coordination_server(
            directory,
            listener=listener,
            stack=STACK,
            awid_service_token=AWID_SERVICE_TOKEN,
            app_origin=app.origin,
            ca_file=app.ca_file,
        ) as server:
            yield replace(app, server=server)


@pytest.fixture(scope="session")
def library(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningApp]:
    directory = tmp_path_factory.mktemp("library") / "deployment"
    with library_deployment(directory, awid_service_token=AWID_SERVICE_TOKEN) as app:
        yield app


@pytest.fixture(scope="session")
def library_without_awid_service_token(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[RunningApp]:
    directory = tmp_path_factory.mktemp("library-without-token") / "deployment"
    with library_deployment(directory, awid_service_token=None) as app:
        yield app


@pytest.fixture(scope="session")
def library_origin(library: RunningApp) -> str:
    return library.origin


@pytest.fixture()
def workspaces(tmp_path: Path) -> Callable[[str], AWWorkspace]:
    require_e2e_enabled()
    return aw_workspace_factory(tmp_path, awid_url=AWID_URL)


@pytest.fixture()
def aw_workspace(workspaces: Callable[[str], AWWorkspace]) -> AWWorkspace:
    return workspaces("primary")


def connected_team(workspace: AWWorkspace, library: RunningApp) -> E2ETeam:
    """A new team whose server is the deployment's, with Library not installed."""
    team = provision_team(workspace, awid_url=AWID_URL, namespace_prefix="library-e2e")
    connect_team_server(team, library, awid_url=AWID_URL)
    return team


def installed_team(
    workspace: AWWorkspace, library: RunningApp, *, grant_scopes: tuple[str, ...] = ()
) -> E2ETeam:
    """A new team that installed Library; ``grant_scopes`` narrows its grant."""
    team = connected_team(workspace, library)
    install_app(team, library, grant_scopes=grant_scopes)
    return team


def test_health_endpoints_are_public(library: RunningApp) -> None:
    for path in ("/health", "/live", "/ready"):
        response = httpx.get(f"{library.origin}{path}", timeout=10.0)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "ok", path
        assert body["service"] == E2E_APP_ID, path
        assert body["build"] == {"git_sha": E2E_BUILD_SHA}, path


def test_public_blueprint_catalog_needs_no_auth(library: RunningApp) -> None:
    blueprints = httpx.get(f"{library.origin}/v1/blueprints", timeout=10.0)
    assert blueprints.status_code == 200, blueprints.text
    assert isinstance(blueprints.json(), list)
    assert httpx.get(f"{library.origin}/v1/blueprints/none", timeout=10.0).status_code == 404


def test_shelf_and_team_routes_without_envelope_fail_closed(library_origin: str) -> None:
    # The shelf is private: shelf reads + team writes require a certificate.
    assert httpx.get(f"{library_origin}/v1/shelf", timeout=10.0).status_code == 401
    assert httpx.get(f"{library_origin}/v1/proposals", timeout=10.0).status_code == 401


def test_manifest_is_public_and_names_this_deployment(library: RunningApp) -> None:
    served = httpx.get(f"{library.origin}/manifests/v2.json", timeout=10.0)
    assert served.status_code == 200, served.text
    bare = httpx.get(f"{library.origin}/aweb-app.json", timeout=10.0)
    assert bare.status_code == 200, bare.text
    assert bare.content == served.content
    document = json.loads(served.content)
    assert document["app"]["origin"] == library.origin
    assert document["app"]["id"] == library.app_id == E2E_APP_ID


def test_private_team_authenticates_without_the_awid_service_token(
    library_without_awid_service_token: RunningApp, aw_workspace: AWWorkspace
) -> None:
    team = installed_team(aw_workspace, library_without_awid_service_token)
    result = aw_request(
        team, HTTPMethod.GET, f"{library_without_awid_service_token.origin}/v1/proposals"
    )
    assert assert_aw_success(result, context="private team without service token").strip() == "[]"


def test_real_aw_team_auth_reaches_team_scoped_routes(
    library: RunningApp, aw_workspace: AWWorkspace
) -> None:
    team = installed_team(aw_workspace, library)
    blueprints = aw_request(team, HTTPMethod.GET, f"{library.origin}/v1/blueprints")
    assert isinstance(
        json.loads(assert_aw_success(blueprints, context="list blueprints smoke")), list
    )
    # A valid certificate passes auth: get-binding for an unbound agent is a real
    # 404 (not 401), proving auth + the live endpoint.
    binding = aw_request(
        team, HTTPMethod.GET, f"{library.origin}/v1/agents/agent-1/profile-binding"
    )
    assert_aw_status(binding, 404, context="authenticated get-binding for unbound agent")
    proposals = aw_request(team, HTTPMethod.GET, f"{library.origin}/v1/proposals")
    assert assert_aw_success(proposals, context="list proposals smoke").strip() == "[]"


def test_revoked_certificate_fails_after_awid_revocation_cache_refresh(
    library: RunningApp,
    aw_workspace: AWWorkspace,
) -> None:
    team = installed_team(aw_workspace, library)
    assert (
        assert_aw_success(
            aw_request(team, HTTPMethod.GET, f"{library.origin}/v1/proposals"),
            context="valid certificate reaches proposals",
        ).strip()
        == "[]"
    )

    run_aw(
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
    revoked = aw_request(team, HTTPMethod.GET, f"{library.origin}/v1/proposals")
    assert_aw_status(revoked, 401, context="revoked certificate")
