"""Real pre-status AWID refuses private-team verification without fallback."""

from __future__ import annotations

import os
from http import HTTPMethod

import httpx
import pytest
from aweb_naapp_testing.deployment import (
    RunningApp,
    assert_aw_status,
    assert_aw_success,
    aw_request,
    candidate_hostname,
    compose,
    configure_app_client,
    wait_http_ok,
)
from test_e2e_smoke import (
    AWID_URL,
    STACK,
    installed_team,
    require_e2e_enabled,
    running_library,
)

pytestmark = pytest.mark.e2e


def test_private_certificate_refused_by_real_pre_status_registry(
    aw_workspace, library_without_awid_service_token: RunningApp, tmp_path
):
    require_e2e_enabled()
    if os.environ.get("NAAPP_E2E_CONTAINER_NETWORK") == "1":
        project = os.environ["NAAPP_E2E_PROJECT"]
        old_registry = (
            f"http://{candidate_hostname(project=project, service='awid-pre-status')}:8010"
        )
    else:
        binding = compose(STACK, "port", "awid-pre-status", "8010").stdout.strip().splitlines()[0]
        port = int(binding.rsplit(":", 1)[1])
        host = os.environ.get("NAAPP_E2E_HOST", "127.0.0.1")
        old_registry = f"http://{host}:{port}"
    wait_http_ok(f"{old_registry}/health")
    team = installed_team(aw_workspace, library_without_awid_service_token)
    team_path = f"/v1/namespaces/{team.namespace}/teams/{team.team}"
    status_path = f"{team_path}/certificates/{team.certificate_id}/status"

    # Both actual registry builds see the same real private team and certificate.
    # The old build has no /status route; no response or verifier is substituted.
    for registry in (old_registry, AWID_URL):
        private = httpx.get(registry + team_path)
        assert private.status_code == 403, private.text
        assert private.json()["detail"]["code"] == "team_private"
    missing_route = httpx.get(old_registry + status_path)
    assert missing_route.status_code == 404, missing_route.text
    assert missing_route.json() == {"detail": "Not Found"}
    current_status = httpx.get(AWID_URL + status_path)
    assert current_status.status_code == 200, current_status.text
    assert current_status.json()["status"] == "active"

    assert library_without_awid_service_token.server is not None
    with running_library(
        tmp_path / "old-registry",
        awid_service_token=None,
        operator=library_without_awid_service_token.server.operator,
        registry_url=old_registry,
    ) as app:
        configure_app_client(team.workspace, app)
        result = aw_request(team, HTTPMethod.GET, f"{app.origin}/v1/proposals")
        assert_aw_status(result, 401, context="private certificate on registry without status")
    current = aw_request(
        team, HTTPMethod.GET, f"{library_without_awid_service_token.origin}/v1/proposals"
    )
    assert (
        assert_aw_success(current, context="same certificate on current registry").strip() == "[]"
    )
