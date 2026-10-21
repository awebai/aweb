"""Real pre-status AWID refuses private-team verification without fallback."""
from __future__ import annotations

import os

import httpx
import pytest
from test_e2e_smoke import (
    AWID_URL,
    _assert_aw_status,
    _assert_aw_success,
    _aw_request,
    _compose,
    _provision_team,
    _require_e2e_enabled,
    _running_library,
    _wait_http_ok,
)

pytestmark = pytest.mark.e2e


def test_private_certificate_refused_by_real_pre_status_registry(aw_workspace):
    _require_e2e_enabled()
    binding = _compose("port", "awid-pre-status", "8010").stdout.strip().splitlines()[0]
    port = int(binding.rsplit(":", 1)[1])
    host = os.environ.get("NAAPP_E2E_HOST", "127.0.0.1")
    old_registry = f"http://{host}:{port}"
    _wait_http_ok(f"{old_registry}/health")
    team = _provision_team(aw_workspace)
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

    with _running_library(awid_service_token=None, registry_url=old_registry) as app:
        result = _aw_request(team, "GET", f"{app.origin}/v1/proposals")
        _assert_aw_status(result, 401, context="private certificate on registry without status")
        assert "Unknown AWID certificate" in result.stdout
    with _running_library(awid_service_token=None) as app:
        result = _aw_request(team, "GET", f"{app.origin}/v1/proposals")
        assert _assert_aw_success(result, context="same certificate on current registry").strip() == "[]"
