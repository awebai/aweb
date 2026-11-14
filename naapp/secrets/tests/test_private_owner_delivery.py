"""H's customer-hosted topology: tokenless service, private team, real AWID reads."""

import base64
import json

import pytest
from aweb_naapp.hooks.owner_act import owner_act_signing_bytes

from tests.test_owner_delivery import PATH, assert_first_owner_and_login, delivery, effects
from tests.test_production_bootstrap import root as root

pytestmark = pytest.mark.parametrize(
    "root", [{"manifest_version": 3, "private_team": True}], indirect=True
)


async def test_tokenless_private_team_first_owner_uses_the_service_members_signed_reads(
    root, registry
):
    service, client, settings, member, *_ = root
    assert settings.awid_service_token is None
    assert set(settings.awid_member_credentials) == {member.team_id}
    await assert_first_owner_and_login(root, registry)
    # Includes startup's member check and the real controller/H2 reads, never
    # a synthetic key source or a token hidden in the production runtime.
    name, domain = member.team_id.split(":", 1)
    team_path = f"/v1/namespaces/{domain}/teams/{name}"
    reads = [
        request
        for request in registry.transport.calls
        if request.method == "GET" and request.url.path in {team_path, team_path + "/certificates"}
    ]
    assert {request.url.path for request in reads} == {team_path, team_path + "/certificates"}
    assert all(
        request.headers["Authorization"].startswith(
            f"DIDKey {client.service_fixture_member.did_key} "
        )
        for request in reads
    )


async def test_tokenless_unknown_team_returns_protection_unavailable_before_any_app_effect(root, registry):
    service, client, settings, member, installed, _, coordination, _ = root
    body, _, _ = await delivery(root, registry)
    fields = json.loads(base64.b64decode(body["signing"]).split(b"\n", 1)[1])
    fields["team_id"] = "unknown:example.com"
    signing = owner_act_signing_bytes(fields)
    body["signing"] = base64.b64encode(signing).decode()
    body["signature"] = (
        base64.b64encode(member.team_key.sign(signing).signature).decode().rstrip("=")
    )
    before = await effects(service, installed["installation_id"], member.team_id)
    before_app_reads = len(coordination.calls)
    response = await client.post(settings.console_origin + PATH, json=body)
    # An absent team has no authoritative protection projection. The shared
    # verifier must report that missing current evidence before key/app reads,
    # rather than infer legacy membership from an unknown team.
    assert (response.status_code, response.json()["detail"]) == (503, "protected_state_unavailable")
    assert await effects(service, installed["installation_id"], member.team_id) == before
    assert len(coordination.calls) == before_app_reads
    # A missing team must reach real AWID, rather than failing locally because
    # a tokenless client incorrectly insists on a caller certificate ID.
    assert any(
        request.method == "GET" and request.url.path == "/v1/namespaces/example.com/teams/unknown"
        for request in registry.transport.calls
    )
