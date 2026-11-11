"""How a client authenticates its requests to its home AWID registry: the
headers ``RegistryRequestAuth`` gives are sent to the real AWID routes on real
PostgreSQL, which accept or refuse them."""

from __future__ import annotations

import pytest
from awid.did import generate_keypair
from awid.registry_auth import RegistryRequestAuth

from test_team_visibility_enforcement import (
    SERVICE_TOKEN,
    _assert_team_private,
    _create_team,
    _register_member,
    _revoke_member,
    _setup_namespace,
    service_client,  # noqa: F401 - fixture
)

GATED_READS = (
    "/v1/namespaces/{domain}/teams/ops",
    "/v1/namespaces/{domain}/teams/ops/certificates",
    "/v1/namespaces/{domain}/teams/ops/members/alice",
    "/v1/namespaces/{domain}/teams/ops/revocations",
)


async def private_team(client, controller_identity, domain):
    ns_key, ns_did = controller_identity
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "ops")
    member_key, member_did, cert_id = await _register_member(
        client, team_key, team_did, domain, "ops", "alice"
    )
    return member_key, member_did, cert_id, (team_key, team_did)


@pytest.mark.asyncio
async def test_a_member_key_signs_each_gated_read_of_its_team(client, controller_identity):
    domain = "auth-member.com"
    member_key, member_did, _, _ = await private_team(client, controller_identity, domain)
    auth = RegistryRequestAuth(member_signing_keys={f"ops:{domain}": member_key})
    for template in GATED_READS:
        path = template.format(domain=domain)
        headers = auth.headers("GET", path)
        assert headers["Authorization"].startswith(f"DIDKey {member_did} ")
        assert "X-AWID-Service-Token" not in headers
        response = await client.get(path, headers=headers)
        assert response.status_code == 200, (path, response.text)


@pytest.mark.asyncio
async def test_the_signature_covers_the_path_without_its_query(client, controller_identity):
    domain = "auth-query.com"
    member_key, _, _, _ = await private_team(client, controller_identity, domain)
    auth = RegistryRequestAuth(member_signing_keys={f"ops:{domain}": member_key})
    path = f"/v1/namespaces/{domain}/teams/ops/certificates?limit=1"
    response = await client.get(path, headers=auth.headers("GET", path))
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_an_unsigned_private_team_read_is_refused(client, controller_identity):
    domain = "auth-unsigned.com"
    await private_team(client, controller_identity, domain)
    path = f"/v1/namespaces/{domain}/teams/ops"
    headers = RegistryRequestAuth().headers("GET", path)
    assert headers == {}
    _assert_team_private(await client.get(path, headers=headers))


@pytest.mark.asyncio
async def test_a_revoked_members_signature_is_refused(client, controller_identity):
    domain = "auth-revoked.com"
    member_key, _, cert_id, (team_key, team_did) = await private_team(
        client, controller_identity, domain
    )
    await _revoke_member(client, team_key, team_did, domain, "ops", cert_id)
    auth = RegistryRequestAuth(member_signing_keys={f"ops:{domain}": member_key})
    path = f"/v1/namespaces/{domain}/teams/ops"
    _assert_team_private(await client.get(path, headers=auth.headers("GET", path)))


@pytest.mark.asyncio
async def test_a_member_key_is_never_sent_with_another_teams_reads(client, controller_identity):
    domain = "auth-own-team.com"
    member_key, _, _, _ = await private_team(client, controller_identity, domain)
    ns_key, ns_did = controller_identity
    await _create_team(client, ns_key, ns_did, domain, "other")
    auth = RegistryRequestAuth(member_signing_keys={f"ops:{domain}": member_key})
    path = f"/v1/namespaces/{domain}/teams/other"
    assert auth.headers("GET", path) == {}
    _assert_team_private(await client.get(path, headers=auth.headers("GET", path)))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1/namespaces/example.com/teams/ops/certificates"),
        ("GET", "/v1/namespaces/example.com/teams/ops/certificates/c1/status"),
        ("GET", "/v1/namespaces/example.com"),
        ("GET", "/v1/did/did:aw:abc/key"),
    ],
)
def test_a_member_key_signs_only_gated_team_reads(method, path):
    """No write, identity read or certificate status read inherits the
    member's authority."""
    member_key, _ = generate_keypair()
    auth = RegistryRequestAuth(member_signing_keys={"ops:example.com": member_key})
    assert auth.headers(method, path) == {}


def test_a_request_the_caller_signs_keeps_its_own_signature():
    member_key, _ = generate_keypair()
    auth = RegistryRequestAuth(member_signing_keys={"ops:example.com": member_key})
    assert auth.headers("GET", "/v1/namespaces/example.com/teams/ops", signed_by_caller=True) == {}


@pytest.mark.asyncio
async def test_the_service_token_takes_precedence_over_a_member_key(
    service_client, controller_identity  # noqa: F811 - fixture
):
    domain = "auth-token.com"
    member_key, _, _, _ = await private_team(service_client, controller_identity, domain)
    auth = RegistryRequestAuth(
        service_token=SERVICE_TOKEN, member_signing_keys={f"ops:{domain}": member_key}
    )
    for template in GATED_READS:
        path = template.format(domain=domain)
        headers = auth.headers("GET", path)
        assert headers == {"X-AWID-Service-Token": SERVICE_TOKEN}
        response = await service_client.get(path, headers=headers)
        assert response.status_code == 200, (path, response.text)


@pytest.mark.parametrize(
    ("method", "path", "signed_by_caller"),
    [
        ("POST", "/v1/namespaces/example.com/teams", True),
        ("GET", "/v1/did/did:aw:abc/key", False),
        ("GET", "/v1/namespaces/example.com/teams/ops", True),
    ],
)
def test_the_service_token_rides_on_every_request(method, path, signed_by_caller):
    auth = RegistryRequestAuth(service_token=SERVICE_TOKEN)
    assert auth.headers(method, path, signed_by_caller=signed_by_caller) == {
        "X-AWID-Service-Token": SERVICE_TOKEN
    }


def test_a_blank_service_token_is_no_token():
    assert RegistryRequestAuth(service_token="  ").headers("GET", "/v1/did/x/key") == {}
