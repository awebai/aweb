"""Administrative pins and routed-read neighbors through the public SDK on HTTP."""

from __future__ import annotations

import base64
import json
from enum import StrEnum

import httpx
import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError
from awid.signing import canonical_json_bytes, sign_message
from test_id_registry_client import _bundle, signer_for
from id_tree_support import certificate_id, did_aw, did_key
from test_registry_client import FakeRedis
from test_registry_evidence_boundaries import DOMAIN, TEAM, prepared_revoke
from test_registry_evidence_boundaries import peer_factory as peer_factory


class Administration(StrEnum):
    REGISTER_NAMESPACE = "register_namespace"
    UPDATE_NAMESPACE = "update_namespace"
    ROTATE_NAMESPACE = "rotate_namespace"
    REGISTER_TEAM = "register_team"
    VISIBILITY = "visibility"
    DELETE_TEAM = "delete_team"
    REGISTER_CERTIFICATE = "register_certificate"
    REVOKE_CERTIFICATE = "revoke_certificate"
    PREPARED_REVOKE = "prepared_revoke"
    REGISTER_ADDRESS = "register_address"
    UPDATE_ADDRESS = "update_address"
    DELETE_ADDRESS = "delete_address"
    REASSIGN_ADDRESS = "reassign_address"
    PUBLISH_SERVER = "publish_server"
    REGISTER_ID = "register_id"
    REVOKE_ID = "revoke_id"
    ROTATE_WITH_PREVIOUS = "rotate_with_previous"


async def administrative_call(client, *, operation: Administration, seed: bytes, did: str):
    stable_id = stable_id_from_did_key(did)
    actions = {
        Administration.REGISTER_NAMESPACE: lambda: client.register_namespace(DOMAIN, did, seed),
        Administration.UPDATE_NAMESPACE: lambda: client.update_namespace_delivery_origin(
            DOMAIN, seed, None
        ),
        Administration.ROTATE_NAMESPACE: lambda: client.rotate_namespace_controller(
            DOMAIN, did, seed
        ),
        Administration.REGISTER_TEAM: lambda: client.register_team(
            domain=DOMAIN,
            name=TEAM,
            display_name=TEAM,
            team_did_key=did,
            visibility="public",
            namespace_controller_signing_key=seed,
        ),
        Administration.VISIBILITY: lambda: client.set_team_visibility(
            DOMAIN, TEAM, "private", seed
        ),
        Administration.DELETE_TEAM: lambda: client.delete_team(DOMAIN, TEAM, seed),
        Administration.REGISTER_CERTIFICATE: lambda: client.register_team_certificate(
            DOMAIN,
            TEAM,
            team_controller_signing_key=seed,
            certificate_id="member",
            member_did_key=did,
            member_did_aw=None,
            member_address=None,
            alias="member",
            identity_scope="local",
        ),
        Administration.REVOKE_CERTIFICATE: lambda: client.revoke_team_certificate(
            DOMAIN,
            TEAM,
            team_controller_signing_key=seed,
            certificate_id="member",
        ),
        Administration.PREPARED_REVOKE: lambda: client.revoke_team_certificate_with_proof(
            DOMAIN,
            TEAM,
            **prepared_revoke(origin=client.registry_url),
        ),
        Administration.REGISTER_ADDRESS: lambda: client.register_address(
            DOMAIN,
            "member",
            stable_id,
            seed,
            current_did_key=did,
        ),
        Administration.UPDATE_ADDRESS: lambda: client.update_address(DOMAIN, "member", seed),
        Administration.DELETE_ADDRESS: lambda: client.delete_address(DOMAIN, "member", seed),
        Administration.REASSIGN_ADDRESS: lambda: client.reassign_address(
            DOMAIN, "member", stable_id, seed
        ),
        Administration.PUBLISH_SERVER: lambda: client.publish_team_server_record(
            DOMAIN,
            TEAM,
            {},
            sign_message(seed, canonical_json_bytes({})),
        ),
        Administration.REGISTER_ID: lambda: client.register_id_certificate(
            _bundle("alice", "bob"),
            signer=signer_for("bob"),
            expected_head=None,
            invitation_id=None,
        ),
        Administration.REVOKE_ID: lambda: client.revoke_id_certificate(
            "example.com",
            did_aw("bob"),
            signer=signer_for("root"),
            expected_head=certificate_id("bob"),
        ),
        Administration.ROTATE_WITH_PREVIOUS: lambda: client.rotate_namespace_with_previous_key(
            "example.com",
            from_seq=1,
            previous_did_key=did_key("root"),
            new_did_key=did_key("root_rotated"),
            previous_signer=signer_for("root"),
            new_signer=signer_for("root_rotated"),
        ),
    }
    return await actions[operation]()


@pytest.mark.asyncio
@pytest.mark.parametrize("client_type", [RegistryClient, CachedRegistryClient])
@pytest.mark.parametrize("operation", list(Administration))
async def test_administrative_mutation_pins_its_configured_registry_without_discovery(
    peer_factory,
    operation,
    client_type,
):
    configured, other = peer_factory(), peer_factory()
    configured.status = other.status = 403
    configured.response = other.response = b'{"detail":"controller refused"}'
    routes = []

    async def resolver(domain):
        routes.append(domain)
        return other.origin

    options = dict(
        domain_registry_resolver=resolver,
        transport=httpx.AsyncHTTPTransport(trust_env=False),
        service_token="unit-home-service-capability-at-least-32-bytes",
    )
    client = (
        client_type(configured.origin, FakeRedis(), **options)
        if client_type is CachedRegistryClient
        else client_type(configured.origin, **options)
    )
    seed, public = generate_keypair()
    did = did_from_public_key(public)
    stable_id = stable_id_from_did_key(did)
    # Address invalidation can read prior public state, but only at the pin.
    configured.replies[("GET", f"/v1/namespaces/{DOMAIN}/addresses/member")] = (
        404,
        b'{"detail":{"code":"address_not_found"}}',
    )
    configured.replies[("GET", f"/v1/did/{stable_id}/key")] = (
        200,
        json.dumps({"did_aw": stable_id, "current_did_key": did}).encode(),
    )
    try:
        with pytest.raises(RegistryError) as refused:
            await administrative_call(client, operation=operation, seed=seed, did=did)
        assert refused.value.status_code == 403
        mutations = [
            (request, headers)
            for request, headers in zip(
                configured.requests,
                configured.request_headers,
                strict=True,
            )
            if request[0] != "GET"
        ]
        assert len(mutations) == 1
        for _request, headers in mutations:
            if "x-aweb-signed-payload" in headers:
                signed = headers["x-aweb-signed-payload"]
                assert (
                    json.loads(base64.urlsafe_b64decode(signed + "=" * (-len(signed) % 4)))["aud"]
                    == configured.origin
                )
        assert routes == []
        assert other.requests == []
        # Read routing remains domain-selected on this same client.
        assert await client.registry_audience(DOMAIN) == other.origin
        assert routes == [DOMAIN]
        with pytest.raises(RegistryError) as read_refused:
            await client.get_namespace(DOMAIN)
        assert read_refused.value.status_code == 403
        assert routes == [DOMAIN, DOMAIN]
        assert len(other.requests) == 1 and other.requests[0][0] == "GET"
        assert "x-awid-service-token" not in other.request_headers[0]
    finally:
        await client.aclose()
