"""An enrolled global ID cannot evade ID-tree status by omitting its did:aw claim.

id-certificates.md §5: enrolled omission is not a legacy success; a revoked or
root-replaced enrolled ID is refused on every lane. Real AWID routes, real aweb
app, PostgreSQL and Redis; only DNS is fixture authority.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from awid.did import stable_id_from_did_key
from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier
from aweb.api import _build_awid_registry_client
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_id_chain_request_auth import (
    ALICE,
    ROOT,
    VECTORS,
    _fixture_signer,
    _signed_fixture_certificate,
)
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_identity_headers,
    _signed_team_headers,
)

__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tree_state, reason",
    [
        ("revoked", "revoked"),
        ("root-replaced", "root_replaced"),
        ("never-enrolled", None),
    ],
)
@pytest.mark.parametrize(
    "presentation", ["claims-did-aw", "omits-did-aw", "claimless-team-certificate"]
)
async def test_stored_did_aw_gets_the_tree_status_of_a_claimed_one(
    privacy_app, monkeypatch, tree_state, reason, presentation
):
    env = privacy_app
    actor = env.actors["bob"]
    actor.sk, actor.did = bytes.fromhex(ALICE["seed_hex"]), ALICE["did_key"]
    stable = stable_id_from_did_key(actor.did)
    domain = f"awtest-omit-{uuid4().hex}.test"
    async with registry_listener(env) as (writer, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        controller = [ROOT]

        async def exact_dns(selected):
            assert selected == domain
            return DomainAuthority(controller[0]["did_key"], origin, "_awid." + domain)

        env.registry_app.dependency_overrides[get_domain_verifier] = lambda: exact_dns
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
        cached = _build_awid_registry_client(env.app, redis=env.redis)
        object.__setattr__(cached, "_domain_verifier", exact_dns)
        env.app.state.awid_registry_client = cached
        try:
            await writer.register_namespace(
                domain, ROOT["did_key"], bytes.fromhex(ROOT["seed_hex"])
            )
            assert (await writer.register_did(actor.did, actor.sk)).did_aw == stable
            # The member row is the global identity, as after a global connect.
            await env.db.execute(
                "UPDATE {{tables.agents}} SET did_key=$1, did_aw=$2, "
                "did_aw_verified_key=$1, identity_scope='global' WHERE agent_id=$3",
                actor.did,
                stable,
                actor.id,
            )
            if tree_state != "never-enrolled":
                human = _signed_fixture_certificate(
                    "alice",
                    domain=domain,
                    identity=stable,
                    parent={"kind": "namespace", "id": domain},
                    issuer="root",
                )
                receipt = await writer.register_id_certificate(
                    {"v": 1, "type": "aweb.id-chain", "certificates": [human]},
                    signer=_fixture_signer("alice"),
                    expected_head=None,
                    invitation_id=None,
                )
                if tree_state == "revoked":
                    await writer.revoke_id_certificate(
                        domain,
                        stable,
                        signer=_fixture_signer("root"),
                        expected_head=receipt["certificate_id"],
                    )
                else:
                    controller[0] = VECTORS["keys"]["root_rotated"]
                    await writer.rotate_namespace_controller(
                        domain,
                        controller[0]["did_key"],
                        bytes.fromhex(controller[0]["seed_hex"]),
                    )
            body = json.dumps(
                {
                    "to_did": env.actors["carol"].did,
                    "subject": "omission",
                    "body": "hello",
                }
            ).encode()
            if presentation == "claimless-team-certificate":
                certificate = _encode_certificate(
                    _make_certificate(
                        env.team_sk,
                        env.team_did,
                        actor.did,
                        team_id=TEAM,
                        alias="bob",
                        identity_scope="local",
                        certificate_id="privacy-bob",
                    )
                )
                auth = _signed_team_headers(
                    actor.sk, actor.did, TEAM, certificate, body
                )
            else:
                claim = stable if presentation == "claims-did-aw" else ""
                auth = _signed_identity_headers(actor.sk, actor.did, claim, body)
            before = await env.db.fetch_val("SELECT count(*) FROM {{tables.messages}}")
            response = await env.client.post(
                "/v1/messages",
                content=body,
                headers={**auth, "Content-Type": "application/json"},
            )
            if reason is None:
                assert response.status_code == 200, response.text
                assert (
                    await env.db.fetch_val(
                        "SELECT from_did FROM {{tables.messages}} "
                        "ORDER BY created_at DESC LIMIT 1"
                    )
                    == stable
                )
            else:
                assert response.status_code == 403, response.text
                assert response.json()["detail"] == reason
            assert await env.db.fetch_val(
                "SELECT count(*) FROM {{tables.messages}}"
            ) == before + (reason is None)
        finally:
            env.app.state.awid_registry_client = writer
            await cached.aclose()
