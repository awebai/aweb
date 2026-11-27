"""Cached AWID status refusals at the signed handoff start boundary.

Secrets tests its requester policy with the production runtime's plain AWID
client. This test exercises the handoff router with the cached SDK client.
"""

import base64
import json
import os
from contextlib import aclosing
from datetime import UTC, datetime, timedelta

import httpx
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member
from aweb_naapp_testing.human_members import human_namespace
from awid.id_certificates import encode_id_chain_header, id_certificate_signing_bytes
from awid.registry import CachedRegistryClient
from fastapi import FastAPI, Request
from redis.asyncio import Redis

from aweb_naapp.console import ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_requester import CHAIN_HEADER, requester_parent
from aweb_naapp.console.handoff_store import HandoffStore, handoff_start_router
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from tests.console.test_handoff_store import handoff_db, start_body

__all__ = ["handoff_db"]

API = "https://api.example"
DOMAIN = "example.com"


async def test_direct_child_handoff_distinguishes_unusable_status_from_failed_read(
    handoff_db, registry
):
    holder = Member(team_id=f"people:{DOMAIN}")
    await registry.add_team(holder.team_id, holder.team_did_key)
    async with (
        human_namespace(registry, DOMAIN) as namespace,
        Redis.from_url(os.environ["REDIS_URL"]) as redis,
    ):
        human = await namespace.register(holder)
        agent = Member(
            team_id=holder.team_id,
            team_key=holder.team_key,
            certificate_id="requester-cert",
            alias="requester",
        )
        agent_id = (await human.client.register_did(agent.did_key, bytes(agent.member_key))).did_aw
        agent.extra_cert_fields = {"member_did_aw": agent_id}
        fields = {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": agent_id,
            "domain": DOMAIN,
            "parent": {"kind": "identity", "id": human.principal},
            "kind": "agent",
            "issuer_key": holder.did_key,
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        signature = holder.member_key.sign(id_certificate_signing_bytes(fields)).signature
        signed = {
            "certificate": fields,
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        }
        bundle = {"v": 1, "type": "aweb.id-chain", "certificates": [human.identity, signed]}
        await human.client.register_id_certificate(
            bundle,
            signer=lambda payload: (agent.did_key, agent.member_key.sign(payload).signature),
            expected_head=None,
            invitation_id=None,
        )
        await registry.add_certificate(agent.certificate(), team_key=agent.team_key)

        team_cache = AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=60,
            service_token=SERVICE_TOKEN,
            transport=registry.transport,
        )
        store = HandoffStore(handoff_db)

        async def principal(request: Request):
            return await authenticate_request(request, public_origin=API, team_cache=team_cache)

        async def start_session(start, signer, request, *, requester):
            requester.require_fresh()
            return await store.create(start, team_id=signer.team_id)

        def status_fault(request, response):
            if request.url.path != "/v1/id-certificates/status":
                return None
            assert response.status_code == 200
            return status_response

        async with aclosing(
            CachedRegistryClient(
                REGISTRY_URL,
                redis,
                transport=registry.transport,
                service_token=SERVICE_TOKEN,
                domain_verifier=namespace.authority,
            )
        ) as cache:
            app = FastAPI()
            app.include_router(
                handoff_start_router(
                    store=store,
                    principal=principal,
                    session_start=start_session,
                    requester_parent=requester_parent(cache),
                    limiter=LoginLimiter(
                        handoff_db,
                        client_identity=ClientIdentity(),
                        limit=50,
                        window=timedelta(minutes=1),
                    ),
                )
            )
            body = start_body(purpose="session")
            body["scope"]["principal"] = human.principal
            raw = json.dumps(body).encode()
            chain_header = encode_id_chain_header(bundle)
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url=API) as client:

                async def start_handoff():
                    headers = agent.headers(aud=API, method="POST", path="/handoffs", body=raw)
                    headers.update({"Content-Type": "application/json", CHAIN_HEADER: chain_header})
                    return await client.post("/handoffs", content=raw, headers=headers)

                registry.transport.fault = status_fault
                for upstream_response, expected_status, code in (
                    (httpx.Response(503), 503, "principal_status_unavailable"),
                    (httpx.Response(200, content=b"[]"), 422, "registry_response_unusable"),
                ):
                    status_response = upstream_response
                    response = await start_handoff()
                    assert response.status_code == expected_status, response.text
                    assert response.json() == {"detail": code}
                    assert (
                        await handoff_db.fetch_value(
                            "SELECT count(*) FROM {{tables.console_handoffs}}"
                        )
                        == 0
                    )

                registry.transport.fault = None
                valid = await start_handoff()
                assert valid.status_code == 201, valid.text
                assert (
                    await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}")
                    == 1
                )
