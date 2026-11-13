"""Closed legacy transport/auth controls, with no DB or external service."""

import base64
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.registry import CachedRegistryClient, RegistryError
from awid.signing import sign_message

from aweb.protected_signing.custody import ProtectedControllerCustody
from aweb.protected_signing.legacy_delivery import deliver_legacy
from aweb_naapp.runtime.protected_signer import CatalogOperation, ProtectedKeyContext
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, signing_bytes
from aweb_naapp.signing_key import parse_signing_key_hex

ORIGIN = "https://registry.customer.example"
DOMAIN, TEAM = "customer.example", "engineering:customer.example"
NOW = datetime(2026, 11, 13, 12, tzinfo=UTC)


def fixture(name):
    seed, public = generate_keypair()
    controller = did_from_public_key(public)
    actor, child = [stable_id_from_public_key(generate_keypair()[1]) for _ in range(2)]
    member_key = did_from_public_key(generate_keypair()[1])
    context = ProtectedKeyContext("signer", "team_controller", TEAM, DOMAIN, actor, DOMAIN, 1)
    if name == "team.agent.admit":
        subject = {"team_id": TEAM, "root_id": actor, "root_key": controller,
            "child_id": child, "child_key": member_key, "member_alias": "worker",
            "admission_policy_digest": "sha256:" + "a" * 64, "expected_policy_version": 1}
    else:
        subject = {"team_id": TEAM, "root_id_or_self": actor, "member_id": child,
            "certificate_id": str(uuid4()), "expected_membership": {"member_did_key": member_key,
                "member_did_aw": child, "member_address": None, "alias": "worker", "identity_scope": "global"}}
    op = CatalogOperation(str(uuid4()), context, ORIGIN, name, "default", subject)
    artifact = artifact_for(op, controller, NOW)
    signing = signing_bytes(op, artifact)
    signature = sign_message(seed, signing)
    result = {"signing": base64.b64encode(signing).decode(),
        "signature": base64.b64encode(base64.b64decode(signature + "==")).decode()}
    key = parse_signing_key_hex(seed.hex())
    calls = []

    class CountSigning:
        def sign(self, payload):
            calls.append(payload)
            return key.sign(payload)

    # Actual delivery methods; custody file isolation remains native coverage.
    custody = object.__new__(ProtectedControllerCustody)
    custody.service_id, custody.team_id, custody.domain = context.service_id, TEAM, DOMAIN
    custody.authority_kind, custody.team_key_did, custody._key = "team_controller", controller, CountSigning()
    return op, artifact, result, custody, calls


class ObservedCachedRegistry(CachedRegistryClient):
    def __init__(self, *, lost=False):
        self.events, self.sent = [], []

        def transport(request):
            self.events.append("post")
            self.sent.append(request)
            if lost:
                raise httpx.ReadError("answer lost after effect", request=request)
            return httpx.Response(200, json={})

        super().__init__(ORIGIN, redis_client=SimpleNamespace(), transport=httpx.MockTransport(transport))

    async def _registry_url_for_domain(self, domain):
        assert domain == DOMAIN
        self.events.append("domain")
        return self.registry_url

    async def _invalidate_team_certificate_cache_keys(self, domain, name, *, tolerate_unavailable=False):
        assert tolerate_unavailable is True
        assert (domain, name) == (DOMAIN, "engineering")
        self.events.append("invalidate")

    async def invalidate_team_certificate_cache(self, domain, name):
        # Observe the existing SDK cache port. No local Redis is started.
        assert (domain, name) == (DOMAIN, "engineering")
        self.events.append("invalidate")


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["team.agent.admit", "team.agent.remove"])
@pytest.mark.parametrize("lost", [False, True])
async def test_legacy_plan_preserves_cache_fences_and_sends_one_exact_request(name, lost):
    op, artifact, result, custody, _ = fixture(name)
    client = ObservedCachedRegistry(lost=lost)
    try:
        if lost:
            with pytest.raises(RegistryError):
                await deliver_legacy(custody, client, op, artifact, result)
        else:
            await deliver_legacy(custody, client, op, artifact, result)
        assert client.events == ["domain", "invalidate", "post", "invalidate"]
        assert len(client.sent) == 1
        request = client.sent[0]
        envelope = json.loads(base64.urlsafe_b64decode(request.headers["X-AWEB-Signed-Payload"] + "=="))
        assert str(request.url) == op.audience + envelope["path"]
        if name == "team.agent.remove":
            assert request.content == b'{"certificate_id":"' + op.subject["certificate_id"].encode() + b'"}'
            assert envelope == artifact["request"]
        else:
            body = json.loads(request.content)
            assert json.loads(base64.b64decode(body["certificate"])) == {**artifact,
                "signature": base64.b64encode(base64.b64decode(result["signature"])).rstrip(b"=").decode()}
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,expected_auth_signatures", [("team.agent.remove", 0), ("team.agent.admit", 1)])
async def test_only_a_distinct_registration_envelope_needs_another_signature(name, expected_auth_signatures):
    op, artifact, result, custody, calls = fixture(name)
    client = ObservedCachedRegistry()
    try:
        deliver = custody.remove_member if name == "team.agent.remove" else custody.register_admission
        await deliver(client, op, artifact, result)
        assert len(calls) == expected_auth_signatures
        if calls:
            assert calls[0] != base64.b64decode(result["signing"])
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_a_resolved_registry_mismatch_does_not_invalidate_or_send():
    from aweb_naapp.runtime.protected_signer import SignerRefused

    op, artifact, result, custody, _ = fixture("team.agent.admit")
    client = ObservedCachedRegistry()

    async def other_origin(domain):
        client.events.append("domain")
        return "https://other.customer.example"

    client._registry_url_for_domain = other_origin
    try:
        with pytest.raises(SignerRefused, match="scope_refused"):
            await deliver_legacy(custody, client, op, artifact, result)
        assert client.events == ["domain"] and client.sent == []
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_a_changed_signed_result_never_reaches_a_cache_or_delivery_port():
    op, artifact, result, custody, _ = fixture("team.agent.remove")
    client = ObservedCachedRegistry()
    try:
        with pytest.raises(ValueError, match="signed artifact"):
            await deliver_legacy(custody, client, op, artifact,
                {**result, "signing": base64.b64encode(b"changed").decode()})
        assert client.events == [] and client.sent == []
    finally:
        await client.aclose()
