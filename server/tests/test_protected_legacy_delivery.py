"""Closed legacy transport/auth controls, with no DB or external service."""

from contextlib import aclosing

import base64
import json
from datetime import UTC, datetime, timedelta
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
    from aweb_naapp.runtime.protected_signer import SignerRefused

    op, artifact, result, custody, _ = fixture("team.agent.remove")
    client = ObservedCachedRegistry()
    try:
        with pytest.raises(SignerRefused, match="operation_mismatch"):
            await deliver_legacy(custody, client, op, artifact,
                {**result, "signing": base64.b64encode(b"changed").decode()})
        assert client.events == [] and client.sent == []
    finally:
        await client.aclose()



@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["team.agent.admit", "team.agent.remove"])
@pytest.mark.parametrize("lost", [False, True])
async def test_service_owned_send_preserves_sdk_cache_fences(name, lost):
    from aweb_naapp.runtime.protected_signer.retention import FrozenDelivery, RetainedEffect
    from awid.protected_effect import HEADER, artifact_digest
    op, artifact, result, custody, calls = fixture(name)
    signing, signature = base64.b64decode(result["signing"]), base64.b64decode(result["signature"])
    _, delivery = custody.authenticate_delivery(op, artifact, signing, signature)
    frozen = FrozenDelivery(delivery.audience, delivery.method, delivery.path,
        {**delivery.headers, HEADER: "transport-only-fixture"}, delivery.body)
    retained = RetainedEffect(op.operation_id, signing, signature,
        artifact_digest(signing, base64.b64encode(signature).rstrip(b"=").decode()),
        NOW + timedelta(seconds=60), frozen, "transport-only-fixture")
    async with aclosing(ObservedCachedRegistry(lost=lost)) as registry:
        custody.configure_effects(registry=registry, clients={ORIGIN: registry._http_client}, clock=lambda: NOW)
        if lost:
            with pytest.raises(httpx.ReadError):
                await custody.deliver_retained(op, retained)
        else:
            await custody.deliver_retained(op, retained)
        expected = "invalidate"
        assert registry.events == [expected, "post", expected]
        assert len(registry.sent) == 1
    assert len(calls) == (1 if name == "team.agent.admit" else 0)


def _other_signature(signing: bytes) -> str:
    """A valid Ed25519 signature over the same bytes, by a key that is not the controller's."""
    seed, _ = generate_keypair()
    return base64.b64encode(base64.b64decode(sign_message(seed, signing) + "==")).decode()


def _controller_signature_over(custody, payload: bytes) -> str:
    """The controller's own valid signature, over bytes that are not this operation's."""
    return base64.b64encode(custody._key.sign(payload).signature).decode()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["team.agent.admit", "team.agent.remove"])
@pytest.mark.parametrize("case", ["other_key_signature", "unrelated_signed_bytes", "changed_artifact",
                                  "other_custody_key", "other_scope"])
async def test_only_the_verified_signed_artifact_of_this_custodys_operation_is_authenticated(name, case):
    from aweb_naapp.runtime.protected_signer import SignerRefused

    op, artifact, result, custody, calls = fixture(name)
    signing = base64.b64decode(result["signing"])
    if case == "other_key_signature":
        result = {**result, "signature": _other_signature(signing)}
    elif case == "unrelated_signed_bytes":
        unrelated = signing + b" "
        result = {"signing": base64.b64encode(unrelated).decode(),
                  "signature": _controller_signature_over(custody, unrelated)}
    elif case == "changed_artifact":
        field = "alias" if "alias" in artifact else "certificate_id"
        artifact = {**artifact, field: "changed"}
    elif case == "other_custody_key":
        custody.team_key_did = did_from_public_key(generate_keypair()[1])
    else:
        custody.team_id = "other:customer.example"
    calls.clear()
    client = ObservedCachedRegistry()
    try:
        with pytest.raises((SignerRefused, ValueError)):
            await deliver_legacy(custody, client, op, artifact, result)
        assert calls == [] and client.sent == []
    finally:
        await client.aclose()


def test_the_controller_key_is_used_only_by_custody_methods():
    from pathlib import Path

    package = Path(__file__).resolve().parents[1] / "src" / "aweb" / "protected_signing"
    users = sorted(path.name for path in package.glob("*.py") if "._key." in path.read_text())
    assert users == ["custody.py"], users
