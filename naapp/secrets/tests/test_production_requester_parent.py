"""Production handoffs use the runtime's real ID-chain resolver and holding.

The holder's credential handoff precedes controller designation and the first
session start. No holder session or direct cache insert prepares the requester.
"""

import base64
import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import dns.asyncresolver as dns_api
import httpx
import pytest
from aweb_naapp.hooks.owner_act import HumanCredential
from aweb_naapp_testing import Member, did_key
from aweb_naapp_testing.network import DnsServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.dns_verify import awid_txt_value
from awid.id_certificates import (
    encode_id_chain_header,
    id_certificate_signing_bytes,
    verify_id_chain,
)
from nacl.signing import SigningKey

from tests.human_owner import b64, fixture_principal, human
from tests.test_handoff_sessions import signed_request
from tests.test_owner_delivery import PATH, delivery, effects
from tests.test_production_bootstrap import root as root
from tests.test_production_handoffs import start_request

pytestmark = pytest.mark.parametrize(
    "root", [{"manifest_version": 3, "real_identity_dns": True}], indirect=True
)


async def collect_credential(root, holder, principal):
    """Use the real H-signed start, browser ceremony and key-bound result."""
    service, client, settings, *_ = root
    key, verifier, raw, headers = start_request(root, holder, principal)
    started = await client.post(settings.public_origin + "/handoffs", content=raw, headers=headers)
    assert started.status_code == 201, started.text
    handoff = started.json()["handoff_id"]
    prefix = settings.console_origin + f"/handoff/{handoff}/credential"
    # The ceremony runs in the holder's browser, which keeps its own cookies;
    # the controller's later delivery must not carry them.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as browser_client:
        state = await browser_client.get(prefix)
        assert state.status_code == 200, state.text
        browser = {"Origin": settings.console_origin, "X-CSRF-Token": state.json()["csrf_token"]}
        options = await browser_client.post(prefix + "/options", json={}, headers=browser)
        assert options.status_code == 200, options.text
        device = SoftAuthenticator(settings.console_origin)
        completed = await browser_client.post(
            prefix + "/complete",
            json={"credential": device.create(options.json())},
            headers=browser,
        )
        assert completed.status_code == 200, completed.text
    code = parse_qs(urlsplit(completed.json()["redirect_uri"]).query)["code"][0]
    path = f"/handoffs/{handoff}/result"
    raw = json.dumps({"v": 1, "code": code, "verifier": verifier}).encode()
    result = await client.post(
        settings.console_origin + path,
        content=raw,
        headers=signed_request(key, settings.console_origin, "POST", path, raw, session_id=handoff),
    )
    assert result.status_code == 200, result.text
    return result.json()["credential"]


async def agent(registry, sdk, parent, chain, *, alias):
    """Publish a genuine child identity and its independently signed team certificate."""
    member = Member(
        team_id=parent.team_id,
        team_key=parent.team_key,
        member_key=SigningKey.generate(),
        certificate_id=alias,
        alias=alias,
    )
    principal = (await sdk.register_did(member.did_key, bytes(member.member_key))).did_aw
    member.extra_cert_fields = {"member_did_aw": principal}
    fields = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": principal,
        "domain": "example.com",
        "parent": {"kind": "identity", "id": parent.extra_cert_fields["member_did_aw"]},
        "kind": "agent",
        "issuer_key": parent.did_key,
        "issued_at": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed = {
        "certificate": fields,
        "signature": b64(parent.member_key.sign(id_certificate_signing_bytes(fields)).signature),
    }
    bundle = {"v": 1, "type": "aweb.id-chain", "certificates": [*chain, signed]}
    await sdk.register_id_certificate(
        bundle,
        signer=lambda payload: (member.did_key, member.member_key.sign(payload).signature),
        expected_head=None,
        invitation_id=None,
    )
    await registry.add_certificate(member.certificate())
    return member, bundle["certificates"]


@pytest.mark.parametrize(
    "requester,status,code",
    [
        ("holder", 201, None),
        ("child", 201, None),
        ("grandchild", 403, "scope_not_signer"),
        ("other_parent", 403, "scope_not_signer"),
        ("no_chain", 403, "scope_not_signer"),
        ("missing_certificate", 403, "principal_not_member"),
    ],
)
async def test_first_session_start_resolves_the_requester_from_runtime_evidence(
    root, registry, monkeypatch, requester, status, code
):
    service, client, settings, member, installed, *_ = root
    body, principal, _ = await delivery(root, registry)
    world = client.owner_delivery_fixture
    # The production SDK verifies actual TXT evidence through a private DNS
    # server, rather than substituting an identity or requester check.
    dns = DnsServer(
        records={
            ("_awid.example.com", "TXT"): ['"' + awid_txt_value(did_key(world.human_root)) + '"']
        }
    )
    await dns.start()
    resolver = dns_api.Resolver(configure=False)
    resolver.nameservers, resolver.port = ["127.0.0.1"], dns.port
    monkeypatch.setattr(dns_api, "default_resolver", resolver)
    try:
        holder = world.human_members[principal]
        if requester != "missing_certificate":
            body["credential"] = await collect_credential(root, holder, principal.principal_did)
            subject = json.loads(base64.b64decode(body["signing"]).split(b"\n", 1)[1])["subject"]
            subject["credential_sha256"] = HumanCredential.parse(body["credential"]).sha256
            signing, signature = world.owner.sign("human-role.designate", subject)
            body.update(signing=base64.b64encode(signing).decode(), signature=signature)
        designated = await client.post(settings.console_origin + PATH, json=body)
        assert designated.status_code == 200, designated.text
        db = service.runtime.db()
        assert await db.fetch_value("SELECT count(*) FROM console_holding_certificates") == 0
        assert await db.fetch_value("SELECT certificate IS NOT NULL FROM role_holdings")
        chain = [world.human_identities[principal]]
        signer = holder
        if requester != "holder":
            parent = holder
            if requester == "other_parent":
                other = fixture_principal(member.team_id, "bob")
                async with human(world, other) as (parent, _):
                    chain = [world.human_identities[other]]
            async with human(world, principal) as (_, sdk):
                signer, chain = await agent(registry, sdk, parent, chain, alias="requester-child")
                if requester == "grandchild":
                    signer, chain = await agent(
                        registry, sdk, signer, chain, alias="requester-grandchild"
                    )
        if requester == "missing_certificate":
            # A legacy holding without retained evidence cannot borrow the
            # requester's certificate to establish the human's membership.
            await db.execute("UPDATE role_holdings SET certificate=NULL")
        before = await effects(service, installed["installation_id"], member.team_id)
        handoffs_before = await db.fetch_value("SELECT count(*) FROM console_handoffs")
        _, _, raw, headers = start_request(root, signer, principal.principal_did, purpose="session")
        if requester not in {"holder", "no_chain"}:
            headers["X-AWID-ID-Chain"] = encode_id_chain_header(
                {"v": 1, "type": "aweb.id-chain", "certificates": chain}
            )
        if requester in {"child", "missing_certificate"}:
            # The direct child's chain must hold under the runtime's own
            # evidence; otherwise any refusal below says nothing about the
            # holding. The result carries only outcome codes.
            bundle = {"v": 1, "type": "aweb.id-chain", "certificates": chain}
            subject = {"id": signer.extra_cert_fields["member_did_aw"], "did_key": signer.did_key}
            evidence = await service.runtime.registry_client().id_chain_evidence(
                bundle, subject, domain="example.com"
            )
            verified = verify_id_chain(
                bundle, subject=subject, evidence=evidence, domain="example.com"
            )
            assert (verified.get("identity_valid"), verified.get("kind")) == (True, "agent"), {
                key: verified.get(key) for key in ("outcome", "reason", "identity_valid", "kind")
            }
        started = await client.post(
            settings.public_origin + "/handoffs", content=raw, headers=headers
        )
        assert started.status_code == status, started.text
        assert await effects(service, installed["installation_id"], member.team_id) == before
        assert await db.fetch_value("SELECT count(*) FROM console_sessions") == 0
        if code:
            assert started.json()["detail"] == code
            assert await db.fetch_value("SELECT count(*) FROM console_handoffs") == handoffs_before
            return
        handoff = started.json()["handoff_id"]
        state = await client.get(settings.console_origin + f"/handoff/{handoff}/session")
        assert state.status_code == 200, state.text
        assert state.json()["scope"]["principal"] == principal.principal_did
        if requester == "holder":
            assert state.json()["requester"] is None
        else:
            fingerprint = hashlib.sha256(signer.did_key.encode()).hexdigest()[:16]
            assert state.json()["requester"] == {
                "id": signer.extra_cert_fields["member_did_aw"],
                "address": None,
                "key_fingerprint": " ".join(fingerprint[i : i + 4] for i in range(0, 16, 4)),
            }
        assert dns.queries[("_awid.example.com", "TXT")] > 0
    finally:
        dns.close()
