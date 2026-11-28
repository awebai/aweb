"""An issuer's human ID can act in another namespace's team (R3)."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.id_certificates import (
    encode_id_chain_header,
    sign_id_certificate,
    verify_id_chain,
)
from awid.signing import (
    VerifyResult,
    canonical_json_bytes,
    sign_message,
    verify_signature,
)
from messaging_actor_support import (
    admit_messaging_actor,
    messaging_actor_headers,
    set_messaging_inbound_mode,
)
from test_dashboard_privacy import TEAM, privacy_stack
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_team_headers,
)


@dataclass(frozen=True)
class HumanMember:
    stable_id: str
    did_key: str
    issuer_key: str
    chain: dict
    team_certificate: str
    agent_id: str


def _signer(key):
    did_key = did_from_public_key(bytes(key.verify_key))
    return lambda payload: (did_key, key.sign(payload).signature)


def _now_seconds():
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


async def _enroll_and_admit(env, registry, *, domain, alias, key):
    did_key = did_from_public_key(bytes(key.verify_key))
    identity = await registry.register_did(did_key, bytes(key))
    root = SigningKey(await env.registry.ensure_namespace(domain=domain))
    issuer = did_from_public_key(bytes(root.verify_key))
    signed = await sign_id_certificate(
        {
            "v": 1,
            "type": "aweb.id-certificate",
            "kind": "human",
            "id": identity.did_aw,
            "domain": domain,
            "parent": {"kind": "namespace", "id": domain},
            "issuer_key": issuer,
            "issued_at": _now_seconds(),
        },
        signer=_signer(root),
    )
    chain = {"v": 1, "type": "aweb.id-chain", "certificates": [signed]}
    await registry.register_id_certificate(
        chain, signer=_signer(key), expected_head=None, invitation_id=None
    )

    certificate = _make_certificate(
        env.team_sk,
        env.team_did,
        did_key,
        team_id=TEAM,
        alias=alias,
        identity_scope="global",
        member_did_aw=identity.did_aw,
        certificate_id=f"cross-domain-{uuid4()}",
    )
    await env.registry.add_certificate(certificate, team_key=SigningKey(env.team_sk))
    team_certificate = _encode_certificate(certificate)
    auth = {
        "X-AWID-ID-Chain": encode_id_chain_header(chain),
        "Content-Type": "application/json",
    }
    connect_body = b"{}"
    connected = await env.client.post(
        "/v1/connect",
        content=connect_body,
        headers={
            **auth,
            **_signed_team_headers(
                bytes(key), did_key, TEAM, team_certificate, connect_body
            ),
        },
    )
    assert connected.status_code == 200, connected.text
    member = connected.json()
    assert (member["team_id"], member["alias"], member["agent_type"]) == (
        TEAM,
        alias,
        "human",
    )
    return HumanMember(
        identity.did_aw, did_key, issuer, chain, team_certificate, member["agent_id"]
    )


async def _send_mail(env, *, key, sender, receiver):
    payload = {
        "from_did": sender.did_key,
        "subject": "Cross-domain human mail",
        "body": "Sent as a member of the receiving team.",
        "message_id": str(uuid4()),
        "conversation_id": str(uuid4()),
        "timestamp": _now_seconds(),
    }
    signed = canonical_json_bytes(
        {
            **payload,
            "type": "mail",
            "from": sender.stable_id,
            "from_stable_id": sender.stable_id,
            "to": receiver.did_key,
            "to_did": receiver.did_key,
        }
    )
    body = canonical_json_bytes(
        {
            **payload,
            "to_did": receiver.did_key,
            "new_conversation": True,
            "signed_payload": signed.decode(),
            "signature": sign_message(bytes(key), signed),
        }
    )
    response = await env.client.post(
        "/v1/messages",
        content=body,
        headers={
            **_signed_team_headers(
                bytes(key), sender.did_key, TEAM, sender.team_certificate, body
            ),
            "X-AWID-ID-Chain": encode_id_chain_header(sender.chain),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["message_id"] == payload["message_id"]
    return payload["message_id"]


@pytest.mark.asyncio
async def test_two_human_ids_from_other_domains_can_act_in_one_team(
    shared_test_pool, monkeypatch
):
    async with privacy_stack(shared_test_pool, monkeypatch, aliases=()) as env:
        registry = env.app.state.awid_registry_client
        receiver = await admit_messaging_actor(
            env, alias="reader", team_id=TEAM, address="example.test/reader"
        )
        await set_messaging_inbound_mode(env, receiver, "open")

        # One holder controls two independent keys. Neither issuer nor the
        # member certificates need a shared person identifier to admit them.
        holder_keys = [SigningKey.generate(), SigningKey.generate()]
        issuer_domains = ["first-issuer.test", "second-issuer.test"]
        senders = [
            await _enroll_and_admit(
                env, registry, domain=domain, alias=f"member-{index}", key=key
            )
            for index, (domain, key) in enumerate(
                zip(issuer_domains, holder_keys, strict=True), 1
            )
        ]
        assert len({sender.stable_id for sender in senders}) == 2
        assert len({sender.agent_id for sender in senders}) == 2
        assert len({sender.issuer_key for sender in senders}) == 2
        assert all(domain != TEAM.split(":", 1)[1] for domain in issuer_domains)

        for key, sender, domain in zip(
            holder_keys, senders, issuer_domains, strict=True
        ):
            message_id = await _send_mail(
                env, key=key, sender=sender, receiver=receiver
            )
            received = await env.client.get(
                "/v1/messages/inbox",
                params={"message_id": message_id},
                headers=messaging_actor_headers(receiver),
            )
            assert received.status_code == 200, received.text
            [mail] = received.json()["messages"]
            assert mail["message_id"] == message_id
            assert mail["from_stable_id"] == sender.stable_id
            assert mail["from_agent_id"] == sender.agent_id
            assert mail["sender_membership"] == {
                "team_id": TEAM,
                "member_did_aw": sender.stable_id,
                "state": "active",
            }
            assert mail["verification_status"] == "verified"
            assert (
                verify_signature(
                    sender.did_key, mail["signed_payload"].encode(), mail["signature"]
                )
                == VerifyResult.VERIFIED
            )
            assert mail["id_chain"] == sender.chain
            subject = {"id": sender.stable_id, "did_key": sender.did_key}
            evidence = await registry.id_chain_evidence(
                mail["id_chain"], subject, domain=domain
            )
            assert verify_id_chain(
                mail["id_chain"], subject=subject, evidence=evidence, domain=domain
            ) == {
                "outcome": "nearest_human",
                "identity_valid": True,
                "human_id": sender.stable_id,
                "kind": "human",
                "reason": "verified",
            }
