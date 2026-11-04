"""Additional real authority and topology neighbors for team-vouched routes."""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from awid.signing import canonical_json_bytes, sign_message
from test_actf_return_route import (  # noqa: F401
    route_pair, _actor, _effects, _expire_team_evidence, _federation_packet,
    _hosted_mcp_send, _publish_server, _route_rows, _send, _socket, _origin, _stored, _submission,
)
from test_messages_http import _encode_certificate, _make_keypair, _make_certificate


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("fault", ["other-member", "wrong-key", "wrong-label", "foreign-origin", "tampered-binding"])
async def test_team_route_forgery_neighbors(route_pair, kind, encrypted, fault):
    source, target = route_pair.source, route_pair.target
    sender = source.local
    if encrypted and fault == "wrong-label":
        # The optional v2 label must actually be signed for a label mismatch
        # to exercise the boundary. The team binding alone does not bind alias.
        sender = SimpleNamespace(**dict(vars(sender), address=f"{source.team_id}/{sender.alias}"))
    packet, _ = _federation_packet(sender, target.global_actor, kind, encrypted=encrypted)
    reason = "local_sender_certificate_invalid"
    if fault == "other-member":
        other = await _actor(source, "other", global_identity=False)
        packet["envelope"]["sender_certificate"] = other.encoded_certificate
    elif fault in {"wrong-key", "wrong-label"}:
        cert = dict(source.local.certificate)
        cert.pop("signature")
        key = source.team_sk
        if fault == "wrong-key":
            key, _, _ = _make_keypair()
        else:
            cert["alias"] = "another-label"
        cert["signature"] = sign_message(key, canonical_json_bytes(cert))
        packet["envelope"]["sender_certificate"] = _encode_certificate(cert)
    elif fault == "foreign-origin":
        packet["envelope"]["sender_delivery_origin"] = "https://unselected.example"
        reason = "local_sender_route_mismatch"
    elif fault == "tampered-binding":
        if encrypted:
            packet["envelope"]["encrypted_envelope"]["from"]["team_id"] = f"other:{source.domain}"
        else:
            fields = json.loads(packet["envelope"]["signed_payload"])
            fields["from"] = f"other:{source.domain}/{source.local.alias}"
            packet["envelope"]["signed_payload"] = canonical_json_bytes(fields).decode()
        reason = "federation_signature_invalid"
    before = await _effects(source), await _effects(target)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == reason, response.text
    assert response.json()["retryable"] is False
    assert (await _effects(source), await _effects(target)) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_reply_registry_connection_failure_is_retryable_and_recovers(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    response, first = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert response.status_code == 200, response.text
    await _expire_team_evidence(target)
    dns_key = (f"_awid.{source.domain}", "TXT")
    records = route_pair.dns.records[dns_key]
    sock = _socket()
    unavailable = _origin(sock)
    sock.close()
    route_pair.dns.records[dns_key] = [f'"awid=v1;controller={source.team_did};registry={unavailable}"']
    before = await _effects(source), await _effects(target)
    routes = await _route_rows(target, first.cid, source.local.did)
    response, _ = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 503, response.text
    assert response.json()["retryable"] is True
    assert "Retry shortly" in response.json()["detail"]
    assert (await _effects(source), await _effects(target)) == before
    assert await _route_rows(target, first.cid, source.local.did) == routes
    assert not source.calls.count(("POST", "/v1/federation/messages"))
    route_pair.dns.records[dns_key] = records
    response, _ = await _send(target.global_actor, source.local, kind, encrypted=encrypted, continuation=str(first.cid))
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("route_pair", [{"shared_registry": True}], indirect=True)
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_hosted_same_server_team_route_round_trip(route_pair, monkeypatch, kind, encrypted):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "disposable-actf-proxy-secret")
    source, target = route_pair.source, route_pair.target
    await source.db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,$2,'members',$3)",
                            target.team_id, target.domain, target.team_did)
    await target.registry.db.execute("UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1 WHERE domain=$2", source.origin, target.domain)
    local_target = SimpleNamespace(**dict(vars(target), db=source.db, client=source.client, server=source.server, origin=source.origin))
    recipient = await _actor(local_target, "same-server", global_identity=True)
    first = await _hosted_mcp_send(source.local, recipient, kind, encrypted=encrypted)
    assert "error" not in first, first
    reply = await _hosted_mcp_send(recipient, source.local, kind, encrypted=encrypted, continuation=first["conversation_id"])
    assert "error" not in reply, reply
    table = "messages" if kind == "mail" else "chat_messages"
    row = await source.db.fetch_one("SELECT * FROM {{tables."+table+"}} WHERE message_id=$1", UUID(reply["message_id"]))
    assert row["from_did"] == recipient.stable
    assert ("POST", "/v1/federation/messages") not in source.calls
    assert ("POST", "/v1/federation/messages") not in target.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("route_pair", [{"shared_registry": True}], indirect=True)
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_hosted_different_servers_shared_registry_round_trip(route_pair, monkeypatch, kind, encrypted):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "disposable-actf-proxy-secret")
    source, target = route_pair.source, route_pair.target
    assert source.registry_client.registry_url == target.registry_client.registry_url
    assert source.origin != target.origin
    first = await _hosted_mcp_send(source.local, target.global_actor, kind, encrypted=encrypted)
    assert "error" not in first, first
    reply = await _hosted_mcp_send(target.global_actor, source.local, kind, encrypted=encrypted,
                                    continuation=first["conversation_id"])
    assert "error" not in reply, reply
    answer = await _hosted_mcp_send(source.local, target.global_actor, kind, encrypted=encrypted,
                                     continuation=first["conversation_id"])
    assert "error" not in answer, answer
    table = "messages" if kind == "mail" else "chat_messages"
    for node, result, author in ((target, first, source.local.did),
                                  (source, reply, target.global_actor.stable),
                                  (target, answer, source.local.did)):
        row = await node.db.fetch_one("SELECT * FROM {{tables."+table+"}} WHERE message_id=$1",
                                     UUID(result["message_id"]))
        assert row is not None and row["from_did"] == author
        assert str(row["conversation_id" if kind == "mail" else "session_id"]) == first["conversation_id"]
    assert source.calls.count(("POST", "/v1/federation/messages")) == 1
    assert target.calls.count(("POST", "/v1/federation/messages")) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_established_receipt_outlives_authority_and_refuses_changed_body(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    packet, first = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    accepted = await target.client.post("/v1/federation/messages", json=packet)
    assert accepted.status_code == 200, accepted.text
    # Same ID and conversation, but genuinely signed/encrypted changed content.
    changed, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted,
        message_id=str(first.mid), continuation=str(first.cid), body="a different signed message")
    before = await _effects(target)
    routes = await _route_rows(target, first.cid, source.local.did)
    conflict = await target.client.post("/v1/federation/messages", json=changed)
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["reason"] == "federation_message_replay_conflict"
    assert await _effects(target) == before
    await source.registry.revoke(source.local.certificate["certificate_id"])
    await _expire_team_evidence(target)
    fresh, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted,
                                 continuation=str(first.cid))
    refused = await target.client.post("/v1/federation/messages", json=fresh)
    assert refused.status_code == 403, refused.text
    assert refused.json()["reason"] == "local_sender_certificate_revoked"
    await _publish_server(source, "http://127.0.0.1:1")
    await _expire_team_evidence(target)
    registry_reads, dns_reads = list(source.registry_calls), dict(route_pair.dns.queries)
    # A real unreachable DNS-selected registry, then missing DNS. Neither is
    # consulted for the already-accepted receipt (unlike a new message).
    key = (f"_awid.{source.domain}", "TXT")
    sock = _socket()
    unavailable = _origin(sock)
    sock.close()
    route_pair.dns.records[key] = [f'"awid=v1;controller={source.team_did};registry={unavailable}"']
    for missing_dns in (False, True):
        if missing_dns:
            route_pair.dns.records.clear()
        repeated = await target.client.post("/v1/federation/messages", json=packet)
        assert repeated.status_code == 200, repeated.text
        assert repeated.json() == accepted.json()
        assert await _effects(target) == before
        assert await _route_rows(target, first.cid, source.local.did) == routes
        assert source.registry_calls == registry_reads
        assert dict(route_pair.dns.queries) == dns_reads


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("fault", ["captured-recipient", "future"])
async def test_team_message_binding_and_skew_precede_admission(route_pair, kind, encrypted, fault):
    source, target = route_pair.source, route_pair.target
    created = datetime.now(timezone.utc) + timedelta(seconds=310) if fault == "future" else None
    packet, _ = _federation_packet(source.local, target.global_actor, kind,
                                    encrypted=encrypted, created_at=created)
    if fault == "captured-recipient":
        other = await _actor(target, "other-recipient", global_identity=True)
        packet["envelope"].update(target_address=other.address, target_did_aw=other.stable,
                                    target_current_did_key=other.did)
    before = await _effects(target)
    registry_reads = list(source.registry_calls)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == ("federation_timestamp_invalid" if fault == "future"
                                          else "federation_envelope_invalid")
    assert response.json()["retryable"] is False
    assert await _effects(target) == before
    assert source.registry_calls == registry_reads


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_team_rotation_reissue_renews_stored_route_at_same_origin(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    packet, first = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    accepted = await target.client.post("/v1/federation/messages", json=packet)
    assert accepted.status_code == 200, accepted.text
    source.team_sk, _, source.team_did = _make_keypair()
    await source.registry.rotate_team_key(source.team_id, source.team_did)
    await _expire_team_evidence(target)
    stale, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted,
                                 continuation=str(first.cid))
    before = await _effects(target)
    refused = await target.client.post("/v1/federation/messages", json=stale)
    assert refused.status_code == 409, refused.text
    assert refused.json()["reason"] == "local_sender_team_key_stale"
    assert await _effects(target) == before
    await source.registry.revoke(source.local.certificate["certificate_id"])
    cert = _make_certificate(source.team_sk, source.team_did, source.local.did,
        team_id=source.team_id, alias=source.local.alias, identity_scope="local")
    encoded = _encode_certificate(cert)
    await source.registry_client.register_team_certificate(
        source.domain, "members", team_controller_signing_key=source.team_sk,
        certificate_id=cert["certificate_id"], member_did_key=source.local.did,
        member_did_aw=None, member_address=None, alias=source.local.alias,
        identity_scope="local", certificate=encoded)
    await _publish_server(source, source.origin)
    source.local.certificate, source.local.encoded_certificate = cert, encoded
    renewed, sent = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted,
                                      continuation=str(first.cid))
    response = await target.client.post("/v1/federation/messages", json=renewed)
    assert response.status_code == 200, response.text
    await _stored(target.global_actor, kind, sent)
    for row in await _route_rows(target, first.cid, source.local.did):
        if row is not None:
            assert row["delivery_origin"] == source.origin
            assert row["route_certificate_id"] == cert["certificate_id"]
            assert row["route_certificate"] == encoded


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_sender_certificate_registry_hint_cannot_select_authority(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    packet, sent = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    cert = dict(source.local.certificate, registry_url=target.registry_client.registry_url)
    cert.pop("signature")
    cert["signature"] = sign_message(source.team_sk, canonical_json_bytes(cert))
    packet["envelope"]["sender_certificate"] = _encode_certificate(cert)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 200, response.text
    await _stored(target.global_actor, kind, sent)
    path = f"/v1/namespaces/{source.domain}/teams/members/certificates/{cert['certificate_id']}/status"
    assert ("GET", path) in source.registry_calls
    assert ("GET", path) not in target.registry_calls
    assert route_pair.dns.queries[(f"_awid.{source.domain}", "TXT")] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_team_and_contacts_refuses_local_first_contact(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    await target.db.execute("UPDATE {{tables.agents}} SET inbound_mode='team_and_contacts' WHERE agent_id=$1",
                            target.global_actor.id)
    packet, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    before = await _effects(target)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 403, response.text
    assert response.json()["reason"] == "recipient_policy_rejected"
    assert "public address" in response.json()["detail"]
    assert await _effects(target) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_team_label_is_not_a_contact_or_address_target(route_pair, kind):
    from test_messages_http import _signed_team_headers
    source, target = route_pair.source, route_pair.target
    label = f"{source.team_id}/{source.local.alias}"
    before = await _effects(target), await _effects(source)
    registry_reads = list(source.registry_calls)
    raw = json.dumps({"contact_address": label}).encode()
    actor = target.global_actor
    contact = await target.client.post("/v1/contacts", content=raw, headers={
        **_signed_team_headers(actor.sk, actor.did, target.team_id, actor.encoded_certificate, raw),
        "Content-Type": "application/json"})
    assert contact.status_code == 422, contact.text
    labelled = SimpleNamespace(**dict(vars(source.local), address=label))
    response, _ = await _send(actor, labelled, kind)
    assert response.status_code in {400, 422}, response.text
    assert (await _effects(target), await _effects(source)) == before
    assert source.registry_calls == registry_reads
    assert ("POST", "/v1/federation/messages") not in source.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_v2_signed_team_and_label_reach_the_decrypted_inner_header(route_pair, kind):
    from copy import deepcopy
    from aweb.e2ee_messages import decrypt_e2ee_message
    source, target = route_pair.source, route_pair.target
    sender = SimpleNamespace(**dict(vars(source.local), address=f"{source.team_id}/{source.local.alias}"))
    packet, sent = _federation_packet(sender, target.global_actor, kind, encrypted=True)
    before = await _effects(target)
    for field in ("team_id", "address"):
        changed = deepcopy(packet)
        changed["envelope"]["encrypted_envelope"]["from"][field] += "-tampered"
        response = await target.client.post("/v1/federation/messages", json=changed)
        assert response.status_code == 422, response.text
        assert response.json()["reason"] == "federation_signature_invalid"
        assert await _effects(target) == before
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 200, response.text
    row = await _stored(target.global_actor, kind, sent)
    envelope = row["encrypted_envelope"]
    if isinstance(envelope, str):
        envelope = json.loads(envelope)
    actor = target.global_actor
    inner = decrypt_e2ee_message(envelope, dict(did=actor.did, stable_id=actor.stable,
        address=actor.address, private_key=actor.encryption_private))
    assert inner["from"]["team_id"] == envelope["from"]["team_id"] == source.team_id
    assert inner["from"]["address"] == envelope["from"]["address"] == sender.address
    assert inner["body"] == sent.fields["body"]
    for route in await _route_rows(target, sent.cid, source.local.did):
        if route is not None:
            assert route["address"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_warm_authority_is_scoped_and_stored_team_cannot_change(route_pair, kind, encrypted):
    from awid.team_server_record import build_team_server_record, sign_team_server_record
    source, target = route_pair.source, route_pair.target
    first, sent = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    accepted = await target.client.post("/v1/federation/messages", json=first)
    assert accepted.status_code == 200, accepted.text
    other_sk, _, other_did = _make_keypair()
    other_team = f"other:{source.domain}"
    await source.registry.add_team(other_team, other_did, visibility="private")
    cert = _make_certificate(other_sk, other_did, source.local.did, team_id=other_team,
        alias=source.local.alias, identity_scope="local", certificate_id=source.local.certificate["certificate_id"])
    encoded = _encode_certificate(cert)
    await source.registry_client.register_team_certificate(source.domain, "other",
        team_controller_signing_key=other_sk, certificate_id=cert["certificate_id"],
        member_did_key=source.local.did, member_did_aw=None, member_address=None,
        alias=source.local.alias, identity_scope="local", certificate=encoded)
    record = build_team_server_record(other_team, other_did, source.origin, datetime.now(timezone.utc))
    await source.registry_client.publish_team_server_record(source.domain, "other", record,
                                                            sign_team_server_record(other_sk, record))
    other_node = SimpleNamespace(**dict(vars(source), team_id=other_team, team_sk=other_sk, team_did=other_did))
    other = SimpleNamespace(**dict(vars(source.local), node=other_node,
                                    certificate=cert, encoded_certificate=encoded))
    # A member can legitimately sign for either team, but cannot change an
    # existing conversation's learned team authority by signing for another.
    continuation, _ = _federation_packet(other, target.global_actor, kind, encrypted=encrypted,
                                          continuation=str(sent.cid))
    before = await _effects(target)
    routes = await _route_rows(target, sent.cid, source.local.did)
    refused = await target.client.post("/v1/federation/messages", json=continuation)
    assert refused.status_code == 422, refused.text
    assert refused.json()["reason"] == "local_sender_route_mismatch"
    assert await _effects(target) == before
    assert await _route_rows(target, sent.cid, source.local.did) == routes
    # Revoke the same certificate ID in the second team only. The original
    # team's warm active entry must not answer the other team's status request.
    await source.registry_client.revoke_team_certificate(source.domain, "other",
        team_controller_signing_key=other_sk, certificate_id=cert["certificate_id"])
    packet, _ = _federation_packet(other, target.global_actor, kind, encrypted=encrypted)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 403, response.text
    assert response.json()["reason"] == "local_sender_certificate_revoked"
    assert await _effects(target) == before
    path = f"/v1/namespaces/{source.domain}/teams/other/certificates/{cert['certificate_id']}/status"
    assert ("GET", path) in source.registry_calls
    second = await _actor(source, "second", global_identity=False)
    await source.registry.revoke(second.certificate["certificate_id"])
    packet, _ = _federation_packet(second, target.global_actor, kind, encrypted=encrypted)
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 403, response.text
    assert response.json()["reason"] == "local_sender_certificate_revoked"
    assert await _effects(target) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
@pytest.mark.parametrize("fault", ["no-server-record", "no-dns"])
async def test_missing_route_authority_gives_supported_recovery(route_pair, kind, encrypted, fault):
    source, target = route_pair.source, route_pair.target
    before = await _effects(source), await _effects(target)
    if fault == "no-server-record":
        await source.registry.db.execute("DELETE FROM {{tables.team_server_records}}")
        response, _ = await _send(source.local, target.global_actor, kind, encrypted=encrypted)
        assert response.status_code == 424, response.text
        assert response.json()["reason"] == "local_sender_team_server_missing"
        assert "set-server" in response.json()["detail"]
        assert ("POST", "/v1/federation/messages") not in target.calls
    else:
        route_pair.dns.records.pop((f"_awid.{source.domain}", "TXT"))
        packet, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
        response = await target.client.post("/v1/federation/messages", json=packet)
        assert response.status_code == 422, response.text
        assert response.json()["reason"] == "sender_registry_unresolvable"
        assert "_awid" in response.json()["detail"]
        assert "--global" in response.json()["detail"]
    assert response.json()["retryable"] is False
    assert (await _effects(source), await _effects(target)) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("encrypted", [False, True], ids=["plaintext", "v2"])
async def test_team_dns_dependency_failure_is_retryable(route_pair, kind, encrypted):
    source, target = route_pair.source, route_pair.target
    packet, _ = _federation_packet(source.local, target.global_actor, kind, encrypted=encrypted)
    before = await _effects(target)
    route_pair.dns.close()
    response = await target.client.post("/v1/federation/messages", json=packet)
    assert response.status_code == 503, response.text
    assert response.json()["reason"] == "sender_registry_discovery_failed"
    assert response.json()["retryable"] is True
    assert "Retry shortly" in response.json()["detail"]
    assert await _effects(target) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mail", "chat"])
async def test_source_refuses_encrypted_local_route_without_signed_team(route_pair, kind):
    from test_messages_http import _signed_team_headers
    source, target = route_pair.source, route_pair.target
    missing_team = SimpleNamespace(**dict(vars(source.local),
        node=SimpleNamespace(**dict(vars(source), team_id=""))))
    path, payload, _ = _submission(missing_team, target.global_actor, kind, encrypted=True)
    assert not payload["encrypted_envelope"]["from"].get("team_id")
    raw = json.dumps(payload).encode()
    before = await _effects(source), await _effects(target)
    response = await source.client.post(path, content=raw, headers={
        **_signed_team_headers(source.local.sk, source.local.did, source.team_id,
                               source.local.encoded_certificate, raw),
        "Content-Type": "application/json"})
    assert response.status_code == 422, response.text
    assert response.json()["reason"] == "local_sender_certificate_required"
    assert (await _effects(source), await _effects(target)) == before
    assert ("POST", "/v1/federation/messages") not in target.calls
