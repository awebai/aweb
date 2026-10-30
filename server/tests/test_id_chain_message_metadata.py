"""Real HTTP/PG/Redis carrier regression; metadata never changes signed bytes.

These local senders deliberately have no registry status reader, which exercises
ordinary local auth with unavailable ancestry. Receiver-side authority still
requires its own fresh evidence; this file tests transport, not DNS authority.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from nacl.signing import SigningKey
from awid.did import did_from_public_key
from awid.id_certificates import encode_id_chain_header, id_certificate_signing_bytes
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app, TEAM  # noqa: F401
from test_messages_http import _signed_identity_headers, _signed_team_headers


def _bundle(subject):
    root = SigningKey.generate()
    cert = dict(v=1, type='aweb.id-certificate', id=subject,
                domain='metadata.example.test', parent={'kind': 'namespace', 'id': 'metadata.example.test'},
                kind='agent', issuer_key=did_from_public_key(bytes(root.verify_key)),
                issued_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    signature = root.sign(id_certificate_signing_bytes(cert)).signature
    return dict(v=1, type='aweb.id-chain', certificates=[dict(
        certificate=cert, signature=base64.urlsafe_b64encode(signature).decode().rstrip('='))])


def _headers(actor, body=b'', *, lane='identity', chain=None):
    headers = (_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
               if lane == 'team' else _signed_identity_headers(actor.sk, actor.did, '', body))
    headers['Content-Type'] = 'application/json'
    if chain is not None:
        headers['X-AWID-ID-Chain'] = encode_id_chain_header(chain)
    return headers


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
@pytest.mark.parametrize('lane', ['identity', 'team'])
async def test_message_chain_round_trips_without_altering_signed_message(privacy_app, kind, lane):
    env = privacy_app
    sender, recipient = env.actors['alice'], env.actors['bob']
    chain = _bundle(sender.did)
    message_id, timestamp = str(uuid4()), datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    signed = dict(type=kind, message_id=message_id, timestamp=timestamp,
                  from_did=sender.did, to=recipient.did, body='real signed message')
    # 'from' is a signed label only; author binding uses from_did.
    signed['from'] = sender.did
    if kind == 'mail':
        signed.update(subject='metadata', priority='normal')
        payload = dict(to_did=recipient.did, subject='metadata', body=signed['body'])
        endpoint = '/v1/messages'
    else:
        signed.update(wait_seconds=None, reply_to=None, sender_leaving=False, hang_on=False)
        payload = dict(to_dids=[recipient.did], message=signed['body'])
        endpoint = '/v1/chat/sessions'
    canonical = canonical_json_bytes(signed).decode()
    signature = sign_message(sender.sk, canonical.encode())
    payload.update(message_id=message_id, timestamp=timestamp, from_did=sender.did,
                   signed_payload=canonical, signature=signature)
    body = json.dumps(payload).encode()
    sent = await env.client.post(endpoint, content=body, headers=_headers(sender, body, lane=lane, chain=chain))
    assert sent.status_code == 200, sent.text
    if kind == 'mail':
        exact = f'/v1/messages/{message_id}'
        index = '/v1/messages/inbox'
    else:
        exact = index = f"/v1/chat/sessions/{sent.json()['session_id']}/messages"
    read = await env.client.get(exact, headers=_headers(recipient))
    assert read.status_code == 200, read.text
    item = read.json() if kind == 'mail' else read.json()['messages'][0]
    assert item['id_chain'] == chain
    assert item['from_did'] == sender.did
    assert item['signed_payload'] == canonical
    assert item['signature'] == signature
    indexed = await env.client.get(index, headers=_headers(recipient))
    assert indexed.status_code == 200, indexed.text
    assert next(m for m in indexed.json()['messages'] if m['message_id'] == message_id)['id_chain'] == chain
    table = '{{tables.messages}}' if kind == 'mail' else '{{tables.chat_messages}}'
    stored = await env.db.fetch_val(f'SELECT id_chain FROM {table} WHERE message_id=$1', UUID(message_id))
    assert (json.loads(stored) if isinstance(stored, str) else stored) == chain


@pytest.mark.asyncio
@pytest.mark.parametrize('lane', ['identity', 'team'])
async def test_another_authors_chain_refuses_before_message_storage(privacy_app, lane):
    env = privacy_app
    sender, recipient = env.actors['alice'], env.actors['bob']
    body = json.dumps(dict(to_did=recipient.did, body='must not be stored')).encode()
    before = await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}')
    result = await env.client.post('/v1/messages', content=body,
                                  headers=_headers(sender, body, lane=lane, chain=_bundle(recipient.did)))
    assert result.status_code == 403, result.text
    assert result.json()['detail'] == 'subject_mismatch'
    assert await env.db.fetch_val('SELECT count(*) FROM {{tables.messages}}') == before
