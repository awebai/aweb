"""Real source/receiver routes: unknown source kind, authoritative receiver."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from aweb.api import create_app
from aweb.mcp.auth import AuthContext
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from aweb.mcp.tools import chat as mcp_chat
from awid.registry import Address, AddressDelivery, KeyResolution, IDTreeEnrollment
from awid.signing import canonical_json_bytes, sign_message
from federation_activation_support import TestFederationAuthority
from identity_binding_support import seed_verified_bindings
from test_chat_http import _make_keypair, _signed_identity_headers
from test_federation_preactivation_harness import two_receiver_databases  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('adapter', ['http', 'mcp'])
@pytest.mark.parametrize('existing', [False, True])
async def test_remote_human_refusal_keeps_typed_body_through_source(two_receiver_databases, monkeypatch, adapter, existing):
    source_db, receiver_db = two_receiver_databases
    alice_key, _, alice_key_did = _make_keypair()
    _, _, bob_key_did = _make_keypair()
    facts = {
        'did:aw:alice': (alice_key_did, 'alpha.test/alice', 'https://alpha.test'),
        'did:aw:bob': (bob_key_did, 'beta.test/bob', 'https://beta.test'),
    }
    apps = []
    kind_lookups = []
    for db, name in [(source_db, 'alice'), (receiver_db, 'bob')]:
        key, address, origin = facts['did:aw:' + name]
        domain = address.split('/')[0]
        team = 't:' + domain
        await db.execute("INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,$2,'t',$3)", team, domain, key)
        actor = await db.fetch_val("""INSERT INTO {{tables.agents}}
            (team_id,alias,did_key,did_aw,did_aw_verified_key,address,identity_scope,inbound_mode)
            VALUES ($1,$2,$3,$4,$3,$5,'global','open') RETURNING agent_id""", team, name, key, 'did:aw:' + name, address)
        registry = AsyncMock()
        async def resolve_key(did):
            key, _, _ = facts[did]
            return KeyResolution(did, key, id_tree=IDTreeEnrollment(False, None))
        async def resolve_kind(did):
            kind_lookups.append(did)
            # No tree enrollment or human classification at the source.
            key, _, _ = facts[did]
            return KeyResolution(did, key, id_tree=None if did == 'did:aw:bob' else IDTreeEnrollment(False, None))
        async def resolve_address(domain, name, **kwargs):
            did = 'did:aw:' + name
            key, address, origin = facts[did]
            assert address == f'{domain}/{name}'
            return Address(address_id=name, domain=domain, name=name, did_aw=did,
                           current_did_key=key, reachability='public',
                           created_at='2026-10-31T00:00:00Z', delivery=AddressDelivery(origin=origin))
        registry.resolve_key.side_effect = resolve_key
        registry.resolve_key_fresh.side_effect = resolve_kind
        registry.resolve_address.side_effect = resolve_address
        registry.resolve_address_fresh.side_effect = resolve_address
        async def list_addresses(did, **kwargs):
            _, address, _ = facts[did]
            return [await resolve_address(*address.split('/'))]
        registry.list_did_addresses.side_effect = list_addresses
        registry.registry_url = 'https://registry.test'
        registry.registry_audience.return_value = 'https://registry.test'
        infra = SimpleNamespace(get_manager=lambda _, manager=db: manager)
        app = create_app()
        app.state.db = infra
        app.state.redis = None
        app.state.rate_limiter = None
        app.state.awid_registry_client = registry
        app.state.public_origin = origin
        app.state.federation_authority = TestFederationAuthority(db, registry)
        app.state.on_mutation = None
        seed_verified_bindings(app, ('did:aw:' + name, key, address))
        apps.append((app, infra, registry, actor))
    source, receiver = apps
    transport = httpx.ASGITransport(app=receiver[0])
    source[0].state.federation_chat_transport = transport
    auth = AuthContext(team_id='t:alpha.test', agent_id=str(source[3]), workspace_id=str(uuid4()), alias='alice',
                       did_key=alice_key_did, did_aw='did:aw:alice', address='alpha.test/alice', trusted_proxy=True)
    monkeypatch.setattr(mcp_chat, 'get_auth', lambda: auth)
    async def signer(**kwargs):
        payload = canonical_signed_payload(kwargs['payload'])
        return HostedMessageSigningResult(from_did=alice_key_did, signing_key_id=alice_key_did,
                                           signed_payload=payload, signature=sign_message(alice_key, payload.encode()))
    async def send(cid, *, continuation=False):
        if adapter == 'mcp':
            result = json.loads(await mcp_chat.chat_send(
                source[1], None, registry_client=source[2], federation_authority=source[0].state.federation_authority,
                hosted_signer=signer, message='hello', plaintext=True, leaving=True,
                federation_transport=transport, public_origin='https://alpha.test',
                **({'session_id': cid} if continuation else {'to_address': 'beta.test/bob'})))
            return result
        mid = str(uuid4())
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        signed = canonical_json_bytes(dict(type='chat', from_did=alice_key_did, from_stable_id='did:aw:alice',
            body='hello', conversation_id=cid, message_id=mid, timestamp=timestamp, sender_leaving=True,
            to='beta.test/bob', to_did=bob_key_did, to_stable_id='did:aw:bob', **{'from': 'alpha.test/alice'})).decode()
        payload = dict(from_did=alice_key_did, message_id=mid, timestamp=timestamp,
                       signature=sign_message(alice_key, signed.encode()), signed_payload=signed)
        if continuation:
            path = f'/v1/chat/sessions/{cid}/messages'
            payload.update(body='hello', leaving=True)
        else:
            path = '/v1/chat/sessions'
            payload.update(session_id=cid, to_addresses=['beta.test/bob'], message='hello', leaving=True)
        body = json.dumps(payload).encode()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=source[0]), base_url='https://alpha.test') as client:
            response = await client.post(path, content=body, headers={'Content-Type': 'application/json',
                **_signed_identity_headers(alice_key, alice_key_did, 'did:aw:alice', body)})
        return {'http_status': response.status_code, **response.json()}
    # Same real path reaches an agent before it reaches an authoritative human.
    control = await send(str(uuid4()))
    assert 'error' not in control and control.get('http_status', 200) == 200, control
    cid = control['session_id']
    assert await receiver_db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == 1
    await receiver_db.execute("UPDATE {{tables.agents}} SET agent_type='human' WHERE did_aw='did:aw:bob'")
    refused = await send(cid if existing else str(uuid4()), continuation=existing)
    assert refused.get('http_status', 422) == 422, refused
    assert refused.get('reason') == 'recipient_human_mail_only', refused
    assert refused['retryable'] is False
    assert refused['recipients'] == ['beta.test/bob']
    assert 'did:aw:bob' in kind_lookups
    assert await source_db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == 1
    assert await receiver_db.fetch_val('SELECT count(*) FROM {{tables.chat_messages}}') == 1
    assert await receiver_db.fetch_val('SELECT count(*) FROM {{tables.message_ingress_receipts}}') == 1
