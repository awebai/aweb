"""Frozen S4 contact-trust case through real AWID/aweb HTTP and Postgres.

The existing privacy fixture supplies disposable apps, databases and Redis.
Only initial namespace/contact state is provisioned directly. Address replacement,
resolution, request authentication and explicit contact binding use real routes.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.activation import build_federation_authority_activation
from aweb.messaging.contacts import add_contact, has_exact_active_identity_contact
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import _request, privacy_app  # noqa: F401


_VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / 'docs/vectors/id-certificates-v1.json').read_text()
)
_CASE_NAME = 'address-replacement-does-not-transfer-contact-trust'
_CASES = [case for case in _VECTORS['operation_cases'] if case['name'] == _CASE_NAME]
assert len(_CASES) == 1, 'S4 must consume the frozen operation case by name'


@pytest.mark.asyncio
@pytest.mark.parametrize('case', _CASES, ids=lambda case: case['name'])
async def test_address_replacement_does_not_transfer_contact_trust(privacy_app, monkeypatch, case):
    env = privacy_app
    domain, name = 'example.test', 'responsible-human'
    address = f'{domain}/{name}'
    owner_did = env.actors['bob'].did
    root = _VECTORS['keys']['root']
    root_seed = bytes.fromhex(root['seed_hex'])
    old = _VECTORS['keys'][case['input']['old_human']]
    replacement = _VECTORS['keys'][case['input']['new_human']]

    async def trusted(did):
        return await has_exact_active_identity_contact(
            env.infra, owner_did=owner_did,
            contact_address=address, contact_did_aw=did,
        )

    async with registry_listener(env) as (registry, registry_origin):
        for identity in (old, replacement):
            registered = await registry.register_did(
                identity['did_key'], bytes.fromhex(identity['seed_hex']),
            )
            assert registered.did_aw == identity['did_aw']
        namespace_id = await env.registry_db.fetch_val(
            '''INSERT INTO {{tables.dns_namespaces}}
               (domain, controller_did, verification_status, last_verified_at,
                default_delivery_origin)
               VALUES ($1, $2, 'verified', clock_timestamp(), $3)
               RETURNING namespace_id''',
            domain, root['did_key'], str(env.client.base_url).rstrip('/'),
        )
        await env.registry_db.execute(
            '''INSERT INTO {{tables.public_addresses}} (namespace_id, name, did_aw)
               VALUES ($1, $2, $3)''',
            namespace_id, name, old['did_aw'],
        )
        contact = await add_contact(
            env.infra, owner_did=owner_did, contact_address=address,
            contact_did_aw=old['did_aw'], binding_controller_did=root['did_key'],
            label='Responsible human',
        )
        assert await trusted(old['did_aw'])
        assert not await trusted(replacement['did_aw'])

        # Use the guarded disposable-registry composition, not a fake resolver.
        monkeypatch.setenv('APP_ENV', 'development')
        monkeypatch.setenv('AWEB_FEDERATION_TEST', '1')
        monkeypatch.setenv('AWEB_FEDERATION_TEST_DEFAULT_REGISTRY', '1')
        monkeypatch.setenv('AWID_REGISTRY_URL', registry_origin)
        authority = build_federation_authority_activation(
            env.infra, public_origin=str(env.client.base_url).rstrip('/'),
        )
        env.app.state.federation_authority = authority
        try:
            before = await registry.resolve_address(domain, name)
            reassigned = await registry.reassign_address(
                domain, name, replacement['did_aw'], root_seed,
            )
            assert before.did_aw == old['did_aw']
            assert reassigned.did_aw == replacement['did_aw']

            listed = await _request(env, 'bob', 'GET', '/v1/contacts')
            assert listed.status_code == 200, listed.text
            saved = next(row for row in listed.json()['contacts'] if row['contact_id'] == contact['contact_id'])
            assert saved['contact_did_aw'] == old['did_aw']
            assert saved['contact_address'] == address
            assert await trusted(old['did_aw'])
            assert not await trusted(replacement['did_aw'])

            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            announcement = canonical_json_bytes({
                'address': address, 'controller_did': root['did_key'],
                'old_did': old['did_aw'], 'new_did': replacement['did_aw'],
                'timestamp': timestamp,
            })
            payload = {
                'address': address, 'expected_old_did_aw': old['did_aw'],
                'new_did_aw': replacement['did_aw'], 'controller_did': root['did_key'],
                'timestamp': timestamp, 'signature': sign_message(root_seed, announcement),
                'accept_reassignment': False,
            }
            path = f"/v1/contacts/{contact['contact_id']}/bind"
            refused = await _request(env, 'bob', 'POST', path, payload)
            observed = {
                'address_preserved': reassigned.address_id == before.address_id,
                'automatic_contact_rebind': saved['contact_did_aw'] == replacement['did_aw'],
                'explicit_contact_rebind_required': refused.is_error,
            }
            assert observed == case['expected']
            assert refused.json()['reason'] == 'contact_identity_binding_required'
            assert await trusted(old['did_aw'])
            assert not await trusted(replacement['did_aw'])

            accepted = await _request(env, 'bob', 'POST', path, payload | {'accept_reassignment': True})
            assert accepted.status_code == 200, accepted.text
            assert accepted.json()['contact_id'] == contact['contact_id']
            assert accepted.json()['contact_address'] == address
            assert accepted.json()['contact_did_aw'] == replacement['did_aw']
            assert not await trusted(old['did_aw'])
            assert await trusted(replacement['did_aw'])
        finally:
            await authority.aclose()
