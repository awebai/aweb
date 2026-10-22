"""P8 consumes shared authority/signature cases; context JSON is fixture-only."""
from dataclasses import replace
from datetime import datetime
import json
from pathlib import Path
import hashlib

import pytest

from aweb.human_channels.contract import ContractError, canonical_record, decode_record
from aweb.human_channels.presence import (
    PresenceIdentity, PresenceGrant, PresenceCaller, PresenceOwnershipPin,
    PresenceVerificationContext, PresenceVerifier, sign_presence_record,
    verify_native_presence, verify_presence_binding,
)
ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / 'docs/vectors/human-channels-presence-v1.json').read_text())


def record(schema, value):
    return decode_record(schema, json.dumps(value).encode())


def identity(value):
    return None if value is None else PresenceIdentity(**value)


def subject(value):
    return record('NativeParticipant' if value['kind'] == 'native' else 'BridgedParticipant', value)


def context_from_fixture(value):
    """A test adapter, deliberately not a public request/context deserializer."""
    values = dict(value)
    values['subject'] = subject(value['subject'])
    values['scope'] = record('PresenceScope', value['scope'])
    values['subject_identity'] = identity(value['subject_identity'])
    values['now'] = datetime.fromisoformat(value['now'].replace('Z', '+00:00'))
    values['consumed_request_ids'] = frozenset(value['consumed_request_ids'])
    caller = value['caller']
    grant = caller['grant']
    if grant is not None:
        grant = PresenceGrant(frozenset(grant['scopes']), datetime.fromisoformat(grant['expires_at'].replace('Z', '+00:00')) if grant['expires_at'] else None, grant['never_expires'])
    values['caller'] = PresenceCaller(identity(caller['identity']), caller['action_authorized'], grant)
    pin = value['ownership_pin']
    if pin is not None:
        pin = PresenceOwnershipPin(subject(pin['subject']), pin['audience'], identity(pin['owner']), identity(pin['issuer']), pin['authorization_revision'])
    values['ownership_pin'] = pin
    return PresenceVerificationContext(**values)


def verify(case):
    artifact = record('SignedArtifact', case['artifact'])
    function = verify_native_presence if case['family'] == 'native' else verify_presence_binding
    return function(artifact, context_from_fixture(case['context']))


@pytest.mark.parametrize('case', VECTORS['valid'], ids=lambda c: c['name'])
def test_shared_presence_acceptance(case):
    assert verify(case).value == case['expected']
    intent = record('PresenceIntent' if case['family'] == 'native' else 'PresenceBindingIntent', json.loads(case['artifact']['signed_payload']))
    signed = sign_presence_record(intent, bytes.fromhex(VECTORS['public_test_seeds'][case['key']]))
    assert signed.value == case['artifact']


@pytest.mark.parametrize('case', VECTORS['invalid'], ids=lambda c: c['name'])
def test_shared_presence_refusal(case):
    with pytest.raises(ContractError) as error:
        verify(case)
    assert error.value.code == case['error']


@pytest.mark.asyncio
async def test_public_port_binds_real_auth_identity_and_grant_to_context():
    from aweb.identity_auth_deps import MessagingAuth
    from aweb.auth_context import GrantContext
    case = VECTORS['valid'][0]
    ctx = context_from_fixture(case['context'])
    class Provider:
        async def resolve(self, auth, intent):
            return ctx
    service = PresenceVerifier(Provider())
    auth = MessagingAuth(did_key=ctx.caller.identity.signing_key_id, did_aw=None, address=None)
    artifact = record('SignedArtifact', case['artifact'])
    assert (await service.verify_presence(auth, artifact)).value == case['expected']
    with pytest.raises(ContractError, match='authenticated caller binding'):
        await service.verify_presence(replace(auth, did_key='did:key:zWrong'), artifact)
    grant = GrantContext('11111111-1111-4111-8111-111111111111', 'did:key:zSession', None, ('mail.send',), ctx.now, True)
    with pytest.raises(ContractError, match='authenticated grant binding'):
        await service.verify_presence(replace(auth, grant=grant), artifact)


# This is a host embedding fixture, not a new OSS or Cloud production route.
# Public request auth, registry resolution and verification execute unchanged.
from datetime import timedelta, timezone
import asyncio
import os
from uuid import uuid4
from fastapi import Depends, HTTPException, Request
from awid.did import stable_id_from_did_key
from aweb.identity_auth_deps import get_messaging_auth
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize('global_subject,owner_lane,rotated', [(False, False, False), (True, False, False), (True, True, False), (True, False, True)])
async def test_live_go_signature_public_identity_and_python_host_verification(privacy_app, tmp_path, global_subject, owner_lane, rotated):
    env = privacy_app
    registry = env.app.state.awid_registry_client
    # Current public authority is read from the real AWID application. Test DB
    # writes provision identities only, never fabricate a presence or owner proof.
    identities = {}
    for name in ('alice', 'bob', 'carol'):
        actor = env.actors[name]
        stable = stable_id_from_did_key(actor.did)
        await registry.register_did(actor.did, actor.sk)
        resolution = await registry.resolve_key_fresh(stable)
        assert resolution.current_did_key == actor.did
        identities[name] = PresenceIdentity(stable if global_subject else actor.did, resolution.current_did_key, True)
        await env.db.execute("UPDATE {{tables.agents}} SET identity_scope=$1, did_aw=$2, certificate_id=$3 WHERE agent_id=$4",
                             'global' if global_subject else 'local', stable if global_subject else None, 'privacy-' + name, actor.id)
    old_key = None
    if rotated:
        from test_messages_http import _make_keypair
        actor = env.actors['alice']
        old_key = (actor.sk, actor.did)
        new_seed, _, new_did = _make_keypair()
        stable = identities['alice'].principal
        await registry.rotate_key(stable, new_did, actor.sk, new_seed)
        current = await registry.resolve_key_fresh(stable)
        assert current.current_did_key == new_did
        await env.db.execute('UPDATE {{tables.agents}} SET did_key=$1 WHERE agent_id=$2', new_did, actor.id)
        actor.sk, actor.did = new_seed, new_did
        identities['alice'] = PresenceIdentity(stable, current.current_did_key, True)
    selected = identities['alice']
    subject_ref = subject({'kind': 'native', 'did': selected.principal})
    audience = str(env.client.base_url).rstrip('/')
    pin = PresenceOwnershipPin(subject_ref, audience, identities['bob'], identities['carol'], 'owner-4')

    class Provider:
        def __init__(self, owner_pin):
            self.owner_pin = owner_pin

        async def resolve(self, auth, intent):
            current = await registry.resolve_key_fresh(selected.principal if global_subject else stable_id_from_did_key(env.actors['alice'].did))
            assert current.current_did_key == selected.signing_key_id
            caller = PresenceIdentity(auth.did_aw or auth.did_key, auth.did_key, True)
            # Permit authenticated teammates at the action-policy layer so
            # signer binding, not a fixture allowlist, must reject the outsider.
            allowed = auth.team_id == TEAM
            return PresenceVerificationContext(
                subject=subject_ref, subject_active=True, platform='telegram', scope=record('PresenceScope', {'kind':'platform'}),
                mode='native', audience=audience, authorization_revision='policy-7', subject_identity=selected,
                caller=PresenceCaller(caller, allowed), expected_intent_hash='sha256:' + hashlib.sha256(canonical_record(intent)).hexdigest(), expected_generation=7, consumed_request_ids=frozenset(),
                now=datetime.now(timezone.utc), max_ttl_seconds=300, max_clock_skew_seconds=30, ownership_pin=self.owner_pin)
    verifier = PresenceVerifier(Provider(pin))
    wrong_pin_verifier = PresenceVerifier(Provider(replace(pin, owner=selected)))

    @env.app.post('/__p8/native')
    @env.app.post('/__p8/wrong-owner-pin')
    async def host_verify(request: Request, auth=Depends(get_messaging_auth)):
        try:
            artifact = decode_record('SignedArtifact', await request.body())
            service = wrong_pin_verifier if request.url.path.endswith('wrong-owner-pin') else verifier
            result = await service.verify_presence(auth, artifact)
            return result.value
        except ContractError as error:
            raise HTTPException(status_code={'invalid':422,'unsupported':409,'forbidden':403,'stale':409,'replay_conflict':409,'authority_unavailable':503}[error.code], detail={'family':'presence','code':error.code,'field':error.field})

    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued, expiry = now.isoformat().replace('+00:00','Z'), (now+timedelta(minutes=5)).isoformat().replace('+00:00','Z')
    acting_name = 'bob' if owner_lane else 'alice'
    acting = identities[acting_name]
    value = dict(version='aweb-presence-intent-v1', operation='register', subject=subject_ref.value, platform='telegram',
                 scope={'kind':'platform'}, mode='native', audience=audience, expected_generation=7, request_id=str(uuid4()),
                 authorization='owner' if owner_lane else 'subject', signer=acting.principal, signing_key_id=acting.signing_key_id,
                 issued_at=issued, expires_at=expiry)
    if owner_lane:
        proof = dict(version='aweb-presence-owner-proof-v1', subject=subject_ref.value, owner=acting.principal, platform='telegram',
                     scope={'kind':'platform'}, operations=['register'], audience=audience, authorization_revision='owner-4',
                     signer=identities['carol'].principal, signing_key_id=identities['carol'].signing_key_id,
                     issued_at=issued, expires_at=expiry)
        value['ownership_proof'] = sign_presence_record(record('OwnershipProof', proof), env.actors['carol'].sk).value
    # Only the signing client receives the disposable private key. The public
    # verifier/provider receive actual public identities and independently pinned facts.
    payload = dict(url=audience, seed=env.actors[acting_name].sk.hex(), did=env.actors[acting_name].did,
                   stable_id=acting.principal if global_subject else '', intent=value,
                   wrong_seed=env.actors['carol'].sk.hex(), wrong_did=env.actors['carol'].did,
                   owner_lane=owner_lane, old_seed=old_key[0].hex() if old_key else '', old_did=old_key[1] if old_key else '')
    path = tmp_path / 'presence-signer.json'
    path.write_text(json.dumps(payload)); path.chmod(0o600)
    child_env = os.environ.copy(); child_env['AW_TEST_P8_SIGNER_INPUT'] = str(path)
    process = await asyncio.create_subprocess_exec('go', 'test', './awid', '-run', '^TestHumanChannelsPresenceLiveSigner$', '-count=1',
                                                  cwd=ROOT/'cli/go', env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), 60)
    assert process.returncode == 0, stdout.decode()+stderr.decode()


@pytest.mark.asyncio
async def test_port_snapshots_signed_bytes_before_awaiting_authority():
    from aweb.identity_auth_deps import MessagingAuth
    case = VECTORS['valid'][0]
    ctx = context_from_fixture(case['context'])
    artifact = record('SignedArtifact', case['artifact'])
    removal = json.loads(case['artifact']['signed_payload'])
    removal['operation'] = 'remove'
    other = sign_presence_record(record('PresenceIntent', removal), bytes.fromhex(VECTORS['public_test_seeds']['subject']))
    class Provider:
        async def resolve(self, auth, intent):
            assert intent.value['operation'] == 'register'
            artifact.value.update(other.value)
            return ctx
    auth = MessagingAuth(ctx.caller.identity.signing_key_id, None, None)
    result = await PresenceVerifier(Provider()).verify_presence(auth, artifact)
    assert result.value == case['expected']
