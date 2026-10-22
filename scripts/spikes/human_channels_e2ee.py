"""X-E2 laboratory codec, NOT an enabled or frozen public protocol.

Reuses actual HPKE/AES/signature primitives. Only the owner-only, native-speaker
case is explored; the public P4 authority service is not implemented here.
No application imports this module. All exported fixture private keys are public
synthetic test material. Run via uv --project server, not as an installed API.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey
from awid.did import did_from_public_key, stable_id_from_did_key
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from aweb import e2ee_messages as native
from aweb.human_channels.contract import decode_record, require_canonical_signed_payload

TYPE = 'aweb.experimental.managed-chat.x-e2'
ZERO = 'sha256:' + '00' * 32
NOW = datetime(2026, 10, 21, 17, 0, tzinfo=timezone.utc)

def canon(v): return canonical_json_bytes(v)
def digest(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()
def b64(raw): return base64.b64encode(raw).decode().rstrip('=')
def un64(v): return base64.b64decode(v + '=' * (-len(v) % 4), validate=True)
def participant(i): return {'kind':'native','did':i['did']}
def sign(value, identity):
    raw=canon(value)
    return {'signed_payload':raw.decode(),'signature':sign_message(un64(identity['signing_seed']),raw)}
def checked(artifact, signer, schema=None):
    raw=artifact['signed_payload'].encode()
    require_canonical_signed_payload(raw)
    verify_did_key_signature(did_key=signer,payload=raw,signature_b64=artifact['signature'])
    if schema:decode_record(schema,raw)
    return json.loads(raw)
def head(record):return digest(record['signed_payload'].encode())

def identity(name, index, now=NOW, *, signing_seed=None, team_id='spike:example.test'):
    seed=signing_seed or bytes([index])*32
    key=SigningKey(seed);did=did_from_public_key(bytes(key.verify_key))
    private=X25519PrivateKey.from_private_bytes(bytes([index+16])*32)
    assertion=build_encryption_key_assertion(signing_key=seed,identity_did=did,
        identity_stable_id=stable_id_from_did_key(did), encryption_public_key=private.public_key().public_bytes_raw(),
        custody='self',now=now)
    return dict(address='',did=did,stable_id=stable_id_from_did_key(did),team_id=team_id,
        signing_seed=b64(seed),x25519_private=b64(private.private_bytes_raw()),encryption_key=assertion)

def sender(i):return {**i,'signing_key':un64(i['signing_seed'])}
def decrypt_identity(i):return {**i,'encryption_key_id':i['encryption_key']['encryption_key_id'],'private_key':un64(i['x25519_private'])}
def content_key(envelope,i):
    local=decrypt_identity(i)
    return native._open_key_wrap(wrap=native._select_key_wrap(envelope,local),envelope=envelope,identity=local)

def make_chain(ids, session, now=NOW):
    owner=ids['alice'];bridge=ids['bob'];result=[]
    for epoch,names in enumerate([['alice','bob'],['alice','bob','carol'],['alice','carol']]):
        label='bridge_readable' if epoch==1 else 'end_to_end'
        operation='create' if epoch==0 else 'add' if epoch==1 else 'remove'
        members=[{'participant':participant(ids[n]),'consent_id':str(uuid4()),'joined_epoch':1 if n=='carol' else 0} for n in names]
        # Real consent signatures, including existing members' explicit bridge label/control disclosure consent.
        state=dict(owner=owner['did'],members=members,delegations=[],history_grants=[],
            bridges=[dict(bridge=bridge['stable_id'],platforms=['telegram'],guest_admission=False,max_guests=0,audience_digest='commitment:'+'11'*32)] if epoch==1 else [],
            history='join_forward',control_history_disclosure='shared_control_history_v1',confidentiality=label,
            authority_mode='identity_chain',max_intent_ttl_seconds=300,max_clock_skew_seconds=30,
            service=dict(service=owner['did'],signing_key_id=owner['did'],audience='x-e2-laboratory'))
        intent=dict(version='aweb-chat-policy-v1',session_id=session,operation_id=str(uuid4()),operation=operation,
            epoch=epoch,previous_hash=head(result[-1]) if result else ZERO,
            subjects=[participant(ids[n]) for n in (names if epoch==0 else ['carol'] if epoch==1 else ['bob'])],
            state=state,consents=[],audience='x-e2-laboratory',signer=owner['did'],signing_key_id=owner['did'],
            issued_at=now.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'),expires_at=(now+timedelta(minutes=5)).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'))
        commitment=digest(canon({k:intent[k] for k in ('session_id','operation_id','operation','subjects','state')}))
        for name,member in zip(names,members):
            consent=dict(consent_id=member['consent_id'],policy_hash=commitment,version='aweb-chat-consent-v1',session_id=session,
                participant=member['participant'],operation_id=intent['operation_id'],membership_hash=intent['previous_hash'],
                control_history_disclosure='shared_control_history_v1',confidentiality=label,audience='x-e2-laboratory',
                signer=ids[name]['did'],signing_key_id=ids[name]['did'],issued_at=intent['issued_at'],expires_at=intent['expires_at'])
            intent['consents'].append(sign(consent,ids[name]))
        result.append(sign(intent,owner))
    return result

def verify_chain(chain,owner,session):
    """Owner-only spike lane; the P4 verifier must cover delegation/transfer too."""
    previous=ZERO
    if not chain:raise ValueError('missing chain')
    for epoch,record in enumerate(chain):
        value=checked(record,owner,'MembershipIntent')
        if (value['session_id'],value['epoch'],value['previous_hash'],value['signer'],value['state']['owner']) != (session,epoch,previous,owner,owner):raise ValueError('chain continuity/owner')
        if (epoch==0) != (value['operation']=='create'):raise ValueError('creation anchor')
        state=value['state'];members=state['members']
        if not members or state['delegations']:raise ValueError('unsupported prototype authority lane')
        commitment=digest(canon({k:value[k] for k in ('session_id','operation_id','operation','subjects','state')}))
        consents={}
        for artifact in value['consents']:
            consent=json.loads(artifact['signed_payload']);subject=consent['participant']
            if subject['kind']!='native':raise ValueError('prototype supports native consent only')
            consent=checked(artifact,subject['did'],'AdmissionConsent')
            if (consent['policy_hash'],consent['session_id'],consent['operation_id'],consent['membership_hash'],consent['confidentiality'],consent['signer']) != (commitment,session,value['operation_id'],previous,state['confidentiality'],subject['did']):raise ValueError('consent context')
            consents[consent['consent_id']]=subject
        # Deliberately require every resulting member to consent in this small experiment.
        if any(consents.get(m['consent_id'])!=m['participant'] for m in members):raise ValueError('missing consent')
        previous=head(record)
    return value,previous

def protected(envelope,*,ciphertext=True,hashes=True):
    value=native._envelope_map(envelope,include_signature=False,include_ciphertext=ciphertext,include_ciphertext_hash=hashes)
    value['group_context']=envelope['group_context']
    return canon(value)

def inner_header(inner):
    value=native._inner_payload_map(inner,include_content=False)
    value['group_context']=inner['group_context']
    return native._hash_bytes(canon(value))

def encrypt_group(ids,chain,session,body,*,now=NOW):
    policy,policy_head=verify_chain(chain,ids['alice']['did'],session)
    alice=ids['alice'];names={m['participant']['did'] for m in policy['state']['members']}
    if alice['did'] not in names:raise ValueError('not a sender')
    recipients=[i for i in ids.values() if i['did'] in names and i['did']!=alice['did']]
    # Build actual HPKE wraps with existing primitives; use a fresh content nonce
    # for the new experiment, never reuse the provisional native ciphertext nonce.
    original=native.encrypt_e2ee_chat(sender=sender(alice),recipients=recipients,body=body,message_id=str(uuid4()),conversation_id=session,created_at=now)
    inner=native.decrypt_e2ee_message(original,decrypt_identity(alice));cek=content_key(original,alice)
    envelope=copy.deepcopy(original)
    envelope.update(message_version=3,envelope_type=TYPE,group_context=dict(session_id=session,membership_epoch=policy['epoch'],membership_hash=policy_head,author_ref=participant(alice),message_id=envelope['message_id']))
    inner.update(inner_version=3,group_context=envelope['group_context'])
    inner_bytes=canon(inner)
    nonce=os.urandom(12)
    envelope['crypto'].update(content_nonce=b64(nonce),ciphertext_size=len(inner_bytes)+16,inner_header_hash=inner_header(inner))
    ciphertext=AESGCM(cek).encrypt(nonce,inner_bytes,protected(envelope,ciphertext=False,hashes=False))
    envelope['ciphertext']=b64(ciphertext);envelope['crypto']['ciphertext_hash']=native._hash_bytes(ciphertext)
    envelope['signature']=sign_message(un64(alice['signing_seed']),protected(envelope))
    return envelope

def authenticate_group(envelope,chain,owner,session):
    policy,policy_head=verify_chain(chain,owner,session)
    if envelope.get('message_version')!=3 or envelope.get('envelope_type')!=TYPE:raise ValueError('unsupported experiment profile')
    ctx=envelope['group_context'];decode_record('GroupContext',canon(ctx))
    signer=envelope['from']['did']
    if ctx!=dict(session_id=session,membership_epoch=policy['epoch'],membership_hash=policy_head,author_ref={'kind':'native','did':signer},message_id=envelope['message_id']):raise ValueError('protected context')
    if envelope['conversation_id']!=session or envelope['signing_key_id']!=signer:raise ValueError('signer/session')
    members={m['participant']['did'] for m in policy['state']['members']}
    if {r['did'] for r in envelope['recipients']}|{signer}!=members:raise ValueError('recipient policy')
    verify_did_key_signature(did_key=signer,payload=protected(envelope),signature_b64=envelope['signature'])
    ciphertext=un64(envelope['ciphertext'])
    if native._hash_bytes(ciphertext)!=envelope['crypto']['ciphertext_hash'] or len(ciphertext)!=envelope['crypto']['ciphertext_size']:raise ValueError('ciphertext digest')
    if native._hash_canonical('key_wraps',[native._key_wrap_map(w) for w in envelope['key_wraps']])!=envelope['crypto']['key_wraps_hash']:raise ValueError('wrap digest')
    for recipient in envelope['recipients']:
        matches=[w for w in envelope['key_wraps'] if w['wrap_purpose']=='delivery' and w.get('recipient_did')==recipient['did'] and w['recipient_encryption_key_id']==recipient['encryption_key_id'] and w['wrap_id']==recipient['wrap_id']]
        if len(matches)!=1:raise ValueError('missing recipient wrap')
    copies=[w for w in envelope['key_wraps'] if w['wrap_purpose']=='sender_copy' and w.get('recipient_did')==signer]
    if len(copies)!=1:raise ValueError('missing sender copy')
    for bridge in policy['state']['bridges']:
        if not any(r.get('stable_id')==bridge['bridge'] and stable_id_from_did_key(r['did'])==bridge['bridge'] for r in envelope['recipients']):raise ValueError('missing bridge wrap identity')
    return policy

def decrypt_with_key(envelope,cek):
    aad=native._content_aad(envelope) if envelope['message_version']==2 else protected(envelope,ciphertext=False,hashes=False)
    plain=AESGCM(cek).decrypt(un64(envelope['crypto']['content_nonce']),un64(envelope['ciphertext']),aad)
    inner=json.loads(plain)
    if envelope['message_version']==2:
        if native._inner_header_hash(inner)!=envelope['crypto']['inner_header_hash']:raise ValueError('native inner header')
        native._verify_inner_header(envelope,inner)
        return inner
    if inner_header(inner)!=envelope['crypto']['inner_header_hash'] or inner.get('group_context')!=envelope['group_context']:raise ValueError('inner context')
    for key in ('kind','message_id','conversation_id','created_at'):
        if inner[key]!=envelope[key]:raise ValueError('inner/outer header')
    if inner['inner_version']!=3 or inner['from']['did']!=envelope['from']['did']:raise ValueError('inner author')
    if {r['did'] for r in inner['recipients']}!={r['did'] for r in envelope['recipients']}:raise ValueError('inner recipients')
    return inner

def open_group(envelope,chain,i,owner,session):
    authenticate_group(envelope,chain,owner,session)
    return decrypt_with_key(envelope,content_key(envelope,i))

def open_reshare(original,capsule,grant,chain,newcomer,owner,session):
    policy,policy_head=verify_chain(chain,owner,session)
    g=checked(grant,owner)
    expected=dict(version='aweb.experimental.history-grant.x-e2',session_id=session,source_hash=digest(canon(original)),
        message_id=original['message_id'],policy_head=policy_head,recipient=newcomer['did'],holder=capsule['from']['did'])
    if g!=expected:raise ValueError('history grant scope')
    if g['recipient'] not in {m['participant']['did'] for m in policy['state']['members']}:raise ValueError('inactive history recipient')
    if g['holder'] not in {r['did'] for r in original['recipients']}|{original['from']['did']}:raise ValueError('not an original holder')
    if g['holder'] not in {m['participant']['did'] for m in policy['state']['members']}:raise ValueError('inactive holder')
    payload=json.loads(native.decrypt_e2ee_message(capsule,decrypt_identity(newcomer))['body'])
    if set(payload)!={'grant','original','cek'}:raise ValueError('capsule requires content key and original proof')
    if payload['grant']!=grant or payload['original']!=canon(original).decode():raise ValueError('capsule evidence')
    if original['message_version']==2:
        native.verify_e2ee_message_envelope_signature(original)
        if original['conversation_id']!=session or original['kind']!='chat':raise ValueError('source session')
        if native._hash_bytes(un64(original['ciphertext']))!=original['crypto']['ciphertext_hash']:raise ValueError('source ciphertext digest')
        if native._hash_canonical('key_wraps',[native._key_wrap_map(w) for w in original['key_wraps']])!=original['crypto']['key_wraps_hash']:raise ValueError('source wrap digest')
    else:authenticate_group(original,chain[:original['group_context']['membership_epoch']+1],owner,session)
    return decrypt_with_key(original,un64(payload['cek']))

def experiment(ids=None,*,now=NOW):
    ids=ids or {n:identity(n,i,now) for i,n in enumerate(['alice','bob','carol'],1)}
    session=str(uuid4());owner=ids['alice']['did'];chain=make_chain(ids,session,now)
    original=native.encrypt_e2ee_chat(sender=sender(ids['alice']),recipients=[ids['bob']],body='old group content',message_id=str(uuid4()),conversation_id=session,created_at=now)
    old_bytes=canon(original)
    verify_chain(chain,owner,session)
    try:native.decrypt_e2ee_message(original,decrypt_identity(ids['carol']))
    except native.E2EEEnvelopeError:pass
    else:raise AssertionError('newcomer received old key')
    bridged=encrypt_group(ids,chain[:2],session,'visible to bridge',now=now)
    assert open_group(bridged,chain[:2],ids['bob'],owner,session)['body']=='visible to bridge'
    g=dict(version='aweb.experimental.history-grant.x-e2',session_id=session,source_hash=digest(old_bytes),message_id=original['message_id'],policy_head=head(chain[1]),recipient=ids['carol']['did'],holder=ids['bob']['did'])
    grant=sign(g,ids['alice'])
    payload=dict(grant=grant,original=old_bytes.decode(),cek=b64(content_key(original,ids['bob'])))
    capsule=native.encrypt_e2ee_mail(sender=sender(ids['bob']),recipients=[ids['carol']],subject='Experimental authorized history transfer',body=canon(payload).decode(),message_id=str(uuid4()),conversation_id=str(uuid4()),created_at=now)
    assert open_reshare(original,capsule,grant,chain[:2],ids['carol'],owner,session)['body']=='old group content'
    assert canon(original)==old_bytes
    future=encrypt_group(ids,chain,session,'future after removal',now=now)
    assert open_group(future,chain,ids['carol'],owner,session)['body']=='future after removal'
    assert content_key(original,ids['alice'])!=content_key(future,ids['alice'])
    try:open_group(future,chain,ids['bob'],owner,session)
    except native.E2EEEnvelopeError:pass
    else:raise AssertionError('removed member received future key')
    try:native.decrypt_e2ee_message(bridged,decrypt_identity(ids['bob']))
    except native.E2EEEnvelopeError:pass
    else:raise AssertionError('legacy accepted experiment')
    return dict(checks=['chain_verified','old_key_denied','bridge_readable','original_preserved','authorized_reshare','removed_key_denied','legacy_refuses_new_profile'],fixture=dict(status='experimental; not frozen; no server membership implementation',owner=owner,session_id=session,identities=ids,chain=chain,original=original,bridge_epoch=bridged,future=future,grant=grant,capsule=capsule))

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--write-fixture',action='store_true');args=parser.parse_args()
    result=experiment()
    if args.write_fixture:
        root=Path(__file__).resolve().parents[2]
        (root/'docs/vectors/human-channels-e2ee-spike.json').write_text(json.dumps(result['fixture'],indent=2)+'\n')
    print(json.dumps(result['checks']))
