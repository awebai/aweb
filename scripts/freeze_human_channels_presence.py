"""Deliberate P8 candidate vector generation. All seeds are public synthetic keys.

Context JSON below is test input for a trusted host adapter, NOT a wire grammar.
Review generated vectors at an exact SHA; never re-freeze to repair a test.
"""
import copy
import json
from pathlib import Path
from datetime import datetime, timezone
from nacl.signing import SigningKey
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message

ROOT=Path(__file__).resolve().parents[1]
keys={name:bytes([i])*32 for i,name in enumerate(('subject','owner','issuer','other'),49)}
identities={name:dict(principal=did_from_public_key(bytes(SigningKey(seed).verify_key)),signing_key_id=did_from_public_key(bytes(SigningKey(seed).verify_key)),active=True) for name,seed in keys.items()}
ID='11111111-1111-4111-8111-111111111111'
SUBJECT={'kind':'native','did':identities['subject']['principal']}
SCOPE={'kind':'platform'}

def signed(v,key):
 raw=canonical_json_bytes(v)
 return dict(signed_payload=raw.decode(),signature=sign_message(keys[key],raw))

def base(mode='native',owner=False,global_subject=False):
 subject=copy.deepcopy(SUBJECT);subject_identity=copy.deepcopy(identities['subject'])
 if global_subject:subject['did']=subject_identity['principal']='did:aw:presence-subject'
 actor=copy.deepcopy(identities['owner'] if owner else subject_identity)
 context=dict(subject=subject,subject_active=True,platform='telegram',scope=SCOPE.copy(),mode=mode,audience='https://presence.example.test',authorization_revision='policy-7',subject_identity=subject_identity,
  caller=dict(identity=actor,action_authorized=True,grant=None),expected_generation=7,consumed_request_ids=[],now='2026-10-21T17:02:00Z',max_ttl_seconds=300,max_clock_skew_seconds=30,ownership_pin=None,allow_scoped_native=False)
 binding=mode!='native'
 value=dict(version='aweb-presence-binding-intent-v1' if binding else 'aweb-presence-intent-v1',operation='bind' if binding else 'register',subject=subject,platform='telegram',scope=SCOPE.copy(),mode=mode,audience=context['audience'],expected_generation=7,request_id=ID,authorization='owner' if owner else 'subject',signer=actor['principal'],signing_key_id=actor['signing_key_id'],issued_at='2026-10-21T17:00:00Z',expires_at='2026-10-21T17:05:00Z')
 if binding:value['binding_digest']=context['binding_digest']='commitment:'+'11'*32
 if owner:
  context['ownership_pin']=dict(subject=subject,audience=context['audience'],owner=copy.deepcopy(identities['owner']),issuer=copy.deepcopy(identities['issuer']),authorization_revision='owner-4')
  proof=dict(version='aweb-presence-binding-owner-proof-v1' if binding else 'aweb-presence-owner-proof-v1',subject=subject,owner=identities['owner']['principal'],platform='telegram',scope=SCOPE.copy(),operations=['bind','rebind','unbind'] if binding else ['register','replace','remove'],audience=context['audience'],authorization_revision='owner-4',signer=identities['issuer']['principal'],signing_key_id=identities['issuer']['signing_key_id'],issued_at='2026-10-21T17:00:00Z',expires_at='2026-10-21T17:04:00Z')
  if binding:proof['mode']=mode
  value['ownership_proof']=signed(proof,'issuer')
 return dict(family='binding' if binding else 'native',value=value,context=context,key='owner' if owner else 'subject')

valid=[];invalid=[]
def add(name,case,code=None):
 case=copy.deepcopy(case);artifact=signed(case.pop('value'),case['key']);case['name']=name;case['artifact']=artifact
 import hashlib
 case['context']['expected_intent_hash']='sha256:'+hashlib.sha256(artifact['signed_payload'].encode()).hexdigest()
 if code:case['error']=code;invalid.append(case)
 else:
  v=json.loads(artifact['signed_payload']);ctx=case['context'];binding=case['family']=='binding'
  expires=min(v['expires_at'],json.loads(v['ownership_proof']['signed_payload'])['expires_at'] if 'ownership_proof' in v else v['expires_at'])
  grant=ctx['caller']['grant']
  if grant and not grant['never_expires']:expires=min(expires,grant['expires_at'])
  receipt={k:v[k] for k in ('subject','platform','scope','mode','operation','expected_generation','request_id')}
  import hashlib
  receipt.update(version='aweb-verified-presence-binding-v1' if binding else 'aweb-verified-presence-v1',intent_hash='sha256:'+hashlib.sha256(artifact['signed_payload'].encode()).hexdigest(),authorization_revision=ctx['authorization_revision'],expires_at=expires)
  if binding:receipt['binding_digest']=v['binding_digest']
  case['expected']=receipt;valid.append(case)

for name,case in [('local_subject',base()),('global_subject',base(global_subject=True)),('native_owner',base(owner=True)),('shared_subject',base('shared')),('dedicated_owner',base('dedicated',owner=True))]:add(name,case)
c=base();c['value']['platform']=c['context']['platform']='msteams';add('msteams_subject',c)
c=base();c['value']['operation']='remove';add('native_remove',c)
c=base('dedicated',owner=True);c['value']['operation']='unbind';add('dedicated_unbind',c)
c=base();c['value']['scope']=c['context']['scope']={'kind':'session','session_id':ID};c['context']['allow_scoped_native']=True;add('explicit_scoped_policy',c)
c=base();c['context']['caller']['grant']=dict(scopes=['presence.write'],expires_at='2026-10-21T17:03:00Z',never_expires=False);add('presence_grant_with_root_intent',c)
c=base();c['context']['caller']['grant']=dict(scopes=['presence.write'],expires_at=None,never_expires=True);add('never_expiring_grant_with_root_intent',c)
c=base();c['value'].update(issued_at='0001-10-21T17:00:00Z',expires_at='0001-10-21T17:05:00Z');c['context']['now']='0001-10-21T17:02:00Z';add('year_0001',c)
c=base(owner=True);guest=dict(kind='bridged',bridge='did:aw:bridge',subject='pairwise-subject');c['value']['subject']=c['context']['subject']=c['context']['ownership_pin']['subject']=guest;c['context']['subject_identity']=None;p=json.loads(c['value']['ownership_proof']['signed_payload']);p['subject']=guest;c['value']['ownership_proof']=signed(p,'issuer');add('guest_owner_distinct_from_native_subject',c)

for name,field,value,code in [('wrong_audience','audience','https://other.example.test','forbidden'),('wrong_subject','subject',{'kind':'native','did':identities['other']['principal']},'forbidden'),('wrong_platform','platform','slack','forbidden'),('stale_generation','expected_generation',6,'stale'),('expired_intent','expires_at','2026-10-21T17:01:00Z','stale'),('future_intent','issued_at','2026-10-21T17:03:00Z','stale'),('excessive_ttl','expires_at','2026-10-21T17:10:00Z','invalid')]:
 c=base();c['value'][field]=value;add(name,c,code)
for name,change,code in [('wrong_authenticated_identity',lambda c:c['context']['caller'].update(identity=copy.deepcopy(identities['other'])),'forbidden'),('wrong_team_or_token_owner',lambda c:c['context']['caller'].update(action_authorized=False),'forbidden'),('inactive_subject',lambda c:c['context'].update(subject_active=False),'forbidden'),('no_subject_authority',lambda c:c['context'].update(subject_identity=None),'authority_unavailable'),('consumed_request_across_families',lambda c:c['context'].update(consumed_request_ids=[ID]),'replay_conflict'),('missing_freshness_policy',lambda c:c['context'].update(max_ttl_seconds=0),'authority_unavailable')]:
 c=base();change(c);add(name,c,code)
c=base();c['context']['caller']['grant']=dict(scopes=['mail.send'],expires_at=None,never_expires=True);add('mail_only_grant',c,'forbidden')
c=base();c['context']['caller']['grant']=dict(scopes=['presence.write'],expires_at='2026-10-21T17:01:00Z',never_expires=False);add('expired_grant',c,'forbidden')
c=base();c['value']['scope']=c['context']['scope']={'kind':'session','session_id':ID};add('scoped_native_not_enabled',c,'unsupported')
c=base();c['context']['subject_identity']['signing_key_id']=identities['other']['signing_key_id'];add('local_binding_inconsistent',c,'authority_unavailable')
c=base(global_subject=True);c['context']['subject_identity']['signing_key_id']=identities['other']['signing_key_id'];add('old_global_key',c,'stale')
c=base('shared');c['context']['mode']='dedicated';add('different_binding_mode',c,'forbidden')
c=base('shared');c['context']['binding_digest']='commitment:'+'22'*32;add('different_private_binding_digest',c,'forbidden')
for name,change,code in [('missing_owner_pin',lambda c:c['context'].update(ownership_pin=None),'authority_unavailable'),('missing_issuer',lambda c:c['context']['ownership_pin'].update(issuer=None),'authority_unavailable'),('missing_owner_revision',lambda c:c['context']['ownership_pin'].update(authorization_revision=''),'authority_unavailable'),('old_owner_revision',lambda c:c['context']['ownership_pin'].update(authorization_revision='owner-5'),'stale'),('wrong_current_owner',lambda c:c['context']['ownership_pin'].update(owner=copy.deepcopy(identities['other'])),'forbidden')]:
 c=base(owner=True);change(c);add(name,c,code)
for name,field,value,code in [('proof_wrong_audience','audience','https://other.example.test','forbidden'),('proof_wrong_subject','subject',{'kind':'native','did':identities['other']['principal']},'forbidden'),('proof_wrong_operations','operations',['remove'],'forbidden'),('expired_proof','expires_at','2026-10-21T17:01:00Z','stale')]:
 c=base(owner=True);p=json.loads(c['value']['ownership_proof']['signed_payload']);p[field]=value;c['value']['ownership_proof']=signed(p,'issuer');add(name,c,code)
c=base(owner=True);p=json.loads(c['value']['ownership_proof']['signed_payload']);p.update(signer=identities['other']['principal'],signing_key_id=identities['other']['signing_key_id']);c['value']['ownership_proof']=signed(p,'other');add('self_pinned_proof_issuer',c,'forbidden')
c=base('dedicated',owner=True);p=json.loads(c['value']['ownership_proof']['signed_payload']);p['mode']='shared';c['value']['ownership_proof']=signed(p,'issuer');add('proof_different_binding_mode',c,'forbidden')
c=base('dedicated',owner=True);c['value']['ownership_proof']=base(owner=True)['value']['ownership_proof'];add('native_proof_cannot_approve_binding',c,'invalid')
c=base();add('native_approval_is_not_binding',{**c,'family':'binding'},'invalid')
# Corrupt signature and noncanonical original bytes independently of semantic data.
c=base();add('invalid_signature',c,'invalid');invalid[-1]['artifact']['signature']='A'*86
c=base();add('noncanonical_signed_intent',c,'invalid');v=json.loads(invalid[-1]['artifact']['signed_payload']);raw=json.dumps(v).encode();invalid[-1]['artifact']=dict(signed_payload=raw.decode(),signature=sign_message(keys['subject'],raw))
c=base(global_subject=True);c['key']='other';c['value']['signing_key_id']=identities['other']['signing_key_id'];c['context']['subject_identity']['signing_key_id']=identities['other']['signing_key_id'];c['context']['caller']['identity']['signing_key_id']=identities['other']['signing_key_id'];add('rotated_global_current_key',c)
c=base();add('wrong_authorized_intent_bytes',c,'forbidden');invalid[-1]['context']['expected_intent_hash']='sha256:'+'00'*32
c=base();add('missing_authorized_intent_hash',c,'authority_unavailable');invalid[-1]['context']['expected_intent_hash']=''
c=base('shared');c['context'].pop('binding_digest');add('missing_private_binding_target',c,'authority_unavailable')
c=base('shared');c['context']['consumed_request_ids']=[ID];add('binding_reuses_consumed_native_request',c,'replay_conflict')
c=base();c['key']='other';c['value'].update(signer=identities['other']['principal'],signing_key_id=identities['other']['signing_key_id']);c['context']['caller']['identity']=identities['other'];add('other_admin_has_no_subject_authority',c,'forbidden')
c=base();c['key']='other';c['value']['signing_key_id']=identities['other']['signing_key_id'];c['context']['caller']['grant']=dict(scopes=['presence.write'],expires_at=None,never_expires=True);add('grant_key_cannot_sign_root_intent',c,'stale')
c=base();c['value']['subject']=c['context']['subject']=dict(kind='bridged',bridge='did:aw:bridge',subject='pairwise-subject');c['context']['subject_identity']=None;add('guest_cannot_use_native_subject_signature',c,'forbidden')
result=dict(profile='aweb-presence-verification-v1',context_status='trusted host facts for tests only; never parse from a request',public_test_seeds={k:v.hex() for k,v in keys.items()},valid=valid,invalid=invalid)
(ROOT/'docs/vectors/human-channels-presence-v1.json').write_text(json.dumps(result,indent=2)+'\n')
print(f'{len(valid)} valid, {len(invalid)} refusal cases')
