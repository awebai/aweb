"""Deliberate P0 grammar/fixture generation; review outputs before freezing.

Run with `uv run --project server python scripts/freeze_human_channels_profile.py`.
All seeds below are public synthetic conformance seeds, never operational keys.
"""
from __future__ import annotations
import base64
import hashlib
import copy
import json
from pathlib import Path
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[1]
S: dict[str, dict] = {}

def obj(name, required, optional=None):
    S[name] = {"required": required, "optional": optional or {}}

def enum(*values):
    return {"enum": list(values)}

def ref(name):
    return {"ref": name}

def arr(item):
    return {"array": item}

platform = enum("telegram", "msteams", "slack", "whatsapp", "discord")
kind = enum("mail", "chat")
conf = enum("end_to_end", "hosted_readable", "bridge_readable", "server_readable")
participant = {"one_of": [ref("NativeParticipant"), ref("BridgedParticipant")]}
obj("NativeParticipant", {"kind": enum("native"), "did": "did"})
obj("BridgedParticipant", {"kind": enum("bridged"), "bridge": "didaw", "subject": "opaque"})
obj("SignedArtifact", {"signed_payload": "text", "signature": "signature"})
obj("GroupContext", {"session_id": "uuid", "membership_epoch": "uint", "membership_hash": "hash", "author_ref": participant, "message_id": "uuid"})
obj("ServiceBinding", {"service": "did", "signing_key_id": "didkey", "audience": "text"})
obj("Capabilities", {"version": enum("aweb-human-channels-capabilities-v1"), "implemented": arr("opaque"), "enabled": arr("opaque"), "refused": arr("opaque")})
obj("ResolveRequest", {"version": enum("aweb-human-resolve-v1")}, {"team_id": "uuid", "selector": "text", "session_id": "uuid", "participant": participant})
obj("AuthorityFacts", {"principal": participant, "signing_key_id": "didkey", "route": ref("ServiceBinding"), "custody": enum("self_custodial", "hosted_custodial", "bridge_custodial"), "active": "bool", "access": enum("allowed", "denied"), "inbound": enum("allowed", "consent_required", "denied"), "confidentiality": conf, "capabilities": arr("opaque"), "authorization_revision": "opaque"}, {"actor_id": "uuid", "team_id": "uuid", "key_assertion": "json_object", "ownership_proof": ref("SignedArtifact")})
obj("PrepareRequest", {"version": enum("aweb-human-prepare-v1"), "kind": kind, "message_id": "uuid", "author": participant, "envelope": "text", "format": enum("native_plaintext", "native_encrypted_v2", "managed_chat_plaintext")}, {"target": ref("AuthorityFacts"), "conversation_id": "uuid", "group_context": ref("GroupContext"), "attachment_refs": arr("json_object")})
obj("PreparedSend", {"version": enum("aweb-prepared-send-v1"), "prepared_id": "uuid", "message_id": "uuid", "kind": kind, "envelope": "text", "envelope_hash": "hash", "authority_revision": "opaque", "expires_at": "timestamp", "author": ref("AuthorProjection"), "recipients": arr(ref("AuthorityFacts"))}, {"attachment_refs": arr("json_object"), "conversation_id": "uuid", "group_context": ref("GroupContext")})
obj("IngressKey", {"issuer": "did", "namespace": "opaque", "key": "opaque", "input_hash": "hash"})
obj("AcceptedSend", {"version": enum("aweb-accepted-send-v1"), "message_id": "uuid", "kind": kind, "envelope_hash": "hash", "replayed": "bool", "publication": enum("durable_outbox"), "mutation_ids": arr("uuid")}, {"conversation_id": "uuid", "acceptance": ref("SignedArtifact")})
obj("IngressResult", {"version": enum("aweb-ingress-result-v1"), "key": ref("IngressKey"), "accepted": ref("AcceptedSend"), "result": "json_object"})
obj("Delegation", {"delegation_id": "uuid", "delegate": "did", "operations": arr(enum("add", "remove", "history_grant", "export_checkpoint")), "expires_at": "timestamp"}, {"bridge": "didaw", "platform": platform, "max_guests": "uint"})
obj("AdmissionConsent", {"consent_id": "uuid", "policy_hash": "hash", "version": enum("aweb-chat-consent-v1"), "session_id": "uuid", "participant": participant, "operation_id": "uuid", "membership_hash": "hash", "control_history_disclosure": enum("shared_control_history_v1"), "confidentiality": conf, "audience": "text", "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"})
obj("Member", {"participant": participant, "consent_id": "uuid", "joined_epoch": "uint"}, {"left_epoch": "uint"})
obj("HistoryGrant", {"participant": participant, "message_intervals": arr(ref("Interval")), "control_through_epoch": "uint", "consent_id": "uuid"})
obj("Interval", {"after_seq": "uint", "through_seq": "uint"})
obj("BridgeAdmission", {"bridge": "didaw", "platforms": arr(platform), "guest_admission": "bool", "max_guests": "uint", "audience_digest": "commitment"})
obj("PolicyState", {"owner": "did", "members": arr(ref("Member")), "delegations": arr(ref("Delegation")), "history_grants": arr(ref("HistoryGrant")), "bridges": arr(ref("BridgeAdmission")), "history": enum("join_forward"), "control_history_disclosure": enum("shared_control_history_v1"), "confidentiality": conf, "authority_mode": enum("identity_chain", "server_readable"), "max_intent_ttl_seconds": "positive_uint", "max_clock_skew_seconds": "uint", "service": ref("ServiceBinding")})
obj("MembershipIntent", {"version": enum("aweb-chat-policy-v1"), "session_id": "uuid", "operation_id": "uuid", "operation": enum("create", "add", "remove", "leave", "delegate", "revoke_delegation", "transfer", "history_grant"), "epoch": "uint", "previous_hash": "hash", "subjects": arr(participant), "state": ref("PolicyState"), "consents": arr(ref("SignedArtifact")), "audience": "text", "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"}, {"delegation_id": "uuid"})
common = {"version": enum("aweb-chat-export-checkpoint-v1"), "session_id": "uuid", "transition_id": "uuid", "export_id": "uuid", "bridge": "didaw", "operation": enum("activate", "pause", "revoke"), "audience": "text", "authorization": enum("owner", "bridge_attenuation", "revoke_authority"), "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"}
owner = {"expected_membership_epoch": "uint", "expected_membership_hash": "hash", "expected_export_generation": "uint", "generation": "positive_uint", "policy_digest": "commitment"}
obj("CheckpointIntent", common, owner)
receipt = {"version": enum("aweb-chat-export-receipt-v1"), "session_id": "uuid", "transition_id": "uuid", "export_id": "uuid", "bridge": "didaw", "generation": "positive_uint", "operation": enum("activate", "pause", "revoke"), "authorization": common["authorization"], "policy_digest": "commitment", "intent_hash": "hash", "membership_epoch": "uint", "membership_hash": "hash", "acceptance_seq": "positive_uint", "effective_after_seq": "positive_uint", "signer": "did", "signing_key_id": "didkey"}
obj("CheckpointReceipt", receipt)
obj("ExportCapture", {"export_id": "uuid", "bridge": "didaw", "generation": "positive_uint", "policy_digest": "commitment", "transition_id": "uuid", "checkpoint_seq": "positive_uint", "state": enum("activate", "pause", "revoke")})
obj("MessageAcceptance", {"version": enum("aweb-chat-acceptance-v1"), "session_id": "uuid", "message_id": "uuid", "capture_status": enum("recorded", "legacy_unknown")}, {"message_envelope_hash": "hash", "acceptance_seq": "positive_uint", "membership_epoch": "uint", "membership_hash": "hash", "exports": arr(ref("ExportCapture")), "signer": "did", "signing_key_id": "didkey"})
obj("PresenceScope", {"kind": enum("platform", "session")}, {"session_id": "uuid"})
obj("PresenceIntent", {"version": enum("aweb-presence-intent-v1"), "operation": enum("register", "replace", "remove"), "subject": participant, "platform": platform, "scope": ref("PresenceScope"), "mode": enum("native"), "audience": "text", "expected_generation": "uint", "request_id": "uuid", "authorization": enum("subject", "owner"), "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"}, {"ownership_proof": ref("SignedArtifact")})
obj("NativeOperation", {"operation_id": "uuid", "intent_hash": "hash", "version": enum("aweb-native-operation-v1"), "agent": "did", "session_id": "uuid", "input_id": "uuid", "input_hash": "hash", "owner": enum("native", "aweb"), "generation": "positive_uint", "fence": "positive_uint", "lease_until": "timestamp", "state": enum("claimed", "started", "outcome_unknown", "completed", "blocked"), "audience": "text", "signer": "did", "signing_key_id": "didkey"})
obj("NativeReply", {"version": enum("aweb-native-reply-v1"), "agent": "did", "session_id": "uuid", "input_id": "uuid", "input_hash": "hash", "generation": "positive_uint", "fence": "positive_uint", "slot": "opaque", "message_id": "uuid", "envelope_hash": "hash", "envelope": "text", "state": enum("committed", "transport_unknown", "accepted"), "signer": "did", "signing_key_id": "didkey"})
obj("PageRequest", {"resource": enum("mail", "sessions", "messages", "participants", "policy_chain", "checkpoints", "acceptances"), "limit": "limit"}, {"session_id": "uuid", "cursor": "opaque"})
obj("PageResult", {"resource": S["PageRequest"]["required"]["resource"], "items": arr("json_object"), "authorization_revision": "opaque", "has_more": "bool"}, {"next_cursor": "opaque"})
obj("SessionCreate", {"session_id": "uuid", "intent": ref("SignedArtifact")})
obj("SessionView", {"session_id": "uuid", "membership_epoch": "uint", "membership_hash": "hash", "owner": "did", "participants": arr(participant), "confidentiality": conf, "control_history_grant": enum("consented", "required", "expired"), "authorization_revision": "opaque", "capabilities": arr("opaque")})
obj("AuthorProjection", {"author": participant, "author_assurance": enum("native", "platform_attested"), "trust_status": enum("verified", "verified_custodial", "external_untrusted"), "verified": "bool", "signer_verified": "bool", "confidentiality": conf}, {"via": "platform_kind"})
obj("Refusal", {"version": enum("aweb-human-channels-error-v1"), "family": enum("resolve", "prepare", "accept", "membership", "history", "checkpoint", "presence", "native", "attachment"), "code": enum("invalid", "unsupported", "forbidden", "consent_required", "stale", "replay_conflict", "not_found", "authority_unavailable", "native_unavailable", "outcome_unknown", "limit_exceeded"), "retry": enum("never", "refresh", "backoff", "reconcile"), "effects": enum("none")})

obj("NarrowStopAck", {"version": enum("aweb-chat-narrow-stop-ack-v1"), "session_id": "uuid", "transition_id": "uuid", "export_id": "uuid", "bridge": "didaw", "operation": enum("pause", "revoke"), "result": enum("committed", "already_stopped"), "signer": "did", "signing_key_id": "didkey"})
obj("VerifiedPresence", {"version": enum("aweb-verified-presence-v1"), "subject": participant, "platform": platform, "scope": ref("PresenceScope"), "mode": enum("native"), "operation": enum("register", "replace", "remove"), "expected_generation": "uint", "request_id": "uuid", "intent_hash": "hash", "authorization_revision": "opaque", "expires_at": "timestamp"})
obj("NativeOperationRequest", {"version": enum("aweb-native-operation-intent-v1"), "operation_id": "uuid", "agent": "did", "session_id": "uuid", "input_id": "uuid", "input_hash": "hash", "owner": enum("native", "aweb"), "expected_generation": "uint", "expected_fence": "uint", "operation": enum("claim", "start", "renew", "complete", "reconcile", "resolve"), "audience": "text", "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"}, {"evidence_hash": "hash", "decision": enum("reuse_reply", "resume_proved_safe", "retry_duplicate_risk", "keep_blocked"), "owner_authorization": ref("SignedArtifact")})
obj("MessageView", {"kind": kind, "message_id": "uuid", "envelope": "text", "envelope_hash": "hash", "author": ref("AuthorProjection")}, {"conversation_id": "uuid", "acceptance": ref("SignedArtifact")})
obj("NativePlaintext", {"from": "text", "from_did": "didkey", "to": "text", "to_did": "didkey", "type": kind, "subject": "string", "body": "string", "timestamp": "timestamp"}, {"message_id": "uuid", "conversation_id": "uuid", "from_stable_id": "didaw", "to_stable_id": "didaw", "priority": enum("low", "normal", "high", "urgent"), "wait_seconds": "uint", "reply_to": "text", "sender_leaving": "bool", "hang_on": "bool", "via": "platform_kind"})
obj("NativeV2Content", {"inner_version": {"integer_const": 2}, "kind": kind, "message_id": "uuid", "conversation_id": "string", "created_at": "timestamp", "from": "json_object", "recipients": arr("json_object"), "body": "string"}, {"subject": "string", "attachments": arr("json_object"), "reply_to_message_id": "uuid", "via": "platform_kind"})

obj("ManagedPlaintext", {"version": enum("aweb-managed-chat-plaintext-v1"), "type": enum("chat"), "message_id": "uuid", "conversation_id": "uuid", "group_context": ref("GroupContext"), "recipients": arr(participant), "body": "string", "signer": "did", "signing_key_id": "didkey", "created_at": "timestamp"}, {"via": "platform_kind", "reply_to_message_id": "uuid"})
obj("OwnershipProof", {"version": enum("aweb-presence-owner-proof-v1"), "subject": participant, "owner": "did", "platform": platform, "scope": ref("PresenceScope"), "operations": arr(enum("register", "replace", "remove")), "audience": "text", "authorization_revision": "opaque", "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"})

obj("PresenceBindingIntent", {"version": enum("aweb-presence-binding-intent-v1"), "operation": enum("bind", "rebind", "unbind"), "subject": participant, "platform": platform, "scope": ref("PresenceScope"), "mode": enum("shared", "dedicated"), "binding_digest": "commitment", "audience": "text", "expected_generation": "uint", "request_id": "uuid", "authorization": enum("subject", "owner"), "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"}, {"ownership_proof": ref("SignedArtifact")})
obj("BindingOwnershipProof", {"version": enum("aweb-presence-binding-owner-proof-v1"), "subject": participant, "owner": "did", "platform": platform, "scope": ref("PresenceScope"), "mode": enum("shared", "dedicated"), "operations": arr(enum("bind", "rebind", "unbind")), "audience": "text", "authorization_revision": "opaque", "signer": "did", "signing_key_id": "didkey", "issued_at": "timestamp", "expires_at": "timestamp"})
obj("VerifiedPresenceBinding", {"version": enum("aweb-verified-presence-binding-v1"), "subject": participant, "platform": platform, "scope": ref("PresenceScope"), "mode": enum("shared", "dedicated"), "operation": enum("bind", "rebind", "unbind"), "binding_digest": "commitment", "expected_generation": "uint", "request_id": "uuid", "intent_hash": "hash", "authorization_revision": "opaque", "expires_at": "timestamp"})

caps = ["signed-via-v1", "human-alias-v1", "human-send-uow-v1", "bridged-participants-v1", "managed-chat-policy-v1", "shared-control-history-v1", "chat-export-checkpoints-v1", "presence-intents-v1", "presence-binding-intents-v1", "native-chat-receipts-v1"]
profile = {"profile": "aweb-human-channels-v1", "schemas": S, "capabilities": caps, "deferred_capabilities": ["managed-chat-encrypted-v1", "group-reshare-v1", "group-federation-v1"]}
raw = json.dumps(profile, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
(ROOT / 'docs/vectors/human-channels-profile-v1.json').write_text(json.dumps(profile, indent=2, ensure_ascii=False)+'\n')
# Schemas are compiled contract data, not independent conformance-vector copies.
(ROOT / 'server/src/aweb/human_channels/_profile.py').write_text('# Generated by scripts/freeze_human_channels_profile.py; review before freeze.\nimport json\nPROFILE = json.loads('+repr(raw)+')\n')
(ROOT / 'cli/go/awid/human_channels_profile.go').write_text('// Code generated by scripts/freeze_human_channels_profile.py; DO NOT EDIT.\npackage awid\n\nconst humanChannelsProfileJSON = `'+raw+'`\n')

seed = bytes(range(32)); key = SigningKey(seed)
# All identifiers are synthetic vector values.
DIDKEY = 'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd'
DID = 'did:aw:human-channels-vector'
UUID = '11111111-1111-4111-8111-111111111111'
HASH = 'sha256:'+'00'*32
COMMIT = 'commitment:'+'11'*32

def sample(rule, depth=0):
    if isinstance(rule, str):
        return {'did':DID, 'didaw':DID, 'didkey':DIDKEY, 'uuid':UUID, 'hash':HASH, 'commitment':COMMIT, 'timestamp':'2026-10-21T00:00:00Z', 'uint':0, 'positive_uint':1, 'limit':100, 'bool':True, 'json_object':{}, 'string':'', 'platform_kind':'telegram', 'opaque':'vector', 'text':'café <>& ☃', 'signature':base64.b64encode(bytes(64)).decode().rstrip('=')}[rule]
    if 'enum' in rule:return rule['enum'][0]
    if 'integer_const' in rule:return rule['integer_const']
    if 'ref' in rule:return sample_object(rule['ref'])
    if 'array' in rule:return []
    if 'one_of' in rule:return sample(rule['one_of'][0])
    raise AssertionError(rule)

def sample_object(name):
    v={k:sample(rule) for k,rule in S[name]['required'].items()}
    if name=='CheckpointIntent':v.update({k:sample(rule) for k,rule in owner.items()})
    if name=='CheckpointReceipt':v['effective_after_seq']=v['acceptance_seq']
    if name=='MessageAcceptance':
        v.update({k:sample(rule) for k,rule in S[name]['optional'].items()})
    if name=='ResolveRequest':v.update(team_id=UUID,selector='juan')
    if name=='PrepareRequest':v['target']=sample_object('AuthorityFacts')
    if name=='SignedArtifact':
        v['signed_payload']='{}';v['signature']=base64.b64encode(key.sign(b'{}').signature).decode().rstrip('=')
    if name=='PageResult':v['has_more']=False
    if name=='NativeV2Content':v['subject']=''
    return v

valid=[]
for name in S:
    v=sample_object(name)
    canonical=json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    valid.append({'name':name,'schema':name,'value':v,'canonical':canonical,'sha256':'sha256:'+hashlib.sha256(canonical.encode()).hexdigest(),'signature':base64.b64encode(key.sign(canonical.encode()).signature).decode().rstrip('=')})
byname={x['name']:x for x in valid}
# These are explicit contract neighbors, not inferred successes from an implementation.
for name,v in [('narrow_stop',{k:v for k,v in byname['CheckpointIntent']['value'].items() if k not in owner}),('legacy_capture',{k:v for k,v in byname['MessageAcceptance']['value'].items() if k in S['MessageAcceptance']['required']})]:
    if name=='narrow_stop':v.update(authorization='bridge_attenuation',operation='revoke')
    else:v['capture_status']='legacy_unknown'
    canonical=json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    valid.append({'name':name,'schema':'CheckpointIntent' if name=='narrow_stop' else 'MessageAcceptance','value':v,'canonical':canonical,'sha256':'sha256:'+hashlib.sha256(canonical.encode()).hexdigest(),'signature':base64.b64encode(key.sign(canonical.encode()).signature).decode().rstrip('=')})
for schema in ("NativePlaintext", "NativeV2Content"):
    for k in ("mail", "chat"):
        for via in (None, "telegram", "msteams", "future_chat"):
            v=sample_object(schema)
            v["type" if schema=="NativePlaintext" else "kind"]=k
            if schema=="NativeV2Content":
                v["from"]={"did":DIDKEY};v["recipients"]=[{"did":DIDKEY}]
                if k=="chat":v.pop("subject",None)
            if via:v["via"]=via
            canonical=json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))
            valid.append({'name':schema+'_'+k+'_'+str(via),'schema':schema,'value':v,'canonical':canonical,'sha256':'sha256:'+hashlib.sha256(canonical.encode()).hexdigest(),'signature':base64.b64encode(key.sign(canonical.encode()).signature).decode().rstrip('=')})
v=sample_object("Capabilities");v["implemented"]=["signed-via-v1","future-v9"];v["enabled"]=v["implemented"][:]
canonical=json.dumps(v,sort_keys=True,separators=(',',':'))
valid.append({'name':'future_advertised_capability','schema':'Capabilities','value':v,'canonical':canonical,'sha256':'sha256:'+hashlib.sha256(canonical.encode()).hexdigest(),'signature':base64.b64encode(key.sign(canonical.encode()).signature).decode().rstrip('=')})
for name,schema,v in [
    ("session_only_guest_resolution","ResolveRequest",{"version":"aweb-human-resolve-v1","session_id":UUID,"participant":sample_object("BridgedParticipant")}),
    ("dedicated_binding","PresenceBindingIntent",{**sample_object("PresenceBindingIntent"),"mode":"dedicated"}),
    ("shared_binding_owner","PresenceBindingIntent",{**sample_object("PresenceBindingIntent"),"authorization":"owner","ownership_proof":sample_object("SignedArtifact")}),
    ("managed_unknown_via","ManagedPlaintext",{**sample_object("ManagedPlaintext"),"via":"future_chat"}),
    ("projection_unknown_via","AuthorProjection",{**sample_object("AuthorProjection"),"via":"future_chat"}),
]:
    canonical=json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    valid.append({'name':name,'schema':schema,'value':v,'canonical':canonical,'sha256':'sha256:'+hashlib.sha256(canonical.encode()).hexdigest(),'signature':base64.b64encode(key.sign(canonical.encode()).signature).decode().rstrip('=')})
tampered=[]
for source,field,replacement in [('NativePlaintext_mail_telegram','via','msteams'),('GroupContext','message_id','22222222-2222-4222-8222-222222222222'),('PresenceIntent','expected_generation',1),('CheckpointReceipt','acceptance_seq',2),('ManagedPlaintext','body','modified')]:
    original=next(x for x in valid if x['name']==source);v=copy.deepcopy(original['value']);v[field]=replacement
    tampered.append({'name':source+'_'+field,'json':json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')),'signature':original['signature']})
negative=[]
def bad(name,schema,value,code='invalid'):
    negative.append({'name':name,'schema':schema,'json':json.dumps(value,ensure_ascii=False,separators=(',',':')),'code':code})
for name in S:
    v=copy.deepcopy(byname[name]['value']);v['unexpected']=True;bad(name+'_extra',name,v)
    k=next(iter(S[name]['required']));v=copy.deepcopy(byname[name]['value']);v.pop(k);bad(name+'_missing',name,v)
v=copy.deepcopy(byname['CheckpointIntent']['value']);v['generation']=9007199254740992;bad('unsafe_counter','CheckpointIntent',v)
v=copy.deepcopy(byname['CheckpointIntent']['value']);v['authorization']='bridge_attenuation';bad('narrower_cannot_supply_owner_fields','CheckpointIntent',v)
v=copy.deepcopy(next(x['value'] for x in valid if x['name']=='narrow_stop'));v['operation']='activate';bad('narrower_cannot_activate','CheckpointIntent',v)
v=copy.deepcopy(byname['AuthorProjection']['value']);v['author']={'kind':'bridged','bridge':DID,'subject':'vector'};bad('guest_never_verified','AuthorProjection',v)
v=copy.deepcopy(byname['PresenceScope']['value']);v['session_id']=UUID;bad('platform_scope_has_no_session','PresenceScope',v)
v=copy.deepcopy(byname['PageResult']['value']);v['has_more']=True;bad('more_requires_cursor','PageResult',v)
v=copy.deepcopy(byname['Capabilities']['value']);v['enabled']=['unfrozen-v9'];bad('unknown_capability','Capabilities',v,'unsupported')
v=copy.deepcopy(byname['Capabilities']['value']);v['implemented']=[];v['enabled']=['bridged-participants-v1'];bad('enable_unimplemented','Capabilities',v,'unsupported')
v=copy.deepcopy(byname['PreparedSend']['value']);v['envelope_hash']=HASH;bad('prepared_envelope_hash','PreparedSend',v)
# PreparedSend's positive digest must match the preserved exact envelope string.
v=byname['PreparedSend']['value'];v['envelope_hash']='sha256:'+hashlib.sha256(v['envelope'].encode()).hexdigest()
canonical=json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'));byname['PreparedSend'].update(canonical=canonical,sha256='sha256:'+hashlib.sha256(canonical.encode()).hexdigest(),signature=base64.b64encode(key.sign(canonical.encode()).signature).decode().rstrip('='))
bad('enum_wrong_type','NativeParticipant',{'kind':{},'did':DID})
v=copy.deepcopy(byname['PresenceIntent']['value']);v['version']='aweb-presence-intent-v9';bad('unknown_version','PresenceIntent',v,'unsupported')
v=copy.deepcopy(byname['PolicyState']['value']);v['bridges']=[sample_object('BridgeAdmission')];bad('bridge_requires_label','PolicyState',v)
v=copy.deepcopy(byname['Refusal']['value']);v['code']='outcome_unknown';bad('unknown_outcome_never_blind_retry','Refusal',v)
v=copy.deepcopy(byname['NativeOperationRequest']['value']);v['operation']='resolve';bad('native_resolution_needs_owner_decision','NativeOperationRequest',v)
v=copy.deepcopy(byname['PolicyState']['value']);v['authority_mode']='server_readable';bad('server_only_policy_not_e2ee','PolicyState',v)
for schema in ("NativePlaintext","NativeV2Content","ManagedPlaintext","AuthorProjection"):
    for value in ("",None,"Telegram","telegram:user","a"*33,{},"slack/channel"):
        v=copy.deepcopy(byname[schema]['value']);v['via']=value;bad(schema+'_malformed_via_'+repr(value),schema,v)
v=sample_object('ResolveRequest');v.update(session_id=UUID,participant=sample_object('BridgedParticipant'));bad('resolve_mixed_selectors','ResolveRequest',v)
v={'version':'aweb-human-resolve-v1','session_id':UUID};bad('resolve_partial_selector','ResolveRequest',v)
v=sample_object('PresenceBindingIntent');v['authorization']='owner';bad('binding_owner_proof_required','PresenceBindingIntent',v)
bad('native_intent_is_not_binding_approval','PresenceBindingIntent',sample_object('PresenceIntent'),'invalid')
bad('native_owner_proof_is_not_binding_proof','BindingOwnershipProof',sample_object('OwnershipProof'),'invalid')
negative += [{'name':'duplicate_key','schema':'NativeParticipant','json':'{"kind":"native","kind":"bridged","did":"'+DID+'"}','code':'invalid'}, {'name':'unknown_schema','schema':'FutureV9','json':'{}','code':'unsupported'}, {'name':'float_counter','schema':'GroupContext','json':json.dumps(byname['GroupContext']['value']).replace('"membership_epoch": 0','"membership_epoch": 1.0'),'code':'invalid'}]
vectors={'profile':'aweb-human-channels-v1','provenance':'P0 conformance; public deterministic seed; freeze requires exact-SHA review','public_test_seed_hex':seed.hex(),'public_test_key_hex':bytes(key.verify_key).hex(),'valid':valid,'invalid':negative,'tampered':tampered}
(ROOT/'docs/vectors/human-channels-v1.json').write_text(json.dumps(vectors,indent=2,ensure_ascii=False)+'\n')
import subprocess
subprocess.run(['gofmt','-w',str(ROOT/'cli/go/awid/human_channels_profile.go')],check=True)
print(f'Generated {len(S)} DTO schemas, {len(valid)} signed cases and {len(negative)} refusal cases.')
