"""P8 portable intent verification. Contexts are trusted host facts, never wire DTOs.

No context is loaded from an intent, token, URL or private application schema.
The host resolves current authority, then rechecks/CASes its durable lifecycle
when applying the returned P0 DTO. This module neither persists nor suppresses.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import TYPE_CHECKING, Protocol

from nacl.signing import SigningKey
from awid.did import did_from_public_key, public_key_from_did
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature
from .contract import ContractError, ContractRecord, canonical_record, decode_record

if TYPE_CHECKING:
    from aweb.identity_auth_deps import MessagingAuth


@dataclass(frozen=True)
class PresenceIdentity:
    principal: str
    signing_key_id: str
    active: bool


@dataclass(frozen=True)
class PresenceGrant:
    scopes: frozenset[str]
    expires_at: datetime | None
    never_expires: bool


@dataclass(frozen=True)
class PresenceCaller:
    identity: PresenceIdentity
    action_authorized: bool
    grant: PresenceGrant | None = None


@dataclass(frozen=True)
class PresenceOwnershipPin:
    subject: ContractRecord
    audience: str
    owner: PresenceIdentity
    issuer: PresenceIdentity
    authorization_revision: str


@dataclass(frozen=True)
class PresenceVerificationContext:
    subject: ContractRecord
    subject_active: bool
    platform: str
    scope: ContractRecord
    mode: str
    audience: str
    authorization_revision: str
    subject_identity: PresenceIdentity | None
    caller: PresenceCaller
    expected_intent_hash: str
    expected_generation: int
    consumed_request_ids: frozenset[str]
    now: datetime
    max_ttl_seconds: int
    max_clock_skew_seconds: int
    ownership_pin: PresenceOwnershipPin | None = None
    allow_scoped_native: bool = False
    binding_digest: str | None = None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ContractError('authority_unavailable', 'clock')
    return value.astimezone(timezone.utc)


def _identity(identity: PresenceIdentity | None) -> PresenceIdentity:
    if identity is None:
        raise ContractError('authority_unavailable', 'identity authority')
    try:
        decode_record('ServiceBinding', canonical_json_bytes(dict(
            service=identity.principal, signing_key_id=identity.signing_key_id, audience='presence-context')))
        public_key_from_did(identity.signing_key_id)
    except (ContractError, ValueError, TypeError) as error:
        raise ContractError('authority_unavailable', 'identity authority') from error
    if identity.principal.startswith('did:key:') and identity.principal != identity.signing_key_id:
        raise ContractError('authority_unavailable', 'local identity key')
    if identity.active is not True:
        raise ContractError('forbidden', 'inactive identity')
    return identity


def _binding(value: dict, identity: PresenceIdentity | None) -> None:
    current = _identity(identity)
    if value['signer'] not in (current.principal, current.signing_key_id):
        raise ContractError('forbidden', 'signer principal')
    if value['signing_key_id'] != current.signing_key_id:
        raise ContractError('stale', 'current signing key')


def _signature(artifact: ContractRecord, value: dict, identity: PresenceIdentity) -> None:
    _binding(value, identity)
    try:
        verify_did_key_signature(did_key=identity.signing_key_id,
                                payload=artifact.value['signed_payload'].encode(),
                                signature_b64=artifact.value['signature'])
    except ValueError as error:
        raise ContractError('invalid', 'signature') from error


def _fresh(value: dict, context: PresenceVerificationContext) -> datetime:
    issued = datetime.strptime(value['issued_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    expires = datetime.strptime(value['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    now = _utc(context.now)
    ttl = (expires - issued).total_seconds()
    if ttl <= 0 or ttl > context.max_ttl_seconds:
        raise ContractError('invalid', 'intent lifetime')
    if (issued - now).total_seconds() > context.max_clock_skew_seconds or expires <= now:
        raise ContractError('stale', 'freshness')
    return expires


def _record(artifact: ContractRecord, schema: str) -> ContractRecord:
    if artifact.schema != 'SignedArtifact':
        raise ContractError('invalid', 'signed artifact')
    canonical_record(artifact)
    return decode_record(schema, artifact.value['signed_payload'].encode())


def sign_presence_record(record: ContractRecord, signing_key: bytes) -> ContractRecord:
    """Create a P0 artifact, without asserting current identity or ownership."""
    if record.schema not in {'PresenceIntent', 'PresenceBindingIntent', 'OwnershipProof', 'BindingOwnershipProof'}:
        raise ContractError('unsupported', 'presence signing purpose')
    raw = canonical_record(record)
    record = decode_record(record.schema, raw)
    try:
        key_id = did_from_public_key(bytes(SigningKey(signing_key).verify_key))
        if record.value['signing_key_id'] != key_id:
            raise ContractError('invalid', 'signing key')
        signature = sign_message(signing_key, raw)
    except (TypeError, ValueError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError('invalid', 'signing key') from error
    return decode_record('SignedArtifact', canonical_json_bytes(dict(signed_payload=raw.decode(), signature=signature)))


def _verify(artifact: ContractRecord, context: PresenceVerificationContext, *, binding: bool) -> ContractRecord:
    if artifact.schema != 'SignedArtifact':
        raise ContractError('invalid', 'signed artifact')
    artifact = decode_record('SignedArtifact', canonical_record(artifact))
    schema = 'PresenceBindingIntent' if binding else 'PresenceIntent'
    record = _record(artifact, schema)
    value = record.value
    # Host inputs are explicit and fail closed. They are not a request decoder.
    if context.subject.schema not in ('NativeParticipant', 'BridgedParticipant') or context.scope.schema != 'PresenceScope':
        raise ContractError('authority_unavailable', 'subject/scope authority')
    try:
        canonical_record(context.subject)
        canonical_record(context.scope)
    except ContractError as error:
        raise ContractError('authority_unavailable', 'subject/scope authority') from error
    if (type(context.max_ttl_seconds) is not int or context.max_ttl_seconds <= 0 or
            type(context.max_clock_skew_seconds) is not int or context.max_clock_skew_seconds < 0 or
            type(context.expected_generation) is not int or context.expected_generation < 0 or
            not context.authorization_revision or not context.audience or not context.expected_intent_hash):
        raise ContractError('authority_unavailable', 'verification policy')
    if context.expected_intent_hash != 'sha256:' + hashlib.sha256(artifact.value['signed_payload'].encode()).hexdigest():
        raise ContractError('forbidden', 'authorized intent bytes')
    if context.subject_active is not True or context.caller.action_authorized is not True:
        raise ContractError('forbidden', 'caller action authority')
    if (value['subject'], value['platform'], value['scope'], value['mode'], value['audience']) != (
            context.subject.value, context.platform, context.scope.value, context.mode, context.audience):
        raise ContractError('forbidden', 'exact presence target')
    if binding:
        if context.binding_digest is None:
            raise ContractError('authority_unavailable', 'private binding target')
        if value['binding_digest'] != context.binding_digest:
            raise ContractError('forbidden', 'private binding target')
    if not binding and value['scope']['kind'] == 'session' and not context.allow_scoped_native:
        raise ContractError('unsupported', 'scoped native policy')
    if value['expected_generation'] != context.expected_generation:
        raise ContractError('stale', 'presence generation')
    if value['request_id'] in context.consumed_request_ids:
        raise ContractError('replay_conflict', 'consumed presence request')
    _binding(value, context.caller.identity)
    deadline = _fresh(value, context)
    grant = context.caller.grant
    if grant is not None:
        if 'presence.write' not in grant.scopes:
            raise ContractError('forbidden', 'grant scope')
        if not grant.never_expires:
            if grant.expires_at is None or _utc(grant.expires_at) <= _utc(context.now):
                raise ContractError('forbidden', 'expired grant')
            deadline = min(deadline, _utc(grant.expires_at))
    if value['authorization'] == 'subject':
        if context.subject.value['kind'] != 'native':
            raise ContractError('forbidden', 'guest has no native signing identity')
        identity = _identity(context.subject_identity)
        if context.subject.value['did'] not in (identity.principal, identity.signing_key_id):
            raise ContractError('authority_unavailable', 'subject identity binding')
    else:
        if 'ownership_proof' not in value:
            raise ContractError('invalid', 'ownership proof')
        pin = context.ownership_pin
        if pin is None or not pin.authorization_revision:
            raise ContractError('authority_unavailable', 'ownership authority')
        try:
            canonical_record(pin.subject)
        except ContractError as error:
            raise ContractError('authority_unavailable', 'ownership pin target') from error
        if pin.subject.value != context.subject.value or pin.audience != context.audience:
            raise ContractError('authority_unavailable', 'ownership pin target')
        identity = _identity(pin.owner)
        issuer = _identity(pin.issuer)
        if issuer.principal == identity.principal or issuer.signing_key_id == identity.signing_key_id:
            raise ContractError('authority_unavailable', 'owner cannot issue its own ownership proof')
        proof_artifact = decode_record('SignedArtifact', canonical_json_bytes(value['ownership_proof']))
        proof = _record(proof_artifact, 'BindingOwnershipProof' if binding else 'OwnershipProof').value
        if (proof['subject'], proof['owner'], proof['platform'], proof['scope'], proof['audience']) != (
                context.subject.value, identity.principal, value['platform'], value['scope'], context.audience):
            raise ContractError('forbidden', 'ownership proof target')
        if binding and proof['mode'] != value['mode']:
            raise ContractError('forbidden', 'ownership proof mode')
        if value['operation'] not in proof['operations']:
            raise ContractError('forbidden', 'ownership proof operation')
        if proof['authorization_revision'] != pin.authorization_revision:
            raise ContractError('stale', 'ownership revision')
        _signature(proof_artifact, proof, issuer)
        deadline = min(deadline, _fresh(proof, context))
    _signature(artifact, value, identity)
    output = {key: value[key] for key in ('subject', 'platform', 'scope', 'mode', 'operation', 'expected_generation', 'request_id')}
    if binding:
        output['binding_digest'] = value['binding_digest']
    output.update(version='aweb-verified-presence-binding-v1' if binding else 'aweb-verified-presence-v1',
                  intent_hash='sha256:' + hashlib.sha256(artifact.value['signed_payload'].encode()).hexdigest(),
                  authorization_revision=context.authorization_revision,
                  expires_at=deadline.isoformat(timespec='seconds').replace('+00:00', 'Z'))
    return decode_record('VerifiedPresenceBinding' if binding else 'VerifiedPresence', canonical_json_bytes(output))


def verify_native_presence(artifact: ContractRecord, context: PresenceVerificationContext) -> ContractRecord:
    return _verify(artifact, context, binding=False)


def verify_presence_binding(artifact: ContractRecord, context: PresenceVerificationContext) -> ContractRecord:
    return _verify(artifact, context, binding=True)


class PresenceContextProvider(Protocol):
    async def resolve(self, auth: MessagingAuth, intent: ContractRecord) -> PresenceVerificationContext:
        """Return independent current identity/owner/policy/lifecycle facts for this action."""
        ...


class PresenceVerifier:
    """Public P0 port adapter. The embedding supplies the authority provider."""
    def __init__(self, provider: PresenceContextProvider):
        self.provider = provider

    async def _verify(self, auth: MessagingAuth, artifact: ContractRecord, *, binding: bool) -> ContractRecord:
        if artifact.schema != 'SignedArtifact':
            raise ContractError('invalid', 'signed artifact')
        artifact = decode_record('SignedArtifact', canonical_record(artifact))
        intent = _record(artifact, 'PresenceBindingIntent' if binding else 'PresenceIntent')
        context = await self.provider.resolve(auth, intent)
        caller = context.caller
        _identity(caller.identity)
        if caller.identity.signing_key_id != auth.did_key or caller.identity.principal not in (auth.did_key, auth.did_aw):
            raise ContractError('forbidden', 'authenticated caller binding')
        expected = None if auth.grant is None else PresenceGrant(frozenset(auth.grant.scopes), auth.grant.expires_at, auth.grant.never_expires)
        if caller.grant != expected:
            raise ContractError('forbidden', 'authenticated grant binding')
        return _verify(artifact, context, binding=binding)

    async def verify_presence(self, auth: MessagingAuth, intent: ContractRecord) -> ContractRecord:
        return await self._verify(auth, intent, binding=False)

    async def verify_presence_binding(self, auth: MessagingAuth, intent: ContractRecord) -> ContractRecord:
        return await self._verify(auth, intent, binding=True)
