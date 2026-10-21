"""Typed identity helpers, not membership, signature verification or activation.

The bridge uses derivation inputs privately. A caller must separately verify
the signed policy, current signer authority and exact message GroupContext.
No display name, account link or valid bridge signature creates membership.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re

from awid.signing import canonical_json_bytes
from .contract import ContractError, ContractRecord, canonical_record, decode_record


def _participant(ref: ContractRecord) -> ContractRecord:
    if ref.schema not in ('NativeParticipant', 'BridgedParticipant'):
        raise ContractError('invalid', 'participant reference')
    return decode_record(ref.schema, canonical_record(ref))


def _session(session_id: str) -> None:
    # Reuse P0's UUID primitive without inventing a second session identifier.
    decode_record('PresenceScope', canonical_json_bytes(dict(kind='session', session_id=session_id)))


def require_native_participant_input(row: dict) -> None:
    """A legacy native adapter must never discard an explicit guest tag."""
    if row.get('participant_kind') not in (None, 'native') or row.get('kind') == 'bridged':
        raise ContractError('unsupported', 'managed participant requires P5')
    ref = row.get('participant_ref')
    if ref is None:
        return
    if type(ref) is not dict:
        raise ContractError('invalid', 'participant reference')
    if ref.get('kind') == 'bridged':
        raise ContractError('unsupported', 'managed participant requires P5')
    ref = decode_record('NativeParticipant', canonical_json_bytes(ref)).value
    did = row.get('did') or row.get('did_aw') or row.get('did_key') or ''
    if ref['did'] != str(did).strip():
        raise ContractError('invalid', 'native participant DID binding')


def scoped_participant_key(session_id: str, ref: ContractRecord) -> bytes:
    """Exact local lookup key. It is neither a route nor a new public address."""
    _session(session_id)
    return canonical_json_bytes(dict(session_id=session_id, participant=_participant(ref).value))


def derive_guest_reference(key: bytes, *, bridge: str, platform: str, account_scope: str,
                           account_id: str, subject_kind: str, generation: str,
                           session_id: str) -> ContractRecord:
    """Bridge-private pairwise derivation. Never put these inputs in a message.

    One independent subject key/generation is shared by intake bots of this
    bridge. Loss needs a fresh key/generation, never guessed continuity. Private
    opt-out/account mappings must survive independently; this grants no admission.
    """
    if type(key) is not bytes or len(key) < 32:
        raise ContractError('invalid', 'subject derivation key')
    _session(session_id)
    try:
        private_text_valid = all(type(v) is str and v and len(v.encode()) <= 4096 for v in (account_scope, account_id, generation))
    except UnicodeError:
        private_text_valid = False
    if (type(platform) is not str or re.fullmatch(r'[a-z][a-z0-9_]{0,31}', platform) is None or
            subject_kind not in ('human', 'bot') or not private_text_valid):
        raise ContractError('invalid', 'private subject derivation context')
    # Validate the bridge separately; its namespace is not an external account ID.
    decode_record('BridgedParticipant', canonical_json_bytes(dict(kind='bridged', bridge=bridge, subject='validation')))
    raw = canonical_json_bytes(dict(version='aweb-guest-subject-v1', bridge=bridge, platform=platform,
                                    account_scope=account_scope, account_id=account_id, subject_kind=subject_kind,
                                    generation=generation, session_id=session_id))
    subject = base64.urlsafe_b64encode(hmac.new(key, raw, hashlib.sha256).digest()).decode().rstrip('=')
    return decode_record('BridgedParticipant', canonical_json_bytes(dict(kind='bridged', bridge=bridge, subject=subject)))


def project_session_author(*, expected_session: str, expected_participant: ContractRecord,
                           group: ContractRecord, signer_principal: str, signer_verified: bool,
                           confidentiality: str) -> ContractRecord:
    """Project already-verified facts for an exact participant/message context.

    This only checks identity binding. It does not check membership/epoch,
    delegation, current policy, consent, opt-out, history or crypto signatures;
    P4/P5 must establish those facts before exposing a managed message.
    """
    if group.schema != 'GroupContext':
        raise ContractError('invalid', 'group context')
    group = decode_record('GroupContext', canonical_record(group))
    expected = _participant(expected_participant)
    actual = group.value['author_ref']
    actual_ref = decode_record('NativeParticipant' if actual['kind'] == 'native' else 'BridgedParticipant', canonical_json_bytes(actual))
    if scoped_participant_key(expected_session, expected) != scoped_participant_key(group.value['session_id'], actual_ref):
        raise ContractError('forbidden', 'exact session participant')
    if signer_verified is not True:
        raise ContractError('invalid', 'unverified signer')
    guest = actual['kind'] == 'bridged'
    if signer_principal != actual['bridge' if guest else 'did']:
        raise ContractError('forbidden', 'author signer binding')
    if guest and confidentiality not in ('bridge_readable', 'server_readable'):
        raise ContractError('invalid', 'guest confidentiality')
    return decode_record('AuthorProjection', canonical_json_bytes(dict(
        author=actual, author_assurance='platform_attested' if guest else 'native',
        confidentiality=confidentiality, signer_verified=True,
        trust_status='external_untrusted' if guest else 'verified_custodial' if confidentiality == 'hosted_readable' else 'verified',
        verified=not guest)))
