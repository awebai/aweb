"""aweb.team-credential-policy/1: optional maxima authorized by the team key."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from awid.did import public_key_from_did
from awid.signing import VerifyResult, canonical_json_bytes, verify_signature_with_public_key

POLICY_FIELDS = ('member_certificate', 'ephemeral_certificate', 'identity_grant', 'hosted_mcp_grant')
RECORD_FIELDS = frozenset(('v', 'type', 'team_id', 'team_did_key', 'revision', 'issued_at', *POLICY_FIELDS))
SIGNING_PREFIX = b'aweb.team-credential-policy/1\n'


class CredentialPolicyError(ValueError):
    pass


def policy_signing_bytes(record: dict[str, Any]) -> bytes:
    return SIGNING_PREFIX + canonical_json_bytes(record)


def verify_credential_policy(record: Any, signature: Any, *, team_id: str, team_did_key: str) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise CredentialPolicyError('Invalid credential policy fields')
    if type(record['v']) is not int or record['v'] != 1 or record['type'] != 'aweb.team-credential-policy':
        raise CredentialPolicyError('Invalid credential policy type/version')
    if record['team_id'] != team_id or record['team_did_key'] != team_did_key:
        raise CredentialPolicyError('Credential policy team or current key mismatch')
    if type(record['revision']) is not int or not 1 <= record['revision'] <= 2**53 - 1:
        raise CredentialPolicyError('Invalid credential policy revision')
    for field in POLICY_FIELDS:
        value = record[field]
        if value is not None and (type(value) is not int or not 1 <= value <= 2**31 - 1):
            raise CredentialPolicyError(f'Invalid credential policy {field}')
    try:
        if not isinstance(record['issued_at'], str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', record['issued_at']):
            raise ValueError('timestamp')
        issued = datetime.strptime(record['issued_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if issued > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError('future timestamp')
        key = public_key_from_did(team_did_key)
    except (TypeError, ValueError) as exc:
        raise CredentialPolicyError('Invalid credential policy key/issued_at') from exc
    if not isinstance(signature, str) or verify_signature_with_public_key(key, policy_signing_bytes(record), signature) != VerifyResult.VERIFIED:
        raise CredentialPolicyError('Invalid credential policy signature')
    return dict(record)
