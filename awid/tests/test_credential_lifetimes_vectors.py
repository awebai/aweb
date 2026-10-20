"""One public byte authority consumed by all three verifier languages."""
import copy
import json
from pathlib import Path
from datetime import datetime

import pytest
from awid.certificates import CertificateValidationError, validate_certificate_lifetime
from awid.credential_policy import CredentialPolicyError, policy_signing_bytes, verify_credential_policy
from awid.did import public_key_from_did
from awid.signing import VerifyResult, canonical_json_bytes, verify_signature_with_public_key

VECTOR = Path(__file__).parents[2] / "docs" / "vectors" / "certificate-lifetimes-v2.json"


def test_shared_lifetime_and_policy_wire_bytes():
    vector = json.loads(VECTOR.read_text())
    key = public_key_from_did(vector['team_did_key'])
    for item in vector['certificates']:
        cert = copy.deepcopy(item['certificate'])
        signature = cert.pop('signature')
        assert canonical_json_bytes(cert).decode() == item['canonical']
        outcome = 'valid'
        try:
            # All consumers reject v1-shaped lifetime fields before use.
            if cert['version'] == 1 and ('expires_at' in cert or 'validity_class' in cert):
                validate_certificate_lifetime(cert, now=datetime.fromisoformat(vector['now']))
            if verify_signature_with_public_key(key, canonical_json_bytes(cert), signature) != VerifyResult.VERIFIED:
                outcome = 'signature_invalid'
            else:
                validate_certificate_lifetime(cert, now=datetime.fromisoformat(vector['now']))
        except CertificateValidationError as exc:
            outcome = exc.code
        assert outcome == item['expected'], item['name']
    policy = vector['policy']
    assert policy_signing_bytes(policy['record']).decode() == policy['signing_bytes']
    assert verify_credential_policy(policy['record'], policy['signature'], team_id='ops:example.test', team_did_key=vector['team_did_key']) == policy['record']
    policy['record']['identity_grant'] = 1
    with pytest.raises(CredentialPolicyError):
        verify_credential_policy(policy['record'], policy['signature'], team_id='ops:example.test', team_did_key=vector['team_did_key'])
