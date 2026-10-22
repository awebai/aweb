"""Both language readers consume the same frozen public bytes and refusals."""
import hashlib
import json
from pathlib import Path

import pytest
from nacl.signing import VerifyKey

from aweb.human_channels.contract import ContractError, decode_record, canonical_record, require_capability, require_canonical_signed_payload, PROFILE

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / 'docs/vectors/human-channels-v1.json').read_text())


def test_compiled_profile_is_the_public_profile():
    assert PROFILE == json.loads((ROOT / 'docs/vectors/human-channels-profile-v1.json').read_text())


@pytest.mark.parametrize('case', VECTORS['valid'], ids=lambda c: c['name'])
def test_shared_canonical_signature_vectors(case):
    raw = json.dumps(case['value'], ensure_ascii=False).encode()
    record = decode_record(case['schema'], raw)
    canonical = canonical_record(record)
    require_canonical_signed_payload(canonical)
    assert canonical.decode() == case['canonical']
    assert 'sha256:' + hashlib.sha256(canonical).hexdigest() == case['sha256']
    import base64
    signature = base64.b64decode(case['signature'] + '==')
    key = VerifyKey(bytes.fromhex(VECTORS['public_test_key_hex']))
    key.verify(canonical, signature)
    with pytest.raises(Exception):
        key.verify(canonical + b' ', signature)


@pytest.mark.parametrize('case', VECTORS['invalid'], ids=lambda c: c['name'])
def test_shared_refusal_vectors(case):
    with pytest.raises(ContractError) as error:
        decode_record(case['schema'], case['json'].encode())
    assert error.value.code == case['code']


@pytest.mark.parametrize('raw', [b'{} {}', b'{"did":"\\ud800","kind":"native"}', b'\xff', b'[]'])
def test_invalid_json_refuses_before_projection(raw):
    with pytest.raises(ContractError):
        decode_record('NativeParticipant', raw)


@pytest.mark.parametrize('case', VECTORS['tampered'], ids=lambda c: c['name'])
def test_semantic_tampering_breaks_original_signature(case):
    import base64
    from nacl.exceptions import BadSignatureError
    key = VerifyKey(bytes.fromhex(VECTORS['public_test_key_hex']))
    with pytest.raises(BadSignatureError):
        key.verify(case['json'].encode(), base64.b64decode(case['signature'] + '=='))


def test_unknown_advertised_capability_preserves_known_neighbor():
    case = next(c for c in VECTORS['valid'] if c['name'] == 'future_advertised_capability')
    record = decode_record('Capabilities', case['canonical'].encode())
    require_capability(record, 'signed-via-v1')
    for token in ('future-v9', 'managed-chat-encrypted-v1', 'group-federation-v1'):
        with pytest.raises(ContractError, match='unsupported'):
            require_capability(record, token)


def test_canonicalization_rechecks_mutated_dto():
    record = decode_record('NativeParticipant', b'{"kind":"native","did":"did:aw:vector"}')
    record.value['external_account_id'] = 'not-public'
    with pytest.raises(ContractError):
        canonical_record(record)


@pytest.mark.parametrize('raw', [b'{ }', b'{"b":1,"a":2}', b'{"a":"\\u0061"}', b'{"a":1.0}', b'{"a":-0}', b'[]', b'{"a":1,"a":1}', b'{"a":"\\ud800"}', b'\xff'])
def test_signed_payload_requires_original_canonical_bytes(raw):
    with pytest.raises(ContractError):
        require_canonical_signed_payload(raw)


def test_valid_signature_does_not_make_noncanonical_artifact_acceptable():
    import base64
    case = next(c for c in VECTORS['invalid'] if c['name'] == 'noncanonical_signed_payload')
    artifact = json.loads(case['json'])
    VerifyKey(bytes.fromhex(VECTORS['public_test_key_hex'])).verify(
        artifact['signed_payload'].encode(), base64.b64decode(artifact['signature'] + '=='))
    with pytest.raises(ContractError):
        decode_record('SignedArtifact', case['json'].encode())
