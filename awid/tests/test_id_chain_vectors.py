"""Pure ancestry consumes final cases by name from the root vector authority."""
import copy
import json
from pathlib import Path
import pytest
from awid.id_certificates import IDChainEvidence, IDCertificateError, request_disposition, status_cache_mode, status_request, verify_id_chain

V = json.loads((Path(__file__).resolve().parents[2] / 'docs/vectors/id-certificates-v1.json').read_text())

def inputs(case):
    status = copy.deepcopy(V['status_fixtures'][case['status']])
    subject = dict(case['subject'], **case.get('subject_patch', {}))
    bundle = {'v': 1, 'type': 'aweb.id-chain', 'certificates': [copy.deepcopy(V['certificates'][n]['signed']) for n in case['chain']]}
    if not case['chain'] or case.get('presented_chain') is False:
        bundle = None
    epoch = next(e for e in reversed(status['namespace']['epochs']) if e['retired_at'] is None)
    authority = case.get('namespace_authority', {'domain': status['domain'], 'dns_name': '_awid.' + status['domain'], 'inherited': False, 'controller_key': epoch['did_key']})
    cache = case.get('cache', {'age_seconds': 0, 'refresh': 'not_needed'})
    evidence = None if case.get('status_source') == 'caller' else IDChainEvidence(status, authority, cache['age_seconds'], cache['refresh'] == 'failed')
    return bundle, subject, evidence, status['domain']

@pytest.mark.parametrize('case', V['verification_cases'], ids=lambda c: c['name'])
def test_final_identity_tree_verification_and_request_decision(case):
    bundle, subject, evidence, domain = inputs(case)
    result = verify_id_chain(bundle, subject=subject, evidence=evidence, domain=domain)
    assert result == case['expected']
    for human_required, key in [(False, 'ordinary'), (True, 'human_required')]:
        assert request_disposition(result, subject=subject, original_auth_passed=case['original_auth'] == 'passed', human_required=human_required) == case['expected_request'][key]
    if 'tree_lookup' in case:
        assert (status_request(bundle, subject, domain=domain) is not None) == case['tree_lookup']
    if 'expected_cache_mode' in case:
        c = case['cache']
        assert status_cache_mode(c['age_seconds'], c['refresh'] == 'failed') == case['expected_cache_mode']

def test_omitted_global_domain_requires_private_resolution_input():
    subject = V['verification_cases'][0]['subject'] | {'id': V['keys']['global_agent']['did_aw']}
    with pytest.raises(IDCertificateError) as exc: status_request(None, subject)
    assert exc.value.code == 'evidence_unavailable'
    assert verify_id_chain(None, subject=subject, evidence=None)['reason'] == 'evidence_unavailable'

def test_status_request_only_sends_global_ids_in_chain_order():
    bundle, subject, _, domain = inputs(V['verification_cases'][0])
    assert status_request(bundle, subject) == {'v': 1, 'domain': domain, 'ids': [V['keys']['alice']['did_aw']]}
    assert status_request(None, subject, domain=domain) is None

def test_ancestry_does_not_reuse_decode_time_claimed_issuer_verdict():
    case = next(c for c in V['verification_cases'] if c['name'] == 'old-local-signature-after-parent-rotation')
    bundle, subject, evidence, domain = inputs(case)
    from awid.id_certificates import verify_id_certificate
    signed = bundle['certificates'][-1]
    verify_id_certificate(signed, issuer_key=signed['certificate']['issuer_key'])
    assert verify_id_chain(bundle, subject=subject, evidence=evidence, domain=domain)['reason'] == 'stale_issuer_key'

@pytest.mark.parametrize('mutation', ['extra', 'duplicate', 'missing', 'wrong-domain', 'over-limit'])
def test_invalid_status_never_confers_authority(mutation):
    bundle, subject, evidence, domain = inputs(V['verification_cases'][0])
    s = evidence.status
    if mutation == 'extra': s['unrecognized'] = True
    if mutation == 'duplicate': s['identities'].append(copy.deepcopy(s['identities'][0]))
    if mutation == 'missing': del s['missing']
    if mutation == 'wrong-domain': s['domain'] = 'attacker.example'
    if mutation == 'over-limit': s['missing'] = ['x' * 131072]
    assert verify_id_chain(bundle, subject=subject, evidence=evidence, domain=domain)['reason'] == 'evidence_unavailable'
