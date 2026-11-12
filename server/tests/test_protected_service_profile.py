"""Trusted public service configuration is closed, explicit and unambiguous."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from aweb.protected_signing.profile import ProfileRefused, ProtectedServiceProfile

FIXTURE = Path(__file__).resolve().parents[2] / 'docs/vectors/protected-service-profile-v1.json'


@pytest.fixture
def fields():
    return json.loads(FIXTURE.read_bytes())


def load(fields):
    return ProtectedServiceProfile.from_json(json.dumps(fields).encode())


def test_public_fixture_loads_and_selects_its_exact_scope(fields):
    profile = ProtectedServiceProfile.from_json(FIXTURE.read_bytes())
    binding = profile.binding_for(fields['bindings'][0]['scope'])
    assert binding.context().fields() == fields['bindings'][0]['scope']
    assert profile.request_origin == 'https://signer.customer.example'
    assert profile.human_origin == 'https://human.customer.example'
    assert profile.rp_id == 'human.customer.example'
    assert profile.namespace_keys() == {
        'customer.example': fields['namespace_authorities'][0]['controller_did'],
    }
    assert profile.fields() == fields


@pytest.mark.parametrize('key', ['request_origin', 'human_origin', 'registry_origin'])
@pytest.mark.parametrize('origin', [
    'https://other.example/path', 'https://user:password@other.example',
    'https://other.example?redirect=elsewhere', 'https://other.example/#x',
    'https://OTHER.example', 'https://other.example/',
])
def test_noncanonical_or_credential_bearing_origins_refuse(fields, key, origin):
    fields[key] = origin
    with pytest.raises(ProfileRefused, match='profile_invalid'):
        load(fields)


@pytest.mark.parametrize('change', ['rp', 'http_human', 'service', 'domain', 'human_domain',
                                   'key', 'policy', 'generation', 'version', 'secret'])
def test_mismatched_refs_or_unknown_secret_fields_refuse(fields, change):
    binding = fields['bindings'][0]
    if change == 'rp':
        fields['rp_id'] = 'customer.example'
    elif change == 'http_human':
        fields['human_origin'] = 'http://human.customer.example'
    elif change == 'service':
        binding['scope']['service_id'] = 'other-signer'
    elif change == 'domain':
        binding['scope']['authority']['domain'] = 'other.example'
    elif change == 'human_domain':
        binding['scope']['human']['domain'] = 'other.example'
    elif change == 'key':
        binding['authority_key_did'] = 'did:key:invalid'
    elif change == 'policy':
        binding['policy']['ref'] = 'other-policy'
    elif change == 'generation':
        binding['scope']['generation'] = True
    elif change == 'version':
        fields['v'] = True
    else:
        binding['signing_key_file'] = '/worker/controller.key'
    with pytest.raises(ProfileRefused, match='profile_invalid'):
        load(fields)


@pytest.mark.parametrize('change', ['namespace', 'binding', 'generation', 'key'])
def test_duplicate_or_conflicting_bindings_refuse(fields, change):
    if change == 'namespace':
        fields['namespace_authorities'].append(copy.deepcopy(fields['namespace_authorities'][0]))
    else:
        other = copy.deepcopy(fields['bindings'][0])
        if change == 'generation':
            other['scope']['generation'] = 2
        elif change == 'key':
            other['scope']['human']['id'] = 'did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk'
            other['authority_key_did'] = fields['namespace_authorities'][0]['controller_did']
        fields['bindings'].append(other)
    with pytest.raises(ProfileRefused, match='profile_invalid'):
        load(fields)


def test_duplicate_json_fields_refuse():
    with pytest.raises(ProfileRefused, match='profile_invalid'):
        ProtectedServiceProfile.from_json(b'{"v":1,"v":1}')


def test_absent_scope_never_selects_a_default(fields):
    profile = load(fields)
    scope = copy.deepcopy(fields['bindings'][0]['scope'])
    scope['generation'] = 2
    with pytest.raises(ProfileRefused, match='profile_scope_refused'):
        profile.binding_for(scope)


def test_unknown_top_level_field_refuses(fields):
    fields['response_url'] = 'https://other.example/handoff'
    with pytest.raises(ProfileRefused, match='profile_invalid'):
        load(fields)
