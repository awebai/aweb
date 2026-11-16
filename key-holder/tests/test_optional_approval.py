"""Operator issuance and optional enrollment are separate authority paths."""

from datetime import datetime, timezone
import json
import subprocess
import sys

import httpx
import pytest
from awid.did import generate_keypair, did_from_public_key, stable_id_from_did_key
from awid.id_certificates import verify_id_certificate
from approval_service.grading import EnrollmentGrading

from aweb_key_holder.enrollment import Holder
from aweb_key_holder.http import create_app
from aweb_key_holder.keys import KeyStore, Refused


def target():
    _, public = generate_keypair()
    key = did_from_public_key(public)
    return stable_id_from_did_key(key), key


def test_operator_is_persisted_default_and_can_issue_without_awsign(tmp_path):
    store = KeyStore.create(tmp_path / 'private', organisation='example.test')
    assert store.human_issuance() == 'operator'
    holder = Holder(store, registry=None, origin='https://holder.example')
    person, key = target()
    result = holder.issue_person_certificate(person, key)
    assert set(result) == {'state', 'person', 'identity_key', 'certificate'}
    assert result['state'] == 'issued'
    verify_id_certificate(result['certificate'], issuer_key=store.descriptor().did_key)
    with store._connection() as db:
        assert db.execute('SELECT count(*) FROM enrollments').fetchone()[0] == 0
    audit = store.audit()
    assert len(audit) == 1 and audit[0]['operation'] == 'namespace_id_issue'
    assert audit[0]['actor'] == 'operator' and audit[0]['approval'] is None
    with pytest.raises(Refused, match='approver_not_active'):
        holder.active_person(person)


def test_approved_mode_requires_configuration_but_keeps_operator_command(tmp_path):
    store = KeyStore.create(tmp_path / 'private', organisation='example.test')
    store.set_human_issuance('approved')
    with pytest.raises(Refused, match='approval_not_configured'):
        Holder(store, registry=None, origin='https://holder.example')
    holder = Holder(store, registry=None, origin='https://holder.example',
        approval_origin='https://approval.example', rp_id='approval.example',
        grading=EnrollmentGrading('passkey_only',None))
    assert holder.issue_person_certificate(*target())['state'] == 'issued'
    assert store.audit()[0]['actor'] == 'operator'
    with pytest.raises(Refused,match='issuing_setting_invalid'):
        store.set_human_issuance('agent')
    assert store.human_issuance() == 'approved'


@pytest.mark.asyncio
async def test_unconfigured_enrollment_and_operator_public_issue_are_clear_refusals(tmp_path):
    holder = Holder(KeyStore.create(tmp_path / 'private',organisation='example.test'),
        registry=None, origin='https://holder.example')
    person,_=target()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(holder)),base_url=holder.origin) as client:
        r=await client.post('/v1/humans',json={})
        assert r.status_code==403 and r.json()['error']['code']=='human_issuance_operator'
        r=await client.post('/v1/enrollments/'+person,json={})
        assert r.status_code==403 and r.json()['error']['code']=='approval_not_configured'


def test_private_cli_persists_operator_setting_without_runtime_site(tmp_path):
    state=tmp_path/'private'
    def run(*args):
        return subprocess.run([sys.executable,'-m','aweb_key_holder.cli','--state',str(state),*args],capture_output=True,text=True)
    assert run('init','--organisation','example.test').returncode==0
    r=run('configure','--human-issuance','approved')
    assert r.returncode==0,(r.stdout,r.stderr)
    assert json.loads(r.stdout)=={'human_issuance':'approved'}
    assert KeyStore.open(state).human_issuance()=='approved'
