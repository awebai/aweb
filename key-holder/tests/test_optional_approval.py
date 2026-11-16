"""Operator issuance and optional enrollment are separate authority paths."""

import json
import subprocess
import sys

import httpx
import pytest
from approval_service.grading import EnrollmentGrading
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.http import create_app
from aweb_key_holder.keys import KeyStore, Refused
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.id_certificates import verify_id_certificate


def target():
    _, public = generate_keypair()
    key = did_from_public_key(public)
    return stable_id_from_did_key(key), key


def test_operator_is_persisted_default_and_can_issue_without_awsign(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    assert store.human_issuance() == "operator"
    holder = Holder(store, registry=None, origin="https://holder.example")
    person, key = target()
    result = holder.issue_person_certificate(person, key)
    assert set(result) == {"state", "person", "identity_key", "certificate"}
    assert result["state"] == "issued"
    verify_id_certificate(result["certificate"], issuer_key=store.descriptor().did_key)
    with store._connection() as db:
        assert db.execute("SELECT count(*) FROM enrollments").fetchone()[0] == 0
    audit = store.audit()
    assert len(audit) == 1 and audit[0]["operation"] == "namespace_id_issue"
    assert audit[0]["actor"] == "operator" and audit[0]["approval"] is None
    with pytest.raises(Refused, match="approver_not_active"):
        holder.active_person(person)


def test_approved_mode_requires_configuration_but_keeps_operator_command(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    store.set_human_issuance("approved")
    with pytest.raises(Refused, match="approval_not_configured"):
        Holder(store, registry=None, origin="https://holder.example")
    holder = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    )
    assert holder.issue_person_certificate(*target())["state"] == "issued"
    assert store.audit()[0]["actor"] == "operator"
    with pytest.raises(Refused, match="issuing_setting_invalid"):
        store.set_human_issuance("agent")
    assert store.human_issuance() == "approved"


@pytest.mark.asyncio
async def test_unconfigured_enrollment_and_operator_public_issue_are_clear_refusals(
    tmp_path,
):
    holder = Holder(
        KeyStore.create(tmp_path / "private", organisation="example.test"),
        registry=None,
        origin="https://holder.example",
    )
    person, _ = target()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        r = await client.post("/v1/humans", json={})
        assert (
            r.status_code == 403
            and r.json()["error"]["code"] == "human_issuance_operator"
        )
        r = await client.post("/v1/enrollments/" + person, json={})
        assert (
            r.status_code == 403
            and r.json()["error"]["code"] == "approval_not_configured"
        )


def test_private_cli_persists_operator_setting_without_runtime_site(tmp_path):
    state = tmp_path / "private"

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "aweb_key_holder.cli", "--state", str(state), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    assert run("init", "--organisation", "example.test").returncode == 0
    r = run("configure", "--human-issuance", "approved")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert json.loads(r.stdout) == {"human_issuance": "approved"}
    assert KeyStore.open(state).human_issuance() == "approved"


def test_existing_store_migrates_with_keys_and_audit_unchanged(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    descriptor = store.descriptor()
    with store._connection() as db, db:
        # Exact preceding schema: only the new private setting is absent.
        db.execute("ALTER TABLE configuration DROP COLUMN human_issuance")
        db.execute("PRAGMA user_version=2")
    with pytest.raises(Refused, match="schema_unavailable"):
        KeyStore.open(store.directory)
    store.migrate()
    reopened = KeyStore.open(store.directory)
    assert reopened.descriptor() == descriptor
    assert reopened.human_issuance() == "operator"
    assert reopened.audit() == []


def test_issuing_rule_changes_are_audited_atomically(tmp_path):
    import base64
    from approval_service.canonical import parse

    store=KeyStore.create(tmp_path/'private',organisation='example.test')
    store.set_human_issuance('approved')
    store.set_human_issuance('approved')
    store.set_human_issuance('operator')
    rows=store.audit()
    assert len(rows)==2
    changes=[]
    for row in rows:
        assert row['operation']=='human_issuance_change'
        assert row['actor']=='operator' and row['at']>0
        raw=base64.b64decode(row['payload'])
        prefix=b'aweb.key-holder.setting/1\n'
        assert raw.startswith(prefix)
        changes.append(parse(raw[len(prefix):]))
    assert [(c['from'],c['to']) for c in changes]==[('operator','approved'),('approved','operator')]
    with store._connection() as db:
        db.execute("CREATE TRIGGER fail_setting BEFORE UPDATE OF human_issuance ON configuration BEGIN SELECT RAISE(ABORT,'setting_failed'); END")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError,match='setting_failed'):
        store.set_human_issuance('approved')
    assert store.human_issuance()=='operator' and store.audit()==rows
