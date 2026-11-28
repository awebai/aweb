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
from legacy_schema import remove_attestation_inventory
from policy_inputs import policy_file


def target():
    _, public = generate_keypair()
    key = did_from_public_key(public)
    return stable_id_from_did_key(key), key


def test_absent_policy_is_off_and_operator_can_issue_without_awsign(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    with store._connection() as db:
        assert "human_issuance" not in {
            row[1] for row in db.execute("PRAGMA table_info(configuration)")
        }
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


def test_configured_gate_requires_the_enrollment_site_and_private_issuance_cannot_bypass(
    tmp_path,
):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    policy = policy_file(tmp_path / "human-approval.json", store.descriptor().domain)
    derived = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=policy,
    )
    assert derived.approval_origin == "https://approval.example"
    assert derived.rp_id == "approval.example"
    holder = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=policy,
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    )
    with pytest.raises(Refused, match="human_approval_required"):
        holder.issue_person_certificate(*target())
    assert holder.bootstrap_pending(*target())["state"] == "enrollment_pending"


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
        assert r.status_code == 401
        r = await client.post("/v1/enrollments/" + person, json={})
        assert r.status_code == 401


def test_old_private_setting_is_not_an_accepted_alias(tmp_path):
    state = tmp_path / "private"
    KeyStore.create(state, organisation="example.test")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(state),
            "configure",
            "--human-issuance",
            "approved",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_existing_store_migrates_with_keys_and_audit_unchanged(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    descriptor = store.descriptor()
    with store._connection() as db, db:
        # Restore the v2 schema before running the ordered migrations.
        remove_attestation_inventory(db)
        db.execute("ALTER TABLE enrollments DROP COLUMN retired_at")
        db.execute("DROP TABLE person_revisions")
        db.execute(
            "CREATE TABLE revision (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value INTEGER NOT NULL)"
        )
        db.execute("INSERT INTO revision VALUES (1,0)")
        db.execute("PRAGMA user_version=2")
    with pytest.raises(Refused, match="schema_unavailable"):
        KeyStore.open(store.directory)
    store.migrate()
    reopened = KeyStore.open(store.directory)
    assert reopened.descriptor() == descriptor
    with reopened._connection() as db:
        assert "human_issuance" not in {
            row[1] for row in db.execute("PRAGMA table_info(configuration)")
        }
    assert reopened.audit() == []


def test_applied_policy_changes_are_audited_atomically(tmp_path):
    import base64
    import sqlite3
    from approval_service.canonical import parse

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    path = policy_file(tmp_path / "human-approval.json", "example.test", None)
    holder = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=path,
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    )
    policy_file(path, "example.test")
    holder.gate()
    holder.gate()
    policy_file(path, "example.test", None)
    holder.gate()
    rows = store.audit()
    assert len(rows) == 2
    changes = []
    for row in rows:
        assert row["operation"] == "human_approval_change"
        assert row["actor"] == "operator" and row["at"] > 0
        raw = base64.b64decode(row["payload"])
        prefix = b"aweb.key-holder.human-approval/1\n"
        assert raw.startswith(prefix)
        changes.append(parse(raw[len(prefix) :]))
    assert [(c["from"]["require"], c["to"]["require"]) for c in changes] == [
        ({}, {"organisation.human.add": "passkey"}),
        ({"organisation.human.add": "passkey"}, {}),
    ]
    with store._connection() as db:
        db.execute(
            "CREATE TRIGGER fail_policy BEFORE INSERT ON signatures WHEN NEW.operation='human_approval_change' BEGIN SELECT RAISE(ABORT,'policy_failed'); END"
        )
    policy_file(path, "example.test")
    with pytest.raises(sqlite3.IntegrityError, match="policy_failed"):
        holder.gate()
    assert store.audit() == rows


@pytest.mark.parametrize(
    "origin", ["http://holder.example", "https://holder.example/path"]
)
def test_approval_configured_holder_refuses_an_origin_the_service_would_refuse(
    tmp_path, origin
):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    with pytest.raises(Refused, match="enforcer_origin_invalid"):
        Holder(
            store,
            registry=None,
            origin=origin,
            approval_origin="https://approval.example",
            rp_id="approval.example",
            grading=EnrollmentGrading("passkey_only", None),
        )
    # No approval service: the existing HTTP operator/routine lane stays valid.
    if origin.startswith("http:"):
        Holder(store, registry=None, origin=origin)


@pytest.mark.parametrize(
    "origin", ["http://holder.example", "https://holder.example/path"]
)
def test_cli_refuses_bad_approval_audience_before_starting_a_listener(tmp_path, origin):
    state = tmp_path / "private"
    KeyStore.create(state, organisation="example.test")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(state),
            "--registry-origin",
            "https://registry.example",
            "--origin",
            origin,
            "--approval-origin",
            "https://approval.example",
            "--rp-id",
            "approval.example",
            "--grading",
            "passkey_only",
            "serve",
            "--port",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert result.returncode == 1
    assert json.loads(result.stderr) == {"error": "enforcer_origin_invalid"}
