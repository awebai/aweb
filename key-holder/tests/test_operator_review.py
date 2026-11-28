"""Private operator controls and public refusals use real SQLite/signatures."""

import json
import subprocess
import sys
import time

import httpx
import pytest
from approval_service.enrollment import PublicIssuer
from approval_service.grading import EnrollmentGrading
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.http import create_app
from aweb_key_holder.keys import KeyStore, Refused
from awid.id_certificates import id_certificate_id
from test_enrollment import creation, owner, person
from policy_inputs import policy_file


def world(tmp_path, *, approved=True):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    policy = policy_file(
        tmp_path / "human-approval.json",
        store.descriptor().domain,
        "passkey" if approved else None,
    )
    return Holder(
        store,
        human_approval_config=policy,
        registry=None,
        origin="https://holder.example",
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    )


def test_bootstrap_audit_names_the_operator_not_the_pending_subject(tmp_path):
    holder = world(tmp_path)
    holder.bootstrap_pending(*person())
    records = [
        r
        for r in holder.store.audit()
        if r["operation"] in ("namespace_id_issue", "enrollment_intent")
    ]
    assert len(records) == 2
    assert all(r["actor"] == "operator" for r in records)


def test_private_audit_reader_is_paged_and_needs_no_runtime_config(tmp_path):
    holder = world(tmp_path, approved=False)
    holder.issue_person_certificate(*person())
    holder.issue_person_certificate(*person())
    entries = holder.store.audit()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(holder.store.directory),
            "audit",
            "--after",
            str(entries[0]["sequence"]),
            "--limit",
            "1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [entries[1]]


def request_for(holder, target, key):
    with holder.store._connection() as db:
        start = int(time.time())
        certificate = holder._certificate(holder.store.descriptor(), target, key, start)
        return holder._request(
            db,
            purpose="act_approval",
            operation="human.add",
            requester={"kind": "identity", "id": target, "key": key},
            approver=target,
            target={
                "person": target,
                "identity_key": key,
                "certificate": id_certificate_id(certificate),
            },
            start=start,
            deadline=start + 600,
        )


def test_unrelated_person_does_not_invalidate_a_prepared_request(tmp_path):
    holder = world(tmp_path)
    target, key = person()
    before = request_for(holder, target, key)
    holder.bootstrap_pending(*person())
    after = request_for(holder, target, key)
    assert before["act"]["expected_revision"] == after["act"]["expected_revision"]


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [False, True])
async def test_unsigned_requests_cannot_discover_operator_mode_or_enrollment_configuration(
    tmp_path, configured
):
    if configured:
        holder = world(tmp_path)
    else:
        holder = Holder(
            KeyStore.create(tmp_path / "private", organisation="example.test"),
            registry=None,
            origin="https://holder.example",
        )
    target, _ = person()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        for path in ("/v1/humans", f"/v1/enrollments/{target}"):
            response = await client.post(path, json={})
            assert response.status_code == 401


@pytest.mark.parametrize("state", ["expired", "evidence"])
def test_retirement_exits_stuck_state_without_erasing_evidence_or_audit(
    tmp_path, state
):
    holder = world(tmp_path)
    if state == "expired":
        from pending import expire_pending

        target, key = person()
        holder.bootstrap_pending(target, key)
        expire_pending(holder, target)
    else:
        target, receipt = creation(holder)
        holder.finish_creation(
            target,
            receipt,
            issuer=PublicIssuer(holder.store.descriptor().did_key, int(time.time())),
            **owner(holder, target),
        )
    with holder.store._connection() as db:
        previous = dict(
            db.execute("SELECT * FROM enrollments WHERE person=?", (target,)).fetchone()
        )
        consumed = db.execute("SELECT count(*) FROM consumed").fetchone()[0]
    audit = holder.store.audit()
    with holder.store._connection() as db:
        revision = holder.store.person_revision(db, target)
    with pytest.raises(Refused, match="bootstrap_closed"):
        holder.bootstrap_pending(*person())
    result = holder.store.retire_person(target)
    assert result["state"] == "retired"
    with holder.store._connection() as db:
        row = dict(
            db.execute("SELECT * FROM enrollments WHERE person=?", (target,)).fetchone()
        )
        assert row["evidence"] == previous["evidence"]
        assert row["active"] == 0
        assert db.execute("SELECT count(*) FROM consumed").fetchone()[0] == consumed
    assert holder.store.audit()[:-1] == audit
    assert holder.store.audit()[-1]["actor"] == "operator"
    with holder.store._connection() as db:
        assert holder.store.person_revision(db, target) == revision + 1
    assert holder.store.retire_person(target) == result
    assert len(holder.store.audit()) == len(audit) + 1
    with pytest.raises(Refused, match="enrollment_replacement_unavailable"):
        holder.pending(target)
    with pytest.raises(Refused, match="enrollment_replacement_unavailable"):
        holder.bootstrap_pending(target, previous["identity_key"])
    with pytest.raises(Refused, match="approver_not_active"):
        holder.active_person(target)
    assert holder.bootstrap_pending(*person())["state"] == "enrollment_pending"


def test_person_history_migrates_existing_enrollment_without_reset(tmp_path):
    holder = world(tmp_path)
    target, key = person()
    saved = holder.bootstrap_pending(target, key)
    audit = holder.store.audit()
    from legacy_schema import remove_attestation_inventory

    with holder.store._connection() as db, db:
        remove_attestation_inventory(db)
        db.execute("ALTER TABLE enrollments DROP COLUMN retired_at")
        db.execute("DROP TABLE person_revisions")
        db.execute(
            "CREATE TABLE revision (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value INTEGER NOT NULL)"
        )
        db.execute("INSERT INTO revision VALUES(1,7)")
        db.execute(
            "ALTER TABLE configuration ADD COLUMN human_issuance TEXT NOT NULL DEFAULT 'operator'"
        )
        db.execute("PRAGMA user_version=3")
    holder.store.migrate()
    reopened = KeyStore.open(holder.store.directory)
    assert holder.pending(target) == saved
    assert reopened.audit() == audit
    with reopened._connection() as db:
        assert reopened.person_revision(db, target) == 7
        assert reopened.person_revision(db, person()[0]) == 0
    reopened.retire_person(target)
    with reopened._connection() as db:
        assert reopened.person_revision(db, target) == 8


@pytest.mark.asyncio
async def test_self_signed_outsider_cannot_distinguish_existing_from_unknown_rows(
    tmp_path,
):
    from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
    from test_native_holder import call

    holder = world(tmp_path)
    target, key = person()
    holder.bootstrap_pending(target, key)
    seed, public = generate_keypair()
    outsider_key = did_from_public_key(public)
    outsider = stable_id_from_did_key(outsider_key)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        for suffix, body in [
            ("binding", {"material": {}, "registration_count": 1}),
            ("finish", {}),
            ("activate", {}),
        ]:
            answers = []
            for subject in (target, person()[0]):
                answer = await call(
                    client,
                    f"/v1/enrollments/{subject}/{suffix}",
                    body,
                    seed=seed,
                    key=outsider_key,
                    identity=outsider,
                    chain=[],
                )
                assert answer.status_code == 401
                answers.append(answer.json())
            assert answers[0] == answers[1]
