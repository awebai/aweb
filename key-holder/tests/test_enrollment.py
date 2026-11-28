"""Holder-owned enrollment state and concrete shared protocol checks."""

import json
import sqlite3
import time
from datetime import UTC, datetime

import pytest
from approval_service.canonical import canonical, parse
from approval_service.encoding import decode, encode
from approval_service.enrollment import PublicIssuer
from approval_service.grading import EnrollmentGrading
from approval_service.requester import AdmittedRequester
from approval_service.seams import check_enrollment_intent, commitment
from approval_service.verify import Refused as ApprovalRefused
from authenticator import Passkey, packed_device
from aweb_key_holder.auth import Caller
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.keys import KeyStore, Refused
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from pending import expire_pending
from policy_inputs import policy_file


@pytest.fixture
def holder(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    policy = policy_file(tmp_path / "human-approval.json", store.descriptor().domain)
    return Holder(
        store,
        human_approval_config=policy,
        registry=None,
        origin="https://holder.example",
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    )


def person():
    _, public = generate_keypair()
    key = did_from_public_key(public)
    return stable_id_from_did_key(key), key


def test_first_bootstrap_is_exact_single_use_with_unchanged_retry_bounds(holder):
    target, key = person()
    # This private operator transaction is not the public authenticated endpoint.
    result = holder.bootstrap_pending(target, key)
    assert result == holder.bootstrap_pending(target, key)
    signed = result["intent"]
    root = holder.store.descriptor()
    checked = check_enrollment_intent(
        signed,
        issuer_key=root.did_key,
        requester=signed["intent"]["requester"],
        origin=holder.approval_origin,
        rp_id=holder.rp_id,
        now=int(datetime.now(UTC).timestamp()),
    )
    assert checked["state"] == "pending" and checked["person"] == target
    with pytest.raises(Refused, match="bootstrap_closed"):
        holder.bootstrap_pending(*person())
    assert {row["operation"] for row in holder.store.audit()} == {
        "namespace_id_issue",
        "enrollment_intent",
        "human_approval_change",
    }


def test_new_human_is_not_a_routine_signed_object_or_an_active_approver(holder):
    target, key = person()
    holder.bootstrap_pending(target, key)
    with pytest.raises(Refused, match="approver_not_active"):
        holder.active_person(target)
    assert (
        next(
            row
            for row in holder.store.audit()
            if row["operation"] == "namespace_id_issue"
        )["approval"]
        is None
    )


def test_bad_creation_proof_cannot_sign_evidence_or_consume_nonce(holder):
    target, key = person()
    result = holder.bootstrap_pending(target, key)
    with pytest.raises((ApprovalRefused, Refused)):
        holder.finish_creation(target, {}, issuer=None, **owner(holder, target))
    assert holder.pending(target) == result
    assert len(holder.store.audit()) == 3
    with holder.store._connection() as db:
        assert db.execute("SELECT count(*) FROM consumed").fetchone()[0] == 0


def test_unknown_or_substituted_enrollment_material_is_not_signed(holder):
    target, key = person()
    result = holder.bootstrap_pending(target, key)
    with pytest.raises((ApprovalRefused, Refused)):
        holder.bind_registration(
            target,
            {"state": "pending", "registrations": []},
            registration_count=1,
            **owner(holder, target),
        )
    assert holder.pending(target) == result
    assert len(holder.store.audit()) == 3


def owner(holder, person):
    """Explicit checked caller port for the storage/crypto component tests."""
    key = holder.pending(person)["intent"]["intent"]["identity_key"]
    caller = Caller(person, key, datetime.now(UTC).isoformat(), b"")
    return {
        "caller": caller,
        "admitted": AdmittedRequester(
            canonical(caller.descriptor), key, int(time.time())
        ),
    }


def creation(holder, identity=None, *, device=None):
    target, key = identity or person()
    intent = holder.bootstrap_pending(target, key)["intent"]
    if device is None:
        device = Passkey(holder.approval_origin, holder.rp_id)
    material = {
        "version": 1,
        "state": "pending",
        "locator": commitment("enrollment_locator", intent),
        "deadline": intent["intent"]["deadline"],
        "registrations": [
            {
                "registration": device.register(decode(intent["intent"]["challenge"])),
                "client_extension_results": {"credProps": {"rk": True}},
            }
        ],
    }
    confirmation = holder.bind_registration(
        target, material, registration_count=1, **owner(holder, target)
    )
    request = parse(decode(confirmation["request_bytes"]))
    receipt = {
        "version": 1,
        "request_bytes": confirmation["request_bytes"],
        "assertion": device.assert_request(request),
        "binding": confirmation["binding"],
        "id_chain": [intent["intent"]["pending_certificate"]],
    }
    return target, receipt


def test_creation_proof_evidence_and_nonce_commit_once_with_real_webauthn_crypto(
    holder,
):
    target, receipt = creation(holder)
    issuer = PublicIssuer(holder.store.descriptor().did_key, int(time.time()))
    value = holder.finish_creation(
        target, receipt, issuer=issuer, **owner(holder, target)
    )
    assert value["evidence"]["evidence"]["creation"]["grade"] == "passkey_uv"
    assert value["creation_receipt"] == receipt
    audit = holder.store.audit()
    assert (
        holder.finish_creation(target, receipt, issuer=issuer, **owner(holder, target))
        == value
    )
    assert holder.store.audit() == audit
    with holder.store._connection() as db:
        assert db.execute("SELECT count(*) FROM consumed").fetchone()[0] == 1
        row = db.execute(
            "SELECT namespace, person, credential, assessment FROM attestation_inventory"
        ).fetchone()
        assert tuple(row) == (
            holder.store.descriptor().domain,
            target,
            receipt["assertion"]["id"],
            json.dumps({"format": "none"}),
        )
        assert not db.execute("SELECT * FROM active_attestation_inventory").fetchall()
    # Signed creation evidence alone does not establish public committed identity.
    with pytest.raises(Refused, match="approver_not_active"):
        holder.active_person(target)


def test_replacing_expired_enrollment_removes_its_pending_inventory(holder):
    target, receipt = creation(holder)
    identity_key = receipt["binding"]["binding"]["identity_key"]
    expire_pending(holder, target)
    holder.bootstrap_pending(target, identity_key)
    with holder.store._connection() as db:
        assert not db.execute("SELECT * FROM attestation_inventory").fetchall()


def test_verified_hardware_chain_stays_in_the_issuer_inventory(holder):
    device, snapshot, (aaguid, batch_der, root_der) = packed_device(
        holder.approval_origin, holder.rp_id
    )
    holder.grading = EnrollmentGrading("hardware", snapshot)
    target, receipt = creation(holder, device=device)
    issuer = PublicIssuer(holder.store.descriptor().did_key, int(time.time()))
    value = holder.finish_creation(
        target, receipt, issuer=issuer, **owner(holder, target)
    )
    credential = receipt["binding"]["binding"]["credentials"][0]
    assert credential["grade"] == "certified_hardware"
    assert set(credential) == {
        "id",
        "key",
        "algorithm",
        "grade",
        "snapshot",
        "grade_policy",
    }
    with holder.store._connection() as db:
        saved = db.execute(
            "SELECT assessment FROM attestation_inventory WHERE person=? AND credential=?",
            (target, credential["id"]),
        ).fetchone()
    assert json.loads(saved["assessment"]) == {
        "format": "packed",
        "aaguid": aaguid,
        "firmware_version": None,
        "verified_chain": [encode(batch_der), encode(root_der)],
    }
    for public in (receipt, value, holder.store.audit()):
        serialized = json.dumps(public)
        assert aaguid not in serialized
        assert encode(batch_der) not in serialized
        assert encode(root_der) not in serialized


def test_nonce_write_failure_rolls_back_evidence_and_signature_audit(holder):
    target, receipt = creation(holder)
    before = holder.store.audit()
    with holder.store._connection() as db:
        db.execute(
            "CREATE TRIGGER fail_consumption BEFORE INSERT ON consumed BEGIN SELECT RAISE(ABORT,'consume_failed'); END"
        )
    issuer = PublicIssuer(holder.store.descriptor().did_key, int(time.time()))
    with pytest.raises(sqlite3.IntegrityError, match="consume_failed"):
        holder.finish_creation(target, receipt, issuer=issuer, **owner(holder, target))
    assert holder.store.audit() == before
    with holder.store._connection() as db:
        assert (
            db.execute(
                "SELECT evidence FROM enrollments WHERE person=?", (target,)
            ).fetchone()[0]
            is None
        )
        assert db.execute("SELECT count(*) FROM consumed").fetchone()[0] == 0
        db.execute("DROP TRIGGER fail_consumption")
    assert holder.finish_creation(
        target, receipt, issuer=issuer, **owner(holder, target)
    )["evidence"]


def test_expired_bootstrap_can_enroll_again_with_new_bounds_and_old_audit_retained(
    holder,
):
    target, key = person()
    holder.bootstrap_pending(target, key)
    expired = expire_pending(holder, target)
    before = holder.store.audit()
    renewed = holder.bootstrap_pending(target, key)["intent"]
    assert renewed != expired
    assert renewed["intent"]["challenge"] != expired["intent"]["challenge"]
    assert (
        renewed["intent"]["deadline"] - renewed["intent"]["not_before"] == 24 * 60 * 60
    )
    assert holder.store.audit()[: len(before)] == before
    _, receipt = creation(holder, identity=(target, key))
    issuer = PublicIssuer(holder.store.descriptor().did_key, int(time.time()))
    assert holder.finish_creation(
        target, receipt, issuer=issuer, **owner(holder, target)
    )["evidence"]


@pytest.mark.parametrize("has_evidence", [False, True])
def test_live_pending_or_any_evidence_cannot_be_replaced(holder, has_evidence):
    target, receipt = creation(holder)
    if has_evidence:
        holder.finish_creation(
            target,
            receipt,
            issuer=PublicIssuer(holder.store.descriptor().did_key, int(time.time())),
            **owner(holder, target),
        )
        expire_pending(holder, target)
    before = holder.store.audit()
    with holder.store._connection() as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = holder._row(db, target)
        original = parse(row["intent"].encode())["intent"]
        with pytest.raises(Refused, match="person_already_exists"):
            holder._pending(
                db,
                person=target,
                identity_key=row["identity_key"],
                requester=original["requester"],
                certificate=original["pending_certificate"]["certificate"],
            )
    assert holder.store.audit() == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,status",
    [
        ("request_invalid", 400),
        ("identity_key_mismatch", 400),
        ("registration_count_mismatch", 400),
        ("certificate_mismatch", 400),
        ("enrollment_expired", 409),
        ("signature_invalid", 401),
        ("nonce_invalid", 401),
    ],
)
async def test_error_status_distinguishes_input_state_and_authentication(
    holder, code, status
):
    from aweb_key_holder.http import create_app

    response = await create_app(holder).exception_handlers[Refused](None, Refused(code))
    assert response.status_code == status
