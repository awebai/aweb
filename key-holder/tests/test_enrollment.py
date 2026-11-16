"""Holder-owned enrollment state and concrete shared protocol checks."""

from datetime import datetime, timezone

from awid.did import generate_keypair, did_from_public_key, stable_id_from_did_key
from approval_service.grading import EnrollmentGrading
from approval_service.seams import check_enrollment_intent, commitment, check_http
from approval_service.canonical import canonical, parse
from approval_service.encoding import decode
from approval_service.enrollment import PublicIssuer
import sqlite3
import time
from approval_service.verify import Refused as ApprovalRefused
import pytest

from aweb_key_holder.enrollment import Holder
from aweb_key_holder.keys import KeyStore, Refused
from authenticator import Passkey
from pending import expire_pending


@pytest.fixture
def holder(tmp_path):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    store.set_human_issuance("approved")
    return Holder(
        store,
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
        now=int(datetime.now(timezone.utc).timestamp()),
    )
    assert checked["state"] == "pending" and checked["person"] == target
    with pytest.raises(Refused, match="bootstrap_closed"):
        holder.bootstrap_pending(*person())
    assert {row["operation"] for row in holder.store.audit()} == {
        "namespace_id_issue",
        "enrollment_intent",
    }


def test_new_human_is_not_a_routine_signed_object_or_an_active_approver(holder):
    target, key = person()
    holder.bootstrap_pending(target, key)
    with pytest.raises(Refused, match="approver_not_active"):
        holder.active_person(target)
    assert holder.store.audit()[0]["approval"] is None


def test_bad_creation_proof_cannot_sign_evidence_or_consume_nonce(holder):
    target, key = person()
    result = holder.bootstrap_pending(target, key)
    with pytest.raises((ApprovalRefused, Refused)):
        holder.finish_creation(target, {}, issuer=None)
    assert holder.pending(target) == result
    assert len(holder.store.audit()) == 2
    with holder.store._connection() as db:
        assert db.execute("SELECT count(*) FROM consumed").fetchone()[0] == 0


def test_unknown_or_substituted_enrollment_material_is_not_signed(holder):
    target, key = person()
    result = holder.bootstrap_pending(target, key)
    with pytest.raises((ApprovalRefused, Refused)):
        holder.bind_registration(
            target, {"state": "pending", "registrations": []}, registration_count=1
        )
    assert holder.pending(target) == result
    assert len(holder.store.audit()) == 2


def creation(holder, identity=None):
    target, key = identity or person()
    intent = holder.bootstrap_pending(target, key)["intent"]
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
    confirmation = holder.bind_registration(target, material, registration_count=1)
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
    value = holder.finish_creation(target, receipt, issuer=issuer)
    assert value["evidence"]["evidence"]["creation"]["grade"] == "passkey_uv"
    assert value["creation_receipt"] == receipt
    audit = holder.store.audit()
    assert holder.finish_creation(target, receipt, issuer=issuer) == value
    assert holder.store.audit() == audit
    with holder.store._connection() as db:
        assert db.execute("SELECT count(*) FROM consumed").fetchone()[0] == 1
    # Signed creation evidence alone does not establish public committed identity.
    with pytest.raises(Refused, match="approver_not_active"):
        holder.active_person(target)


def test_nonce_write_failure_rolls_back_evidence_and_signature_audit(holder):
    target, receipt = creation(holder)
    before = holder.store.audit()
    with holder.store._connection() as db:
        db.execute(
            "CREATE TRIGGER fail_consumption BEFORE INSERT ON consumed BEGIN SELECT RAISE(ABORT,'consume_failed'); END"
        )
    issuer = PublicIssuer(holder.store.descriptor().did_key, int(time.time()))
    with pytest.raises(sqlite3.IntegrityError, match="consume_failed"):
        holder.finish_creation(target, receipt, issuer=issuer)
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
    assert holder.finish_creation(target, receipt, issuer=issuer)["evidence"]


def test_controller_http_proof_is_only_for_its_frozen_bootstrap_body(holder):
    target, key = person()
    intent = holder.bootstrap_pending(target, key)["intent"]
    body = {
        "version": 1,
        "intent": intent,
        "admission": {"team_certificate": None, "id_chain": []},
    }
    issued = int(time.time())
    header = holder.authorize_bootstrap(
        target, "enrollment_material", canonical(body), issued
    )
    checked = check_http(
        header,
        canonical(body),
        requester=intent["intent"]["requester"],
        origin=holder.approval_origin,
        method="POST",
        path="/v1/enrollments/material",
        purpose="enrollment_material",
        now=issued,
    )
    assert checked["key"] == holder.store.descriptor().did_key
    with pytest.raises(Refused, match="operation_not_served"):
        holder.authorize_bootstrap(target, "submit", canonical(body), issued)
    other = {
        **body,
        "intent": {
            **intent,
            "intent": {**intent["intent"], "identity_key": person()[1]},
        },
    }
    with pytest.raises(Refused, match="enrollment_changed"):
        holder.authorize_bootstrap(
            target, "enrollment_material", canonical(other), issued
        )


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
    assert holder.finish_creation(target, receipt, issuer=issuer)["evidence"]


@pytest.mark.parametrize("has_evidence", [False, True])
def test_live_pending_or_any_evidence_cannot_be_replaced(holder, has_evidence):
    target, receipt = creation(holder)
    if has_evidence:
        holder.finish_creation(
            target,
            receipt,
            issuer=PublicIssuer(holder.store.descriptor().did_key, int(time.time())),
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
