"""Pure storage/port controls; database commit behavior has separate native cases."""

import base64
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.runtime.protected_signer import ProtectedSigner, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for
from aweb_naapp.runtime.protected_signer.execution_intent import (
    materialize_artifact,
    prepare_artifact_intent,
    validate_issued_artifact,
)
from aweb_naapp.runtime.protected_signer.retention import FrozenDelivery, RetainedEffect
from tests.runtime.test_protected_execution_intent import live_operation
from tests.runtime.test_protected_identity_artifacts import NOW


@pytest.mark.parametrize("name", ["root", "owner_act", "removal"])
def test_issued_storage_is_historical_and_never_rebuilds_or_rewrites_the_request(name, monkeypatch):
    op = live_operation(name)
    key = SigningKey.generate()
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(key.verify_key)), NOW, NOW + timedelta(hours=24))
    actual = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    row = {"request": {**op.intent(), "artifact": descriptor}, "issued_artifact": actual}
    saved = deepcopy(row)
    engine = object.__new__(ProtectedSigner)
    engine.clock = lambda: NOW + timedelta(days=3)

    def no_issue(*args):
        pytest.fail("a historical load must not issue a new artifact")

    monkeypatch.setattr("aweb_naapp.runtime.protected_signer.service.materialize_artifact", no_issue)
    assert engine._issued_artifact(row) == actual
    assert row == saved
    row["issued_artifact"] = None
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        engine._issued_artifact(row)


def test_old_format_is_readable_as_history_but_cannot_be_executed():
    op = live_operation("owner_act")
    key = did_from_public_key(bytes(SigningKey.generate().verify_key))
    old = op.intent()
    del old["approval_format"]
    old["artifact"] = artifact_for(op, key, NOW)
    engine = object.__new__(ProtectedSigner)
    assert engine._issued_artifact({"request": old}) == old["artifact"]
    with pytest.raises(SignerRefused, match="upgrade_aw_required"):
        engine._require_current_format(old)


@pytest.mark.asyncio
async def test_retained_load_checks_the_actual_signature_and_original_effect_deadline_as_history():
    op = live_operation("removal")
    key = SigningKey.generate()
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(key.verify_key)), NOW, NOW + timedelta(hours=24))
    actual = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    signing = validate_issued_artifact(op, descriptor, actual)
    signature = key.sign(signing).signature
    until = NOW + timedelta(hours=2, seconds=300)
    retained = RetainedEffect(op.operation_id, signing, signature, "a" * 64, until,
        FrozenDelivery(op.audience, "POST", descriptor["delivery"]["path"], {"Authorization": "private"}, b"retained"), "private-proof")
    row = {"operation_id": op.operation_id, "request": {**op.intent(), "artifact": descriptor},
        "issued_artifact": actual, "expires_at": NOW + timedelta(hours=24), "evidence_ref": None,
        "retained_effect": retained.fields(), "signed_result": retained.result()}
    engine = object.__new__(ProtectedSigner)
    engine.clock = lambda: NOW + timedelta(days=3)
    assert (await engine._load_retained(row))[2] == retained
    row["signed_result"]["signature"] = base64.b64encode(b"x" * 64).decode()
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await engine._load_retained(row)


def test_retainer_receives_the_actual_artifact_beside_the_frozen_descriptor():
    op = live_operation("removal")
    key = SigningKey.generate()
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(key.verify_key)), NOW, NOW + timedelta(hours=24))
    actual = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    signing = validate_issued_artifact(op, descriptor, actual)
    calls = []

    def retain(**fields):
        assert fields["artifact"] == actual and fields["request"]["artifact"] == descriptor
        calls.append(fields)
        return None

    engine = object.__new__(ProtectedSigner)
    engine.custody = SimpleNamespace(retain_authorized_effect=retain)
    assert engine._retain_authorized_effect(op, {"artifact": descriptor}, signing, key.sign(signing).signature,
        object(), NOW + timedelta(hours=2, seconds=300), artifact=actual) is None
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_owner_act_without_service_delivery_refuses_before_pending_or_signing():
    from aweb_naapp.runtime.protected_signer import RestrictedRequester

    op = live_operation("owner_act")
    engine = object.__new__(ProtectedSigner)

    async def observe(context, *, purpose):
        return SimpleNamespace()

    def no_signature(*args):
        pytest.fail("unserved row must not sign")

    class NoStore:
        def __getattr__(self, name):
            pytest.fail("unserved row must not use pending state: " + name)

    engine.db = NoStore()
    engine.custody = SimpleNamespace(sign_owner_act=no_signature)
    engine.authority = SimpleNamespace(observe=observe)
    with pytest.raises(SignerRefused, match="operation_not_served"):
        await engine.prepare(op, requester=RestrictedRequester("requester", op.context))
