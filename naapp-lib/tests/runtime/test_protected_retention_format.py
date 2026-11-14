"""Private retention format, not service-attestation authorization evidence."""

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer import ProtectedSigner, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, signing_bytes
from aweb_naapp.runtime.protected_signer.retention import (
    EffectConfirmation,
    FrozenDelivery,
    RetainedEffect,
)
from tests.runtime.test_protected_identity_artifacts import HKEY, NOW, operation


def retained():
    delivery = FrozenDelivery("https://registry.example", "POST", "/v1/effect?exact=%2F",
        {"Authorization": "DIDKey retained-auth", "X-AWEB-Protected-Effect": "retained-proof"}, b'{"exact":"bytes"}')
    return RetainedEffect(str(uuid4()), b"retained-signing", b"s" * 64, "a" * 64,
        datetime(2026, 11, 13, 20, tzinfo=UTC), delivery, "retained-proof")


def test_private_effect_round_trip_preserves_complete_delivery_and_public_artifact():
    effect = retained()
    restored = RetainedEffect.from_fields(effect.fields())
    assert restored == effect
    assert restored.delivery.body == b'{"exact":"bytes"}'
    assert restored.delivery.path == "/v1/effect?exact=%2F"
    assert restored.delivery.headers["Authorization"] == "DIDKey retained-auth"
    public = restored.applied_result()
    assert set(public) == {"v", "type", "artifact", "delivery"}
    assert public["v"] == 2 and public["type"] == "aweb.protected-delivery"
    assert public["artifact"] == {"signing": base64.b64encode(effect.signing).decode(),
        "signature": base64.b64encode(effect.signature).decode()}
    assert public["delivery"] == {"mode": "service_owned", "state": "applied", "reference": {
        "operation_id": effect.operation_id, "artifact_sha256": effect.artifact_sha256}}
    assert "retained-auth" not in str(public) and "retained-proof" not in str(public)
    assert "retained-auth" not in repr(restored) and "retained-proof" not in repr(restored)
    assert "retained-auth" not in repr(restored.delivery)


def test_retained_headers_are_snapshotted_and_not_mutable_through_a_caller():
    headers = {"Authorization": "original"}
    delivery = FrozenDelivery("https://registry.example", "POST", "/effect", headers, b"body")
    headers["Authorization"] = "changed"
    assert delivery.headers["Authorization"] == "original"
    with pytest.raises(TypeError):
        delivery.headers["Authorization"] = "changed"


@pytest.mark.parametrize("change", [
    {"operation_id": "not-a-uuid"}, {"signature": b"s" * 63},
    {"artifact_sha256": "A" * 64}, {"expires_at": datetime(2026, 11, 13)},
    {"attestation": ""},
])
def test_a_malformed_private_effect_is_not_accepted(change):
    with pytest.raises(ValueError):
        replace(retained(), **change)


def test_retention_cannot_replace_the_engine_artifact_or_extend_its_bound():
    effect = retained()
    effect.require_matches(effect.operation_id, effect.result(), effect.expires_at)
    with pytest.raises(ValueError):
        effect.require_matches(str(uuid4()), effect.result(), effect.expires_at)
    with pytest.raises(ValueError):
        effect.require_matches(effect.operation_id, {**effect.result(), "signing": "changed"}, effect.expires_at)
    with pytest.raises(ValueError):
        effect.require_matches(effect.operation_id, effect.result(), effect.expires_at - timedelta(seconds=1))


@pytest.mark.parametrize("change", [
    {"audience": "https://registry.example/path"}, {"path": "https://other.example/effect"},
    {"path": "/effect#fragment"}, {"method": "GET"}, {"headers": {"Authorization": "bad\r\nInjected: yes"}},
    {"body": "text instead of exact bytes"},
])
def test_retained_delivery_is_a_fixed_mutation_request(change):
    with pytest.raises(ValueError):
        replace(retained().delivery, **change)


def test_confirmation_names_the_exact_effect_with_an_original_freshness_bound():
    effect = retained()
    observation = EffectConfirmation(effect.operation_id, effect.artifact_sha256, effect.expires_at)
    observation.require_matches(effect, effect.expires_at - timedelta(seconds=1))
    for changed in [replace(observation, operation_id=str(uuid4())), replace(observation, artifact_sha256="b" * 64)]:
        with pytest.raises(ValueError):
            changed.require_matches(effect, effect.expires_at - timedelta(seconds=1))
    with pytest.raises(ValueError):
        observation.require_matches(effect, effect.expires_at)


@pytest.mark.parametrize("change", [{"extra": "private"}, {"v": True}, {"signature": "bad"}])
def test_private_storage_has_a_closed_unambiguous_shape(change):
    with pytest.raises(ValueError):
        RetainedEffect.from_fields({**retained().fields(), **change})


@pytest.mark.parametrize("change", ["operation", "signature", "deadline", "audience"])
def test_engine_rejects_a_retainer_that_changes_the_verified_effect(change):
    # Local byte-binding glue, not a current-authority/service-proof positive.
    op = operation("team.agent.admit")
    artifact = artifact_for(op, HKEY, NOW)
    signing, signature = signing_bytes(op, artifact), b"s" * 64
    limit = NOW + timedelta(seconds=60)
    value = RetainedEffect(op.operation_id, signing, signature, "a" * 64, limit,
        FrozenDelivery(op.audience, "POST", "/effect", {}, b"body"), "opaque")
    if change == "operation":
        value = replace(value, operation_id=str(uuid4()))
    elif change == "signature":
        value = replace(value, signature=b"t" * 64)
    elif change == "deadline":
        value = replace(value, expires_at=limit + timedelta(seconds=1))
    else:
        value = replace(value, delivery=replace(value.delivery, audience="https://different.example"))
    calls = []

    def retain(**kw):
        assert kw["operation"] is op and kw["artifact"] == artifact
        assert kw["signing"] == signing and kw["signature"] == signature and kw["expires_at"] == limit
        return value

    async def no_network(*args):
        calls.append(args)

    engine = object.__new__(ProtectedSigner)
    engine.custody = SimpleNamespace(retain_authorized_effect=retain,
        deliver_retained=no_network, confirm_retained=no_network)
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        engine._retain_authorized_effect(op, {"artifact": artifact}, signing, signature, object(), limit, artifact=artifact)
    assert calls == []


@pytest.mark.parametrize("has_port", [False, True])
def test_legacy_custody_keeps_its_existing_signed_result_without_retention(has_port):
    engine = object.__new__(ProtectedSigner)
    engine.custody = SimpleNamespace(**({"retain_authorized_effect": lambda **kw: None} if has_port else {}))
    op = operation("team.agent.admit")
    assert engine._retain_authorized_effect(op, {"artifact": {}}, b"signing", b"s" * 64, object(), NOW, artifact={}) is None


def test_shared_owner_transport_fixture_uses_the_public_artifact_digest():
    from awid.did import did_from_public_key
    from awid.protected_effect import artifact_digest
    from nacl.signing import SigningKey

    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
    )
    from tests.runtime.protected_signer_support import ControllerCustody
    from tests.runtime.test_protected_execution_intent import live_operation

    op = live_operation("owner_act")
    key = SigningKey.generate()
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(key.verify_key)), NOW, NOW + timedelta(hours=24))
    artifact = materialize_artifact(op, descriptor, NOW + timedelta(seconds=1))
    signing = signing_bytes(op, artifact)
    signature = key.sign(signing).signature
    retained = ControllerCustody(key, lambda: NOW).retain_authorized_effect(
        operation=op, request={"artifact": descriptor}, artifact=artifact, signing=signing, signature=signature,
        expires_at=NOW + timedelta(seconds=300))
    assert retained.artifact_sha256 == artifact_digest(signing, base64.b64encode(signature).decode().rstrip("="))
    assert retained.applied_result()["delivery"]["reference"]["artifact_sha256"] == retained.artifact_sha256
