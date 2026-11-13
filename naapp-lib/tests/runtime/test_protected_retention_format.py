"""Private retention format, not service-attestation authorization evidence."""

import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer.retention import EffectConfirmation, FrozenDelivery, RetainedEffect


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
