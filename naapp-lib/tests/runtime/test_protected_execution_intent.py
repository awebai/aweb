"""Definition-owned issuance changes times, never the approved target."""

from copy import deepcopy
from datetime import timedelta
from uuid import uuid4

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.runtime.protected_signer import RevokeHumanRole, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import signing_bytes
from aweb_naapp.runtime.protected_signer.types import owner_act_operation
from tests.runtime.test_protected_identity_artifacts import NOW, operation
from tests.runtime.test_protected_owner_removal import owner_operation


def live_operation(name):
    if name == "root":
        return operation("identity.root.endorse")
    op = owner_operation()
    if name == "removal":
        return op
    return owner_act_operation(RevokeHumanRole(str(uuid4()), op.context, "https://app.customer.example",
        "app", str(uuid4()), "app.owner", op.context.human_id))


@pytest.mark.parametrize("name", ["root", "owner_act", "removal"])
def test_long_wait_issues_only_the_definitions_times_without_changing_the_intent(name):
    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
        validate_issued_artifact,
    )

    op = live_operation(name)
    key = SigningKey.generate()
    controller = did_from_public_key(bytes(key.verify_key))
    descriptor = prepare_artifact_intent(op, controller, NOW, NOW + timedelta(hours=24))
    saved = deepcopy(descriptor)
    artifact = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    signing = validate_issued_artifact(op, descriptor, artifact)
    assert signing == signing_bytes(op, artifact)
    key.verify_key.verify(signing, key.sign(signing).signature)
    assert descriptor == saved
    assert descriptor["delivery"]["audience"] == op.audience
    assert descriptor["type"] == "aweb.protected-artifact-intent"
    if name == "removal":
        assert "timestamp" not in descriptor["template"]["request"]
        assert artifact["request"]["timestamp"] == "2026-11-13T14:00:00Z"
        assert artifact["request"]["certificate_id"] == op.subject["certificate_id"]
    else:
        assert "issued_at" not in descriptor["template"]
        assert artifact["issued_at"] == "2026-11-13T14:00:00Z"
        if name == "owner_act":
            assert "expires_at" not in descriptor["template"]
            assert artifact["nonce"] == descriptor["template"]["nonce"]
            assert artifact["expires_at"] == "2026-11-13T14:10:00Z"


def test_owner_act_expiry_is_capped_by_the_original_issuance_window():
    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
    )

    op = live_operation("owner_act")
    controller = did_from_public_key(bytes(SigningKey.generate().verify_key))
    descriptor = prepare_artifact_intent(op, controller, NOW, NOW + timedelta(hours=24))
    artifact = materialize_artifact(op, descriptor, NOW + timedelta(hours=24, seconds=-30))
    assert artifact["expires_at"] == "2026-11-14T12:00:00Z"


@pytest.mark.parametrize("offset", [-1, 86400])
def test_issue_cannot_start_before_or_after_the_frozen_window(offset):
    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
    )

    op = live_operation("removal")
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(SigningKey.generate().verify_key)),
        NOW, NOW + timedelta(hours=24))
    with pytest.raises(SignerRefused, match="operation_expired"):
        materialize_artifact(op, descriptor, NOW + timedelta(seconds=offset))


@pytest.mark.parametrize("change", ["certificate", "route", "audience", "extra_issuance_rule"])
def test_a_descriptor_cannot_rebind_the_retained_artifact_or_choose_signing_fields(change):
    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
        validate_issued_artifact,
    )

    op = live_operation("removal")
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(SigningKey.generate().verify_key)),
        NOW, NOW + timedelta(hours=24))
    artifact = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    if change == "certificate":
        descriptor["template"]["request"]["certificate_id"] = str(uuid4())
    elif change == "route":
        descriptor["delivery"]["path"] = "/another"
    elif change == "audience":
        descriptor["delivery"]["audience"] = "https://another.example"
    else:
        descriptor["issued_fields"] = ["/subject"]
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        validate_issued_artifact(op, descriptor, artifact)


def test_bounded_admission_does_not_acquire_execution_time_issuance():
    from aweb_naapp.runtime.protected_signer.execution_intent import prepare_artifact_intent

    with pytest.raises(SignerRefused, match="operation_not_served"):
        prepare_artifact_intent(operation("team.agent.admit"), did_from_public_key(bytes(SigningKey.generate().verify_key)),
            NOW, NOW + timedelta(hours=24))


@pytest.mark.parametrize("change", ["nonce", "issuer", "expiry", "window", "window_extra"])
def test_issued_owner_act_remains_exact_and_the_issuance_window_is_closed(change):
    from aweb_naapp.runtime.protected_signer.execution_intent import (
        materialize_artifact,
        prepare_artifact_intent,
        validate_issued_artifact,
    )

    op = live_operation("owner_act")
    descriptor = prepare_artifact_intent(op, did_from_public_key(bytes(SigningKey.generate().verify_key)),
        NOW, NOW + timedelta(hours=24))
    artifact = materialize_artifact(op, descriptor, NOW + timedelta(hours=2))
    if change == "nonce":
        artifact["nonce"] = uuid4().hex
    elif change == "issuer":
        artifact["team_key_did"] = did_from_public_key(bytes(SigningKey.generate().verify_key))
    elif change == "expiry":
        artifact["expires_at"] = "2026-11-13T14:10:01Z"
    elif change == "window":
        descriptor["issuance_window"]["not_after"] = "2026-11-16T12:00:00Z"
    else:
        descriptor["issuance_window"]["renewable"] = True
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        validate_issued_artifact(op, descriptor, artifact)
