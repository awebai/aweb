"""Additive owner row: a closed target and the existing revocation wire."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer import CatalogOperation, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, signing_bytes
from tests.runtime.test_protected_member_removal import CONTROLLER, operation, subject


def owner_operation(**changes):
    fields = subject()
    del fields["root_id_or_self"]
    fields.update(changes)
    return CatalogOperation(str(uuid4()), operation(fields).context, operation(fields).audience,
        "team.agent.remove", "owner_approved", fields)


def test_owner_removal_has_a_closed_subject_live_floor_and_existing_wire():
    op = owner_operation()
    assert op.spec.needs_human and not op.spec.supports_self_removal
    assert op.spec.effect.provider == "owner_removal"
    assert op.spec.prepared_fields == {"requester_key", "target_kind"}
    artifact = artifact_for(op, CONTROLLER, datetime.now(UTC))
    assert artifact["request"]["certificate_id"] == op.subject["certificate_id"]
    assert artifact["request"]["operation"] == "revoke_certificate"
    assert signing_bytes(op, artifact)
    assert "{/target_kind}" in " ".join(op.spec.display.consequences)


@pytest.mark.parametrize("changes", [{"root_id_or_self": "self"}, {"kind": "agent"}, {"owner_uv": True}])
def test_owner_subject_never_supplies_its_authority_or_classification(changes):
    with pytest.raises(SignerRefused, match="request_invalid"):
        owner_operation(**changes)
