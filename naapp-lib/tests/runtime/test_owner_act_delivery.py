"""Delivery evidence uses the real runtime H2 verifier and retains its artifact."""

import json

import pytest
from nacl.signing import SigningKey

from aweb_naapp.runtime.owner_act_delivery import OwnerActDeliveryRefused
from tests.runtime.test_human_member import TEAM, human  # noqa: F401
from tests.runtime.test_runtime_team_services import _runtime


@pytest.mark.parametrize("certificate", [b"", b"not-json", b"[]", b"\xff"])
async def test_malformed_certificate_is_a_typed_owner_refusal(tmp_path, certificate):
    runtime = _runtime(tmp_path)
    with pytest.raises(OwnerActDeliveryRefused) as refused:
        await runtime.check_human_role_member(
            TEAM, principal="did:aw:untrusted-input", certificate=certificate
        )
    assert refused.value.code == "owner_required"


async def test_delivery_retains_exact_signed_bytes_and_exposes_proved_identity(
    human, registry, tmp_path
):
    member, principal, client, _, _ = human
    # Whitespace is part of the supplied artifact, not the signed JSON's canonicalization.
    certificate = (json.dumps(member.certificate(), indent=2) + "\n").encode()
    runtime = _runtime(tmp_path, registry=registry, database_url=registry.db.config.get_dsn())
    checked = await runtime.check_human_role_member(
        TEAM, principal=principal, certificate=certificate, identity_client=client
    )
    assert checked.certificate == certificate
    assert checked.principal == checked.proof.principal == principal
    assert checked.team_id == checked.proof.team_id == TEAM
    assert checked.proof.membership.certificate_id == member.certificate_id
    checked.require_fresh()


@pytest.mark.parametrize("different", ["team", "principal"])
async def test_delivery_cannot_substitute_a_different_certificate_identity(
    human, registry, tmp_path, different
):
    member, principal, client, _, _ = human
    other_principal = await registry.register_did(SigningKey.generate())
    runtime = _runtime(tmp_path, registry=registry, database_url=registry.db.config.get_dsn())
    with pytest.raises(OwnerActDeliveryRefused) as refused:
        await runtime.check_human_role_member(
            "other:example.com" if different == "team" else TEAM,
            principal=other_principal if different == "principal" else principal,
            certificate=json.dumps(member.certificate()).encode(),
            identity_client=client,
        )
    assert refused.value.code == "owner_required"


async def test_delivery_maps_definite_membership_loss_to_its_typed_refusal(
    human, registry, tmp_path
):
    member, principal, client, _, _ = human
    await registry.revoke(member.certificate_id)
    runtime = _runtime(tmp_path, registry=registry, database_url=registry.db.config.get_dsn())
    with pytest.raises(OwnerActDeliveryRefused) as refused:
        await runtime.check_human_role_member(
            TEAM,
            principal=principal,
            certificate=json.dumps(member.certificate()).encode(),
            identity_client=client,
        )
    assert refused.value.code == "principal_not_member"
