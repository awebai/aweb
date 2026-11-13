"""The independent embedding's closed custody port, using actual files/keys."""

import os
import uuid
from dataclasses import replace

import pytest
from aweb_naapp.hooks.owner_act import owner_act_signing_bytes
from aweb_naapp.runtime.protected_signer import (
    ProtectedKeyContext,
    RevokeHumanRole,
    SignerRefused,
)
from awid.did import did_from_public_key, stable_id_from_did_key
from nacl.signing import SigningKey

from aweb.protected_signing.custody import ProtectedControllerCustody


@pytest.fixture
def case(tmp_path):
    directory = tmp_path / "protected"
    directory.mkdir(mode=0o700)
    key = SigningKey.generate()
    key_path = directory / "team.key"
    key_path.write_text(bytes(key).hex() + "\n")
    key_path.chmod(0o600)
    human = stable_id_from_did_key(
        did_from_public_key(bytes(SigningKey.generate().verify_key))
    )
    context = ProtectedKeyContext(
        "customer-signer",
        "team_controller",
        "engineering:customer.example",
        "customer.example",
        human,
        "customer.example",
        1,
    )
    operation = RevokeHumanRole(
        str(uuid.uuid4()),
        context,
        "https://app.customer.example",
        "customer-app",
        str(uuid.uuid4()),
        "customer.owner",
        human,
    )
    fields = {
        "v": 1,
        "type": "aweb.owner-act",
        "act": "human-role.revoke",
        "team_id": context.authority_id,
        "team_key_did": did_from_public_key(bytes(key.verify_key)),
        "aud": operation.audience,
        "subject": operation.intent()["subject"],
        "nonce": uuid.uuid4().hex,
        "issued_at": "2026-11-11T00:00:00Z",
        "expires_at": "2026-11-11T00:10:00Z",
    }
    return key_path, key, operation, fields


def custody(case, *, worker_uids=frozenset({65534})):
    path, _, operation, _ = case
    return ProtectedControllerCustody(
        service_id=operation.context.service_id,
        team_id=operation.context.authority_id,
        domain=operation.context.authority_domain,
        key_file=path,
        worker_uids=worker_uids,
    )


def test_only_exact_typed_owner_act_is_signed(case):
    _, key, operation, fields = case
    adapter = custody(case)
    signature = adapter.sign_owner_act(operation, fields)
    key.verify_key.verify(owner_act_signing_bytes(fields), signature)
    assert adapter.team_key_did == fields["team_key_did"]


def test_typed_log_key_record_uses_the_same_isolated_file_without_private_log_material(
    case,
):
    import base64
    from datetime import UTC, datetime

    from aweb_naapp.runtime.protected_signer import CatalogOperation
    from aweb_naapp.runtime.protected_signer.codecs import artifact_for
    from awid.e2ee_keys import encryption_key_id
    from awid.log_key_record import log_key_record_signing_bytes

    _, key, original, _ = case
    public = base64.b64encode(bytes(range(32))).rstrip(b"=").decode()
    operation = CatalogOperation(
        original.operation_id,
        original.context,
        "https://signer.customer.example",
        "team.log-key.sign",
        "default",
        {
            "team_id": original.context.authority_id,
            "key_id": encryption_key_id(public),
            "public_key": public,
            "created_at": "2026-11-12T00:00:00Z",
        },
    )
    adapter = custody(case)
    artifact = artifact_for(
        operation, adapter.team_key_did, datetime(2026, 11, 13, tzinfo=UTC)
    )
    signature = adapter.sign_operation(operation, artifact)
    key.verify_key.verify(log_key_record_signing_bytes(artifact), signature)
    for changed in (
        {
            **artifact,
            "team_key_did": did_from_public_key(
                bytes(SigningKey.generate().verify_key)
            ),
        },
        {**artifact, "signature": "caller-controlled"},
        {**artifact, "created_at": "2026-11-13T00:00:00Z"},
    ):
        with pytest.raises(SignerRefused):
            adapter.sign_operation(operation, changed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("act", "human-role.designate"),
        ("team_id", "other:customer.example"),
        ("team_key_did", "did:key:other"),
        ("aud", "https://other.customer.example"),
        ("subject", {"app_id": "other.app"}),
    ],
)
def test_artifact_cannot_swap_operation_authority_or_subject(case, field, value):
    _, _, operation, fields = case
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        custody(case).sign_owner_act(operation, {**fields, field: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"service_id": "other-signer"},
        {"authority_id": "other:customer.example"},
        {"authority_domain": "other.example"},
    ],
)
def test_operation_must_name_the_provisioned_key_authority(case, changes):
    _, _, operation, fields = case
    operation = replace(operation, context=replace(operation.context, **changes))
    with pytest.raises(SignerRefused, match="scope_refused"):
        custody(case).sign_owner_act(operation, fields)


def test_plain_bytes_and_caller_objects_cannot_select_a_signing_operation(case):
    _, _, _, fields = case
    adapter = custody(case)
    for operation in (b"arbitrary signing bytes", fields, None):
        with pytest.raises(SignerRefused, match="operation_refused"):
            adapter.sign_owner_act(operation, fields)
    assert not hasattr(adapter, "sign")
    assert not hasattr(adapter, "export")


@pytest.mark.parametrize(
    "worker_uids",
    [frozenset(), frozenset({0}), frozenset({os.geteuid()}), frozenset({True})],
)
def test_worker_identity_cannot_share_signer_or_privileged_custody(case, worker_uids):
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        custody(case, worker_uids=worker_uids)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o620, 0o604])
def test_worker_readable_or_writable_key_file_refuses(case, mode):
    case[0].chmod(mode)
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        custody(case)


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o707])
def test_key_directory_must_be_private_to_the_signer(case, mode):
    case[0].parent.chmod(mode)
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        custody(case)


def test_symlink_key_is_not_a_custody_boundary(case):
    path = case[0]
    original = path.with_suffix(".original")
    path.rename(original)
    path.symlink_to(original)
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        custody(case)


def test_symlink_directory_is_not_a_custody_boundary(case):
    path = case[0]
    original = path.parent.with_name("original")
    path.parent.rename(original)
    path.parent.symlink_to(original, target_is_directory=True)
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        custody(case)
