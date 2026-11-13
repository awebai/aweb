"""Closed artifact families preserve the consumer's exact existing protocol."""

import json
from datetime import UTC, datetime

import pytest

from aweb_naapp.runtime.protected_signer import ProtectedKeyContext, SignerRefused


def test_server_record_codec_uses_the_existing_record_and_refuses_extra_signing_input():
    from awid.team_server_record import build_team_server_record, record_signing_bytes

    from aweb_naapp.runtime.protected_signer.codecs import (
        artifact_for,
        signing_bytes,
        validate_subject,
    )

    context = ProtectedKeyContext(
        "signer",
        "team_controller",
        "demo:example.org",
        "example.org",
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
        "example.org",
        1,
    )
    from awid.did import did_from_public_key, generate_keypair

    _, public = generate_keypair()
    key = did_from_public_key(public)
    now = datetime(2026, 11, 12, tzinfo=UTC)
    subject = {"server_url": "https://coord.example.org/prefix"}
    assert validate_subject("team.server-record.publish", "default", subject) == subject
    operation = type(
        "Operation",
        (),
        {
            "operation": "team.server-record.publish",
            "variant": "default",
            "context": context,
            "intent": lambda self: {"subject": subject},
        },
    )()
    artifact = artifact_for(operation, key, now)
    assert artifact == build_team_server_record(
        context.authority_id, key, subject["server_url"], now
    )
    assert signing_bytes(operation, artifact) == record_signing_bytes(artifact)
    for changed in (
        {**subject, "bytes": "raw"},
        {"server_url": "https://coord.example.org/"},
        {"server_url": "https://coord.example.org/?secret=1"},
    ):
        with pytest.raises(SignerRefused):
            validate_subject("team.server-record.publish", "default", changed)
    wrong = {**artifact, "team_id": "other:example.org"}
    with pytest.raises(SignerRefused):
        signing_bytes(operation, wrong)
    assert json.loads(signing_bytes(operation, artifact).split(b"\n", 1)[1]) == artifact


@pytest.mark.asyncio
async def test_existing_custody_port_refuses_new_family_before_pending_or_remote_work():
    from types import SimpleNamespace

    from aweb_naapp.runtime.protected_signer import (
        CatalogOperation,
        ProtectedSigner,
        RestrictedRequester,
    )

    context = ProtectedKeyContext(
        "signer",
        "team_controller",
        "demo:example.org",
        "example.org",
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
        "example.org",
        1,
    )
    operation = CatalogOperation(
        "00000000-0000-4000-8000-000000000001",
        context,
        "https://registry.example.org",
        "team.server-record.publish",
        "default",
        {"server_url": "https://coord.example.org"},
    )
    signer = ProtectedSigner.__new__(ProtectedSigner)
    signer.custody = SimpleNamespace(sign_owner_act=lambda *_: None)
    # No db, authority or B2 initialized: refusal must precede all those uses.
    with pytest.raises(SignerRefused, match="operation_refused"):
        await signer.prepare(operation, requester=RestrictedRequester(context.human_id, context))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "family,artifact_seconds",
    [
        ("owner_act", 600),
        ("owner_act", 30),
        ("server_record", None),
    ],
)
async def test_prepare_bounds_the_handoff_without_inventing_an_artifact_expiry(
    monkeypatch,
    family,
    artifact_seconds,
):
    """Exercise prepare up to B2's boundary, without a DB or approval ceremony."""
    from contextlib import asynccontextmanager
    from datetime import timedelta
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from awid.did import did_from_public_key, generate_keypair

    from aweb_naapp.runtime.approvals import Assurance
    from aweb_naapp.runtime.protected_signer import (
        CatalogOperation,
        ProtectedSigner,
        RestrictedRequester,
        service,
    )

    context = ProtectedKeyContext(
        "signer",
        "team_controller",
        "demo:example.org",
        "example.org",
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
        "example.org",
        1,
    )
    now = datetime(2026, 11, 12, tzinfo=UTC)
    _, public = generate_keypair()
    key = did_from_public_key(public)
    if family == "server_record":
        name, subject = "team.server-record.publish", {"server_url": "https://coord.example.org"}
    else:
        name, subject = (
            "human-role.revoke",
            {
                "app_id": "demo",
                "installation_id": "00000000-0000-4000-8000-000000000002",
                "role": "demo.owner",
                "principal": context.human_id,
            },
        )
    operation = CatalogOperation(
        "00000000-0000-4000-8000-000000000001",
        context,
        "https://registry.example.org",
        name,
        "default",
        subject,
    )
    actor = RestrictedRequester(context.human_id, context)
    tx = object()
    build_artifact = service.artifact_for

    def artifact_for(*args):
        artifact = build_artifact(*args)
        if artifact_seconds is not None:
            artifact["expires_at"] = (
                (now + timedelta(seconds=artifact_seconds))
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
        return artifact

    monkeypatch.setattr(service, "artifact_for", artifact_for)

    @asynccontextmanager
    async def transaction():
        yield tx

    class MintReached(Exception):
        pass

    async def mint(**kwargs):
        assert kwargs["tx"] is tx
        assert kwargs["expires_at"] == now + timedelta(seconds=artifact_seconds or 600)
        artifact = kwargs["request"]["artifact"]
        if family == "server_record":
            from awid.team_server_record import RECORD_FIELDS

            # Adding an expiry would change the signed wire and break its consumer.
            assert set(artifact) == RECORD_FIELDS
        else:
            assert artifact["expires_at"] == kwargs["expires_at"].isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
        raise MintReached

    signer = ProtectedSigner.__new__(ProtectedSigner)
    signer.db = SimpleNamespace(transaction=transaction)
    signer.clock = lambda: now
    signer.custody = SimpleNamespace(sign_operation=Mock())
    signer.authority = SimpleNamespace(
        observe=AsyncMock(
            return_value=SimpleNamespace(
                team_key_did=key,
                prepare=AsyncMock(),
            )
        )
    )
    signer.policies = SimpleNamespace(
        current=AsyncMock(
            return_value=SimpleNamespace(
                min_assurance=Assurance.PASSKEY,
                version=1,
            )
        )
    )
    signer._lock = AsyncMock(return_value=None)
    signer.approvals = SimpleNamespace(mint=mint)
    with pytest.raises(MintReached):
        await signer.prepare(operation, requester=actor)
    signer.custody.sign_operation.assert_not_called()


@pytest.mark.parametrize("source", ["constructor", "retained-request", "catalog-bridge"])
def test_authority_key_lookup_accepts_the_released_revoke_type_and_retained_parser(source):
    from awid.did import did_from_public_key, generate_keypair

    from aweb_naapp.runtime.protected_signer import RevokeHumanRole
    from aweb_naapp.runtime.protected_signer.codecs import artifact_for, authority_key
    from aweb_naapp.runtime.protected_signer.http import parse_operation
    from aweb_naapp.runtime.protected_signer.types import owner_act_operation
    from tests.runtime.test_protected_log_key import operation

    context = operation().context
    legacy = RevokeHumanRole(
        operation().operation_id,
        context,
        "https://console.example.org",
        "logs",
        "00000000-0000-4000-8000-000000000003",
        "logs.reader",
        context.human_id,
    )
    value = legacy
    if source == "retained-request":
        value = parse_operation(legacy.intent())
        assert type(value) is RevokeHumanRole
    elif source == "catalog-bridge":
        value = owner_act_operation(legacy)
    _, public = generate_keypair()
    key = did_from_public_key(public)
    artifact = artifact_for(owner_act_operation(legacy), key, datetime.now(UTC))
    # execute calls this immediately after its current-authority fence, before
    # custody/signing. Preserve the released type, normalize only codec lookup.
    assert authority_key(value, artifact) == key
