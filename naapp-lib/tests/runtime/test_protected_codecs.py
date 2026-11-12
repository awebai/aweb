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
