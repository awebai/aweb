"""Native HTTP and custody publication share validation, renewal and storage."""

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from awid.e2ee_keys import (
    build_encryption_key_assertion,
    canonical_encryption_assertion,
    encryption_key_id,
)
from awid.signing import sign_message
from aweb.lifecycle_agent import AgentDisposition, apply_agent_disposition_on
from aweb.routes.agents import EncryptionKeyAssertion, publish_encryption_key
from aweb.routes.connect import connect_agent
from aweb.team_auth import parse_and_verify_certificate
from aweb.team_auth_deps import TeamIdentity, resolve_team_identity
from aweb.team_key_pins import AdmittedTeamKeys, TeamKeyPin
import test_certificate_projection
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair


projection_member = test_certificate_projection.projection_member


def _assertion(
    member_sk, member_did, *, now=None, custody="self", public=None, previous=None
):
    return build_encryption_key_assertion(
        signing_key=member_sk,
        identity_did=member_did,
        identity_stable_id=None,
        encryption_public_key=public or bytes(PrivateKey.generate().public_key),
        previous_encryption_key_id=previous,
        custody=custody,
        now=now,
    )


@pytest.mark.asyncio
async def test_wrong_signature_refuses_before_storage_actionably():
    sk, _, did = _make_keypair()
    assertion = _assertion(sk, did)
    assertion["signature"] = sign_message(
        bytes(SigningKey.generate()), canonical_encryption_assertion(assertion)
    )
    identity = TeamIdentity(
        team_id="test:example.test",
        alias="member",
        did_key=did,
        did_aw="",
        address="",
        agent_id=str(uuid4()),
        identity_scope="local",
        certificate_id="test-member",
    )
    with pytest.raises(HTTPException) as refused:
        await publish_encryption_key(
            db=None, identity=identity, payload=EncryptionKeyAssertion(**assertion)
        )
    assert refused.value.status_code == 422
    assert refused.value.detail["code"] == "invalid_encryption_key_assertion"
    assert refused.value.detail["message"].endswith(
        "Publish an identity-signed encryption-key assertion with current validity and matching identity fields, then retry."
    )


async def _connected_identity(db):
    team_sk, _, team_key = _make_keypair()
    member_sk, _, member_key = _make_keypair()
    certificate = _make_certificate(
        team_sk,
        team_key,
        member_key,
        team_id="publication:example.test",
        alias="member",
        identity_scope="local",
        certificate_id="publication-member",
    )
    verified = parse_and_verify_certificate(
        _encode_certificate(certificate),
        request_did_key=member_key,
        team_did_key=team_key,
        revoked_certificate_ids=set(),
        registered_certificate_ids={"publication-member"},
    )
    verified["verified_team_did_key"] = team_key
    await connect_agent(
        db=db,
        cert_info=verified,
        team_did_key=team_key,
        hostname="",
        workspace_path="",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )
    return member_sk, await resolve_team_identity(db, verified)


@pytest.mark.asyncio
@pytest.mark.parametrize("custody", ["self", "hosted_custodial"])
async def test_same_key_renewal_preserves_key_custody_and_predecessor(
    aweb_cloud_db, custody
):
    db = aweb_cloud_db.aweb_db
    member_sk, identity = await _connected_identity(db)
    public = bytes(PrivateKey.generate().public_key)
    predecessor = encryption_key_id(
        base64.b64encode(bytes(PrivateKey.generate().public_key)).decode().rstrip("=")
    )
    previous = _assertion(
        member_sk,
        identity.did_key,
        public=public,
        previous=predecessor,
        custody=custody,
        now=datetime.now(timezone.utc) - timedelta(days=60),
    )
    renewed = _assertion(
        member_sk,
        identity.did_key,
        public=public,
        previous=predecessor,
        custody=custody,
    )
    await publish_encryption_key(
        db=db, identity=identity, payload=EncryptionKeyAssertion(**previous)
    )
    async with db.transaction() as tx:
        result = await publish_encryption_key(
            db=tx, identity=identity, payload=EncryptionKeyAssertion(**renewed)
        )
    assert result.agent_id == identity.agent_id
    assert result.encryption_key.model_dump(exclude_none=True) == renewed
    rows = await db.fetch_all(
        "SELECT encryption_key_id, assertion_custody, previous_encryption_key_id, "
        "expires_at_text, assertion_signature FROM {{tables.agent_encryption_keys}}",
    )
    assert [dict(row) for row in rows] == [
        {
            "encryption_key_id": previous["encryption_key_id"],
            "assertion_custody": custody,
            "previous_encryption_key_id": predecessor,
            "expires_at_text": renewed["expires_at"],
            "assertion_signature": renewed["signature"],
        }
    ]


@pytest.mark.asyncio
async def test_publication_shares_host_transaction_and_requires_live_member(
    aweb_cloud_db,
):
    db = aweb_cloud_db.aweb_db
    member_sk, identity = await _connected_identity(db)
    payload = EncryptionKeyAssertion(**_assertion(member_sk, identity.did_key))
    with pytest.raises(RuntimeError, match="host custody write failed"):
        async with db.transaction() as tx:
            await publish_encryption_key(db=tx, identity=identity, payload=payload)
            raise RuntimeError("host custody write failed")
    assert (
        await db.fetch_value("SELECT count(*) FROM {{tables.agent_encryption_keys}}")
        == 0
    )
    with pytest.raises(HTTPException) as refused:
        await publish_encryption_key(
            db=db, identity=replace(identity, agent_id=str(uuid4())), payload=payload
        )
    assert refused.value.status_code == 404
    assert refused.value.detail == (
        "Agent not found. Reconnect this identity to the team before publishing its encryption key."
    )


@pytest.mark.asyncio
async def test_generation_publication_uses_admission_transaction_and_rolls_back(
    projection_member,
):
    env = projection_member
    payload = EncryptionKeyAssertion(
        **_assertion(env.member, env.initial.certificate.claims["member_did_key"])
    )
    with pytest.raises(RuntimeError, match="custody completion failed"):
        async with env.stack.aweb_db.transaction() as tx:
            await connect_agent(**{**env.arguments, "db": tx})
            result = await publish_encryption_key(
                db=tx,
                generation=env.initial,
                agent_id=env.planned.agent_id,
                payload=payload,
            )
            assert result.agent_id == str(env.planned.agent_id)
            assert result.encryption_key == payload
            raise RuntimeError("custody completion failed")
    assert (
        await env.stack.aweb_db.fetch_value(
            "SELECT count(*) FROM {{tables.agent_encryption_keys}}"
        )
        == 0
    )
    async with env.stack.aweb_db.transaction() as tx:
        await connect_agent(**{**env.arguments, "db": tx})
        await publish_encryption_key(
            db=tx,
            generation=env.initial,
            agent_id=env.planned.agent_id,
            payload=payload,
        )
    assert (
        await env.stack.aweb_db.fetch_value(
            "SELECT assertion_signature FROM {{tables.agent_encryption_keys}}"
        )
        == payload.signature
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("conflict", ["certificate", "retired", "missing", "stale-key"])
async def test_generation_publication_refuses_unmatched_or_ineligible_projection(
    projection_member, conflict
):
    env = projection_member
    generation = await env.proof() if conflict == "certificate" else env.initial
    payload = EncryptionKeyAssertion(
        **_assertion(env.member, generation.certificate.claims["member_did_key"])
    )
    async with env.stack.aweb_db.transaction() as tx:
        await connect_agent(**{**env.arguments, "db": tx})
        team_id = env.initial.certificate.claims["team_id"]
        if conflict == "retired":
            assert (
                await apply_agent_disposition_on(
                    tx,
                    agent_ids=[env.planned.agent_id],
                    team_id=team_id,
                    disposition=AgentDisposition.RETIRED,
                    deleted_at=datetime.now(timezone.utc),
                )
                == 1
            )
        elif conflict == "stale-key":
            keys = AdmittedTeamKeys(tx)
            before = await keys.pin(team_id)
            assert before is not None
            assert await keys.move(
                team_id,
                expected=before,
                new=TeamKeyPin(_make_keypair()[2], datetime.now(timezone.utc)),
            )
        with pytest.raises(HTTPException) as refused:
            await publish_encryption_key(
                db=tx,
                generation=generation,
                agent_id=uuid4() if conflict == "missing" else env.planned.agent_id,
                payload=payload,
            )
        assert refused.value.status_code == 409
        assert refused.value.detail == {
            "code": "encryption_admission_conflict",
            "message": "The generation does not match the current admitted member. Complete admission with the current certificate and retry in that transaction.",
        }
        assert (
            await tx.fetch_value(
                "SELECT count(*) FROM {{tables.agent_encryption_keys}}"
            )
            == 0
        )


@pytest.mark.asyncio
async def test_generation_publication_requires_open_admission_transaction(
    projection_member,
):
    env = projection_member
    payload = EncryptionKeyAssertion(
        **_assertion(env.member, env.initial.certificate.claims["member_did_key"])
    )
    with pytest.raises(HTTPException) as refused:
        await publish_encryption_key(
            db=env.stack.aweb_db,
            generation=env.initial,
            agent_id=env.planned.agent_id,
            payload=payload,
        )
    assert refused.value.status_code == 422
    assert refused.value.detail["message"] == (
        "Publish the verified generation and exact agent_id inside the same open admission transaction, then retry."
    )
