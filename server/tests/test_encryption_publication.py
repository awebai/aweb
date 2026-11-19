"""Native HTTP and custody publication share validation, renewal and storage."""

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from awid.e2ee_keys import build_encryption_key_assertion, canonical_encryption_assertion, encryption_key_id
from awid.signing import sign_message
from aweb.routes.agents import EncryptionKeyAssertion, publish_encryption_key
from aweb.routes.connect import connect_agent
from aweb.team_auth import parse_and_verify_certificate
from aweb.team_auth_deps import TeamIdentity, resolve_team_identity
from test_messages_http import _encode_certificate, _make_certificate, _make_keypair


def _assertion(member_sk, member_did, *, now=None, custody="self", public=None, previous=None):
    return build_encryption_key_assertion(
        signing_key=member_sk, identity_did=member_did, identity_stable_id=None,
        encryption_public_key=public or bytes(PrivateKey.generate().public_key),
        previous_encryption_key_id=previous, custody=custody, now=now,
    )


@pytest.mark.asyncio
async def test_wrong_signature_refuses_before_storage_actionably():
    sk, _, did = _make_keypair()
    assertion = _assertion(sk, did)
    assertion["signature"] = sign_message(bytes(SigningKey.generate()), canonical_encryption_assertion(assertion))
    identity = TeamIdentity(
        team_id="test:example.test", alias="member", did_key=did, did_aw="", address="",
        agent_id=str(uuid4()), identity_scope="local", certificate_id="test-member",
    )
    with pytest.raises(HTTPException) as refused:
        await publish_encryption_key(db=None, identity=identity, payload=EncryptionKeyAssertion(**assertion))
    assert refused.value.status_code == 422
    assert refused.value.detail["code"] == "invalid_encryption_key_assertion"
    assert refused.value.detail["message"].endswith(
        "Publish an identity-signed encryption-key assertion with current validity and matching identity fields, then retry."
    )


async def _connected_identity(db):
    team_sk, _, team_key = _make_keypair()
    member_sk, _, member_key = _make_keypair()
    certificate = _make_certificate(
        team_sk, team_key, member_key, team_id="publication:example.test", alias="member",
        identity_scope="local", certificate_id="publication-member",
    )
    verified = parse_and_verify_certificate(
        _encode_certificate(certificate), request_did_key=member_key, team_did_key=team_key,
        revoked_certificate_ids=set(), registered_certificate_ids={"publication-member"},
    )
    verified["verified_team_did_key"] = team_key
    await connect_agent(
        db=db, cert_info=verified, team_did_key=team_key, hostname="", workspace_path="",
        repo_origin="", role="", human_name="", agent_type="agent",
    )
    return member_sk, await resolve_team_identity(db, verified)


@pytest.mark.asyncio
@pytest.mark.parametrize("custody", ["self", "hosted_custodial"])
async def test_same_key_renewal_preserves_key_custody_and_predecessor(aweb_cloud_db, custody):
    db = aweb_cloud_db.aweb_db
    member_sk, identity = await _connected_identity(db)
    public = bytes(PrivateKey.generate().public_key)
    predecessor = encryption_key_id(base64.b64encode(bytes(PrivateKey.generate().public_key)).decode().rstrip("="))
    previous = _assertion(
        member_sk, identity.did_key, public=public, previous=predecessor, custody=custody,
        now=datetime.now(timezone.utc) - timedelta(days=60),
    )
    renewed = _assertion(member_sk, identity.did_key, public=public, previous=predecessor, custody=custody)
    await publish_encryption_key(db=db, identity=identity, payload=EncryptionKeyAssertion(**previous))
    async with db.transaction() as tx:
        result = await publish_encryption_key(db=tx, identity=identity, payload=EncryptionKeyAssertion(**renewed))
    assert result.agent_id == identity.agent_id
    assert result.encryption_key.model_dump(exclude_none=True) == renewed
    rows = await db.fetch_all(
        "SELECT encryption_key_id, assertion_custody, previous_encryption_key_id, "
        "expires_at_text, assertion_signature FROM {{tables.agent_encryption_keys}}",
    )
    assert [dict(row) for row in rows] == [{
        "encryption_key_id": previous["encryption_key_id"], "assertion_custody": custody,
        "previous_encryption_key_id": predecessor, "expires_at_text": renewed["expires_at"],
        "assertion_signature": renewed["signature"],
    }]


@pytest.mark.asyncio
async def test_publication_shares_host_transaction_and_requires_live_member(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    member_sk, identity = await _connected_identity(db)
    payload = EncryptionKeyAssertion(**_assertion(member_sk, identity.did_key))
    with pytest.raises(RuntimeError, match="host custody write failed"):
        async with db.transaction() as tx:
            await publish_encryption_key(db=tx, identity=identity, payload=payload)
            raise RuntimeError("host custody write failed")
    assert await db.fetch_value("SELECT count(*) FROM {{tables.agent_encryption_keys}}") == 0
    with pytest.raises(HTTPException) as refused:
        await publish_encryption_key(db=db, identity=replace(identity, agent_id=str(uuid4())), payload=payload)
    assert refused.value.status_code == 404
    assert refused.value.detail == (
        "Agent not found. Reconnect this identity to the team before publishing its encryption key."
    )
