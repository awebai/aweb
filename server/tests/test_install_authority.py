"""Generic install authority checks with real policy reads in PostgreSQL."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from aweb.auth_context import GrantContext
from aweb.install_authority import (
    CertificateInstallAdminSubject,
    InternalInstallAdminSubject,
    require_install_admin,
)
from aweb.internal_auth import build_internal_auth_header_value
from aweb.team_auth_deps import TeamIdentity
from fastapi import FastAPI, HTTPException, Request

TEAM = "demo:example.com"
ACTOR = str(uuid4())
PRINCIPAL = str(uuid4())
SECRET = "test-install-policy-proxy-secret"
pytestmark = pytest.mark.asyncio


def identity(**changes):
    original = TeamIdentity(
        team_id=TEAM, alias="alice", did_key="did:key:alice", did_aw="did:aw:alice",
        address="example.com/alice", agent_id=ACTOR, identity_scope="global", certificate_id="cert-1",
    )
    return replace(original, **changes)


def request(*, headers=None, policy=None):
    app = FastAPI()
    if policy is not None:
        app.state.install_admin_policy = policy
    return Request({
        "type": "http", "app": app, "method": "POST", "path": "/v1/apps/install",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    })


class Policy:
    def __init__(self):
        self.seen = []

    async def __call__(self, tx, subject, *, action, app_id):
        self.seen.append((subject, action, app_id))
        if isinstance(subject, CertificateInstallAdminSubject):
            subject_id = subject.did_key
        else:
            if subject.principal_type != "u":
                return False
            subject_id = subject.principal_id
        return bool(await tx.fetch_value(
            "SELECT EXISTS (SELECT 1 FROM aweb.test_install_admins WHERE team_id = $1 AND subject_id = $2)",
            subject.team_id, subject_id,
        ))


@pytest_asyncio.fixture
async def db(test_db_factory):
    db = await test_db_factory.create_db(suffix="install_authority", schema="aweb")
    await db.execute("CREATE TABLE aweb.test_install_admins (team_id TEXT NOT NULL, subject_id TEXT NOT NULL)")
    await db.execute("CREATE TABLE aweb.team_app_install_admins (team_id TEXT, principal_did TEXT, role TEXT, revoked_at TIMESTAMPTZ)")
    return db


async def require(db, req, caller=None, team_id=TEAM):
    async with db.transaction() as tx:
        await require_install_admin(tx, req, caller, team_id, action="apps.install", app_id="fixture")


async def test_absent_policy_and_role_claims_never_grant_admin(db):
    req = request(headers={"X-Role": "admin"})
    req.state.role = "owner"
    with pytest.raises(HTTPException) as exc:
        await require(db, req, identity())
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "admin_required"


async def test_current_authoritative_policy_is_read_inside_each_transaction(db):
    policy = Policy()
    req = request(policy=policy)
    await db.execute("INSERT INTO aweb.test_install_admins VALUES ($1, $2)", TEAM, "did:key:alice")
    await require(db, req, identity())
    subject, action, app_id = policy.seen[-1]
    assert subject == CertificateInstallAdminSubject(
        team_id=TEAM, agent_id=ACTOR, certificate_id="cert-1", did_key="did:key:alice",
    )
    assert (action, app_id) == ("apps.install", "fixture")
    await db.execute("DELETE FROM aweb.test_install_admins")
    with pytest.raises(HTTPException) as exc:
        await require(db, req, identity())
    assert (exc.value.status_code, exc.value.detail["code"]) == (403, "admin_required")
    assert len(policy.seen) == 2


async def test_another_team_cannot_borrow_a_policy_delegation(db):
    policy = Policy()
    await db.execute("INSERT INTO aweb.test_install_admins VALUES ($1, $2)", TEAM, "did:key:alice")
    with pytest.raises(HTTPException) as exc:
        await require(db, request(policy=policy), identity(team_id="other:example.com"))
    assert exc.value.status_code == 404
    assert policy.seen == []


async def test_identity_grants_cannot_acquire_install_admin_authority(db):
    policy = Policy()
    await db.execute("INSERT INTO aweb.test_install_admins VALUES ($1, $2)", TEAM, "did:key:alice")
    caller = identity(grant=GrantContext(
        grant_id=str(uuid4()), session_did_key="did:key:session", issuing_certificate_id="cert-1",
        scopes=("coord.write",), expires_at=datetime.now(UTC) + timedelta(hours=1),
    ))
    with pytest.raises(HTTPException) as exc:
        await require(db, request(policy=policy), caller)
    assert (exc.value.status_code, exc.value.detail["code"]) == (403, "admin_required")
    assert policy.seen == []


def proxy_headers(principal_type="u"):
    return {
        "X-Team-ID": TEAM,
        "X-User-ID" if principal_type == "u" else "X-API-Key": PRINCIPAL,
        "X-AWEB-Actor-ID": ACTOR,
        "X-AWEB-Auth": build_internal_auth_header_value(
            secret=SECRET, team_id=TEAM, principal_type=principal_type, principal_id=PRINCIPAL, actor_id=ACTOR,
        ),
    }


@pytest.mark.parametrize("principal_type", ["u", "k"])
async def test_verified_internal_subject_reaches_host_policy(db, monkeypatch, principal_type):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", SECRET)
    policy = Policy()
    await db.execute("INSERT INTO aweb.test_install_admins VALUES ($1, $2)", TEAM, PRINCIPAL)
    req = request(headers=proxy_headers(principal_type), policy=policy)
    if principal_type == "u":
        await require(db, req)
    else:
        with pytest.raises(HTTPException) as exc:
            await require(db, req)
        assert exc.value.detail["code"] == "admin_required"
    subject, _, _ = policy.seen[-1]
    assert subject == InternalInstallAdminSubject(
        team_id=TEAM, principal_type=principal_type, principal_id=PRINCIPAL, actor_id=ACTOR,
    )


async def test_unverified_internal_headers_never_reach_policy(db, monkeypatch):
    monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
    monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", SECRET)
    headers = proxy_headers()
    headers["X-AWEB-Actor-ID"] = str(uuid4())
    policy = Policy()
    with pytest.raises(HTTPException) as exc:
        await require(db, request(headers=headers, policy=policy))
    assert exc.value.status_code == 401
    assert policy.seen == []


async def test_proxy_headers_do_not_authenticate_when_trust_is_disabled(db, monkeypatch):
    monkeypatch.delenv("AWEB_TRUST_PROXY_HEADERS", raising=False)
    policy = Policy()
    with pytest.raises(HTTPException) as exc:
        await require(db, request(headers=proxy_headers(), policy=policy))
    assert exc.value.status_code == 401
    assert policy.seen == []
