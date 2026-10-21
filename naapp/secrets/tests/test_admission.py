"""Admission of a member's use of a secret (§4.1), on real PostgreSQL with the real
installation fence, idempotency store and role assignments."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import asyncpg
import pytest
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.roles import apply_roles_migrations, assign, principal_key, unassign
from aweb_naapp.runtime.attestation import VerifiedAttestation
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationRefused,
    apply_installation_migrations,
)
from aweb_naapp.runtime.team_auth import Principal
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_secrets import records
from aweb_secrets.admission import AdmissionRefused, UseRequest, admit_use
from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME
from aweb_secrets.grant import GrantRecord
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import apply_revision_migrations
from aweb_secrets.secret import SecretRecord

TEAM = "backend:acme.com"
INSTALLATION = "inst_5d2a9c31"
GENERATION = 3
# Tuesday 2026-10-20, 12:00 UTC.
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def _member(seed: int, *, did_aw: bool = True, team_id: str = TEAM) -> Principal:
    key = bytes(SigningKey(bytes([seed]) * 32).verify_key)
    return Principal(
        team_id=team_id,
        did_key=did_from_public_key(key),
        did_aw=stable_id_from_public_key(key) if did_aw else None,
        address=None,
        alias=f"member-{seed}",
        certificate_id=f"cert-{seed}",
        team_did_key="did:key:z6MkteamKey",
    )


ALICE = _member(1)
BOB = _member(2)
BUILD_BOT = _member(3, did_aw=False)

POLICY_BODY: dict[str, Any] = {
    "approval": "none",
    "approvers": [],
    "approval_ttl_s": 900,
    "rate": [{"per": "principal_secret", "capacity": 2, "window_s": 3600}],
    "windows": None,
    "operations": [],
    "open_request": True,
    "request": {"max_bytes": 65536},
    "result": {"max_bytes": 65536},
    "requires_attestation": None,
    "distinct_approver": "not_required",
}
SECRET: dict[str, Any] = {
    "v": 1,
    "secret_id": "sec_19ab42",
    "ref": "staging-api",
    "description": "Staging API key",
    "kind": "bearer",
    "kind_params": {},
    "sensitivity": "standard",
    "approve_only": False,
    "backend": "native",
}


def _grant_source_grant(
    installation_id: str | None = INSTALLATION, generation: int | None = GENERATION
) -> Grant:
    return Grant(
        team_id=TEAM,
        scopes=frozenset({"secrets:use"}),
        fresh_until=time.monotonic() + 30,
        installation_id=installation_id,
        generation=generation,
    )


class InstalledSecrets:
    async def grant_for(self, team_id: str) -> Grant | None:
        return _grant_source_grant() if team_id == TEAM else None


def _request(request_id: str = "req_1", body: bytes = b"GET /v1/status", **changes) -> UseRequest:
    request = UseRequest(
        secret_ref="staging-api",
        request_id=request_id,
        request_sha256=hashlib.sha256(body).digest(),
        operation_id=None,
        params=None,
    )
    return replace(request, **changes)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="secrets_admission")
    await apply_installation_migrations(database)
    await apply_idempotency_migrations(database)
    await apply_roles_migrations(database)
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    await apply_revision_migrations(database)
    yield database


@pytest.fixture
def fence(db) -> InstallationFence:
    return InstallationFence(db, app_id="secrets", grants=InstalledSecrets())


async def _install(
    db: AsyncDatabaseManager,
    *,
    secret: dict | None = None,
    policy_body: dict | None = None,
    subject: dict | None = None,
    installation_id: str = INSTALLATION,
    active_version: int | None = 4,
    **grant_changes,
) -> Policy:
    policy = Policy.from_body(policy_body or POLICY_BODY)
    record = SecretRecord.from_after(secret or SECRET)
    after = {
        "v": 1,
        "grant_id": grant_changes.pop("grant_id", "grt_alice001"),
        "secret_id": record.secret_id,
        "subject": subject or {"principal": principal_key(ALICE).principal_did},
        "capability": "use",
        "operations": [],
        "open_request": True,
        "jobs": [],
        "policy_digest": policy.digest,
    }
    after.update(grant_changes)
    async with db.transaction() as tx:
        if await records.secret_by_ref(tx, installation_id, TEAM, record.ref) is None:
            await records.create_secret(tx, installation_id, TEAM, record)
            if active_version is not None:
                await records.set_active_version(
                    tx, installation_id, TEAM, record.secret_id, active_version
                )
        await records.create_policy(tx, installation_id, policy)
        await records.create_grant(tx, installation_id, TEAM, GrantRecord.from_after(after))
    return policy


async def _admit(
    db: AsyncDatabaseManager,
    fence: InstallationFence,
    principal: Principal = ALICE,
    request: UseRequest | None = None,
    *,
    grant: Grant | None = None,
    attestation: VerifiedAttestation | None = None,
    now: datetime = NOW,
):
    async with db.transaction() as tx:
        return await admit_use(
            tx,
            fence=fence,
            grant=grant or _grant_source_grant(),
            principal=principal,
            request=request or _request(),
            attestation=attestation,
            now=now,
        )


async def _refusal(*args, **kwargs) -> str:
    with pytest.raises(AdmissionRefused) as refused:
        await _admit(*args, **kwargs)
    return refused.value.code


async def _intents(db: AsyncDatabaseManager) -> int:
    return int(await db.fetch_value("SELECT count(*) FROM {{tables.intents}}"))


async def test_a_granted_principal_is_admitted_and_its_intent_recorded(db, fence) -> None:
    policy = await _install(db)
    admitted = await _admit(db, fence)
    assert not admitted.replayed and not admitted.approval_required
    row = await db.fetch_one(
        "SELECT * FROM {{tables.intents}} WHERE intent_id = $1", admitted.intent_id
    )
    assert row is not None
    assert (row["installation_id"], row["install_generation"]) == (INSTALLATION, GENERATION)
    assert (row["principal_did"], row["grant_id"]) == (ALICE.did_aw, "grt_alice001")
    assert (row["policy_digest"], row["secret_version"]) == (policy.digest, 4)
    assert row["action"] == "open_request"


async def test_no_grant_no_use(db, fence) -> None:
    await _install(db)
    assert await _refusal(db, fence, BOB) == "grant_missing"
    assert await _intents(db) == 0


async def test_an_unknown_secret_is_refused_like_an_ungranted_one(db, fence) -> None:
    await _install(db)
    assert await _refusal(db, fence, request=_request(secret_ref="payroll")) == "grant_missing"


async def test_the_same_did_aw_on_another_team_gets_nothing(db, fence) -> None:
    await _install(db)
    elsewhere = replace(ALICE, team_id="frontend:acme.com")
    other_team_grant = replace(_grant_source_grant(), team_id="frontend:acme.com")
    assert await _refusal(db, fence, elsewhere, grant=other_team_grant) == "grant_missing"


async def test_a_reissued_certificate_under_the_same_did_aw_keeps_the_grant(db, fence) -> None:
    await _install(db)
    reissued = replace(ALICE, did_key=BOB.did_key, certificate_id="cert-1b")
    await _admit(db, fence, reissued)


async def test_a_member_without_did_aw_is_granted_by_its_did_key(db, fence) -> None:
    await _install(db, subject={"principal": BUILD_BOT.did_key})
    await _admit(db, fence, BUILD_BOT)
    new_key = replace(BUILD_BOT, did_key=BOB.did_key)
    assert await _refusal(db, fence, new_key) == "grant_missing"


async def test_a_role_grant_admits_the_roles_members_only_while_they_hold_it(db, fence) -> None:
    await _install(db, subject={"role": "secrets.role.deployers"})
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), "secrets.role.deployers")
    await _admit(db, fence, BOB)
    async with db.transaction() as tx:
        await unassign(tx, principal_key(BOB), "secrets.role.deployers")
    assert await _refusal(db, fence, BOB, _request("req_2")) == "grant_missing"


async def test_a_revoked_grant_admits_nothing(db, fence) -> None:
    await _install(db)
    async with db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
    assert await _refusal(db, fence) == "grant_missing"


async def test_a_sensitive_secret_refuses_open_requests(db, fence) -> None:
    await _install(db, secret={**SECRET, "sensitivity": "sensitive"})
    assert await _refusal(db, fence) == "open_request_not_allowed"


async def test_a_policy_without_open_requests_refuses_them(db, fence) -> None:
    await _install(db, policy_body={**POLICY_BODY, "open_request": False})
    assert await _refusal(db, fence) == "open_request_not_allowed"


async def test_a_grant_of_named_operations_does_not_cover_an_open_request(db, fence) -> None:
    await _install(
        db,
        operations=[{"operation_id": "refund", "digest": "a" * 64}],
        open_request=False,
    )
    assert await _refusal(db, fence) == "open_request_not_allowed"


async def test_an_unconfirmed_secret_is_disabled(db, fence) -> None:
    await _install(db, active_version=None)
    assert await _refusal(db, fence) == "secret_disabled"


async def test_a_disabled_secret_is_refused(db, fence) -> None:
    await _install(db)
    async with db.transaction() as tx:
        await tx.execute("UPDATE {{tables.secrets}} SET state = 'disabled'")
    assert await _refusal(db, fence) == "secret_disabled"


async def test_a_closed_window_is_a_refusal(db, fence) -> None:
    windows = {
        "time_zone": "UTC",
        "ranges": [{"days": ["sat", "sun"], "from": "00:00", "to": "23:59"}],
    }
    await _install(db, policy_body={**POLICY_BODY, "windows": windows})
    assert await _refusal(db, fence) == "policy_window_closed"


async def test_the_rate_limit_is_a_refusal_and_a_refusal_charges_nothing(db, fence) -> None:
    await _install(db)
    await _admit(db, fence, request=_request("req_1"))
    await _admit(db, fence, request=_request("req_2"))
    assert await _refusal(db, fence, request=_request("req_3")) == "policy_rate_limited"
    assert await _intents(db) == 2


async def test_requires_attestation_refuses_without_a_verified_attestation(db, fence) -> None:
    await _install(
        db, policy_body={**POLICY_BODY, "requires_attestation": {"channels": ["dashboard"]}}
    )
    assert await _refusal(db, fence) == "attestation_unavailable"
    dashboard = VerifiedAttestation(
        custodian_id="cust_1", channel="dashboard", human_principal=None, session_id="ses_1"
    )
    l2 = VerifiedAttestation(
        custodian_id="cust_1", channel="mcp_l2", human_principal="h_1", session_id="ses_1"
    )
    assert await _refusal(db, fence, attestation=l2) == "attestation_unavailable"
    await _admit(db, fence, attestation=dashboard)


async def test_per_use_approval_is_required_by_the_policy(db, fence) -> None:
    await _install(
        db, policy_body={**POLICY_BODY, "approval": "per_use", "approvers": ["finance-approver"]}
    )
    assert (await _admit(db, fence)).approval_required


async def test_a_replayed_request_returns_the_first_receipt(db, fence) -> None:
    await _install(db)
    first = await _admit(db, fence)
    again = await _admit(db, fence)
    assert (again.intent_id, again.replayed) == (first.intent_id, True)
    assert await _intents(db) == 1
    # The replay charged no rate token: one more request still fits.
    await _admit(db, fence, request=_request("req_2"))


async def test_a_replayed_request_id_with_other_bytes_is_a_conflict(db, fence) -> None:
    await _install(db)
    await _admit(db, fence)
    assert await _refusal(db, fence, request=_request(body=b"DELETE /v1/all")) == (
        "idempotency_conflict"
    )


async def test_a_replay_after_the_grant_is_revoked_is_refused(db, fence) -> None:
    await _install(db)
    await _admit(db, fence)
    async with db.transaction() as tx:
        await records.revoke_grant(tx, INSTALLATION, "grt_alice001")
    assert await _refusal(db, fence) == "grant_revoked"


async def test_the_first_admitting_grant_is_used_direct_before_role(db, fence) -> None:
    closed = {"time_zone": "UTC", "ranges": [{"days": ["sat"], "from": "00:00", "to": "01:00"}]}
    await _install(db, grant_id="grt_alice001", policy_body={**POLICY_BODY, "windows": closed})
    open_policy = await _install(db, grant_id="grt_role0001", subject={"role": "secrets.owner"})
    async with db.transaction() as tx:
        await assign(tx, principal_key(ALICE), "secrets.owner")
    admitted = await _admit(db, fence)
    assert (admitted.grant_id, admitted.policy_digest) == ("grt_role0001", open_policy.digest)


async def test_when_no_grant_admits_the_first_candidates_refusal_is_returned(db, fence) -> None:
    closed = {"time_zone": "UTC", "ranges": [{"days": ["sat"], "from": "00:00", "to": "01:00"}]}
    await _install(db, grant_id="grt_alice001", policy_body={**POLICY_BODY, "windows": closed})
    await _install(
        db,
        grant_id="grt_role0001",
        subject={"role": "secrets.owner"},
        policy_body={**POLICY_BODY, "open_request": False},
    )
    async with db.transaction() as tx:
        await assign(tx, principal_key(ALICE), "secrets.owner")
    assert await _refusal(db, fence) == "policy_window_closed"


async def test_a_newer_generation_supersedes_an_older_grant(db, fence) -> None:
    await _install(db)
    await _admit(db, fence, grant=_grant_source_grant(generation=GENERATION + 1))
    with pytest.raises(InstallationRefused) as refused:
        await _admit(db, fence, request=_request("req_2"))
    assert refused.value.code == "generation_superseded"


async def test_a_grant_without_installation_identity_is_refused(db, fence) -> None:
    await _install(db)
    with pytest.raises(InstallationRefused) as refused:
        await _admit(db, fence, grant=_grant_source_grant(installation_id=None))
    assert refused.value.code == "installation_identity_required"


async def test_a_new_installation_finds_none_of_the_old_grants(db, fence) -> None:
    await _install(db)
    await _admit(db, fence)
    reinstalled = _grant_source_grant(installation_id="inst_new00001", generation=GENERATION + 1)
    assert (
        await _refusal(db, fence, grant=reinstalled, request=_request("req_2")) == "grant_missing"
    )


STATUS: dict[str, Any] = {
    "v": 1,
    "operation_id": "charge-status",
    "secret_id": "sec_19ab42",
    "method": "GET",
    "url": {"host": "api.payments.example", "port": 443, "path": "/v1/charges/{charge}"},
    "params": {
        "charge": {
            "schema": {"type": "string", "minLength": 3, "maxLength": 64},
            "charset": "base64url",
            "placement": "path",
        }
    },
    "body": None,
    "headers": {"fixed": {}, "allowed": []},
    "response": {
        "projection": ["/status"],
        "max_bytes": 4096,
        "content_types": ["application/json"],
    },
    "side_effect": "none",
    "token_issuing": False,
    "result_handling": "deny",
    "store_as_secret": None,
    "idempotency": None,
    "reconcile": None,
    "timeout_s": 10,
}


def _operation(**changes) -> OperationTemplate:
    return OperationTemplate.from_after({**STATUS, **changes})


async def _define(db, template: OperationTemplate) -> None:
    async with db.transaction() as tx:
        if await records.secret_by_ref(tx, INSTALLATION, TEAM, SECRET["ref"]) is None:
            await records.create_secret(tx, INSTALLATION, TEAM, SecretRecord.from_after(SECRET))
            await records.set_active_version(tx, INSTALLATION, TEAM, SECRET["secret_id"], 4)
        await records.create_operation(tx, INSTALLATION, TEAM, template)


async def _install_operation(
    db, template: OperationTemplate, *, policy_changes=None, secret=None, **grant_changes
) -> Policy:
    pinned = [{"operation_id": template.operation_id, "digest": template.digest}]
    body = {**POLICY_BODY, "operations": pinned, "open_request": False, **(policy_changes or {})}
    async with db.transaction() as tx:
        if secret is not None:
            await records.create_secret(tx, INSTALLATION, TEAM, SecretRecord.from_after(secret))
            await records.set_active_version(tx, INSTALLATION, TEAM, secret["secret_id"], 4)
    await _define(db, template)
    grant = {"operations": pinned, "open_request": False, **grant_changes}
    return await _install(db, policy_body=body, secret=secret, **grant)


def _named(request_id: str = "req_op1", **params) -> UseRequest:
    return _request(
        request_id,
        body=b"charge-status " + request_id.encode(),
        operation_id="charge-status",
        params={"charge": "ch_3Pq", **params},
    )


async def test_a_granted_named_operation_is_admitted_at_its_digest(db, fence) -> None:
    template = _operation()
    await _install_operation(db, template)
    admitted = await _admit(db, fence, request=_named())
    row = await db.fetch_one(
        "SELECT action, operation_id, operation_digest FROM {{tables.intents}} WHERE intent_id = $1",
        admitted.intent_id,
    )
    assert dict(row) == {
        "action": "operation",
        "operation_id": "charge-status",
        "operation_digest": template.digest,
    }


async def test_an_edited_operation_is_not_covered_by_the_old_grant(db, fence) -> None:
    await _install_operation(db, _operation())
    await _define(db, _operation(timeout_s=5))
    assert await _refusal(db, fence, request=_named()) == "operation_not_allowed"


async def test_an_unknown_operation_is_not_allowed(db, fence) -> None:
    await _install_operation(db, _operation())
    unknown = replace(_named(), operation_id="refund")
    assert await _refusal(db, fence, request=unknown) == "operation_not_allowed"


async def test_a_policy_that_does_not_list_the_operation_refuses_it(db, fence) -> None:
    await _install_operation(db, _operation(), policy_changes={"operations": []})
    assert await _refusal(db, fence, request=_named()) == "operation_not_allowed"


async def test_an_open_request_grant_does_not_cover_a_named_operation(db, fence) -> None:
    template = _operation()
    await _install_operation(db, template, operations=[], open_request=True)
    assert await _refusal(db, fence, request=_named()) == "operation_not_allowed"


@pytest.mark.parametrize(
    "params",
    [{"charge": "ch/3Pq"}, {"charge": "ch"}, {"charge": "ch_3Pq", "extra": 1}, {}],
)
async def test_parameters_outside_their_slots_are_invalid(db, fence, params) -> None:
    await _install_operation(db, _operation())
    request = replace(_named(), params=params)
    assert await _refusal(db, fence, request=request) == "params_invalid"


async def test_a_token_issuing_operation_without_result_handling_is_denied(db, fence) -> None:
    await _install_operation(db, _operation(token_issuing=True))
    assert await _refusal(db, fence, request=_named()) == "token_issuing_denied"


async def test_a_token_issuing_operation_that_withholds_its_result_is_admitted(db, fence) -> None:
    await _install_operation(db, _operation(token_issuing=True, result_handling="withhold"))
    await _admit(db, fence, request=_named())


async def test_approve_only_requires_approval_whatever_the_policy(db, fence) -> None:
    approve_only = {**SECRET, "sensitivity": "sensitive", "approve_only": True}
    await _install_operation(db, _operation(), secret=approve_only)
    assert (await _admit(db, fence, request=_named())).approval_required


async def test_a_secret_made_sensitive_refuses_its_unprojected_operations(db, fence) -> None:
    unprojected = _operation(
        response={"projection": None, "max_bytes": 4096, "content_types": ["application/json"]}
    )
    await _install_operation(db, unprojected)
    sensitive = SecretRecord.from_after({**SECRET, "sensitivity": "sensitive"})
    async with db.transaction() as tx:
        await records.update_secret(tx, INSTALLATION, TEAM, sensitive)
    assert await _refusal(db, fence, request=_named()) == "operation_not_allowed"


async def test_a_loose_policy_never_refills_a_strict_ones_buckets(db, fence) -> None:
    strict = {**POLICY_BODY, "rate": [{"per": "principal_secret", "capacity": 2, "window_s": 3600}]}
    loose = {
        **POLICY_BODY,
        "approval": "per_use",
        "approvers": ["finance-approver"],
        "rate": [{"per": "principal_secret", "capacity": 100, "window_s": 3600}],
    }
    await _install(db, grant_id="grt_alice001", policy_body=strict)
    await _install(
        db, grant_id="grt_role0001", subject={"role": "secrets.owner"}, policy_body=loose
    )
    async with db.transaction() as tx:
        await assign(tx, principal_key(ALICE), "secrets.owner")
    used = [(await _admit(db, fence, request=_request(f"req_{n}"))).grant_id for n in range(5)]
    assert used == ["grt_alice001", "grt_alice001", "grt_role0001", "grt_role0001", "grt_role0001"]


async def _unassign_blocked(db, principal, role) -> None:
    with pytest.raises(asyncpg.LockNotAvailableError):
        async with db.transaction() as tx:
            await tx.execute("SET LOCAL lock_timeout = '100ms'")
            await unassign(tx, principal_key(principal), role)


async def test_a_role_admitting_a_request_is_held_until_the_admission_commits(db, fence) -> None:
    await _install(db, subject={"role": "secrets.role.deployers"})
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), "secrets.role.deployers")
    async with db.transaction() as admitting:
        admitted = await admit_use(
            admitting,
            fence=fence,
            grant=_grant_source_grant(),
            principal=BOB,
            request=_request(),
            attestation=None,
            now=NOW,
        )
        assert admitted.grant_id == "grt_alice001"
        await _unassign_blocked(db, BOB, "secrets.role.deployers")
    async with db.transaction() as tx:
        await unassign(tx, principal_key(BOB), "secrets.role.deployers")


async def test_a_replay_holds_the_role_it_was_admitted_under(db, fence) -> None:
    await _install(db, subject={"role": "secrets.role.deployers"})
    async with db.transaction() as tx:
        await assign(tx, principal_key(BOB), "secrets.role.deployers")
    await _admit(db, fence, BOB)
    async with db.transaction() as replaying:
        replayed = await admit_use(
            replaying,
            fence=fence,
            grant=_grant_source_grant(),
            principal=BOB,
            request=_request(),
            attestation=None,
            now=NOW,
        )
        assert replayed.replayed
        await _unassign_blocked(db, BOB, "secrets.role.deployers")


async def test_a_refusal_committed_by_its_caller_leaves_no_claim_behind(db, fence) -> None:
    await _install(db, subject={"principal": BOB.did_aw}, grant_id="grt_bob00001")
    async with db.transaction() as tx:
        with pytest.raises(AdmissionRefused):
            await admit_use(
                tx,
                fence=fence,
                grant=_grant_source_grant(),
                principal=ALICE,
                request=_request(),
                attestation=None,
                now=NOW,
            )
        # The caller records the denial in the same transaction and commits.
    await _install(db)
    admitted = await _admit(db, fence)
    assert not admitted.replayed


async def test_a_replay_under_a_superseded_generation_is_refused(db, fence) -> None:
    await _install(db)
    await _admit(db, fence)
    with pytest.raises(InstallationRefused) as refused:
        await _admit(db, fence, grant=_grant_source_grant(generation=GENERATION + 1))
    assert refused.value.code == "generation_superseded"


async def test_admissions_under_reversed_policy_orders_never_deadlock(db, fence) -> None:
    # Alice's direct grant is under policy A and her role grant under B; Bob's
    # direct grant is under B and his role grant under A. Each admission is
    # refused by its first candidate's window and charges its second, so both
    # lock both policies' shared per-secret buckets, in opposite candidate orders.
    closed = {"time_zone": "UTC", "ranges": [{"days": ["sat"], "from": "00:00", "to": "01:00"}]}
    a = {**POLICY_BODY, "rate": [{"per": "secret", "capacity": 1000, "window_s": 3600}]}
    b = {**a, "approval_ttl_s": 600}
    await _install(db, grant_id="grt_alice001", policy_body={**a, "windows": closed})
    await _install(db, grant_id="grt_alice002", subject={"role": "secrets.role.b"}, policy_body=b)
    await _install(
        db,
        grant_id="grt_bob00001",
        subject={"principal": BOB.did_aw},
        policy_body={**b, "windows": closed},
    )
    await _install(db, grant_id="grt_bob00002", subject={"role": "secrets.role.a"}, policy_body=a)
    async with db.transaction() as tx:
        await assign(tx, principal_key(ALICE), "secrets.role.b")
        await assign(tx, principal_key(BOB), "secrets.role.a")

    async def admit(principal: Principal, n: int) -> str:
        return (await _admit(db, fence, principal, request=_request(f"req_{n}"))).grant_id

    outcomes = await asyncio.gather(
        *(admit(ALICE if n % 2 else BOB, n) for n in range(24)), return_exceptions=True
    )
    assert [o for o in outcomes if isinstance(o, BaseException)] == []
