"""The owner's access view: who can use which secret, agreeing with real admission."""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import aweb_naapp.runtime
import httpx
import pytest
from aweb_naapp.console import CONSOLE_HEADERS, apply_console_migrations
from aweb_naapp.roles import assign, principal_key, unassign
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.team_auth import Principal, record_observed_principal
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI
from pgdbm import AsyncMigrationManager

from aweb_secrets import records
from aweb_secrets.admission import AdmissionRefused, UseRequest, admit_use
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_access import ConsoleAccess, console_access_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.containment_routes import containment_console_router
from aweb_secrets.grant import GrantRecord
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from tests.test_admission import POLICY_BODY, STATUS, _member
from tests.test_change_set_records import grant_after, item
from tests.test_change_sets import (
    ALICE,
    CAROL,
    ORIGIN,
    TEAM,
    Installations,
    World,
    by_member,
    change_set,
    draft,
)
from tests.test_change_sets import SECRET as DRAFT_SECRET
from tests.test_console import API
from tests.test_console_changes import sign_in
from tests.test_containment_service import service
from tests.test_use_approvals import Uses
from tests.test_use_approvals import uses as _uses
from tests.test_use_approvals import world as _world

world = _world
uses = _uses

RUNTIME_MIGRATIONS = Path(aweb_naapp.runtime.__file__).parent / "migrations"
DB_AGENT = _member(41)
READER = _member(42)
OPEN_AGENT = _member(43)
READERS = "secrets.role.readers"
ORDERS_DB = SecretRecord.from_after(
    {
        "v": 1,
        "secret_id": "sec_ordersdb1",
        "ref": "orders-db",
        "description": "Orders database",
        "kind": "bearer",
        "kind_params": {},
        "sensitivity": "sensitive",
        "approve_only": False,
        "backend": "native",
    }
)
PAYMENTS = SecretRecord.from_after(
    {
        **ORDERS_DB.after,
        "secret_id": "sec_paymnt01",
        "ref": "payments-api",
        "description": "Payments API",
        "sensitivity": "standard",
    }
)
ORDERS_URL = {"host": "db.orders.example", "port": 443, "path": "/v1/orders/{charge}"}
INSERT = OperationTemplate.from_after(
    {
        **STATUS,
        "operation_id": "insert-order",
        "secret_id": ORDERS_DB.secret_id,
        "method": "POST",
        "url": ORDERS_URL,
        "side_effect": "irreversible",
    }
)
READ = OperationTemplate.from_after(
    {**STATUS, "operation_id": "read-orders", "secret_id": ORDERS_DB.secret_id, "url": ORDERS_URL}
)
PINS = [{"operation_id": o.operation_id, "digest": o.digest} for o in (INSERT, READ)]
DB_POLICY = Policy.from_body({**POLICY_BODY, "rate": [], "operations": PINS, "open_request": False})
OPEN_POLICY = Policy.from_body({**POLICY_BODY, "rate": []})


def grant(grant_id, secret, subject, *, operations=(), open_request=False, policy=DB_POLICY):
    return GrantRecord.from_after(
        {
            "v": 1,
            "grant_id": grant_id,
            "secret_id": secret.secret_id,
            "subject": subject,
            "capability": "use",
            "operations": [
                {"operation_id": o.operation_id, "digest": o.digest} for o in operations
            ],
            "open_request": open_request,
            "jobs": [],
            "policy_digest": policy.digest,
        }
    )


DB_WRITE = grant("grt_dbwrite1", ORDERS_DB, {"principal": DB_AGENT.did_aw}, operations=[INSERT])
READING = grant("grt_readers1", ORDERS_DB, {"role": READERS}, operations=[READ])
OPEN = grant(
    "grt_open0001",
    PAYMENTS,
    {"principal": OPEN_AGENT.did_aw},
    open_request=True,
    policy=OPEN_POLICY,
)


async def seed(w: World) -> None:
    """The confirmed records of the DB-write scenario, and the runtime's observed names."""
    db = w.db
    await AsyncMigrationManager(
        db, migrations_path=str(RUNTIME_MIGRATIONS), module_name="aweb_naapp"
    ).apply_pending_migrations()
    async with db.transaction() as tx:
        for secret in (ORDERS_DB, PAYMENTS):
            await records.create_secret(tx, INSTALLATION_ID, TEAM, secret)
            await records.set_active_version(tx, INSTALLATION_ID, TEAM, secret.secret_id, 1)
        for operation in (INSERT, READ):
            await records.create_operation(tx, INSTALLATION_ID, TEAM, operation)
        for policy in (DB_POLICY, OPEN_POLICY):
            await records.create_policy(tx, INSTALLATION_ID, policy)
        for record in (DB_WRITE, READING, OPEN):
            await records.create_grant(tx, INSTALLATION_ID, TEAM, record)
        for member in (DB_AGENT, READER):
            await assign(tx, principal_key(member), READERS)
    # OPEN_AGENT was never observed, so it has no name to show.
    for member, alias in ((DB_AGENT, "db-agent"), (READER, "report-bot")):
        await record_observed_principal(db, replace(member, alias=alias))


@pytest.fixture
async def access(uses: Uses) -> Uses:
    await seed(uses.world)
    return uses


async def application(context: Uses, *, origin: str = ORIGIN, agent_origin: str = API):
    w = context.world
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        credential_audit=w.credential_audit,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    app.include_router(console_ui_router(sessions=console.sessions))
    app.include_router(console_access_router(services=ConsoleAccess(console=console)))
    app.include_router(containment_console_router(await service(context), console=console))
    return split_origins(FastAPI(), app, human_origin=origin, agent_origin=agent_origin)


@asynccontextmanager
async def clients(context: Uses):
    composed = await application(context)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=composed), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=composed), base_url=API) as agent,
    ):
        yield human, agent


class Page(HTMLParser):
    """Each element's data attributes, by class, in document order."""

    def __init__(self, html: str) -> None:
        super().__init__()
        self.found: list[tuple[str, dict[str, str]]] = []
        self.text: list[str] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes = {name: value or "" for name, value in attrs}
        for name in attributes.get("class", "").split():
            self.found.append((name, attributes))

    def handle_data(self, data):
        self.text.append(data)

    def all(self, name: str) -> list[dict[str, str]]:
        return [attributes for found, attributes in self.found if found == name]


def agents(page: Page) -> dict[str, dict[str, str]]:
    return {a["data-principal-did"]: a for a in page.all("access-agent")}


def grants(page: Page) -> dict[tuple[str, str], dict[str, str]]:
    return {(g["data-principal-did"], g["data-grant-id"]): g for g in page.all("access-grant")}


def uses_of(page: Page) -> dict[tuple[str, str, str], dict[str, str]]:
    return {
        (u["data-principal-did"], u["data-grant-id"], u.get("data-operation-id", "")): u
        for u in page.all("access-use")
    }


async def admission(context: Uses, member: Principal, secret: SecretRecord, operation: str, n: int):
    """Real admission at fixed valid concrete inputs: None when admitted, else its refusal."""
    body = f"{member.did_key} {operation} {n}".encode()
    request = UseRequest(
        secret_ref=secret.ref,
        request_id=f"req_{n}",
        request_sha256=hashlib.sha256(body).digest(),
        operation_id=operation or None,
        params={"charge": "ch_3Pq"} if operation else None,
    )
    try:
        async with context.world.db.transaction() as tx:
            await admit_use(
                tx,
                fence=context.world.fence,
                grant=Installations().grant,
                principal=member,
                request=request,
                attestation=None,
                now=datetime.now(UTC),
            )
    except AdmissionRefused as refused:
        return refused.code
    return None


async def owner_page(human, context: Uses, path: str = "/access") -> Page:
    response = await human.get(path)
    assert response.status_code == 200, response.text
    for name, value in CONSOLE_HEADERS.items():
        assert response.headers[name] == value
    return Page(response.text)


async def test_the_agent_with_db_write_is_flagged_with_its_direct_grant(access):
    async with clients(access) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        page = await owner_page(human, access)
    listed = agents(page)
    assert set(listed) == {DB_AGENT.did_aw, READER.did_aw, OPEN_AGENT.did_aw}
    assert set(listed[DB_AGENT.did_aw]["data-flags"].split()) == {"sensitive", "write"}
    assert set(listed[READER.did_aw]["data-flags"].split()) == {"sensitive"}
    assert listed[OPEN_AGENT.did_aw]["data-flags"] == ""
    direct = grants(page)[(DB_AGENT.did_aw, DB_WRITE.grant_id)]
    assert direct["data-secret-id"] == ORDERS_DB.secret_id and "data-via-role" not in direct
    write = uses_of(page)[(DB_AGENT.did_aw, DB_WRITE.grant_id, INSERT.operation_id)]
    assert write["data-side-effect"] == "irreversible" and write["data-covered"] == "true"
    # Named agents show their observed name beside their DID; the unobserved one only its DID.
    text = "".join(page.text)
    assert "db-agent" in text and "report-bot" in text
    assert all(member.did_aw in text for member in (DB_AGENT, READER, OPEN_AGENT))


async def test_role_derived_access_names_its_role_for_each_member(access):
    async with clients(access) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        page = await owner_page(human, access)
    for member in (DB_AGENT, READER):
        row = grants(page)[(member.did_aw, READING.grant_id)]
        assert row["data-via-role"] == READERS
        assert (
            uses_of(page)[(member.did_aw, READING.grant_id, READ.operation_id)]["data-side-effect"]
            == "none"
        )
    assert (OPEN_AGENT.did_aw, READING.grant_id) not in grants(page)


async def test_the_secret_view_lists_who_can_use_it_and_how(access):
    async with clients(access) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        page = await owner_page(human, access, f"/access/secrets/{ORDERS_DB.ref}")
        assert (await human.get("/access/secrets/no-such-secret")).status_code == 404
    assert set(agents(page)) == {DB_AGENT.did_aw, READER.did_aw}
    assert set(grants(page)) == {
        (DB_AGENT.did_aw, DB_WRITE.grant_id),
        (DB_AGENT.did_aw, READING.grant_id),
        (READER.did_aw, READING.grant_id),
    }


async def test_listed_coverage_agrees_with_real_admission(access):
    members = {m.did_aw: m for m in (DB_AGENT, READER, OPEN_AGENT)}
    secrets = {s.secret_id: s for s in (ORDERS_DB, PAYMENTS)}
    async with clients(access) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        page = await owner_page(human, access)
    listed = uses_of(page)
    assert len(listed) == 4
    by_grant = {(g["data-principal-did"], g["data-grant-id"]): g for g in page.all("access-grant")}
    for n, ((did, grant_id, operation), row) in enumerate(sorted(listed.items())):
        secret = secrets[by_grant[(did, grant_id)]["data-secret-id"]]
        assert (row["data-covered"] == "true") is (
            await admission(access, members[did], secret, operation, n) is None
        )
    # Configured access is per agent: an operation granted only to another
    # agent is neither listed for this one nor admitted.
    assert (READER.did_aw, DB_WRITE.grant_id, INSERT.operation_id) not in listed
    assert await admission(access, READER, ORDERS_DB, INSERT.operation_id, 99) == (
        "operation_not_allowed"
    )


async def test_revoking_the_displayed_grant_removes_the_access_and_admission_refuses(access):
    async with clients(access) as (human, _):
        csrf = await sign_in(
            access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
        )
        before = await owner_page(human, access)
        assert (DB_AGENT.did_aw, DB_WRITE.grant_id) in grants(before)
        assert await admission(access, DB_AGENT, ORDERS_DB, INSERT.operation_id, 1) is None
        revoke = before.all("access-revoke")
        assert {b["data-grant-id"] for b in revoke} >= {DB_WRITE.grant_id}
        response = await human.post(
            f"/installations/{INSTALLATION_ID}/containment",
            json={
                "request_id": "access-revoke-1",
                "action": "revoke-grant",
                "target": DB_WRITE.grant_id,
            },
            headers=csrf,
        )
        assert response.status_code == 200, response.text
        after = await owner_page(human, access)
    assert (DB_AGENT.did_aw, DB_WRITE.grant_id) not in grants(after)
    assert "write" not in agents(after)[DB_AGENT.did_aw]["data-flags"].split()
    # The role-derived read access is untouched.
    assert (DB_AGENT.did_aw, READING.grant_id) in grants(after)
    assert await admission(access, DB_AGENT, ORDERS_DB, INSERT.operation_id, 2) == (
        "operation_not_allowed"
    )
    assert await admission(access, DB_AGENT, ORDERS_DB, READ.operation_id, 3) is None


async def test_an_unconfirmed_draft_grants_no_listed_access(access):
    await draft(
        access.world,
        change_set(
            drafter=by_member(CAROL),
            changes=[
                item("secret", "create", DRAFT_SECRET["ref"], DRAFT_SECRET),
                item(
                    "policy",
                    "create",
                    Policy.from_body(POLICY_BODY).digest,
                    {"v": 1, **POLICY_BODY},
                ),
                item("grant", "create", grant_after()["grant_id"], grant_after()),
            ],
        ),
    )
    async with clients(access) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        page = await owner_page(human, access)
    assert CAROL.principal_did not in agents(page)
    assert grant_after()["grant_id"] not in {g["data-grant-id"] for g in page.all("access-grant")}


async def test_only_a_current_owner_reads_the_view_on_the_human_origin(access):
    async with clients(access) as (human, agent):
        assert (await human.get("/access")).status_code == 303
        assert (await agent.get("/access")).status_code == 404
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        assert (await human.get("/access")).status_code == 200
        async with access.world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        refused = await human.get("/access")
        assert refused.status_code in (303, 401, 403)
        assert DB_AGENT.did_aw not in refused.text


async def test_an_owner_withdrawal_committed_under_the_snapshot_refuses_without_retry(access):
    db = access.world.db
    async with clients(access) as (human, _):
        await sign_in(access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did))
        holding, release = asyncio.Event(), asyncio.Event()

        async def withdraw():
            async with db.transaction() as tx:
                await unassign(tx, ALICE, OWNER_ROLE)
                holding.set()
                await release.wait()

        withdrawal = asyncio.create_task(withdraw())
        await holding.wait()
        view = asyncio.create_task(human.get("/access"))
        for _ in range(500):
            if await db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()"
                " AND wait_event_type='Lock' AND query LIKE '%role_assignments%FOR SHARE%')"
            ):
                break
            await asyncio.sleep(0.01)
        else:
            release.set()
            await asyncio.gather(withdrawal, view, return_exceptions=True)
            pytest.fail("the view did not reach the owner role hold")
        release.set()
        await withdrawal
        refused = await asyncio.wait_for(view, 5)
    assert refused.status_code == 409 and refused.json()["detail"] == "access_changed"
    assert DB_AGENT.did_aw not in refused.text


async def test_removing_one_member_from_a_role_ends_only_its_access_and_admission_agrees(access):
    owners = grant(
        "grt_owners01", PAYMENTS, {"role": OWNER_ROLE}, open_request=True, policy=OPEN_POLICY
    )
    async with access.world.db.transaction() as tx:
        await records.create_grant(tx, INSTALLATION_ID, TEAM, owners)
    async with clients(access) as (human, _):
        csrf = await sign_in(
            access.world, human, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
        )
        before = await owner_page(human, access)
        # Once per agent and owner-defined role; never for direct or owner-role grants.
        assert sorted(
            (c["data-principal-did"], c["data-role"]) for c in before.all("access-remove-member")
        ) == sorted([(DB_AGENT.did_aw, READERS), (READER.did_aw, READERS)])
        assert (ALICE.principal_did, owners.grant_id) in grants(before)
        assert await admission(access, READER, ORDERS_DB, READ.operation_id, 1) is None
        response = await human.post(
            f"/installations/{INSTALLATION_ID}/containment",
            json={
                "request_id": "access-remove-1",
                "action": "remove-role-member",
                "target": READERS,
                "principal": READER.did_aw,
            },
            headers=csrf,
        )
        assert response.status_code == 200, response.text
        after = await owner_page(human, access)
    assert READER.did_aw not in agents(after)
    assert (DB_AGENT.did_aw, READING.grant_id) in grants(after)
    assert await admission(access, READER, ORDERS_DB, READ.operation_id, 2) == "grant_missing"
    assert await admission(access, DB_AGENT, ORDERS_DB, READ.operation_id, 3) is None
