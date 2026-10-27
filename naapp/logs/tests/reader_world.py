"""Logs' reader governance on real PostgreSQL, with a real AWID registry,
real owner acts and a software passkey: the world the reader tests share."""

from __future__ import annotations

import base64
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.approvals import DeliveryStatus
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.installation import InstallationFence, apply_installation_migrations
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty, contact_sha256
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TEAM_ID, TeamOwner, team_owner
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import running_registry
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.ledger import LogsSigner
from aweb_logs.readers import ReaderDesignations, ReaderDirectory

LOGS = "https://logs.example.test"


CONSOLE = "https://console.logs.example.test"


CONTACT = "reader@example.com"


OTHER_CONTACT = "someone-else@example.com"


class Installations:
    """logs' installation in TEAM_ID as the team server reports it."""

    def __init__(self) -> None:
        self.grant = Grant(
            team_id=TEAM_ID,
            installation_id=INSTALLATION_ID,
            generation=1,
            scopes=frozenset({"logs.readers"}),
            fresh_until=time.monotonic_ns() + seconds_to_ns(55),
        )

    async def grant_for(self, team_id, certificate_id=None):
        return self.grant if team_id == TEAM_ID else None

    async def status_for(self, team_id):
        if team_id != TEAM_ID:
            return None
        return SimpleNamespace(
            team_id=TEAM_ID,
            app_id=APP_ID,
            state="active",
            installation_id=INSTALLATION_ID,
            generation=1,
            granted_scopes=self.grant.scopes,
            fresh_until=self.grant.fresh_until,
        )


@dataclass
class Inbox:
    enrolments: dict[str, list[str]] = field(default_factory=dict)

    async def deliver_enrolment_link(self, approver, link_token: str) -> DeliveryStatus:
        self.enrolments.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        return DeliveryStatus.DELIVERED

    async def deliver_notice(self, contact: str, notice) -> DeliveryStatus:
        return DeliveryStatus.DELIVERED


def governance_registration() -> RegistrationView:
    now = datetime.now(UTC)
    return RegistrationView(
        TEAM_ID,
        "post-governance-hook",
        now,
        timedelta(seconds=60),
        (Registration(str(uuid4()), LOGS, "POST", "/hooks/ingest", now - timedelta(hours=1)),),
    )


@dataclass
class World:
    db: AsyncDatabaseManager
    owner: TeamOwner
    signer: LogsSigner
    directory: ReaderDirectory
    inbox: Inbox
    registered: list[bool]
    designations: ReaderDesignations = field(init=False)
    recorder: CredentialAudit = field(init=False)
    passkeys: Passkeys = field(init=False)


@pytest.fixture(name="world")
async def world_fixture(test_db_factory) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="logs_reader_designation")
    registry_db = await test_db_factory.create_db(suffix="logs_reader_designation_awid")
    for migrate in (
        apply_owner_act_migrations,
        apply_installation_migrations,
        apply_outbox_migrations,
    ):
        await migrate(db)
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    fence = InstallationFence(db, app_id=APP_ID, grants=Installations())
    producer = HookProducer(
        ServerProducer.app(
            origin=LOGS,
            app_id=APP_ID,
            installation_id=INSTALLATION_ID,
            generation=1,
            kid="logs-governance",
            seed=os.urandom(32),
        )
    )
    signer = LogsSigner(logs_origin=LOGS, kid="logs-chain", signing_key=SigningKey.generate())
    directory = ReaderDirectory(db)
    registered = [True]

    async def view(team_id: str) -> RegistrationView | None:
        return governance_registration() if registered[0] else None

    async with running_registry(registry_db.config.get_dsn()) as registry:
        owner = await team_owner(registry, team_id=TEAM_ID)
        state = World(db, owner, signer, directory, Inbox(), registered)
        state.recorder = CredentialAudit(
            db=db,
            app_id=APP_ID,
            fence=fence,
            contexts=directory.proof_context(app_id=APP_ID),
            owner_act_scope=owner.verifier.scope,
            producer=lambda **_: producer,
            passkeys=lambda: state.passkeys,
            role_of=directory.role_of,
            registration_view=view,
            max_backlog_age=timedelta(minutes=5),
            migration_module="aweb_logs_credential_audit",
            after_enqueue=directory.appender(signer),
        )
        await state.recorder.migrate()
        state.passkeys = Passkeys(
            db,
            rp=RelyingParty(origin=CONSOLE, name="logs"),
            delivery=state.inbox,
            audit=state.recorder,
            retirement=directory,
            enrolment_ttl=timedelta(hours=1),
            challenge_ttl=timedelta(minutes=5),
            proof_context=directory.proof_context(app_id=APP_ID),
        )
        await state.passkeys.migrate()
        state.designations = ReaderDesignations(
            directory,
            fence=fence,
            verifier=owner.verifier,
            passkeys=state.passkeys,
            recorder=state.recorder,
        )
        yield state


async def slot(world: World, contact: str = CONTACT) -> str:
    async with world.db.transaction() as tx:
        issued = await world.directory.create_slot(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM_ID,
            contact_sha256=contact_sha256(contact),
        )
    return issued.scope


def designation(scope: str, contact: str = CONTACT) -> dict:
    return {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": contact_sha256(contact),
    }


async def chained(world: World) -> list[dict]:
    """The team's chain entries, as the envelopes logs retained."""
    rows = await world.db.fetch_all(
        "SELECT signing_bytes, signature FROM {{tables.chain_events}}"
        " WHERE team_id = $1 ORDER BY team_seq",
        TEAM_ID,
    )
    return [
        verify(bytes(row["signing_bytes"]), row["signature"], team_id=TEAM_ID).fields
        for row in rows
    ]


async def outbox(world: World) -> list[tuple]:
    rows = await world.db.fetch_all(
        "SELECT event_id, payload, signature FROM {{tables.outbox_events}} ORDER BY position"
    )
    return [(row["event_id"], bytes(row["payload"]), row["signature"]) for row in rows]


async def count(world: World, table: str) -> int:
    return await world.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}")


async def nothing_took_effect(world: World, scope: str) -> None:
    assert await world.directory.reader(scope) is None
    assert world.inbox.enrolments == {}
    assert await count(world, "outbox_events") == 0
    assert await count(world, "owner_act_nonces") == 0
    assert await chained(world) == []


async def enrolled_reader(world: World) -> tuple[str, str]:
    """A designated reader that has enrolled its passkey: its scope and holder."""
    scope = await slot(world)
    signing, signature = world.owner.sign("app-role.designate", designation(scope))
    await world.designations.designate(
        signing=signing, signature=signature, scope=scope, contact=CONTACT
    )
    token = world.inbox.enrolments[CONTACT][-1]
    enrolment = await world.recorder.prepare_enrolment(token)
    with world.recorder.prepared(enrolment):
        await world.passkeys.complete_enrolment(
            token,
            SoftAuthenticator(CONSOLE).create(await world.passkeys.enrolment_options(token)),
            fence=enrolment,
        )
    return scope, await holder(world, scope)


async def holder(world: World, scope: str) -> str | None:
    return await world.db.fetch_value(
        "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope = $1 AND superseded_at IS NULL",
        scope,
    )


def revocation(scope: str, subject_ref: str) -> dict:
    return {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "subject_ref": subject_ref,
    }


def act_body(signing: bytes, signature: str, **fields) -> dict:
    return {"signing": base64.b64encode(signing).decode(), "signature": signature, **fields}


def console_headed(response: httpx.Response) -> bool:
    return all(response.headers.get(name) == value for name, value in CONSOLE_HEADERS.items())
