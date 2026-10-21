"""A real passkey world for the console tests: B3 on PostgreSQL, with owners
designated, recovered and retired by real team owner acts, and enrolled
through real WebAuthn ceremonies."""

from dataclasses import dataclass, field
from datetime import timedelta

from aweb_naapp_testing import Registry
from aweb_naapp_testing.owner_acts import (
    TeamOwner,
    designation_subject,
    revocation_subject,
    team_owner,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from pgdbm import AsyncDatabaseManager

from aweb_naapp.console import MAX_SESSION, ConsoleSessions, apply_console_migrations
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.runtime.approvals import ApprovalRevocation, PgApprovalStore
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
from tests.runtime.approvals.support import AuditOutbox
from tests.runtime.approvals.test_passkeys import Contacts

HUMAN = "https://console.example"
OWNER_A = "app.owner.a"
OWNER_B = "app.owner.b"


@dataclass
class Console:
    db: AsyncDatabaseManager
    passkeys: Passkeys
    contacts: Contacts
    owner: TeamOwner
    origin: str = HUMAN
    allowed: set[str] = field(default_factory=lambda: {OWNER_A, OWNER_B})

    async def admits(self, scope: str) -> bool:
        """The app's predicate: which scopes may log in on this console."""
        return scope in self.allowed

    def sessions(self, ttl: timedelta = MAX_SESSION) -> ConsoleSessions:
        return ConsoleSessions(self.db, passkeys=self.passkeys, scopes=self.admits, ttl=ttl)

    async def enrol(self, scope: str, contact: str | None = None) -> tuple[str, SoftAuthenticator]:
        """Designate the scope's first approver and enrol its passkey."""
        return await self._designate("app-role.designate", scope, contact or f"{scope}@example.com")

    async def recover(self, scope: str, contact: str) -> tuple[str, SoftAuthenticator]:
        """Replace the scope's approver after a lockout; the old one is retired at once."""
        return await self._designate("app-credential.recover", scope, contact)

    async def retire(self, scope: str, subject: str) -> None:
        """The owner revokes `subject`'s role: consume the act and retire in one transaction."""
        act_subject = revocation_subject(scope, subject)
        prepared = await self.owner.prepare("app-role.revoke", act_subject)
        async with self.db.transaction() as tx:
            evidence = await self.owner.consume(tx, prepared, act_subject)
            await self.passkeys.retire(tx, scope=scope, evidence=evidence)

    async def designate(self, scope: str, contact: str, act: str = "app-role.designate") -> str:
        """Apply one signed owner act that designates the scope's approver, and
        return the enrolment link token delivered to `contact`."""
        act_subject = designation_subject(scope, contact)
        prepared = await self.owner.prepare(act, act_subject)
        async with self.db.transaction() as tx:
            evidence = await self.owner.consume(tx, prepared, act_subject)
            designation = await self.passkeys.designate(
                tx, scope=scope, contact=contact, evidence=evidence
            )
        await self.passkeys.deliver(designation)
        return self.contacts.last(contact)

    async def _designate(self, act: str, scope: str, contact: str) -> tuple[str, SoftAuthenticator]:
        token = await self.designate(scope, contact, act)
        device = SoftAuthenticator(self.origin)
        approver = await self.passkeys.complete_enrolment(
            token, device.create(dict(await self.passkeys.enrolment_options(token)))
        )
        return approver.subject, device


async def console_world(
    test_db_factory, registry: Registry, suffix: str, origin: str = HUMAN
) -> Console:
    db = await test_db_factory.create_db(suffix=suffix, schema="app")
    audit = AuditOutbox(db)
    await audit.create()
    store = PgApprovalStore(db)
    await store.migrate()
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=origin, name="Console"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
    )
    await passkeys.migrate()
    await apply_owner_act_migrations(db)
    await apply_console_migrations(db)
    return Console(db, passkeys, contacts, await team_owner(registry), origin)
