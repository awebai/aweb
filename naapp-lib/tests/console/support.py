"""A real passkey world for the console tests: B3 on PostgreSQL, with owners
enrolled through real WebAuthn ceremonies."""

import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from pgdbm import AsyncDatabaseManager

from aweb_naapp.console import MAX_SESSION, ConsoleSessions, apply_console_migrations
from aweb_naapp.runtime.approvals import ApprovalRevocation, PgApprovalStore
from aweb_naapp.runtime.passkeys import OwnerActKind, Passkeys, RelyingParty
from tests.runtime.approvals.soft_authenticator import SoftAuthenticator
from tests.runtime.approvals.support import AuditOutbox
from tests.runtime.approvals.test_passkeys import Contacts, owner_act

HUMAN = "https://console.example"
OWNER_A = "app.owner.a"
OWNER_B = "app.owner.b"


@dataclass
class Console:
    db: AsyncDatabaseManager
    passkeys: Passkeys
    contacts: Contacts
    allowed: set[str] = field(default_factory=lambda: {OWNER_A, OWNER_B})

    async def admits(self, scope: str) -> bool:
        """The app's predicate: which scopes may log in on this console."""
        return scope in self.allowed

    def sessions(self, ttl: timedelta = MAX_SESSION) -> ConsoleSessions:
        return ConsoleSessions(self.db, passkeys=self.passkeys, scopes=self.admits, ttl=ttl)

    async def enrol(self, scope: str, contact: str | None = None) -> tuple[str, SoftAuthenticator]:
        """Designate the scope's first approver and enrol its passkey."""
        return await self._designate(
            OwnerActKind.DESIGNATE, scope, contact or f"{scope}@example.com"
        )

    async def recover(self, scope: str, contact: str) -> tuple[str, SoftAuthenticator]:
        """Replace the scope's approver after a lockout; the old one is retired at once."""
        return await self._designate(OwnerActKind.RECOVER, scope, contact)

    async def _designate(
        self, kind: OwnerActKind, scope: str, contact: str
    ) -> tuple[str, SoftAuthenticator]:
        await self.passkeys.designate(
            scope=scope,
            contact=contact,
            owner_act=owner_act(kind, contact, scope, str(uuid.uuid4())),
        )
        token = self.contacts.last(contact)
        device = SoftAuthenticator(HUMAN)
        approver = await self.passkeys.complete_enrolment(
            token, device.create(dict(await self.passkeys.enrolment_options(token)))
        )
        return approver.subject, device


async def console_world(test_db_factory, suffix: str) -> Console:
    db = await test_db_factory.create_db(suffix=suffix, schema="app")
    audit = AuditOutbox(db)
    await audit.create()
    store = PgApprovalStore(db)
    await store.migrate()
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=HUMAN, name="Console"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
    )
    await passkeys.migrate()
    await apply_console_migrations(db)
    return Console(db, passkeys, contacts)
