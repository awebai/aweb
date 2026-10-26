"""Service test adapter using real S4, owner rows and prepared B3 authority.

The console seat owns the production caller factory and its mounted proof.
This adapter exercises the service protocol against actual authority stores.
"""

from datetime import UTC, datetime

from aweb_naapp.console import COOKIE_NAME
from aweb_naapp.roles import has_role, hold_role
from fastapi import HTTPException, Request

from aweb_secrets.console import OwnerConsole
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.reconciliation_service import ReconciliationControls
from tests.test_reconciliation_control_audit import control_world


class OwnerFence:
    def __init__(self, console, session, scope):
        self.console, self.session, self.scope = console, session, scope
        self.owner_scope, self.owner_subject = session.scope, session.subject
        self.expires_at = session.expires_at
        self._tx, self._handle = None, None

    async def _session(self, tx, *, lock=False):
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at FROM {{tables.console_sessions}}"
            " WHERE token_sha256=$1" + (" FOR SHARE" if lock else ""),
            self.session.token_sha256,
        )
        if (
            row is None
            or row["closed_at"] is not None
            or (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            != (self.owner_scope, self.owner_subject, self.session.evidence_ref, self.expires_at)
            or self.expires_at <= datetime.now(UTC)
        ):
            raise HTTPException(401, "console_session_required")

    async def prepare(self, tx):
        if self._tx is not None:
            if self._tx is not tx:
                raise HTTPException(401, "console_session_required")
            return self._handle
        await self.console.fence.check(tx, self.scope)
        owner = await self.console.directory.owner_of(tx, self.owner_scope)
        if (
            owner is None
            or owner.team_id != self.scope.team_id
            or owner_scope(self.scope.installation_id, owner.team_id, owner.principal_did)
            != self.owner_scope
            or not await hold_role(tx, owner, OWNER_ROLE)
        ):
            raise HTTPException(403, "owner_required")
        self._owner = owner
        self._handle = await self.console.passkeys.prepare_current_approvers(
            tx, [(self.owner_scope, self.owner_subject)]
        )
        if not await self.console.passkeys.login_evidence_is_current(
            self.owner_scope, self.owner_subject, self.session.evidence_ref, tx=tx
        ):
            raise HTTPException(401, "console_session_required")
        await self._session(tx, lock=True)
        self._tx = tx
        await self.check(tx)
        return self._handle

    async def check(self, tx):
        if self._tx is not tx or not await has_role(tx, self._owner, OWNER_ROLE):
            raise HTTPException(403, "owner_required")
        await self._session(tx)
        await self.console.fence.check(tx, self.scope)
        if self.expires_at <= datetime.now(UTC):
            raise HTTPException(401, "console_session_required")


async def service_world(uses, *, approval_required=False):
    from aweb_naapp.console import apply_console_migrations

    context, view, request, audit, _, _ = await control_world(
        uses, approval_required=approval_required
    )
    w = uses.world
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id=None):
        assert installation_id == w.admitted.installation_id
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=context.arguments["fence"],
        verifier=w.owner.verifier,
        installation=installation,
        credential_audit=w.credential_audit,
    )
    options = await w.passkeys.login_options(request["owner"]["scope"])
    logged = await w.passkeys.verify_login(
        request["owner"]["scope"], w.devices["alice@acme.com"].get(dict(options))
    )
    issued = await console.sessions.open(
        subject=logged.subject, scope=request["owner"]["scope"], evidence_ref=logged.evidence_ref
    )
    session = await console.sessions.current(
        Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/reconciliation",
                "headers": [
                    (b"cookie", (COOKIE_NAME + "=" + issued.token).encode()),
                    (b"x-csrf-token", issued.csrf_token.encode()),
                ],
            }
        )
    )
    service = ReconciliationControls(
        reads=audit._reads,
        audit=audit,
        approvals=uses.approvals,
        passkeys=w.passkeys,
        use_audit=context.arguments["use_audit"],
        broker=None,
        runs=context.service,
        clock=uses.clock,
    )
    return context, view, service, console, session
