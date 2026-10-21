"""Owner-only HTTP ceremonies on the console origin, using S4 sessions and B3.

The app composes one OwnerConsole with the same database, passkeys and fence
used by its broker. Its installation lookup reads authoritative F6 records;
request team fields never establish the installation's team. Routes belong only
on split_origins' human app. S4 rechecks the owner role on every session request.

No request body is echoed in validation errors. Bootstrap consumes a K2 act in
the fenced transaction; registration and login use B3's distinct ceremonies.
"""

import base64
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Annotated, Any

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleRoute,
    ConsoleSession,
    ConsoleSessions,
    LoginLimiter,
    console_login_router,
)
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.roles import PrincipalKey, assign, hold_role
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.passkeys import (
    ContactChangeRefused,
    DesignationRefused,
    EnrolmentRefused,
    Passkeys,
    contact_sha256,
)
from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb_secrets.change import ChangeRefused
from aweb_secrets.change_policy import keep_four_eyes_owners
from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory, owner_scope, record_owner
from aweb_secrets.principal import is_principal

InstallationLookup = Callable[[str], Awaitable[AdmittedInstallation]]


async def _body(request: Request, fields: set[str]) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="request_invalid") from None
    if not isinstance(body, dict) or set(body) != fields:
        raise HTTPException(status_code=400, detail="request_invalid")
    return body


def _text(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=400, detail="request_invalid")
    return value


class OwnerConsole:
    """Shared services of the owner console; the app owns their lifecycle.

    Mount with owner_console_router. Apply S4 console migrations before serving.
    The installation lookup refreshes F6 outside any write transaction and must
    return its stored installation identity, or refuse an unavailable one.
    """

    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        passkeys: Passkeys,
        directory: OwnerDirectory,
        fence: InstallationFence,
        verifier: OwnerActVerifier,
        installation: InstallationLookup,
        limiter: LoginLimiter | None = None,
    ) -> None:
        self.db = db
        self.passkeys = passkeys
        self.directory = directory
        self.fence = fence
        self.verifier = verifier
        self.installation = installation
        self.sessions = ConsoleSessions(db, passkeys=passkeys, scopes=self.admits_scope)
        self.limiter = limiter or LoginLimiter(
            db, client_identity=ClientIdentity(), limit=12, window=timedelta(minutes=1)
        )

    async def admits_scope(self, scope: str) -> bool:
        # B3's login alone does not check application roles. The same predicate
        # is used by login AND by every subsequent S4 session request.
        return await self.directory.owner_of(self.db, scope) is not None


def owner_console_router(services: OwnerConsole, *, prefix: str = "") -> APIRouter:
    """Mount only on the human-origin application. Never mount on the agent API."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)
    router.include_router(
        console_login_router(sessions=services.sessions, limiter=services.limiter)
    )

    @router.get("/session")
    async def session(
        current: Annotated[ConsoleSession, Depends(services.sessions.current)],
    ) -> dict[str, Any]:
        return {"scope": current.scope, "expires_at": current.expires_at.isoformat()}

    @router.post("/installations/{installation_id}/owner-acts")
    async def owner_act(installation_id: str, request: Request) -> dict[str, str]:
        body = await _body(request, {"signing", "signature", "team_id", "principal", "contact"})
        principal_did = _text(body, "principal")
        if not is_principal(principal_did):
            raise HTTPException(status_code=403, detail="owner_required")
        try:
            admitted = await services.installation(installation_id)
        except (LookupError, InstallationRefused):
            raise HTTPException(status_code=403, detail="owner_required") from None
        if admitted.installation_id != installation_id or body["team_id"] != admitted.team_id:
            raise HTTPException(status_code=403, detail="owner_required")
        principal = PrincipalKey(team_id=admitted.team_id, principal_did=principal_did)
        contact = _text(body, "contact")
        scope = owner_scope(installation_id, admitted.team_id, principal_did)
        expected = {
            "app_id": admitted.app_id,
            "installation_id": installation_id,
            "role": scope,
            "contact_sha256": contact_sha256(contact),
        }
        try:
            signing = base64.b64decode(_text(body, "signing"), validate=True)
            prepared = await services.verifier.prepare(
                signing, _text(body, "signature"), team_id=admitted.team_id
            )
            async with services.db.transaction() as tx:
                await services.fence.check(tx, admitted)
                act = await services.verifier.consume_in(tx, prepared, expected_subject=expected)
                recovering = prepared.act_name == "app-credential.recover"
                # The root act can grant this role; hold it before B3 locks
                # approval candidates, so withdrawal serializes with bootstrap.
                await assign(tx, principal, OWNER_ROLE)
                if not await hold_role(tx, principal, OWNER_ROLE):
                    raise HTTPException(status_code=403, detail="owner_required")
                await record_owner(tx, installation_id=installation_id, principal=principal)
                designation = await services.passkeys.designate(
                    tx, scope=scope, contact=contact, evidence=act
                )
                if recovering:
                    await keep_four_eyes_owners(
                        tx,
                        installation_id=installation_id,
                        team_id=admitted.team_id,
                        directory=services.directory,
                        excluding=principal,
                    )
        except (ValueError, Refused, DesignationRefused, InstallationRefused, ChangeRefused):
            raise HTTPException(status_code=403, detail="owner_required") from None
        await services.passkeys.deliver(designation)
        return {"scope": scope, "effective_at": designation.effective_at.isoformat()}

    @router.post("/enrolment/options")
    async def enrolment_options(request: Request) -> dict[str, Any]:
        body = await _body(request, {"link_token"})
        try:
            return dict(await services.passkeys.enrolment_options(_text(body, "link_token")))
        except EnrolmentRefused:
            raise HTTPException(status_code=403, detail="enrolment_refused") from None

    @router.post("/enrolment")
    async def enrolment(request: Request) -> dict[str, str]:
        body = await _body(request, {"link_token", "credential"})
        if not isinstance(body["credential"], dict):
            raise HTTPException(status_code=400, detail="request_invalid")
        try:
            approver = await services.passkeys.complete_enrolment(
                _text(body, "link_token"), body["credential"]
            )
        except EnrolmentRefused:
            raise HTTPException(status_code=403, detail="enrolment_refused") from None
        return {"scope": approver.scope}

    @router.post("/contact-proof")
    async def contact_proof(request: Request) -> dict[str, str]:
        body = await _body(request, {"proof_token"})
        try:
            effective_at = await services.passkeys.prove_contact(_text(body, "proof_token"))
        except ContactChangeRefused:
            raise HTTPException(status_code=403, detail="contact_proof_refused") from None
        return {"effective_at": effective_at.isoformat()}

    return router
