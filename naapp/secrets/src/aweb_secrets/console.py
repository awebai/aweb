"""Human console ceremonies and scoped owner/approver sessions, using S4 and B3.

The app composes one OwnerConsole with the same database, passkeys and fence
used by its broker. Its installation lookup reads authoritative F6 records;
the owner-act team field is only a G1 lookup hint, never team authority. Routes belong only
on split_origins' human app. S4 rechecks the current owner role or approver
record on every session request; owner-only actions separately require the
owner role.

No request body is echoed in validation errors. Bootstrap consumes a K2 act in
the fenced transaction; registration and login use B3's distinct ceremonies.
"""

import base64
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, Annotated, Any, Protocol

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleRoute,
    ConsoleSession,
    ConsoleSessions,
    KeyBoundConsoleSession,
    LoginLimiter,
    console_assets_router,
    console_login_router,
    credential_router,
    session_is_current,
)
from aweb_naapp.console import exact_body as _body
from aweb_naapp.console import require_json as _require_json
from aweb_naapp.console import text_field as _text
from aweb_naapp.console.handoff_authority import PreparedSessionTarget
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.roles import PrincipalKey
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.passkeys import (
    Designation,
    Passkeys,
    PreparedCurrentApprovers,
)
from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets.change import ChangeRefused
from aweb_secrets.owners import (
    OwnerDirectory,
    OwnerRequired,
    owner_binding,
    owner_scope,
)
from aweb_secrets.principal import is_principal

if TYPE_CHECKING:
    from aweb_naapp.runtime.credential_audit import CredentialAudit


class InstallationLookup(Protocol):
    async def __call__(self, installation_id: str, *, team_id: str) -> AdmittedInstallation:
        """Refresh authoritative G1/F6 for team_id: the team a console session's
        scope was enrolled under, or an untrusted hint before any session exists.
        An id that team does not hold raises LookupError."""
        ...


class KeyBoundPreparation(Protocol):
    async def __call__(
        self,
        tx: TransactionManager,
        current: KeyBoundConsoleSession,
        *,
        approver_pairs: Sequence[tuple[str, str]],
    ) -> PreparedSessionTarget: ...


class OwnerConsole:
    """Shared services of the owner console; the app owns their lifecycle.

    Mount with owner_console_router. Apply S4 console migrations before serving.
    The installation lookup refreshes F6 outside any write transaction and must
    return its authoritative installation identity, or refuse an unavailable one.
    The retired owner binding route receives only an untrusted lookup hint and
    refuses its effect. Other calls name the team of the session or record they
    act for, so another team's installation id is never resolved.
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
        credential_audit: "CredentialAudit",
        client_address_header: str | None = None,
        limiter: LoginLimiter | None = None,
        key_bound: Callable[[Request], Awaitable[ConsoleSession]] | None = None,
        prepare_key_bound: KeyBoundPreparation | None = None,
    ) -> None:
        self.db = db
        self.passkeys = passkeys
        self.directory = directory
        self.fence = fence
        self.verifier = verifier
        self.installation = installation
        self.credential_audit = credential_audit
        self._prepare_key_bound = prepare_key_bound
        self.sessions = ConsoleSessions(
            db, passkeys=passkeys, scopes=self.admits_scope, key_bound=key_bound
        )
        self.limiter = limiter or LoginLimiter(
            db,
            client_identity=ClientIdentity(trusted_header=client_address_header),
            limit=12,
            window=timedelta(minutes=1),
        )

    async def prepare_session(
        self,
        tx: TransactionManager,
        current: ConsoleSession,
        *,
        approver_pairs: Sequence[tuple[str, str]],
    ) -> PreparedCurrentApprovers | None:
        """Prepare the complete signed authority after app locks, before B2/S3.

        Cookie callers keep their existing B3 preparation. The trusted callback
        is the same factory that verified this request; it retains the original
        app handle and deadline. Return its canonical B3 union for caller reuse.
        """
        if not isinstance(current, KeyBoundConsoleSession):
            return None
        if self._prepare_key_bound is None:
            raise HTTPException(401, "console_session_required")
        held = await self._prepare_key_bound(tx, current, approver_pairs=approver_pairs)
        return held.approvers

    @staticmethod
    async def check_key_bound(tx: TransactionManager, current: ConsoleSession) -> None:
        """Final local check after the last protected read; never prepare again."""
        if isinstance(current, KeyBoundConsoleSession) and not await session_is_current(
            tx, current, hold=False
        ):
            raise HTTPException(401, "console_session_required")

    async def admits_scope(self, scope: str) -> bool:
        # B3's login alone does not check application roles. The same predicate
        # is used by login AND by every subsequent S4 session request.
        if await self.directory.owner_of(self.db, scope) is not None:
            return True
        # S4 separately verifies B3's current holder and login credential.
        # A scope grants no installation-wide action authority: S14 rechecks
        # the record's live coverage under the action's installation fence.
        return bool(
            await self.db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM {{tables.approvers}} WHERE scope=$1)",
                scope,
            )
        )

    async def session_installation(
        self, current: ConsoleSession, installation_id: str
    ) -> AdmittedInstallation:
        """The installation as the session's own team holds it. The team is the
        one the session's scope was enrolled under, as an owner or an approver;
        an id that team does not hold raises LookupError, as an unknown id does."""
        record = await owner_binding(self.db, current.scope)
        team_id = (
            record["team_id"]
            if record is not None
            else await self.db.fetch_value(
                "SELECT team_id FROM {{tables.approvers}} WHERE scope=$1", current.scope
            )
        )
        if team_id is None:
            raise LookupError("installation not found")
        return await self.installation(installation_id, team_id=team_id)

    async def apply_owner_act(
        self,
        *,
        admitted: AdmittedInstallation,
        signing: bytes,
        signature: str,
        principal: PrincipalKey,
        contact: str,
    ) -> Designation:
        """Legacy owner bindings and recovery are retired for every scope."""
        raise OwnerRequired("owner_required")


def owner_console_router(services: OwnerConsole, *, prefix: str = "") -> APIRouter:
    """Mount only on the human-origin application. Never mount on the agent API."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)
    router.include_router(console_assets_router())
    router.include_router(
        console_login_router(sessions=services.sessions, limiter=services.limiter)
    )
    router.include_router(
        credential_router(passkeys=services.passkeys, recorder=services.credential_audit)
    )

    @router.get("/session")
    async def session(
        current: Annotated[ConsoleSession, Depends(services.sessions.current)],
    ) -> dict[str, Any]:
        return {"scope": current.scope, "expires_at": current.expires_at.isoformat()}

    @router.post(
        "/installations/{installation_id}/owner-acts", dependencies=[Depends(_require_json)]
    )
    async def owner_act(installation_id: str, request: Request) -> dict[str, str]:
        body = await _body(request, {"signing", "signature", "team_id", "principal", "contact"})
        team_id = _text(body, "team_id")
        principal_did = _text(body, "principal")
        if not is_principal(principal_did):
            raise HTTPException(status_code=403, detail="owner_required")
        try:
            admitted = await services.installation(installation_id, team_id=team_id)
        except InstallationRefused as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None
        except LookupError:
            raise HTTPException(status_code=403, detail="owner_required") from None
        if admitted.installation_id != installation_id or team_id != admitted.team_id:
            raise HTTPException(status_code=403, detail="owner_required")
        principal = PrincipalKey(team_id=admitted.team_id, principal_did=principal_did)
        contact = _text(body, "contact")
        scope = owner_scope(installation_id, admitted.team_id, principal_did)
        try:
            designation = await services.apply_owner_act(
                admitted=admitted,
                signing=base64.b64decode(_text(body, "signing"), validate=True),
                signature=_text(body, "signature"),
                principal=principal,
                contact=contact,
            )
        except InstallationRefused as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None
        except ChangeRefused as refused:
            raise HTTPException(status_code=403, detail=refused.code) from None
        except GovernanceUnavailable as refused:
            raise HTTPException(503, refused.code) from None
        except Refused as refused:
            raise HTTPException(503, refused.code) from None
        except (ValueError, OwnerRequired):
            raise HTTPException(status_code=403, detail="owner_required") from None
        await services.passkeys.deliver(designation)
        return {"scope": scope, "effective_at": designation.effective_at.isoformat()}

    return router
