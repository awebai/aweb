"""Owner-only value ingress on the human origin, before fresh confirmation.

Composition shares OwnerConsole's sessions, authoritative installation lookup,
F6 and role directory with the broker. Only the human app mounts this router.
The entered token uses native custody's inert allocator; this route neither
activates a credential nor creates a secret, grant or provider client. The
later console draft/approve/confirm flow owns activation.
"""

from datetime import UTC, datetime

from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.roles import hold_role
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from aweb_secrets.console import OwnerConsole, _body, _require_json, _text
from aweb_secrets.custody import (
    Custody,
    CustodyUnavailable,
    SealContext,
    ValueInvalid,
    encode_value,
)
from aweb_secrets.owners import OWNER_ROLE, owner_scope


class ConsoleValues:
    """Console-only staging capability; it never returns entered bytes."""

    def __init__(self, *, console: OwnerConsole, custody: Custody) -> None:
        self.console = console
        self._custody = custody

    async def stage_backend_credential(
        self,
        current: ConsoleSession,
        *,
        installation_id: str,
        value: bytes,
    ) -> SealContext:
        # Authoritative F6 lookup/refresh is outside the write transaction.
        admitted = await self.console.installation(installation_id)
        if admitted.installation_id != installation_id:
            raise HTTPException(status_code=403, detail="owner_required")
        async with self.console.db.transaction() as tx:
            await self.console.fence.check(tx, admitted)
            owner = await self.console.directory.owner_of(tx, current.scope)
            if (
                owner is None
                or owner.team_id != admitted.team_id
                or current.scope
                != owner_scope(installation_id, admitted.team_id, owner.principal_did)
                or not await hold_role(tx, owner, OWNER_ROLE)
            ):
                raise HTTPException(status_code=403, detail="owner_required")
            expired = current.expires_at <= datetime.now(UTC)
            if expired or not await self.console.passkeys.login_evidence_is_current(
                current.scope,
                current.subject,
                current.evidence_ref,
                tx=tx,
            ):
                raise HTTPException(status_code=401, detail="console_session_required")
            # There is no ordinary secret ancestry here: bkc_onepassword has
            # its private parent. B3's approver/credential locks precede that
            # parent and custody; retirement cannot race this ingress.
            context = await self._custody.stage_backend_credential(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                value=value,
            )
            # The parent or key provider may have waited past the F6 deadline.
            # The same fence lock is already held; sample its live clock again.
            await self.console.fence.check(tx, admitted)
            if current.expires_at <= datetime.now(UTC):
                raise HTTPException(status_code=401, detail="console_session_required")
        return context


def console_values_router(services: ConsoleValues, *, prefix: str = "") -> APIRouter:
    """Mount alongside owner_console_router only on the human-origin app."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)

    @router.post(
        "/installations/{installation_id}/backend-credentials/onepassword/versions",
        status_code=201,
        dependencies=[Depends(_require_json)],
    )
    async def backend_credential(installation_id: str, request: Request) -> dict[str, str | int]:
        current = await services.console.sessions.current(request)
        body = await _body(request, {"value"})
        try:
            value = encode_value("bearer", {"value": _text(body, "value")})
            context = await services.stage_backend_credential(
                current,
                installation_id=installation_id,
                value=value,
            )
        except HTTPException as refused:
            if refused.status_code == 401:
                # The write transaction has rolled back. Preserve S4's normal
                # close/clearing-cookie behavior for a session lost mid-request.
                await services.console.sessions.close(current)
                response = Response()
                services.console.sessions.clear_cookie(response)
                raise HTTPException(
                    status_code=401,
                    detail="console_session_required",
                    headers={"Set-Cookie": response.headers["set-cookie"]},
                ) from None
            raise
        except ValueInvalid:
            raise HTTPException(status_code=400, detail="request_invalid") from None
        except InstallationRefused as refused:
            raise HTTPException(status_code=refused.status, detail=refused.code) from None
        except LookupError:
            raise HTTPException(status_code=403, detail="owner_required") from None
        except CustodyUnavailable:
            raise HTTPException(status_code=503, detail="custody_unavailable") from None
        return {
            "v": 1,
            "backend": "onepassword",
            "credential_id": context.secret_id,
            "version": context.version,
        }

    return router
