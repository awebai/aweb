"""Owner-only value ingress on the human origin, before fresh confirmation.

Composition shares OwnerConsole's sessions, authoritative installation lookup,
F6 and role directory with the broker. Only the human app mounts this router.
The entered token uses native custody's inert allocator. Reference validation
opens that scoped token and calls the SDK outside authority transactions; only
metadata enters the final, reauthorized staging transaction. The later console
draft/approve/confirm flow owns activation of both candidates.
"""

from datetime import UTC, datetime

from aweb_naapp.console import ConsoleRoute, ConsoleSession
from aweb_naapp.roles import hold_role
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationRefused
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pgdbm import TransactionManager

from aweb_secrets.console import OwnerConsole, _body, _require_json, _text
from aweb_secrets.custody import (
    Custody,
    CustodyUnavailable,
    SealContext,
    ValueInvalid,
    encode_value,
)
from aweb_secrets.custody.onepassword import OnePasswordRead, OnePasswordReference, OnePasswordSDK
from aweb_secrets.custody.store import BACKEND_CREDENTIAL_ID, StagedOnePasswordReference
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from aweb_secrets.secret import SecretInvalid, SecretRecord


class ConsoleValues:
    """Console-only staging capability; it never returns entered bytes."""

    def __init__(self, *, console: OwnerConsole, custody: Custody) -> None:
        self.console = console
        self._custody = custody

    async def _session_open(self, tx: TransactionManager, current: ConsoleSession) -> None:
        # A vault read can outlast a logout, without retiring its LOGIN proof.
        # Read only: no session lock is added after parent/custody locks.
        if current.expires_at <= datetime.now(UTC) or not await tx.fetch_value(
            "SELECT 1 FROM {{tables.console_sessions}} WHERE token_sha256=$1"
            " AND closed_at IS NULL AND expires_at>clock_timestamp()",
            current.token_sha256,
        ):
            raise HTTPException(status_code=401, detail="console_session_required")

    async def _authorize(
        self, tx: TransactionManager, current: ConsoleSession, admitted: AdmittedInstallation
    ) -> None:
        await self.console.fence.check(tx, admitted)
        owner = await self.console.directory.owner_of(tx, current.scope)
        if (
            owner is None
            or owner.team_id != admitted.team_id
            or current.scope
            != owner_scope(admitted.installation_id, admitted.team_id, owner.principal_did)
            or not await hold_role(tx, owner, OWNER_ROLE)
        ):
            raise HTTPException(status_code=403, detail="owner_required")
        await self._session_open(tx, current)
        if not await self.console.passkeys.login_evidence_is_current(
            current.scope, current.subject, current.evidence_ref, tx=tx
        ):
            raise HTTPException(status_code=401, detail="console_session_required")

    async def stage_onepassword_reference(
        self,
        current: ConsoleSession,
        *,
        installation_id: str,
        initial: SecretRecord,
        reference: OnePasswordReference,
        credential_version: int,
    ) -> StagedOnePasswordReference:
        """Observe outside locks, then stage metadata under fresh owner checks.

        Preview permits a token candidate and reference to be confirmed together.
        Neither this preview nor the staged binding grants broker authority.
        """
        if (
            type(credential_version) is not int
            or credential_version <= 0
            or initial.backend != "onepassword"
            or initial.kind != reference.kind
        ):
            raise HTTPException(status_code=400, detail="request_invalid")
        admitted = await self.console.installation(installation_id)
        if admitted.installation_id != installation_id:
            raise HTTPException(status_code=403, detail="owner_required")
        async with self.console.db.transaction() as tx:
            await self._authorize(tx, current, admitted)
        # The authorization transaction has ended before KMS or SDK I/O.
        credential = await self._custody.backend_credential_preview.open(
            SealContext(
                installation_id, admitted.team_id, BACKEND_CREDENTIAL_ID, credential_version
            )
        )
        observed = await OnePasswordSDK().read(reference, credential=credential)
        return await self._stage_observed_reference(
            current, admitted=admitted, initial=initial, observed=observed
        )

    async def _stage_observed_reference(
        self,
        current: ConsoleSession,
        *,
        admitted: AdmittedInstallation,
        initial: SecretRecord,
        observed: OnePasswordRead,
    ) -> StagedOnePasswordReference:
        # observed is internal SDK output, never request JSON. Custody rechecks
        # its exact scoped token, locked actual record kind and immutable shape.
        async with self.console.db.transaction() as tx:
            await self._authorize(tx, current, admitted)
            staged = await self._custody.stage_onepassword_reference(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                secret_id=initial.secret_id,
                observed=observed,
                initial=initial,
            )
            await self.console.fence.check(tx, admitted)
            await self._session_open(tx, current)
        return staged

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
            await self._authorize(tx, current, admitted)
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
            await self._session_open(tx, current)
        return context


def console_values_router(services: ConsoleValues, *, prefix: str = "") -> APIRouter:
    """Mount alongside owner_console_router only on the human-origin app."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)

    @router.post(
        "/installations/{installation_id}/onepassword/references",
        status_code=201,
        dependencies=[Depends(_require_json)],
    )
    async def onepassword_reference(installation_id: str, request: Request) -> dict:
        current = await services.console.sessions.current(request)
        body = await _body(request, {"secret", "reference", "credential_version"})
        try:
            initial = SecretRecord.from_after(body["secret"])
            reference = OnePasswordReference.from_config(initial.kind, body["reference"])
        except (SecretInvalid, CustodyUnavailable):
            raise HTTPException(status_code=400, detail="request_invalid") from None
        try:
            staged = await services.stage_onepassword_reference(
                current,
                installation_id=installation_id,
                initial=initial,
                reference=reference,
                credential_version=body["credential_version"],
            )
        except HTTPException as refused:
            if refused.status_code == 401:
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
        return staged.after

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
