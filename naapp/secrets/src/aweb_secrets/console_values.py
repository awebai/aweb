"""Owner-only value ingress on the human origin, before fresh confirmation.

Composition shares OwnerConsole's sessions, authoritative installation lookup,
F6 and role directory with the broker. Only the human app mounts this router.
Entered native values and vault tokens use native custody's inert allocator. Reference validation
opens that scoped token and calls the SDK outside authority transactions; only
metadata enters the final, reauthorized staging transaction. The later console
draft/approve/confirm flow owns activation of both candidates.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus

from aweb_naapp.console import ConsoleRoute, ConsoleSession, KeyBoundConsoleSession
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
from aweb_secrets.owners import hold_owner as hold_owner_holding
from aweb_secrets.owners import owner_scope
from aweb_secrets.secret import SecretBackend, SecretInvalid, SecretKind, SecretRecord


class ValueStagingCode(StrEnum):
    INVALID_REQUEST = "request_invalid"
    JSON_REQUIRED = "json_required"
    CSRF_REQUIRED = "csrf_token_required"
    OWNER_REQUIRED = "owner_required"
    SESSION_REQUIRED = "console_session_required"
    CUSTODY_UNAVAILABLE = "custody_unavailable"


_NATIVE_REFUSALS = {
    ValueStagingCode.INVALID_REQUEST: "Check the secret details and value fields, then submit again.",
    ValueStagingCode.JSON_REQUIRED: "Use the console form to submit the value as JSON.",
    ValueStagingCode.OWNER_REQUIRED: "Sign in with the current installation owner's passkey to store a value.",
    ValueStagingCode.CUSTODY_UNAVAILABLE: "The value could not be sealed. Ask the operator to check custody readiness, then enter it again.",
}


@dataclass(frozen=True, kw_only=True)
class StagedNativeValue:
    context: SealContext
    created_at: datetime


@asynccontextmanager
async def native_value_refusals() -> AsyncIterator[None]:
    """Render value-free console failures as actions (secrets.md §6.1)."""
    try:
        yield
    except HTTPException as refused:
        # The shared shell owns session recovery and recognises this CSRF code.
        if refused.status_code == HTTPStatus.UNAUTHORIZED or (
            refused.status_code == HTTPStatus.FORBIDDEN
            and refused.detail == ValueStagingCode.CSRF_REQUIRED
        ):
            raise
        try:
            code = ValueStagingCode(refused.detail)
        except ValueError:
            message = (
                f"{refused.detail.rstrip('.')}. Check the value fields and try again."
                if refused.status_code == HTTPStatus.BAD_REQUEST and isinstance(refused.detail, str)
                else "Check that the installation is active, sign in as its owner, and try again."
            )
        else:
            message = _NATIVE_REFUSALS[code]
        raise HTTPException(refused.status_code, message, headers=refused.headers) from None


class ConsoleValues:
    """Console-only staging capability; it never returns entered bytes."""

    def __init__(self, *, console: OwnerConsole, custody: Custody) -> None:
        self.console = console
        self._custody = custody

    async def stage_native_value(
        self,
        current: ConsoleSession,
        *,
        installation_id: str,
        initial: SecretRecord,
        value: dict[str, str],
    ) -> StagedNativeValue:
        """§6.1 (secrets.md:596-606): owner-only ingress, inert until confirmation."""
        if initial.backend != SecretBackend.NATIVE:
            raise HTTPException(
                HTTPStatus.BAD_REQUEST, "Choose a native secret before entering its value"
            )
        admitted = await self.console.session_installation(current, installation_id)
        if admitted.installation_id != installation_id:
            raise HTTPException(HTTPStatus.FORBIDDEN, ValueStagingCode.OWNER_REQUIRED)
        async with self.console.db.transaction() as tx:
            await self._authorize(tx, current, admitted)
            version = await self._custody.sealer.ingest(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                secret_id=initial.secret_id,
                value=encode_value(initial.kind, value),
                initial=initial,
            )
            created_at = await tx.fetch_value(
                "SELECT created_at FROM {{tables.sealed_versions}}"
                " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3 AND version=$4",
                admitted.installation_id,
                admitted.team_id,
                initial.secret_id,
                version,
            )
            if not isinstance(created_at, datetime):
                raise CustodyUnavailable("staged version metadata is unavailable")
            # The allocator/KMS may wait; consume no stale authority after it.
            await self.console.fence.check(tx, admitted)
            await self._session_open(tx, current)
        return StagedNativeValue(
            context=SealContext(
                admitted.installation_id, admitted.team_id, initial.secret_id, version
            ),
            created_at=created_at,
        )

    async def _session_open(self, tx: TransactionManager, current: ConsoleSession) -> None:
        if isinstance(current, KeyBoundConsoleSession):
            await self.console.check_key_bound(tx, current)
            return
        # A vault read can outlast a logout, without retiring its LOGIN proof.
        # Read only: no session lock is added after parent/custody locks.
        if current.expires_at <= datetime.now(UTC) or not await tx.fetch_value(
            "SELECT 1 FROM {{tables.console_sessions}} WHERE token_sha256=$1"
            " AND closed_at IS NULL AND expires_at>clock_timestamp()",
            current.token_sha256,
        ):
            raise HTTPException(status_code=401, detail=ValueStagingCode.SESSION_REQUIRED)

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
            or not await hold_owner_holding(tx, owner, installation_id=admitted.installation_id)
        ):
            raise HTTPException(status_code=403, detail=ValueStagingCode.OWNER_REQUIRED)
        await self.console.prepare_session(
            tx, current, approver_pairs=[(current.scope, current.subject)]
        )
        if not await self.console.passkeys.login_evidence_is_current(
            current.scope,
            current.subject,
            current.evidence_ref,
            tx=tx,
            hold=not isinstance(current, KeyBoundConsoleSession),
        ):
            raise HTTPException(status_code=401, detail=ValueStagingCode.SESSION_REQUIRED)
        await self._session_open(tx, current)

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
            or initial.backend != SecretBackend.ONEPASSWORD
            or initial.kind != reference.kind
        ):
            raise HTTPException(status_code=400, detail=ValueStagingCode.INVALID_REQUEST)
        admitted = await self.console.session_installation(current, installation_id)
        if admitted.installation_id != installation_id:
            raise HTTPException(status_code=403, detail=ValueStagingCode.OWNER_REQUIRED)
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
        admitted = await self.console.session_installation(current, installation_id)
        if admitted.installation_id != installation_id:
            raise HTTPException(status_code=403, detail=ValueStagingCode.OWNER_REQUIRED)
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


@asynccontextmanager
async def _value_staging_errors(
    console: OwnerConsole, *, current: ConsoleSession
) -> AsyncIterator[None]:
    """Preserve session cookie retirement after a rolled-back staging write."""
    try:
        yield
    except HTTPException as refused:
        if refused.status_code == HTTPStatus.UNAUTHORIZED:
            await console.sessions.close(current)
            response = Response()
            console.sessions.clear_cookie(response)
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail=ValueStagingCode.SESSION_REQUIRED,
                headers={"Set-Cookie": response.headers["set-cookie"]},
            ) from None
        raise
    except ValueInvalid as refused:
        # The shared codec owns kind validation and never includes entered bytes.
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(refused)) from None
    except InstallationRefused as refused:
        raise HTTPException(status_code=refused.status, detail=refused.code) from None
    except LookupError:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail=ValueStagingCode.OWNER_REQUIRED
        ) from None
    except CustodyUnavailable:
        raise HTTPException(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=ValueStagingCode.CUSTODY_UNAVAILABLE
        ) from None


def _onepassword_reference_router(services: ConsoleValues) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.post(
        "/installations/{installation_id}/onepassword/references",
        status_code=HTTPStatus.CREATED,
        dependencies=[Depends(_require_json)],
    )
    async def onepassword_reference(installation_id: str, request: Request) -> dict:
        current = await services.console.sessions.current(request)
        body = await _body(request, {"secret", "reference", "credential_version"})
        try:
            initial = SecretRecord.from_after(body["secret"])
            reference = OnePasswordReference.from_config(initial.kind, body["reference"])
        except (SecretInvalid, CustodyUnavailable):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST, detail=ValueStagingCode.INVALID_REQUEST
            ) from None
        async with _value_staging_errors(services.console, current=current):
            staged = await services.stage_onepassword_reference(
                current,
                installation_id=installation_id,
                initial=initial,
                reference=reference,
                credential_version=body["credential_version"],
            )
        return staged.after

    return router


def _backend_credential_router(services: ConsoleValues) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.post(
        "/installations/{installation_id}/backend-credentials/onepassword/versions",
        status_code=HTTPStatus.CREATED,
        dependencies=[Depends(_require_json)],
    )
    async def backend_credential(installation_id: str, request: Request) -> dict[str, str | int]:
        current = await services.console.sessions.current(request)
        body = await _body(request, {"value"})
        async with _value_staging_errors(services.console, current=current):
            value = encode_value(SecretKind.BEARER, {"value": _text(body, "value")})
            context = await services.stage_backend_credential(
                current,
                installation_id=installation_id,
                value=value,
            )
        return {
            "v": 1,
            "backend": SecretBackend.ONEPASSWORD,
            "credential_id": context.secret_id,
            "version": context.version,
        }

    return router


def console_values_router(services: ConsoleValues, *, prefix: str = "") -> APIRouter:
    """Mount owner-only value stages together on the human-origin app."""
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)
    router.include_router(_onepassword_reference_router(services))
    router.include_router(_backend_credential_router(services))
    router.include_router(_native_value_router(services))
    return router


async def _require_native_json(request: Request) -> None:
    async with native_value_refusals():
        await _require_json(request)


def _native_value_router(services: ConsoleValues) -> APIRouter:
    router = APIRouter(route_class=ConsoleRoute)

    @router.post(
        "/installations/{installation_id}/native/versions",
        status_code=HTTPStatus.CREATED,
        dependencies=[Depends(_require_native_json)],
    )
    async def stage_value(installation_id: str, request: Request) -> dict[str, str | int]:
        async with native_value_refusals():
            current = await services.console.sessions.current(request)
            body = await _body(request, {"secret", "value"})
            try:
                initial = SecretRecord.from_after(body["secret"])
            except SecretInvalid:
                raise HTTPException(
                    HTTPStatus.BAD_REQUEST, ValueStagingCode.INVALID_REQUEST
                ) from None
            async with _value_staging_errors(services.console, current=current):
                staged = await services.stage_native_value(
                    current,
                    installation_id=installation_id,
                    initial=initial,
                    value=body["value"],
                )
        return {
            "secret_id": staged.context.secret_id,
            "version": staged.context.version,
            "created_at": staged.created_at.isoformat(),
        }

    return router
