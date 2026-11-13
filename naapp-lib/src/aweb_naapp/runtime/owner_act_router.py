"""The anonymous, shared human-role owner-act delivery route.

Stateless checks precede controller authentication; installation and app state
are read only afterwards. The router owns the single nonce/effect transaction.
Apps supply the existing OwnerActEffect, never another transport or parser.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from awid.team_certificate import MAX_HEADER_BYTES, TeamCertificateError, decode_team_certificate
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pgdbm import AsyncDatabaseManager

from aweb_naapp import ratelimit
from aweb_naapp.console import CONSOLE_HEADERS, ClientIdentity
from aweb_naapp.email import EmailNotSent
from aweb_naapp.hooks.owner_act import (
    HUMAN_ROLE_ACTS,
    PREFIX,
    HumanCredential,
    Refused,
    _check_fields,
    _require_valid_time,
)
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import parse_canonical_object
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.installation import InstallationRefused
from aweb_naapp.runtime.origins import _carries_team_auth, _host, _origin_hosts
from aweb_naapp.runtime.owner_act_delivery import (
    OwnerActDelivery,
    OwnerActDeliveryRefused,
    OwnerActEffect,
)
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp.runtime.passkeys.proof import is_public_cose_key

__all__ = ["OWNER_ACT_PATH", "OwnerActLimiter", "mount_owner_act_routes"]

OWNER_ACT_PATH = "/.well-known/aweb-owner-act"
MAX_BODY_BYTES = 1 << 20
_BODY_FIELDS = frozenset({"signing", "signature", "credential", "notice_contact", "certificate"})
_EMAIL_FAILURE_CODES = frozenset(
    {
        "tls_unavailable",
        "auth_failed",
        "recipient_refused",
        "message_refused",
        "connection_failed",
        "timeout",
    }
)
logger = logging.getLogger(__name__)


def _refuse(status: int = 403, code: str = "owner_required") -> HTTPException:
    return HTTPException(status_code=status, detail=code, headers=CONSOLE_HEADERS)


@dataclass(frozen=True)
class OwnerActLimiter:
    """A durable client-address budget, independent of caller-supplied act fields.

    The app applies apply_ratelimit_migrations alongside its other shared stores.
    No database is needed until the first request, after runtime startup.
    """

    client_identity: ClientIdentity
    limit: int
    window: timedelta

    def __post_init__(self) -> None:
        if (
            type(self.limit) is not int
            or self.limit <= 0
            or self.window <= timedelta(0)
            or self.window.total_seconds() != int(self.window.total_seconds())
        ):
            raise ValueError("owner-act limits need positive capacity and whole window seconds")

    async def admit(self, request: Request, db: AsyncDatabaseManager) -> None:
        now = datetime.now(UTC)
        charge = ratelimit.Charge(
            bucket="owner_act.delivery.client",
            key=hashlib.sha256(self.client_identity.of(request).encode()).hexdigest(),
            capacity=self.limit,
            window_s=int(self.window.total_seconds()),
        )
        # A malformed or refused act still spends its own client budget.
        async with db.transaction() as tx:
            decision = await ratelimit.take(tx, [charge], now=now)
        await ratelimit.sweep(db, now=now, limit=16)
        if decision.throttled:
            raise HTTPException(
                429,
                "owner_act_rate_limited",
                headers={**CONSOLE_HEADERS, "Retry-After": str(decision.retry_after_s)},
            )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate field")
        value[name] = item
    return value


def _base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64 string required")
    decoded = base64.b64decode(value, validate=True)
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("standard padded base64 required")
    return decoded


async def _delivery(request: Request, declaration: Any) -> OwnerActDelivery:
    """Stage 1. No registry, installation, holding or nonce read occurs here."""
    content_types = request.headers.getlist("content-type")
    if (
        len(content_types) != 1
        or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
    ):
        raise _refuse(415, "json_required")
    body_bytes = bytearray()
    async for chunk in request.stream():
        if len(body_bytes) + len(chunk) > MAX_BODY_BYTES:
            raise _refuse(400, "request_invalid")
        body_bytes.extend(chunk)
    try:
        body = json.loads(body_bytes, object_pairs_hook=_object)
        if not isinstance(body, dict) or set(body) - _BODY_FIELDS:
            raise ValueError("unexpected body fields")
        signing = _base64(body.get("signing"))
        signature = body.get("signature")
        if not isinstance(signature, str):
            raise ValueError("signature required")
        if not signing.startswith(PREFIX):
            raise ValueError("no owner act")
        fields = json.loads(signing[len(PREFIX) :], object_pairs_hook=_object)
        subject = fields.get("subject") if isinstance(fields, dict) else None
        if (
            not isinstance(fields, dict)
            or not isinstance(fields.get("act"), str)
            or not isinstance(subject, dict)
            or not isinstance(subject.get("installation_id"), str)
            or not isinstance(subject.get("role"), str)
        ):
            raise ValueError("missing lookup keys")
        credential = HumanCredential.parse(body["credential"]) if "credential" in body else None
        notice = body.get("notice_contact")
        if "notice_contact" in body and (not isinstance(notice, str) or not notice):
            raise ValueError("nonempty notice required")
        if notice is not None:
            notice.encode("utf-8")
    except (ValueError, binascii.Error, UnicodeError, RecursionError):
        raise _refuse(400, "request_invalid") from None
    try:
        checked = _check_fields(parse_canonical_object(signing[len(PREFIX) :]))
        if checked.audience != declaration["origin"]:
            raise _refuse()
        role = next(
            (role for role in declaration["roles"] if role["name"] == checked.subject["role"]), None
        )
        if role is None or checked.act not in role["acts"]:
            raise _refuse()
        needs_credential = checked.act != "human-role.revoke"
        if (
            ("credential" in body) != needs_credential
            or ("notice_contact" in body) != (needs_credential and role["notice_contact"])
            or (not needs_credential and "certificate" in body)
        ):
            raise _refuse(400, "request_invalid")
        _require_valid_time(checked, datetime.now(UTC))
    except Refused:
        raise _refuse() from None
    # Certificate presence/validity is stage 3, after signature authentication.
    # Preserve the exact signed JSON bytes, never a reconstructed certificate.
    certificate = None
    if needs_credential:
        value = body.get("certificate")
        if isinstance(value, str) and value and len(value) <= MAX_HEADER_BYTES:
            try:
                decode_team_certificate(value)
                certificate = base64.b64decode(value, validate=True)
            except (TeamCertificateError, ValueError):
                pass
    return OwnerActDelivery(
        signing=signing,
        signature=signature,
        act=checked.act,
        team_id=checked.team_id,
        subject=checked.subject,
        credential=credential,
        notice_contact=notice,
        certificate=certificate,
    )


def mount_owner_act_routes(
    app: FastAPI | APIRouter,
    *,
    runtime: NaappRuntime,
    effect: OwnerActEffect,
    verifier: OwnerActVerifier,
    limiter: OwnerActLimiter,
    allow_security_key: bool = False,
) -> None:
    """Mount once on the declared human app/router, after effect composition.

    The dedicated verifier names this app's ID as scope, its human origin as
    audience, and HUMAN_ROLE_ACTS as vocabulary. It shares the app's nonce table
    with its other owner-act verifiers. Effect preparation is network-capable;
    apply and final original-proof checks run only in the router's transaction.
    """
    declaration = runtime.manifest.owner_acts
    if (
        declaration is None
        or verifier.audience != declaration["origin"]
        or verifier.scope != runtime.manifest.app_id
        or set(verifier.acts) != set(HUMAN_ROLE_ACTS)
    ):
        raise ValueError("owner-act delivery requires the declared human-role verifier")
    origin = declaration["origin"]
    human_hosts = _origin_hosts(origin)

    @app.post(OWNER_ACT_PATH)
    async def deliver(request: Request) -> JSONResponse:
        await limiter.admit(request, runtime.db())
        if (
            _host(request.scope) not in human_hosts
            or _carries_team_auth(request.scope["headers"])
            or "cookie" in request.headers
            or "x-aw-console-session" in request.headers
        ):
            raise _refuse()
        delivery = await _delivery(request, declaration)
        # Stage 2. Only the caller-selected team affects a registry failure.
        try:
            prepared_act = await verifier.prepare(
                delivery.signing, delivery.signature, team_id=delivery.team_id
            )
        except Refused:
            raise _refuse() from None
        except Exception:
            raise _refuse(503, "team_key_unavailable") from None
        try:
            # Stage 3. Admission precedes app rows, H2 and all effect locks.
            permit = await runtime.installation_fence().permit(delivery.team_id)
            if (
                permit.admitted.installation_id != delivery.subject["installation_id"]
                or permit.status.manifest_version != 3
            ):
                raise _refuse()
            if delivery.credential is not None:
                rp_id = delivery.credential.rp_id
                if not is_public_cose_key(delivery.credential.public_key) or (
                    rp_id != urlsplit(origin).hostname
                    and not (allow_security_key and rp_id == "aweb:")
                ):
                    raise _refuse()
                if delivery.credential.sha256 != delivery.subject["credential_sha256"] or (
                    delivery.notice_contact is not None
                    and contact_sha256(delivery.notice_contact)
                    != delivery.subject.get("notice_contact_sha256")
                ):
                    raise _refuse()
            # Reconciliation precedes effect preparation: an earlier revoke
            # removed the holding that a fresh effect would require. The same
            # current installation and original act proof still gate this read.
            replay_fence = permit.store.for_installation(permit.admitted)
            async with runtime.db().transaction() as tx:
                await replay_fence.prepare(tx)
                await replay_fence.check(tx, None)
                if await verifier.applied_in(tx, prepared_act):
                    await replay_fence.check(tx, None)
                    prepared_act.require_fresh()
                    return JSONResponse(
                        {"detail": "applied_earlier"}, status_code=409, headers=CONSOLE_HEADERS
                    )
            prepared_effect = await effect.prepare(installation=permit.admitted, delivery=delivery)
            fence = permit.store.for_installation(permit.admitted)
            async with runtime.db().transaction() as tx:
                await fence.prepare(tx)
                await fence.check(tx, None)
                act = await verifier.consume_in(
                    tx, prepared_act, expected_subject=prepared_effect.expected_subject
                )
                result = await prepared_effect.apply(tx, installation=permit.admitted, act=act)
                # This is the final await: no refresh or lock upgrade follows it.
                await fence.check(tx, None)
                prepared_effect.require_fresh()
                prepared_act.require_fresh()
        except Refused:
            raise _refuse() from None
        except OwnerActDeliveryRefused as exc:
            raise _refuse(
                503 if exc.code == "principal_status_unavailable" else 403, exc.code
            ) from None
        except InstallationRefused as exc:
            raise _refuse(exc.status, exc.code) from None
        except GovernanceUnavailable:
            raise _refuse(503, "release_context_unavailable") from None
        # Failure after COMMIT cannot truthfully report a rolled-back effect.
        try:
            await prepared_effect.after_commit(result)
        except Exception as exc:
            code = (
                exc.code
                if isinstance(exc, EmailNotSent) and exc.code in _EMAIL_FAILURE_CODES
                else "notice_failed"
            )
            logger.warning(
                "Owner-act notice failed: act=%s role=%s installation=%s code=%s",
                result.act,
                result.role,
                permit.admitted.installation_id,
                code,
                extra={
                    "act": result.act,
                    "role": result.role,
                    "installation_id": permit.admitted.installation_id,
                    "failure_code": code,
                },
            )
        return JSONResponse(
            {
                "act": result.act,
                "role": result.role,
                "principal": result.principal,
                "effective_at": result.effective_at.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
            },
            headers=CONSOLE_HEADERS,
        )
