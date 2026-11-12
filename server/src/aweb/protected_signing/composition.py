"""Compose the one shared executor with independent authority and custody.

No HTTP route, request parser, browser ceremony or receipt store is duplicated.
Trusted mounts use requester() after their shared typed parsing, and construct
human actors only after the shared browser/session authentication for this
exact binding. Actors are in-process ports, never client JSON credentials.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path

from aweb_naapp.runtime.approvals import ActionPolicy, ApprovalRevocation, Assurance
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
from aweb_naapp.runtime.protected_signer import (
    ProtectedSigner,
    ReceiptReader,
    RestrictedRequester,
    SignerRefused,
)
from awid.protected_request import verify_protected_request
from awid.registry_types import RegistryError
from awid.request_body_limit import RequestBodyTooLarge
from pgdbm import AsyncMigrationManager
from starlette.requests import Request

from .authority import IndependentAuthority

MAX_PREPARE_BYTES = 65536
logger = logging.getLogger(__name__)


class LocalAudit:
    async def emit(self, event, transaction):
        await transaction.execute(
            "INSERT INTO {{tables.protected_local_audit}} "
            "(kind,actor,subject,occurred_at,approval_id,details) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
            event.kind.value,
            event.actor,
            event.subject,
            event.occurred_at,
            event.approval_id,
            json.dumps(dict(event.details)),
        )


class BindingPolicy:
    def __init__(self, authority):
        self.authority = authority

    async def current(self, policy_ref, *, tx=None):
        if policy_ref != "aweb.human-assurance/1":
            return None
        row = await self.authority.binding(tx if tx is not None else self.authority.db)
        return ActionPolicy(
            policy_ref,
            row["policy_version"],
            Assurance.PASSKEY,
            timedelta(seconds=600),
            (row["b3_scope"],),
        )


class IndependentProtectedSigner:
    """One explicitly provisioned team-controller/H association.

    Delivery is the operator's existing B3/approval delivery adapter. This
    composition creates neither a controller nor an authorizer on a miss.
    Only the shared executor implements and signs supported operations.
    """

    def __init__(
        self, db, *, context, registry, custody, human_origin, request_origin, delivery
    ):
        from awid.log import require_canonical_server_origin

        require_canonical_server_origin(request_origin)
        if not human_origin.startswith("https://"):
            raise ValueError("protected human origin requires HTTPS")
        self.db, self.context, self.registry, self.request_origin = (
            db,
            context,
            registry,
            request_origin,
        )
        self.authority = IndependentAuthority(
            db, context=context, registry=registry, custody=custody
        )
        self.audit = LocalAudit()
        # Same original db, the same B2 store and B3 implementation as every
        # other embedding. No synthetic installation or reusable signer unlock.
        from aweb_naapp.runtime.approvals import PgApprovalStore

        self.passkeys = Passkeys(
            db,
            rp=RelyingParty(human_origin, "Protected signing"),
            delivery=delivery,
            audit=self.audit,
            retirement=ApprovalRevocation(PgApprovalStore(db), self.audit),
            proof_context=self.authority.context_for_scope,
            enrolment_ttl=timedelta(hours=1),
            challenge_ttl=timedelta(minutes=5),
        )
        self.signer = ProtectedSigner(
            db,
            passkeys=self.passkeys,
            policies=BindingPolicy(self.authority),
            delivery=delivery,
            audit=self.audit,
            authority=self.authority,
            custody=custody,
        )

    async def migrate(self):
        await AsyncMigrationManager(
            self.db,
            migrations_path=str(Path(__file__).parent / "migrations"),
            module_name="aweb_independent_protected_signer",
        ).apply_pending_migrations()
        await self.signer.migrate()

    async def requester(self, request, *, principal, operation):
        """Build a restricted actor only after proof/current registered mapping.

        The shared route supplies its fixed label and validated typed scope.
        This binding allows prepare/receipt only, never unattended execution.
        Body size is bounded before the proof helper acquires its whole body.
        """
        if operation not in {
            "protected_operation_prepare",
            "protected_operation_receipt",
        }:
            raise SignerRefused("scope_refused")
        if not isinstance(principal, str) or not principal.startswith("did:aw:"):
            raise SignerRefused("subject_ineligible")
        chunks, length = [], 0
        async for chunk in request.stream():
            length += len(chunk)
            if length > MAX_PREPARE_BYTES:
                raise RequestBodyTooLarge()
            chunks.append(chunk)
        body = b"".join(chunks)

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        did = await verify_protected_request(
            Request(request.scope, receive),
            operation=operation,
            request_origin=self.request_origin,
            service_id=self.context.service_id,
            domain=self.context.authority_domain,
            scope=self.context.fields(),
        )
        try:
            resolution = await self.registry.resolve_key_fresh(principal)
        except RegistryError as exc:
            if exc.status_code == 404:
                raise SignerRefused("requester_invalid") from None
            logger.warning("Protected requester registry lookup failed", exc_info=True)
            raise SignerRefused("evidence_unavailable") from None
        except Exception:
            logger.warning("Protected requester registry lookup failed", exc_info=True)
            raise SignerRefused("evidence_unavailable") from None
        if resolution.did_aw != principal or resolution.current_did_key != did:
            raise SignerRefused("requester_invalid")
        if operation == "protected_operation_receipt":
            return ReceiptReader(principal, self.context)
        return RestrictedRequester(principal, self.context)
