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
from awid.did import validate_stable_id
from awid.dns_auth import enforce_timestamp_skew, require_timestamp
from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy, PolicyInvalid
from awid.protected_request import verify_protected_request
from awid.registry_types import RegistryError, RegistryThrottled
from awid.request_body_limit import RequestBodyTooLarge
from pgdbm import AsyncMigrationManager
from starlette.requests import Request

from .authority import IndependentAuthority
from .registry import PinnedRegistryView

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
    def __init__(self, authority, expected_version=None):
        self.authority = authority
        self.expected_version = expected_version

    async def current(self, policy_ref, *, tx=None):
        if policy_ref != "aweb.human-assurance/1":
            return None
        row = await self.authority.binding(tx if tx is not None else self.authority.db)
        if (
            self.expected_version is not None
            and row["policy_version"] != self.expected_version
        ):
            raise SignerRefused("policy_changed")
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
        self,
        db,
        *,
        context,
        registry,
        custody,
        human_origin,
        request_origin,
        delivery,
        policy_version=None,
        proof_context=None,
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
        self.protected_authority_keys = frozenset({custody.team_key_did})
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
            proof_context=self.authority.context_for_scope if proof_context is None else proof_context,
            enrolment_ttl=timedelta(hours=1),
            challenge_ttl=timedelta(minutes=5),
        )
        self.signer = ProtectedSigner(
            db,
            passkeys=self.passkeys,
            policies=BindingPolicy(self.authority, policy_version),
            delivery=delivery,
            audit=self.audit,
            authority=self.authority,
            custody=custody,
        )

        from .admission import AdmissionEffects

        self.signer.admission = AdmissionEffects(self)

    @classmethod
    def from_profile(cls, db, *, profile, scope, registry_client, custody, delivery, proof_context=None):
        """Use the host's lifespan-owned registry_client(), without another client.

        The profile must already come from trusted operator configuration.
        An exact explicit binding is required; public references are checked
        against the configured custody and shared current policy, never used
        as approval evidence.
        """
        binding = profile.binding_for(scope)
        if binding.authority_key_did != custody.team_key_did:
            raise SignerRefused("authority_changed")
        return cls(
            db,
            context=binding.context(),
            registry=PinnedRegistryView(registry_client, profile=profile),
            custody=custody,
            human_origin=profile.human_origin,
            request_origin=profile.request_origin,
            delivery=delivery,
            policy_version=binding.policy.version,
            proof_context=proof_context,
        )

    async def authenticate_prepare(self, request, operation):
        if operation.context != self.context:
            raise SignerRefused("scope_refused")
        if (
            operation.intent()["operation"] == "team.log-key.sign"
            and operation.audience != self.request_origin
        ):
            raise SignerRefused("scope_refused")
        return await self.requester(
            request,
            principal=request.headers.get("X-AWEB-DID-AW", ""),
            operation="protected_operation_prepare",
            context=operation.context,
        )

    async def authenticate_receipt(self, request, operation_id):
        context = await self.signer.lookup_context(operation_id)
        if context is None:
            raise SignerRefused("operation_not_found")
        return await self.requester(
            request,
            principal=request.headers.get("X-AWEB-DID-AW", ""),
            operation="protected_operation_receipt",
            context=context,
        )

    async def authenticate_execute(self, request, operation_id):
        context = await self.signer.lookup_context(operation_id)
        if context is None:
            raise SignerRefused("operation_not_found")
        return await self.requester(request, principal=request.headers.get("X-AWEB-DID-AW", ""),
                                    operation="protected_operation_execute", context=context)

    def protected_sessions(self):
        from aweb_naapp.console import ConsoleSessions

        async def current_scope(scope):
            try:
                return (
                    await self.authority.context_for_scope(scope, tx=self.db)
                    == self.context
                )
            except SignerRefused:
                return False

        return ConsoleSessions(self.db, passkeys=self.passkeys, scopes=current_scope)

    def operations_http(self, *, limiter, human_sessions=None, human_csrf_key=None):
        from aweb_naapp.runtime.protected_signer import ProtectedOperationsHTTP

        return ProtectedOperationsHTTP(
            self.signer,
            request_origin=self.request_origin,
            requester=self.authenticate_prepare,
            reader=self.authenticate_receipt,
            limiter=limiter,
            executor=self.authenticate_execute,
            policy_reader=self.read_admission_policy,
            human_sessions=human_sessions,
            human_csrf_key=human_csrf_key,
        )

    async def read_admission_policy(self, request, team_id):
        """Configuration only, under a named requester's current registered key.

        The explicit operator requester grant is held with this profile binding;
        an arbitrary valid registry key is not a prospective root grant. The
        current controller/H checks remain independent of policy contents.
        """
        c = self.context
        if c.authority_kind != "team_controller" or team_id != c.authority_id:
            raise SignerRefused("scope_refused")
        principal = request.headers.get("X-AWEB-DID-AW", "")
        await self._request_key(request, principal=principal,
            operation="protected_admission_policy_read",
            scope={"service_id": c.service_id, "team_id": team_id}, domain=c.authority_domain)
        actor = RestrictedRequester(principal, c)
        fence = await self.authority.observe(c, purpose="receipt")
        async with self.db.transaction() as tx:
            await fence.prepare(tx, actor)
            row = await tx.fetch_one(
                "SELECT policy FROM {{tables.protected_admission_policies}} WHERE service_id=$1 FOR SHARE",
                c.service_id,
            )
            policy = None
            if row is not None:
                try:
                    raw = json.loads(row["policy"]) if isinstance(row["policy"], str) else row["policy"]
                    policy = AdmissionPolicy.from_fields(raw, service_id=c.service_id)
                    if team_id not in policy.fields()["teams"]:
                        raise PolicyInvalid()
                except (ValueError, TypeError):
                    raise SignerRefused("evidence_unavailable") from None
            await fence.check(tx, actor)
            fence.require_fresh()
            enforce_timestamp_skew(require_timestamp(request))
        return {"service_id": c.service_id, "team_id": team_id, "mode": "protected",
                "policy": policy.fields() if policy is not None else None}

    async def migrate(self):
        await AsyncMigrationManager(
            self.db,
            migrations_path=str(Path(__file__).parent / "migrations"),
            module_name="aweb_independent_protected_signer",
        ).apply_pending_migrations()
        await self.signer.migrate()

    async def requester(self, request, *, principal, operation, context=None):
        """Build a restricted actor only after proof/current registered mapping.

        The shared route supplies its fixed label and validated typed scope.
        This binding allows prepare/receipt only, never unattended execution.
        Body size is bounded before the proof helper acquires its whole body.
        """
        if operation not in {
            "protected_operation_prepare",
            "protected_operation_receipt",
            "protected_operation_execute",
        }:
            raise SignerRefused("scope_refused")
        context = self.context if context is None else context
        expected, selected = self.context.fields(), context.fields()
        if operation == "protected_operation_receipt":
            expected.pop("generation")
            selected.pop("generation")
        if expected != selected:
            raise SignerRefused("scope_refused")
        await self._request_key(request, principal=principal, operation=operation,
                                scope=context.fields(), domain=context.authority_domain)
        if operation == "protected_operation_receipt":
            return ReceiptReader(principal, context)
        return RestrictedRequester(principal, context)

    async def _request_key(self, request, *, principal, operation, scope, domain):
        try:
            if (
                not isinstance(principal, str)
                or validate_stable_id(principal) != principal
            ):
                raise ValueError()
        except ValueError:
            raise SignerRefused("requester_invalid") from None
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
            domain=domain,
            scope=scope,
        )
        try:
            resolution = await self.registry.resolve_key_fresh(principal)
        except RegistryError as exc:
            if exc.status_code == 404:
                raise SignerRefused("requester_invalid") from None
            logger.warning("Protected requester registry lookup failed", exc_info=True)
            raise SignerRefused(
                "evidence_unavailable",
                retry_after_seconds=(
                    exc.retry_after_seconds
                    if isinstance(exc, RegistryThrottled)
                    else None
                ),
            ) from None
        except Exception:
            logger.warning("Protected requester registry lookup failed", exc_info=True)
            raise SignerRefused("evidence_unavailable") from None
        if resolution.did_aw != principal or resolution.current_did_key != did:
            raise SignerRefused("requester_invalid")
        enforce_timestamp_skew(require_timestamp(request))
        return did
