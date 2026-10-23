"""S3 transition recording through the sole shared hook producer.

The caller freezes value-free metadata after preparing CURRENT broker authority,
then installs BrokerAudit as Dispatches.on_transition. Every catalog event and
its console activity record use S3's actual transaction. This callback does no
network I/O, grants no authority and never renders a request from live records.
The caller still performs admission/backlog checks and repeats the final live
fence AFTER all awaited transition/outbox writes, before publication commits.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from aweb_naapp.dispatch import State, Transition
from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.hooks.producer import HookProducer, RegistrationView
from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets.admission import Admission
from aweb_secrets.broker_fence import PreparedBrokerCall
from aweb_secrets.use_context import UseCommitments, note_dispatch_started, use_context

_HOOK = "post-secret-use-hook"
_COMPLETED = frozenset(
    {
        "disposition",
        "undeclared_credential",
        "returned_hmac",
        "upstream_response_hmac",
        "upstream_status_code",
        "upstream_bytes",
        "upstream_truncated",
        "redaction_count",
    }
)
_ACTIONS = {
    State.REFUSED: "refused",
    State.ADMITTED: "admitted",
    State.DISPATCHING: "dispatching",
    State.COMPLETED: "completed",
    State.NOT_SENT: "not_sent",
    State.OUTCOME_UNKNOWN: "outcome_unknown",
    State.RECONCILED_COMPLETED: "reconciled",
    State.RECONCILED_FAILED: "reconciled",
    State.RECONCILED_UNKNOWN: "reconciled",
}


async def freeze_broker_audit(
    tx: TransactionManager,
    *,
    admission: Admission,
    principal: Principal,
    dispatch_id: UUID,
    call: PreparedBrokerCall,
    signed_trace_id: str | None = None,
) -> None:
    """Before S3.create, after authority/input preparation, in their SAME tx.

    Only the configured path template is retained: not the rendered path/query,
    body, header values, params or backend locator. Original authenticated-byte
    MACs come from the persist-once use context, never S8's equality hash.
    This is an internal composition seam, never an HTTP input model.
    """
    stored = await use_context(tx, dispatch_id)
    context, scope = stored.commitments.context, admission.installation
    intent = await tx.fetch_one(
        "SELECT * FROM {{tables.intents}} WHERE intent_id=$1 AND installation_id=$2 AND team_id=$3",
        admission.intent_id,
        scope.installation_id,
        scope.team_id,
    )
    if (
        intent is None
        or (
            stored.intent_id,
            context.app_id,
            context.installation_id,
            context.team_id,
            context.generation,
            context.tool,
        )
        != (
            admission.intent_id,
            scope.app_id,
            scope.installation_id,
            scope.team_id,
            scope.generation,
            "request",
        )
        or (
            intent["principal_did"],
            intent["member_did_key"],
            intent["certificate_id"],
            intent["install_generation"],
            intent["grant_id"],
            intent["policy_digest"],
            intent["secret_id"],
            intent["secret_version"],
        )
        != (
            principal_key(principal).principal_did,
            principal.did_key,
            principal.certificate_id,
            scope.generation,
            admission.grant_id,
            admission.policy_digest,
            call.secret.secret_id,
            call.secret.version,
        )
        or (
            principal.team_id,
            call.secret.installation_id,
            call.secret.team_id,
            call.stored.record.secret_id,
            call.stored.active_version,
            call.policy.digest,
        )
        != (
            scope.team_id,
            scope.installation_id,
            scope.team_id,
            call.secret.secret_id,
            call.secret.version,
            admission.policy_digest,
        )
    ):
        raise ValueError("broker audit requires the original scoped intent and prepared call")
    operation = call.operation
    if (intent["operation_id"], intent["operation_digest"]) != (
        None if operation is None else operation.operation_id,
        None if operation is None else operation.digest,
    ):
        raise ValueError("broker audit operation differs from its original intent")
    record, rendered = call.stored.record, call.rendered
    url = urlsplit(rendered.url)
    payload: dict[str, Any] = {
        "op_kind": "broker",
        "secret_id": record.secret_id,
        "secret_version": call.secret.version,
        "secret_kind": record.kind,
        "secret_backend": record.backend,
        "secret_sensitivity": record.sensitivity,
        "target_method": rendered.method,
        "target_host": url.hostname,
        "target_port": url.port or 443,
        "target_path_template": call.target_path_template,
        "grant_id": admission.grant_id,
        "policy_digest": admission.policy_digest,
    }
    if operation is not None:
        payload.update(operation_id=operation.operation_id, operation_digest=operation.digest)
    if stored.commitments.request_mac is not None:
        payload["request_sha256"] = stored.commitments.request_mac
    if stored.commitments.params_mac is not None:
        payload["params_sha256"] = stored.commitments.params_mac
    packaged_catalog().validate(_HOOK, {**payload, "action": "admitted"})
    await tx.execute(
        "INSERT INTO {{tables.broker_audit_contexts}} (dispatch_id,actor,payload,signed_trace_id)"
        " VALUES ($1,$2::jsonb,$3::jsonb,CASE WHEN $4::text ~ '^[0-9a-f]{32}$'"
        " AND $4 <> repeat('0',32) THEN $4 ELSE NULL END)"
        " ON CONFLICT (dispatch_id) DO NOTHING",
        dispatch_id,
        json.dumps(_actor(principal)),
        json.dumps(payload),
        signed_trace_id,
    )


class BrokerAudit:
    """One caller's transition callback with an outside-lock registration view.

    producer is the runtime's authoritative installation-scoped factory. Details
    are already-verified internal transition metadata, never raw agent input.
    Approval lifecycle transitions deliberately refuse until their retained B3
    proof composition is supplied; this callback does not synthesize evidence.
    Response MACs MUST be producer-keyed over the actual response bytes. Missing
    required details refuse the transition rather than invent a commitment. Snapshot target/authority/actor/MAC fields cannot be overridden.
    """

    def __init__(
        self,
        *,
        producer: Callable[..., HookProducer],
        view: RegistrationView | None,
        refusal_code: str | None = None,
        completed: Mapping[str, Any] | None = None,
    ) -> None:
        if completed is not None and completed.keys() - _COMPLETED:
            raise ValueError("completed metadata cannot change frozen broker authority")
        self._producer, self._view = producer, view
        self._refusal_code = refusal_code
        # Catalog values here are scalars. Detach caller-owned mappings.
        self._completed = None if completed is None else dict(completed)

    async def __call__(self, tx: TransactionManager, event: Transition) -> None:
        stored = await use_context(tx, event.dispatch_id)
        row = await tx.fetch_one(
            "SELECT actor,payload,signed_trace_id FROM {{tables.broker_audit_contexts}}"
            " WHERE dispatch_id=$1",
            event.dispatch_id,
        )
        if row is None or stored.commitments.context.tool != "request":
            raise ValueError("broker transition has no frozen request audit context")
        if event.to_state is State.RECEIVED:
            return  # No received action exists in the catalog.
        context = stored.commitments.context
        producer = self._producer(
            installation_id=context.installation_id,
            generation=context.generation,
        )
        _same_producer(producer, context)
        if event.to_state not in _ACTIONS:
            raise ValueError("approval transitions require their retained-proof composition")
        payload = json.loads(row["payload"])
        payload.update(
            action=_ACTIONS[event.to_state],
            dispatch_id=str(event.dispatch_id),
            dispatch_state=event.to_state.value,
        )
        status = "success"
        if event.to_state is State.REFUSED:
            if self._refusal_code is None:
                raise ValueError("a refused transition requires its fixed refusal code")
            payload["refusal_code"] = self._refusal_code
            status = "denied"
        elif event.to_state is State.COMPLETED:
            if self._completed is None:
                raise ValueError("a completed transition requires sanitized result metadata")
            payload.update(self._completed)
        elif event.to_state in (State.NOT_SENT, State.RECONCILED_FAILED):
            status = "failed"
        elif event.to_state in (State.OUTCOME_UNKNOWN, State.RECONCILED_UNKNOWN):
            status = "outcome_unknown"
        if event.to_state is State.DISPATCHING:
            await note_dispatch_started(tx, event.dispatch_id, event.occurred_at)
        options = dict(
            team_id=context.team_id,
            payload=payload,
            actor=json.loads(row["actor"]),
            occurred_at=event.occurred_at,
            signed_trace_id=row["signed_trace_id"],
        )
        if event.to_state is State.REFUSED:
            event_id = await producer.enqueue_refusal(tx, **options)
        else:
            event_id = await producer.enqueue(
                tx,
                hook=_HOOK,
                result_status=status,
                view=self._view,
                **options,
            )
        await _activity(
            tx,
            event_id=event_id,
            context=context,
            dispatch_id=event.dispatch_id,
            occurred_at=event.occurred_at,
            payload=payload,
            actor=json.loads(row["actor"]),
        )


def _actor(principal: Principal) -> dict[str, Any]:
    actor: dict[str, Any] = {
        "authority_mode": "team_cert",
        "attestations": [],
        "did_key": principal.did_key,
        "certificate_id": principal.certificate_id,
        "alias": principal.alias,
    }
    if principal.did_aw_registry_verified and principal.did_aw is not None:
        actor["did_aw"] = principal.did_aw
    return actor


def _same_producer(producer: HookProducer, context: CommitmentContext) -> None:
    if (
        producer.producer.app_id,
        producer.producer.installation_id,
        producer.producer.generation,
    ) != (
        context.app_id,
        context.installation_id,
        context.generation,
    ):
        raise ValueError("broker producer differs from frozen installation context")


async def _activity(
    tx: TransactionManager,
    *,
    event_id: UUID,
    context: CommitmentContext,
    dispatch_id: UUID | None,
    occurred_at: datetime,
    payload: Mapping[str, Any],
    actor: Mapping[str, Any],
) -> None:
    await tx.execute(
        "INSERT INTO {{tables.broker_use_events}}"
        " (event_id,installation_id,team_id,install_generation,dispatch_id,occurred_at,action,payload,actor)"
        " VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb)",
        event_id,
        context.installation_id,
        context.team_id,
        context.generation,
        dispatch_id,
        occurred_at,
        payload["action"],
        json.dumps(payload),
        json.dumps(actor),
    )


async def record_broker_refusal(
    tx: TransactionManager,
    *,
    producer: HookProducer,
    principal: Principal,
    commitments: UseCommitments,
    code: str,
    occurred_at: datetime,
    signed_trace_id: str | None = None,
) -> UUID:
    """Outer admission transaction, after the failed inner savepoint rolls back.

    Authoritative installation/matched-tool context and principal come from B1/F6,
    never the body. Missing complete input omits its MAC. This creates no intent,
    S2 claim or S3 dispatch and can authorize no external effect. Configuration
    failures without established attribution must not call this path; their codes
    are absent from the shared refusal catalog. Failure rolls back both records.
    """
    context = commitments.context
    if context.tool != "request" or context.team_id != principal.team_id:
        raise ValueError("broker refusal requires its authenticated team and matched tool")
    _same_producer(producer, context)
    payload: dict[str, Any] = {"action": "refused", "op_kind": "broker", "refusal_code": code}
    if commitments.request_mac is not None:
        payload["request_sha256"] = commitments.request_mac
    if commitments.params_mac is not None:
        payload["params_sha256"] = commitments.params_mac
    actor = _actor(principal)
    event_id = await producer.enqueue_refusal(
        tx,
        team_id=context.team_id,
        payload=payload,
        actor=actor,
        occurred_at=occurred_at,
        signed_trace_id=signed_trace_id,
    )
    await _activity(
        tx,
        event_id=event_id,
        context=context,
        dispatch_id=None,
        occurred_at=occurred_at,
        payload=payload,
        actor=actor,
    )
    return event_id
