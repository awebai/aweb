"""Restricted, immutable run/slot approval data and its transaction-bound fence.

FrozenRunPlan is inert even when loaded from arbitrary bytes. It contains no
opened values and cannot admit a run or authorize a mint. PreparedRun is made
by the internal planner after installation/role/forest/grant locks; S12 owns
coverage and joint B2 consumption. S12 calls recheck after all awaited B2 work
inside the same savepoint. Only the later persisted admission association can
supply internal mint authority; neither type is a public admit_use argument.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.approvals.request import RequestNotCanonical, parse_request_json
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets.derived_grants import GrantSnapshot
from aweb_secrets.derived_lineage import LineageNode
from aweb_secrets.grant import GrantRecord
from aweb_secrets.jobs import JobDefinition, unique_durable_slot
from aweb_secrets.operation import OperationTemplate, operation_digest
from aweb_secrets.policy import Policy
from aweb_secrets.records import StoredSecret
from aweb_secrets.runner_protocol import canonical

_DOMAIN = b"aweb.secrets.run-plan/1\n"
_FIELDS = frozenset(
    {
        "v",
        "run_id",
        "intent_id",
        "dispatch_id",
        "installation",
        "requester",
        "runner_id",
        "job",
        "params",
        "slots",
    }
)


def _time(value: datetime | None) -> str | None:
    if value is None:
        return None
    _require(value.tzinfo is not None)
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _lineage_body(node: LineageNode) -> dict[str, Any]:
    return {
        "secret_id": node.secret.record.secret_id,
        "ref": node.secret.record.ref,
        "version": node.secret.active_version,
        "parent_secret_id": node.parent_secret_id,
        "parent_version": node.parent_version,
        "source_grant_id": node.source_grant_id,
        "issuing_principal": node.issuing_principal,
        "policy_digest": node.policy_digest,
        "sensitivity": node.secret.record.sensitivity,
        "approve_only": node.secret.record.approve_only,
        "dispatch_started_at": _time(node.dispatch_started_at),
        "upstream_expires_at": _time(node.upstream_expires_at),
        "expires_at": _time(node.expires_at),
    }


class RunPlanRefused(Exception):
    def __init__(self, code: str = "run_plan_invalid") -> None:
        self.code = code
        super().__init__(code)


def _require(condition: bool) -> None:
    if not condition:
        raise RunPlanRefused()


@dataclass(frozen=True, repr=False)
class PlannedMint:
    """Resolved metadata, never a credential or authority to call the broker."""

    operation: OperationTemplate
    params: Mapping[str, Any]
    template: GrantSnapshot
    template_policy: Policy

    def _body(self) -> dict[str, Any]:
        return {
            "operation": dict(self.operation.after),
            "operation_digest": self.operation.digest,
            "params": dict(self.params),
            "grant_template": self.template.template.after,
            "grant_template_digest": self.template.template.digest,
            "template_policy": dict(self.template_policy.body),
        }


@dataclass(frozen=True, repr=False)
class PlannedSlot:
    ordinal: int
    label: str
    source: StoredSecret
    ancestry: tuple[LineageNode, ...]
    parent_grant: GrantRecord
    parent_policy: Policy
    delivery: str
    mint: PlannedMint | None = None

    def _body(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "label": self.label,
            "source": {
                "secret_id": self.source.record.secret_id,
                "ref": self.source.record.ref,
                "version": self.source.active_version,
                "record": self.source.record.after,
            },
            "ancestry_ids": [node.secret.record.secret_id for node in self.ancestry],
            "ancestry": [_lineage_body(node) for node in self.ancestry],
            "sensitivity": "sensitive"
            if any(node.secret.record.sensitivity == "sensitive" for node in self.ancestry)
            else "standard",
            "approve_only": any(node.secret.record.approve_only for node in self.ancestry),
            "parent_grant": self.parent_grant.after,
            "parent_policy": dict(self.parent_policy.body),
            "delivery": self.delivery,
            "mint": None if self.mint is None else self.mint._body(),
        }


@dataclass(frozen=True, repr=False)
class FrozenRunSlot:
    """Fresh views of an exact frozen slot, suitable for S12's approval view."""

    canonical: bytes = field(repr=False)

    @property
    def body(self) -> dict[str, Any]:
        return json.loads(self.canonical)

    @property
    def ordinal(self) -> int:
        return self.body["ordinal"]

    @property
    def source_id(self) -> str:
        return self.body["source"]["secret_id"]

    @property
    def source_version(self) -> int:
        return self.body["source"]["version"]

    @property
    def parent_grant(self) -> GrantRecord:
        return GrantRecord.from_after(self.body["parent_grant"])

    @property
    def approval_required(self) -> bool:
        template = self.template_policy
        return (
            self.body["approve_only"]
            or self.parent_policy.body["approval"] == "per_use"
            or (template is not None and template.body["approval"] == "per_use")
        )

    @property
    def ancestry_ids(self) -> tuple[str, ...]:
        return tuple(self.body["ancestry_ids"])

    @property
    def parent_policy(self) -> Policy:
        return Policy.from_body(self.body["parent_policy"])

    @property
    def template_policy(self) -> Policy | None:
        mint = self.body["mint"]
        return None if mint is None else Policy.from_body(mint["template_policy"])


@dataclass(frozen=True)
class FrozenRunPlan:
    canonical: bytes = field(repr=False)

    @property
    def digest(self) -> str:
        return hashlib.sha256(_DOMAIN + self.canonical).hexdigest()

    @property
    def body(self) -> dict[str, Any]:
        return json.loads(self.canonical)

    @property
    def slots(self) -> tuple[FrozenRunSlot, ...]:
        return tuple(FrozenRunSlot(canonical(slot)) for slot in self.body["slots"])

    @classmethod
    def from_bytes(cls, data: bytes) -> FrozenRunPlan:
        """Load restricted plan data only; this never supplies admission authority.

        The planner must re-resolve all current authority under locks before a
        prepared run can use it. Canonical bytes are required in storage.
        """
        try:
            body = parse_request_json(data)
            _require(set(body) == _FIELDS and type(body["v"]) is int and body["v"] == 1)
            _require(isinstance(body["slots"], list))
            _require(canonical(body) == data)
            return cls(data)
        except (RequestNotCanonical, ValueError, TypeError, RecursionError):
            raise RunPlanRefused() from None

    @classmethod
    def freeze(
        cls,
        *,
        run_id: str,
        intent_id: str,
        dispatch_id: UUID,
        installation: AdmittedInstallation,
        requester: Principal,
        runner_id: str,
        job: JobDefinition,
        params: Mapping[str, Any],
        slots: Sequence[PlannedSlot],
    ) -> FrozenRunPlan:
        """Detach a resolved plan from all caller-owned mutable models.

        These consistency checks complement, and never replace, CURRENT/source
        resolution, ancestry liveness and the caller's authority fence. No
        eligible-approver list is frozen: S12 reads current coverage under locks.
        """
        _require(requester.team_id == installation.team_id)
        _require(bool(run_id) and bool(intent_id) and job.params_valid(params))
        job_body = job.after
        _require(runner_id in job_body["runner_ids"])
        _require(len(slots) == len(job_body["credentials"]))
        principal = principal_key(requester).principal_did
        for ordinal, (slot, declared) in enumerate(
            zip(slots, job_body["credentials"], strict=True)
        ):
            grant, policy = slot.parent_grant, slot.parent_policy
            _require(type(slot.ordinal) is int and slot.ordinal == ordinal)
            _require(slot.label == declared["secret_ref"] and slot.delivery == declared["delivery"])
            _require(slot.source.state == "active" and slot.source.active_version is not None)
            _require(bool(slot.ancestry) and slot.ancestry[-1].secret == slot.source)
            ids = [node.secret.record.secret_id for node in slot.ancestry]
            _require(len(set(ids)) == len(ids))
            for index, node in enumerate(slot.ancestry):
                _require(
                    (node.installation_id, node.team_id)
                    == (
                        installation.installation_id,
                        installation.team_id,
                    )
                )
                _require(node.parent_secret_id == (None if index == 0 else ids[index - 1]))
            _require(grant.secret_id == slot.source.record.secret_id and grant.capability == "run")
            _require(
                grant.policy_digest == policy.digest and (job.job_id, job.digest) in grant.jobs
            )
            _require(grant.subject_principal is None or grant.subject_principal == principal)
            # An ordinary derived durable substitution keeps the owner's label;
            # the authoritative planner must select exactly one matching slot.
            if slot.delivery == "durable" and len(slot.ancestry) > 1:
                try:
                    selected = unique_durable_slot(
                        job, lineage_refs=[node.secret.record.ref for node in slot.ancestry]
                    )
                except ValueError:
                    raise RunPlanRefused() from None
                _require(selected == ordinal)
            else:
                _require(slot.source.record.ref == slot.label)
            _require((slot.mint is None) == (slot.delivery == "durable"))
            if slot.mint is not None:
                mint = slot.mint
                _require(mint.operation.secret_id in ids)
                _require(mint.operation.after["secret_id"] == mint.operation.secret_id)
                _require(mint.operation.after["operation_id"] == mint.operation.operation_id)
                _require(operation_digest(mint.operation.after) == mint.operation.digest)
                try:
                    job.validate_mint_mapping(ordinal, mint.operation)
                    expanded = job.expand_mint_params(ordinal, params)
                except ValueError:
                    raise RunPlanRefused() from None
                _require(dict(mint.params) == expanded and mint.operation.params_valid(expanded))
                _require(mint.operation.token_issuing)
                _require(mint.operation.after["result_handling"] == "store_as_secret")
                store = mint.operation.after["store_as_secret"]
                template = mint.template.template
                _require(template.grant_template_id == store["grant_template"])
                _require(template.digest == store["grant_template_digest"])
                _require(template.terms["policy_digest"] == mint.template_policy.digest)
                _require(template.terms["subject"] == {"principal": principal})
        try:
            return cls.from_bytes(
                canonical(
                    {
                        "v": 1,
                        "run_id": run_id,
                        "intent_id": intent_id,
                        "dispatch_id": str(dispatch_id),
                        "installation": {
                            "app_id": installation.app_id,
                            "team_id": installation.team_id,
                            "installation_id": installation.installation_id,
                            "generation": installation.generation,
                        },
                        "requester": {
                            "principal_did": principal,
                            "member_did_key": requester.did_key,
                            "certificate_id": requester.certificate_id,
                        },
                        "runner_id": runner_id,
                        "job": {"job_id": job.job_id, "digest": job.digest, "record": job_body},
                        "params": dict(params),
                        "slots": [slot._body() for slot in slots],
                    }
                )
            )
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise RunPlanRefused() from None


class RunRecheck(Protocol):
    async def __call__(
        self,
        tx: TransactionManager,
        *,
        clock: Callable[[], datetime],
        max_ttl_s: int,
    ) -> None:
        """Recheck prepared authority, sampling clock AFTER all awaited reads.

        Includes CURRENT job/runner, slot grant/source version, operation and
        complete template/policy pins, ancestry expiry and effective flags.
        Takes no new authority locks after S12 has taken covering/B2 locks.
        """
        ...


@dataclass(frozen=True, repr=False)
class PreparedRun:
    """Internal planner input to S12, bound to its original transaction.

    This is still not an AdmittedRun or send authority. S12 must re-read current
    covering approvers, jointly consume B2 in one savepoint, then recheck before
    committing its original run/slot/plan associations. Stable already-admitted
    retrieval must be classified before enforcing a fresh-send refusal.
    """

    plan: FrozenRunPlan
    clock: Callable[[], datetime] = field(repr=False)
    max_ttl_s: int
    _transaction_id: str = field(repr=False)
    _recheck: RunRecheck = field(repr=False)

    @classmethod
    async def bind(
        cls,
        tx: TransactionManager,
        *,
        plan: FrozenRunPlan,
        clock: Callable[[], datetime],
        max_ttl_s: int,
        recheck: RunRecheck,
    ) -> PreparedRun:
        # pgdbm creates a new TransactionManager for a savepoint. PostgreSQL's
        # full transaction ID binds the outer transaction AND its savepoints,
        # while rejecting another connection or a later reused connection.
        _require(callable(clock) and type(max_ttl_s) is int and max_ttl_s > 0)
        transaction_id = await tx.fetch_value("SELECT pg_current_xact_id()::text")
        return cls(plan, clock, max_ttl_s, transaction_id, recheck)

    @property
    def slots(self) -> tuple[FrozenRunSlot, ...]:
        return self.plan.slots

    @property
    def installation(self) -> AdmittedInstallation:
        return AdmittedInstallation(**self.plan.body["installation"])

    async def recheck(self, tx: TransactionManager) -> None:
        current_id = await tx.fetch_value("SELECT pg_current_xact_id()::text")
        if current_id != self._transaction_id:
            raise RunPlanRefused("run_plan_transaction_changed")
        await self._recheck(tx, clock=self.clock, max_ttl_s=self.max_ttl_s)
