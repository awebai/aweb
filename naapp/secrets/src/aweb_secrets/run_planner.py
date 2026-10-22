"""Authoritative preparation for the sole frozen run/slot approval boundary.

The caller refreshes InstallationFence outside the write transaction and uses
app.installation_fence in composition. Preparation takes fence -> role holds ->
canonical ancestry forest -> globally sorted source/candidate grant union ->
CURRENT job/runner/issuer/template locks. S12 then takes coverage/B2 locks.

This module neither claims idempotency nor creates dispatches, charges rates,
consumes approvals or opens credentials. Those effects and the persisted joint
admission marker are required before S13 can construct internal mint authority.
The public job/issuance availability guards remain closed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from aweb_naapp.egress import InternalDestinations
from aweb_naapp.roles import hold_role, principal_key, roles_of
from aweb_naapp.runtime.attestation import VerifiedAttestation
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets import derived_grants, derived_lineage, jobs, records, runners
from aweb_secrets.containment_state import ContainmentRefused, require_enabled
from aweb_secrets.destination import DestinationInvalid, parse_destination_scope
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.operation import OperationInvalid
from aweb_secrets.policy import Policy
from aweb_secrets.run_plan import (
    FrozenRunPlan,
    PlannedMint,
    PlannedSlot,
    PreparedRun,
    RunPlanRefused,
)

_REFUSALS = (
    derived_lineage.LineageRefused,
    derived_grants.DerivedGrantRefused,
    jobs.JobRefused,
    OperationInvalid,
    ContainmentRefused,
    InstallationRefused,
)


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise RunPlanRefused(code)


async def _runner(tx, installation: AdmittedInstallation, job: jobs.JobDefinition, runner_id: str):
    runner = await runners.active_runner(tx, runner_id)
    if runner is None:
        raise RunPlanRefused("runner_unavailable")
    _require(
        (runner.installation_id, runner.team_id)
        == (installation.installation_id, installation.team_id),
        "runner_unavailable",
    )
    _require(
        runner_id in job.after["runner_ids"] and job.job_id in runner.record.after["allowed_jobs"],
        "job_not_allowed",
    )
    return runner


def _policy_valid(policy: Policy, now: datetime, attestation: VerifiedAttestation | None) -> None:
    _require(policy.window_open(now), "policy_window_closed")
    _require(policy.attestation_satisfied(attestation), "attestation_unavailable")


async def _mint(
    tx,
    *,
    installation: AdmittedInstallation,
    path: Sequence[derived_lineage.LineageNode],
    job: jobs.JobDefinition,
    ordinal: int,
    params: Mapping[str, Any],
    internal_destinations: InternalDestinations,
) -> PlannedMint | None:
    recipe = job.after["credentials"][ordinal]["mint"]
    if recipe is None:
        return None
    issuer = await derived_lineage.current_operation(tx, path, recipe["operation_id"])
    if issuer is None or issuer.digest != recipe["digest"]:
        raise RunPlanRefused("operation_not_allowed")
    job.validate_mint_mapping(ordinal, issuer)
    expanded = job.expand_mint_params(ordinal, params)
    _require(issuer.params_valid(expanded), "params_invalid")
    _require(
        issuer.token_issuing and issuer.after["result_handling"] == "store_as_secret",
        "operation_not_allowed",
    )
    store = issuer.after["store_as_secret"]
    try:
        for destination in store["destinations"]:
            parse_destination_scope(destination, internal_destinations=internal_destinations)
    except DestinationInvalid:
        raise RunPlanRefused("destination_not_allowed") from None
    snapshot = await derived_grants.snapshot_grant_template(
        tx,
        path,
        template_id=store["grant_template"],
        expected_digest=store["grant_template_digest"],
    )
    # Prelock complete template/CURRENT compatibility before covering/B2 locks.
    template = await derived_grants.fence_grant_snapshot(
        tx,
        path,
        snapshot,
        expected_digest=store["grant_template_digest"],
    )
    policy = await records.policy(tx, installation.installation_id, template.terms["policy_digest"])
    if policy is None:
        raise RunPlanRefused("operation_not_allowed")
    return PlannedMint(issuer, expanded, snapshot, policy)


class RunPlanner:
    def __init__(
        self,
        fence: InstallationFence,
        *,
        clock: Callable[[], datetime],
        derived_max_ttl_s: int,
        internal_destinations: InternalDestinations,
    ) -> None:
        if type(derived_max_ttl_s) is not int or derived_max_ttl_s <= 0 or not callable(clock):
            raise ValueError("run planner requires a positive deployment cap and live clock")
        self.fence = fence
        self.clock = clock
        self.derived_max_ttl_s = derived_max_ttl_s
        self.internal_destinations = internal_destinations

    async def _start(self, tx, grant: Grant, principal: Principal):
        installation = await self.fence.admit(tx, grant)
        _require(principal.team_id == installation.team_id, "grant_missing")
        # Lock the kill-switch row before normal-use authority. Frozen retrieval
        # retains a refusal rather than treating it as fresh send permission.
        try:
            await require_enabled(tx, installation.installation_id, installation.team_id)
            disabled = False
        except ContainmentRefused:
            disabled = True
        key = principal_key(principal)
        roles = tuple(sorted(role for role in await roles_of(tx, key) if is_secrets_role(role)))
        held = tuple([role for role in roles if await hold_role(tx, key, role)])
        return installation, held, disabled

    async def prepare(
        self,
        tx: TransactionManager,
        *,
        grant: Grant,
        principal: Principal,
        run_id: str,
        intent_id: str,
        dispatch_id: UUID,
        candidate_job: jobs.JobDefinition,
        runner_id: str,
        params: Mapping[str, Any],
        attestation: VerifiedAttestation | None = None,
    ) -> PreparedRun:
        """Prepare a fresh fixed-selector run, without admitting or enabling it.

        candidate_job is inert discovery from the sole jobs.current_job in a
        prior, completed read transaction. Its exact CURRENT digest is checked
        after the forest locks. A stale discovery refuses; it cannot change
        slots or add locks after approval. No HTTP job definition is accepted.
        Ordinary-child substitution will enter through its recorded plan after
        the selector's request shape is settled; no agent slot override exists.
        """
        installation, roles, disabled = await self._start(tx, grant, principal)
        _require(not disabled, "installation_disabled")
        _require(candidate_job.params_valid(params), "params_invalid")
        credentials = candidate_job.after["credentials"]
        _require(bool(credentials), "job_not_allowed")
        sources = []
        for slot in credentials:
            source = await records.secret_by_ref(
                tx,
                installation.installation_id,
                installation.team_id,
                slot["secret_ref"],
                lock=False,
            )
            if source is None:
                raise RunPlanRefused("grant_missing")
            sources.append(source.record.secret_id)
        try:
            paths = await derived_lineage.lock_forest(
                tx,
                installation.installation_id,
                installation.team_id,
                sources,
            )
            candidates = []
            for path in paths:
                grants = await records.active_grants(
                    tx,
                    installation.installation_id,
                    path[-1].secret.record.secret_id,
                    principal_did=principal_key(principal).principal_did,
                    roles=roles,
                    lock=False,
                )
                candidates.append(
                    sorted(
                        (g for g in grants if g.capability == "run"),
                        key=lambda g: (g.subject_principal is None, g.grant_id),
                    )
                )
            forest = await derived_lineage.lock_forest_grants(
                tx,
                paths,
                candidate_grant_ids=[g.grant_id for group in candidates for g in group],
            )
            alive = forest.check(clock=self.clock, max_ttl_s=self.derived_max_ttl_s)
            job = await jobs.resolve_job_pin(
                tx, installation.installation_id, candidate_job.job_id, candidate_job.digest
            )
            await _runner(tx, installation, job, runner_id)
            slots = []
            for ordinal, (path, grants) in enumerate(zip(paths, candidates, strict=True)):
                mint = await _mint(
                    tx,
                    installation=installation,
                    path=path,
                    job=job,
                    ordinal=ordinal,
                    params=params,
                    internal_destinations=self.internal_destinations,
                )
                selected = None
                first = None
                for candidate in grants:
                    if (
                        candidate.grant_id not in alive
                        or (job.job_id, job.digest) not in candidate.jobs
                    ):
                        continue
                    policy = await records.policy(
                        tx, installation.installation_id, candidate.policy_digest
                    )
                    if policy is None:
                        raise RunPlanRefused("job_not_allowed")
                    try:
                        _policy_valid(policy, self.clock(), attestation)
                    except RunPlanRefused as refused:
                        first = first or refused
                        continue
                    selected = (candidate, policy)
                    break
                if selected is None:
                    raise first or RunPlanRefused("job_not_allowed")
                candidate, policy = selected
                declared = credentials[ordinal]
                slots.append(
                    PlannedSlot(
                        ordinal,
                        declared["secret_ref"],
                        path[-1].secret,
                        tuple(path),
                        candidate,
                        policy,
                        declared["delivery"],
                        mint,
                    )
                )
            plan = FrozenRunPlan.freeze(
                run_id=run_id,
                intent_id=intent_id,
                dispatch_id=dispatch_id,
                installation=installation,
                requester=principal,
                requester_roles=roles,
                runner_id=runner_id,
                job=job,
                params=params,
                slots=slots,
            )
            prepared = await self._bind(tx, installation, principal, roles, attestation, plan)
            await prepared.recheck(tx)
            return prepared
        except _REFUSALS as refused:
            raise RunPlanRefused(refused.code) from None

    async def prepare_frozen(
        self,
        tx: TransactionManager,
        *,
        grant: Grant,
        principal: Principal,
        plan: FrozenRunPlan,
        attestation: VerifiedAttestation | None = None,
    ) -> PreparedRun:
        """Prelock a persisted S12 plan; retain normal-use refusals for retrieval.

        S12 classifies a stable dispatched result before enforcing recheck's
        fresh-send refusal. The original frozen plan never changes, and this
        method supplies no admission marker or AdmittedRun.
        """
        installation, roles, disabled = await self._start(tx, grant, principal)
        _require(
            installation == AdmittedInstallation(**plan.body["installation"]), "job_not_allowed"
        )
        expected = plan.body["requester"]
        _require(
            expected["principal_did"] == principal_key(principal).principal_did
            and expected["member_did_key"] == principal.did_key
            and expected["certificate_id"] == principal.certificate_id,
            "grant_missing",
        )
        prepared = await self._bind(tx, installation, principal, roles, attestation, plan)
        try:
            # Prime every authority row reachable by this frozen plan before
            # coverage/B2. A permanent refusal cannot grant send authority; the
            # later callback reaches the same already-locked refusal point.
            await prepared.recheck(tx)
        except RunPlanRefused:
            pass
        return prepared

    async def _bind(self, tx, installation, principal, roles, attestation, plan):
        authority = _RunAuthority(self, installation, principal, roles, attestation, plan)
        return await PreparedRun.bind(
            tx,
            plan=plan,
            clock=self.clock,
            max_ttl_s=self.derived_max_ttl_s,
            recheck=authority,
        )


@dataclass(repr=False)
class _RunAuthority:
    planner: RunPlanner
    installation: AdmittedInstallation
    principal: Principal
    held_roles: tuple[str, ...]
    attestation: VerifiedAttestation | None
    plan: FrozenRunPlan
    refusal: RunPlanRefused | None = field(default=None, init=False)

    async def __call__(self, tx, *, clock, max_ttl_s) -> None:
        if self.refusal is not None:
            raise self.refusal
        try:
            await self._check(tx, clock, max_ttl_s)
        except RunPlanRefused as refused:
            self.refusal = refused
            raise
        except _REFUSALS as refused:
            self.refusal = RunPlanRefused(refused.code)
            raise self.refusal from None

    async def _check(self, tx, clock, max_ttl_s):
        installation, body = self.installation, self.plan.body
        await require_enabled(tx, installation.installation_id, installation.team_id)
        present = set(await roles_of(tx, principal_key(self.principal)))
        frozen_roles = tuple(body["requester"]["roles"])
        _require(set(frozen_roles) <= set(self.held_roles) & present, "grant_revoked")
        _require(bool(self.plan.slots), "job_not_allowed")
        paths = await derived_lineage.lock_forest(
            tx,
            installation.installation_id,
            installation.team_id,
            [slot.source_id for slot in self.plan.slots],
        )
        forest = await derived_lineage.lock_forest_grants(
            tx,
            paths,
            candidate_grant_ids=[slot.parent_grant.grant_id for slot in self.plan.slots],
        )
        job = await jobs.resolve_job_pin(
            tx, installation.installation_id, body["job"]["job_id"], body["job"]["digest"]
        )
        await _runner(tx, installation, job, body["runner_id"])
        slots = []
        policies = []
        for frozen, path in zip(self.plan.slots, paths, strict=True):
            grant = frozen.parent_grant
            active = await records.active_grants(
                tx,
                installation.installation_id,
                frozen.source_id,
                principal_did=principal_key(self.principal).principal_did,
                roles=frozen_roles,
                lock=False,
            )
            current = next((g for g in active if g.grant_id == grant.grant_id), None)
            _require(current is not None and current.after == grant.after, "grant_revoked")
            _require(
                path[-1].secret.active_version == frozen.source_version, "secret_version_changed"
            )
            policy = await records.policy(tx, installation.installation_id, grant.policy_digest)
            _require(policy is not None, "job_not_allowed")
            mint = await _mint(
                tx,
                installation=installation,
                path=path,
                job=job,
                ordinal=frozen.ordinal,
                params=body["params"],
                internal_destinations=self.planner.internal_destinations,
            )
            policies.append(policy)
            if mint is not None:
                policies.append(mint.template_policy)
            slots.append(
                PlannedSlot(
                    frozen.ordinal,
                    frozen.body["label"],
                    path[-1].secret,
                    tuple(path),
                    current,
                    policy,
                    frozen.body["delivery"],
                    mint,
                )
            )
        # The last awaited authority read checks installation freshness. Pure
        # forest/policy checks then sample the LIVE clock with no later await.
        await self.planner.fence.check(tx, installation)
        alive = forest.check(clock=clock, max_ttl_s=max_ttl_s)
        _require(all(slot.parent_grant.grant_id in alive for slot in slots), "grant_revoked")
        now = clock()
        for policy in policies:
            _policy_valid(policy, now, self.attestation)
        rebuilt = FrozenRunPlan.freeze(
            run_id=body["run_id"],
            intent_id=body["intent_id"],
            dispatch_id=UUID(body["dispatch_id"]),
            installation=installation,
            requester=self.principal,
            requester_roles=frozen_roles,
            runner_id=body["runner_id"],
            job=job,
            params=body["params"],
            slots=slots,
        )
        _require(rebuilt.canonical == self.plan.canonical, "job_not_allowed")
