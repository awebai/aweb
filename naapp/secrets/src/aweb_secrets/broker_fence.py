"""CURRENT broker authority prepared before S3 locks, checked before dispatch.

This fence never opens a credential, consults a token cache, consumes an
approval or sends a request. Commit S3's dispatching transition first; only
then open the exact prepared version through custody and use that version's
cache key. A new transaction constructs a new fence and re-reads authority.
"""

from __future__ import annotations

import copy
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

from aweb_naapp.dispatch import Dispatch
from aweb_naapp.egress import (
    Bounds,
    Destination,
    EgressRefused,
    InternalDestinations,
    canonical_url,
    match_destination,
)
from aweb_naapp.roles import hold_role, principal_key, roles_of
from aweb_naapp.runtime.attestation import VerifiedAttestation
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp.runtime.team_auth import Principal
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, records
from aweb_secrets.admission import Admission, AdmissionRefused, UseRequest, _covers
from aweb_secrets.broker import SecretVersion
from aweb_secrets.containment_state import ContainmentRefused, require_enabled
from aweb_secrets.custody import SealContext
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.operation_request import OperationRequest, render_operation
from aweb_secrets.policy import Policy
from aweb_secrets.use_approval import BrokerOpen


@dataclass(frozen=True, repr=False)
class PreparedBrokerCall:
    stored: records.StoredSecret
    secret: SecretVersion
    operation: OperationTemplate | None
    rendered: OperationRequest
    policy: Policy
    token_destination: Destination | None
    target_path_template: str


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionRefused(code)


class BrokerFence:
    def __init__(
        self,
        fence: InstallationFence,
        *,
        admission: Admission,
        principal: Principal,
        request: UseRequest,
        dispatch_id: UUID,
        headers: Sequence[tuple[str, str]],
        attestation: VerifiedAttestation | None,
        clock: Callable[[], datetime],
        derived_max_ttl_s: int,
        internal_destinations: InternalDestinations,
        open_call: BrokerOpen | None = None,
        backend_version_check: Callable[[SealContext], Awaitable[None]] | None = None,
    ) -> None:
        if not callable(clock) or type(derived_max_ttl_s) is not int or derived_max_ttl_s <= 0:
            raise ValueError("broker fence requires a live clock and positive deployment cap")
        self.fence = fence
        self.admission = admission
        self.principal = principal
        self.request = replace(request, params=copy.deepcopy(request.params))
        self.dispatch_id = dispatch_id
        self.headers = tuple(headers)
        self.attestation = attestation
        self.clock = clock
        self.derived_max_ttl_s = derived_max_ttl_s
        self.internal_destinations = internal_destinations
        self.open_call = copy.deepcopy(open_call)
        self.backend_version_check = backend_version_check
        self._tx: TransactionManager | None = None
        self._call: PreparedBrokerCall | None = None
        self._forest: derived_lineage.LockedForest | None = None

    @property
    def call(self) -> PreparedBrokerCall:
        if self._call is None:
            raise RuntimeError("prepare broker authority first")
        return self._call

    async def prepare(self, tx: TransactionManager) -> None:
        self._tx, self._call, self._forest = None, None, None
        try:
            await self._prepare(tx)
        except (derived_lineage.LineageRefused, ContainmentRefused, EgressRefused) as refused:
            raise AdmissionRefused(refused.code) from None

    async def _prepare(self, tx: TransactionManager) -> None:
        scope = self.admission.installation
        await self.fence.for_installation(scope).prepare(tx)
        await require_enabled(tx, scope.installation_id, scope.team_id)
        key = principal_key(self.principal)
        _require(key.team_id == scope.team_id, "grant_missing")
        roles = []
        for role in sorted(await roles_of(tx, key)):
            if is_secrets_role(role) and await hold_role(tx, key, role):
                roles.append(role)
        intent = await tx.fetch_one(
            "SELECT * FROM {{tables.intents}} WHERE intent_id=$1 AND installation_id=$2 AND team_id=$3",
            self.admission.intent_id,
            scope.installation_id,
            scope.team_id,
        )
        if intent is None:
            raise AdmissionRefused("grant_missing")
        _require(intent["principal_did"] == key.principal_did, "grant_missing")
        _require(intent["install_generation"] == scope.generation, "generation_superseded")
        _require(
            intent["request_id"] == self.request.request_id
            and bytes(intent["request_sha256"]) == self.request.request_sha256,
            "idempotency_conflict",
        )
        _require(intent["operation_id"] == self.request.operation_id, "operation_not_allowed")
        paths = await derived_lineage.lock_forest(
            tx, scope.installation_id, scope.team_id, [intent["secret_id"]]
        )
        forest = await derived_lineage.lock_forest_grants(
            tx, paths, candidate_grant_ids=[intent["grant_id"]]
        )
        alive = forest.check(clock=self.clock, max_ttl_s=self.derived_max_ttl_s)
        path, stored = paths[0], paths[0][-1].secret
        if stored.active_version is None:
            raise AdmissionRefused("secret_disabled")
        _require(stored.active_version == intent["secret_version"], "secret_version_changed")
        grants = await records.active_grants(
            tx,
            scope.installation_id,
            intent["secret_id"],
            principal_did=key.principal_did,
            roles=roles,
            lock=False,
        )
        selected = next(
            (g for g in grants if g.grant_id == intent["grant_id"] and g.capability == "use"), None
        )
        if selected is None:
            raise AdmissionRefused("grant_revoked")
        _require(
            selected.grant_id in alive
            and selected.grant_id == self.admission.grant_id
            and selected.policy_digest == intent["policy_digest"]
            and selected.policy_digest == self.admission.policy_digest,
            "grant_revoked",
        )
        policy = await records.policy(tx, scope.installation_id, intent["policy_digest"])
        if policy is None:
            raise AdmissionRefused("grant_revoked")
        operation = (
            None
            if self.request.operation_id is None
            else await derived_lineage.current_operation(tx, path, self.request.operation_id)
        )
        sensitivity = (
            "sensitive"
            if any(n.secret.record.sensitivity == "sensitive" for n in path)
            else "standard"
        )
        refusal = _covers(selected, policy, self.request, sensitivity, operation)
        if refusal:
            raise AdmissionRefused(refusal)
        _require(
            not any(n.secret.record.approve_only for n in path) or intent["approval_required"],
            "operation_not_allowed",
        )
        destinations = await records.destinations(
            tx, scope.installation_id, stored.record.secret_id
        )
        if operation is not None:
            _require(operation.digest == intent["operation_digest"], "operation_not_allowed")
            rendered = render_operation(
                operation,
                self.request.params or {},
                headers=self.headers,
                idempotency_key=f"secrets-{self.dispatch_id}",
            )
            chosen = self._destination(destinations, rendered.method, rendered.url)
            reserved = operation.after["idempotency"]
            reserved = frozenset() if reserved is None else frozenset({reserved["header"].lower()})
            narrowed = replace(
                rendered.destination,
                network=chosen.network,
                cidr=chosen.cidr,
                header_allow=(rendered.destination.header_allow & chosen.header_allow) | reserved,
            )
            rendered = replace(
                rendered,
                destination=narrowed,
                max_bytes=min(rendered.max_bytes, policy.body["result"]["max_bytes"]),
                bounds=replace(
                    rendered.bounds,
                    max_response_bytes=min(
                        rendered.bounds.max_response_bytes, policy.body["result"]["max_bytes"]
                    ),
                ),
            )
            target = operation.after["url"]["path"]
        else:
            if self.open_call is None:
                raise AdmissionRefused("params_invalid")
            call = self.open_call
            url = str(canonical_url(call.canonical_url))
            chosen = self._destination(destinations, call.method, url)
            maximum = policy.body["result"]["max_bytes"]
            rendered = OperationRequest(
                call.method,
                url,
                chosen,
                list(self.headers),
                call.body,
                Bounds(max_response_bytes=maximum),
                maximum,
                None,
                [],
                False,
                "deny",
                [],
            )
            target = chosen.path
        _require(len(rendered.body) <= policy.body["request"]["max_bytes"], "params_invalid")
        token_destination = None
        if stored.record.kind == "oauth2-client-credentials":
            token_destination = self._destination(
                destinations, "POST", stored.record.kind_params["token_endpoint"]
            )
        self._call = PreparedBrokerCall(
            stored,
            SecretVersion(
                scope.installation_id, scope.team_id, stored.record.secret_id, stored.active_version
            ),
            operation,
            rendered,
            policy,
            token_destination,
            target,
        )
        self._forest, self._tx = forest, tx

    def _destination(self, records_, method, url) -> Destination:
        last = None
        for record in records_:
            try:
                match_destination(
                    record.destination,
                    method,
                    url,
                    internal_destinations=self.internal_destinations,
                )
            except EgressRefused as refused:
                last = refused
                continue
            return record.destination
        if last is not None:
            raise last
        raise AdmissionRefused("destination_not_in_scope")

    async def check(self, tx: TransactionManager, dispatch: Dispatch) -> None:
        if self._tx is not tx or self._forest is None or self._call is None:
            raise RuntimeError("prepare broker authority in this transaction first")
        _require(dispatch.dispatch_id == self.dispatch_id, "operation_not_allowed")
        if self._call.stored.record.backend == "onepassword":
            if self.backend_version_check is None:
                raise AdmissionRefused("custody_unavailable", 503)
            # M1 compares the live item version with this approved version.
            # The callback takes no new authority locks. Custody open checks
            # it again after dispatching commits, before credential release.
            version = self._call.secret
            await self.backend_version_check(
                SealContext(
                    version.installation_id, version.team_id, version.secret_id, version.version
                )
            )
        # This is the final awaited authority read. The following expiry and
        # policy checks take no locks and use a live post-wait clock.
        await self.fence.check(tx, self.admission.installation)
        try:
            alive = self._forest.check(clock=self.clock, max_ttl_s=self.derived_max_ttl_s)
        except derived_lineage.LineageRefused as refused:
            raise AdmissionRefused(refused.code) from None
        _require(self.admission.grant_id in alive, "grant_revoked")
        _require(self._call.policy.window_open(self.clock()), "policy_window_closed")
        _require(
            self._call.policy.attestation_satisfied(self.attestation), "attestation_unavailable"
        )
