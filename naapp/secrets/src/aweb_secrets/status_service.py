"""Read-only broker receipt lookup under current installation/read authority.

This service owns no dispatch machine, opener, cache or approval consumer.
Original provenance is never relabeled by a renewed caller certificate. Job-run
registry/reconciliation lookup will extend this service when those associations
are composed; their absent implementation grants no fallback read authority.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from aweb_naapp.dispatch import State
from aweb_naapp.roles import hold_role, principal_key, roles_of
from aweb_naapp.runtime.approvals import ApprovalRefused, Approvals, ApprovalState
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.installation import InstallationFence, InstallationRefused
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets import records, tool_results
from aweb_secrets.grant import is_secrets_role
from aweb_secrets.member_types import ToolReply
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.run_status import RunStatus

_APPROVAL_STATES = {
    ApprovalState.PENDING: "awaiting_approval",
    ApprovalState.APPROVED: "approved",
    ApprovalState.REJECTED: "denied",
    ApprovalState.EXPIRED: "expired",
    ApprovalState.REVOKED: "revoked",
    ApprovalState.CONSUMED: "admitted",
}
_CLOSING_CODES = {
    State.APPROVAL_DENIED: "approval_denied",
    State.APPROVAL_EXPIRED: "approval_expired",
}


class UseStatus:
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        fence: InstallationFence,
        approvals: Approvals | None = None,
        runs: RunStatus | None = None,
    ) -> None:
        self._db, self._fence, self._approvals = db, fence, approvals
        self._runs = runs

    async def get(self, *, ref: str, authorization: Authorization) -> ToolReply:
        """Look up a caller's ID or an authorized opaque receipt, never send.

        Owner inspection needs the opaque locator. Missing records, other
        principals and revoked read grants all share one 404 shape. Installation
        authority failures preserve the fence's safe code/status.
        """
        principal, grant = authorization.principal, authorization.grant
        if principal.team_id != grant.team_id:
            return self._missing()
        if authorization.tool.name != "status":
            return ToolReply(403, tool_results.refused("grant_missing", request_id=None))
        try:
            async with self._db.transaction() as tx:
                scope = await self._fence.admit(tx, grant)
                key = principal_key(principal)
                roles = []
                for role in sorted(await roles_of(tx, key)):
                    if (role == OWNER_ROLE or is_secrets_role(role)) and await hold_role(
                        tx, key, role
                    ):
                        roles.append(role)
                row = await tx.fetch_one(
                    "SELECT i.*,c.dispatch_id,d.state,d.result FROM {{tables.intents}} i"
                    " JOIN {{tables.use_contexts}} c USING (intent_id,installation_id,team_id,install_generation)"
                    " JOIN {{tables.dispatches}} d USING (dispatch_id)"
                    " LEFT JOIN {{tables.use_approvals}} a ON a.intent_id=i.intent_id"
                    " WHERE i.installation_id=$1 AND i.team_id=$2"
                    " AND c.app_id=$3 AND c.tool='request'"
                    " AND ((i.request_id=$4 AND i.principal_did=$5)"
                    " OR ((i.intent_id=$4 OR a.approval_ref=$4) AND (i.principal_did=$5 OR $6)))"
                    " ORDER BY (i.intent_id=$4) DESC LIMIT 1",
                    scope.installation_id,
                    scope.team_id,
                    scope.app_id,
                    ref,
                    key.principal_did,
                    OWNER_ROLE in roles,
                )
                reply = self._missing()
                if row is None and self._runs is not None:
                    reply = await self._runs.get_in(
                        tx, ref=ref, scope=scope, principal_did=key.principal_did, roles=roles
                    )
                if row is not None and (
                    OWNER_ROLE in roles
                    or await self._read_granted(tx, row, key.principal_did, roles)
                ):
                    if row["install_generation"] != scope.generation:
                        reply = ToolReply(
                            409, tool_results.refused("generation_superseded", request_id=None)
                        )
                    else:
                        reply = await self._reply(
                            tx, row, ref, own=row["principal_did"] == key.principal_did
                        )
                # SQL/approval reads may wait: sample F6 after all of them.
                await self._fence.check(tx, scope)
                return reply
        except InstallationRefused as refused:
            return ToolReply(refused.status, tool_results.refused(refused.code, request_id=None))

    @staticmethod
    async def _read_granted(tx, row, principal_did: str, roles: list[str]) -> bool:
        grants = await records.active_grants(
            tx,
            row["installation_id"],
            row["secret_id"],
            principal_did=principal_did,
            roles=roles,
        )
        return any(
            grant.grant_id == row["grant_id"] and grant.capability == "use" for grant in grants
        )

    async def _reply(
        self, tx: TransactionManager, row: Mapping[str, Any], ref: str, *, own: bool
    ) -> ToolReply:
        receipt = {"request_id": row["request_id"], "request_ref": row["intent_id"]}
        state = State(row["state"])
        link = await tx.fetch_one(
            "SELECT approval_ref FROM {{tables.use_approvals}} WHERE intent_id=$1"
            " AND installation_id=$2 AND team_id=$3 AND dispatch_id=$4",
            row["intent_id"],
            row["installation_id"],
            row["team_id"],
            row["dispatch_id"],
        )
        if state is State.AWAITING_APPROVAL or (link is not None and link["approval_ref"] == ref):
            if link is None or self._approvals is None:
                return self._unavailable(receipt)
            try:
                view = await self._approvals.requester_view(
                    link["approval_ref"], row["principal_did"]
                )
            except ApprovalRefused:
                return self._unavailable(receipt)
            current = _APPROVAL_STATES[view.approval_state]
            if current in {"denied", "expired", "revoked"} and ref != link["approval_ref"]:
                return ToolReply(
                    200, {"state": "refused", **receipt, "code": f"approval_{current}"}
                )
            body = {"state": current, **receipt}
            if current == "approved":
                body["next"] = "resubmit"
            elif current == "awaiting_approval":
                body["approval_ref"] = link["approval_ref"]
            return ToolReply(200, body)
        if state in _CLOSING_CODES:
            return ToolReply(200, {"state": "refused", **receipt, "code": _CLOSING_CODES[state]})
        if state is State.REFUSED:
            # S3.refuse stores no result. The fixed refusal code lives in the
            # transactional operational record, never in exception text.
            event = await tx.fetch_value(
                "SELECT payload FROM {{tables.broker_use_events}} WHERE dispatch_id=$1"
                " AND installation_id=$2 AND team_id=$3 AND action='refused'"
                " ORDER BY occurred_at DESC LIMIT 1",
                row["dispatch_id"],
                row["installation_id"],
                row["team_id"],
            )
            payload = json.loads(event) if isinstance(event, str) else event
            if not isinstance(payload, Mapping) or not isinstance(payload.get("refusal_code"), str):
                return self._unavailable(receipt)
            return ToolReply(200, {"state": "refused", **receipt, "code": payload["refusal_code"]})
        if (
            state
            in {
                State.COMPLETED,
                State.RECONCILED_COMPLETED,
                State.RECONCILED_FAILED,
                State.RECONCILED_UNKNOWN,
            }
            and row["result"] is not None
        ):
            stored = json.loads(row["result"]) if isinstance(row["result"], str) else row["result"]
            allowed = (
                {"completed", "result_withheld"} if state is State.COMPLETED else {state.value}
            )
            if (
                not isinstance(stored, Mapping)
                or stored.get("state") not in allowed
                or any(stored.get(key) != value for key, value in receipt.items())
            ):
                return self._unavailable(receipt)
            body = {**receipt, "state": stored["state"]}
            for field in ("result", "code"):
                # Governance inspection exposes state/code, not another
                # member's projected entity (secrets §11.2).
                if field == "result" and not own:
                    continue
                if field in stored:
                    body[field] = copy.deepcopy(stored[field])
            return ToolReply(200, body)
        if state is State.COMPLETED:
            return self._unavailable(receipt)
        if state is State.OUTCOME_UNKNOWN:
            return ToolReply(200, tool_results.outcome_unknown(**receipt))
        body = {"state": state.value, **receipt}
        if state is State.NOT_SENT:
            body["next"] = "resubmit"
        # Status always uses HTTP 200 for an accessible stored outcome.
        return ToolReply(200, body)

    @staticmethod
    def _missing() -> ToolReply:
        return ToolReply(404, tool_results.refused("not_found", request_id=None))

    @staticmethod
    def _unavailable(receipt: Mapping[str, str]) -> ToolReply:
        return ToolReply(
            503, {"state": "refused", **receipt, "code": "release_context_unavailable"}
        )
