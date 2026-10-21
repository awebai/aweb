"""Transactional containment (§12), after the caller's installation and role fences.

Ancestry is locked before descendant selection. Issuance uses the same locks,
so a concurrent child is either selected or refused. B2 revocations and custody
writes commit together. No audit availability predicate is consulted here.
"""

import hashlib
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from aweb_naapp.idempotency import IdempotencyConflict, IdempotencyExpired, claim
from aweb_naapp.roles import hold_role, principal_key
from aweb_naapp.runtime.approvals import Approvals
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp.runtime.passkeys import Passkeys
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, use_approvals
from aweb_secrets.containment_state import ContainmentRefused
from aweb_secrets.containment_state import require_enabled as require_enabled
from aweb_secrets.custody import Custody, SealContext
from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory
from aweb_secrets.revisions import bump_config_revision
from aweb_secrets.tokens import TokenCache


async def _lock_tree(
    tx: TransactionManager,
    installation_id: str,
    team_id: str,
    secret_id: str,
    *,
    lock_grants: bool = True,
) -> tuple[str, ...]:
    ancestors = await derived_lineage.lock_ancestry(tx, installation_id, team_id, secret_id)
    if not ancestors:
        raise ContainmentRefused("secret_unknown", 404)
    rows = await tx.fetch_all(
        """
        WITH RECURSIVE descendants AS (
            SELECT $3::text AS secret_id, ARRAY[$3::text] AS path
            UNION ALL
            SELECT d.secret_id, a.path || d.secret_id FROM descendants a
            JOIN {{tables.derived_secrets}} d ON d.parent_secret_id=a.secret_id
            WHERE d.installation_id=$1 AND d.team_id=$2
              AND NOT d.secret_id=ANY(a.path)
        ) SELECT secret_id FROM descendants ORDER BY path
        """,
        installation_id,
        team_id,
        secret_id,
    )
    ids = tuple(row["secret_id"] for row in rows)
    for descendant_id in ids[1:]:
        await derived_lineage.lock_ancestry(tx, installation_id, team_id, descendant_id)
    if lock_grants:
        await tx.fetch_all(
            "SELECT grant_id FROM {{tables.grants}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])"
            " ORDER BY grant_id FOR SHARE",
            installation_id,
            team_id,
            list({node.secret.record.secret_id for node in ancestors} | set(ids)),
        )
    return ids


async def _disable(
    tx: TransactionManager,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    secret_ids: tuple[str, ...],
) -> None:
    for secret_id in secret_ids:
        await tx.execute(
            "UPDATE {{tables.secrets}} SET state='disabled', updated_at=NOW()"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3 AND state<>'disabled'",
            installation_id,
            team_id,
            secret_id,
        )
        await custody.disable(
            tx,
            installation_id=installation_id,
            team_id=team_id,
            secret_id=secret_id,
        )


async def disable_secret_tree(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    revoked_by: str,
) -> tuple[str, ...]:
    ids = await _lock_tree(tx, installation_id, team_id, secret_id)
    await use_approvals.revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
        revoked_by=revoked_by,
        reason="secret_disabled",
    )
    await _disable(
        tx,
        custody,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
    )
    await bump_config_revision(tx, installation_id)
    return ids


async def replace_value_consequences(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    secret_id: str,
    current_version: int,
    revoked_by: str,
) -> tuple[str, ...]:
    """S10 calls before activation; returned IDs are evicted only after commit."""
    ids = await _lock_tree(tx, installation_id, team_id, secret_id)
    await use_approvals.void_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_id=secret_id,
        current_version=current_version,
        revoked_by=revoked_by,
    )
    await use_approvals.revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids[1:],
        revoked_by=revoked_by,
        reason="secret_version_changed",
    )
    await _disable(
        tx,
        custody,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids[1:],
    )
    return ids


async def disable_installation(
    tx: TransactionManager,
    approvals: Approvals,
    custody: Custody,
    *,
    installation_id: str,
    team_id: str,
    revoked_by: str,
) -> tuple[str, ...]:
    """One local flag survives remote grant refreshes. Fence held first."""
    rows = await tx.fetch_all(
        "SELECT secret_id FROM {{tables.secrets}} WHERE installation_id=$1 AND team_id=$2"
        " ORDER BY secret_id",
        installation_id,
        team_id,
    )
    ids = tuple(row["secret_id"] for row in rows)
    await use_approvals.revoke_use_approvals(
        tx,
        approvals,
        installation_id=installation_id,
        team_id=team_id,
        secret_ids=ids,
        revoked_by=revoked_by,
        reason="installation_disabled",
    )
    await tx.execute(
        "INSERT INTO {{tables.containment_installations}} (installation_id, team_id, disabled_at)"
        " VALUES ($1,$2,NOW()) ON CONFLICT (installation_id, team_id)"
        " DO UPDATE SET disabled_at=EXCLUDED.disabled_at",
        installation_id,
        team_id,
    )
    await bump_config_revision(tx, installation_id)
    return ids


@dataclass(frozen=True)
class ContainmentResult:
    receipt_id: str
    action: str
    target: str | None
    affected_secret_ids: tuple[str, ...]


ACTIONS = {
    "revoke-grant": "grant.revoked",
    "revoke-approvals": "credential.revoked",
    "disable-secret": "resource.disabled",
    "disable-installation": "installation.disabled",
    "deregister-runner": "runner.deregistered",
    "revoke-approver": "credential.revoked",
}
GovernanceEnqueue = Callable[..., Awaitable[UUID]]
RunnerDeregistration = Callable[..., Awaitable[object]]


class Containment:
    """Services shared by containment actions and S10 confirmation callbacks."""

    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        fence: InstallationFence,
        approvals: Approvals,
        custody: Custody,
        passkeys: Passkeys,
        directory: OwnerDirectory,
        tokens: TokenCache,
        governance: GovernanceEnqueue,
        deregister_runner: RunnerDeregistration | None = None,
    ) -> None:
        self.db = db
        self.fence = fence
        self.approvals = approvals
        self.custody = custody
        self.passkeys = passkeys
        self.directory = directory
        self.tokens = tokens
        self.governance = governance
        self.deregister_runner = deregister_runner

    async def evict(self, installation_id: str, team_id: str, ids: tuple[str, ...]) -> None:
        for secret_id in ids:
            await self.tokens.evict_secret(
                installation_id=installation_id,
                team_id=team_id,
                secret_id=secret_id,
            )

    async def by_member(
        self,
        *,
        grant: Grant,
        principal: Principal,
        request_id: str,
        action: str,
        target: str | None = None,
        credential_id: bytes | None = None,
        signed_trace_id: str | None = None,
    ) -> ContainmentResult:
        if grant.team_id != principal.team_id:
            raise ContainmentRefused("owner_required")
        self._validate(request_id, action, target, credential_id)
        await self.fence.refresh(principal.team_id)
        key = principal_key(principal)
        actor = {
            "authority_mode": "team_cert",
            "attestations": [],
            "did_key": principal.did_key,
            "certificate_id": principal.certificate_id,
        }
        if principal.did_aw:
            actor["did_aw"] = principal.did_aw
        async with self.db.transaction() as tx:
            installed = await self.fence.admit(tx, grant)
            if not await hold_role(tx, key, OWNER_ROLE):
                raise ContainmentRefused("owner_required")
            result = await self._act(
                tx,
                installation_id=installed.installation_id,
                team_id=installed.team_id,
                authorized_by=key.principal_did,
                request_id=request_id,
                action=action,
                target=target,
                credential_id=credential_id,
                authority="team_cert",
                actor=actor,
                signed_trace_id=signed_trace_id,
            )
        await self.evict(installed.installation_id, installed.team_id, result.affected_secret_ids)
        return result

    @staticmethod
    def _validate(
        request_id: str,
        action: str,
        target: str | None,
        credential_id: bytes | None,
    ) -> None:
        if action not in ACTIONS:
            raise ContainmentRefused("containment_action_invalid", 400)
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 200:
            raise ContainmentRefused("request_invalid", 400)
        if action == "disable-installation":
            if target is not None:
                raise ContainmentRefused("containment_target_invalid", 400)
        elif not isinstance(target, str) or not 1 <= len(target) <= 512:
            raise ContainmentRefused("containment_target_invalid", 400)
        if credential_id is not None and (action != "revoke-approver" or not credential_id):
            raise ContainmentRefused("containment_target_invalid", 400)

    async def _act(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        authorized_by: str,
        request_id: str,
        action: str,
        target: str | None,
        credential_id: bytes | None,
        authority: str,
        actor: Mapping[str, Any],
        signed_trace_id: str | None = None,
        evidence_sha256: str | None = None,
    ) -> ContainmentResult:
        request_hash = hashlib.sha256(
            json.dumps(
                {
                    "action": action,
                    "target": target,
                    "credential_id": credential_id.hex() if credential_id is not None else None,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).digest()
        receipt_id = "cnt_" + secrets.token_urlsafe(16)
        try:
            receipt = await claim(
                tx,
                key=(installation_id, authorized_by, request_id),
                request_hash=request_hash,
                receipt_ref=receipt_id,
                retention=timedelta(days=30),
            )
        except IdempotencyConflict:
            raise ContainmentRefused("idempotency_conflict", 409) from None
        except IdempotencyExpired:
            raise ContainmentRefused("idempotency_expired", 410) from None
        if not receipt.created:
            row = await tx.fetch_one(
                "SELECT action, target, affected_secret_ids FROM {{tables.containment_receipts}}"
                " WHERE receipt_id=$1 AND installation_id=$2 AND team_id=$3",
                receipt.receipt_ref,
                installation_id,
                team_id,
            )
            if row is None:
                raise RuntimeError("containment receipt missing")
            return ContainmentResult(
                receipt.receipt_ref,
                row["action"],
                row["target"],
                tuple(json.loads(row["affected_secret_ids"])),
            )
        kwargs = dict(installation_id=installation_id, team_id=team_id, revoked_by=authorized_by)
        if action == "disable-secret":
            assert target is not None
            ids = await disable_secret_tree(
                tx, self.approvals, self.custody, secret_id=target, **kwargs
            )
        elif action == "disable-installation":
            ids = await disable_installation(tx, self.approvals, self.custody, **kwargs)
        elif action == "revoke-grant":
            from aweb_secrets.derived_containment import revoke_grant_tree

            ids = await revoke_grant_tree(
                tx,
                self.approvals,
                self.custody,
                grant_id=target,
                **kwargs,
            )
        elif action == "revoke-approvals":
            row = await tx.fetch_one(
                "SELECT secret_id FROM {{tables.use_approvals}}"
                " WHERE installation_id=$1 AND team_id=$2 AND approval_id=$3",
                installation_id,
                team_id,
                target,
            )
            if row is None:
                raise ContainmentRefused("approval_unknown", 404)
            await _lock_tree(tx, installation_id, team_id, row["secret_id"])
            await self.approvals.revoke_many(
                [target],
                revoked_by=authorized_by,
                reason="approval_revoked",
                tx=tx,
            )
            ids = ()
        elif action == "deregister-runner":
            if self.deregister_runner is None:
                raise ContainmentRefused("runner_unavailable", 503)
            await self.deregister_runner(
                tx,
                installation_id,
                target,
                now=datetime.now(UTC),
            )
            ids = ()
        else:
            raise ContainmentRefused("approver_unavailable", 503)
        payload = {
            "act": ACTIONS[action],
            "direction": "narrowing",
            "authority": authority,
            "resource_type": action.removeprefix("disable-")
            .removeprefix("revoke-")
            .removeprefix("deregister-"),
        }
        if target is not None:
            payload["resource_ref"] = target
        if evidence_sha256 is not None:
            payload["approval_evidence_sha256"] = evidence_sha256
        await self.governance(
            tx,
            team_id=team_id,
            payload=payload,
            actor=actor,
            occurred_at=datetime.now(UTC),
            result_status="success",
            signed_trace_id=signed_trace_id,
        )
        await tx.execute(
            "INSERT INTO {{tables.containment_receipts}}"
            " (receipt_id,installation_id,team_id,action,target,affected_secret_ids)"
            " VALUES ($1,$2,$3,$4,$5,$6)",
            receipt_id,
            installation_id,
            team_id,
            action,
            target,
            json.dumps(ids),
        )
        return ContainmentResult(receipt_id, action, target, tuple(ids))

    async def replacement_consequences(
        self,
        tx: TransactionManager,
        *,
        old: SealContext,
        new: SealContext,
        revoked_by: str,
    ) -> tuple[str, ...]:
        if (old.installation_id, old.team_id, old.secret_id) != (
            new.installation_id,
            new.team_id,
            new.secret_id,
        ):
            raise ContainmentRefused("replacement_scope_mismatch")
        if old.version == new.version:
            return ()
        return await replace_value_consequences(
            tx,
            self.approvals,
            self.custody,
            installation_id=new.installation_id,
            team_id=new.team_id,
            secret_id=new.secret_id,
            current_version=new.version,
            revoked_by=revoked_by,
        )

    async def prepare_replacements(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        secret_ids: tuple[str, ...],
    ) -> None:
        paths = {
            secret_id: await derived_lineage.ancestry_ids(
                tx,
                installation_id,
                team_id,
                secret_id,
            )
            for secret_id in set(secret_ids)
        }
        if any(not path for path in paths.values()):
            raise ContainmentRefused("secret_unknown", 404)
        # A requested parent subsumes every requested descendant. Sorting the
        # immutable full paths also orders disjoint sibling subtrees correctly.
        minimal = [
            secret_id
            for secret_id, path in paths.items()
            if not any(ancestor in paths for ancestor in path[:-1])
        ]
        locked: set[str] = set()
        for secret_id in sorted(minimal, key=lambda root: paths[root]):
            locked.update(
                await _lock_tree(
                    tx,
                    installation_id,
                    team_id,
                    secret_id,
                    lock_grants=False,
                )
            )
            locked.update(
                await derived_lineage.ancestry_ids(
                    tx,
                    installation_id,
                    team_id,
                    secret_id,
                )
            )
        await tx.fetch_all(
            "SELECT grant_id FROM {{tables.grants}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])"
            " ORDER BY grant_id FOR SHARE",
            installation_id,
            team_id,
            list(locked),
        )

    async def reenable(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        target_kind: str,
        target_ref: str,
    ) -> None:
        """S10-only callback after passkey confirmation and ancestry preparation.

        No API containment action calls this method. Enabling one record never
        enables a descendant or restores a destroyed version.
        """
        if target_kind == "installation":
            if target_ref != installation_id:
                raise ContainmentRefused("installation_unknown", 404)
            await tx.execute(
                "UPDATE {{tables.containment_installations}} SET disabled_at=NULL"
                " WHERE installation_id=$1 AND team_id=$2",
                installation_id,
                team_id,
            )
            return
        if target_kind != "secret":
            raise ContainmentRefused("reenable_target_unsupported", 400)
        from aweb_secrets import records

        stored = await records.secret_by_ref(tx, installation_id, team_id, target_ref)
        if stored is None:
            raise ContainmentRefused("secret_unknown", 404)
        secret_id = stored.record.secret_id
        try:
            async with tx.transaction() as attempt:
                await attempt.execute(
                    "UPDATE {{tables.secrets}} SET state='active', updated_at=NOW()"
                    " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3",
                    installation_id,
                    team_id,
                    secret_id,
                )
                nodes = await derived_lineage.lock_ancestry(
                    attempt, installation_id, team_id, secret_id
                )
                await derived_lineage.check_ancestry(attempt, nodes)
                await self.custody.enable(
                    attempt,
                    installation_id=installation_id,
                    team_id=team_id,
                    secret_id=secret_id,
                )
        except derived_lineage.LineageRefused as refused:
            raise ContainmentRefused(refused.code) from None
