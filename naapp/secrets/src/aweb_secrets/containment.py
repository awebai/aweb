"""Transactional containment (§12), after the caller's installation and role fences.

Ancestry is locked before descendant selection. Issuance uses the same locks,
so a concurrent child is either selected or refused. B2 revocations and custody
writes commit together. No audit availability predicate is consulted here.
"""

import hashlib
import json
import logging
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from aweb_naapp.console import ConsoleSession
from aweb_naapp.idempotency import IdempotencyConflict, IdempotencyExpired, claim
from aweb_naapp.roles import hold_role, principal_key
from aweb_naapp.runtime.approvals import Approvals
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
    Passkeys,
    RetirementRefused,
)
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, use_approvals
from aweb_secrets.containment_state import ContainmentRefused
from aweb_secrets.containment_state import require_enabled as require_enabled
from aweb_secrets.custody import Custody, SealContext
from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory, owner_scope
from aweb_secrets.revisions import bump_config_revision
from aweb_secrets.tokens import TokenCache

_LOG = logging.getLogger(__name__)


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
    current_version: int | None,
    revoked_by: str,
) -> tuple[str, ...]:
    """S10 calls before activation; returned IDs are evicted only after commit."""
    ids = await _lock_tree(tx, installation_id, team_id, secret_id)
    if current_version is None:
        await use_approvals.revoke_use_approvals(
            tx,
            approvals,
            installation_id=installation_id,
            team_id=team_id,
            secret_ids=ids,
            revoked_by=revoked_by,
            reason="secret_version_changed",
        )
    else:
        await use_approvals.void_use_approvals(
            tx,
            approvals,
            installation_id=installation_id,
            team_id=team_id,
            secret_id=secret_id,
            current_version=current_version,
            revoked_by=revoked_by,
            descendant_secret_ids=ids[1:],
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
                if action != "revoke-approvals" or target is None:
                    raise ContainmentRefused("owner_required")
                await self._authorize_member_approver(
                    tx,
                    installed,
                    key.principal_did,
                    target,
                )
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
            await self.fence.check(tx, installed)
        await self.evict(installed.installation_id, installed.team_id, result.affected_secret_ids)
        return result

    async def by_console(
        self,
        *,
        admitted: AdmittedInstallation,
        session: ConsoleSession,
        request_id: str,
        action: str,
        target: str | None = None,
        credential_id: bytes | None = None,
    ) -> ContainmentResult:
        """Narrow under the current LOGIN proof, without a fresh ceremony.

        The human router supplies S4 session/CSRF and authoritative installation
        lookup. All authority, effects and the governance outbox share this tx.
        """
        self._validate(request_id, action, target, credential_id)
        async with self.db.transaction() as tx:
            await self.fence.check(tx, admitted)
            self._session_unexpired(session)
            await self.authorize_console(
                tx, admitted=admitted, session=session, action=action, target=target
            )
            await self._session_current(tx, session)
            try:
                commitment = await self.passkeys.evidence_commitment(
                    session.evidence_ref,
                    context=PasskeyInstallationContext(
                        admitted.app_id,
                        admitted.team_id,
                        admitted.installation_id,
                        admitted.generation,
                    ),
                    scope=session.scope,
                    subject=session.subject,
                    purpose="login",
                    tx=tx,
                )
            except PasskeyProofUnavailable:
                raise ContainmentRefused("login_evidence_unavailable", 401) from None
            result = await self._act(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                authorized_by=session.subject,
                request_id=request_id,
                action=action,
                target=target,
                credential_id=credential_id,
                authority="passkey_session",
                actor={"authority_mode": "system", "attestations": []},
                evidence_sha256=commitment,
            )
            await self._session_current(tx, session)
            await self.fence.check(tx, admitted)
            self._session_unexpired(session)
        try:
            await self.evict(admitted.installation_id, admitted.team_id, result.affected_secret_ids)
        except Exception:
            # The effect is committed. Cleanup failure must not invite a replay;
            # S13 checks active custody before using a cached token.
            _LOG.warning("post-containment cache cleanup unavailable")
        return result

    @staticmethod
    def _session_unexpired(session: ConsoleSession) -> None:
        if session.expires_at <= datetime.now(UTC):
            raise ContainmentRefused("console_session_required", 401)

    @staticmethod
    async def _session_current(tx: TransactionManager, session: ConsoleSession) -> None:
        # F6, application authority and exact LOGIN credential precede this
        # session lock. Logout only updates the session row. Holding it makes
        # logout serialize with the effect, while a completed logout is seen.
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at FROM {{tables.console_sessions}}"
            " WHERE token_sha256=$1 FOR SHARE",
            session.token_sha256,
        )
        # Check the live clock AFTER any row-lock wait, and bind every field
        # back to the exact token S4 authenticated, never another live session.
        if (
            row is None
            or row["closed_at"] is not None
            or (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            != (session.scope, session.subject, session.evidence_ref, session.expires_at)
            or row["expires_at"] <= datetime.now(UTC)
        ):
            raise ContainmentRefused("console_session_required", 401)

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

            assert target is not None

            if not await tx.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM {{tables.grants}}"
                " WHERE installation_id=$1 AND team_id=$2 AND grant_id=$3)",
                installation_id,
                team_id,
                target,
            ):
                raise ContainmentRefused("grant_unknown", 404)
            ids = await revoke_grant_tree(
                tx,
                self.approvals,
                self.custody,
                grant_id=target,
                **kwargs,
            )
        elif action == "revoke-approvals":
            assert target is not None
            sources = await use_approvals.use_approval_secret_ids(
                tx,
                installation_id=installation_id,
                team_id=team_id,
                approval_id=target,
            )
            if not sources:
                raise ContainmentRefused("approval_unknown", 404)
            for source in sources:
                await _lock_tree(tx, installation_id, team_id, source)
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
            assert target is not None
            await self._revoke_approver(
                tx,
                installation_id=installation_id,
                team_id=team_id,
                target=target,
                credential_id=credential_id,
                authorized_by=authorized_by,
            )
            ids = ()
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

    async def invalidate_value_consequences(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        secret_id: str,
        revoked_by: str,
    ) -> tuple[str, ...]:
        """Invalidate a prepared dependent root with no replacement version.

        S10 prepares the complete forest and confirming approval before B2.
        This hook revokes every root version and disables descendants only;
        the caller clears the root's active version and destroys old material
        in the same transaction. Its existing disabled state is preserved.
        """
        return await replace_value_consequences(
            tx,
            self.approvals,
            self.custody,
            installation_id=installation_id,
            team_id=team_id,
            secret_id=secret_id,
            current_version=None,
            revoked_by=revoked_by,
        )

    async def prepare_replacements(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        secret_ids: tuple[str, ...],
        approval_ids: tuple[str, ...] = (),
    ) -> None:
        """Lock the complete replacement/reenable forest before B2 consumption.

        S10 includes its confirming approval in approval_ids. This conservative
        all-version union is held through every later per-root callback.
        """
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
        affected: set[str] = set()
        for secret_id in sorted(minimal, key=lambda root: paths[root]):
            tree = await _lock_tree(
                tx,
                installation_id,
                team_id,
                secret_id,
                lock_grants=False,
            )
            affected.update(tree)
            locked.update(tree)
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
        # Prelock a conservative superset across the FULL forest before S10
        # consumes its own confirmation or invokes any per-root callback.
        # Revocation later retains the root's version filter.
        associated_ids = await use_approvals.select_use_approval_ids(
            tx,
            installation_id=installation_id,
            team_id=team_id,
            secret_ids=tuple(affected),
        )
        await self.approvals.lock_many(
            tx,
            [*approval_ids, *associated_ids],
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
        # Resolve the mutable ref without locking the child before its parent.
        secret_id = await tx.fetch_value(
            "SELECT secret_id FROM {{tables.secrets}}"
            " WHERE installation_id=$1 AND team_id=$2 AND ref=$3",
            installation_id,
            team_id,
            target_ref,
        )
        if secret_id is None:
            raise ContainmentRefused("secret_unknown", 404)
        try:
            async with tx.transaction() as attempt:
                nodes = await derived_lineage.lock_ancestry(
                    attempt,
                    installation_id,
                    team_id,
                    secret_id,
                )
                if not nodes or nodes[-1].secret.record.ref != target_ref:
                    raise ContainmentRefused("secret_unknown", 404)
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
                # A confirmed empty root must be enabled before the owner can
                # stage a new binding. This restores no version: admission still
                # refuses it until a later confirmation activates a value.
                empty_root = (
                    len(nodes) == 1
                    and nodes[0].parent_secret_id is None
                    and nodes[0].secret.active_version is None
                )
                if not empty_root:
                    await derived_lineage.check_ancestry(attempt, nodes)
                await self.custody.enable(
                    attempt,
                    installation_id=installation_id,
                    team_id=team_id,
                    secret_id=secret_id,
                )
        except derived_lineage.LineageRefused as refused:
            raise ContainmentRefused(refused.code) from None

    async def _revoke_approver(
        self,
        tx: TransactionManager,
        *,
        installation_id: str,
        team_id: str,
        target: str,
        credential_id: bytes | None,
        authorized_by: str,
    ) -> None:
        owner = await tx.fetch_one(
            "SELECT scope, principal_did FROM {{tables.owner_principals}}"
            " WHERE installation_id=$1 AND team_id=$2 AND scope=$3",
            installation_id,
            team_id,
            target,
        )
        approver = await tx.fetch_one(
            "SELECT scope FROM {{tables.approvers}}"
            " WHERE installation_id=$1 AND team_id=$2 AND (approver_ref=$3 OR scope=$3)"
            " FOR UPDATE",
            installation_id,
            team_id,
            target,
        )
        scope = owner["scope"] if owner is not None else approver["scope"] if approver else None
        if scope is None:
            raise ContainmentRefused("approver_unknown", 404)
        subject = await tx.fetch_value(
            "SELECT subject FROM {{tables.passkey_approvers}}"
            " WHERE scope=$1 AND superseded_at IS NULL",
            scope,
        )
        if subject is None:
            raise ContainmentRefused("approver_unknown", 404)

        async def protect(guard_tx: TransactionManager, guarded_scope: str, holder: str) -> None:
            if owner is None:
                return
            # Losing one of multiple keys does not lock the owner out.
            if credential_id is not None and await guard_tx.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM {{tables.passkey_credentials}}"
                " WHERE subject=$1 AND credential_id<>$2 AND revoked_at IS NULL)",
                holder,
                credential_id,
            ):
                return
            owners = await self.directory.enrolled_owners(
                guard_tx,
                installation_id=installation_id,
                team_id=team_id,
            )
            if not any(p.principal_did != owner["principal_did"] for p in owners):
                raise RetirementRefused("last_owner_protected")

        # Removing a designation's covering record precedes B3/B2 retirement.
        # A partial key revocation preserves its record and remaining key.
        if approver is not None:
            if credential_id is None:
                remove = True
            else:
                remove = not await tx.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM {{tables.passkey_credentials}}"
                    " WHERE subject=$1 AND credential_id<>$2 AND revoked_at IS NULL)",
                    subject,
                    credential_id,
                )
            if remove:
                await tx.execute(
                    "DELETE FROM {{tables.approvers}}"
                    " WHERE installation_id=$1 AND team_id=$2 AND scope=$3",
                    installation_id,
                    team_id,
                    scope,
                )
        kwargs = dict(scope=scope, subject=subject, authorized_by=authorized_by, protect=protect)
        try:
            if credential_id is None:
                await self.passkeys.retire_in(tx, **kwargs)
            else:
                await self.passkeys.revoke_passkey_in(tx, credential_id=credential_id, **kwargs)
        except RetirementRefused as refused:
            raise ContainmentRefused(refused.reason) from None
        await bump_config_revision(tx, installation_id)

    async def authorize_console(
        self,
        tx: TransactionManager,
        *,
        admitted: AdmittedInstallation,
        session: ConsoleSession,
        action: str,
        target: str | None,
    ) -> bool:
        """Authorize the action and retain its exact login credential through tx.

        The caller admits the installation first and uses S4 for session expiry
        and CSRF. Application authority locks precede B3's scope/credential locks.
        Return whether the authorized caller is an owner.
        """
        owner = await self._console_authority(
            tx,
            admitted=admitted,
            session=session,
            action=action,
            target=target,
        )
        if not await self.passkeys.login_evidence_is_current(
            session.scope,
            session.subject,
            session.evidence_ref,
            tx=tx,
        ):
            raise ContainmentRefused("login_evidence_unavailable", 401)
        return owner

    async def _console_authority(
        self,
        tx: TransactionManager,
        *,
        admitted: AdmittedInstallation,
        session: ConsoleSession,
        action: str,
        target: str | None,
    ) -> bool:
        owner = await self.directory.owner_of(tx, session.scope)
        if (
            owner is not None
            and owner.team_id == admitted.team_id
            and session.scope
            == owner_scope(admitted.installation_id, owner.team_id, owner.principal_did)
            and await hold_role(tx, owner, OWNER_ROLE)
        ):
            # Pre-acquire normal resource authority before B3 login evidence.
            await self._prepare_action(tx, admitted, action, target)
            return True
        if action in {"disable-installation", "deregister-runner"}:
            raise ContainmentRefused("owner_required")
        secret_ids = await self._prepare_action(tx, admitted, action, target)
        row = await tx.fetch_one(
            "SELECT approver_ref, covers FROM {{tables.approvers}}"
            " WHERE installation_id=$1 AND team_id=$2 AND scope=$3"
            + (" FOR UPDATE" if action == "revoke-approver" else " FOR SHARE"),
            admitted.installation_id,
            admitted.team_id,
            session.scope,
        )
        if row is None:
            raise ContainmentRefused("approver_required")
        if action == "revoke-approver":
            if target not in {session.scope, row["approver_ref"]}:
                raise ContainmentRefused("coverage_denied")
            return False
        if not secret_ids:
            raise ContainmentRefused("coverage_denied")
        for secret_id in secret_ids:
            ancestry = await derived_lineage.ancestry_ids(
                tx,
                admitted.installation_id,
                admitted.team_id,
                secret_id,
            )
            if not set(ancestry).intersection(json.loads(row["covers"])):
                raise ContainmentRefused("coverage_denied")
        return False

    async def _prepare_action(
        self,
        tx: TransactionManager,
        admitted: AdmittedInstallation,
        action: str,
        target: str | None,
    ) -> tuple[str, ...]:
        secret_ids: tuple[str, ...]
        if action == "disable-secret":
            secret_ids = (target,) if target is not None else ()
        elif action == "revoke-grant":
            secret_id = await tx.fetch_value(
                "SELECT secret_id FROM {{tables.grants}}"
                " WHERE installation_id=$1 AND team_id=$2 AND grant_id=$3",
                admitted.installation_id,
                admitted.team_id,
                target,
            )
            secret_ids = (secret_id,) if secret_id is not None else ()
        elif action == "revoke-approvals":
            assert target is not None
            secret_ids = await use_approvals.use_approval_secret_ids(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                approval_id=target,
            )
        else:
            return ()
        if not secret_ids:
            raise ContainmentRefused("resource_unknown", 404)
        for secret_id in secret_ids:
            await _lock_tree(tx, admitted.installation_id, admitted.team_id, secret_id)
        return secret_ids

    async def _authorize_member_approver(
        self,
        tx: TransactionManager,
        admitted: AdmittedInstallation,
        principal_did: str,
        approval_id: str,
    ) -> None:
        from aweb_secrets.approvers import approvers_for_secrets

        secret_ids = await self._prepare_action(tx, admitted, "revoke-approvals", approval_id)
        scope_sets = []
        for secret_id in secret_ids:
            ids = await derived_lineage.ancestry_ids(
                tx,
                admitted.installation_id,
                admitted.team_id,
                secret_id,
            )
            covering = await approvers_for_secrets(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                secret_ids=ids,
            )
            scopes = {record.scope for record in covering if record.principal_did == principal_did}
            if not scopes:
                raise ContainmentRefused("approver_required")
            scope_sets.append(scopes)
        # Retirement serializes on this B2 row. Read the committed candidate
        # and holder AFTER acquiring it, so a completed retirement is seen and
        # a concurrent retirement commits after this narrowing action.
        await self.approvals.lock_many(tx, [approval_id])
        approval = await self.approvals.get(approval_id)
        if approval is not None:
            current_scopes = set()
            for candidate in approval.candidates:
                if (
                    candidate.principal_did == principal_did
                    and candidate.retired_at is None
                    and await self.passkeys.is_current(candidate.scope, candidate.subject)
                ):
                    current_scopes.add(candidate.scope)
            if all(scopes.intersection(current_scopes) for scopes in scope_sets):
                return
        raise ContainmentRefused("approver_required")
