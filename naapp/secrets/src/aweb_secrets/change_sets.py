"""The change-set lifecycle (design §6.2-§6.3, decisions 54 and 61).

A drafted change set is inert. Its draft transaction records it, any sealed
values it brought in, and one B2 approval. A member's draft asks every
current owner; an owner's console draft asks that owner alone. The approval's
links go out only after the commit. A member drafts at most so many change
sets in a window, counted inside the draft transaction.

An owner's passkey decision is then confirmed, in one transaction and in the
order every writer takes its locks:
1. the installation fence (X9);
2. a hold on the deciding owner's secrets.owner role, so a concurrent
   revocation either waits for the confirmation or makes it refuse;
3. the change-set row, and the approval admitted once as owner evidence
   (Passkeys.owner_approval);
4. the four-eyes setting's row, read under its lock;
5. the configuration revision, claimed atomically, the last lock taken;
6. then each item applies.
The change set must still be for this installation, generation and team,
unexpired, and confirmed by an owner the setting in force allows.
A draft that expires or is cancelled revokes its approval and destroys its
sealed values. A kind whose apply does not exist yet is refused at draft
time, so no draft can be confirmed and then do nothing.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aweb_naapp.roles import PrincipalKey, assign, hold_role
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRefused,
    Approvals,
    Assurance,
    PendingApproval,
)
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    InstallationRefused,
)
from aweb_naapp.runtime.passkeys import (
    ContactChange,
    ContactChangeRefused,
    Designation,
    DesignationRefused,
    OwnerApproval,
    Passkeys,
)
from awid.utc_timestamps import parse_utc_seconds
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_secrets.approvers import approver_exists, record_approver
from aweb_secrets.change import (
    MAX_LIFETIME,
    ChangeRefused,
    check_confirmable,
    check_confirmer,
    validate_change,
)
from aweb_secrets.change_policy import four_eyes, lock_four_eyes, relax_four_eyes
from aweb_secrets.custody import Custody, SealContext
from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory, approver_scope, owner_scope
from aweb_secrets.revisions import claim_config_revision, config_revision

MIGRATIONS_PATH = Path(__file__).resolve().parent / "change_set_migrations"
MIGRATIONS_MODULE = "aweb_secrets_change_sets"

POLICY_PREFIX = "secrets.change"
# Kinds whose apply exists. The rest are refused at draft time until theirs does.
APPLICABLE_KINDS = frozenset({"role", "approver", "approver_contact", "change_set_policy"})


async def apply_change_set_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


@dataclass(frozen=True)
class DraftLimit:
    """At most ``count`` member drafts per drafting principal and installation in ``window``."""

    count: int
    window: timedelta


@dataclass(frozen=True)
class Confirmation:
    """A confirmed change set: the revision it moved to, and the approver
    designations and contact changes whose links and notices
    :meth:`ChangeSets.deliver` sends after commit."""

    revision: int
    designations: tuple[Designation, ...]
    contact_changes: tuple[ContactChange, ...]


def change_policy_ref(installation_id: str, team_id: str, scope: str | None = None) -> str:
    """The B2 policy a change set mints under: every owner, or one console scope."""
    return "|".join([POLICY_PREFIX, installation_id, team_id, *([scope] if scope else [])])


class ChangeSetPolicies:
    """The B2 policies of change sets, read from the installation's current
    owners and four-eyes setting."""

    def __init__(self, db: AsyncDatabaseManager, directory: OwnerDirectory) -> None:
        self._db = db
        self._directory = directory

    async def current(self, policy_ref: str) -> ActionPolicy | None:
        parts = policy_ref.split("|")
        if parts[0] != POLICY_PREFIX or len(parts) not in (3, 4):
            return None
        installation_id, team_id = parts[1], parts[2]
        if len(parts) == 4:
            scopes: tuple[str, ...] = (parts[3],)
        else:
            owners = await self._directory.enrolled_owners(
                self._db, installation_id=installation_id, team_id=team_id
            )
            scopes = tuple(owner_scope(installation_id, team_id, o.principal_did) for o in owners)
        if not scopes:
            return None
        return ActionPolicy(
            policy_ref=policy_ref,
            version=1,
            min_assurance=Assurance.PASSKEY,
            ttl=MAX_LIFETIME,
            approver_scopes=scopes,
            allow_requester_approval=await four_eyes(self._db, installation_id) == "not_required",
        )


def _request(value: Any) -> dict[str, Any]:
    return json.loads(value) if isinstance(value, str) else dict(value)


class ChangeSets:
    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        approvals: Approvals,
        passkeys: Passkeys,
        directory: OwnerDirectory,
        custody: Custody,
        draft_limit: DraftLimit,
    ) -> None:
        self._db = db
        self._approvals = approvals
        self._passkeys = passkeys
        self._directory = directory
        self._custody = custody
        self._draft_limit = draft_limit

    async def draft(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        *,
        sealed: Sequence[SealContext] = (),
    ) -> PendingApproval:
        """Record a draft and mint its approval in ``tx``. Deliver the returned
        approval with ``Approvals.deliver`` after the commit."""
        validate_change(change)
        for index, item in enumerate(change["changes"]):
            if item["kind"] not in APPLICABLE_KINDS:
                raise ChangeRefused(
                    f"change.changes[{index}]: {item['kind']} cannot be applied yet",
                    code="change_kind_not_applicable",
                )
            if item["kind"] == "role" and item["after"]["role"] == OWNER_ROLE:
                # Owners are designated only by the team owner act (§10.2).
                raise ChangeRefused(
                    f"change.changes[{index}]: a change set never grants {OWNER_ROLE}",
                    code="role_not_grantable",
                )
        installation_id, team_id = change["installation_id"], change["team_id"]
        for context in sealed:
            if (context.installation_id, context.team_id) != (installation_id, team_id):
                raise ChangeRefused(
                    "a sealed value belongs to another installation or team",
                    code="sealed_value_foreign",
                )
            if await tx.fetch_value(
                "SELECT 1 FROM {{tables.change_set_sealed}} WHERE installation_id = $1"
                " AND team_id = $2 AND secret_id = $3 AND version = $4",
                context.installation_id,
                context.team_id,
                context.secret_id,
                context.version,
            ):
                raise ChangeRefused(
                    "the sealed value belongs to another change set", code="sealed_value_taken"
                )
        if change["base_revision"] != await config_revision(tx, installation_id):
            raise ChangeRefused(
                "the configuration changed after this change set was drafted",
                code="base_revision_stale",
            )
        drafter = change["drafter"]
        if drafter["via"] == "team_auth":
            drafted_by = requested_by = drafter["principal"]
            await self._within_draft_limit(tx, installation_id, drafted_by)
            policy_ref = change_policy_ref(installation_id, team_id)
        else:
            drafted_by = drafter["scope"]
            owner = await self._directory.owner_of(tx, drafted_by)
            if owner is None:
                raise ChangeRefused("only an owner drafts on the console", code="owner_required")
            requested_by = owner.principal_did
            policy_ref = change_policy_ref(installation_id, team_id, drafted_by)
        try:
            pending = await self._approvals.mint(
                request=change, policy_ref=policy_ref, requested_by=requested_by, tx=tx
            )
        except ApprovalRefused as refused:
            raise ChangeRefused(str(refused), code="no_owner_to_confirm") from None
        await tx.execute(
            """
            INSERT INTO {{tables.change_sets}} (change_id, installation_id, team_id,
                base_revision, request, via, drafted_by, approval_id, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            change["change_id"],
            installation_id,
            team_id,
            change["base_revision"],
            json.dumps(dict(change)),
            drafter["via"],
            drafted_by,
            pending.approval.approval_id,
            parse_utc_seconds(change["expires_at"]),
        )
        for context in sealed:
            await tx.execute(
                "INSERT INTO {{tables.change_set_sealed}}"
                " (change_id, installation_id, team_id, secret_id, version)"
                " VALUES ($1, $2, $3, $4, $5)",
                change["change_id"],
                context.installation_id,
                context.team_id,
                context.secret_id,
                context.version,
            )
        return pending

    async def _within_draft_limit(
        self, tx: TransactionManager, installation_id: str, principal: str
    ) -> None:
        await tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            f"{installation_id}\n{principal}",
        )
        drafted = await tx.fetch_value(
            """
            SELECT count(*) FROM {{tables.change_sets}}
            WHERE installation_id = $1 AND drafted_by = $2 AND via = 'team_auth'
                AND created_at > NOW() - $3::interval
            """,
            installation_id,
            principal,
            self._draft_limit.window,
        )
        if int(drafted) >= self._draft_limit.count:
            raise ChangeRefused("too many change sets drafted recently", code="draft_rate_limited")

    async def confirm(
        self,
        tx: TransactionManager,
        change_id: str,
        *,
        operation_id: str,
        fence: InstallationFence,
        admitted: AdmittedInstallation,
    ) -> Confirmation:
        """Apply a decided change set in ``tx``, for the installation the
        caller admitted from its installation record. Deliver the returned
        confirmation after the commit."""
        try:
            await fence.check(tx, admitted)
        except InstallationRefused as refused:
            raise ChangeRefused(str(refused), code=refused.code) from None
        drafted = await tx.fetch_value(
            "SELECT approval_id FROM {{tables.change_sets}} WHERE change_id = $1", change_id
        )
        if drafted is None:
            raise ChangeRefused("the change set is not pending", code="change_not_pending")
        decided = await self._approvals.get(drafted)
        decided_by = decided.decided_by if decided is not None else None
        if decided_by is None:
            raise ChangeRefused("no owner has decided the change set", code="change_not_approved")
        confirmer = await self._directory.owner_of(tx, decided_by.scope)
        if confirmer is None or not await hold_role(tx, confirmer, OWNER_ROLE):
            raise ChangeRefused("the deciding owner is no longer an owner", code="owner_required")
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.change_sets}} WHERE change_id = $1 FOR UPDATE", change_id
        )
        if row is None or row["state"] != "pending":
            raise ChangeRefused("the change set is not pending", code="change_not_pending")
        change = _request(row["request"])
        try:
            evidence = await self._passkeys.owner_approval(
                tx,
                self._approvals,
                approval_id=row["approval_id"],
                request=change,
                operation_id=operation_id,
            )
        except (ApprovalRefused, DesignationRefused) as refused:
            raise ChangeRefused(str(refused), code="change_not_approved") from None
        if evidence.approver_scope != decided_by.scope:
            raise ChangeRefused("the admitted decision changed", code="change_not_approved")
        installation_id = change["installation_id"]
        distinct_approver = await lock_four_eyes(tx, installation_id)
        check_confirmable(
            change,
            installation_id=admitted.installation_id,
            install_generation=admitted.generation,
            team_id=admitted.team_id,
            current_revision=await config_revision(tx, installation_id),
            now=datetime.now(UTC),
        )
        drafter = change["drafter"]
        drafting_owner = (
            await self._directory.owner_of(tx, drafter["scope"])
            if drafter["via"] == "console"
            else None
        )
        check_confirmer(
            change,
            distinct_approver=distinct_approver,
            confirmer=confirmer.principal_did,
            drafter_principal=drafting_owner.principal_did if drafting_owner else None,
        )
        revision = await claim_config_revision(tx, installation_id, change["base_revision"])
        designations: list[Designation] = []
        contact_changes: list[ContactChange] = []
        for item in change["changes"]:
            applied = await self._apply(tx, change, item, evidence)
            if isinstance(applied, ContactChange):
                contact_changes.append(applied)
            else:
                designations.extend(applied)
        await tx.execute(
            "UPDATE {{tables.change_sets}} SET state = 'applied', closed_at = NOW()"
            " WHERE change_id = $1",
            change_id,
        )
        return Confirmation(
            revision=revision,
            designations=tuple(designations),
            contact_changes=tuple(contact_changes),
        )

    async def _apply(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        item: Mapping[str, Any],
        evidence: OwnerApproval,
    ) -> list[Designation] | ContactChange:
        installation_id, team_id = change["installation_id"], change["team_id"]
        after = item["after"]
        if item["kind"] == "role":
            await assign(
                tx, PrincipalKey(team_id=team_id, principal_did=after["principal"]), after["role"]
            )
            return []
        if item["kind"] == "approver":
            if await approver_exists(
                tx,
                installation_id=installation_id,
                team_id=team_id,
                approver_ref=after["approver_ref"],
            ):
                raise ChangeRefused(
                    f"approver {after['approver_ref']} already exists", code="approver_exists"
                )
            scope = approver_scope(installation_id, team_id, after["approver_ref"])
            try:
                designation = await self._passkeys.designate(
                    tx, scope=scope, contact=after["contact"], evidence=evidence
                )
            except DesignationRefused as refused:
                raise ChangeRefused(str(refused), code="approver_designation_refused") from None
            await record_approver(
                tx,
                installation_id=installation_id,
                team_id=team_id,
                approver_ref=after["approver_ref"],
                scope=scope,
                covers=after["covers"],
                principal_did=after["principal"],
                change_id=change["change_id"],
            )
            return [designation]
        if item["kind"] == "approver_contact":
            # The scope and contact come from the item of the request the owner's
            # approval admitted, so they are exactly what the owner confirmed.
            if not await approver_exists(
                tx,
                installation_id=installation_id,
                team_id=team_id,
                approver_ref=after["approver_ref"],
            ):
                raise ChangeRefused(f"no approver {after['approver_ref']}", code="approver_unknown")
            try:
                return await self._passkeys.change_contact_by_owner(
                    tx,
                    scope=approver_scope(installation_id, team_id, after["approver_ref"]),
                    new_contact=after["contact"],
                    evidence=evidence,
                )
            except ContactChangeRefused as refused:
                raise ChangeRefused(str(refused), code=refused.reason) from None
        if item["kind"] == "change_set_policy":
            await relax_four_eyes(tx, installation_id=installation_id)
            return []
        raise ChangeRefused(f"{item['kind']} cannot be applied", code="change_kind_not_applicable")

    async def deliver(self, confirmation: Confirmation) -> None:
        for designation in confirmation.designations:
            await self._passkeys.deliver(designation)
        for contact_change in confirmation.contact_changes:
            await self._passkeys.send_notices(contact_change)

    async def cancel(self, tx: TransactionManager, change_id: str, *, cancelled_by: str) -> None:
        """Withdraw a pending change set: its approval is revoked and its sealed
        values destroyed."""
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.change_sets}} WHERE change_id = $1 FOR UPDATE", change_id
        )
        if row is None or row["state"] != "pending":
            raise ChangeRefused("the change set is not pending", code="change_not_pending")
        await self._close(tx, row, state="cancelled", by=cancelled_by)

    async def expire(self, *, now: datetime) -> int:
        """Close every pending change set past its expiry. Returns how many."""
        due = await self._db.fetch_all(
            "SELECT change_id FROM {{tables.change_sets}}"
            " WHERE state = 'pending' AND expires_at <= $1",
            now,
        )
        expired = 0
        for change in due:
            async with self._db.transaction() as tx:
                row = await tx.fetch_one(
                    "SELECT * FROM {{tables.change_sets}}"
                    " WHERE change_id = $1 AND state = 'pending' FOR UPDATE SKIP LOCKED",
                    change["change_id"],
                )
                if row is None:
                    continue
                await self._close(tx, row, state="expired", by="change_set_expiry")
                expired += 1
        return expired

    async def _close(
        self, tx: TransactionManager, row: Mapping[str, Any], *, state: str, by: str
    ) -> None:
        try:
            await self._approvals.revoke(row["approval_id"], revoked_by=by, reason=state, tx=tx)
        except ApprovalRefused:
            pass  # already decided past revoking, or expired: nothing left to withdraw
        sealed = await tx.fetch_all(
            "SELECT installation_id, team_id, secret_id, version"
            " FROM {{tables.change_set_sealed}} WHERE change_id = $1",
            row["change_id"],
        )
        for context in sealed:
            await self._custody.destroy(tx, SealContext(**dict(context)))
        await tx.execute(
            "UPDATE {{tables.change_sets}} SET state = $2, closed_at = NOW() WHERE change_id = $1",
            row["change_id"],
            state,
        )
