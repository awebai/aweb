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
sealed values. Each sealed value is bound at draft time to the secret_value
item that names it, and a confirmed value replaces the secret's last one,
destroying it in the same transaction. A kind whose apply does not exist yet
is refused at draft time, so no draft can be confirmed and then do nothing.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aweb_naapp.egress import InternalDestinations
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

from aweb_secrets import records, runners
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
from aweb_secrets.destination import DestinationInvalid, DestinationRecord
from aweb_secrets.grant import GrantRecord, GrantTemplate
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.owners import OWNER_ROLE, OwnerDirectory, approver_scope, owner_scope
from aweb_secrets.policy import Policy
from aweb_secrets.revisions import claim_config_revision, config_revision
from aweb_secrets.runner_protocol import RunnerRefused
from aweb_secrets.secret import SecretRecord, sealed_shape_changed

MIGRATIONS_PATH = Path(__file__).resolve().parent / "change_set_migrations"
MIGRATIONS_MODULE = "aweb_secrets_change_sets"

POLICY_PREFIX = "secrets.change"
# Kinds whose apply exists. The rest are refused at draft time until theirs does.
APPLICABLE_KINDS = frozenset(
    {
        "secret",
        "secret_value",
        "destination",
        "operation",
        "grant",
        "grant_template",
        "policy",
        "role",
        "approver",
        "approver_contact",
        "change_set_policy",
        "runner",
    }
)


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
class RunnerRegistration:
    """One-time material for the confirming owner's console after commit."""

    runner_id: str
    registration_code: str = field(repr=False)
    reenabled: bool
    keys_replaced: bool


@dataclass(frozen=True)
class Confirmation:
    """A confirmed change set: the revision it moved to, and the approver
    designations and contact changes whose links and notices
    :meth:`ChangeSets.deliver` sends after commit. Runner codes belong only
    in the owner-console projection; never serialize this internal object."""

    change_id: str
    installation_id: str
    team_id: str
    confirmed_scope: str
    confirmed_subject: str
    revision: int
    designations: tuple[Designation, ...]
    contact_changes: tuple[ContactChange, ...]
    runner_registrations: tuple[RunnerRegistration, ...] = field(default=(), repr=False)


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


# The kinds stored as secrets' own records (S8).
RECORD_KINDS = frozenset(
    {"secret", "secret_value", "destination", "operation", "grant", "grant_template", "policy"}
)


def _exists(kind: str, ref: str) -> ChangeRefused:
    return ChangeRefused(f"{kind} {ref} already exists", code="record_exists")


# Secret, destination and grant ids are unique across installations; a
# secret's ref is unique within its installation.
async def _secret_exists(
    tx: TransactionManager, installation_id: str, record: SecretRecord
) -> bool:
    return bool(
        await tx.fetch_value(
            "SELECT 1 FROM {{tables.secrets}}"
            " WHERE secret_id = $1 OR (installation_id = $2 AND ref = $3)",
            record.secret_id,
            installation_id,
            record.ref,
        )
    )


async def _require_secret(
    tx: TransactionManager, installation_id: str, team_id: str, secret_id: str
) -> None:
    """Refuse a record for a secret this installation's team does not hold."""
    if not await tx.fetch_value(
        "SELECT 1 FROM {{tables.secrets}}"
        " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3",
        installation_id,
        team_id,
        secret_id,
    ):
        raise records.RecordMissing(f"no secret {secret_id}")


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
        internal_destinations: InternalDestinations,
    ) -> None:
        self._db = db
        self._approvals = approvals
        self._passkeys = passkeys
        self._directory = directory
        self._custody = custody
        self._draft_limit = draft_limit
        self._internal_destinations = internal_destinations

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
        await self._bind_sealed(tx, change, sealed)
        for item in change["changes"]:
            if item["kind"] == "secret":
                await self._check_sealed_shape(
                    tx, installation_id, team_id, SecretRecord.from_after(item["after"]), lock=False
                )
        for index, item in enumerate(change["changes"]):
            if item["kind"] == "destination":
                self._destination(item["after"], f"change.changes[{index}]")
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

    async def _bind_sealed(
        self, tx: TransactionManager, change: Mapping[str, Any], sealed: Sequence[SealContext]
    ) -> None:
        """Require the sealed values to be exactly those the change's secret_value
        items name: each item's secret, by an earlier secret item of the change
        or as stored, at the item's version."""
        installation_id, team_id = change["installation_id"], change["team_id"]
        named: set[tuple[str, int]] = set()
        drafted: dict[str, SecretRecord] = {}
        bindings: list[tuple[SealContext, SecretRecord]] = []
        for index, item in enumerate(change["changes"]):
            after = item["after"]
            if item["kind"] == "secret":
                drafted[after["ref"]] = SecretRecord.from_after(after)
            elif item["kind"] == "secret_value":
                record = drafted.get(after["secret_ref"])
                if record is None:
                    stored = await records.secret_by_ref(
                        tx, installation_id, team_id, after["secret_ref"]
                    )
                    if stored is None:
                        raise ChangeRefused(
                            f"change.changes[{index}]: no secret {after['secret_ref']}",
                            code="secret_unknown",
                        )
                    record = stored.record
                secret_id = record.secret_id
                named.add((secret_id, after["version"]))
                context = SealContext(
                    installation_id=installation_id,
                    team_id=team_id,
                    secret_id=secret_id,
                    version=after["version"],
                )
                bindings.append((context, record))
        brought = {(context.secret_id, context.version) for context in sealed}
        if named - brought:
            raise ChangeRefused(
                "a secret value names a version the change set did not bring",
                code="sealed_value_missing",
            )
        if brought - named:
            raise ChangeRefused(
                "a sealed value is not named by any secret value", code="sealed_value_unbound"
            )

        for context, record in bindings:
            if not await self._custody.value_matches(tx, context, record):
                raise ChangeRefused(
                    "the sealed value does not match its secret record", code="sealed_secret_fixed"
                )

    def _destination(self, after: Mapping[str, Any], where: str) -> DestinationRecord:
        try:
            return DestinationRecord.from_after(
                after, internal_destinations=self._internal_destinations
            )
        except DestinationInvalid as refused:
            raise ChangeRefused(f"{where}: {refused}", code=refused.code) from None

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
        runner_registrations: list[RunnerRegistration] = []
        for item in change["changes"]:
            applied = await self._apply(tx, change, item, evidence)
            if isinstance(applied, RunnerRegistration):
                runner_registrations.append(applied)
            elif isinstance(applied, ContactChange):
                contact_changes.append(applied)
            else:
                designations.extend(applied)
        await tx.execute(
            "UPDATE {{tables.change_sets}} SET state = 'applied', closed_at = NOW()"
            " WHERE change_id = $1",
            change_id,
        )
        return Confirmation(
            change_id=change_id,
            installation_id=admitted.installation_id,
            team_id=admitted.team_id,
            confirmed_scope=evidence.approver_scope,
            confirmed_subject=evidence.approver_subject,
            revision=revision,
            designations=tuple(designations),
            contact_changes=tuple(contact_changes),
            runner_registrations=tuple(runner_registrations),
        )

    async def _apply(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        item: Mapping[str, Any],
        evidence: OwnerApproval,
    ) -> list[Designation] | ContactChange | RunnerRegistration:
        installation_id, team_id = change["installation_id"], change["team_id"]
        after = item["after"]
        if item["kind"] == "runner":
            return await self._apply_runner(tx, change, item)
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
        if item["kind"] in RECORD_KINDS:
            await self._apply_record(tx, change, item)
            return []
        raise ChangeRefused(f"{item['kind']} cannot be applied", code="change_kind_not_applicable")

    async def _apply_runner(
        self, tx: TransactionManager, change: Mapping[str, Any], item: Mapping[str, Any]
    ) -> RunnerRegistration:
        installation_id, team_id = change["installation_id"], change["team_id"]
        try:
            record = runners.RunnerRecord.from_after(item["after"])
            if item["op"] == "create":
                if await tx.fetch_value(
                    "SELECT 1 FROM {{tables.runners}} WHERE runner_id = $1", record.runner_id
                ):
                    raise _exists("runner", record.runner_id)
                code = await runners.create_runner(
                    tx, installation_id, team_id, record, now=datetime.now(UTC)
                )
                return RunnerRegistration(record.runner_id, code, False, False)
            current = await tx.fetch_one(
                "SELECT deregistered_at FROM {{tables.runners}}"
                " WHERE runner_id = $1 AND installation_id = $2 AND team_id = $3 FOR UPDATE",
                record.runner_id,
                installation_id,
                team_id,
            )
            if current is None:
                raise ChangeRefused("no runner in this installation", code="runner_unknown")
            code = await runners.replace_runner(
                tx, installation_id, team_id, record, now=datetime.now(UTC)
            )
            return RunnerRegistration(
                record.runner_id, code, current["deregistered_at"] is not None, True
            )
        except RunnerRefused as refused:
            raise ChangeRefused("runner change refused", code=refused.code) from None

    async def _apply_record(
        self, tx: TransactionManager, change: Mapping[str, Any], item: Mapping[str, Any]
    ) -> None:
        installation_id, team_id = change["installation_id"], change["team_id"]
        kind, op, after = item["kind"], item["op"], item["after"]
        try:
            if kind == "secret":
                record = SecretRecord.from_after(after)
                if op == "create":
                    if await _secret_exists(tx, installation_id, record):
                        raise _exists(kind, record.secret_id)
                    await records.create_secret(tx, installation_id, team_id, record)
                    if not await self._custody.bind_shape(
                        tx, installation_id=installation_id, team_id=team_id, record=record
                    ):
                        raise ChangeRefused(
                            "the sealed secret's shape is fixed", code="sealed_secret_fixed"
                        )
                else:
                    if await tx.fetch_value(
                        "SELECT 1 FROM {{tables.secrets}}"
                        " WHERE installation_id = $1 AND ref = $2 AND secret_id <> $3",
                        installation_id,
                        record.ref,
                        record.secret_id,
                    ):
                        raise _exists(kind, record.ref)
                    await self._check_sealed_shape(tx, installation_id, team_id, record, lock=True)
                    await records.update_secret(tx, installation_id, team_id, record)
            elif kind == "secret_value":
                await self._replace_value(tx, change, after)
            elif kind == "destination":
                destination = self._destination(after, "destination")
                await _require_secret(tx, installation_id, team_id, destination.secret_id)
                if await tx.fetch_value(
                    "SELECT 1 FROM {{tables.destinations}} WHERE destination_id = $1",
                    destination.destination_id,
                ):
                    raise _exists(kind, destination.destination_id)
                await records.create_destination(tx, installation_id, team_id, destination)
            elif kind == "operation":
                operation = OperationTemplate.from_after(after)
                await _require_secret(tx, installation_id, team_id, operation.secret_id)
                await records.create_operation(tx, installation_id, team_id, operation)
            elif kind == "grant":
                grant = GrantRecord.from_after(after)
                await _require_secret(tx, installation_id, team_id, grant.secret_id)
                if await records.policy(tx, installation_id, grant.policy_digest) is None:
                    raise records.RecordMissing(f"no policy {grant.policy_digest}")
                if await tx.fetch_value(
                    "SELECT 1 FROM {{tables.grants}} WHERE grant_id = $1", grant.grant_id
                ):
                    raise _exists(kind, grant.grant_id)
                await records.create_grant(tx, installation_id, team_id, grant)
            elif kind == "grant_template":
                template = GrantTemplate.from_after(after)
                stored = await records.grant_template(
                    tx, installation_id, template.grant_template_id
                )
                if op == "create" and stored is not None:
                    raise _exists(kind, template.grant_template_id)
                if op == "update" and stored is None:
                    raise records.RecordMissing(f"no grant template {template.grant_template_id}")
                await records.set_grant_template(tx, installation_id, template)
            else:
                await records.create_policy(
                    tx,
                    installation_id,
                    Policy.from_body({k: v for k, v in after.items() if k != "v"}),
                )
        except records.RecordRefused as refused:
            raise ChangeRefused(str(refused), code=refused.code) from None
        except records.RecordMissing as missing:
            raise ChangeRefused(str(missing), code="record_missing") from None

    async def _check_sealed_shape(
        self,
        tx: TransactionManager,
        installation_id: str,
        team_id: str,
        record: SecretRecord,
        *,
        lock: bool,
    ) -> None:
        # FOR UPDATE conflicts with ingest's KEY SHARE (NO KEY UPDATE does not).
        # Read custody in a subsequent statement to see an ingest we waited for.
        row = await tx.fetch_one(
            "SELECT record FROM {{tables.secrets}}"
            " WHERE installation_id = $1 AND team_id = $2 AND secret_id = $3"
            + (" FOR UPDATE" if lock else ""),
            installation_id,
            team_id,
            record.secret_id,
        )
        if row is not None:
            current = SecretRecord.from_after(_request(row["record"]))
            if sealed_shape_changed(current, record) and await self._custody.ever_sealed(
                tx, installation_id=installation_id, team_id=team_id, secret_id=record.secret_id
            ):
                raise ChangeRefused("a sealed secret's shape is fixed", code="sealed_secret_fixed")
        allowed = (
            await self._custody.bind_shape(
                tx, installation_id=installation_id, team_id=team_id, record=record
            )
            if lock and row is not None
            else await self._custody.shape_allows(
                tx, installation_id=installation_id, team_id=team_id, record=record
            )
        )
        if not allowed:
            raise ChangeRefused("a sealed secret's shape is fixed", code="sealed_secret_fixed")

    async def _replace_value(
        self, tx: TransactionManager, change: Mapping[str, Any], after: Mapping[str, Any]
    ) -> None:
        """Make the item's sealed version, bound to it at draft time, the secret's
        active one, and destroy the version it replaces."""
        installation_id, team_id = change["installation_id"], change["team_id"]
        stored = await records.secret_by_ref(tx, installation_id, team_id, after["secret_ref"])
        if stored is None:
            raise records.RecordMissing(f"no secret {after['secret_ref']}")
        secret_id = stored.record.secret_id
        context = SealContext(
            installation_id=installation_id,
            team_id=team_id,
            secret_id=secret_id,
            version=after["version"],
        )
        if not await self._custody.value_matches(tx, context, stored.record):
            raise ChangeRefused(
                "the sealed value does not match its secret record", code="sealed_secret_fixed"
            )
        await records.set_active_version(tx, installation_id, team_id, secret_id, after["version"])
        if stored.active_version is not None and stored.active_version != after["version"]:
            await self._custody.destroy(
                tx,
                SealContext(
                    installation_id=installation_id,
                    team_id=team_id,
                    secret_id=secret_id,
                    version=stored.active_version,
                ),
            )

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
