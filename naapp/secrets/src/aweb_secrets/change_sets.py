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
3. the change-set row, replacement/reenable ancestry root-first, the grant
   union, and the complete forest/confirmation approval union in ID order;
   then the approval admitted once as owner evidence
   (Passkeys.owner_approval);
4. the four-eyes setting's row, read under its lock;
5. the configuration revision, claimed atomically;
6. then each item applies, with parent secrets before custody rows. Existing
   ingests hold parent KEY SHARE; reshapes take parent UPDATE before custody.
The change set must still be for this installation, generation and team,
unexpired, and confirmed by an owner the setting in force allows.
A draft that expires or is cancelled revokes its approval and destroys its
sealed values. Each staged value is bound at draft time to its native value, private token or
reference item, and checked again at confirmation. Private token replacement
prepares all dependent roots before B2; only explicitly rebound references can
activate under the new token. Unlocked token-dependent discovery relies on
all parent-locking record paths preparing their forests before the revision,
and all active-version writers claiming that revision before writes, including
automatic backend reconciliation. Required proof-bound audit shares
the transaction.
A confirmed value replaces the secret's last one,
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
from aweb_naapp.hooks.producer import RegistrationView
from aweb_naapp.hooks.strictjson import Refused as HookRefused
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
    PasskeyInstallationContext,
    PasskeyProofUnavailable,
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
from aweb_secrets.containment import Containment, ContainmentRefused
from aweb_secrets.custody import Custody, SealContext
from aweb_secrets.custody.store import BACKEND_CREDENTIAL_ID
from aweb_secrets.destination import DestinationInvalid, DestinationRecord
from aweb_secrets.grant import GrantRecord, GrantTemplate
from aweb_secrets.job_changes import apply_job_change, job_prelock_ids
from aweb_secrets.operation import CAPTURE_FIELDS, OperationTemplate
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
        "job",
        "reenable",
        "backend_credential",
        "onepassword_binding",
    }
)


# These creation paths have proof-bound governance in the sole writer. Keep
# HTTP exposure tied to this set until the remaining update/B3 paths are ready.
AUDITED_CREATE_KINDS = frozenset(
    {
        "backend_credential",
        "onepassword_binding",
        "secret",
        "secret_value",
        "destination",
        "operation",
        "grant",
        "policy",
        "role",
        "job",
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
    affected_secret_ids: tuple[str, ...] = ()


def change_policy_ref(installation_id: str, team_id: str, scope: str | None = None) -> str:
    """The B2 policy a change set mints under, optionally bound to a console drafter."""
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
        allow_requester = await four_eyes(self._db, installation_id) == "not_required"
        if len(parts) == 4 and allow_requester:
            scopes: tuple[str, ...] = (parts[3],)
        else:
            # A console drafter normally confirms its own change. Four-eyes
            # instead needs another owner; OwnerDirectory excludes the drafter
            # from these current enrolled owners, as for a member draft.
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
            allow_requester_approval=allow_requester,
        )


# The kinds stored as secrets' own records (S8).
RECORD_KINDS = frozenset(
    {"secret", "destination", "operation", "grant", "grant_template", "policy"}
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
        containment: Containment,
        draft_limit: DraftLimit,
        internal_destinations: InternalDestinations,
    ) -> None:
        self._db = db
        self._approvals = approvals
        self._passkeys = passkeys
        self._directory = directory
        self._custody = custody
        self._containment = containment
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
            if item["kind"] == "job" and (
                item["op"] != "create"
                or any(slot["delivery"] != "durable" for slot in item["after"]["credentials"])
            ):
                raise ChangeRefused(
                    "job change is not applicable yet", code="change_kind_not_applicable"
                )
            if item["kind"] == "reenable" and item["after"]["target_kind"] not in {
                "secret",
                "installation",
            }:
                raise ChangeRefused(
                    "unsupported reenable target", code="reenable_target_unsupported"
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
            if item["kind"] == "job":
                await self._validate_job_sources(tx, change, item)
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
        """Bind exactly the brought native/private/reference candidates to items.

        Full staged-row equality and credential epochs are checked at both
        draft and confirmation. This read phase takes no authority locks.
        """
        installation_id, team_id = change["installation_id"], change["team_id"]
        named: set[tuple[str, int]] = set()
        drafted: dict[str, SecretRecord] = {}
        bindings: list[tuple[SealContext, SecretRecord]] = []
        for index, item in enumerate(change["changes"]):
            after = item["after"]
            if item["kind"] == "secret":
                drafted[after["ref"]] = SecretRecord.from_after(after)
            elif item["kind"] in {"backend_credential", "onepassword_binding"}:
                context = await self._bind_backend(tx, change, item, drafted)
                named.add((context.secret_id, context.version))
            elif item["kind"] == "secret_value":
                record = drafted.get(after["secret_ref"])
                if record is None:
                    stored = await records.secret_by_ref(
                        tx, installation_id, team_id, after["secret_ref"], lock=False
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

    @staticmethod
    def _backend_token_version(change: Mapping[str, Any]) -> int | None:
        return next(
            (
                item["after"]["version"]
                for item in change["changes"]
                if item["kind"] == "backend_credential"
            ),
            None,
        )

    async def _active_backend_token(
        self, tx: TransactionManager, change: Mapping[str, Any]
    ) -> int | None:
        return await tx.fetch_value(
            "SELECT active_version FROM {{tables.onepassword_credentials}}"
            " WHERE installation_id=$1 AND team_id=$2",
            change["installation_id"],
            change["team_id"],
        )

    async def _bind_backend(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        item: Mapping[str, Any],
        drafted: Mapping[str, SecretRecord],
    ) -> SealContext:
        """Compare the full server-staged candidate, without taking authority locks."""
        installation_id, team_id = change["installation_id"], change["team_id"]
        after = item["after"]
        secret_id = (
            after["credential_id"] if item["kind"] == "backend_credential" else after["secret_id"]
        )
        context = SealContext(installation_id, team_id, secret_id, after["version"])
        active_token = await self._active_backend_token(tx, change)
        if item["kind"] == "backend_credential":
            if not await self._custody.backend_credential_matches(
                tx, context
            ) or context.version <= (active_token or 0):
                raise ChangeRefused(
                    "backend credential candidate unavailable", code="backend_credential_invalid"
                )
            return context
        record = next((r for r in drafted.values() if r.secret_id == secret_id), None)
        row = await tx.fetch_one(
            "SELECT record, active_version FROM {{tables.secrets}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3",
            installation_id,
            team_id,
            secret_id,
        )
        if record is None and row is not None:
            record = SecretRecord.from_after(_request(row["record"]))
        expected_token = self._backend_token_version(change) or active_token
        if (
            record is None
            or after["credential_version"] != expected_token
            or context.version <= ((row["active_version"] if row is not None else None) or 0)
            or not await self._custody.onepassword_binding_matches(tx, context, record, after)
        ):
            raise ChangeRefused(
                "backend reference candidate unavailable", code="onepassword_binding_invalid"
            )
        return context

    async def _backend_dependents(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        new_version: int,
    ) -> list:
        # Discovery only: prepare_replacements locks the complete forest before B2.
        return await tx.fetch_all(
            "SELECT s.secret_id, s.active_version FROM {{tables.secrets}} s"
            " JOIN {{tables.onepassword_versions}} v USING (installation_id,team_id,secret_id)"
            " WHERE s.installation_id=$1 AND s.team_id=$2 AND s.active_version=v.version"
            " AND v.credential_version<>$3 ORDER BY s.secret_id",
            change["installation_id"],
            change["team_id"],
            new_version,
        )

    async def _apply_backend_credential(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        after: Mapping[str, Any],
        confirmed_by: str,
    ) -> tuple[str, ...]:
        installation_id, team_id = change["installation_id"], change["team_id"]
        row = await tx.fetch_one(
            "SELECT active_version FROM {{tables.onepassword_credentials}}"
            " WHERE installation_id=$1 AND team_id=$2 FOR UPDATE",
            installation_id,
            team_id,
        )
        old = row["active_version"] if row is not None else None
        context = SealContext(installation_id, team_id, BACKEND_CREDENTIAL_ID, after["version"])
        if (
            row is None
            or context.version <= (old or 0)
            or not await self._custody.backend_credential_matches(tx, context)
        ):
            raise ChangeRefused(
                "backend credential candidate unavailable", code="backend_credential_invalid"
            )
        affected: set[str] = set()
        for dependent in await self._backend_dependents(tx, change, context.version):
            try:
                affected.update(
                    await self._containment.invalidate_value_consequences(
                        tx,
                        installation_id=installation_id,
                        team_id=team_id,
                        secret_id=dependent["secret_id"],
                        revoked_by=confirmed_by,
                    )
                )
            except ContainmentRefused as refused:
                raise ChangeRefused("backend replacement refused", code=refused.code) from None
            await tx.execute(
                "UPDATE {{tables.secrets}} SET active_version=NULL, updated_at=NOW()"
                " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3",
                installation_id,
                team_id,
                dependent["secret_id"],
            )
            await self._custody.destroy(
                tx,
                SealContext(
                    installation_id, team_id, dependent["secret_id"], dependent["active_version"]
                ),
            )
        await tx.execute(
            "UPDATE {{tables.onepassword_credentials}} SET active_version=$3"
            " WHERE installation_id=$1 AND team_id=$2",
            installation_id,
            team_id,
            context.version,
        )
        if old is not None:
            await self._custody.destroy(
                tx, SealContext(installation_id, team_id, BACKEND_CREDENTIAL_ID, old)
            )
        return tuple(sorted(affected))

    async def _apply_onepassword_binding(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        after: Mapping[str, Any],
        confirmed_by: str,
    ) -> tuple[str, ...]:
        installation_id, team_id = change["installation_id"], change["team_id"]
        context = SealContext(installation_id, team_id, after["secret_id"], after["version"])
        row = await tx.fetch_one(
            "SELECT record, active_version FROM {{tables.secrets}}"
            " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3 FOR UPDATE",
            installation_id,
            team_id,
            context.secret_id,
        )
        if row is None:
            raise ChangeRefused("secret unavailable", code="secret_unknown")
        record = SecretRecord.from_after(_request(row["record"]))
        if (
            after["credential_version"] != await self._active_backend_token(tx, change)
            or context.version <= (row["active_version"] or 0)
            or not await self._custody.onepassword_binding_matches(tx, context, record, after)
        ):
            raise ChangeRefused(
                "backend reference candidate unavailable", code="onepassword_binding_invalid"
            )
        affected = {context.secret_id}
        if row["active_version"] is not None:
            old = SealContext(installation_id, team_id, context.secret_id, row["active_version"])
            try:
                affected.update(
                    await self._containment.replacement_consequences(
                        tx,
                        old=old,
                        new=context,
                        revoked_by=confirmed_by,
                    )
                )
            except ContainmentRefused as refused:
                raise ChangeRefused("replacement refused", code=refused.code) from None
            await self._custody.destroy(tx, old)
        await records.set_active_version(
            tx, installation_id, team_id, context.secret_id, context.version
        )
        return tuple(sorted(affected))

    async def _backend_audit(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        item: Mapping[str, Any],
        evidence: OwnerApproval,
        commitment: str,
        view: RegistrationView | None,
    ) -> None:
        # Explicit owner-confirmed versions may rebind the reference/credential;
        # they use the existing widening act, not automatic observation authority.
        after = item["after"]
        payload = {
            "act": "resource.version_added",
            "direction": "widening",
            "authority": "passkey_session",
            "resource_type": item["kind"],
            "resource_ref": after.get("secret_id", BACKEND_CREDENTIAL_ID),
            "approval_id": evidence.approval_id,
            "approval_evidence_sha256": commitment,
        }
        if item["kind"] == "onepassword_binding":
            payload["after_ref"] = await tx.fetch_value(
                "SELECT version_ref FROM {{tables.onepassword_versions}}"
                " WHERE installation_id=$1 AND team_id=$2 AND secret_id=$3 AND version=$4",
                change["installation_id"],
                change["team_id"],
                after["secret_id"],
                after["version"],
            )
        try:
            await self._containment.governance(
                tx,
                team_id=change["team_id"],
                payload=payload,
                actor={"authority_mode": "system", "attestations": []},
                occurred_at=datetime.now(UTC),
                result_status="success",
                view=view,
            )
        except HookRefused as refused:
            raise ChangeRefused(
                "required governance recording unavailable", code=refused.code
            ) from None

    async def _validate_job_sources(
        self, tx: TransactionManager, change: Mapping[str, Any], item: Mapping[str, Any]
    ) -> None:
        # No SDK/KMS read and no late parent lock: confirmation prepared all
        # existing credential ancestry before CURRENT/B2/revision.
        proposed = {
            i["after"]["ref"]: SecretRecord.from_after(i["after"])
            for i in change["changes"]
            if i["kind"] == "secret"
        }
        for slot in item["after"]["credentials"]:
            ref = slot["secret_ref"]
            record = proposed.get(ref)
            if record is None:
                stored = await records.secret_by_ref(
                    tx, change["installation_id"], change["team_id"], ref, lock=False
                )
                if stored is None or stored.state != "active":
                    raise ChangeRefused(
                        "job credential source unavailable", code="job_source_unknown"
                    )
                record = stored.record
            required, optional = CAPTURE_FIELDS[record.kind]
            selected = {
                entry["field"]
                for entry in item["after"]["env"].values()
                if isinstance(entry, dict) and entry.get("$credential") == ref
            }
            if not selected <= required | optional:
                raise ChangeRefused(
                    "job credential fields differ from source kind", code="job_source_invalid"
                )

    async def _creation_audit(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        item: Mapping[str, Any],
        evidence: OwnerApproval,
        commitment: str,
        view: RegistrationView | None,
    ) -> None:
        if item["kind"] in {"backend_credential", "onepassword_binding"}:
            await self._backend_audit(tx, change, item, evidence, commitment, view)
            return
        kind, after = item["kind"], item["after"]
        payload: dict[str, Any] = {
            "direction": "widening",
            "authority": "passkey_session",
            "approval_id": evidence.approval_id,
            "approval_evidence_sha256": commitment,
        }
        if kind == "policy":
            payload.update(act="policy.changed", policy_digest=item["ref"])
        elif kind == "role":
            payload.update(
                act="role.designated",
                role=after["role"],
                subject_ref="member:" + after["principal"],
            )
        elif kind == "secret_value":
            secret_id = await tx.fetch_value(
                "SELECT secret_id FROM {{tables.secrets}} WHERE installation_id=$1 AND team_id=$2 AND ref=$3",
                change["installation_id"],
                change["team_id"],
                after["secret_ref"],
            )
            payload.update(
                act="resource.version_added", resource_type="secret", resource_ref=secret_id
            )
        else:
            payload.update(
                act="grant.created"
                if kind == "grant"
                else "runner.registered"
                if kind == "runner"
                else "resource.created",
                resource_type=kind,
                resource_ref=after[kind + "_id"],
            )
        try:
            await self._containment.governance(
                tx,
                team_id=change["team_id"],
                payload=payload,
                actor={"authority_mode": "system", "attestations": []},
                occurred_at=datetime.now(UTC),
                result_status="success",
                view=view,
            )
        except HookRefused as refused:
            raise ChangeRefused(
                "required governance recording unavailable", code=refused.code
            ) from None

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
        governance_view: RegistrationView | None = None,
    ) -> Confirmation:
        """Apply a decided change set in ``tx``, for the installation the
        caller admitted from its installation record. Deliver the returned
        confirmation after the commit. ``governance_view`` is trusted shared-resolver
        data read before this transaction, never request JSON. New backend
        effects require its fresh audit target and the retained APPROVE proof.
        """
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
        await self._prepare_containment(tx, row, change, admitted)
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
        bound = await tx.fetch_all(
            "SELECT installation_id, team_id, secret_id, version"
            " FROM {{tables.change_set_sealed}} WHERE change_id=$1",
            change_id,
        )
        await self._bind_sealed(tx, change, [SealContext(**dict(value)) for value in bound])
        backend_items = [
            i
            for i in change["changes"]
            if i["kind"] in {"backend_credential", "onepassword_binding"}
        ]
        audited_items = [
            i
            for i in change["changes"]
            if i["op"] == "create" and i["kind"] in AUDITED_CREATE_KINDS
        ]
        commitment = None
        if audited_items:
            if (
                decided is None
                or decided_by is None
                or (decided.approval_id, decided_by.scope, decided_by.subject)
                != (evidence.approval_id, evidence.approver_scope, evidence.approver_subject)
            ):
                raise ChangeRefused("the approved decision changed", code="change_not_approved")
            try:
                commitment = await self._passkeys.evidence_commitment(
                    decided_by.evidence_ref,
                    context=PasskeyInstallationContext(
                        admitted.app_id,
                        admitted.team_id,
                        admitted.installation_id,
                        admitted.generation,
                    ),
                    scope=evidence.approver_scope,
                    subject=evidence.approver_subject,
                    purpose="approve",
                    tx=tx,
                )
            except PasskeyProofUnavailable:
                raise ChangeRefused(
                    "approval proof unavailable", code="passkey_proof_unavailable"
                ) from None
        revision = await claim_config_revision(tx, installation_id, change["base_revision"])
        designations: list[Designation] = []
        contact_changes: list[ContactChange] = []
        runner_registrations: list[RunnerRegistration] = []
        affected: set[str] = set()
        # Activate a proposed credential before binding items regardless of their
        # presentation order. All dependencies were prepared before B2 admission.
        for item in backend_items:
            if item["kind"] == "backend_credential":
                affected.update(
                    await self._apply_backend_credential(
                        tx, change, item["after"], confirmer.principal_did
                    )
                )
        for item in change["changes"]:
            if item["kind"] == "backend_credential":
                continue
            applied = await self._apply(tx, change, item, evidence, confirmer.principal_did)
            if isinstance(applied, RunnerRegistration):
                runner_registrations.append(applied)
            elif isinstance(applied, tuple):
                affected.update(applied)
            elif isinstance(applied, ContactChange):
                contact_changes.append(applied)
            else:
                designations.extend(applied)
        if commitment is not None:
            for item in audited_items:
                await self._creation_audit(tx, change, item, evidence, commitment, governance_view)
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
            affected_secret_ids=tuple(sorted(affected)),
        )

    async def _prepare_containment(
        self,
        tx: TransactionManager,
        row: Mapping[str, Any],
        change: Mapping[str, Any],
        admitted: AdmittedInstallation,
    ) -> None:
        if (change["installation_id"], change["install_generation"], change["team_id"]) != (
            admitted.installation_id,
            admitted.generation,
            admitted.team_id,
        ):
            raise ChangeRefused(
                "change is for another installation", code="change_wrong_installation"
            )
        # Canonical sealed bindings survive ref edits. Absent first-create parents
        # stay inert and need no existing ancestry; discovery takes no child lock.
        rows = await tx.fetch_all(
            "SELECT DISTINCT b.secret_id FROM {{tables.change_set_sealed}} b"
            " JOIN {{tables.secrets}} s USING (installation_id, team_id, secret_id)"
            " WHERE b.change_id=$1 AND b.installation_id=$2 AND b.team_id=$3",
            row["change_id"],
            admitted.installation_id,
            admitted.team_id,
        )
        roots = {record["secret_id"] for record in rows}
        # Metadata-only edits lock the parent in _check_sealed_shape; operation
        # creation reads it FOR SHARE, and destination/grant inserts acquire FK
        # KEY SHARE. Prepare these existing parents before B2/revision too.
        # First-create parents remain absent/inert until the record-write phase.
        parent_ids = {
            item["after"]["secret_id"]
            for item in change["changes"]
            if item["kind"] in {"secret", "destination", "operation", "grant"}
        }
        job_refs = sorted(
            {
                slot["secret_ref"]
                for item in change["changes"]
                if item["kind"] == "job"
                for slot in item["after"]["credentials"]
            }
        )
        if job_refs:
            parents = await tx.fetch_all(
                "SELECT secret_id FROM {{tables.secrets}} WHERE installation_id=$1 AND team_id=$2 AND ref=ANY($3::text[])",
                admitted.installation_id,
                admitted.team_id,
                job_refs,
            )
            roots.update(parent["secret_id"] for parent in parents)
        if parent_ids:
            existing = await tx.fetch_all(
                "SELECT secret_id FROM {{tables.secrets}}"
                " WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])",
                admitted.installation_id,
                admitted.team_id,
                sorted(parent_ids),
            )
            roots.update(record["secret_id"] for record in existing)
        token_version = self._backend_token_version(change)
        if token_version is not None:
            roots.update(
                row["secret_id"]
                for row in await self._backend_dependents(tx, change, token_version)
            )
        for item in change["changes"]:
            if item["kind"] == "reenable" and item["after"]["target_kind"] == "secret":
                roots.add(
                    await self._reenable_id(
                        tx, admitted.installation_id, admitted.team_id, item["after"]["target_ref"]
                    )
                )
        try:
            await self._containment.prepare_replacements(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                secret_ids=tuple(sorted(roots)),
                approval_ids=(row["approval_id"],),
                job_ids=job_prelock_ids(change["changes"]),
            )
        except ContainmentRefused as refused:
            raise ChangeRefused("containment preparation refused", code=refused.code) from None

    async def _reenable_id(
        self,
        tx: TransactionManager,
        installation_id: str,
        team_id: str,
        ref: str,
    ) -> str:
        secret_id = await tx.fetch_value(
            "SELECT secret_id FROM {{tables.secrets}}"
            " WHERE installation_id=$1 AND team_id=$2 AND ref=$3",
            installation_id,
            team_id,
            ref,
        )
        if secret_id is None:
            raise ChangeRefused("no secret with this ref", code="secret_unknown")
        return str(secret_id)

    async def _apply(
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        item: Mapping[str, Any],
        evidence: OwnerApproval,
        confirmed_by: str,
    ) -> list[Designation] | ContactChange | RunnerRegistration | tuple[str, ...]:
        installation_id, team_id = change["installation_id"], change["team_id"]
        after = item["after"]
        if item["kind"] == "onepassword_binding":
            return await self._apply_onepassword_binding(tx, change, after, confirmed_by)
        if item["kind"] == "job":
            await self._validate_job_sources(tx, change, item)
            await apply_job_change(tx, installation_id=installation_id, team_id=team_id, item=item)
            return []
        if item["kind"] == "runner":
            return await self._apply_runner(tx, change, item)
        if item["kind"] == "secret_value":
            try:
                return await self._replace_value(tx, change, after, confirmed_by)
            except records.RecordMissing as missing:
                raise ChangeRefused(str(missing), code="record_missing") from None
        if item["kind"] == "reenable":
            try:
                await self._containment.reenable(
                    tx,
                    installation_id=installation_id,
                    team_id=team_id,
                    target_kind=after["target_kind"],
                    target_ref=after["target_ref"],
                )
            except ContainmentRefused as refused:
                raise ChangeRefused("reenable refused", code=refused.code) from None
            if after["target_kind"] == "secret":
                return (await self._reenable_id(tx, installation_id, team_id, after["target_ref"]),)
            return ()
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
            # B3's audit resolves this scoped binding in the same transaction.
            # A refused designation rolls the binding back with the effect.
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
            try:
                designation = await self._passkeys.designate(
                    tx, scope=scope, contact=after["contact"], evidence=evidence
                )
            except DesignationRefused as refused:
                raise ChangeRefused(str(refused), code="approver_designation_refused") from None
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
        self,
        tx: TransactionManager,
        change: Mapping[str, Any],
        after: Mapping[str, Any],
        confirmed_by: str,
    ) -> tuple[str, ...]:
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
        affected: tuple[str, ...] = ()
        if stored.active_version is not None and stored.active_version != after["version"]:
            try:
                affected = await self._containment.replacement_consequences(
                    tx,
                    old=SealContext(installation_id, team_id, secret_id, stored.active_version),
                    new=context,
                    revoked_by=confirmed_by,
                )
            except ContainmentRefused as refused:
                raise ChangeRefused("replacement refused", code=refused.code) from None
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
        return affected

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
