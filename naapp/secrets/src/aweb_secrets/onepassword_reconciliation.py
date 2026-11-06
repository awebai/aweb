"""Decision92's separate observation transaction, never S3 dispatch authority.

Observe/validate the remote item outside every held transaction first. This
writer takes F6, the complete forest/grant/B2 union, then the configuration
revision before parent/custody writes. The revision also serializes it with
owner confirmations, whose unlocked token-dependent discovery relies on every
active-version writer claiming that revision. Final dispatch checks remain
DB-only. No value is returned or transplanted into the observing attempt.

Composition must retain the original attempt's secret_version_changed refusal,
perform postcommit cache cleanup only, and activate this path only alongside
the reviewed receiving catalog support. Delivery stays with the shared outbox.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence
from pgdbm import AsyncDatabaseManager

from aweb_secrets import records
from aweb_secrets.containment import Containment
from aweb_secrets.custody import Custody, CustodyUnavailable
from aweb_secrets.custody.opening import BackendObservation, active_binding
from aweb_secrets.revisions import bump_config_revision


@dataclass(frozen=True)
class BackendReconciliation:
    """Cleanup result, never replacement admission/approval/dispatch authority."""

    changed: bool
    affected_secret_ids: tuple[str, ...] = ()


class BackendReconciler:
    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        custody: Custody,
        containment: Containment,
        fence: InstallationFence,
    ) -> None:
        self._db = db
        self._custody = custody
        self._containment = containment
        self._fence = fence

    async def reconcile(
        self,
        observation: BackendObservation,
        *,
        admitted: AdmittedInstallation,
    ) -> BackendReconciliation:
        """CAS a trusted, shape-validated observation in its own transaction.

        A stale observation refuses without allocation/event; an equal remote
        version is a no-op. A changed version activates for later fresh uses
        only. The caller must never reuse this attempt or its old approval.
        """
        old = observation.binding.context
        if (old.installation_id, old.team_id) != (admitted.installation_id, admitted.team_id):
            raise CustodyUnavailable("backend observation scope differs")
        async with self._db.transaction() as tx:
            await self._fence.check(tx, admitted)
            await self._containment.prepare_replacements(
                tx,
                installation_id=admitted.installation_id,
                team_id=admitted.team_id,
                secret_ids=(old.secret_id,),
            )
            current = await active_binding(tx, old)
            if current != observation.binding:
                raise CustodyUnavailable("the backend observation is stale")
            if type(observation.item_version) is not int or observation.item_version <= 0:
                raise CustodyUnavailable("unusable backend observation")
            if observation.item_version == current.item_version:
                return BackendReconciliation(False)
            # All active-version writers serialize with owner-confirmed writes.
            # The bump also makes pending change-set projections stale.
            await bump_config_revision(tx, admitted.installation_id)
            new = await self._custody.stage_onepassword_observation(tx, observation)
            affected = await self._containment.replacement_consequences(
                tx,
                old=old,
                new=new.context,
                revoked_by="backend_observation",
            )
            await records.set_active_version(
                tx,
                admitted.installation_id,
                admitted.team_id,
                old.secret_id,
                new.context.version,
            )
            await self._custody.destroy(tx, old)
            await self._containment.governance(
                tx,
                team_id=admitted.team_id,
                payload={
                    "act": "resource.version_observed",
                    "direction": "narrowing",
                    "authority": "backend_observation",
                    "resource_type": "secret",
                    "resource_ref": old.secret_id,
                    "before_ref": current.version_ref,
                    "after_ref": new.version_ref,
                    "reason_code": "external_version_changed",
                },
                actor={"authority_mode": "system", "attestations": []},
                occurred_at=datetime.now(UTC),
                result_status="success",
            )
            # Sample F6's live clock after every potentially blocking phase.
            await self._fence.check(tx, admitted)
        return BackendReconciliation(True, tuple(sorted({old.secret_id, *affected})))
