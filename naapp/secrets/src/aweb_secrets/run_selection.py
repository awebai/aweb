"""Inert discovery for the manifest's optional ordinary-child run selector.

The planner locks/rechecks the complete selected forest and each child's own
run grant. Discovery never supplies grant, slot-override or mint authority.
Run-bound issuance remains unavailable in this service.
"""

from aweb_naapp.runtime.installation import AdmittedInstallation
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, jobs, records
from aweb_secrets.run_plan import RunPlanRefused


async def discover_sources(
    tx: TransactionManager,
    installation: AdmittedInstallation,
    job: jobs.JobDefinition,
    *,
    selected_ref: str | None,
) -> list[str]:
    credentials = job.after["credentials"]
    selected_id = None
    selected_ordinal = None
    if selected_ref is not None:
        child = await records.secret_by_ref(
            tx, installation.installation_id, installation.team_id, selected_ref, lock=False
        )
        if child is None:
            raise RunPlanRefused("job_not_allowed")
        selected_id = child.record.secret_id
        ids = await derived_lineage.ancestry_ids(
            tx, installation.installation_id, installation.team_id, selected_id
        )
        if len(ids) < 2:
            raise RunPlanRefused("job_not_allowed")
        refs = await tx.fetch_all(
            "SELECT ref FROM {{tables.secrets}} WHERE installation_id=$1 AND team_id=$2 AND secret_id=ANY($3::text[])",
            installation.installation_id,
            installation.team_id,
            list(ids),
        )
        try:
            selected_ordinal = jobs.unique_durable_slot(
                job, lineage_refs=[row["ref"] for row in refs]
            )
        except jobs.JobRefused:
            raise RunPlanRefused("job_not_allowed") from None
    sources = []
    for ordinal, slot in enumerate(credentials):
        if ordinal == selected_ordinal:
            assert selected_id is not None
            sources.append(selected_id)
        else:
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
    return sources
