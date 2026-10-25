"""Transaction-only job helper for custody's sole change-set writer.

Caller order: installation/forest -> grants -> existing CURRENT pointers FOR
UPDATE (sorted job_prelock_ids) -> B2 union/admission -> config revision ->
apply. The revision serializes absent first-create pointers; apply rechecks
presence without a late authority lock. This module never claims a revision,
consumes approval, emits governance, starts/commits a transaction or delivers.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from pgdbm import TransactionManager

from aweb_secrets.change import ChangeRefused
from aweb_secrets.jobs import JobDefinition, JobInvalid, create_job


def _job(item: Mapping[str, Any]) -> JobDefinition:
    if (
        set(item) != {"kind", "op", "ref", "after"}
        or item["kind"] != "job"
        or item["op"] not in ("create", "update")
        or not isinstance(item["after"], dict)
    ):
        raise ChangeRefused("invalid job change")
    try:
        job = JobDefinition.from_after(item["after"])
    except JobInvalid:
        raise ChangeRefused("invalid job definition") from None
    if item["ref"] != job.job_id:
        raise ChangeRefused("job ref differs from definition")
    return job


def job_prelock_ids(items: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    """Pure preparation input; custody acquires these before B2, after grants."""
    return tuple(sorted({_job(item).job_id for item in items if item.get("kind") == "job"}))


async def apply_job_change(
    tx: TransactionManager,
    *,
    installation_id: str,
    team_id: str,
    item: Mapping[str, Any],
) -> None:
    job = _job(item)
    row = await tx.fetch_one(
        "SELECT d.team_id FROM {{tables.current_jobs}} c"
        " JOIN {{tables.job_definitions}} d USING (installation_id,job_id,digest)"
        " WHERE c.installation_id=$1 AND c.job_id=$2",
        installation_id,
        job.job_id,
    )
    if item["op"] == "create" and row is not None:
        raise ChangeRefused("job already exists", code="record_exists")
    if item["op"] == "update" and (row is None or row["team_id"] != team_id):
        raise ChangeRefused("job not found", code="record_missing")
    await create_job(tx, installation_id, team_id, job)
