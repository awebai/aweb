"""Grant-scoped agent metadata. This module never reads credential storage.

Call after B1 authorization. Reads use the same installation fence and stable
principal/role keys as admission, without admitting a use, consuming an
approval or charging a rate bucket. Discovery is not execution authority.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from aweb_naapp.roles import principal_key, roles_of
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager

from aweb_secrets import jobs, records
from aweb_secrets.grant import GrantRecord
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord


class CatalogRefused(ValueError):
    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class Catalog:
    def __init__(self, db: AsyncDatabaseManager, *, fence: InstallationFence) -> None:
        self.db = db
        self.fence = fence

    async def list(self, *, grant: Grant, principal: Principal) -> list[dict[str, Any]]:
        return await self._read(None, grant=grant, principal=principal)

    async def describe(self, ref: str, *, grant: Grant, principal: Principal) -> dict[str, Any]:
        found = await self._read(ref, grant=grant, principal=principal)
        if not found:
            raise CatalogRefused("secret_not_found", 404)
        return found[0]

    async def _read(self, ref: str | None, *, grant: Grant, principal: Principal):
        if grant.team_id != principal.team_id:
            raise CatalogRefused("grant_missing")
        async with self.db.transaction() as tx:
            installation = await self.fence.admit(tx, grant)
            key = principal_key(principal)
            roles = await roles_of(tx, key)
            owner = OWNER_ROLE in roles
            rows = await tx.fetch_all(
                """SELECT record, state FROM {{tables.secrets}}
                   WHERE installation_id = $1 AND team_id = $2
                     AND ($3::text IS NULL OR ref = $3) ORDER BY ref""",
                installation.installation_id,
                installation.team_id,
                ref,
            )
            result = []
            for row in rows:
                secret = SecretRecord.from_after(json.loads(row["record"]))
                grants = await records.active_grants(
                    tx,
                    installation.installation_id,
                    secret.secret_id,
                    principal_did=key.principal_did,
                    roles=roles,
                )
                policies = {}
                for candidate in grants:
                    policy = await records.policy(
                        tx, installation.installation_id, candidate.policy_digest
                    )
                    if policy is not None:
                        policies[candidate.grant_id] = policy
                grants = [candidate for candidate in grants if candidate.grant_id in policies]
                if not owner and (row["state"] != "active" or not grants):
                    continue
                destinations = await records.destinations(
                    tx, installation.installation_id, secret.secret_id
                )
                item = {
                    "ref": secret.ref,
                    "kind": secret.after["kind"],
                    "sensitivity": secret.after["sensitivity"],
                    "approval_required": secret.after["approve_only"]
                    or (
                        bool(grants)
                        and all(policies[g.grant_id].body["approval"] == "per_use" for g in grants)
                    ),
                    "destinations": [
                        {
                            field: scope.after[field]
                            for field in ("scheme", "host", "port", "path", "methods")
                        }
                        for scope in destinations
                    ],
                }
                if ref is not None:
                    item["operations"] = await self._operations(
                        tx, installation.installation_id, secret, grants, policies, owner
                    )
                    item["jobs"] = await self._jobs(
                        tx,
                        installation.installation_id,
                        installation.team_id,
                        secret,
                        grants,
                        owner,
                    )
                result.append(item)
            # Fence freshness is checked after the authority reads/lock waits.
            await self.fence.check(tx, installation)
            return result

    async def _operations(
        self,
        tx,
        installation_id,
        secret,
        grants: Sequence[GrantRecord],
        policies: dict[str, Policy],
        owner: bool,
    ):
        rows = await tx.fetch_all(
            """SELECT operation_id FROM {{tables.current_operations}}
               WHERE installation_id = $1 AND secret_id = $2 ORDER BY operation_id""",
            installation_id,
            secret.secret_id,
        )
        found = []
        for row in rows:
            operation = await records.current_operation(
                tx, installation_id, secret.secret_id, row["operation_id"]
            )
            if operation is None:
                continue
            pin = (operation.operation_id, operation.digest)
            if owner or any(
                g.capability == "use"
                and g.covers_operation(*pin)
                and pin in policies[g.grant_id].allowed_operations
                for g in grants
            ):
                found.append(
                    {
                        "operation_id": operation.operation_id,
                        "digest": operation.digest,
                        "params": operation.after["params"],
                    }
                )
        return found

    async def _jobs(
        self, tx, installation_id, team_id, secret, grants: Sequence[GrantRecord], owner: bool
    ):
        pins = {pin for g in grants if g.capability == "run" for pin in g.jobs}
        if owner:
            rows = await tx.fetch_all(
                """SELECT c.job_id, c.digest FROM {{tables.current_jobs}} c
                   JOIN {{tables.job_definitions}} d USING (installation_id, job_id, digest)
                   WHERE c.installation_id = $1 AND d.team_id = $2 ORDER BY c.job_id""",
                installation_id,
                team_id,
            )
            pins.update((row["job_id"], row["digest"]) for row in rows)
        found = []
        for job_id, digest in sorted(pins):
            job = await jobs.current_job(tx, installation_id, job_id)
            if job is None or job.digest != digest:
                continue
            same_team = await tx.fetch_value(
                """SELECT EXISTS (SELECT 1 FROM {{tables.job_definitions}}
                   WHERE installation_id = $1 AND team_id = $2 AND job_id = $3 AND digest = $4)""",
                installation_id,
                team_id,
                job_id,
                digest,
            )
            if not same_team:
                continue
            body = job.after
            if not any(slot["secret_ref"] == secret.ref for slot in body["credentials"]):
                continue
            found.append(
                {
                    "job_id": job.job_id,
                    "digest": job.digest,
                    "params": body["params"],
                    "runner_ids": body["runner_ids"],
                }
            )
        return found
