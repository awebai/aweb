"""B3 challenge context from persisted scope bindings and the shared F6 record.

Construct once with the configured shared fence.app_id and inject into the
single Passkeys service. B3 supplies its challenge-write transaction. This is
a SQL-only directory read: no owned transaction, network, FOR lock or role
authority. Refresh/admission belongs before B3; proof retrieval never calls
this resolver to relabel historical evidence.
"""

from aweb_naapp.runtime.passkeys import PasskeyInstallationContext, ProofContextUnavailable
from pgdbm.core import TransactionManager


class PasskeyContexts:
    def __init__(self, *, app_id: str) -> None:
        if not isinstance(app_id, str) or not app_id:
            raise ValueError("passkey context requires the configured app ID")
        self._app_id = app_id

    async def __call__(self, scope: str, *, tx: TransactionManager) -> PasskeyInstallationContext:
        rows = await tx.fetch_all(
            """
            WITH bindings AS (
                SELECT installation_id,team_id FROM {{tables.owner_principals}} WHERE scope=$1
                UNION
                SELECT installation_id,team_id FROM {{tables.approvers}} WHERE scope=$1
            )
            SELECT f.app_id,b.team_id,b.installation_id,f.generation
            FROM bindings b JOIN {{tables.installation_fences}} f
                ON f.team_id=b.team_id AND f.installation_id=b.installation_id
                AND f.active_installation_id=b.installation_id
            WHERE f.app_id=$2 AND f.state='active' AND f.fresh_until>clock_timestamp()
                AND (SELECT count(*) FROM bindings)=1
                AND NOT EXISTS (
                    SELECT 1 FROM {{tables.retired_installation_fences}} r
                    WHERE r.app_id=f.app_id AND r.team_id=b.team_id
                        AND r.installation_id=b.installation_id
                )
            """,
            scope,
            self._app_id,
        )
        if len(rows) != 1:
            raise ProofContextUnavailable()
        row = rows[0]
        return PasskeyInstallationContext(
            row["app_id"], row["team_id"], row["installation_id"], row["generation"]
        )
