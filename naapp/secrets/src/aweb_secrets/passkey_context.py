"""B3 challenge context from persisted scope bindings and the shared F6 record.

Construct once with the configured shared fence.app_id and inject into the
single Passkeys service. B3 supplies its challenge-write transaction. This is
a SQL-only directory read: no owned transaction, network, FOR lock or role
authority. Refresh/admission belongs before B3; proof retrieval never calls
this resolver to relabel historical evidence.
"""

from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    ProofContextUnavailable,
    installation_context,
)
from pgdbm.core import TransactionManager


class PasskeyContexts:
    def __init__(self, *, app_id: str) -> None:
        if not isinstance(app_id, str) or not app_id:
            raise ValueError("passkey context requires the configured app ID")
        self._app_id = app_id

    async def __call__(self, scope: str, *, tx: TransactionManager) -> PasskeyInstallationContext:
        bindings = await tx.fetch_all(
            """
            SELECT installation_id,team_id FROM {{tables.owner_principals}} WHERE scope=$1
            UNION
            SELECT installation_id,team_id FROM {{tables.approvers}} WHERE scope=$1
            """,
            scope,
        )
        if len(bindings) != 1:
            raise ProofContextUnavailable()
        return await installation_context(
            tx,
            app_id=self._app_id,
            team_id=bindings[0]["team_id"],
            installation_id=bindings[0]["installation_id"],
        )
