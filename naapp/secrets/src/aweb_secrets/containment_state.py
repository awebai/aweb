"""Local kill switch checked under the shared installation fence."""

from pgdbm.core import TransactionManager


class ContainmentRefused(Exception):
    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


async def require_enabled(tx: TransactionManager, installation_id: str, team_id: str) -> None:
    """Called under the installation fence at admission and dispatch."""
    disabled = await tx.fetch_value(
        "SELECT disabled_at IS NOT NULL FROM {{tables.containment_installations}}"
        " WHERE installation_id=$1 AND team_id=$2 FOR SHARE",
        installation_id,
        team_id,
    )
    if disabled:
        raise ContainmentRefused("installation_disabled")
