"""Console lookup through the root's one authoritative installation fence."""

from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence


class InstallationLookup:
    """A team hint selects a G1 lookup; only its admitted identity is returned.

    Owner bootstrap can therefore start with an empty F6 store. ID-only calls
    resolve the team from that store and still refresh the same authority.
    """

    def __init__(self, fence: InstallationFence) -> None:
        self._fence = fence

    async def __call__(
        self, installation_id: str, *, team_id: str | None = None
    ) -> AdmittedInstallation:
        if not installation_id or team_id == "":
            raise LookupError("installation not found")
        if team_id is None:
            rows = await self._fence.db.fetch_all(
                "SELECT team_id FROM {{tables.installation_fences}} "
                "WHERE app_id=$1 AND installation_id=$2",
                self._fence.app_id,
                installation_id,
            )
            if len(rows) != 1:
                raise LookupError("installation not found")
            team_id = rows[0]["team_id"]
        admitted = (await self._fence.permit(team_id)).admitted
        if (
            admitted.app_id != self._fence.app_id
            or admitted.team_id != team_id
            or admitted.installation_id != installation_id
        ):
            raise LookupError("installation not found")
        return admitted
