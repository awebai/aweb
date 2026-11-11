"""Console lookup through the root's one authoritative installation fence."""

from aweb_naapp.runtime.installation import AdmittedInstallation, InstallationFence


class InstallationLookup:
    """The team selects a G1 lookup; only its admitted identity is returned.

    Owner bootstrap can therefore start with an empty F6 store. An installation
    is resolved for the caller's team only: an id that another team holds is
    not found, exactly as an unknown id is, and no other team's row is read.
    """

    def __init__(self, fence: InstallationFence) -> None:
        self._fence = fence

    async def __call__(self, installation_id: str, *, team_id: str) -> AdmittedInstallation:
        if not installation_id or not team_id:
            raise LookupError("installation not found")
        admitted = (await self._fence.permit(team_id)).admitted
        if (
            admitted.app_id != self._fence.app_id
            or admitted.team_id != team_id
            or admitted.installation_id != installation_id
        ):
            raise LookupError("installation not found")
        return admitted
