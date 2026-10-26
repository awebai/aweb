"""Collection identity is bound to installation, team and app."""

from uuid import UUID

from aweb_naapp.runtime.installation import AdmittedInstallation
from test_record_storage import ACTOR

from folio.collection_scope import collection_scope

INSTALLATION = AdmittedInstallation(
    team_id=ACTOR.team_id, app_id="folio", installation_id="install-1", generation=1
)


def test_page_id_is_stable_per_installed_team_and_collection_and_accepts_long_ids():
    scope = collection_scope(INSTALLATION, "discovery")
    assert scope == collection_scope(INSTALLATION, "discovery")
    assert str(UUID(scope.page_id)) == scope.page_id
    for changes in [
        dict(installation_id="install-2"),
        dict(team_id="other:example.test"),
        dict(app_id="other-app"),
    ]:
        other = AdmittedInstallation(**{**INSTALLATION.__dict__, **changes})
        assert collection_scope(other, "discovery").page_id != scope.page_id
    assert collection_scope(INSTALLATION, "x" * 128).page_id != scope.page_id
