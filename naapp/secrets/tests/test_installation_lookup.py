"""Root lookup resolves the untrusted hint through the single shared G1/F6."""

from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.authorization import GrantUnavailable
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationRefused,
    apply_installation_migrations,
)
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.installation_lookup import InstallationLookup
from tests.test_change_sets import APP_ID, TEAM, Installations


OTHER_TEAM = "other:example.com"


class Authority(Installations):
    """Controllable external G1 source, using the real shared fence."""

    failure = None

    async def status_for(self, team_id):
        if self.failure == "unavailable":
            raise GrantUnavailable("test authority unavailable")
        status = await super().status_for(team_id)
        if status is None:
            return None
        fields = vars(status)
        if self.failure == "pending":
            fields["state"] = "pending"
        elif self.failure == "wrong-app":
            fields["app_id"] = "another-app"
        elif self.failure == "wrong-team":
            fields["team_id"] = "other:example.com"
        return SimpleNamespace(**fields)


@pytest.fixture
async def lookup(test_db_factory):
    db = await test_db_factory.create_db(suffix="root_lookup")
    await apply_installation_migrations(db)
    source = Authority()
    fence = InstallationFence(db, app_id=APP_ID, grants=source)
    return InstallationLookup(fence), db, source


async def test_first_lookup_admits_authority_without_a_seeded_installation(lookup):
    resolve, db, _ = lookup
    assert await db.fetch_value("SELECT count(*) FROM {{tables.installation_fences}}") == 0
    admitted = await resolve(INSTALLATION_ID, team_id=TEAM)
    assert (admitted.app_id, admitted.team_id, admitted.installation_id, admitted.generation) == (
        APP_ID,
        TEAM,
        INSTALLATION_ID,
        1,
    )
    assert await resolve(INSTALLATION_ID, team_id=TEAM) == admitted
    assert await db.fetch_value("SELECT count(*) FROM {{tables.installation_fences}}") == 1


async def test_an_admitted_installation_is_not_resolved_by_its_id_alone(lookup):
    resolve, _, _ = lookup
    await resolve(INSTALLATION_ID, team_id=TEAM)
    with pytest.raises(LookupError):
        await resolve(INSTALLATION_ID, team_id=None)


class TwoTeams(Authority):
    """Each team's own server reports its installation id, whatever it claims."""

    def __init__(self, installation_ids):
        super().__init__()
        self.installation_ids = installation_ids

    async def status_for(self, team_id):
        if team_id not in self.installation_ids:
            return None
        status = await Authority(team_id=team_id).status_for(team_id)
        fields = vars(status)
        fields["installation_id"] = self.installation_ids[team_id]
        return SimpleNamespace(**fields)


async def _two_teams(test_db_factory, installation_ids):
    db = await test_db_factory.create_db(suffix="root_lookup_teams")
    await apply_installation_migrations(db)
    fence = InstallationFence(db, app_id=APP_ID, grants=TwoTeams(installation_ids))
    return InstallationLookup(fence), db


async def _refusal(resolve, installation_id, team_id):
    with pytest.raises(LookupError) as refused:
        await resolve(installation_id, team_id=team_id)
    return type(refused.value), str(refused.value)


async def test_another_teams_installation_id_answers_as_an_unknown_id_does(test_db_factory):
    resolve, db = await _two_teams(
        test_db_factory, {TEAM: INSTALLATION_ID, OTHER_TEAM: "other-installation"}
    )
    admitted = await resolve(INSTALLATION_ID, team_id=TEAM)
    await resolve("other-installation", team_id=OTHER_TEAM)
    assert await _refusal(resolve, INSTALLATION_ID, OTHER_TEAM) == await _refusal(
        resolve, "unknown-installation", OTHER_TEAM
    )
    assert await resolve(INSTALLATION_ID, team_id=TEAM) == admitted


async def test_a_team_reporting_another_teams_installation_id_leaves_that_team_resolvable(
    test_db_factory,
):
    resolve, db = await _two_teams(
        test_db_factory, {TEAM: INSTALLATION_ID, OTHER_TEAM: INSTALLATION_ID}
    )
    admitted = await resolve(INSTALLATION_ID, team_id=TEAM)
    assert (await resolve(INSTALLATION_ID, team_id=OTHER_TEAM)).team_id == OTHER_TEAM
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.installation_fences}} WHERE installation_id=$1",
            INSTALLATION_ID,
        )
        == 2
    )
    assert await resolve(INSTALLATION_ID, team_id=TEAM) == admitted


@pytest.mark.parametrize("hint", [None, "other:example.com"])
async def test_unknown_lookup_cannot_create_authority_from_an_id_or_hint(lookup, hint):
    resolve, db, _ = lookup
    with pytest.raises((LookupError, InstallationRefused)):
        await resolve(INSTALLATION_ID, team_id=hint)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.installation_fences}}") == 0


async def test_authority_for_another_installation_never_authenticates_the_requested_id(lookup):
    resolve, _, _ = lookup
    with pytest.raises(LookupError):
        await resolve("another-installation", team_id=TEAM)


@pytest.mark.parametrize("failure", ["pending", "unavailable", "wrong-app", "wrong-team"])
async def test_unavailable_or_inconsistent_g1_never_returns_an_admission(lookup, failure):
    resolve, _, source = lookup
    source.failure = failure
    with pytest.raises(InstallationRefused):
        await resolve(INSTALLATION_ID, team_id=TEAM)


async def test_each_call_refreshes_authority_instead_of_reusing_admitted_rows(lookup):
    resolve, db, source = lookup
    await resolve(INSTALLATION_ID, team_id=TEAM)
    source.failure = "unavailable"
    with pytest.raises(InstallationRefused) as refused:
        await resolve(INSTALLATION_ID, team_id=TEAM)
    assert refused.value.status == 503
    assert await db.fetch_value("SELECT fresh_until FROM {{tables.installation_fences}}") is None
