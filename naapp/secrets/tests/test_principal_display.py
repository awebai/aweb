"""Owner views name a principal from the runtime's own observations, never by name."""

from pathlib import Path

import aweb_naapp.runtime
import pytest
from aweb_naapp.runtime.team_auth import Principal, record_observed_principal
from pgdbm import AsyncMigrationManager

from aweb_secrets.principal_display import observed_principal_alias, principal_html

TEAM = "backend:acme.com"
DID_AW = "did:aw:2VbyZAlice"
DID_KEY = "did:key:z6MkAlice"
RUNTIME_MIGRATIONS = Path(aweb_naapp.runtime.__file__).parent / "migrations"


def observed(**changes) -> Principal:
    fields = dict(
        team_id=TEAM,
        did_key=DID_KEY,
        did_aw=None,
        address=None,
        alias="alice",
        certificate_id="cert-1",
        team_did_key="did:key:z6MkTeam",
    )
    return Principal(**{**fields, **changes})


@pytest.fixture
async def db(test_db_factory):
    db = await test_db_factory.create_db(suffix="secrets_principal_display")
    await AsyncMigrationManager(
        db, migrations_path=str(RUNTIME_MIGRATIONS), module_name="aweb_naapp"
    ).apply_pending_migrations()
    return db


async def alias_of(db, principal_did: str, *, team_id: str = TEAM) -> str | None:
    async with db.transaction() as tx:
        return await observed_principal_alias(tx, team_id=team_id, principal_did=principal_did)


async def test_a_did_aw_principal_is_named_by_its_observed_alias(db):
    await record_observed_principal(db, observed(did_aw=DID_AW))
    # A key rotation is another observed row of the same stable identity.
    await record_observed_principal(db, observed(did_aw=DID_AW, did_key="did:key:z6MkRotated"))
    assert await alias_of(db, DID_AW) == "alice"


async def test_a_did_key_principal_is_named_only_by_observations_without_a_did_aw(db):
    await record_observed_principal(db, observed())
    assert await alias_of(db, DID_KEY) == "alice"
    # The canonical principal of a key that carries a did_aw is the did_aw.
    await record_observed_principal(db, observed(did_key="did:key:z6MkBob", did_aw=DID_AW))
    assert await alias_of(db, "did:key:z6MkBob") is None


async def test_conflicting_observed_aliases_name_nobody(db):
    await record_observed_principal(db, observed(did_aw=DID_AW))
    await record_observed_principal(db, observed(did_aw=DID_AW, alias="mallory"))
    await record_observed_principal(db, observed(did_key="did:key:z6MkCarol", alias="carol"))
    await record_observed_principal(db, observed(did_key="did:key:z6MkCarol", alias="carol-2"))
    assert await alias_of(db, DID_AW) is None
    assert await alias_of(db, "did:key:z6MkCarol") is None


async def test_names_are_scoped_to_the_exact_team(db):
    await record_observed_principal(db, observed(team_id="backend:other.com", did_aw=DID_AW))
    assert await alias_of(db, DID_AW) is None
    assert await alias_of(db, DID_AW, team_id="backend:other.com") == "alice"


@pytest.mark.parametrize("alias", ["", "   "])
async def test_an_empty_observed_alias_names_nobody(db, alias):
    await record_observed_principal(db, observed(did_aw=DID_AW, alias=alias))
    assert await alias_of(db, DID_AW) is None


@pytest.mark.parametrize("principal_did", [DID_AW, DID_KEY, "alice", "did:web:acme.com", ""])
async def test_an_unobserved_or_non_canonical_principal_has_no_name(db, principal_did):
    await record_observed_principal(db, observed(team_id="backend:other.com", alias="alice"))
    assert await alias_of(db, principal_did) is None


def test_a_named_principal_shows_its_escaped_name_team_and_did():
    html = principal_html(principal_did=DID_AW, alias="<b>al&ce</b>", team_id='acme"<x>')
    assert "&lt;b&gt;al&amp;ce&lt;/b&gt;" in html and "<b>" not in html
    assert "acme&quot;&lt;x&gt;" in html and '"<x>' not in html
    assert DID_AW in html


def test_an_unnamed_principal_shows_only_its_escaped_did():
    html = principal_html(principal_did='did:aw:"<x>', alias=None, team_id=TEAM)
    assert "did:aw:&quot;&lt;x&gt;" in html and '"<x>' not in html
    assert TEAM not in html
