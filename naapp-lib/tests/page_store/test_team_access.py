"""Team grants remain page/scope-bound and never grant owner operations."""

from dataclasses import replace

import pytest

from aweb_naapp.page_store import Access, Scope, StoreError
from tests.page_store.test_store import OWNER, SCOPE, STRANGER, page


@pytest.mark.parametrize("read,write", [(True, False), (False, True), (True, True)])
async def test_admitted_team_members_share_rows_but_not_owner_operations(store, read, write):
    await store.create(
        SCOPE,
        OWNER,
        page(),
        access=Access(owner=OWNER.did_key, team_id=SCOPE.team_id, team_read=read, team_write=write),
        key="create",
    )
    snapshot = await store.read(SCOPE, STRANGER)
    assert snapshot["rev"] == 1
    if write:
        receipt = await store.patch_record(
            SCOPE,
            STRANGER,
            collection="items",
            record_id="item-1",
            expected_rev=1,
            patch={"checked": True},
            key="team-patch",
        )
        assert receipt["rev"] == 2
    else:
        with pytest.raises(StoreError, match="resource_not_found"):
            await store.patch_record(
                SCOPE,
                STRANGER,
                collection="items",
                record_id="item-1",
                expected_rev=1,
                patch={"checked": True},
                key="denied",
            )
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.append_layout(
            SCOPE,
            STRANGER,
            expected_rev=snapshot["rev"],
            key="owner-only",
            layout=snapshot["layout"],
        )
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.change_access(
            SCOPE,
            STRANGER,
            expected_rev=snapshot["rev"],
            key="acl-only",
            access=Access(owner=STRANGER.did_key),
        )


async def test_team_grant_keeps_individual_row_and_field_restrictions(store):
    document = page()
    document["collections"][0]["records"].append(
        {"id": "hidden", "rev": 1, "value": {"label": "Private row", "checked": False}}
    )
    access = Access(
        owner=OWNER.did_key,
        team_id=SCOPE.team_id,
        team_read=True,
        team_write=True,
        hidden_rows={STRANGER.did_key: {"items": {"hidden"}}},
        fields={STRANGER.did_key: {"items": {"checked"}}},
    )
    await store.create(SCOPE, OWNER, document, access=access, key="create")
    result = await store.read_widget(
        SCOPE, STRANGER, widget_id="items", expected_page_rev=1, bind={"collection": "items"}
    )
    assert result["count"] == 1 and result["records"][0]["value"] == {"checked": False}
    with pytest.raises(StoreError, match="query_denied"):
        await store.read_widget(
            SCOPE,
            STRANGER,
            widget_id="items",
            expected_page_rev=1,
            bind={"collection": "items", "sort": [{"field": "label", "direction": "asc"}]},
        )
    with pytest.raises(StoreError, match="action_denied"):
        await store.patch_record(
            SCOPE,
            STRANGER,
            collection="items",
            record_id="hidden",
            expected_rev=1,
            patch={"checked": True},
            key="hidden",
        )


async def test_team_grant_refuses_other_team_installation_and_mismatched_acl_scope(store):
    access = Access(owner=OWNER.did_key, team_id=SCOPE.team_id, team_read=True, team_write=True)
    await store.create(SCOPE, OWNER, page(), access=access, key="create")
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.read(SCOPE, replace(STRANGER, team_id="other:team.example"))
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.read(
            Scope("other-install", SCOPE.team_id, SCOPE.app_id, SCOPE.page_id), STRANGER
        )
    with pytest.raises(StoreError, match="action_denied"):
        await store.change_access(
            SCOPE,
            OWNER,
            expected_rev=1,
            key="wrong-team",
            access=Access(owner=OWNER.did_key, team_id="other:team.example", team_read=True),
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 1


@pytest.mark.parametrize(
    "settings", [{"team_read": "false"}, {"team_write": 1}, {"team_read": True}]
)
def test_team_flags_are_explicit_booleans_with_an_explicit_team(settings):
    with pytest.raises(ValueError):
        Access(owner=OWNER.did_key, **settings)
