"""Layout versions, display state and accessible author lint."""

from __future__ import annotations

import copy
import json

import pytest

from aweb_naapp.page_store import StoreError
from aweb_naapp.pages import lint_page
from tests.page_store.test_store import OWNER, SCOPE, create


async def test_layout_versions_are_immutable_and_ids_survive_reorder(store):
    await create(store)
    before = await store.read(SCOPE, OWNER)
    layout = list(reversed(before["layout"]))
    await store.append_layout(SCOPE, OWNER, expected_rev=1, key="reorder", layout=layout)
    after = await store.read(SCOPE, OWNER)
    assert after["layout_version"] == 2
    assert [w["id"] for w in after["layout"]] == ["future", "items"]
    history = await store.db.fetch_all(
        "SELECT version,layout FROM {{tables.page_layouts}} ORDER BY version"
    )
    assert json.loads(history[0]["layout"]) == before["layout"]
    assert json.loads(history[1]["layout"]) == layout
    changed = copy.deepcopy(layout)
    changed[1] = {"id": "items", "type": "text", "props": {"markdown": "A new semantic widget"}}
    with pytest.raises(StoreError, match="widget_identity_changed"):
        await store.append_layout(SCOPE, OWNER, expected_rev=2, key="reuse-id", layout=changed)


async def test_widget_state_only_overrides_display_and_never_mutates_layout(store):
    await create(store)
    snapshot = await store.read(SCOPE, OWNER)
    receipt = await store.mutate(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="busy",
        state={"items": {"busy": True, "progress": 25, "message": "Working"}},
    )
    after = await store.read(SCOPE, OWNER)
    assert after["layout"] == snapshot["layout"]
    assert after["layout_version"] == 1
    assert receipt["page_rev"] == 2
    assert after["widget_state"]["items"]["progress"] == 25
    for patch in (
        {"action": "approve"},
        {"policy_ref": "owner"},
        {"bind": {}},
        {"task_id": "fake"},
        {"input_schema": {}},
        {"progress": 101},
        {"url": "https://example.com"},
    ):
        with pytest.raises(StoreError, match="schema_invalid"):
            await store.mutate(
                SCOPE, OWNER, expected_rev=2, key=json.dumps(patch), state={"items": patch}
            )
    with pytest.raises(StoreError, match="schema_invalid"):
        await store.mutate(
            SCOPE, OWNER, expected_rev=2, key="unknown", state={"absent": {"busy": True}}
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 2


async def test_text_lint_shows_labels_values_policy_disabled_and_unknown_inert_fallback(store):
    await create(store)
    snapshot = await store.read(SCOPE, OWNER)
    projection = await store.read_widget(
        SCOPE, OWNER, widget_id="items", expected_page_rev=1, bind={"collection": "items"}
    )
    result = lint_page(
        snapshot, allowed_actions={"check"}, projections={"items": projection["records"]}
    )
    assert "Verify fixture inventory" in result.text
    assert result.valid
    assert "Fixture inventory" in result.text
    assert "Item" in result.text
    assert "Check item" in result.text
    assert "Ask the agent to restock [disabled by policy]" in result.text
    assert "This widget needs a newer renderer." in result.text
    assert "untrusted" not in result.text
    snapshot["widget_state"]["items"] = {"action": "request-restock"}
    invalid = lint_page(snapshot, allowed_actions=set())
    assert not invalid.valid
    assert any(error.pointer.startswith("/widget_state/items") for error in invalid.errors)
