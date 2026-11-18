"""Malformed Graph answers make the outcome unknown, never a crash."""

import httpx
import pytest

from onedrive import GraphAppFolder, ProviderUnavailable

GRAPH = "https://graph.standin.invalid/v1.0"
ITEM = {
    "id": "ITEM-1",
    "name": "summary.md",
    "size": 12,
    "description": "bound",
    "file": {"hashes": {"quickXorHash": "AAAA"}},
}


def folder_answering(body) -> GraphAppFolder:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    return GraphAppFolder(httpx.Client(transport=transport), token=lambda: "t", base=GRAPH)


def test_a_well_formed_listing_parses():
    [item] = folder_answering({"value": [ITEM]}).list_items()
    assert (item.id, item.name, item.size, item.quick_xor_hash, item.description) == (
        "ITEM-1",
        "summary.md",
        12,
        "AAAA",
        "bound",
    )


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        {"value": None},
        {"value": {"id": "ITEM-1"}},
        {"value": "not a list"},
        {"value": [ITEM], "@odata.nextLink": 5},
        {"value": ["not an object"]},
        {"value": [{**ITEM, "id": None}]},
        {"value": [{**ITEM, "id": ""}]},
        {"value": [{**ITEM, "name": 3}]},
        {"value": [{**ITEM, "size": "12"}]},
        {"value": [{**ITEM, "size": True}]},
        {"value": [{key: value for key, value in ITEM.items() if key != "size"}]},
        {"value": [{**ITEM, "description": 1}]},
        {"value": [{**ITEM, "file": {"hashes": {"quickXorHash": 1}}}]},
    ],
)
def test_a_malformed_listing_is_unavailable(body):
    with pytest.raises(ProviderUnavailable, match="malformed_response"):
        folder_answering(body).list_items()


@pytest.mark.parametrize(
    "body",
    [
        {"id": "ROOT"},
        {"id": "ROOT", "parentReference": "drive"},
        {"id": "ROOT", "parentReference": {"driveId": 4}},
        {"parentReference": {"driveId": "drive"}},
    ],
)
def test_a_malformed_app_folder_is_unavailable(body):
    with pytest.raises(ProviderUnavailable, match="malformed_response"):
        folder_answering(body).destination()


@pytest.mark.parametrize("body", [{}, {"uploadUrl": 7}, {"uploadUrl": ""}])
def test_a_malformed_upload_session_is_unavailable(body):
    with pytest.raises(ProviderUnavailable, match="malformed_response"):
        folder_answering(body).upload_new("summary.md", b"x", "bound")


def test_a_body_that_is_not_json_is_unavailable():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"<html>"))
    folder = GraphAppFolder(httpx.Client(transport=transport), token=lambda: "t", base=GRAPH)
    with pytest.raises(ProviderUnavailable, match="malformed_response"):
        folder.list_items()
