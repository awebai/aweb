"""The one Python reader consumes the public owner-act manifest verdicts."""

import copy
import json
from pathlib import Path

import pytest

from aweb_naapp.manifest import (
    SUPPORTED_MANIFEST_VERSIONS,
    ManifestError,
    canonical_bytes,
    load_manifest,
    select_variant,
)
from tests.test_manifest_v2_vectors import RESERVED, V2, _manifest_bytes

AWEB_ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = AWEB_ROOT / "docs" / "vectors" / "owner-act-delivery-v1.json"
CASES = json.loads(VECTOR_PATH.read_bytes())["manifest_cases"]


def document(case, *, version=3):
    return {
        "manifest_version": version,
        "app": {"id": "example", "version": "1.0.0", "origin": case["app_origin"]},
        "tools": [],
        "owner_acts": copy.deepcopy(case["owner_acts"]),
    }


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_shared_owner_act_manifest_verdict(case):
    data = canonical_bytes(document(case))
    if case["error"] is not None:
        with pytest.raises(ManifestError) as caught:
            load_manifest(data)
        assert caught.value.code == case["error"]
    else:
        manifest = load_manifest(data)
        assert manifest.manifest_version == 3
        assert manifest.owner_acts == case["owner_acts"]
        assert manifest.document == document(case)
        assert manifest.view()["owner_acts"] == case["owner_acts"]


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_older_versions_still_refuse_owner_acts(version, case):
    with pytest.raises(ManifestError) as caught:
        load_manifest(canonical_bytes(document(case, version=version)))
    assert caught.value.code == "manifest_invalid"


def test_v3_can_have_no_owner_designated_roles():
    value = document(CASES[0])
    value.pop("owner_acts")
    manifest = load_manifest(canonical_bytes(value))
    assert manifest.owner_acts is None
    assert "owner_acts" not in manifest.view()


def test_current_discovery_selects_v3_and_released_reader_selects_v2():
    import hashlib

    v3 = document(CASES[0])
    v2 = {**v3, "manifest_version": 2}
    v2.pop("owner_acts")
    responses = {"/v2.json": canonical_bytes(v2), "/v3.json": canonical_bytes(v3)}
    catalog = {
        "catalog_version": 1,
        "app_id": "example",
        "variants": [
            {
                "manifest_version": version,
                "url": path,
                "digest": "sha256:" + hashlib.sha256(responses[path]).hexdigest(),
            }
            for version, path in ((2, "/v2.json"), (3, "/v3.json"))
        ],
    }
    responses["/.well-known/aweb-app-versions.json"] = canonical_bytes(catalog)

    def fetch(path, limit):
        body = responses.get(path, b"")
        assert len(body) <= limit
        return (200 if body else 404), body

    assert 3 in SUPPORTED_MANIFEST_VERSIONS
    origin = CASES[0]["app_origin"]
    assert select_variant(origin, SUPPORTED_MANIFEST_VERSIONS, fetch).manifest_version == 3
    assert select_variant(origin, (1, 2), fetch).manifest_version == 2


# V3 adds only owner declarations: existing V2 answer refusals must still apply.
@pytest.mark.parametrize(
    "case",
    [case for case in V2["answer_payload_cases"] if case["base"] == "v2"],
    ids=lambda case: case["name"],
)
def test_v3_keeps_answer_payload_refusals(case):
    value = json.loads(_manifest_bytes(case))
    value["manifest_version"] = 3
    manifest = load_manifest(canonical_bytes(value), reserved_names=RESERVED)
    if case["expected"] == "not_refused":
        manifest.check_answer_payload(case["tool"], case["body"])
    else:
        with pytest.raises(ManifestError) as caught:
            manifest.check_answer_payload(case["tool"], case["body"])
        assert caught.value.code == case["expected"]


@pytest.mark.parametrize("count,accepted", [(16, True), (17, False)])
def test_owner_role_count_boundary(count, accepted):
    value = document(CASES[0])
    role = value["owner_acts"]["roles"][0]
    value["owner_acts"]["roles"] = [{**role, "name": f"example.role{n}"} for n in range(count)]
    if accepted:
        assert len(load_manifest(canonical_bytes(value)).owner_acts["roles"]) == count
    else:
        with pytest.raises(ManifestError) as caught:
            load_manifest(canonical_bytes(value))
        assert caught.value.code == "owner_acts_invalid"


@pytest.mark.parametrize("field,limit", [("label", 128), ("description", 512)])
@pytest.mark.parametrize("text_kind", ["limit", "too_long", "control", "bidi"])
def test_owner_role_text_boundaries(field, limit, text_kind):
    value = document(CASES[0])
    text = {
        "limit": "é" * limit,
        "too_long": "é" * (limit + 1),
        "control": "Role\u0085text",
        "bidi": "Role\u202etext",
    }[text_kind]
    value["owner_acts"]["roles"][0][field] = text
    if text_kind == "limit":
        assert load_manifest(canonical_bytes(value)).owner_acts["roles"][0][field] == text
    else:
        with pytest.raises(ManifestError) as caught:
            load_manifest(canonical_bytes(value))
        assert caught.value.code == "owner_acts_invalid"


@pytest.mark.parametrize(
    "case",
    [
        case
        for case in V2["cases"]
        if case["base"] == "v2"
        and not any(m["path"] == "/manifest_version" for m in case["mutations"])
    ],
    ids=lambda case: case["name"],
)
def test_v3_keeps_v2_load_verdicts(case):
    value = json.loads(_manifest_bytes(case))
    value["manifest_version"] = 3
    expected = case["expected"]
    if expected["accepted"]:
        resolved = {**expected["resolved"], "manifest_version": 3}
        assert load_manifest(canonical_bytes(value), reserved_names=RESERVED).view() == resolved
    else:
        with pytest.raises(ManifestError) as caught:
            load_manifest(canonical_bytes(value), reserved_names=RESERVED)
        assert caught.value.code == expected["error"]


def test_owner_origin_does_not_bypass_hostname_separation_with_app_whitespace():
    value = document(CASES[0])
    value["app"]["origin"] = " " + value["owner_acts"]["origin"] + " "
    with pytest.raises(ManifestError) as caught:
        load_manifest(canonical_bytes(value))
    assert caught.value.code == "owner_acts_invalid"
