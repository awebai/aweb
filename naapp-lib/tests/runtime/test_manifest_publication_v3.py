"""One committed template publishes two compatible, byte-pinned variants."""

import copy
import hashlib

import httpx
import pytest
from awid.did import did_from_public_key
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS
from aweb_naapp.manifest import CATALOG_PATH, ManifestError, canonical_bytes, load_manifest
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from tests.runtime.test_served_manifest import ExampleSettings, _v2_template

ORIGIN = "https://console.example.test"
DECLARATION = {
    "roles": [
        {
            "name": "example.owner",
            "label": "Owner",
            "acts": list(HUMAN_ROLE_ACTS),
            "notice_contact": True,
        }
    ],
}


def runtime(tmp_path, *, declaration=DECLARATION, origin=ORIGIN):
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(_v2_template()))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    return NaappRuntime(
        ExampleSettings(_env_file=None),
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        owner_acts=declaration,
        owner_acts_origin=origin,
    )


async def test_v2_and_v3_are_discoverable_and_each_digest_names_the_bytes_served(tmp_path):
    declared = copy.deepcopy(DECLARATION)
    rt = runtime(tmp_path, declaration=declared)
    declared["roles"][0]["notice_contact"] = False
    app = FastAPI()
    mount_manifest_routes(app, runtime=rt)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://example.aweb.ai"
    ) as client:
        catalog = (await client.get(CATALOG_PATH)).json()
        assert [entry["manifest_version"] for entry in catalog["variants"]] == [2, 3]
        documents = {}
        for entry in catalog["variants"]:
            response = await client.get(entry["url"])
            assert response.status_code == 200
            assert entry["digest"] == "sha256:" + hashlib.sha256(response.content).hexdigest()
            documents[entry["manifest_version"]] = response.json()
        assert "owner_acts" not in documents[2]
        assert documents[3]["owner_acts"] == {**DECLARATION, "origin": ORIGIN}
        assert rt.manifest.manifest_version == 3
        assert rt.manifest_bytes == canonical_bytes(documents[3])
        assert (await client.get("/.well-known/aweb-app.json")).status_code == 404
        old = documents[2]
        new = documents[3]
        new.pop("owner_acts")
        new["manifest_version"] = 2
        assert old == new


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "https://example.aweb.ai:9443",
        "https://example.aweb.ai.",
        "http://console.example.test",
    ],
)
def test_declared_owner_roles_require_a_valid_separate_configured_human_origin(tmp_path, origin):
    with pytest.raises((ManifestError, ValueError)):
        runtime(tmp_path, origin=origin)


def test_an_origin_without_a_declaration_does_not_invent_a_role(tmp_path):
    with pytest.raises((ManifestError, ValueError)):
        runtime(tmp_path, declaration=None)


@pytest.mark.parametrize("field", ["app", "tools", "events", "app_keys", "hooks", "roles"])
def test_variant_checker_refuses_drift_in_every_common_declaration(field):
    from aweb_naapp.manifest import check_v2_variant

    old = _v2_template()
    new = {
        **copy.deepcopy(old),
        "manifest_version": 3,
        "owner_acts": {**DECLARATION, "origin": ORIGIN},
    }
    if field == "app":
        new["app"]["id"] = "another"
    elif field == "tools":
        new["tools"][0]["path"] = "/different"
    elif field == "events":
        new[field] = [{"type": "changed", "default_delivery_intent": "ambient"}]
    elif field == "app_keys":
        new[field] = [
            {
                "kid": "read",
                "did_key": did_from_public_key(bytes(SigningKey.generate().verify_key)),
                "purposes": ["app-grant-read"],
            }
        ]
    elif field == "roles":
        new[field] = [{"name": "example.admin", "label": "Admin"}]
    else:
        new[field] = {"registration_version": 1, "productions": [], "registrations": []}
    # Both documents must be individually valid: rejection is the pair's mismatch.
    load_manifest(canonical_bytes(old))
    load_manifest(canonical_bytes(new))
    with pytest.raises(ManifestError) as refused:
        check_v2_variant(canonical_bytes(old), canonical_bytes(new))
    assert refused.value.code == "v2_variant_incompatible"


def test_variant_checker_accepts_only_the_versions_it_compares():
    from aweb_naapp.manifest import check_v2_variant

    old = canonical_bytes(_v2_template())
    with pytest.raises(ManifestError) as refused:
        check_v2_variant(old, old)
    assert refused.value.code == "v2_variant_incompatible"
