"""V3 pins through mounted install routes, real DNS/TLS, PostgreSQL and AWID.

The shared manifest reader owns validation. These tests exercise its server
consumer and the generation boundary for already activated audit bindings.
"""

import json
from urllib.parse import urlsplit

import pytest
import test_hook_binding_activation as owner_fixture
import test_installation_http as http_fixture

from aweb.hook_bindings import activate_binding, list_app_bindings
from aweb_naapp.manifest import SUPPORTED_MANIFEST_VERSIONS
from test_app_manifest_fetch import CATALOG, VARIANT, digest
from test_installation_http import TEAM, admin, headers, post
from test_verified_installations import current

client = http_fixture.client
db = http_fixture.db
origin = http_fixture.origin
owner_env = owner_fixture.env
pytestmark = pytest.mark.asyncio
V3_VARIANT = "/.well-known/aweb-app-v3.json"


def manifest(origin, version=3):
    doc = json.loads(origin.manifest())
    doc["manifest_version"] = version
    doc["app_keys"][0]["purposes"].append("hook-event")
    registration = doc["hooks"]["registrations"][0]
    registration.update(catalog={"id": "aweb.hooks", "version": 1}, hook="post-secret-use-hook")
    production = doc["hooks"]["productions"][0]
    production.update(catalog={"id": "aweb.hooks", "version": 1}, hook="post-governance-hook")
    if version == 3:
        doc["owner_acts"] = {
            "origin": "https://human.fixture.example",
            "roles": [{
                "name": "fixture.reader", "label": "Reader",
                "acts": ["human-credential.replace", "human-role.designate", "human-role.revoke"],
                "notice_contact": False,
            }],
        }
    return doc


def publish(origin, doc):
    # Keep a valid v2 neighbor in the catalog. An invalid v3 must refuse,
    # never silently select the lower version instead.
    data = (json.dumps(doc, indent=2) + "\n").encode()
    v2 = (json.dumps(manifest(origin, 2), indent=2) + "\n").encode()
    variants = [{"manifest_version": 2, "url": VARIANT, "digest": digest(v2)}]
    origin.routes[VARIANT] = (200, v2, [])
    if doc["manifest_version"] == 3:
        variants.append({"manifest_version": 3, "url": V3_VARIANT, "digest": digest(data)})
        origin.routes[V3_VARIANT] = (200, data, [])
    else:
        origin.routes[VARIANT] = (200, data, [])
        variants[0]["digest"] = digest(data)
    origin.routes[CATALOG] = (200, json.dumps({
        "catalog_version": 1, "app_id": "fixture", "variants": variants,
    }).encode(), [])
    return data, {"app_id": "fixture", "origin": origin.url,
                  "digest": digest(data), "granted_scopes": ["fixture:read"]}


async def test_v3_preview_and_install_preserve_the_exact_shared_manifest(client, db, origin):
    data, pin = publish(origin, manifest(origin))
    preview = await post(client, {"origin": origin.url}, "preview")
    assert preview.status_code == 200, preview.text
    assert 3 in SUPPORTED_MANIFEST_VERSIONS
    assert preview.json()["resolved"]["manifest_version"] == 3
    assert preview.json()["manifest"]["owner_acts"] == json.loads(data)["owner_acts"]
    assert await current(db) is None
    await admin(db)
    response = await post(client, pin)
    assert response.status_code == 200, response.text
    assert response.json()["manifest_version"] == 3
    assert response.json()["generation"] == 1
    assert await db.fetch_value("SELECT manifest_bytes FROM {{tables.team_app_installs}}") == data


@pytest.mark.parametrize("version", [2, 3])
async def test_repin_keeps_identity_and_supersedes_active_bindings(client, db, origin, owner_env, version):
    await admin(db)
    v2_bytes, old_pin = publish(origin, manifest(origin, 2))
    first = await post(client, old_pin)
    assert first.status_code == 200, first.text
    before = first.json()

    # The actual current-controller verifier activates both kinds of binding;
    # no SQL state stamp substitutes for an owner act.
    await owner_env.registry_db.execute(
        "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) "
        "VALUES ('example.com','demo',$1,'private')", owner_fixture._did(owner_env.owner.key),
    )
    owner = owner_fixture.Owner(owner_env.owner.key, TEAM)
    bindings = await list_app_bindings(db, team_id=TEAM, app_id="fixture")
    assert {b.kind for b in bindings} == {"registration", "production"}
    for binding in bindings:
        signing, signature = owner.sign("hook-binding.activate", binding)
        activated = await activate_binding(
            db, owner_env.verifier, team_id=TEAM, binding_id=binding.binding_id,
            signing=signing, signature=signature,
        )
        assert activated.state == "active"

    if version == 3:
        invalid = manifest(origin)
        invalid["owner_acts"]["roles"] = []
        _, invalid_pin = publish(origin, invalid)
        refused = await post(client, dict(invalid_pin, expected_generation=before["generation"]))
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"]["code"] == "owner_acts_invalid"
        assert (await current(db))["generation"] == before["generation"]
        assert all(b.state == "active" for b in await list_app_bindings(db, team_id=TEAM, app_id="fixture"))

    data, new_pin = publish(origin, manifest(origin, version))
    # Publishing the catalog does not upgrade a stored v2 pin or its bindings.
    pinned_v2 = await origin.fetcher.fetch(origin.url, manifest_version=2, expected_digest=digest(v2_bytes))
    assert pinned_v2.data == v2_bytes
    assert (await current(db))["manifest_version"] == 2
    assert all(b.state == "active" for b in await list_app_bindings(db, team_id=TEAM, app_id="fixture"))

    updated = await post(client, dict(new_pin, expected_generation=before["generation"]))
    assert updated.status_code == 200, updated.text
    after = updated.json()
    assert after["installation_id"] == before["installation_id"]
    assert after["generation"] == before["generation"] + 1
    assert after["manifest_version"] == version
    assert after["digest"] == digest(data)
    rows = await list_app_bindings(db, team_id=TEAM, app_id="fixture")
    old = [b for b in rows if b.generation == before["generation"]]
    new = [b for b in rows if b.generation == after["generation"]]
    assert {b.binding_id for b in old} == {b.binding_id for b in bindings}
    assert {(b.state, b.ended_by) for b in old} == {("superseded", "generation")}
    assert len(new) == len(old)
    assert {b.kind for b in new} == {"registration", "production"}
    assert all(b.state == "pending" and b.activated_at is None for b in new)
    assert all(b.installation_id == before["installation_id"] and b.digest == digest(data) for b in new)

    view = await client.get(f"/api/v1/apps/fixture/installation?team_id={TEAM}", headers=headers())
    assert view.status_code == 200, view.text
    assert view.json()["resolved"]["manifest_version"] == version


@pytest.mark.parametrize("fault,code", [
    ("empty_roles", "owner_acts_invalid"),
    ("unknown_act", "owner_acts_invalid"),
    ("shared_hostname", "owner_acts_invalid"),
    ("null", "manifest_invalid"),
])
async def test_invalid_owner_acts_refuses_install_beside_valid_v3(client, db, origin, fault, code):
    await admin(db)
    doc = manifest(origin)
    if fault == "empty_roles":
        doc["owner_acts"]["roles"] = []
    elif fault == "unknown_act":
        doc["owner_acts"]["roles"][0]["acts"] = ["unknown.act"]
    elif fault == "shared_hostname":
        # A distinct port still shares the browser cookie hostname.
        doc["owner_acts"]["origin"] = "https://" + urlsplit(origin.url).hostname
    else:
        doc["owner_acts"] = None
    _, pin = publish(origin, doc)
    refused = await post(client, pin)
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"]["code"] == code
    assert await current(db) is None
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.app_hook_bindings}}") == 0
    _, valid_pin = publish(origin, manifest(origin))
    accepted = await post(client, valid_pin)
    assert accepted.status_code == 200, accepted.text


async def test_v2_still_refuses_owner_acts_without_installing(client, db, origin):
    await admin(db)
    doc = manifest(origin)
    doc["manifest_version"] = 2
    _, pin = publish(origin, doc)
    refused = await post(client, pin)
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"]["code"] == "manifest_invalid"
    assert await current(db) is None
