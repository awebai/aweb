"""Owner discovery uses the real runtime without starting a database or network."""

import hashlib
import json

import httpx
import pytest
from aweb_naapp.manifest import load_manifest

from aweb_secrets.app import create_app
from tests.test_app import API, CONSOLE, TOOLS, InstalledTeams, _settings, allow_all, kms_check


@pytest.mark.parametrize(
    ("api_origin", "human_origin", "app_id"),
    [
        (API, CONSOLE, "secrets-test"),
        ("https://agent.example.org", "https://people.example.org", "customer-secrets"),
    ],
)
async def test_both_exact_variants_are_discoverable_only_on_the_api_origin(
    tmp_path, api_origin, human_origin, app_id
):
    configured = _settings("postgresql://localhost/unused", tmp_path).model_copy(
        update={"public_origin": api_origin, "console_origin": human_origin, "app_id": app_id}
    )
    service = create_app(
        configured, grants=InstalledTeams({}), policy=allow_all, kms=kms_check(True)
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
        catalog = await client.get(api_origin + "/.well-known/aweb-app-versions.json")
        assert catalog.status_code == 200
        variants = {item["manifest_version"]: item for item in catalog.json()["variants"]}
        assert set(variants) == {2, 3}
        assert catalog.json()["app_id"] == app_id
        documents = {}
        for version, variant in variants.items():
            response = await client.get(api_origin + variant["url"])
            assert response.status_code == 200
            assert variant["url"] == f"/manifests/v{version}.json"
            assert variant["digest"] == "sha256:" + hashlib.sha256(response.content).hexdigest()
            assert (await client.get(human_origin + variant["url"])).status_code == 404
            manifest = load_manifest(response.content)
            assert manifest.manifest_version == version
            assert manifest.app_id == app_id
            assert manifest.document["app"]["origin"] == api_origin
            assert response.json()["tools"] == TOOLS
            documents[version] = response.json()
        v3 = documents[3]
        assert v3["owner_acts"]["origin"] == human_origin
        [role] = v3["owner_acts"]["roles"]
        assert role["name"] == "secrets.owner"
        assert role["notice_contact"] is True
        assert role["acts"] == [
            "human-credential.replace", "human-role.designate", "human-role.revoke"
        ]
        # The shared v3 publication must preserve the released agent contract.
        assert {k: v for k, v in v3.items() if k not in {"manifest_version", "owner_acts"}} == {
            k: v for k, v in documents[2].items() if k != "manifest_version"
        }
        assert (await client.get(api_origin + "/aweb-app.json")).json() == v3
        assert "owner_acts" not in documents[2]


async def test_owner_session_actions_are_human_routes_and_protect_the_vault_token(tmp_path):
    service = create_app(
        _settings("postgresql://localhost/unused", tmp_path),
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=kms_check(True),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
        response = await client.get(API + "/manifests/v3.json")
        assert response.status_code == 200
        actions = {item["name"]: item for item in response.json()["owner_acts"]["session_actions"]}
        assert set(actions) == {"change-set", "onepassword-token", "confirm"}
        assert all(action["role"] == "secrets.owner" for action in actions.values())
        assert not set(actions).intersection(tool["name"] for tool in TOOLS)
        assert all("scopes" not in action for action in actions.values())
        stage = actions["onepassword-token"]
        assert stage["kind"] == "stage"
        assert {"name": "value", "in": "body", "protected": True} in stage["params"]
        confirm = actions["confirm"]
        assert confirm["completion"]["read"] == "change-set"
        assert confirm["completion"]["done"] == {"member": "state", "in": ["applied"]}
        assert confirm["terminal_output"] == ["/runner_registrations/*/registration_code"]
        # Neither declaration invents an agent-callable route or accepts a cookie.
        for action in actions.values():
            path = action["path"].replace("{installation_id}", "uninstalled").replace(
                "{change_id}", "unknown"
            )
            refused = await client.request(
                action["method"], API + path, headers={"Cookie": "session=untrusted"}
            )
            assert refused.status_code == 404
        assert json.loads(service.runtime.manifest_bytes)["manifest_version"] == 3
