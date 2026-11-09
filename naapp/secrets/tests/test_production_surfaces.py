"""The approved public pages lead into the actual, separate owner console."""

import secrets
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from tests.test_console_bootstrap import delivered_url
from tests.test_production_bootstrap import enrolled_owner, signed_in_owner
from tests.test_production_bootstrap import root as root


class Links(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.hrefs = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.extend(value for name, value in attrs if name == "href")


async def test_actual_root_serves_public_docs_on_api_and_preserves_runtime_health(root):
    service, client, configured, *_ = root
    api, human = configured.public_origin, configured.console_origin
    for path, content_type in (
        ("/", "text/html"),
        ("/reference", "text/html"),
        ("/llms.txt", "text/plain"),
        ("/skills/", "text/plain"),
    ):
        response = await client.get(api + path)
        assert response.status_code == 200, path
        assert response.headers["content-type"].startswith(content_type)
        assert "set-cookie" not in response.headers
        if path in ("/", "/reference"):
            assert human + "/" in Links(response.text).hrefs
        if path != "/":
            assert (await client.get(human + path)).status_code == 404
    assert api in (await client.get(api + "/llms.txt")).text
    for path in ("/aweb-app.json", "/manifests/v2.json"):
        manifest = await client.get(api + path)
        assert manifest.status_code == 200 and manifest.content == service.runtime.manifest_bytes
    ready = await client.get(api + "/ready")
    assert ready.status_code == 200
    assert set(ready.json()["checks"]) == {"database", "outbox", "kms"}
    assert ready.json()["labels"]["custody_mode"] == "local_key_file"
    # An earlier duplicate health route must not hide a broken replacement.
    for path in ("/health", "/ready", "/live"):
        assert sum(getattr(route, "path", None) == path for route in service.api_app.routes) == 1


async def test_public_console_link_reaches_real_owner_setup_and_existing_forms(root):
    _, client, configured, *_ = root
    api, human = configured.public_origin, configured.console_origin
    landing = await client.get(api + "/")
    assert landing.status_code == 200
    console = human + "/"
    assert console in Links(landing.text).hrefs
    entry = await client.get(console, follow_redirects=True)
    assert entry.status_code == 200 and str(entry.url).startswith(human + "/")
    await signed_in_owner(root)
    for path in ("/", "/secrets/new", "/grants/new"):
        page = await client.get(human + path)
        assert page.status_code == 200, path
        assert page.headers["content-type"].startswith("text/html")
        if path != "/":
            assert (await client.get(api + path)).status_code == 404
    # The real human session cookie grants nothing on the agent origin.
    assert (await client.get(api + "/v1/secrets")).status_code == 401
    public = await client.get(api + "/")
    assert public.status_code == 200 and "set-cookie" not in public.headers


async def test_public_entry_reaches_sealed_ingress_and_fresh_passkey_activation(root):
    service, client, configured, _, installed, smtp, *_ = root
    api, human = configured.public_origin, configured.console_origin
    landing = await client.get(api + "/")
    assert human + "/" in Links(landing.text).hrefs
    assert (await client.get(human + "/", follow_redirects=True)).status_code == 200
    owner = await enrolled_owner(root)
    headers = {"X-CSRF-Token": owner.csrf_token}
    installation_id = installed["installation_id"]
    ingress = f"/installations/{installation_id}/backend-credentials/onepassword/versions"
    value = secrets.token_urlsafe(32)
    staged = await client.post(human + ingress, json={"value": value}, headers=headers)
    assert staged.status_code == 201
    if value in staged.text:
        raise AssertionError("entered backend credential appeared in ingress response")
    assert (await client.post(api + ingress, json={"value": value})).status_code == 404
    db = service.runtime.db()
    assert await db.fetch_value("SELECT active_version FROM onepassword_credentials") is None
    for row in await db.fetch_all("SELECT * FROM sealed_versions"):
        if value in str(dict(row)):
            raise AssertionError("entered backend credential was stored as plaintext")
    changes = human + f"/installations/{installation_id}/change-sets"
    drafted = await client.post(
        changes,
        headers=headers,
        json={
            "changes": [
                {
                    "kind": "backend_credential",
                    "op": "create",
                    "ref": "onepassword",
                    "after": staged.json(),
                }
            ],
            "sealed": [
                {"secret_id": staged.json()["credential_id"], "version": staged.json()["version"]}
            ],
            "reason": "Configure dedicated test vault access",
        },
    )
    assert drafted.status_code == 201
    if value in drafted.text:
        raise AssertionError("entered backend credential appeared in draft response")
    path = changes + "/" + drafted.json()["change_id"]
    assert (await client.post(path + "/confirm", json={}, headers=headers)).status_code == 409
    link = delivered_url(smtp.received, contact=owner.body["contact"], path="/approvals")
    [token] = parse_qs(urlsplit(link).fragment)["token"]
    options = await client.post(path + "/approval-options", json={"token": token}, headers=headers)
    assert options.status_code == 200
    approved = await client.post(
        path + "/approve",
        headers=headers,
        json={
            "token": token,
            "assertion": owner.device.get(options.json()),
        },
    )
    assert approved.status_code == 200
    assert await db.fetch_value("SELECT active_version FROM onepassword_credentials") is None
    confirmed = await client.post(path + "/confirm", json={}, headers=headers)
    assert confirmed.status_code == 200
    assert confirmed.json()["state"] == "applied"
    assert (
        await db.fetch_value("SELECT active_version FROM onepassword_credentials")
        == staged.json()["version"]
    )
    assert await db.fetch_value("SELECT state FROM change_sets") == "applied"
