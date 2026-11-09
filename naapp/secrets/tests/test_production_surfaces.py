"""The approved public pages lead into the actual, separate owner console."""

from html.parser import HTMLParser

from tests.test_production_bootstrap import root as root
from tests.test_production_bootstrap import signed_in_owner


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
        assert sum(route.path == path for route in service.api_app.routes) == 1


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
