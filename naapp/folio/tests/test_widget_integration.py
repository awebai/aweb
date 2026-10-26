"""The browser loads only packaged modules and a nonce-authorized table host."""

import re

from test_record_host import linked, listener
from test_widget_authorization import authors
from test_widget_records_session import mint, with_table

__all__ = ["authors", "linked", "listener"]


async def test_editor_modules_and_renderer_are_available_only_by_fixed_asset_names(authors):
    world, _, _, _ = authors
    for name in (
        "renderer.js",
        "renderer.css",
        "atomic-editor.mjs",
        "document-model.mjs",
        "folio-widget-host.mjs",
    ):
        response = await world.client.get("/present/widgets/assets/" + name)
        assert response.status_code == 200, (name, response.text)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert (await world.client.get("/present/widgets/assets/repository.py")).status_code == 404


async def test_readonly_table_html_bootstraps_the_same_checked_link_with_nonce_csp(authors):
    world, _ = await with_table(authors)
    link, path, _, _ = await mint(world, editable=False)
    response = await world.client.get(path)
    assert response.status_code == 200
    assert 'data-widget-token="' + link["token"] + '"' in response.text
    assert 'src="/present/widgets/assets/folio-widget-host.mjs"' in response.text
    nonce = re.search('nonce="([^"]+)"', response.text).group(1)
    assert (
        "script-src 'nonce-" + nonce + "' 'strict-dynamic'"
        in response.headers["Content-Security-Policy"]
    )
