"""F6 accepts origin pins and refuses installer-uploaded authority fields."""

import pytest
import test_installation_http as install_http
from httpx import ASGITransport, AsyncClient
from test_app_manifest_fetch import VARIANT

client = install_http.client
db = install_http.db
origin = install_http.origin


async def _install(app, body: dict):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as caller:
        return await caller.post("/v1/apps/install", json=body)


@pytest.mark.asyncio
@pytest.mark.parametrize(("field", "value"), [
    ("manifest", "e30="), ("events", []), ("event_emitters", []),
    ("app_keys", []), ("app_version", "99.0"), ("manifest_version", 1),
])
async def test_installer_authority_fields_are_refused_before_fetch(client, db, origin, field, value):
    await install_http.admin(db)
    body = install_http.confirmation(origin)
    body[field] = value
    response = await install_http.post(client, body)
    assert response.status_code == 422, response.text
    assert not origin.tls.seen
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_app_installs}}") == 0


@pytest.mark.asyncio
async def test_uploading_an_oversized_body_is_refused_before_parsing(client):
    response = await client.post("/api/v1/apps/install", content=b"x" * ((1 << 20) + 1), headers=install_http.headers())
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_server_fetched_bytes_and_registration_commit_with_the_operator_audit(client, db, origin):
    await install_http.admin(db)
    response = await install_http.post(client, install_http.confirmation(origin))
    assert response.status_code == 200, response.text
    row = await db.fetch_one("SELECT event_type,outcome,resource FROM {{tables.audit_log}}")
    assert dict(row) == {"event_type":"apps.install", "outcome":"success", "resource":"app:fixture"}
    assert await db.fetch_value("SELECT manifest_bytes FROM {{tables.team_app_installs}}") == origin.routes[VARIANT][1]
