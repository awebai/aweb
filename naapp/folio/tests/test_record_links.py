"""Folio adapters on real AWID/PG with an explicit granted-installation fixture.

These isolate the host boundary. Real G1/F6 installation/CLI/MCP acceptance uses
the maintained server stack after F6 lands; this fixture does not replace it.
"""

import asyncio
import base64
import hashlib
import json
import secrets
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit

import httpx
import pytest
import uvicorn
from aweb_naapp.runtime.authorization import Authorization, Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.link_requests import sign_link_request
from aweb_naapp.runtime.team_auth import record_observed_principal
from aweb_naapp_testing import Member, awid_registry, did_key
from nacl.signing import SigningKey
from starlette.requests import Request
from test_record_collections import VALUE
from test_record_runtime import configured
from test_record_storage import POLICY

from folio.api import create_app
from folio.models import CreatePresentationRequest
from folio.record_collections import DISCOVERY_SCHEMA, DISCOVERY_TITLE
from folio.record_models import CollectionDefineRequest, RecordAddRequest

TEAM = "records:example.test"


class GrantedInstallation:
    async def grant_for(self, team_id):
        return Grant(team_id=team_id, scopes=frozenset({"folio:read", "folio:write"}),
                     fresh_until=time.monotonic_ns() + seconds_to_ns(60), installation_id="inst_fixture", generation=1)


async def empty_body():
    return {"type": "http.request", "body": b"", "more_body": False}


@pytest.fixture
def listener():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        yield sock


@pytest.fixture
async def linked(test_db_factory, tmp_path, listener):
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    content = await test_db_factory.create_db(suffix="folio_link")
    ledger = await test_db_factory.create_db(suffix="folio_link_ledger")
    awid_db = await test_db_factory.create_db(suffix="folio_link_awid")
    async with awid_registry(awid_db.config.get_dsn()) as registry:
        member = Member(team_id=TEAM)
        await registry.add_team(TEAM, member.team_did_key)
        await registry.add_certificate(member.certificate())
        settings = configured(tmp_path, database_url=content.config.get_dsn(),
                              db_schema=content.config.get_schema(), public_origin=origin,
                              awid_registry_url="https://registry.example", auth_cache_ttl_seconds=1,
                              AWEB_PAGE_DELETION_DATABASE_URL=ledger.config.get_dsn(),
                              AWEB_PAGE_RETENTION_POLICY=POLICY)
        app = create_app(settings, awid_transport=registry.transport)
        host = app.state.folio_records
        host.grants = GrantedInstallation()
        async with app.router.lifespan_context(app):
            headers = member.headers(aud=origin, method="GET", path="/verified-fixture")
            request = Request({"type": "http", "method": "GET", "path": "/verified-fixture",
                               "raw_path": b"/verified-fixture", "query_string": b"",
                               "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]},
                              receive=empty_body)
            principal = await host.runtime.principal(request)
            await record_observed_principal(host.runtime.db(), principal)
            grant = await host.grants.grant_for(TEAM)
            tool = host.runtime.declared_tools.match("POST", "/v1/collections")
            authorization = Authorization(principal, tool, grant)
            defined = await host.member_operation(authorization, "define_on", CollectionDefineRequest(
                collection_id="discovery", title=DISCOVERY_TITLE, schema=DISCOVERY_SCHEMA, request_id="define"))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin) as client:
                yield SimpleNamespace(host=host, authorization=authorization, defined=defined,
                                      client=client, registry=registry, member=member, app=app, listener=listener)


async def open_link(linked):
    minted = await linked.host.present(linked.authorization, CreatePresentationRequest(slug=linked.defined["document_slug"]))
    key = SigningKey.generate()
    response = await linked.client.post(f"/v1/links/{minted['token']}/session", json={
        "secret": urlsplit(minted["url"]).fragment.removeprefix("k="), "session_did_key": did_key(key)})
    assert response.status_code == 200, response.text
    return SimpleNamespace(id=minted["token"], key=key, session=response.json())


async def signed_request(linked, link, target, *, method="GET", body=b""):
    payload = {"v": 1, "type": "aweb.link-request", "link_id": link.id,
               "session_id": link.session["session_id"], "method": method, "path": target,
               "body_sha256": hashlib.sha256(body).hexdigest(),
               "nonce": secrets.token_hex(16), "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    return await linked.client.request(method, target, content=body, headers={
        "Authorization": f"AWEB-Link-Request {link.session['session_id']} {sign_link_request(payload, link.key)}",
        "X-AWEB-Signed-Payload": encoded, "X-AWEB-CSRF": link.session["csrf_token"],
        "Origin": linked.host.settings.public_origin})


async def signed_get(linked, link, target):
    return await signed_request(linked, link, target)


async def test_live_empty_table_opens_and_follows_added_records_through_checked_queries(linked):
    link = await open_link(linked)
    response = await signed_get(linked, link, f"/v1/links/{link.id}/page")
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["collections"][0]["records"] == []
    await linked.host.member_operation(linked.authorization, "add_on", RecordAddRequest(
        collection_id="discovery", values=VALUE, request_id="add"))
    bind = quote(json.dumps({"collection": "discovery", "limit": 1}), safe="")
    response = await signed_get(linked, link, f"/v1/links/{link.id}/query?bind={bind}&snapshot_rev=2")
    assert response.status_code == 200, response.text
    assert response.json()["count"] == 1
    assert response.json()["records"][0]["value"] == VALUE
    assert response.headers["Cache-Control"] == "no-store"


async def test_revoked_creator_refuses_exchange_and_every_query_with_private_headers(linked):
    import asyncio

    link = await open_link(linked)
    await linked.registry.revoke(linked.member.certificate_id)
    # The runtime reuses bounded request-auth facts, then refreshes from real AWID.
    await asyncio.sleep(1.05)
    for suffix in ("page", "query?bind=%7B%7D&snapshot_rev=1"):
        response = await signed_get(linked, link, f"/v1/links/{link.id}/{suffix}")
        assert response.status_code == 403, response.text
        assert response.json()["detail"]["code"] == "current_member_required"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Referrer-Policy"] == "no-referrer"
    minted = await linked.host.present(linked.authorization, CreatePresentationRequest(slug=linked.defined["document_slug"]))
    response = await linked.client.post(f"/v1/links/{minted['token']}/session", json={
        "secret": urlsplit(minted["url"]).fragment.removeprefix("k="), "session_did_key": did_key(SigningKey.generate())})
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "current_member_required"
    assert response.headers["Referrer-Policy"] == "no-referrer"


async def test_query_cursor_is_bound_to_its_link_and_revision(linked):
    for index in range(3):
        await linked.host.member_operation(linked.authorization, "add_on", RecordAddRequest(
            collection_id="discovery", values={**VALUE, "finding": f"Finding {index}"}, request_id=f"add-{index}"))
    first, second = await open_link(linked), await open_link(linked)
    bind = {"collection": "discovery", "limit": 1}
    def target(link, value):
        return f"/v1/links/{link.id}/query?bind={quote(json.dumps(value), safe='')}&snapshot_rev=4"
    response = await signed_get(linked, first, target(first, bind))
    assert response.status_code == 200, response.text
    assert response.json()["count"] == 3
    cursor = response.json()["next_cursor"]
    assert cursor
    continued = {**bind, "cursor": cursor}
    response = await signed_get(linked, second, target(second, continued))
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "cursor_invalid"
    response = await signed_get(linked, first, target(first, continued))
    assert response.status_code == 200, response.text
    assert response.json()["count"] == 3
    await linked.host.member_operation(linked.authorization, "add_on", RecordAddRequest(
        collection_id="discovery", values=VALUE, request_id="later"))
    response = await signed_get(linked, first, target(first, continued))
    assert response.status_code == 409, response.text
    assert response.headers["Cache-Control"] == "no-store"


async def test_missing_installation_identity_is_refused_before_records_are_written(linked):
    from fastapi import HTTPException

    grant = Grant(team_id=TEAM, scopes=frozenset({"folio:read", "folio:write"}), fresh_until=time.monotonic_ns() + seconds_to_ns(60), installation_id=None, generation=None)
    authorization = Authorization(linked.authorization.principal, linked.authorization.tool, grant)
    with pytest.raises(HTTPException) as refused:
        await linked.host.member_operation(authorization, "add_on", RecordAddRequest(
            collection_id="discovery", values=VALUE, request_id="missing-identity"))
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "installation_identity_required"


@pytest.mark.parametrize("viewport_width", [1280, 375])
async def test_mounted_table_browser_signs_queries_and_reload_requires_reopening(linked, viewport_width):
    await linked.host.member_operation(linked.authorization, "add_on", RecordAddRequest(
        collection_id="discovery", values={**VALUE, "why_relevant": "Verify the same row through signed tools and a table"}, request_id="browser-add"))
    await linked.host.member_operation(linked.authorization, "add_on", RecordAddRequest(
        collection_id="discovery", values={**VALUE, "finding": "Second synthetic record", "why_relevant": "Verify the same row through signed tools and a table"}, request_id="browser-add-second"))
    minted = await linked.host.present(linked.authorization, CreatePresentationRequest(slug=linked.defined["document_slug"]))
    linked.listener.listen()
    server = uvicorn.Server(uvicorn.Config(linked.app, log_level="error", lifespan="off", access_log=False, ws="none"))
    serving = asyncio.create_task(server.serve(sockets=[linked.listener]))
    process = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if serving.done():
                    await serving
                await asyncio.sleep(0.01)
        process = await asyncio.create_subprocess_exec(
            "node", str(Path(__file__).parent / "browser" / "record-table-mounted.mjs"), minted["url"], str(viewport_width),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
        assert process.returncode == 0, (stdout + stderr).decode()
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        server.should_exit = True
        await asyncio.wait_for(serving, 10)


async def test_two_verified_members_race_and_only_one_revision_update_commits(linked):
    from fastapi import HTTPException

    from folio.record_models import RecordQueryRequest, RecordUpdateRequest

    added = await linked.host.member_operation(linked.authorization, "add_on", RecordAddRequest(
        collection_id="discovery", values=VALUE, request_id="race-add"))
    other = Member(team_id=TEAM, team_key=linked.member.team_key, certificate_id="cert-bob", alias="bob")
    await linked.registry.add_certificate(other.certificate())
    headers = other.headers(aud=linked.host.settings.public_origin, method="GET", path="/verified-fixture")
    request = Request({"type": "http", "method": "GET", "path": "/verified-fixture",
                       "raw_path": b"/verified-fixture", "query_string": b"",
                       "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}, receive=empty_body)
    principal = await linked.host.runtime.principal(request)
    await record_observed_principal(linked.host.runtime.db(), principal)
    second = Authorization(principal, linked.authorization.tool, linked.authorization.grant)

    async def update(authorization, status):
        return await linked.host.member_operation(authorization, "update_on", RecordUpdateRequest(
            collection_id="discovery", record_id=added["record"]["id"], expected_rev=1,
            patch={"status": status}, request_id=f"race-{status}"))

    outcomes = await asyncio.gather(update(linked.authorization, "alice"), update(second, "bob"), return_exceptions=True)
    committed = [value for value in outcomes if isinstance(value, dict)]
    refused = [value for value in outcomes if isinstance(value, HTTPException)]
    assert len(committed) == 1 and len(refused) == 1, outcomes
    assert (refused[0].status_code, refused[0].detail["code"]) == (409, "revision_conflict")
    query = await linked.host.member_operation(second, "query_on", RecordQueryRequest(collection_id="discovery"))
    assert query["records"] == [committed[0]["record"]]
    assert query["records"][0]["value"]["finding"] == VALUE["finding"]
    documents = await linked.host.documents(second)
    assert documents[0]["slug"] == linked.defined["document_slug"]
    assert documents[0]["kind"] == "table"


async def test_awid_unavailable_stays_503_on_read_query_and_admit(linked):
    link = await open_link(linked)

    def unavailable(request, response):
        raise httpx.ConnectError("synthetic AWID outage", request=request)

    linked.registry.transport.fault = unavailable
    await asyncio.sleep(1.05)
    for suffix, method in (("page", "GET"), ("query?bind=%7B%7D&snapshot_rev=1", "GET"), ("admit", "POST")):
        response = await signed_request(linked, link, f"/v1/links/{link.id}/{suffix}", method=method)
        assert response.status_code == 503, response.text
        assert response.json()["detail"]["code"] == "current_membership_unavailable"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Referrer-Policy"] == "no-referrer"


async def test_member_revoke_maps_unknown_link_and_ends_holder_reads(linked):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as missing:
        await linked.host.revoke(linked.authorization, "lnk_" + "0" * 32)
    assert missing.value.status_code == 404
    link = await open_link(linked)
    await linked.host.revoke(linked.authorization, link.id)
    response = await signed_get(linked, link, f"/v1/links/{link.id}/page")
    assert response.status_code == 410, response.text
    assert response.json()["detail"]["code"] == "link_unavailable"
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("property_schema", [
    {"type": ["string", "null"], "maxLength": 160},
    True,
    False,
])
async def test_define_refuses_unsupported_field_schemas_without_partial_writes(linked, property_schema):
    from aweb_naapp.pages import inline_schema_errors
    from fastapi import HTTPException

    schema = {"type": "object", "properties": {"status": property_schema}, "additionalProperties": False}
    assert inline_schema_errors(schema) == []
    db = linked.host.runtime.db()

    async def counts():
        return [await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}")
                for table in ("pages", "page_audit", "page_receipts", "documents", "collection_documents")]

    before = await counts()
    with pytest.raises(HTTPException) as refused:
        await linked.host.member_operation(linked.authorization, "define_on", CollectionDefineRequest(
            collection_id="unsupported", title="Unsupported", schema=schema, request_id="unsupported-define"))
    assert (refused.value.status_code, refused.value.detail["code"]) == (422, "schema_invalid")
    assert await counts() == before
