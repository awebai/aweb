"""Folio adapters on real AWID/PG with an explicit granted-installation fixture.

These isolate the host boundary. Real G1/F6 installation/CLI/MCP acceptance uses
the maintained server stack after F6 lands; this fixture does not replace it.
"""

import asyncio
import socket
import time
from types import SimpleNamespace

import httpx
import pytest
from aweb_naapp.runtime.authorization import Authorization, Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.team_auth import record_observed_principal
from aweb_naapp_testing import Member, awid_registry
from starlette.requests import Request
from test_record_collections import VALUE
from test_record_runtime import configured
from test_record_storage import POLICY

from folio.api import create_app
from folio.record_collections import DISCOVERY_SCHEMA, DISCOVERY_TITLE
from folio.record_models import CollectionDefineRequest, RecordAddRequest

TEAM = "records:example.test"


class GrantedInstallation:
    async def grant_for(self, team_id):
        return Grant(
            team_id=team_id,
            scopes=frozenset({"folio:read", "folio:write"}),
            fresh_until=time.monotonic_ns() + seconds_to_ns(60),
            installation_id="inst_fixture",
            generation=1,
        )


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
        settings = configured(
            tmp_path,
            database_url=content.config.get_dsn(),
            db_schema=content.config.get_schema(),
            public_origin=origin,
            awid_registry_url="https://registry.example",
            auth_cache_ttl_seconds=1,
            AWEB_PAGE_DELETION_DATABASE_URL=ledger.config.get_dsn(),
            AWEB_PAGE_RETENTION_POLICY=POLICY,
        )
        app = create_app(settings, awid_transport=registry.transport)
        host = app.state.folio_records
        host.grants = GrantedInstallation()
        async with app.router.lifespan_context(app):
            headers = member.headers(aud=origin, method="GET", path="/verified-fixture")
            request = Request(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/verified-fixture",
                    "raw_path": b"/verified-fixture",
                    "query_string": b"",
                    "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
                },
                receive=empty_body,
            )
            principal = await host.runtime.principal(request)
            await record_observed_principal(host.runtime.db(), principal)
            grant = await host.grants.grant_for(TEAM)
            tool = host.runtime.declared_tools.match("POST", "/v1/collections")
            authorization = Authorization(principal, tool, grant)
            defined = await host.member_operation(
                authorization,
                "define_on",
                CollectionDefineRequest(
                    collection_id="discovery",
                    title=DISCOVERY_TITLE,
                    schema=DISCOVERY_SCHEMA,
                    request_id="define",
                ),
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=origin
            ) as client:
                yield SimpleNamespace(
                    host=host,
                    authorization=authorization,
                    defined=defined,
                    client=client,
                    registry=registry,
                    member=member,
                    app=app,
                    listener=listener,
                )


async def test_missing_installation_identity_is_refused_before_records_are_written(linked):
    from fastapi import HTTPException

    grant = Grant(
        team_id=TEAM,
        scopes=frozenset({"folio:read", "folio:write"}),
        fresh_until=time.monotonic_ns() + seconds_to_ns(60),
        installation_id=None,
        generation=None,
    )
    authorization = Authorization(linked.authorization.principal, linked.authorization.tool, grant)
    with pytest.raises(HTTPException) as refused:
        await linked.host.member_operation(
            authorization,
            "add_on",
            RecordAddRequest(
                collection_id="discovery", values=VALUE, request_id="missing-identity"
            ),
        )
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "installation_identity_required"


async def test_two_verified_members_race_and_only_one_revision_update_commits(linked):
    from fastapi import HTTPException

    from folio.record_models import RecordQueryRequest, RecordUpdateRequest

    added = await linked.host.member_operation(
        linked.authorization,
        "add_on",
        RecordAddRequest(collection_id="discovery", values=VALUE, request_id="race-add"),
    )
    other = Member(
        team_id=TEAM, team_key=linked.member.team_key, certificate_id="cert-bob", alias="bob"
    )
    await linked.registry.add_certificate(other.certificate())
    headers = other.headers(
        aud=linked.host.settings.public_origin, method="GET", path="/verified-fixture"
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/verified-fixture",
            "raw_path": b"/verified-fixture",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        },
        receive=empty_body,
    )
    principal = await linked.host.runtime.principal(request)
    await record_observed_principal(linked.host.runtime.db(), principal)
    second = Authorization(principal, linked.authorization.tool, linked.authorization.grant)

    async def update(authorization, status):
        return await linked.host.member_operation(
            authorization,
            "update_on",
            RecordUpdateRequest(
                collection_id="discovery",
                record_id=added["record"]["id"],
                expected_rev=1,
                patch={"status": status},
                request_id=f"race-{status}",
            ),
        )

    outcomes = await asyncio.gather(
        update(linked.authorization, "alice"), update(second, "bob"), return_exceptions=True
    )
    committed = [value for value in outcomes if isinstance(value, dict)]
    refused = [value for value in outcomes if isinstance(value, HTTPException)]
    assert len(committed) == 1 and len(refused) == 1, outcomes
    assert (refused[0].status_code, refused[0].detail["code"]) == (409, "revision_conflict")
    query = await linked.host.member_operation(
        second, "query_on", RecordQueryRequest(collection_id="discovery")
    )
    assert query["records"] == [committed[0]["record"]]
    assert query["records"][0]["value"]["finding"] == VALUE["finding"]


@pytest.mark.parametrize(
    "property_schema",
    [
        {"type": ["string", "null"], "maxLength": 160},
        True,
        False,
    ],
)
async def test_define_refuses_unsupported_field_schemas_without_partial_writes(
    linked, property_schema
):
    from aweb_naapp.pages import inline_schema_errors
    from fastapi import HTTPException

    schema = {
        "type": "object",
        "properties": {"status": property_schema},
        "additionalProperties": False,
    }
    assert inline_schema_errors(schema) == []
    db = linked.host.runtime.db()

    async def counts():
        return [
            await db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}")
            for table in ("pages", "page_audit", "page_receipts", "documents")
        ]

    before = await counts()
    with pytest.raises(HTTPException) as refused:
        await linked.host.member_operation(
            linked.authorization,
            "define_on",
            CollectionDefineRequest(
                collection_id="unsupported",
                title="Unsupported",
                schema=schema,
                request_id="unsupported-define",
            ),
        )
    assert (refused.value.status_code, refused.value.detail["code"]) == (422, "schema_invalid")
    assert await counts() == before
