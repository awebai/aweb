"""The runtime's real authenticated path prepares evidence; effects own the tx."""

import hashlib
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated
from uuid import uuid4

import httpx
import pytest
from aweb_naapp_testing import Member
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from aweb_naapp.hooks.commitment import CommitmentContext, RequestBytes
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.runtime.authorization import Authorization, Grant
from aweb_naapp.runtime.hook_resolver import HookResolutionUnavailable
from aweb_naapp.runtime.manifest_hooks import bounded_body
from tests.hooks.test_producer import TEAM
from tests.runtime.test_hook_production import INSTALLATION, MANIFEST_HOOK, runtime
from tests.runtime.test_served_manifest import HOSTED_ORIGIN, _key_file

PATH = "/bot/{credential}/things"
TOOL = {
    "name": "change",
    "method": "POST",
    "path": PATH,
    "scopes": ["example:write"],
    "mutation": True,
    "params": [{"name": "credential", "in": "path"}],
    "input_schema": {"type": "object", "properties": {"credential": {"type": "string"}}},
}


@dataclass
class Grants:
    scopes: frozenset[str] = frozenset({"example:write"})
    installed: bool = True
    installation_id: str | None = INSTALLATION
    generation: int = 2

    async def grant_for(self, team_id):
        if not self.installed:
            return None
        return Grant(
            team_id=team_id,
            scopes=self.scopes,
            fresh_until=time.monotonic() + 60,
            installation_id=self.installation_id,
            generation=self.generation,
        )


@asynccontextmanager
async def running(
    tmp_path,
    registry,
    test_db_factory,
    *,
    allow=True,
    grants=None,
    raw=False,
    mutation=True,
    reads=(),
    rollback=False,
    inject=False,
    specific=False,
    database=None,
    key=None,
    key_files=None,
    member=None,
    root_path="",
    **settings,
):
    if member is None:
        member = Member(team_id=TEAM)
        await registry.add_team(TEAM, member.team_did_key)
        await registry.add_certificate(member.certificate())
    database = database or await test_db_factory.create_db(suffix="manifest_hook_runtime")
    key = key or _key_file(tmp_path, "commitment", secrets.token_hex(32))
    tool = {**TOOL, "mutation": mutation, "path": root_path + PATH}
    if raw:
        tool["params"] = [*tool["params"], {"name": "data", "in": "body"}]
        tool["input_schema"] = {
            "type": "object",
            "properties": {"credential": {"type": "string"}, "data": {"type": "string"}},
        }
        tool["body"] = {
            "mode": "raw",
            "raw_param": "data",
            "content_type": "application/octet-stream",
        }
    app_runtime = runtime(
        tmp_path,
        hook=MANIFEST_HOOK,
        registry=registry,
        tools=[tool],
        reads=reads,
        key_files=key_files,
        root_path=root_path,
        extra_productions=("post-secret-use-hook",) if specific else (),
        hook_tool_effects={"change": "post-secret-use-hook"} if specific else {},
        manifest_request_key_file=key,
        database_url=database.config.get_dsn(),
        db_schema=database.config.schema_name,
        **settings,
    )

    async def unavailable(*args):
        # No external authority/DNS in this composition test. Real resolver
        # HTTP/expiry behavior is covered by the landed runtime/accessor tests.
        raise HookResolutionUnavailable("fixture_offline")

    app_runtime.hook_resolver().registrations = unavailable

    async def policy(request, principal, matched):
        return allow

    guard = app_runtime.authorized(grants=grants or Grants(), policy=policy)
    server = FastAPI(lifespan=app_runtime.lifespan)

    @server.post(PATH)
    async def effect(request: Request, auth: Annotated[Authorization, Depends(guard)]):
        if inject:
            request._body = b"changed after admission"
        async with app_runtime.db().transaction() as tx:
            await tx.execute(
                "INSERT INTO {{tables.fixture_effect}} VALUES (1) ON CONFLICT DO NOTHING"
            )
            await app_runtime.record_manifest_command(
                tx,
                request=request,
                authorization=auth,
                http_status=201,
                resource_refs=("thing:opaque",),
                result_ref="result:opaque",
            )
            if rollback:
                raise RuntimeError("effect failed before commit")
        return JSONResponse({"ok": True}, status_code=201)

    async with server.router.lifespan_context(server):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=server, raise_app_exceptions=False, root_path=root_path
            ),
            base_url=HOSTED_ORIGIN,
        ) as client:
            yield app_runtime, client, member


def signed(member, path, body=b"{}", content_type="application/json", **changes):
    headers = member.headers(
        aud=HOSTED_ORIGIN,
        method="POST",
        path=path,
        body=body,
        payload_changes=changes or None,
    )
    return {"headers": {**headers, "Content-Type": content_type}, "content": body}


async def recorded(app_runtime):
    rows = await app_runtime.db().fetch_all(
        "SELECT * FROM {{tables.outbox_events}} ORDER BY position"
    )
    return [verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields for row in rows]


@pytest.mark.parametrize("raw", [False, True])
async def test_signed_mutation_records_only_the_initial_request_commitment(
    tmp_path,
    registry,
    test_db_factory,
    raw,
):
    marker = secrets.token_urlsafe(18)
    path = f"/bot/{marker}/things?key={marker}%2Ffirst&key=second"
    body = b"\x00\xff\r\nraw" if raw else ('{ "token" : "' + marker + '" }').encode()
    content_type = "application/octet-stream" if raw else "application/json; charset=utf-8"
    trace = "f1" * 16
    async with running(tmp_path, registry, test_db_factory, raw=raw, inject=True) as (
        app,
        client,
        member,
    ):
        response = await client.post(
            path, **signed(member, path, body, content_type, trace_id=trace)
        )
        assert response.status_code == 201, response.text
        (event,) = await recorded(app)
        context = CommitmentContext("example", TEAM, INSTALLATION, 2, "change")
        expected = app._hooks.manifest_request_key.request(
            context,
            RequestBytes("POST", path.encode(), (content_type.encode(),), body),
        )
        assert event["payload"] == {
            "app_id": "example",
            "tool": "change",
            "operation_kind": "mutation",
            "request_sha256": expected,
            "http_status": 201,
            "resource_refs": ["thing:opaque"],
            "result_ref": "result:opaque",
        }
        assert expected != hashlib.sha256(body).hexdigest()
        assert event["actor"]["did_key"] == member.did_key
        assert event["actor"]["authority_mode"] == "team_cert"
        assert event["trace"] == {"id": trace, "origin": "signed_request"}
        wire = (await app.db().fetch_one("SELECT payload FROM {{tables.outbox_events}}"))["payload"]
        assert marker.encode() not in wire and body not in wire
        assert b"changed after admission" not in wire


@pytest.mark.parametrize("kind", ["policy", "scope"])
async def test_complete_authenticated_refusal_is_attributable(
    tmp_path, registry, test_db_factory, kind
):
    options = {"allow": False} if kind == "policy" else {"grants": Grants(scopes=frozenset())}
    async with running(tmp_path, registry, test_db_factory, **options) as (app, client, member):
        path = "/bot/refused/things"
        response = await client.post(path, **signed(member, path))
        assert response.status_code == 403
        (event,) = await recorded(app)
        assert event["payload"]["operation_kind"] == "refusal"
        assert event["payload"]["http_status"] == 403
        assert "result_ref" not in event["payload"]
        assert event["result_status"] == "denied"
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.fixture_effect}}") == 0


@pytest.mark.parametrize("kind", ["unsigned", "not_installed", "unknown_installation", "oversize"])
async def test_early_or_unattributable_refusal_has_no_event(
    tmp_path, registry, test_db_factory, kind
):
    options = {
        "not_installed": {"grants": Grants(installed=False)},
        "unknown_installation": {"grants": Grants(installation_id=None)},
        "oversize": {"manifest_hook_max_request_bytes": 1},
    }.get(kind, {})
    async with running(tmp_path, registry, test_db_factory, **options) as (app, client, member):
        path = "/bot/early/things"
        request = {} if kind == "unsigned" else signed(member, path)
        response = await client.post(path, **request)
        assert (
            response.status_code
            == {
                "unsigned": 401,
                "not_installed": 403,
                "unknown_installation": 503,
                "oversize": 413,
            }[kind]
        )
        assert await recorded(app) == []
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.fixture_effect}}") == 0


@pytest.mark.parametrize("listed", [False, True])
async def test_successful_reads_are_opt_in(tmp_path, registry, test_db_factory, listed):
    async with running(
        tmp_path,
        registry,
        test_db_factory,
        mutation=False,
        reads=("change",) if listed else (),
    ) as (app, client, member):
        path = "/bot/read/things"
        assert (await client.post(path, **signed(member, path))).status_code == 201
        records = await recorded(app)
        assert len(records) == int(listed)
        if records:
            assert records[0]["payload"]["operation_kind"] == "read"


@pytest.mark.parametrize("allow", [False, True])
async def test_specific_hook_owns_its_effect_and_refusals(
    tmp_path, registry, test_db_factory, allow
):
    async with running(tmp_path, registry, test_db_factory, specific=True, allow=allow) as (
        app,
        client,
        member,
    ):
        path = "/bot/specific/things"
        assert (await client.post(path, **signed(member, path))).status_code == (
            201 if allow else 403
        )
        assert await recorded(app) == []


async def test_manifest_event_rolls_back_with_its_effect(tmp_path, registry, test_db_factory):
    async with running(tmp_path, registry, test_db_factory, rollback=True) as (app, client, member):
        path = "/bot/rollback/things"
        assert (await client.post(path, **signed(member, path))).status_code == 500
        assert await recorded(app) == []
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.fixture_effect}}") == 0


@pytest.mark.parametrize("interrupted", [False, True])
async def test_body_limit_or_disconnect_does_not_drain_or_substitute_partial_bytes(interrupted):
    calls = []

    async def receive():
        calls.append(True)
        if len(calls) == 1:
            return {"type": "http.request", "body": b"abc", "more_body": True}
        if interrupted:
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": b"def", "more_body": True}

    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []}, receive)
    with pytest.raises(ClientDisconnect if interrupted else HTTPException):
        await bounded_body(request, 4)
    assert len(calls) == 2
    assert not hasattr(request, "_body")


@pytest.mark.parametrize("raw", [False, True])
async def test_runtime_binding_preserves_each_component_and_equal_inputs(
    tmp_path,
    registry,
    test_db_factory,
    raw,
):
    body = b"binary\x00\xff" if raw else b'{"x":1}'
    changed = body + b"x" if raw else b'{"x":2}'
    ct = "application/octet-stream" if raw else "application/json"
    cases = [
        ("/bot/one/things?a=1", ct, body),
        ("/bot/one/things?a=1", ct, body),
        ("/bot/two/things?a=1", ct, body),
        ("/bot/one/things?a=2", ct, body),
        ("/bot/one/things?a=1", ct + "; parameter=value", body),
        ("/bot/one/things?a=1", ct, changed),
    ]
    async with running(tmp_path, registry, test_db_factory, raw=raw) as (app, client, member):
        commitments = []
        for path, content_type, value in cases:
            response = await client.post(path, **signed(member, path, value, content_type))
            assert response.status_code == 201, response.text
            commitments.append((await recorded(app))[-1]["payload"]["request_sha256"])
        assert commitments[0] == commitments[1]
        assert len(set(commitments)) == 5


@pytest.mark.parametrize("values", [(), (b"",), (b"application/json", b"text/plain")])
async def test_received_content_type_count_and_order_are_committed(
    tmp_path,
    registry,
    test_db_factory,
    values,
):
    path, body = "/bot/header/things", b"{}"
    async with running(tmp_path, registry, test_db_factory) as (app, client, member):
        headers = list(
            member.headers(aud=HOSTED_ORIGIN, method="POST", path=path, body=body).items()
        )
        headers.extend(("Content-Type", value.decode()) for value in values)
        response = await client.post(path, headers=headers, content=body)
        assert response.status_code == 201, response.text
        (event,) = await recorded(app)
        expected = app._hooks.manifest_request_key.request(
            CommitmentContext("example", TEAM, INSTALLATION, 2, "change"),
            RequestBytes("POST", path.encode(), values, body),
        )
        assert event["payload"]["request_sha256"] == expected


async def test_rotation_reuses_old_signed_bytes_and_changes_only_new_commitments(
    tmp_path,
    registry,
    test_db_factory,
):
    database = await test_db_factory.create_db(suffix="manifest_rotation")
    key = _key_file(tmp_path, "commitment", secrets.token_hex(32))
    first_dir = tmp_path / "first"
    first_dir.mkdir()
    path = "/bot/rotation/things"
    async with running(
        first_dir,
        registry,
        test_db_factory,
        database=database,
        key=key,
    ) as (app, client, member):
        assert (await client.post(path, **signed(member, path))).status_code == 201
        original = await app.db().fetch_one(
            "SELECT event_id,payload,signature FROM {{tables.outbox_events}}"
        )
        old_commitment = (await recorded(app))[0]["payload"]["request_sha256"]
        files = dict(app.settings.app_key_files)
    # The old HMAC key is destroyed; no history/key ring is needed by a retry.
    key.unlink()
    key.write_text(secrets.token_hex(32) + "\n")
    key.chmod(0o600)
    second_dir = tmp_path / "second"
    second_dir.mkdir()
    async with running(
        second_dir,
        registry,
        test_db_factory,
        database=database,
        key=key,
        key_files=files,
        member=member,
    ) as (app, client, member):
        assert (await client.post(path, **signed(member, path))).status_code == 201
        preserved = await app.db().fetch_one(
            "SELECT event_id,payload,signature FROM {{tables.outbox_events}} WHERE event_id=$1",
            original["event_id"],
        )
        assert preserved == original
        first, second = await recorded(app)
        assert first["payload"]["request_sha256"] == old_commitment
        assert second["payload"]["request_sha256"] != old_commitment
        assert second["producer"]["seq"] == 2


async def test_commitment_binds_the_external_mount_prefix(tmp_path, registry, test_db_factory):
    path = "/mounted/bot/prefix/things?order=2&order=1"
    async with running(
        tmp_path,
        registry,
        test_db_factory,
        root_path="/mounted",
    ) as (app, client, member):
        response = await client.post(path, **signed(member, path))
        assert response.status_code == 201, response.text
        (event,) = await recorded(app)
        expected = app._hooks.manifest_request_key.request(
            CommitmentContext("example", TEAM, INSTALLATION, 2, "change"),
            RequestBytes("POST", path.encode(), (b"application/json",), b"{}"),
        )
        assert event["payload"]["request_sha256"] == expected


async def test_runtime_uses_authoritative_installation_and_generation_context(
    tmp_path,
    registry,
    test_db_factory,
):
    grants = Grants()
    path = "/bot/context/things"
    async with running(tmp_path, registry, test_db_factory, grants=grants) as (app, client, member):
        for installation, generation in [(INSTALLATION, 2), (INSTALLATION, 3), (str(uuid4()), 3)]:
            grants.installation_id, grants.generation = installation, generation
            response = await client.post(path, **signed(member, path))
            assert response.status_code == 201, response.text
            event = (await recorded(app))[-1]
            expected = app._hooks.manifest_request_key.request(
                CommitmentContext("example", TEAM, installation, generation, "change"),
                RequestBytes("POST", path.encode(), (b"application/json",), b"{}"),
            )
            assert event["payload"]["request_sha256"] == expected
            assert event["producer"]["installation_id"] == installation
            assert event["producer"]["generation"] == generation
        assert len({e["payload"]["request_sha256"] for e in await recorded(app)}) == 3


@pytest.mark.parametrize("fault", ["noncanonical", "undeclared"])
async def test_authorization_refusal_logs_do_not_echo_credential_shaped_targets(
    tmp_path,
    registry,
    test_db_factory,
    caplog,
    fault,
):
    from aweb_naapp.runtime.authorization import authorize_request
    from aweb_naapp.runtime.team_auth import Principal

    marker = secrets.token_urlsafe(18)
    path = f"/bot/{marker}/things"
    async with running(tmp_path, registry, test_db_factory) as (app, _, member):
        # Exercise the pre-grant logging boundary directly; the authenticated
        # HTTP path and valid neighbor are covered by the integration cases.
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "headers": [],
                "query_string": b"",
                "raw_path": path.encode(),
                "path": "/mismatched" if fault == "noncanonical" else path,
            }
        )
        principal = Principal(
            team_id=TEAM,
            did_key=member.did_key,
            did_aw=None,
            address=None,
            alias=member.alias,
            certificate_id=member.certificate_id,
            team_did_key=member.team_did_key,
        )

        async def no_policy(*args):
            raise AssertionError("refusal must precede policy")

        with caplog.at_level("WARNING"), pytest.raises(HTTPException) as refusal:
            await authorize_request(
                request,
                principal=principal,
                caller="agent",
                tools=app.declared_tools,
                grants=Grants(),
                policy=no_policy,
            )
        assert refusal.value.status_code == (400 if fault == "noncanonical" else 403)
        assert marker not in caplog.text
        assert "Refused" in caplog.text
