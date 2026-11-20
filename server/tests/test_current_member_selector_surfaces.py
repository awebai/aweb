"""Current membership through actual selectors, transports and controller rotation.

Membership is not identity residence: Direct Address Send Protocol and
Continuations, docs/identity-messaging-contract.md:167-174,311-316. A global
address remains reachable while the old team membership disappears. Missing
selector fields are rejected rather than introducing a new API to this test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import json
from uuid import UUID, uuid4

import pytest
from awid.identity_observation import IdentityKind
from awid.signing import sign_message

from aweb.application_state import application_registry_client
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from mcp_runtime_fixtures import mounted_mcp
from messaging_actor_support import admit_messaging_actor
from test_agent_status_host_http import _controller_request
from test_agent_status_publish_http import (
    _designate,
    _document,
    _open_rate_window,
    _publish,
)
from test_dashboard import _JWT_SECRET, _make_jwt
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _change_key, _connect
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_identity_headers,
    _signed_team_headers,
)
from test_team_key_pinning import pinning as pinning


class Surface(StrEnum):
    HTTP = "http"
    MCP = "mcp"


class Selector(StrEnum):
    ALIAS = "alias"
    QUALIFIED_ALIAS = "qualified-alias"
    AGENT_ID = "agent-id"
    DID_KEY = "did-key"
    DID_AW = "did-aw"
    ADDRESS = "address"


class Operation(StrEnum):
    MAIL = "mail"
    CHAT = "chat"
    TASK = "task-assignee"
    ROSTER = "roster"
    DASHBOARD = "dashboard-roster"
    DASHBOARD_DETAIL = "dashboard-member"
    TEAM_COUNT = "team-count"
    DASHBOARD_COUNT = "dashboard-count"
    USAGE_COUNT = "usage-count"
    STATUS = "workspace-status"
    ROOM = "room-fanout"
    CONTROL = "control-target"
    STATUS_HOST = "status-host-target"
    STATUS_PUBLISH = "status-publish-target"
    HANDLE = "handle-contact"


@dataclass(frozen=True)
class Case:
    operation: Operation
    surface: Surface
    selector: Selector = Selector.ALIAS
    global_residence: bool = False

    @property
    def id(self):
        suffix = "-identity-residence" if self.global_residence else ""
        return f"{self.operation}-{self.surface}-{self.selector}{suffix}"


CASES = (
    [
        Case(operation, surface, selector)
        for operation in (Operation.MAIL, Operation.CHAT)
        for surface in Surface
        for selector in Selector
        # HTTP mail alone exposes to_agent_id. Neither chat nor MCP adds that API.
        if selector is not Selector.AGENT_ID
        or (operation is Operation.MAIL and surface is Surface.HTTP)
    ]
    + [
        Case(operation, surface, Selector.ADDRESS, global_residence=True)
        for operation in (Operation.MAIL, Operation.CHAT)
        for surface in Surface
    ]
    + [
        Case(Operation.TASK, surface, selector)
        for surface in Surface
        for selector in (Selector.ALIAS, Selector.AGENT_ID)
    ]
    + [Case(Operation.ROSTER, surface) for surface in Surface]
    + [
        Case(operation, Surface.HTTP)
        for operation in (
            Operation.DASHBOARD,
            Operation.DASHBOARD_DETAIL,
            Operation.TEAM_COUNT,
            Operation.DASHBOARD_COUNT,
            Operation.USAGE_COUNT,
            Operation.STATUS,
            Operation.ROOM,
            Operation.CONTROL,
            Operation.STATUS_HOST,
            Operation.STATUS_PUBLISH,
        )
    ]
    + [Case(Operation.HANDLE, Surface.MCP, Selector.ADDRESS)]
)


@pytest.fixture(autouse=True)
def dashboard_configuration_before_application_construction(monkeypatch):
    monkeypatch.setenv("AWEB_DASHBOARD_JWT_SECRET", _JWT_SECRET)


@dataclass
class Actor:
    sk: bytes = field(repr=False)
    did: str
    alias: str
    stable: str
    address: str
    id: UUID
    certificate: str


async def _admit(env, alias, *, global_identity=False):
    if global_identity:
        await application_registry_client(
            env.app.state
        ).update_namespace_delivery_origin(
            "example.test", bytes(env.namespace_sk), env.app.state.public_origin
        )
    actual = await admit_messaging_actor(
        env,
        alias=alias,
        team_id=TEAM,
        address=f"example.test/{alias}" if global_identity else "",
        kind=IdentityKind.UNKNOWN,
        local=not global_identity,
    )
    actor = Actor(
        actual.signing_key,
        actual.did_key,
        alias,
        actual.stable_id,
        actual.address,
        UUID(actual.agent_id),
        actual.certificate,
    )
    env.actors[alias] = actor
    if global_identity:
        response = await _http(
            env,
            actor,
            "PATCH",
            "/v1/agents/me/inbound-mode",
            {"inbound_mode": "open"},
            identity_only=True,
        )
        assert response.status_code == 200, response.text
    return actor


async def _readmit(env, actor, team_key):
    sk, did = team_key
    fields = _make_certificate(
        sk,
        did,
        actor.did,
        team_id=TEAM,
        alias=actor.alias,
        identity_scope="global" if actor.stable else "local",
        member_did_aw=actor.stable,
        member_address=actor.address,
        certificate_id="selector-" + uuid4().hex,
    )
    certificate = _encode_certificate(fields)
    name, domain = TEAM.split(":", 1)
    await application_registry_client(env.app.state).register_team_certificate(
        domain,
        name,
        team_controller_signing_key=sk,
        certificate_id=fields["certificate_id"],
        member_did_key=actor.did,
        member_did_aw=actor.stable,
        member_address=actor.address,
        alias=actor.alias,
        identity_scope=fields["identity_scope"],
        certificate=certificate,
    )
    response = await _connect(env, (actor.sk, actor.did, actor.alias), certificate)
    assert response.status_code == 200, response.text
    assert response.json()["agent_id"] == str(actor.id)
    actor.certificate = certificate


def _reference(actor, selector):
    return {
        Selector.ALIAS: actor.alias,
        Selector.QUALIFIED_ALIAS: TEAM.split(":", 1)[0] + "~" + actor.alias,
        Selector.AGENT_ID: str(actor.id),
        Selector.DID_KEY: actor.did,
        Selector.DID_AW: actor.stable,
        Selector.ADDRESS: actor.address,
    }[selector]


async def _http(env, actor, method, path, payload=None, *, identity_only=False):
    body = b"" if payload is None else json.dumps(payload).encode()
    headers = (
        _signed_identity_headers(actor.sk, actor.did, actor.stable, body)
        if identity_only
        else _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
    )
    return await env.client.request(
        method,
        path,
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )


async def _tool(env, actor, name, arguments):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()
    response = await env.client.post(
        "/mcp/",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 200, response.text
    envelope = response.json()
    assert "error" not in envelope, envelope
    result = envelope["result"]
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


async def _effect_counts(env):
    # Observation only: positive authority comes from admission, never these rows.
    return tuple(
        [
            await env.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}")
            for table in ("messages", "chat_messages", "tasks", "control_signals")
        ]
    )


async def _probe(env, case, sender, target, *, phase, team_key):
    op, ref = case.operation, _reference(target, case.selector)
    if op in (Operation.MAIL, Operation.CHAT):
        if case.surface is Surface.MCP:
            args = {"to": ref, "plaintext": True}
            args.update(
                {"body": "selector", "subject": "membership"}
                if op is Operation.MAIL
                else {"message": "selector"}
            )
            return await _tool(
                env, sender, "send_mail" if op is Operation.MAIL else "send_chat", args
            )
        key = {
            Selector.ALIAS: "to_alias",
            Selector.QUALIFIED_ALIAS: "to_alias",
            Selector.AGENT_ID: "to_agent_id",
            Selector.DID_KEY: "to_did",
            Selector.DID_AW: "to_did",
            Selector.ADDRESS: "to_address",
        }[case.selector]
        if op is Operation.MAIL:
            return await _http(
                env,
                sender,
                "POST",
                "/v1/messages",
                {key: ref, "subject": "membership", "body": "selector"},
                identity_only=True,
            )
        chat_key = {
            "to_alias": "to_aliases",
            "to_did": "to_dids",
            "to_address": "to_addresses",
        }[key]
        return await _http(
            env,
            sender,
            "POST",
            "/v1/chat/sessions",
            {chat_key: [ref], "message": "selector"},
            identity_only=True,
        )
    if op is Operation.TASK:
        if case.surface is Surface.MCP:
            return await _tool(
                env, sender, "task_create", {"title": "selector", "assignee": ref}
            )
        return await _http(
            env,
            sender,
            "POST",
            "/v1/tasks",
            {"title": "selector", "assignee_alias": ref},
        )
    if op is Operation.ROSTER:
        if case.surface is Surface.MCP:
            return await _tool(env, sender, "list_agents", {})
        return await _http(env, sender, "GET", "/v1/agents")
    if op is Operation.TEAM_COUNT:
        return await _http(env, sender, "GET", "/v1/team")
    if op in (
        Operation.DASHBOARD,
        Operation.DASHBOARD_DETAIL,
        Operation.DASHBOARD_COUNT,
        Operation.USAGE_COUNT,
    ):
        suffix = {
            Operation.DASHBOARD: "agents",
            Operation.DASHBOARD_DETAIL: "agents/" + target.alias,
            Operation.DASHBOARD_COUNT: "status",
            Operation.USAGE_COUNT: "usage",
        }[op]
        return await env.client.get(
            f"/v1/teams/{TEAM}/{suffix}",
            headers={"Authorization": "Bearer " + _make_jwt([TEAM])},
        )
    if op is Operation.STATUS:
        return await _http(env, sender, "GET", "/v1/status")
    if op is Operation.CONTROL:
        return await _http(
            env,
            sender,
            "POST",
            f"/v1/agents/{target.alias}/control",
            {"signal": "pause"},
        )
    if op is Operation.STATUS_HOST:
        return await _controller_request(
            env,
            target.alias,
            host_did=sender.did,
            previous_host_did="" if phase == 0 else sender.did,
            signer=team_key,
        )
    if op is Operation.STATUS_PUBLISH:
        await _open_rate_window(env, target.alias)
        return await _publish(
            env,
            sender.alias,
            target.alias,
            _document(env, target.alias, sender.alias, seq=phase + 1),
        )
    if op is Operation.HANDLE:
        return await _tool(
            env, sender, "read_contact_messages", {"contact_id": env.matrix_contact_id}
        )
    if op is Operation.ROOM:
        from test_team_room import metadata, post, post_payload

        room = await metadata(env, sender.alias)
        payload = post_payload(env, room, actor=sender.alias)
        response = await post(env, room, actor=sender.alias, payload=payload)
        assert response.status_code == 200, response.text
        return {
            "target_notices": await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.room_post_notices}} WHERE message_id=$1 AND recipient_agent_id=$2",
                UUID(response.json()["message_id"]),
                target.id,
            )
        }
    raise AssertionError(case)


def _check(result, case, target, *, current, phase):
    op = case.operation
    data = result if isinstance(result, dict) else result.json()
    context = (case.id, phase, data)
    # These reads reveal only current members; residence is tested separately.
    if op in (
        Operation.ROSTER,
        Operation.DASHBOARD,
        Operation.STATUS,
        Operation.TEAM_COUNT,
        Operation.DASHBOARD_COUNT,
        Operation.USAGE_COUNT,
    ):
        if isinstance(result, dict):
            assert "error" not in data, context
            assert "agents" in data, context
        else:
            assert result.status_code == 200, context
    if op in (Operation.ROSTER, Operation.DASHBOARD):
        assert (
            str(target.id) in json.dumps(data)
            if current
            else str(target.id) not in json.dumps(data)
        ), context
        return
    if op is Operation.STATUS:
        assert (
            target.alias in json.dumps(data)
            if current
            else target.alias not in json.dumps(data)
        ), context
        return
    if op in (Operation.TEAM_COUNT, Operation.DASHBOARD_COUNT, Operation.USAGE_COUNT):
        key = {
            Operation.TEAM_COUNT: "member_count",
            Operation.DASHBOARD_COUNT: "agent_count",
            Operation.USAGE_COUNT: "active_agents",
        }[op]
        if phase:
            assert data[key] == (3 if current else 2), context
        else:
            assert data[key] >= 2, context
        return
    if op is Operation.ROOM:
        assert data["target_notices"] == int(current), context
        return
    if isinstance(result, dict):
        assert ("error" not in data) is current, context
        if current and op in (Operation.MAIL, Operation.CHAT):
            assert data.get("message_id"), context
    else:
        if current:
            assert result.status_code == 200, context
        else:
            status = (
                422
                if op is Operation.TASK
                or (op is Operation.CHAT and case.selector is Selector.DID_AW)
                else 404
            )
            assert result.status_code == status, context


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
async def test_selector_and_surface_recheck_membership_after_product_rotation(
    pinning, case
):
    env = pinning
    sender = await _admit(env, "matrixsender")
    global_target = case.selector in (Selector.DID_AW, Selector.ADDRESS)
    target = await _admit(env, "matrixtarget", global_identity=global_target)
    if case.operation is Operation.STATUS_PUBLISH:
        await _designate(env, target.alias, sender.alias)

    async def signer(**kwargs):
        payload = dict(kwargs["payload"])
        signed = canonical_signed_payload(payload)
        return HostedMessageSigningResult(
            from_did=sender.did,
            signature=sign_message(sender.sk, signed.encode()),
            signed_payload=signed,
            signing_key_id=sender.did,
        )

    async with mounted_mcp(
        env.app,
        db_infra=env.infra,
        redis=env.redis,
        registry_client=application_registry_client(env.app.state),
        hosted_signer=signer,
    ):
        if case.operation is Operation.HANDLE:
            contact = await _tool(
                env, sender, "add_contact_by_handle", {"handle": "@" + target.address}
            )
            assert "error" not in contact, contact
            env.matrix_contact_id = contact["contact_id"]
        key = (env.team_sk, env.team_did)
        before = await _probe(env, case, sender, target, phase=0, team_key=key)
        _check(before, case, target, current=True, phase=0)
        key = await _change_key(env)
        await _readmit(env, sender, key)
        counts = await _effect_counts(env)
        after = await _probe(env, case, sender, target, phase=1, team_key=key)
        _check(after, case, target, current=case.global_residence, phase=1)
        if not case.global_residence and case.operation in (
            Operation.MAIL,
            Operation.CHAT,
            Operation.TASK,
            Operation.CONTROL,
        ):
            assert await _effect_counts(env) == counts
        await _readmit(env, target, key)
        restored = await _probe(env, case, sender, target, phase=2, team_key=key)
        _check(restored, case, target, current=True, phase=2)
