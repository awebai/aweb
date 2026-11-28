"""Current membership through actual selectors, transports and controller rotation.

Membership is not identity residence: Direct Address Send Protocol
(docs/identity-messaging-contract.md:161-168) and
Continuations (docs/identity-messaging-contract.md:305-310). A global
address remains reachable while the old team membership disappears. Missing
selector fields are rejected rather than introducing a new API to this test.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
import base64
import json
from uuid import UUID, uuid4

import pytest
from awid.identity_observation import IdentityKind
from awid.signing import sign_message

from aweb.application_state import application_registry_client
from aweb.lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from aweb.mcp.signing import HostedMessageSigningResult, canonical_signed_payload
from mcp_runtime_fixtures import mounted_mcp
from messaging_actor_support import admit_messaging_actor
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

__all__ = ["pinning"]


class Surface(StrEnum):
    HTTP = "http"
    MCP = "mcp"
    NATIVE = "native-owner"


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
    NOTICE_COUNT = "room-notice-count"
    CONTROL = "control-target"
    HANDLE = "handle-contact"


class MembershipChange(StrEnum):
    ROTATION = "rotation"
    ARCHIVE = "archive"
    DELETE = "delete"


@dataclass(frozen=True)
class Case:
    operation: Operation
    surface: Surface
    selector: Selector = Selector.ALIAS
    global_residence: bool = False
    superseded_sender: bool = False
    change: MembershipChange = MembershipChange.ROTATION

    @property
    def id(self):
        suffix = "-identity-residence" if self.global_residence else ""
        if self.superseded_sender:
            suffix += "-superseded-sender"
        if self.change is not MembershipChange.ROTATION:
            suffix += f"-{self.change}"
        return f"{self.operation}-{self.surface}-{self.selector}{suffix}"


SEND_CASES = [
    Case(operation, surface, selector)
    for operation in (Operation.MAIL, Operation.CHAT)
    for surface in (Surface.HTTP, Surface.MCP)
    for selector in Selector
    # HTTP mail alone exposes to_agent_id. Neither chat nor MCP adds that API.
    if selector is not Selector.ADDRESS
    and (
        selector is not Selector.AGENT_ID
        or (operation is Operation.MAIL and surface is Surface.HTTP)
    )
] + [
    Case(operation, surface, Selector.ADDRESS, global_residence=True)
    for operation in (Operation.MAIL, Operation.CHAT)
    for surface in (Surface.HTTP, Surface.MCP)
]


CASES = (
    SEND_CASES
    + [
        Case(Operation.TASK, surface, selector)
        for surface in (Surface.HTTP, Surface.MCP)
        for selector in (Selector.ALIAS, Selector.AGENT_ID)
    ]
    + [Case(Operation.ROSTER, surface) for surface in (Surface.HTTP, Surface.MCP)]
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
        )
    ]
    + [Case(Operation.HANDLE, Surface.MCP, Selector.ADDRESS)]
    + [Case(Operation.NOTICE_COUNT, Surface.NATIVE)]
    + [Case(Operation.CHAT, Surface.HTTP, Selector.AGENT_ID)]
    + [
        replace(case, global_residence=False, superseded_sender=True)
        for case in SEND_CASES
    ]
    + [
        Case(operation, surface, change=change)
        for operation in (Operation.MAIL, Operation.CHAT)
        for surface in (Surface.HTTP, Surface.MCP)
        for change in (MembershipChange.ARCHIVE, MembershipChange.DELETE)
    ]
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
            "example.test", bytes(env.namespace_sk), "https://matrix.example.test"
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
            identity_only=False,
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
    registry = application_registry_client(env.app.state)
    previous = json.loads(base64.b64decode(actor.certificate))
    await registry.revoke_team_certificate(
        domain,
        name,
        team_controller_signing_key=sk,
        certificate_id=previous["certificate_id"],
    )
    await registry.register_team_certificate(
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


async def _tool(env, actor, name, arguments, *, identity_only=False):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()
    headers = (
        _signed_identity_headers(actor.sk, actor.did, actor.stable, body)
        if identity_only
        else _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
    )
    response = await env.client.post(
        "/mcp/",
        content=body,
        headers={
            **headers,
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
            for table in (
                "messages",
                "chat_messages",
                "conversations",
                "chat_sessions",
                "contacts",
                "message_ingress_receipts",
                "tasks",
                "control_signals",
            )
        ]
    )


async def _probe(env, case, sender, target, *, phase):
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
                env,
                sender,
                "send_mail" if op is Operation.MAIL else "send_chat",
                args,
                identity_only=case.superseded_sender,
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
        if case.selector is Selector.AGENT_ID:
            return await _http(
                env,
                sender,
                "POST",
                "/v1/chat/sessions",
                {"to_agent_ids": [ref], "message": "selector"},
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
        path = (
            f"/v1/usage?team_id={TEAM}"
            if op is Operation.USAGE_COUNT
            else f"/v1/teams/{TEAM}/{suffix}"
        )
        return await env.client.get(
            path,
            headers={"X-Dashboard-Token": _make_jwt([TEAM])},
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
    if op is Operation.HANDLE:
        return await _tool(
            env, sender, "read_contact_messages", {"contact_id": env.matrix_contact_id}
        )
    if op is Operation.NOTICE_COUNT:
        from aweb.messaging.room_notices import count_room_notices

        return {
            "target_notices": await count_room_notices(
                env.infra, env.matrix_target_identity
            )
        }
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


def _expected_refusal(case, target):
    op = case.operation
    if case.superseded_sender:
        if case.selector in (Selector.ALIAS, Selector.QUALIFIED_ALIAS):
            if case.surface is Surface.MCP:
                detail = (
                    "Alias delivery requires team context"
                    if op is Operation.MAIL
                    else "to_alias requires team context"
                )
            else:
                detail = (
                    "to_alias requires team context"
                    if op is Operation.MAIL
                    else "to_aliases requires team context"
                )
            return 422, None, detail
        if case.selector in (Selector.DID_AW, Selector.ADDRESS):
            return (
                403,
                "recipient_policy_rejected",
                (
                    "Recipient only accepts messages from verified team members or exact active contacts. "
                    "Ask the recipient to add your exact address as a contact or check their inbound policy."
                ),
            )
        return (
            404,
            "local_recipient_route_missing",
            (
                "The recipient is not reachable from outside its team. Use a teammate alias from inside its team, "
                "or ask the recipient for a registered address and retry."
            ),
        )
    if op in (Operation.MAIL, Operation.CHAT):
        if case.selector is Selector.DID_AW:
            destination = (
                "to_address=domain/name or continue an existing conversation"
                if op is Operation.MAIL
                else "to_addresses=domain/name or continue an existing session"
            )
            return (
                422,
                None,
                f"Bare did:aw first-contact is unsupported; use {destination}",
            )
        label = f": {_reference(target, case.selector)}" if op is Operation.CHAT else ""
        return (
            404,
            None,
            (
                f"Recipient name does not identify a current member of the team{label}. "
                "Check the name; if the agent exists, ask it to reconnect with a current team certificate."
            ),
        )
    return {
        Operation.TASK: (422, None, "Assignee agent not found in this team"),
        Operation.DASHBOARD_DETAIL: (404, None, "Agent not found"),
        Operation.CONTROL: (404, None, "Agent not found"),
        Operation.HANDLE: (404, None, "No active agent found for handle contact"),
    }[op]


def _check(result, case, target, *, current, phase):
    op = case.operation
    data = result if isinstance(result, dict) else result.json()
    context = (case.id, phase, data)
    if op is Operation.CHAT and case.selector is Selector.AGENT_ID:
        assert result.status_code == 422, context
        assert any(
            item["type"] == "extra_forbidden" and "to_agent_ids" in item["loc"]
            for item in data["detail"]
        ), context
        return
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
        assert data[key] == (5 if phase == 0 else 3 if current else 2), context
        return
    if op in (Operation.ROOM, Operation.NOTICE_COUNT):
        assert data["target_notices"] == int(current), context
        return
    if current:
        if isinstance(result, dict):
            assert "error" not in data, context
        else:
            assert result.status_code == 200, context
        if op in (Operation.MAIL, Operation.CHAT):
            assert data.get("message_id"), context
        return
    status, reason, detail = _expected_refusal(case, target)
    if isinstance(result, dict):
        assert data["error"] == detail, context
    else:
        assert result.status_code == status, context
        assert data["detail"] == detail, context
    if reason is not None:
        assert data["reason"] == reason, context


async def _assert_send_effect(env, result, case, sender, target):
    if case.operation not in (Operation.MAIL, Operation.CHAT):
        return
    data = result if isinstance(result, dict) else result.json()
    if "error" in data or not data.get("message_id"):
        return
    message_id = UUID(data["message_id"])
    if case.operation is Operation.MAIL:
        row = await env.db.fetch_one(
            "SELECT from_did, to_did, body FROM {{tables.messages}} WHERE message_id=$1",
            message_id,
        )
        assert (row["from_did"], row["to_did"], row["body"]) == (
            sender.stable or sender.did,
            target.stable or target.did,
            "selector",
        ), case.id
    else:
        row = await env.db.fetch_one(
            "SELECT from_did, session_id, body FROM {{tables.chat_messages}} WHERE message_id=$1",
            message_id,
        )
        assert (row["from_did"], row["body"]) == (
            sender.stable or sender.did,
            "selector",
        ), case.id
        participants = await env.db.fetch_all(
            "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1",
            row["session_id"],
        )
        assert {item["did"] for item in participants} == {
            sender.stable or sender.did,
            target.stable or target.did,
        }, case.id


async def _capture_room_actor(env, actor):
    from starlette.requests import Request
    from aweb.team_auth_deps import get_team_identity

    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/room",
            "headers": [
                (key.lower().encode(), value.encode()) for key, value in headers.items()
            ],
            "app": env.app,
        }
    )
    return await get_team_identity(request, env.infra)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
async def test_selector_and_surface_recheck_membership_after_product_change(
    pinning, case
):
    env = pinning
    sender = await _admit(env, "matrixsender")
    global_target = (
        case.selector in (Selector.DID_AW, Selector.ADDRESS)
        or case.change is MembershipChange.ARCHIVE
    )
    target = await _admit(env, "matrixtarget", global_identity=global_target)
    if case.superseded_sender and global_target:
        restricted = await _http(
            env,
            target,
            "PATCH",
            "/v1/agents/me/inbound-mode",
            {"inbound_mode": "team_and_contacts"},
        )
        assert restricted.status_code == 200, restricted.text

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
        if case.operation is Operation.NOTICE_COUNT:
            from test_team_room import metadata, post, post_payload

            room = await metadata(env, sender.alias)
            sent = await post(
                env,
                room,
                actor=sender.alias,
                payload=post_payload(env, room, actor=sender.alias),
            )
            assert sent.status_code == 200, sent.text
            env.matrix_target_identity = await _capture_room_actor(env, target)
        key = (env.team_sk, env.team_did)
        before = await _probe(env, case, sender, target, phase=0)
        _check(before, case, target, current=True, phase=0)
        await _assert_send_effect(env, before, case, sender, target)
        if case.change is MembershipChange.ARCHIVE:
            result = await apply_lifecycle_cascade(
                env.db,
                env.redis,
                LifecycleCascadeRequest(
                    operation="archive_global_agent",
                    actor=LifecycleActor(
                        actor_id=None, actor_type="support", authority="operator"
                    ),
                    team_id=TEAM,
                    target_agent_id=str(target.id),
                    workspace_scope="all_for_agent",
                    require_identity_scope="global",
                ),
                registry_client=application_registry_client(env.app.state),
            )
            assert result.errors == () and result.identity_archived
        elif case.change is MembershipChange.DELETE:
            workspace_id = await env.db.fetch_value(
                "SELECT workspace_id FROM {{tables.workspaces}} WHERE agent_id=$1 AND deleted_at IS NULL",
                target.id,
            )
            deleted = await _http(
                env, target, "DELETE", f"/v1/workspaces/{workspace_id}"
            )
            assert deleted.status_code == 200, deleted.text
            assert deleted.json()["identity_deleted"] is True
        else:
            key = await _change_key(env)
            await _readmit(env, target if case.superseded_sender else sender, key)
        counts = await _effect_counts(env)
        after = await _probe(env, case, sender, target, phase=1)
        _check(after, case, target, current=case.global_residence, phase=1)
        await _assert_send_effect(env, after, case, sender, target)
        if not case.global_residence and case.operation in (
            Operation.MAIL,
            Operation.CHAT,
            Operation.TASK,
            Operation.CONTROL,
        ):
            assert await _effect_counts(env) == counts
        if case.change is not MembershipChange.ROTATION:
            return
        await _readmit(env, sender if case.superseded_sender else target, key)
        if case.operation is Operation.NOTICE_COUNT:
            env.matrix_target_identity = await _capture_room_actor(env, target)
        restored = await _probe(env, case, sender, target, phase=2)
        _check(restored, case, target, current=True, phase=2)
        await _assert_send_effect(env, restored, case, sender, target)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", [Operation.MAIL, Operation.CHAT])
@pytest.mark.parametrize("surface", [Surface.HTTP, Surface.MCP])
async def test_address_residence_alone_does_not_admit_a_team_restricted_target(
    pinning,
    operation,
    surface,
):
    env = pinning
    sender = await _admit(env, "restrictedsender")
    target = await _admit(env, "restrictedtarget", global_identity=True)
    configured = await _http(
        env,
        target,
        "PATCH",
        "/v1/agents/me/inbound-mode",
        {"inbound_mode": "team_and_contacts"},
    )
    assert configured.status_code == 200, configured.text
    case = Case(operation, surface, Selector.ADDRESS)
    async with mounted_mcp(
        env.app,
        db_infra=env.infra,
        redis=env.redis,
        registry_client=application_registry_client(env.app.state),
    ):
        before = await _probe(env, case, sender, target, phase=0)
        _check(before, case, target, current=True, phase=0)
        await _assert_send_effect(env, before, case, sender, target)
        key = await _change_key(env)
        await _readmit(env, sender, key)
        effects = await _effect_counts(env)
        refused = await _probe(env, case, sender, target, phase=1)
        if surface is Surface.HTTP:
            assert refused.status_code == 403, refused.text
            data = refused.json()
            detail = data["detail"]
        else:
            data = refused
            detail = data["error"]
        assert data["reason"] == "recipient_policy_rejected", data
        assert (
            "only accepts messages from verified team members or exact active contacts"
            in detail
        )
        assert await _effect_counts(env) == effects
