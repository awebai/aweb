"""Canonical message DTOs retain the documented embedding callback shapes."""

import json
from collections import OrderedDict
from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from pathlib import Path
from uuid import UUID

import pytest
from aweb import events as existing_transport
from aweb.event_types import MutationEventType, TransportEventType
from aweb.federation.envelope import verify_federation_envelope
from aweb.hooks import fire_mutation_callback
from aweb.identity_auth_deps import MessagingAuth
from aweb.message_events import (
    ChatMessageEvent,
    MessageAcknowledgedEvent,
    ChatMessageSentContext,
    FederatedMessageSentContext,
    MailSentContext,
    MessageAcknowledgedContext,
    MessageDeliveredEvent,
    RoomMessageSentContext,
)
from aweb.messaging.chat_send import _fire_chat_message_sent
from aweb.messaging.kinds import (
    ContentMode,
    MessageKind,
    MessagePriority,
    MessageTransport,
)
from aweb.messaging.runtime import MessagingRuntime
from aweb.routes.messages import SendMessageRequest
from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes
from test_federation_envelope import _envelope, _sign


def test_room_context_exposes_accounting_metadata_without_content():
    context = RoomMessageSentContext(
        team_id="team",
        room_id="room",
        message_id="message",
        from_agent_id="sender",
        from_did="did:key:sender",
        from_did_aw=None,
        from_alias="sender",
    )
    assert context.event_type is MutationEventType.ROOM_MESSAGE_SENT
    assert context.to_context() == {
        "team_id": "team",
        "room_id": "room",
        "message_id": "message",
        "from_agent_id": "sender",
        "from_did": "did:key:sender",
        "from_did_aw": None,
        "from_alias": "sender",
    }


@pytest.mark.parametrize("mode", [*ContentMode, " custom plaintext ", "", None])
@pytest.mark.parametrize("transport", list(MessageTransport))
@pytest.mark.parametrize("alias_container", [list, tuple])
@pytest.mark.asyncio
async def test_chat_context_matches_the_existing_callback(
    mode, transport, alias_container
):
    captured = []

    async def receive(event_type, context):
        captured.append((event_type, context))

    auth = MessagingAuth(did_key="did:key:sender", did_aw=None, address=None)
    runtime = MessagingRuntime(
        registry_client=None,
        federation_authority=None,
        mail_transport=None,
        chat_transport=None,
        public_origin="https://example.test",
        public_origins=frozenset({"https://example.test"}),
        on_mutation=receive,
        agent_wake_publisher=None,
        identity_binding_cache=OrderedDict(),
    )
    session_id = UUID("00000000-0000-0000-0000-000000000001")
    message_id = UUID("00000000-0000-0000-0000-000000000002")
    await _fire_chat_message_sent(
        runtime,
        auth,
        session_id=session_id,
        message_id=message_id,
        from_agent_id=None,
        from_did=auth.did_key,
        to_aliases=["recipient"],
        preview="",
        content_mode=mode.value if isinstance(mode, ContentMode) else mode,
        federated=transport is MessageTransport.FEDERATED,
    )
    aliases = alias_container(["recipient"])
    dto = ChatMessageSentContext(
        team_id=None,
        session_id=str(session_id),
        message_id=str(message_id),
        from_agent_id=None,
        from_alias="",
        from_did=auth.did_key,
        from_did_aw=None,
        to_aliases=aliases,
        preview="",
        content_mode=mode,
        transport=transport,
    )
    expected = {
        "team_id": None,
        "session_id": "00000000-0000-0000-0000-000000000001",
        "conversation_id": "00000000-0000-0000-0000-000000000001",
        "message_id": "00000000-0000-0000-0000-000000000002",
        "from_agent_id": None,
        "from_alias": "",
        "from_did": "did:key:sender",
        "from_did_aw": None,
        "to_aliases": ["recipient"],
        "preview": "",
        "content_mode": "legacy_plaintext_v1"
        if mode is None or mode == ""
        else str(mode),
    }
    if transport is MessageTransport.FEDERATED:
        expected["federated"] = True
    assert captured == [("chat.message_sent", expected)]
    assert type(captured[0][0]) is str
    changed_context = dto.to_context()
    changed_context["to_aliases"].append("someone else")
    assert dto.to_aliases == ("recipient",)
    if isinstance(aliases, list):
        aliases.append("later source mutation")
        assert dto.to_aliases == ("recipient",)


@pytest.mark.parametrize("mode", list(ContentMode))
@pytest.mark.parametrize("transport", list(MessageTransport))
def test_mail_context_preserves_nullable_identity_and_optional_federation(
    mode, transport
):
    dto = MailSentContext(
        team_id=None,
        from_agent_id=None,
        from_did="did:key:sender",
        from_did_aw=None,
        to_agent_id=None,
        from_alias="sender",
        message_id="message",
        conversation_id=None,
        to_alias=None,
        subject="",
        priority=MessagePriority.NORMAL,
        content_mode=mode,
        transport=transport,
    )
    context = json.loads(json.dumps(dto.to_context()))
    assert context == {
        "team_id": None,
        "from_agent_id": None,
        "from_did": "did:key:sender",
        "from_did_aw": None,
        "to_agent_id": None,
        "from_alias": "sender",
        "message_id": "message",
        "conversation_id": None,
        "to_alias": None,
        "subject": "",
        "priority": "normal",
        "content_mode": mode.value,
        **({"federated": True} if transport is MessageTransport.FEDERATED else {}),
    }
    assert dto.event_type is MutationEventType.MAIL_SENT
    with pytest.raises(FrozenInstanceError):
        dto.message_id = "changed"


@pytest.mark.parametrize("kind", [MessageKind.MAIL, MessageKind.CHAT])
@pytest.mark.parametrize("mode", list(ContentMode))
def test_inbound_federation_preserves_its_distinct_documented_context(kind, mode):
    dto = FederatedMessageSentContext(
        kind=kind,
        team_id=None,
        from_did="did:key:sender",
        from_did_aw="did:aw:sender",
        to_agent_id=None,
        from_alias="sender",
        message_id="message",
        conversation_id="conversation",
        to_alias="recipient",
        subject="",
        priority=MessagePriority.NORMAL,
        content_mode=mode,
    )
    context = dto.to_context()
    assert context == {
        "team_id": None,
        "from_agent_id": None,
        "from_did": "did:key:sender",
        "from_did_aw": "did:aw:sender",
        "to_agent_id": None,
        "from_alias": "sender",
        "message_id": "message",
        "conversation_id": "conversation",
        "session_id": "conversation" if kind is MessageKind.CHAT else None,
        "to_alias": "recipient",
        "subject": "",
        "priority": "normal",
        "content_mode": mode.value,
        "federated": True,
    }
    expected_type = (
        MutationEventType.MAIL_SENT
        if kind is MessageKind.MAIL
        else MutationEventType.CHAT_MESSAGE_SENT
    )
    assert dto.event_type is expected_type
    assert "to_aliases" not in context and "preview" not in context
    with pytest.raises(TypeError, match="Pass a MessageKind value for kind"):
        replace(dto, kind=kind.value)
    # Room posts have their own context/event, not a federation message kind.
    with pytest.raises(TypeError, match="Pass a MessageKind value for kind"):
        replace(dto, kind="room")


@pytest.mark.parametrize("mode", list(ContentMode))
@pytest.mark.parametrize("alias,from_alias", [("recipient", "sender"), (None, None)])
def test_acknowledgement_context_retains_the_existing_identity_fields(
    mode, alias, from_alias
):
    dto = MessageAcknowledgedContext(
        team_id=None,
        agent_id=None,
        alias=alias,
        message_id="message",
        from_alias=from_alias,
        subject="",
        content_mode=mode,
    )
    assert dto.event_type is MutationEventType.MAIL_ACKNOWLEDGED
    assert dto.to_context() == {
        "team_id": None,
        "agent_id": None,
        "alias": alias,
        "message_id": "message",
        "from_alias": from_alias,
        "subject": "",
        "content_mode": mode.value,
    }


def test_standard_mutation_vocabulary_covers_the_retained_call_site_inventory():
    root = Path(__file__).resolve().parents[2]
    inventory = json.loads(
        (root / "docs/vectors/mutation-hook-call-sites-v1.json").read_text()
    )
    assert {site["event"] for site in inventory["call_sites"]} <= {
        event.value for event in MutationEventType
    }
    # Known names are constants, not a new callback admission gate.
    assert MutationEventType.MAIL_SENT == "message.sent"
    assert "host.custom_event" != MutationEventType.MAIL_SENT


def test_delivered_transport_event_preserves_the_literal_wire_fields():
    event = MessageDeliveredEvent(
        workspace_id="workspace", content_mode=ContentMode.ENCRYPTED
    )
    assert json.loads(event.to_json())["content_mode"] == "encrypted_v2"
    assert event.type == "message.delivered"


def test_transport_vocabulary_names_every_existing_standard_dto():
    names = set()
    for definition in vars(existing_transport).values():
        if not isinstance(definition, type) or not is_dataclass(definition):
            continue
        for field in fields(definition):
            if (
                field.name == "type"
                and isinstance(field.default, str)
                and field.default
            ):
                names.add(field.default)
                event = definition(
                    **(
                        {"team_id": "team"}
                        if issubclass(definition, existing_transport.TeamEvent)
                        else {"workspace_id": "workspace"}
                    )
                )
                assert type(event.type) is str
                assert json.loads(event.to_json())["type"] == field.default
    assert names == {event.value for event in TransportEventType}


@pytest.mark.asyncio
async def test_known_event_constants_do_not_close_the_host_callback_vocabulary():
    seen = []

    async def receive(name, context):
        seen.append((name, context))

    context = {"host_projection": None, "additive_metadata": {"value": 1}}
    await fire_mutation_callback(receive, "host.custom_event", context)
    assert seen == [("host.custom_event", context)]


@pytest.mark.parametrize(
    "mode", ["legacy_plaintext_v1", "operator-plaintext", "", " Mixed/Mode ", None]
)
def test_mail_context_preserves_content_mode_accepted_by_the_real_request_model(mode):
    request = SendMessageRequest.model_validate(
        {"to_alias": "recipient", "body": "accepted body", "content_mode": mode}
    )
    dto = MailSentContext(
        team_id=None,
        from_agent_id=None,
        from_did="did:key:sender",
        from_did_aw=None,
        to_agent_id=None,
        from_alias="sender",
        message_id="message",
        conversation_id=None,
        to_alias="recipient",
        subject=request.subject,
        priority=MessagePriority.NORMAL,
        content_mode=request.content_mode,
    )
    assert dto.to_context()["content_mode"] == (
        "legacy_plaintext_v1" if mode is None or mode == "" else str(mode)
    )
    if mode == "legacy_plaintext_v1":
        assert dto.content_mode is ContentMode.PLAINTEXT


@pytest.mark.parametrize(
    "priority,mode",
    [
        (" Signed/Priority ", " Received/Plaintext "),
        ("normal", "legacy_plaintext_v1"),
        (None, None),
    ],
)
def test_federation_context_preserves_metadata_accepted_under_a_real_signature(
    priority, mode
):
    signing_key, public_key = generate_keypair()
    envelope = _envelope(did_from_public_key(public_key))
    signed = json.loads(envelope["signed_payload"])
    signed["priority"] = priority
    envelope.update(
        priority=priority,
        content_mode=mode,
        signed_payload=canonical_json_bytes(signed).decode(),
    )
    verified = verify_federation_envelope(envelope, _sign(envelope, signing_key))
    dto = FederatedMessageSentContext(
        kind=MessageKind.MAIL,
        team_id=None,
        from_did=verified.sender_current_did_key,
        from_did_aw=verified.sender_did_aw,
        to_agent_id=None,
        from_alias="sender",
        message_id=verified.message_id,
        conversation_id=verified.conversation_id,
        to_alias="recipient",
        subject=verified.subject,
        priority=verified.priority,
        content_mode=verified.content_mode,
    )
    assert dto.to_context()["priority"] == (
        "normal" if priority is None or priority == "" else str(priority)
    )
    assert dto.to_context()["content_mode"] == (
        "legacy_plaintext_v1" if mode is None or mode == "" else str(mode)
    )
    if priority == "normal":
        assert dto.priority is MessagePriority.NORMAL


def test_acknowledgement_context_preserves_historical_metadata_strings():
    dto = MessageAcknowledgedContext(
        team_id=None,
        agent_id=None,
        alias=None,
        message_id="message",
        from_alias=None,
        subject="",
        content_mode=" Historical/Content ",
    )
    assert dto.to_context()["content_mode"] == " Historical/Content "


def test_transport_exports_reuse_existing_public_dtos_instead_of_a_second_set():
    assert MessageDeliveredEvent is existing_transport.MessageDeliveredEvent
    assert MessageAcknowledgedEvent is existing_transport.MessageAcknowledgedEvent
    assert ChatMessageEvent is existing_transport.ChatMessageEvent
    event = MessageDeliveredEvent(
        workspace_id="workspace", content_mode=ContentMode.ENCRYPTED
    )
    assert json.loads(event.to_json())["content_mode"] == "encrypted_v2"
    assert event.type == TransportEventType.MAIL_DELIVERED
