"""Invalid service inputs get actionable refusals before any dependency use."""

from collections import OrderedDict

import pytest

from aweb.identity_auth_deps import MessagingAuth
from aweb.messaging.mail_models import SendMessageRequest
from aweb.messaging.mail_send import resolve_mail_target
from aweb.messaging.refusals import DeliveryRefusal
from aweb.messaging.runtime import MessagingRuntime


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "did,selectors,status,detail",
    [
        (
            "",
            {},
            401,
            "Authenticated identity is missing a routing DID. Reconnect with your current identity credentials and retry.",
        ),
        (
            "did:key:sender",
            {},
            422,
            "Must provide to_did, to_address, to_agent_id, or to_alias. Choose a recipient and retry.",
        ),
        (
            "did:key:sender",
            {"to_address": "missing-domain"},
            422,
            "to_address must be domain/name. Use a domain/name address and retry.",
        ),
    ],
)
async def test_mail_target_refuses_invalid_input_before_database_or_registry(
    did,
    selectors,
    status,
    detail,
):
    runtime = MessagingRuntime(
        registry_client=None,
        federation_authority=None,
        mail_transport=None,
        chat_transport=None,
        public_origin="",
        public_origins=frozenset(),
        on_mutation=None,
        agent_wake_publisher=None,
        identity_binding_cache=OrderedDict(),
        first_contact_sender_policy=None,
    )
    with pytest.raises(DeliveryRefusal) as refused:
        await resolve_mail_target(
            None,
            MessagingAuth(did_key=did, did_aw=None, address=None),
            SendMessageRequest(body="Invalid selection", **selectors),
            runtime,
            source="127.0.0.1",
        )
    assert refused.value.status_code == status
    assert refused.value.detail == detail
