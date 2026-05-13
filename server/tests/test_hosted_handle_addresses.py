from __future__ import annotations

from pydantic import ValidationError

from aweb.messaging.handle_addresses import normalize_hosted_handle_reference
from aweb.routes.chat import CreateSessionRequest
from aweb.routes.messages import SendMessageRequest


def test_normalize_hosted_handle_reference_contract():
    assert normalize_hosted_handle_reference("@jane/c3po", require_agent=True) == "jane.aweb.ai/c3po"
    assert normalize_hosted_handle_reference("@acme.com/c3po", require_agent=True) == "acme.com/c3po"
    assert normalize_hosted_handle_reference("@Jane/C3PO", require_agent=True) == "jane.aweb.ai/C3PO"
    assert normalize_hosted_handle_reference("@jane") == "jane.aweb.ai"
    assert normalize_hosted_handle_reference("@jane", require_agent=True) == "@jane"
    assert normalize_hosted_handle_reference("@") == "@"
    assert normalize_hosted_handle_reference("@jane/", require_agent=True) == "@jane/"
    assert normalize_hosted_handle_reference("@jane/c3po/extra", require_agent=True) == "@jane/c3po/extra"
    assert normalize_hosted_handle_reference("@jane..aweb.ai/c3po", require_agent=True) == "@jane..aweb.ai/c3po"
    assert normalize_hosted_handle_reference("@.jane/c3po", require_agent=True) == "@.jane/c3po"


def test_mail_request_normalizes_hosted_handle_target_fields():
    alias_payload = SendMessageRequest(to_alias="@jane/c3po", subject="", body="hello")
    assert alias_payload.to_alias is None
    assert alias_payload.to_address == "jane.aweb.ai/c3po"

    address_payload = SendMessageRequest(to_address="@jane/c3po", subject="", body="hello")
    assert address_payload.to_address == "jane.aweb.ai/c3po"

    for value in ["@jane..aweb.ai/c3po", "@.jane/c3po", "@jane/"]:
        try:
            SendMessageRequest(to_address=value, subject="", body="hello")
        except ValidationError:
            pass
        else:
            raise AssertionError(f"{value!r} should be rejected as an invalid hosted handle address")


def test_chat_request_normalizes_hosted_handle_target_fields():
    alias_payload = CreateSessionRequest(to_aliases=["@jane/c3po"], message="hello")
    assert alias_payload.to_aliases == []
    assert alias_payload.to_addresses == ["jane.aweb.ai/c3po"]

    address_payload = CreateSessionRequest(to_addresses=["@jane/c3po"], message="hello")
    assert address_payload.to_addresses == ["jane.aweb.ai/c3po"]

    for value in ["@jane..aweb.ai/c3po", "@.jane/c3po", "@jane/"]:
        try:
            CreateSessionRequest(to_addresses=[value], message="hello")
        except ValidationError:
            pass
        else:
            raise AssertionError(f"{value!r} should be rejected as an invalid hosted handle address")
