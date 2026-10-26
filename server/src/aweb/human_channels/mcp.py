"""Opted-in native MCP ingress uses the same public prepare/UoW service."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

from awid.signing import canonical_json_bytes

from aweb.mcp.signing import encrypt_hosted_message, sign_hosted_message
from aweb.mcp.tools.federation import mcp_messaging_auth

from .contract import ContractError
from .http import _HEADERS, _target
from .native import _dto, _hash, _principal


async def send_mcp_native(
    db, auth, *, kind, arguments, hosted_signer, hosted_encryptor
):
    """Called only for requests carrying the complete stable ingress headers.

    Before signing, session insertion or wake: recover the prior result and
    compare the canonical logical tool input. Stable IDs derive from the
    authenticated ingress namespace/key, not timestamps or platform account IDs.
    """
    service = auth.human_channels_service
    if service is None:
        raise ContractError(
            "authority_unavailable", "configured native messaging service"
        )
    if kind == "chat":
        selectors = sum(
            bool((arguments.get(name) or "").strip())
            for name in ("to_alias", "to_did", "to_address")
        )
        if selectors != (0 if arguments.get("session_id") else 1):
            raise ContractError("invalid", "exactly one recipient or session")
    if not arguments.get("plaintext", False) and (
        arguments.get("priority", "normal") != "normal"
        or arguments.get("wait", False)
        or arguments.get("wait_seconds", 120) != 120
        or arguments.get("leaving", False)
        or arguments.get("hang_on", False)
    ):
        raise ContractError("unsupported", "encrypted ingress control metadata")
    caller = mcp_messaging_auth(auth)
    key = _dto(
        "IngressKey",
        {
            "issuer": _principal(caller),
            "namespace": auth.request.headers[_HEADERS[0]],
            "key": auth.request.headers[_HEADERS[1]],
            "input_hash": auth.request.headers[_HEADERS[2]],
        },
    )
    logical_hash = _hash(canonical_json_bytes({"kind": kind, "arguments": arguments}))
    try:
        original = await service.ingress_result(caller, key)
    except ContractError as error:
        if error.code != "not_found":
            raise
    else:
        if original.value["result"].get("logical_input_hash") != logical_hash:
            raise ContractError("replay_conflict", "native MCP input")
        return original.value["result"]["response"]
    to = (
        arguments.get("to", "")
        if kind == "mail"
        else (
            arguments.get("to_alias")
            or arguments.get("to_did")
            or arguments.get("to_address")
            or ""
        )
    )
    cid = (
        arguments.get("conversation_id")
        if kind == "mail"
        else arguments.get("session_id")
    )
    plaintext = arguments.get("plaintext", False)
    message = arguments["body"] if kind == "mail" else arguments["message"]
    if not message.strip() or (bool(to) == bool(cid)):
        raise ContractError("invalid", "recipient/conversation and body")
    if kind == "mail" and arguments.get("priority", "normal") not in (
        "low",
        "normal",
        "high",
        "urgent",
    ):
        raise ContractError("invalid", "priority")
    namespace = canonical_json_bytes(
        {k: key.value[k] for k in ("issuer", "namespace", "key")}
    ).decode()
    mid = str(uuid5(NAMESPACE_URL, "aweb-native-ingress-message:" + namespace))
    payload = SimpleNamespace(
        to_alias=None,
        to_aliases=[],
        to_did=None,
        to_dids=[],
        to_stable_id=None,
        to_agent_id=None,
        to_address=None,
        conversation_id=cid,
    )
    if to:
        if to.startswith("did:"):
            if kind == "mail":
                payload.to_did = to
            else:
                payload.to_dids = [to]
        elif "/" in to:
            raise ContractError("unsupported", "native MCP same-service selector")
        elif kind == "mail":
            payload.to_alias = to
        else:
            payload.to_aliases = [to]
    recipient = await _target(
        auth.request, payload, caller, db, kind, cid if kind == "chat" else None
    )
    if not cid:
        if kind == "mail":
            from aweb.messaging.conversations import (
                find_active_one_to_one_conversation_between,
            )

            existing = await find_active_one_to_one_conversation_between(
                db,
                conversation_type="mail",
                did_a=_principal(caller),
                did_b=recipient["did_aw"] or recipient["did_key"],
            )
            cid = existing["conversation_id"] if existing else None
        else:
            from aweb.messaging.chat import find_session_between

            cid = await find_session_between(
                db,
                did_a=_principal(caller),
                did_b=recipient["did_aw"] or recipient["did_key"],
            )
    cid = (
        str(cid)
        if cid
        else str(uuid5(NAMESPACE_URL, "aweb-native-ingress-conversation:" + namespace))
    )
    target = await service._facts(caller, recipient)
    signed = dict(
        type=kind,
        message_id=mid,
        conversation_id=cid,
        from_did=caller.did_key,
        to=recipient["alias"],
        to_did=recipient["did_key"],
        subject=arguments.get("subject", ""),
        body=message,
        timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **{"from": caller.alias or caller.address or _principal(caller)},
    )
    if caller.did_aw:
        signed["from_stable_id"] = caller.did_aw
    if recipient.get("did_aw"):
        signed["to_stable_id"] = recipient["did_aw"]
    if kind == "mail" and arguments.get("priority", "normal") != "normal":
        signed["priority"] = arguments["priority"]
    if kind == "chat":
        if arguments.get("wait"):
            signed["wait_seconds"] = arguments["wait_seconds"]
        if arguments.get("leaving"):
            signed["sender_leaving"] = True
        if arguments.get("hang_on"):
            signed["hang_on"] = True
    if plaintext:
        protected = await sign_hosted_message(
            auth=auth, signer=hosted_signer, message_type=kind, payload=signed
        )
        if protected is None:
            raise ContractError("authority_unavailable", "native MCP signing custody")
        raw = canonical_json_bytes(
            {
                "signed_payload": protected.signed_payload,
                "signature": protected.signature,
            }
        ).decode()
        fmt = "native_plaintext"
    else:
        protected = await encrypt_hosted_message(
            auth=auth,
            encryptor=hosted_encryptor,
            message_type=kind,
            payload=signed,
            recipient=recipient,
        )
        if protected is None:
            raise ContractError(
                "authority_unavailable", "native MCP encryption custody"
            )
        raw = canonical_json_bytes(protected.encrypted_envelope).decode()
        fmt = "native_encrypted_v2"
    prepared = await service.prepare(
        caller,
        _dto(
            "PrepareRequest",
            {
                "version": "aweb-human-prepare-v1",
                "kind": kind,
                "message_id": mid,
                "author": {"kind": "native", "did": _principal(caller)},
                "envelope": raw,
                "format": fmt,
                "target": target.value,
                "conversation_id": cid,
            },
        ),
    )
    async with service.unit_of_work(caller) as uow:
        previous = await uow.claim_ingress(key)
        if previous is not None:
            if previous.value["result"].get("logical_input_hash") != logical_hash:
                raise ContractError("replay_conflict", "native MCP input")
            return previous.value["result"]["response"]
        accepted = await uow.accept(prepared)
        response = {"message_id": mid, "conversation_id": cid, "status": "delivered"}
        if kind == "chat":
            response.update(session_id=cid, delivered=True)
        else:
            response["to"] = recipient["alias"]
        await uow.finish_ingress(
            _dto(
                "IngressResult",
                {
                    "version": "aweb-ingress-result-v1",
                    "key": key.value,
                    "accepted": accepted.value,
                    "result": {
                        "logical_input_hash": logical_hash,
                        "response": response,
                    },
                },
            )
        )
    # Blocking chat waits belong to the existing read path after commit. This
    # adapter returns the committed send, never holds a UoW while waiting.
    return response
