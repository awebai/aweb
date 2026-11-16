"""The same covering identity request aw sends, with real Ed25519 signatures."""

import base64
from datetime import datetime, timezone
import hashlib

from fastapi import HTTPException
import pytest
from starlette.requests import Request

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from aweb_key_holder.auth import authenticate


@pytest.fixture
def signed():
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    identity = stable_id_from_did_key(key)
    timestamp = datetime.now(timezone.utc).isoformat()
    body = b'{"person":"second"}'
    payload = {
        "v": 2,
        "did_aw": identity,
        "aud": "https://holder.example",
        "method": "POST",
        "path": "/v1/humans",
        "timestamp": timestamp,
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    return seed, key, body, payload


def request(
    signed, *, audience=None, path=None, body=None, identity=None, legacy=False
):
    seed, key, original, payload = signed
    wire = canonical_json_bytes({**payload, **({"aud": audience} if audience else {})})
    headers = [
        (b"authorization", f"DIDKey {key} {sign_message(seed, wire)}".encode()),
        (b"x-aweb-did-aw", (identity or payload["did_aw"]).encode()),
        (b"x-aweb-timestamp", payload["timestamp"].encode()),
    ]
    if not legacy:
        headers.append(
            (b"x-aweb-signed-payload", base64.urlsafe_b64encode(wire).rstrip(b"="))
        )

    async def receive():
        return {"type": "http.request", "body": original if body is None else body}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": path or payload["path"],
            "raw_path": (path or payload["path"]).encode(),
            "headers": headers,
            "query_string": b"",
        },
        receive,
    )


@pytest.mark.asyncio
async def test_current_covering_identity_key_is_the_requester(signed):
    caller = await authenticate(request(signed), origin="https://holder.example")
    assert caller.descriptor == {
        "kind": "identity",
        "id": signed[3]["did_aw"],
        "key": signed[1],
    }
    assert caller.body == signed[2]


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["audience", "path", "body", "identity", "legacy"])
async def test_foreign_destination_changed_request_and_legacy_do_not_authenticate(
    signed, change
):
    changes = {
        "audience": "https://other-holder.example",
        "path": "/elsewhere",
        "body": b'{"person":"other"}',
        "identity": "did:aw:other",
        "legacy": True,
    }
    with pytest.raises(HTTPException) as refused:
        await authenticate(
            request(signed, **{change: changes[change]}),
            origin="https://holder.example",
        )
    assert refused.value.status_code == 401
