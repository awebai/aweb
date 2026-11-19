"""Raw-key public methods retain address names as single URL segments.

The wire observer stops before the address request; reassign's prerequisite
identity lookup is served by the real registry. No registry answer is fabricated.
"""

import httpx
import pytest

from awid.did import generate_keypair, did_from_public_key
from awid.registry import RegistryClient, RegistryError
from awid.id_tree_requests import covering_payload
from awid.signing import verify_did_key_signature

pytestmark = pytest.mark.asyncio

NAMES = [
    ("Member_One", "Member_One"),
    ("a/b", "a%2Fb"),
    (".", "%2E"),
    ("..", "%2E%2E"),
    ("a?b#c% d", "a%3Fb%23c%25%20d"),
]


@pytest.mark.parametrize("name,encoded", NAMES)
@pytest.mark.parametrize("operation", ["resolve", "update", "delete", "reassign"])
async def test_raw_key_address_path_keeps_the_exact_name(
    controller_app, name, encoded, operation
):
    env = controller_app
    actual = httpx.ASGITransport(app=env.app, client=env.client._transport.client)
    identity = None
    if operation == "reassign":
        seed, public = generate_keypair()
        setup = RegistryClient(str(env.client.base_url).rstrip("/"), transport=actual)
        try:
            identity = await setup.register_did(did_from_public_key(public), seed)
        finally:
            await setup.aclose()

    class Captured(Exception):
        pass

    sent = []

    class Observe(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.method == "GET" and request.url.path.startswith("/v1/did/"):
                return await actual.handle_async_request(request)
            sent.append(request)
            raise Captured

    sdk = RegistryClient(str(env.client.base_url).rstrip("/"), transport=Observe())
    try:
        with pytest.raises(Captured):
            if operation == "resolve":
                await sdk.resolve_address("local", name)
            elif operation == "reassign":
                await sdk.reassign_address(
                    "local", name, identity.did_aw, env.controller[0]
                )
            else:
                await getattr(sdk, operation + "_address")(
                    "local", name, env.controller[0]
                )
    finally:
        await sdk.aclose()

    assert len(sent) == 1
    outgoing = sent[0]
    suffix = "/reassign" if operation == "reassign" else ""
    assert (
        outgoing.url.raw_path
        == ("/v1/namespaces/local/addresses/" + encoded + suffix).encode()
    )
    assert not outgoing.url.query and not outgoing.url.fragment
    assert (
        outgoing.method
        == {"resolve": "GET", "update": "PUT", "delete": "DELETE", "reassign": "POST"}[
            operation
        ]
    )
    if operation != "resolve":
        # The signature covers the encoded path exactly as sent.
        signed = covering_payload(
            aud=str(env.client.base_url).rstrip("/"),
            method=outgoing.method,
            path=outgoing.url.raw_path.decode(),
            domain="local",
            operation=operation + "_address",
            body=outgoing.content,
            timestamp=outgoing.headers["X-AWEB-Timestamp"],
            claims={"name": name},
        )
        _scheme, did, signature = outgoing.headers["Authorization"].split()
        verify_did_key_signature(did_key=did, payload=signed, signature_b64=signature)


async def test_ordinary_address_round_trips_through_real_registry(controller_app):
    name = "Member_One"
    env = controller_app
    seed, public = generate_keypair()
    sdk = RegistryClient(
        str(env.client.base_url).rstrip("/"),
        transport=httpx.ASGITransport(app=env.app, client=env.client._transport.client),
    )
    try:
        identity = await sdk.register_did(did_from_public_key(public), seed)
        registered = await sdk.register_address(
            "local",
            name,
            identity.did_aw,
            env.controller[0],
            current_did_key=did_from_public_key(public),
        )
        assert registered.name == name
        assert (await sdk.resolve_address("local", name)).name == name
        assert (await sdk.update_address("local", name, env.controller[0])).name == name
        await sdk.delete_address("local", name, env.controller[0])
        assert await sdk.resolve_address("local", name) is None
        assert (await sdk.get_namespace("local")).domain == "local"
    finally:
        await sdk.aclose()


@pytest.mark.parametrize("name", [".", ".."])
async def test_dot_address_lookups_and_deletes_stay_on_address_route(
    controller_app, name
):
    # Persisted address names cannot contain dots. These must be address misses,
    # never a normalized request to the address list or the namespace itself.
    env = controller_app
    sdk = RegistryClient(
        str(env.client.base_url).rstrip("/"),
        transport=httpx.ASGITransport(app=env.app, client=env.client._transport.client),
    )
    try:
        assert await sdk.resolve_address("local", name) is None
        with pytest.raises(RegistryError) as refused:
            await sdk.delete_address("local", name, env.controller[0])
        assert refused.value.status_code == 404
        assert (await sdk.get_namespace("local")).domain == "local"
    finally:
        await sdk.aclose()
