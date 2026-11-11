"""The public observer and existing server adapter use the same real registry."""

import subprocess
import sys

import pytest
from aweb.identity_binding import (
    IdentityBinding,
)
from aweb.identity_binding import (
    observe_identity_binding as server_observe,
)
from awid.identity_observation import (
    IdentityObservationRefused,
    observe_identity_binding,
)
from fastapi import HTTPException
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app

__all__ = ["privacy_app"]


def test_public_observation_import_needs_neither_aweb_nor_fastapi():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import awid.identity_observation; "
            'assert "aweb" not in sys.modules; assert "fastapi" not in sys.modules; '
            "from awid import registry, registry_types; "
            "assert all(getattr(registry, n) is getattr(registry_types, n) for n in "
            '("RegistryError", "DIDKeyNotFoundError", "IDTreeEnrollment"))',
        ],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.asyncio
async def test_public_and_server_observation_share_exact_registry_binding(privacy_app):
    env = privacy_app
    actor = env.actors["bob"]
    other = env.actors["alice"]
    async with registry_listener(env) as (client, _):
        registered = await client.register_did(actor.did, actor.sk)
        binding = await observe_identity_binding(
            client, did_key=actor.did, did_aw=registered.did_aw
        )
        adapted = await server_observe(
            client, did_key=actor.did, did_aw=registered.did_aw
        )
        assert isinstance(binding, IdentityBinding)
        assert binding == adapted
        assert binding.did_key == actor.did and binding.did_aw == registered.did_aw
        assert binding.fresh_observation
        with pytest.raises(IdentityObservationRefused) as public_error:
            await observe_identity_binding(
                client, did_key=other.did, did_aw=registered.did_aw
            )
        with pytest.raises(HTTPException) as server_error:
            await server_observe(client, did_key=other.did, did_aw=registered.did_aw)
        assert public_error.value.code == "identity_binding_mismatch"
        assert (server_error.value.status_code, server_error.value.detail) == (
            403,
            "identity_binding_mismatch",
        )


@pytest.mark.asyncio
async def test_public_unavailability_keeps_the_existing_server_503():
    import asyncio

    from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
    from awid.registry import RegistryClient

    # An endpoint owned by this test, then actually stopped: no registry stub.
    listener = await asyncio.start_server(
        lambda reader, writer: writer.close(), "127.0.0.1", 0
    )
    port = listener.sockets[0].getsockname()[1]
    listener.close()
    await listener.wait_closed()
    _, public = generate_keypair()
    key = did_from_public_key(public)
    identity = stable_id_from_did_key(key)
    client = RegistryClient(f"http://127.0.0.1:{port}")
    try:
        with pytest.raises(IdentityObservationRefused) as public_error:
            await observe_identity_binding(client, did_key=key, did_aw=identity)
        with pytest.raises(HTTPException) as server_error:
            await server_observe(client, did_key=key, did_aw=identity)
        assert public_error.value.code == "identity_binding_unavailable"
        assert (server_error.value.status_code, server_error.value.detail) == (
            503,
            "identity_binding_unavailable",
        )
    finally:
        await client.aclose()
