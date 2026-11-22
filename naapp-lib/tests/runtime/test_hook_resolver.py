"""HookResolver behaviour that needs no aweb answer.

Everything that reads an answer is tested against the real server's routes in
server/tests/test_hook_resolver.py.
"""

from __future__ import annotations

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, HOOK_RESOLVE, AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.runtime.hook_resolver import HookResolver
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_server import TeamServerDirectory


def _signer(purpose: str) -> AppCredentialSigner:
    key = SigningKey.generate()
    app_key = AppKey(kid="k1", did_key=did_from_public_key(bytes(key.verify_key)), signing_key=key)
    return AppCredentialSigner(app_id="logs", key=app_key, purpose=purpose)


def _directory() -> TeamServerDirectory:
    return TeamServerDirectory(
        team_cache=AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60)
    )


def test_hook_resolution_signs_only_with_a_hook_resolve_key() -> None:
    with pytest.raises(ValueError):
        HookResolver(
            directory=_directory(),
            signer=_signer(APP_GRANT_READ),
            app_origin="https://logs.example",
        )
    HookResolver(
        directory=_directory(), signer=_signer(HOOK_RESOLVE), app_origin="https://logs.example"
    )


async def test_own_bindings_are_selected_by_exactly_one_of_id_or_hook() -> None:
    resolver = HookResolver(
        directory=_directory(), signer=_signer(HOOK_RESOLVE), app_origin="https://logs.example"
    )
    with pytest.raises(ValueError):
        await resolver.own_bindings("backend:acme.com")
