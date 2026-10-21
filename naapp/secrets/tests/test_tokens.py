"""The token cache key and the in-process token cache."""

from __future__ import annotations

from aweb_secrets.tokens import ProcessTokenCache

from .token_cache_contract import check_token_cache_contract, key


def test_the_key_covers_every_field_that_decides_which_token_is_valid() -> None:
    digests = {
        key(**change).digest()
        for change in (
            {},
            {"installation_id": "inst-2"},
            {"team_id": "other:example.com"},
            {"secret_id": "sec-2"},
            {"version": 2},
            {"token_endpoint": "https://auth.example.com/other"},
            {"scope": "write:things"},
        )
    }
    assert len(digests) == 7
    assert key().digest() == key().digest()


def test_the_key_digest_does_not_read_one_field_into_the_next() -> None:
    assert key(secret_id="a", scope="bc").digest() != key(secret_id="ab", scope="c").digest()


async def test_the_process_cache_meets_the_token_cache_contract() -> None:
    await check_token_cache_contract(lambda clock: ProcessTokenCache(now=lambda: clock[0]))
