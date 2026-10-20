"""The behaviour every TokenCache implementation must show. Custody's sealed
store runs the same checks, plus its own test that no token is at rest in
plaintext."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from aweb_secrets.tokens import TokenCache, TokenKey

Clock = list[datetime]


def key(**change: object) -> TokenKey:
    values: dict[str, object] = {
        "installation_id": "inst-1",
        "team_id": "backend:example.com",
        "secret_id": "sec-1",
        "version": 1,
        "token_endpoint": "https://auth.example.com/oauth/token",
        "scope": "read:things",
    }
    values.update(change)
    return TokenKey(**values)  # type: ignore[arg-type]


async def check_token_cache_contract(make: Callable[[Clock], TokenCache]) -> None:
    clock: Clock = [datetime(2026, 10, 20, 12, 0, tzinfo=UTC)]
    cache = make(clock)
    later = clock[0] + timedelta(minutes=10)

    await cache.put(key(), "token-a", later)
    assert await cache.get(key()) == "token-a"

    # Any other field of the key is another token.
    for change in (
        {"installation_id": "inst-2"},
        {"team_id": "other:example.com"},
        {"secret_id": "sec-2"},
        {"version": 2},
        {"token_endpoint": "https://auth.example.com/other"},
        {"scope": "write:things"},
    ):
        assert await cache.get(key(**change)) is None, change

    # An expired token is never served.
    clock[0] = later
    assert await cache.get(key()) is None

    # Evicting a secret drops every token of that secret, and only those.
    clock[0] = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    await cache.put(key(), "token-a", later)
    await cache.put(key(version=2), "token-b", later)
    await cache.put(key(secret_id="sec-2"), "token-c", later)
    await cache.put(key(installation_id="inst-2"), "token-d", later)
    assert await cache.evict_secret(installation_id="inst-1", team_id="backend:example.com", secret_id="sec-1") == 2
    assert await cache.get(key()) is None
    assert await cache.get(key(version=2)) is None
    assert await cache.get(key(secret_id="sec-2")) == "token-c"
    assert await cache.get(key(installation_id="inst-2")) == "token-d"
