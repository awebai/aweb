"""OAuth2 client-credentials secrets (§7.5): the broker exchanges the client
credentials at the owner-set token endpoint through the egress guard, caches
the access token for its lifetime less 60 s, and injects it as a bearer."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus

import pytest
from aweb_naapp.egress import EgressRefused

from aweb_secrets.broker import TokenExchangeFailed, broker

from .harness import OTHER, Upstream, running_upstream


class MemoryTokens:
    """A token cache on an injected clock. The sealed store is custody's."""

    def __init__(self, now=lambda: datetime.now(UTC)) -> None:
        self.now = now
        self.tokens: dict[str, tuple[str, datetime]] = {}

    async def get(self, key: str) -> str | None:
        entry = self.tokens.get(key)
        if entry is None or entry[1] <= self.now():
            return None
        return entry[0]

    async def put(self, key: str, token: str, expires_at: datetime) -> None:
        self.tokens[key] = (token, expires_at)


def _kind_params(upstream: Upstream, client_auth: str = "client_secret_basic", **change: str) -> dict:
    return {
        "token_endpoint": upstream.url("/oauth2/token"),
        "client_auth": client_auth,
        "scope": upstream.creds.oauth_scope,
        **change,
    }


async def _call(upstream: Upstream, tokens: MemoryTokens, *, secret: str | None = None, **kw):
    return await broker(
        upstream.egress,
        method="GET",
        url=upstream.url("/oauth2/echo"),
        destination=upstream.destination(),
        headers=[],
        body=b"",
        kind="oauth2-client-credentials",
        value={
            "client_id": upstream.creds.oauth_client_id,
            "client_secret": secret or upstream.creds.oauth_client_secret,
        },
        kind_params=kw.pop("kind_params", None) or _kind_params(upstream),
        secret_ref="oauth-test",
        max_bytes=4096,
        projection=None,
        token_issuing=False,
        token_destination=kw.pop("token_destination", None)
        or upstream.destination(path="/oauth2/token", methods=["POST"]),
        tokens=tokens,
        token_key="oauth-test@1",
    )


@pytest.mark.parametrize("client_auth", ["client_secret_basic", "client_secret_post"])
async def test_the_exchanged_token_verifies_at_the_upstream(tmp_path: Path, client_auth: str) -> None:
    async with running_upstream(tmp_path) as upstream:
        call = await _call(upstream, MemoryTokens(), kind_params=_kind_params(upstream, client_auth))
        assert call.result.status == 200, call.result.body
        assert json.loads(call.result.body)["scheme"] == "oauth2-client-credentials"


async def test_the_token_is_cached_and_not_exchanged_again(tmp_path: Path) -> None:
    async with running_upstream(tmp_path) as upstream:
        tokens = MemoryTokens()
        for _ in range(3):
            assert (await _call(upstream, tokens)).result.status == 200
        assert upstream.issued() == 1


async def test_a_token_is_cached_for_its_lifetime_less_sixty_seconds(tmp_path: Path) -> None:
    async with running_upstream(tmp_path, token_lifetime_seconds=600) as upstream:
        tokens = MemoryTokens()
        await _call(upstream, tokens)
        (_, expires_at) = tokens.tokens["oauth-test@1"]
        assert timedelta(seconds=535) < expires_at - datetime.now(UTC) <= timedelta(seconds=540)


async def test_a_token_that_lives_sixty_seconds_or_less_is_not_cached(tmp_path: Path) -> None:
    async with running_upstream(tmp_path, token_lifetime_seconds=60) as upstream:
        tokens = MemoryTokens()
        await _call(upstream, tokens)
        await _call(upstream, tokens)
        assert tokens.tokens == {}
        assert upstream.issued() == 2


async def test_an_expired_cached_token_is_exchanged_again(tmp_path: Path) -> None:
    async with running_upstream(tmp_path) as upstream:
        clock = [datetime.now(UTC)]
        tokens = MemoryTokens(now=lambda: clock[0])
        await _call(upstream, tokens)
        clock[0] += timedelta(hours=1)
        assert (await _call(upstream, tokens)).result.status == 200
        assert upstream.issued() == 2


async def test_a_wrong_client_secret_fails_before_the_target_is_called(tmp_path: Path) -> None:
    async with running_upstream(tmp_path) as upstream:
        with pytest.raises(TokenExchangeFailed):
            await _call(upstream, MemoryTokens(), secret="wrong-client-secret")
        assert upstream.paths == ["/oauth2/token"]


async def test_a_token_endpoint_outside_its_destination_sends_nothing(tmp_path: Path) -> None:
    async with running_upstream(tmp_path) as upstream:
        params = _kind_params(upstream, token_endpoint=upstream.url("/oauth2/token", name=OTHER))
        with pytest.raises(EgressRefused) as refused:
            await _call(upstream, MemoryTokens(), kind_params=params)
        assert refused.value.code == "destination_not_in_scope"
        assert upstream.paths == []


async def test_the_token_and_the_client_secret_are_known_values(tmp_path: Path) -> None:
    async with running_upstream(tmp_path) as upstream:
        tokens = MemoryTokens()
        call = await _call(upstream, tokens)
        token = tokens.tokens["oauth-test@1"][0]
        for value in (token, upstream.creds.oauth_client_secret):
            assert call.known.redact(value.encode()) == (b"[REDACTED:oauth-test]", 1)


@pytest.mark.parametrize("missing", ["token_endpoint", "client_auth", "scope"])
async def test_a_secret_without_its_owner_set_parameter_is_refused(tmp_path: Path, missing: str) -> None:
    async with running_upstream(tmp_path) as upstream:
        params = {k: v for k, v in _kind_params(upstream).items() if k != missing}
        with pytest.raises(ValueError):
            await _call(upstream, MemoryTokens(), kind_params=params)
        assert upstream.paths == []



async def test_the_form_encoded_client_pair_is_a_known_value(tmp_path: Path) -> None:
    async with running_upstream(tmp_path) as upstream:
        call = await _call(upstream, MemoryTokens())
        pair = f"{quote_plus(upstream.creds.oauth_client_id)}:{quote_plus(upstream.creds.oauth_client_secret)}"
        header_value = base64.b64encode(pair.encode())
        assert call.known.redact(header_value) == (b"[REDACTED:oauth-test]", 1)
