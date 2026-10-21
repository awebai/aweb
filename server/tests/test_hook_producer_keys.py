"""The core hook producer's public keys: their configuration and the anonymous read."""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from aweb.config import get_hook_producer_keys, get_settings
from aweb.routes.app_hooks import router as app_hooks_router

PRODUCER_KEYS_PATH = "/v1/hooks/producer-keys"


def _did(start: int) -> str:
    seed = bytes((start + i) % 256 for i in range(32))
    return did_from_public_key(bytes(SigningKey(seed).verify_key))


RETIRED = {
    "kid": "hook-2026-09",
    "did_key": _did(0x10),
    "valid_from": "2026-09-01T00:00:00Z",
    "valid_until": "2026-10-01T00:00:00Z",
}
CURRENT = {
    "kid": "hook-2026-10",
    "did_key": _did(0x30),
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_until": None,
}


def _configure(monkeypatch: pytest.MonkeyPatch, keys: object) -> None:
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps(keys))


def test_no_configured_keys_is_an_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KEYS", raising=False)
    assert get_hook_producer_keys() == ()


def test_configured_keys_keep_retired_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, [RETIRED, CURRENT])
    keys = get_hook_producer_keys()
    assert [key.kid for key in keys] == ["hook-2026-09", "hook-2026-10"]
    assert keys[1].valid_until is None


@pytest.mark.parametrize(
    "keys",
    [
        "not a list",
        [{**CURRENT, "note": "x"}],
        [{k: v for k, v in CURRENT.items() if k != "valid_until"}],
        [{k: v for k, v in CURRENT.items() if k != "did_key"}],
        [CURRENT, {**RETIRED, "kid": CURRENT["kid"]}],
        [{**CURRENT, "kid": ""}],
        [{**CURRENT, "kid": 7}],
        [{**CURRENT, "did_key": "did:key:zNotAKey"}],
        [{**CURRENT, "valid_from": "2026-10-01T00:00:00.000Z"}],
        [{**CURRENT, "valid_from": "2026-10-01 00:00:00Z"}],
        [{**CURRENT, "valid_from": "2026-10-0１T00:00:00Z"}],
        [{**CURRENT, "valid_from": "2026-02-30T00:00:00Z"}],
        [{**RETIRED, "valid_until": RETIRED["valid_from"]}],
        [{**RETIRED, "valid_until": "2026-08-01T00:00:00Z"}],
    ],
)
def test_a_malformed_key_list_is_refused(monkeypatch: pytest.MonkeyPatch, keys: object) -> None:
    _configure(monkeypatch, keys)
    with pytest.raises(ValueError):
        get_hook_producer_keys()


def test_the_server_does_not_start_with_a_malformed_key_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://localhost/aweb")
    monkeypatch.setenv("AWID_SERVICE_TOKEN", "0" * 64)
    _configure(monkeypatch, [CURRENT])
    assert get_settings().hook_producer_keys == get_hook_producer_keys()
    _configure(monkeypatch, [CURRENT, CURRENT])
    with pytest.raises(ValueError):
        get_settings()


def test_a_key_list_that_is_not_json_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", "[{")
    with pytest.raises(ValueError):
        get_hook_producer_keys()


async def _get(path: str, headers: dict[str, str] | None = None):
    app = FastAPI()
    app.include_router(app_hooks_router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path, headers=headers or {})


@pytest.mark.asyncio
async def test_anyone_can_read_the_producer_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, [RETIRED, CURRENT])
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", "30")
    response = await _get(PRODUCER_KEYS_PATH)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["keys"] == [RETIRED, CURRENT]
    assert body["max_age_seconds"] == 30
    assert set(body) == {"keys", "as_of", "max_age_seconds"}


@pytest.mark.asyncio
async def test_the_producer_keys_read_takes_no_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, [CURRENT])
    response = await _get(PRODUCER_KEYS_PATH, {"Authorization": "AWEB-App-Hook-Resolve DIDKey x y"})
    assert response.status_code == 200, response.text
    assert response.json()["keys"] == [CURRENT]
