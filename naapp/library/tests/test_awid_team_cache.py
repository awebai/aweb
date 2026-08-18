from __future__ import annotations

import pytest

from library.auth import AWIDTeamCache
from library.config import Settings


class _Response:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self._payload = payload

    def json(self) -> dict:
        return self._payload


@pytest.mark.asyncio
async def test_private_team_reads_send_configured_service_token_and_page_history(
    monkeypatch,
) -> None:
    token = "library-e2e-service-token-with-at-least-32-bytes"
    seen: list[tuple[str, dict[str, str], dict[str, str | int] | None]] = []

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(
            self, url: str, *, headers: dict[str, str], params: dict[str, str | int] | None = None
        ) -> _Response:
            seen.append((url, headers, params))
            if not url.endswith("/certificates"):
                return _Response({"team_did_key": "did:key:z6Mkhx"})
            if params and params.get("cursor") == "page-2":
                return _Response(
                    {
                        "certificates": [
                            {"certificate_id": "revoked", "revoked_at": "2026-08-18T00:00:00Z"}
                        ],
                        "has_more": False,
                    }
                )
            return _Response({"certificates": [], "has_more": True, "next_cursor": "page-2"})

    monkeypatch.setattr("library.auth.httpx.AsyncClient", lambda **_kwargs: _Client())

    cache = AWIDTeamCache(registry_url="https://awid.test", ttl_seconds=60, service_token=token)
    facts = await cache.get("team:example.test")

    assert facts.revoked_certificate_ids == frozenset({"revoked"})
    assert seen == [
        (
            "https://awid.test/v1/namespaces/example.test/teams/team",
            {"X-AWID-Service-Token": token},
            None,
        ),
        (
            "https://awid.test/v1/namespaces/example.test/teams/team/certificates",
            {"X-AWID-Service-Token": token},
            {"active_only": "false", "limit": 200},
        ),
        (
            "https://awid.test/v1/namespaces/example.test/teams/team/certificates",
            {"X-AWID-Service-Token": token},
            {"active_only": "false", "limit": 200, "cursor": "page-2"},
        ),
    ]


def test_awid_service_token_is_trimmed_and_requires_a_real_secret() -> None:
    token = "library-e2e-service-token-with-at-least-32-bytes"
    assert Settings(awid_service_token=f"  {token}  ").awid_service_token == token
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Settings(awid_service_token="too-short")
