from __future__ import annotations

import httpx

from aweb import cli


def test_handle_api_call_does_not_inject_legacy_api_key(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_get(url: str, *, timeout: int, headers: dict[str, str], **kwargs):
        captured["url"] = url
        captured["headers"] = dict(headers)
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setenv("AWEB_API_KEY", "aw_sk_legacy_should_not_be_used")
    monkeypatch.setattr(cli.httpx, "get", _fake_get)

    response = cli._handle_api_call("GET", "http://example.test/v1/status")

    assert response.status_code == 200
    assert captured["url"] == "http://example.test/v1/status"
    assert "Authorization" not in captured["headers"]
