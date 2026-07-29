from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from library.api import create_app
from library.build_identity import resolve_build_identity
from library.config import Settings

_SHA_A = "a" * 40
_SHA_B = "b" * 40


def _clear_build_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    monkeypatch.delenv("LIBRARY_GIT_SHA", raising=False)


def test_health_reports_render_build_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_build_environment(monkeypatch)
    monkeypatch.setenv("RENDER_GIT_COMMIT", _SHA_A)

    response = TestClient(
        create_app(Settings(public_origin="https://library.aweb.ai"))
    ).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "library",
        "build": {"git_sha": _SHA_A},
    }


def test_build_identity_uses_validated_non_render_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_build_environment(monkeypatch)
    monkeypatch.setenv("LIBRARY_GIT_SHA", _SHA_A)

    assert resolve_build_identity() == {"git_sha": _SHA_A}


def test_build_identity_accepts_equal_render_and_fallback_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_build_environment(monkeypatch)
    monkeypatch.setenv("RENDER_GIT_COMMIT", _SHA_A)
    monkeypatch.setenv("LIBRARY_GIT_SHA", _SHA_A)

    assert resolve_build_identity() == {"git_sha": _SHA_A}


def test_build_identity_rejects_conflicting_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_build_environment(monkeypatch)
    monkeypatch.setenv("RENDER_GIT_COMMIT", _SHA_A)
    monkeypatch.setenv("LIBRARY_GIT_SHA", _SHA_B)

    with pytest.raises(ValueError, match="conflict"):
        resolve_build_identity()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RENDER_GIT_COMMIT", "a" * 39),
        ("RENDER_GIT_COMMIT", "A" * 40),
        ("LIBRARY_GIT_SHA", "not-a-commit"),
    ],
)
def test_build_identity_rejects_invalid_nonempty_values(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    _clear_build_environment(monkeypatch)
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match="full lowercase 40-character Git SHA"):
        resolve_build_identity()


def test_build_identity_is_null_when_no_source_is_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_build_environment(monkeypatch)

    assert resolve_build_identity() == {"git_sha": None}
