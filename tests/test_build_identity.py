from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from library.api import create_app
from library.build_identity import resolve_build_identity, resolve_render_deployment_identity
from library.config import Settings

_SHA_A = "a" * 40
_SHA_B = "b" * 40


_RENDER_DEPLOYMENT_ENV = {
    "RENDER_SERVICE_ID": "srv-d8qm4jvavr4c73dhrmgg",
    "RENDER_SERVICE_NAME": "library",
    "RENDER_EXTERNAL_HOSTNAME": "library-02jf.onrender.com",
    "RENDER_GIT_REPO_SLUG": "awebai/library",
    "RENDER_GIT_BRANCH": "main",
    "RENDER_GIT_COMMIT": _SHA_A,
}


def _clear_build_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*_RENDER_DEPLOYMENT_ENV, "RENDER_REGION", "RENDER_API_KEY", "LIBRARY_GIT_SHA"):
        monkeypatch.delenv(name, raising=False)


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


def test_health_reports_automatic_render_deployment_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_build_environment(monkeypatch)
    for name, value in _RENDER_DEPLOYMENT_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("RENDER_REGION", "oregon")
    monkeypatch.setenv("RENDER_API_KEY", "must-not-be-public")

    response = TestClient(
        create_app(Settings(public_origin="https://library.aweb.ai"))
    ).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "library",
        "build": {"git_sha": _SHA_A},
        "deployment": {
            "service_id": "srv-d8qm4jvavr4c73dhrmgg",
            "service_name": "library",
            "hostname": "library-02jf.onrender.com",
            "origin_url": "https://library-02jf.onrender.com",
            "repo": "awebai/library",
            "branch": "main",
            "commit": _SHA_A,
        },
    }


def test_render_deployment_identity_rejects_partial_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_build_environment(monkeypatch)
    monkeypatch.setenv("RENDER_SERVICE_ID", "srv-d8qm4jvavr4c73dhrmgg")

    with pytest.raises(ValueError, match="missing automatic Render metadata"):
        resolve_render_deployment_identity()


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
