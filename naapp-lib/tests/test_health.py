from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.build_identity import (
    resolve_build_identity,
    resolve_render_deployment_identity,
)
from aweb_naapp.runtime.health import CheckResult, mount_health
from aweb_naapp.runtime.settings import NaappSettings

_SHA_A = "a" * 40
_SHA_B = "b" * 40
_FALLBACK = "EXAMPLE_GIT_SHA"

_RENDER_DEPLOYMENT_ENV = {
    "RENDER_SERVICE_ID": "srv-d8qm4jvavr4c73dhrmgg",
    "RENDER_SERVICE_NAME": "example",
    "RENDER_EXTERNAL_HOSTNAME": "example-02jf.onrender.com",
    "RENDER_GIT_REPO_SLUG": "example/example",
    "RENDER_GIT_BRANCH": "main",
    "RENDER_GIT_COMMIT": _SHA_A,
}


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/example"
    public_origin: str = "https://example.test"
    app_id: str = "example"


@pytest.fixture(autouse=True)
def _clear_build_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*_RENDER_DEPLOYMENT_ENV, "RENDER_REGION", "RENDER_API_KEY", _FALLBACK):
        monkeypatch.delenv(name, raising=False)


def _health(paths: tuple[str, ...] = ("/health",)) -> list[dict]:
    app = FastAPI()
    mount_health(app, ExampleSettings(_env_file=None))
    client = TestClient(app)
    responses = [client.get(path) for path in paths]
    assert all(response.status_code == 200 for response in responses)
    return [response.json() for response in responses]


def test_health_live_and_ready_report_the_app_and_its_build(monkeypatch) -> None:
    monkeypatch.setenv("RENDER_GIT_COMMIT", _SHA_A)
    expected = {"status": "ok", "service": "example", "build": {"git_sha": _SHA_A}}
    assert _health(("/health", "/live", "/ready")) == [expected, expected, expected]


def test_health_uses_the_app_prefixed_build_sha(monkeypatch) -> None:
    monkeypatch.setenv(_FALLBACK, _SHA_B)
    assert _health()[0]["build"] == {"git_sha": _SHA_B}


def test_health_reports_a_null_build_when_none_is_injected() -> None:
    assert _health()[0] == {"status": "ok", "service": "example", "build": {"git_sha": None}}


def test_health_reports_automatic_render_deployment_identity(monkeypatch) -> None:
    for name, value in _RENDER_DEPLOYMENT_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("RENDER_REGION", "oregon")
    monkeypatch.setenv("RENDER_API_KEY", "must-not-be-public")

    assert _health()[0] == {
        "status": "ok",
        "service": "example",
        "build": {"git_sha": _SHA_A},
        "deployment": {
            "service_id": "srv-d8qm4jvavr4c73dhrmgg",
            "service_name": "example",
            "hostname": "example-02jf.onrender.com",
            "origin_url": "https://example-02jf.onrender.com",
            "repo": "example/example",
            "branch": "main",
            "commit": _SHA_A,
        },
    }


def test_mounting_health_refuses_an_invalid_build_identity(monkeypatch) -> None:
    monkeypatch.setenv(_FALLBACK, "not-a-commit")
    with pytest.raises(ValueError):
        mount_health(FastAPI(), ExampleSettings(_env_file=None))


def test_render_deployment_identity_rejects_partial_metadata(monkeypatch) -> None:
    monkeypatch.setenv("RENDER_SERVICE_ID", "srv-d8qm4jvavr4c73dhrmgg")
    with pytest.raises(ValueError):
        resolve_render_deployment_identity()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RENDER_SERVICE_ID", "not-a-service"),
        ("RENDER_EXTERNAL_HOSTNAME", "Not A Host"),
        ("RENDER_GIT_REPO_SLUG", "no-slash"),
        ("RENDER_GIT_COMMIT", "a" * 39),
        ("RENDER_SERVICE_NAME", "bad\x01name"),
    ],
)
def test_render_deployment_identity_rejects_invalid_values(monkeypatch, name, value) -> None:
    for env_name, env_value in _RENDER_DEPLOYMENT_ENV.items():
        monkeypatch.setenv(env_name, env_value)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        resolve_render_deployment_identity()


def test_build_identity_uses_the_validated_fallback(monkeypatch) -> None:
    monkeypatch.setenv(_FALLBACK, _SHA_A)
    assert resolve_build_identity(_FALLBACK) == {"git_sha": _SHA_A}


def test_build_identity_accepts_equal_render_and_fallback_values(monkeypatch) -> None:
    monkeypatch.setenv("RENDER_GIT_COMMIT", _SHA_A)
    monkeypatch.setenv(_FALLBACK, _SHA_A)
    assert resolve_build_identity(_FALLBACK) == {"git_sha": _SHA_A}


def test_build_identity_rejects_conflicting_sources(monkeypatch) -> None:
    monkeypatch.setenv("RENDER_GIT_COMMIT", _SHA_A)
    monkeypatch.setenv(_FALLBACK, _SHA_B)
    with pytest.raises(ValueError):
        resolve_build_identity(_FALLBACK)


@pytest.mark.parametrize(
    ("name", "value"),
    [("RENDER_GIT_COMMIT", "a" * 39), ("RENDER_GIT_COMMIT", "A" * 40), (_FALLBACK, "not-a-commit")],
)
def test_build_identity_rejects_invalid_nonempty_values(monkeypatch, name, value) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        resolve_build_identity(_FALLBACK)


def test_build_identity_is_null_when_no_source_is_injected() -> None:
    assert resolve_build_identity(_FALLBACK) == {"git_sha": None}


# --- Dependency checks --------------------------------------------------------


def _checked(checks: dict) -> TestClient:
    app = FastAPI()
    mount_health(app, ExampleSettings(_env_file=None), checks=checks)
    return TestClient(app)


def _check(ok: bool, **detail: object):
    async def check() -> CheckResult:
        return CheckResult(ok=ok, detail=detail)

    return check


def test_health_and_ready_report_each_check_and_ready_is_200_when_all_pass() -> None:
    client = _checked({"database": _check(True), "queue": _check(True, oldest_age_seconds=None)})
    expected_checks = {"database": {"ok": True}, "queue": {"ok": True, "oldest_age_seconds": None}}
    for path in ("/health", "/ready"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["checks"] == expected_checks


def test_ready_is_503_and_health_reports_unavailable_when_a_check_fails() -> None:
    client = _checked({"database": _check(True), "kms": _check(False)})
    ready = client.get("/ready")
    health = client.get("/health")
    assert ready.status_code == 503
    assert health.status_code == 200
    for response in (ready, health):
        assert response.json()["status"] == "unavailable"
        assert response.json()["checks"]["kms"] == {"ok": False}
        assert response.json()["build"] == {"git_sha": None}


def test_live_runs_no_check() -> None:
    calls: list[str] = []

    async def counted() -> CheckResult:
        calls.append("called")
        return CheckResult(ok=False)

    response = _checked({"kms": counted}).get("/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "example", "build": {"git_sha": None}}
    assert calls == []


def test_a_check_that_raises_fails_without_reporting_the_error(caplog) -> None:
    async def broken() -> CheckResult:
        raise RuntimeError("detail-that-must-not-be-served")

    response = _checked({"kms": broken}).get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["kms"] == {"ok": False}
    assert "detail-that-must-not-be-served" not in response.text
    assert any(record.levelname == "ERROR" for record in caplog.records)


def test_a_check_that_does_not_answer_in_time_fails(monkeypatch) -> None:
    import aweb_naapp.runtime.health as health

    monkeypatch.setattr(health, "HEALTH_CHECK_TIMEOUT_SECONDS", 0.01)

    async def hangs() -> CheckResult:
        await asyncio.sleep(10)
        return CheckResult(ok=True)

    response = _checked({"database": hangs}).get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == {"ok": False}
