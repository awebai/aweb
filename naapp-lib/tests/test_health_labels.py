"""Static deployment identity stays separate from live dependency checks."""

from enum import StrEnum

import httpx
import pytest
from fastapi import FastAPI

from aweb_naapp.runtime.health import CheckResult, mount_health
from aweb_naapp.runtime.settings import NaappSettings


class ExampleMode(StrEnum):
    LOCAL = "local_key_file"
    KMS = "kms"


def settings():
    return NaappSettings(
        _env_file=None,
        database_url="postgresql://localhost/unused",
        public_origin="https://health.example",
        app_id="health-example",
    )


@pytest.mark.parametrize("ok", [True, False])
async def test_static_enum_labels_are_independent_of_check_availability(ok):
    async def dependency():
        return CheckResult(ok=ok)

    labels = {"custody_mode": ExampleMode.LOCAL}
    app = FastAPI()
    mount_health(app, settings(), checks={"custody": dependency}, labels=labels)
    labels["custody_mode"] = ExampleMode.KMS
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://health.example"
    ) as client:
        for path in ("/health", "/ready", "/live"):
            response = await client.get(path)
            assert response.status_code == (503 if path == "/ready" and not ok else 200)
            assert response.json()["labels"] == {"custody_mode": "local_key_file"}
            if path != "/live":
                assert response.json()["checks"]["custody"]["ok"] is ok


@pytest.mark.parametrize("value", ["local_key_file", True, None, 1, object()])
def test_health_labels_refuse_values_that_are_not_declared_enum_members(value):
    with pytest.raises(TypeError):
        mount_health(FastAPI(), settings(), labels={"custody_mode": value})
