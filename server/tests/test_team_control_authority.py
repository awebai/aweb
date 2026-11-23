"""Pure request boundaries and an actual unreachable registry, without a DB."""

import socket
from contextlib import aclosing, asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest
from aweb.api import create_app
from aweb.service_errors import ServiceError
from aweb.team_control_authority import (
    TeamControlAuthorityContext,
    TeamControlAuthorityUnavailable,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
    read_fresh_team_controller,
    require_canonical_team_control_scope,
    require_fresh_team_control_request,
)
from aweb.team_control_error_transport import install_team_control_error_handlers
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pgdbm import AsyncDatabaseManager, DatabaseConfig
from starlette.responses import JSONResponse


@pytest.mark.parametrize(
    "timestamp",
    [
        "",
        "invalid",
        "2026-11-19T00:00:00",
        "1990-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
    ],
)
def test_invalid_or_stale_team_control_request_requires_a_new_signature(timestamp):
    with pytest.raises(TeamControlRequestInvalid) as refusal:
        require_fresh_team_control_request(timestamp=timestamp)
    assert refusal.value.status_code == 422
    assert refusal.value.reason is TeamControlRequestReason.TIMESTAMP_INVALID
    assert refusal.value.message == (
        "The signed team-control request is invalid or expired. "
        "Regenerate the controller-signed command and retry."
    )
    assert refusal.value.__cause__ is not None


@pytest.mark.parametrize("zone", [timezone.utc, timezone(timedelta(hours=3))])
def test_current_zoned_team_control_request_keeps_its_signed_timestamp(zone):
    timestamp = datetime.now(zone).isoformat()
    require_fresh_team_control_request(timestamp=timestamp)


@pytest.mark.parametrize(
    "team_id", ["operators", "Operators:local", "operators:local."]
)
def test_team_control_scope_is_exact_and_canonical(team_id):
    with pytest.raises(TeamControlRequestInvalid) as refusal:
        require_canonical_team_control_scope(team_id)
    assert refusal.value.reason is TeamControlRequestReason.TEAM_SCOPE_INVALID
    assert refusal.value.message == (
        "The team-control request must name its canonical team. "
        "Select the exact team and regenerate the controller-signed command."
    )


def test_canonical_team_control_scope_has_no_member_authority():
    assert require_canonical_team_control_scope("operators:local") == (
        "local",
        "operators",
    )


@asynccontextmanager
async def unreachable_context():
    # A real unconnected manager makes an accidental projection/pin read fail;
    # acquisition must stop at the actual refused TCP connection first.
    db = AsyncDatabaseManager(
        DatabaseConfig(connection_string="postgresql://unused/test")
    )
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{reserved.getsockname()[1]}"
        async with aclosing(
            RegistryClient(registry_url=origin, timeout_seconds=0.1)
        ) as sdk:
            context = TeamControlAuthorityContext(
                db=db, registry_client=sdk, txt_resolver=SystemTXTOutcomeResolver()
            )
            yield context


@pytest.mark.asyncio
async def test_unreachable_registry_produces_no_controller_authority():
    async with unreachable_context() as context:
        with pytest.raises(TeamControlAuthorityUnavailable) as refusal:
            await read_fresh_team_controller(context=context, team_id="operators:local")
    assert refusal.value.status_code == 503
    assert refusal.value.code == "team_control_authority_unavailable"
    assert refusal.value.message == (
        "The team's current controller could not be confirmed. "
        "Nothing was imported. Retry when the registry can be read."
    )
    assert refusal.value.__cause__ is not None


async def assert_unavailable_response(app):
    async with unreachable_context() as context:

        @app.post("/controller")
        async def controller():
            await read_fresh_team_controller(context=context, team_id="operators:local")
            pytest.fail("unreachable registry supplied controller authority")

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://native.test"
        ) as client:
            response = await client.post("/controller")
    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": TeamControlAuthorityUnavailable.code,
            "message": (
                "The team's current controller could not be confirmed. "
                "Nothing was imported. Retry when the registry can be read."
            ),
        }
    }


@pytest.mark.asyncio
async def test_native_controller_outage_keeps_retryable503_and_action(caplog):
    await assert_unavailable_response(create_app())
    records = [
        record
        for record in caplog.records
        if record.name == "aweb.team_control_error_transport"
    ]
    assert len(records) == 1
    assert records[0].exc_info is not None
    error = records[0].exc_info[1]
    assert isinstance(error, TeamControlAuthorityUnavailable)
    assert error.__cause__ is not None


@pytest.mark.asyncio
async def test_unusable_registry_answer_keeps_nonretryable422_and_action():
    registry = FastAPI()

    @registry.get("/v1/namespaces/local/teams/operators")
    async def incomplete_team():
        return {"team_id": "operators:local", "domain": "local", "name": "operators"}

    db = AsyncDatabaseManager(
        DatabaseConfig(connection_string="postgresql://unused/test")
    )
    app = create_app()
    async with aclosing(
        RegistryClient(
            registry_url="https://registry.test", transport=ASGITransport(app=registry)
        )
    ) as sdk:
        context = TeamControlAuthorityContext(
            db=db, registry_client=sdk, txt_resolver=SystemTXTOutcomeResolver()
        )

        @app.post("/controller")
        async def controller():
            return await read_fresh_team_controller(
                context=context, team_id="operators:local"
            )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://native.test"
        ) as client:
            response = await client.post("/controller")

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "registry_response_unusable",
            "message": (
                "AWID returned invalid team or certificate data. "
                "Ask the registry operator to correct the team record before importing."
            ),
        }
    }


@pytest.mark.asyncio
async def test_outer_host_keeps_same_expected_controller_error_mapping():
    app = FastAPI()

    @app.exception_handler(ServiceError)
    async def generic(request, error):
        return JSONResponse(status_code=500, content={"detail": "generic"})

    install_team_control_error_handlers(app)
    await assert_unavailable_response(app)


@pytest.mark.asyncio
async def test_unrelated_service503_keeps_native_generic_masking():
    app = create_app()

    @app.get("/unexpected")
    async def unexpected():
        raise ServiceError("internal detail")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://native.test"
    ) as client:
        response = await client.get("/unexpected")
    assert response.status_code == 500
    assert "internal detail" not in response.text
