"""The production constructor starts both origins on a fresh real database."""

import secrets

import httpx
import pytest
from aweb_naapp.key_file import KeyFileError
from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings
from tests.test_app import API, CONSOLE, _settings


def settings(database, directory, smtp):
    paths = {}
    for name in (
        "custody_key_file",
        "secret_request_key_file",
        "secret_params_key_file",
        "response_key_file",
        "runner_service_key_file",
    ):
        path = directory / name
        path.write_text(secrets.token_hex(32), encoding="ascii")
        path.chmod(0o600)
        paths[name] = path
    password = directory / "smtp-password"
    password.write_text(smtp.password, encoding="utf-8")
    password.chmod(0o600)
    return ServiceSettings(
        _env_file=None,
        **_settings(database.config.get_dsn(), directory / "app-keys").model_dump(),
        **paths,
        email_smtp_host="localhost",
        email_smtp_port=smtp.port,
        email_username=smtp.username,
        email_password_file=password,
        email_from="noreply@secrets.test",
        email_ca_file=smtp.ca_file,
    )


async def test_production_startup_prepares_every_store_before_serving_and_cleans_up(
    test_db_factory, registry, tmp_path
):
    database = await test_db_factory.create_db(suffix="secrets_production_root")
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        service = create_service(
            settings(database, tmp_path, smtp), awid_transport=registry.transport
        )
        for _ in range(2):
            async with service.api_app.router.lifespan_context(service.api_app):
                db = service.runtime.db()
                for table in (
                    "approvals",
                    "passkey_approvers",
                    "console_sessions",
                    "credential_authorizations",
                    "credential_contact_candidates",
                    "credential_narrowing_authority",
                    "change_sets",
                    "job_definitions",
                    "runners",
                    "use_contexts",
                    "run_contexts",
                ):
                    assert await db.fetch_value("SELECT to_regclass($1) IS NOT NULL", table), table
                assert await db.fetch_value("SELECT count(*) FROM installation_fences") == 0
                async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                    assert (await client.get(CONSOLE + "/enrolment")).status_code == 200
                    assert (await client.get(CONSOLE + "/contact-proof")).status_code == 200
                    assert (await client.get(API + "/enrolment")).status_code == 404
                    assert (await client.get(API + "/v1/secrets")).status_code == 401
                    home = await client.get(CONSOLE + "/")
                    assert home.status_code == 303 and home.headers["location"] == "/login"
                    health = await client.get(API + "/health")
                    assert health.status_code == 200
                    assert health.json()["checks"]["kms"]["ok"]
            assert service.runtime.connected_db() is None
            async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                assert (await client.get(CONSOLE + "/enrolment")).status_code == 404


async def test_missing_required_custody_key_refuses_the_production_constructor(
    test_db_factory, registry, tmp_path
):
    database = await test_db_factory.create_db(suffix="secrets_production_missing_key")
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        configured = settings(database, tmp_path, smtp)
        configured.custody_key_file.unlink()
        with pytest.raises(KeyFileError):
            create_service(configured, awid_transport=registry.transport)


async def test_request_response_and_runner_keys_require_independent_material(
    test_db_factory, registry, tmp_path
):
    database = await test_db_factory.create_db(suffix="secrets_production_reused_key")
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        configured = settings(database, tmp_path, smtp)
        # Different file paths must not conceal reuse of the same key material.
        configured.response_key_file.write_bytes(configured.secret_request_key_file.read_bytes())
        with pytest.raises(ValueError, match="independent"):
            create_service(configured, awid_transport=registry.transport)
