"""The production constructor starts both origins on a fresh real database."""

import asyncio
import secrets
from ipaddress import ip_address, ip_network

import httpx
import pytest
from aweb_naapp.egress import DnsResolver, EgressRefused, InternalDestinations
from aweb_naapp.key_file import KeyFileError
from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings
from tests.test_app import API, CONSOLE, _settings


async def test_failed_kms_health_keeps_the_selected_custody_mode(
    test_db_factory, registry, tmp_path, monkeypatch
):
    """Real SDK failure at an owned endpoint; this is not an AWS KMS proof."""
    import boto3

    attempts = 0

    async def unavailable(reader, writer):
        nonlocal attempts
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(
                int(line.split(b":", 1)[1])
                for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            await reader.readexactly(length)
            attempts += 1
            writer.write(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(unavailable, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setenv("AWS_ENDPOINT_URL_KMS", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", secrets.token_hex(16))
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secrets.token_hex(32))
    monkeypatch.setenv("AWS_SESSION_TOKEN", secrets.token_hex(32))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # Use the test's synthetic environment, never a previously cached session.
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)
    try:
        database = await test_db_factory.create_db(suffix="secrets_kms_mode")
        with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
            configured = settings(database, tmp_path, smtp).model_copy(
                update={
                    "custody_key_file": None,
                    "kms_key_id": "alias/lab-d2",
                    "kms_region": "us-east-1",
                }
            )
            service = create_service(configured, awid_transport=registry.transport)
            async with service.api_app.router.lifespan_context(service.api_app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                    for origin in (API, CONSOLE):
                        for path in ("/health", "/ready", "/live"):
                            response = await client.get(origin + path)
                            assert response.status_code == (503 if path == "/ready" else 200)
                            assert response.json()["labels"]["custody_mode"] == "kms"
                            if path != "/live":
                                assert response.json()["checks"]["kms"]["ok"] is False
                    assert attempts > 0
    finally:
        server.close()
        await server.wait_closed()


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
    test_db_factory, registry, tmp_path, monkeypatch
):
    monkeypatch.setenv("APP_ENV", "production")
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
                    for origin in (API, CONSOLE):
                        for path in ("/health", "/ready", "/live"):
                            response = await client.get(origin + path)
                            assert response.status_code == 200
                            assert response.json()["labels"]["custody_mode"] == "local_key_file"
                            if path != "/live":
                                assert response.json()["checks"]["kms"]["ok"]
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


async def test_default_hook_guard_adds_deployment_denials_without_broker_network_options(
    test_db_factory, registry, tmp_path
):
    database = await test_db_factory.create_db(suffix="secrets_default_hook_guard")
    with SmtpServer(tmp_path / "smtp") as smtp:
        configured = settings(database, tmp_path, smtp).model_copy(
            update={
                "egress_denied_networks": (ip_network("8.8.8.8/32"),),
                "internal_destinations": InternalDestinations.ALLOWED,
                "egress_ca_file": smtp.ca_file,
            }
        )
        service = create_service(configured, awid_transport=registry.transport)
        transport = service.runtime._hooks.transport
        assert transport is not None
        guard = transport._egress
        assert guard.addresses.internal_destinations is InternalDestinations.DISABLED
        assert isinstance(guard.resolver, DnsResolver)
        assert guard.ca_file is None
        assert guard.user_agent == "aweb-naapp/hooks"
        guard.addresses.check([ip_address("8.8.4.4")])
        for address in ("8.8.8.8", "127.0.0.1", "169.254.169.254", "::ffff:169.254.169.254"):
            with pytest.raises(EgressRefused) as refused:
                guard.addresses.check([ip_address(address)])
            assert refused.value.code == "destination_address_denied"
