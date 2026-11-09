"""Actual Logs ingest root on the existing owned S19 TLS serving boundary."""

import json
import secrets
import ssl
from contextlib import asynccontextmanager

import httpx
from aweb_logs import MANIFEST_PATH
from aweb_logs.app import create_app
from aweb_logs.config import LogsSettings
from aweb_naapp.email import EmailSettings
from aweb_naapp_testing.smtp import SmtpServer
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from service_server import Listener, serving


@asynccontextmanager
async def logs_receiver(test_db_factory, registry, transport, directory, host, name, certificates):
    """One real app/lifespan; caller keeps DNS and authority alive until teardown.

    Logs mails reader enrolment links through a real TLS SMTP server that lives
    as long as the root does.

    Installation and owner activation remain caller-owned external preconditions.
    No runtime transports, discovery functions or ledger writers are replaced.
    """
    database = await test_db_factory.create_db(suffix="production_logs_receiver")
    keys = {}
    for index, entry in enumerate(json.loads(MANIFEST_PATH.read_bytes())["app_keys"]):
        path = directory / f"logs-key-{index}"
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
        keys[entry["kid"]] = path

    password = directory / "logs-smtp-password"

    def factory(ports):
        return create_app(
            LogsSettings(
                _env_file=None,
                database_url=database.config.get_dsn(),
                db_schema=database.schema,
                app_id="logs-hook-network",
                public_origin=f"https://{name}:{ports[0]}",
                console_origin=f"https://console.{name}:{ports[0]}",
                awid_registry_url=REGISTRY_URL,
                awid_service_token=SERVICE_TOKEN,
                app_key_files=keys,
            ),
            email=EmailSettings.from_env(
                "LOGS_",
                environ={
                    "LOGS_EMAIL_SMTP_HOST": "localhost",
                    "LOGS_EMAIL_SMTP_PORT": str(smtp.port),
                    "LOGS_EMAIL_USERNAME": smtp.username,
                    "LOGS_EMAIL_PASSWORD_FILE": str(password),
                    "LOGS_EMAIL_FROM": "noreply@logs.example.com",
                    "LOGS_EMAIL_CA_FILE": str(smtp.ca_file),
                },
            ),
            awid_transport=registry.transport,
            team_server_transport=transport,
        )

    with SmtpServer(directory / "logs-smtp") as smtp:
        password.write_text(smtp.password)
        password.chmod(0o600)
        async with serving(
            factory, listeners=(Listener(host, 0),), certificates=certificates
        ) as running:
            origin = f"https://{name}:{running.ports[0]}"
            # TLS verifies the listener IP SAN; Host carries the actual app origin.
            async with httpx.AsyncClient(
                verify=ssl.create_default_context(cafile=str(certificates.ca_file)), trust_env=False
            ) as client:
                manifest = await client.get(
                    f"https://{host}:{running.ports[0]}/manifests/v2.json",
                    headers={"Host": f"{name}:{running.ports[0]}"},
                )
                assert manifest.status_code == 200
            yield origin, manifest.content, database
