"""logs' reader service composed on a real runtime: a real coordination server
and AWID, real PostgreSQL, a real TLS SMTP server and a software passkey.

A member granted ``logs.readers`` asks for a reader slot, the team owner
designates a contact for it, the reader enrols from the link it receives by
mail, logs in on the console origin and reads its team's log."""

from __future__ import annotations

import email
import email.policy
import hashlib
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from aweb.app_manifests import FetchedManifest
from aweb.installations import install_verified_manifest_on
from aweb_naapp.egress import AddressPolicy, Egress
from aweb_naapp.egress.send import EgressNotSent
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp.runtime.passkeys.email import PasskeyEmailDelivery
from aweb_naapp_testing import Member
from aweb_naapp_testing.owner_acts import AUDIENCE, TeamOwner
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import FastAPI

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.app import chain_signer
from aweb_logs.config import LogsSettings
from aweb_logs.reader_service import ReaderService, reader_service

from .deployment import TEST_APP_ID, served_manifest, template, write_key_file
from .reader_world import act_body
from .test_reader_routes import READER_SLOT_TOOL, blocked_dns

# The deployment answers at the audience the owner's acts name.
ORIGIN = AUDIENCE
CONSOLE = "https://console.app.example.com"
CONTACT = "reader@example.com"


class Unresolved:
    """The hook drain's resolver: no host resolves, and every attempt is kept."""

    def __init__(self) -> None:
        self.hosts: list[str] = []

    async def resolve(self, host: str) -> list[Any]:
        self.hosts.append(host)
        raise EgressNotSent(f"{host} is not resolved in this test")


class Links(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.urls.extend(value for key, value in attrs if key == "href")


@dataclass
class Deployment:
    member: Member
    owner: TeamOwner
    installation_id: str
    service: ReaderService
    smtp: SmtpServer
    agent: httpx.AsyncClient
    console: httpx.AsyncClient
    looked_up: list[str]


def manifest_template() -> dict[str, Any]:
    manifest = template()
    manifest["app_keys"] += [
        {"kid": "logs-grants", "purposes": ["app-grant-read"]},
        {"kid": "logs-governance", "purposes": ["hook-event"]},
    ]
    manifest["tools"].append(READER_SLOT_TOOL)
    manifest["hooks"]["productions"] = [
        {"catalog": {"id": "aweb.hooks", "version": 1}, "hook": "post-governance-hook", "reads": []}
    ]
    return manifest


async def install(server_db, team_id: str, data: bytes) -> dict:
    manifest = load_manifest(data)
    fetched = FetchedManifest(
        origin=ORIGIN,
        url=ORIGIN + "/.well-known/aweb-app.json",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        data=data,
        manifest=manifest,
    )
    async with server_db.transaction() as tx:
        installation = await install_verified_manifest_on(
            tx, team_id=team_id, fetched=fetched, granted_scopes=["logs.readers"]
        )
    now = datetime.now(UTC)
    await server_db.execute(
        "UPDATE {{tables.app_hook_bindings}} SET state='active',"
        " activated_at=$2::timestamptz - INTERVAL '60 seconds', active_from=$2,"
        " activation_act_sha256=$3 WHERE team_id=$1",
        team_id,
        now - timedelta(minutes=1),
        "ab" * 32,
    )
    return installation


def mailer(smtp: SmtpServer, directory: Path) -> Mailer:
    password = directory / "smtp-password"
    password.write_text(smtp.password)
    password.chmod(0o600)
    return Mailer(
        EmailSettings.from_env(
            "LOGS_",
            environ={
                "LOGS_EMAIL_SMTP_HOST": "localhost",
                "LOGS_EMAIL_SMTP_PORT": str(smtp.port),
                "LOGS_EMAIL_USERNAME": smtp.username,
                "LOGS_EMAIL_PASSWORD_FILE": str(password),
                "LOGS_EMAIL_FROM": "noreply@logs.example.com",
                "LOGS_EMAIL_CA_FILE": str(smtp.ca_file),
            },
        )
    )


async def admit_members(request: Any, principal: Any, tool: Any) -> bool:
    return True


@pytest.fixture
async def deployment(coordination, test_db_factory, tmp_path) -> AsyncIterator[Deployment]:
    member = Member(team_id=f"logs-{uuid4().hex[:12]}:readers.example")
    await coordination.add_member(member)
    await coordination.publish_server(member)
    await coordination.connect(member)
    db = await test_db_factory.create_db(suffix="logs_reader_service")
    manifest = manifest_template()
    key_files = {
        entry["kid"]: write_key_file(tmp_path / f"key-{index}")
        for index, entry in enumerate(manifest["app_keys"])
    }
    manifest_path = tmp_path / "aweb-app.json"
    manifest_path.write_text(json.dumps(manifest))
    installation = await install(
        coordination.server.db.get_manager("aweb"),
        member.team_id,
        served_manifest(key_files, origin=ORIGIN, manifest=manifest),
    )
    settings = LogsSettings(
        _env_file=None,
        database_url=db.config.get_dsn(),
        db_schema=db.schema or "public",
        app_id=TEST_APP_ID,
        public_origin=ORIGIN,
        awid_registry_url=REGISTRY_URL,
        awid_service_token=SERVICE_TOKEN,
        app_key_files=key_files,
    )
    runtime = NaappRuntime(
        settings,
        module_name=MIGRATIONS_MODULE,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=manifest_path,
        awid_transport=coordination.registry.transport,
        team_server_transport=coordination.server.transport,
        hook_egress=Egress(addresses=AddressPolicy(), resolver=Unresolved(), user_agent="logs"),
    )
    api, console = FastAPI(), FastAPI()
    with blocked_dns() as looked_up, SmtpServer(tmp_path / "smtp") as smtp:
        async with runtime.lifespan(api):
            service = await reader_service(
                runtime,
                signer=chain_signer(settings, runtime.manifest),
                console_origin=CONSOLE,
                delivery=PasskeyEmailDelivery(
                    mailer=mailer(smtp, tmp_path),
                    console_origin=CONSOLE,
                    product="Logs",
                    link_text="Open Logs",
                ),
                backlog_age=timedelta(minutes=5),
            )
            api.include_router(
                service.agent_router(
                    runtime.authorized(grants=runtime.installation_grants(), policy=admit_members)
                )
            )
            console.include_router(service.console_router)
            app = split_origins(api, console, agent_origin=ORIGIN, human_origin=CONSOLE)
            async with (
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as agent,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url=CONSOLE
                ) as human,
            ):
                yield Deployment(
                    member=member,
                    owner=TeamOwner(
                        team_key=member.team_key,
                        verifier=None,  # type: ignore[arg-type]
                        team_id=member.team_id,
                    ),
                    installation_id=installation["installation_id"],
                    service=service,
                    smtp=smtp,
                    agent=agent,
                    console=human,
                    looked_up=looked_up,
                )


async def reader_slot(deployment: Deployment) -> str:
    body = json.dumps({"contact_sha256": contact_sha256(CONTACT)}).encode()
    headers = deployment.member.headers(
        aud=ORIGIN, method="POST", path=READER_SLOT_TOOL["path"], body=body
    )
    response = await deployment.agent.post(
        READER_SLOT_TOOL["path"],
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text
    return response.json()["scope"]


def enrolment_token(deployment: Deployment) -> str:
    [received] = deployment.smtp.received
    assert received.rcpt_tos == [CONTACT]
    message = email.message_from_bytes(received.content, policy=email.policy.default)
    [url] = Links(message.get_body(("html",)).get_content()).urls
    parts = urlsplit(url)
    assert parts._replace(fragment="").geturl() == CONSOLE + "/enrolment"
    [token] = parse_qs(parts.fragment)["token"]
    return token


async def test_a_designated_reader_enrols_from_its_mail_logs_in_and_reads(
    deployment: Deployment,
):
    scope = await reader_slot(deployment)
    signing, signature = deployment.owner.sign(
        "app-role.designate",
        {
            "app_id": TEST_APP_ID,
            "installation_id": deployment.installation_id,
            "role": scope,
            "contact_sha256": contact_sha256(CONTACT),
        },
    )
    designated = await deployment.console.post(
        "/readers/designations",
        json=act_body(signing, signature, scope=scope, contact=CONTACT),
    )
    assert designated.status_code == 200, designated.text

    token = enrolment_token(deployment)
    device = SoftAuthenticator(CONSOLE)
    options = await deployment.console.post("/enrolment/options", json={"link_token": token})
    assert options.status_code == 200, options.text
    enrolled = await deployment.console.post(
        "/enrolment", json={"link_token": token, "credential": device.create(options.json())}
    )
    assert enrolled.json() == {"scope": scope}

    login = await deployment.console.post("/login/options", json={"scope": scope})
    assert login.status_code == 200, login.text
    session = await deployment.console.post(
        "/login", json={"scope": scope, "assertion": device.get(login.json())}
    )
    assert session.status_code == 200, session.text

    events = await deployment.console.get("/v1/events")
    verified = await deployment.console.get("/v1/verify")
    assert events.status_code == 200, events.text
    assert [e["event_type"] for e in events.json()["events"]] == [
        "credential.enrolled",
        "role.designated",
    ]
    assert verified.json()["intact"] is True
    assert deployment.looked_up == []


async def test_the_agent_origin_serves_no_console_route_and_the_console_no_reader_slot(
    deployment: Deployment,
):
    for path in ("/readers/designations", "/enrolment/options", "/login/options"):
        assert (await deployment.agent.post(path, json={})).status_code == 404, path
    for path in ("/v1/events", "/v1/verify"):
        assert (await deployment.agent.get(path)).status_code == 404, path
    response = await deployment.console.post(
        READER_SLOT_TOOL["path"], json={"contact_sha256": contact_sha256(CONTACT)}
    )
    assert response.status_code == 404
