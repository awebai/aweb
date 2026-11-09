"""logs' readers on the app as production composes it (``create_app``): a real
coordination server and AWID, real PostgreSQL, a real TLS SMTP server and a
software passkey.

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
from aweb_naapp.css import CSS_SHA256
from aweb_naapp.egress import AddressPolicy, Egress
from aweb_naapp.egress.send import EgressNotSent
from aweb_naapp.email import EmailSettings
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp_testing import Member
from aweb_naapp_testing.owner_acts import AUDIENCE, TeamOwner
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN

from aweb_logs.app import create_app
from aweb_logs.config import LogsSettings
from aweb_logs.readers import ReaderDirectory

from .deployment import TEST_APP_ID, served_manifest, template, write_key_file
from .reader_world import act_body
from .test_reader_routes import READER_SLOT_TOOL, REMOVE_READER_TOOL, blocked_dns

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


class Elements(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def first(self, tag: str, **attrs: str) -> dict[str, str | None]:
        return next(
            found
            for name, found in self.tags
            if name == tag and all(found.get(k) == v for k, v in attrs.items())
        )


@dataclass
class Deployment:
    member: Member
    owner: TeamOwner
    installation_id: str
    directory: ReaderDirectory
    smtp: SmtpServer
    agent: httpx.AsyncClient
    console: httpx.AsyncClient
    looked_up: list[str]


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


def email_settings(smtp: SmtpServer, directory: Path) -> EmailSettings:
    password = directory / "smtp-password"
    password.write_text(smtp.password)
    password.chmod(0o600)
    return EmailSettings.from_env(
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


@pytest.fixture
async def deployment(coordination, test_db_factory, tmp_path) -> AsyncIterator[Deployment]:
    member = Member(team_id=f"logs-{uuid4().hex[:12]}:readers.example")
    await coordination.add_member(member)
    await coordination.publish_server(member)
    await coordination.connect(member)
    db = await test_db_factory.create_db(suffix="logs_reader_service")
    key_files = {
        entry["kid"]: write_key_file(tmp_path / f"key-{index}")
        for index, entry in enumerate(template()["app_keys"])
    }
    installation = await install(
        coordination.server.db.get_manager("aweb"),
        member.team_id,
        served_manifest(key_files, origin=ORIGIN),
    )
    settings = LogsSettings(
        _env_file=None,
        database_url=db.config.get_dsn(),
        db_schema=db.schema or "public",
        app_id=TEST_APP_ID,
        public_origin=ORIGIN,
        console_origin=CONSOLE,
        awid_registry_url=REGISTRY_URL,
        awid_service_token=SERVICE_TOKEN,
        app_key_files=key_files,
    )
    with blocked_dns() as looked_up, SmtpServer(tmp_path / "smtp") as smtp:
        service = create_app(
            settings,
            email=email_settings(smtp, tmp_path),
            awid_transport=coordination.registry.transport,
            team_server_transport=coordination.server.transport,
            hook_egress=Egress(addresses=AddressPolicy(), resolver=Unresolved(), user_agent="logs"),
        )
        async with service.api_app.router.lifespan_context(service.api_app):
            async with (
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=service), base_url=ORIGIN
                ) as agent,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=service), base_url=CONSOLE
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
                    directory=ReaderDirectory(db),
                    smtp=smtp,
                    agent=agent,
                    console=human,
                    looked_up=looked_up,
                )


async def member_post(deployment: Deployment, path: str, value: dict) -> httpx.Response:
    body = json.dumps(value).encode()
    headers = deployment.member.headers(aud=ORIGIN, method="POST", path=path, body=body)
    return await deployment.agent.post(
        path, content=body, headers={**headers, "Content-Type": "application/json"}
    )


async def reader_slot(deployment: Deployment, contact: str = CONTACT) -> str:
    response = await member_post(
        deployment, READER_SLOT_TOOL["path"], {"contact_sha256": contact_sha256(contact)}
    )
    assert response.status_code == 200, response.text
    return response.json()["scope"]


async def designated_reader(deployment: Deployment, contact: str) -> str:
    """A reader the owner designated at ``contact``, by the deployment's routes."""
    scope = await reader_slot(deployment, contact)
    signing, signature = deployment.owner.sign(
        "app-role.designate",
        {
            "app_id": TEST_APP_ID,
            "installation_id": deployment.installation_id,
            "role": scope,
            "contact_sha256": contact_sha256(contact),
        },
    )
    designated = await deployment.console.post(
        "/readers/designations",
        json=act_body(signing, signature, scope=scope, contact=contact),
    )
    assert designated.status_code == 200, designated.text
    return scope


def enrolment_token(deployment: Deployment, contact: str = CONTACT) -> str:
    [received] = [mail for mail in deployment.smtp.received if mail.rcpt_tos == [contact]]
    message = email.message_from_bytes(received.content, policy=email.policy.default)
    body = message.get_body(("html",))
    assert body is not None
    [url] = Links(body.get_content()).urls
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

    home = await deployment.console.get("/")
    assert home.status_code == 200, home.text
    scoped = [attrs for tag, attrs in Elements(home.text).tags if "data-console-scope" in attrs]
    assert [attrs["data-console-scope"] for attrs in scoped] == [scope]

    assert {"/events", "/follow", "/integrity"} <= set(Links(home.text).urls)
    for page in ("/events", "/follow", "/integrity"):
        viewed = await deployment.console.get(page)
        assert viewed.status_code == 200, page
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


async def test_the_console_origin_serves_logs_pages_and_the_shell_assets_only_there(
    deployment: Deployment,
):
    for path in ("/login", "/enrolment", "/contact-proof"):
        response = await deployment.console.get(path)
        assert response.status_code == 200, path
        body = Elements(response.text).first("body")
        assert body["data-console-csrf-key"] == "aweb.logs.console.csrf", path
    for path in ("/", "/events", "/follow", "/integrity"):
        anonymous = await deployment.console.get(path)
        assert (anonymous.status_code, anonymous.headers["location"]) == (303, "/login"), path
        assert (await deployment.agent.get(path)).status_code == 404, path
    for path in (
        "/console-ui/console.js",
        "/console-ui/style.css",
        "/console-bootstrap/bootstrap.js",
        "/console-bootstrap/style.css",
        "/logs-viewer/follow.js",
        f"/css/aweb.{CSS_SHA256[:12]}.css",
    ):
        assert (await deployment.console.get(path)).status_code == 200, path
        assert (await deployment.agent.get(path)).status_code == 404, path


async def enrolled_reader(deployment: Deployment, contact: str) -> str:
    """A designated reader that enrolled its passkey from the link it was mailed."""
    scope = await designated_reader(deployment, contact)
    token = enrolment_token(deployment, contact)
    device = SoftAuthenticator(CONSOLE)
    options = await deployment.console.post("/enrolment/options", json={"link_token": token})
    enrolled = await deployment.console.post(
        "/enrolment", json={"link_token": token, "credential": device.create(options.json())}
    )
    assert enrolled.json() == {"scope": scope}
    return scope


async def test_a_member_removes_a_reader_but_never_the_last(deployment: Deployment):
    kept = await enrolled_reader(deployment, CONTACT)
    removed = await enrolled_reader(deployment, "second-reader@example.com")
    path = REMOVE_READER_TOOL["path"]

    response = await member_post(deployment, path, {"scope": removed})
    assert response.status_code == 200, response.text
    assert response.json() == {"scope": removed}
    current = await deployment.directory.current_readers(
        installation_id=deployment.installation_id, team_id=deployment.member.team_id
    )
    assert [reader.scope for reader in current] == [kept]

    last = await member_post(deployment, path, {"scope": kept})
    assert (last.status_code, last.json()["detail"]) == (409, "last_reader_protected")
    gone = await member_post(deployment, path, {"scope": removed})
    assert (gone.status_code, gone.json()["detail"]) == (404, "reader_unknown")
    assert deployment.looked_up == []


@pytest.mark.parametrize(
    "body", [{}, {"scope": 7}, {"scope": "x", "extra": 1}], ids=["empty", "number", "extra"]
)
async def test_a_malformed_removal_is_refused_without_echo(deployment: Deployment, body):
    response = await member_post(deployment, REMOVE_READER_TOOL["path"], body)
    assert (response.status_code, response.json()) == (400, {"detail": "request_invalid"})


async def test_the_console_origin_serves_no_reader_removal(deployment: Deployment):
    response = await deployment.console.post(REMOVE_READER_TOOL["path"], json={"scope": "x"})
    assert response.status_code == 404
