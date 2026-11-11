"""logs' readers on the app as production composes it (``create_app``): a real
coordination server and AWID, real PostgreSQL, a real TLS SMTP server and a
software passkey.

The team owner designates a human member of the team as a reader by a
human-role act delivered to logs' console origin, binding the reader's
passkey; the reader logs in on the console origin with it and reads its team's
log. A reinstalled logs is a new installation: the old one's readers end with
it, and the owner designates them afresh."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import pytest
from aweb.app_manifests import FetchedManifest
from aweb.installations import install_verified_manifest_on, uninstall_installation_on
from aweb_naapp.css import CSS_SHA256
from aweb_naapp.egress.send import EgressNotSent
from aweb_naapp.email import EmailSettings
from aweb_naapp.hooks.owner_act import HumanCredential
from aweb_naapp.manifest import load_manifest
from aweb_naapp.roles import holding_scope, read_holding
from aweb_naapp.runtime.owner_act_router import OWNER_ACT_PATH
from aweb_naapp_testing import Member
from aweb_naapp_testing.human_members import HumanMember, HumanNamespace, human_namespace
from aweb_naapp_testing.owner_acts import AUDIENCE, TeamOwner
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN

from aweb_logs.app import create_app
from aweb_logs.config import LogsSettings
from aweb_logs.readers import READER_ROLE

from .deployment import TEST_APP_ID, template, write_key_file
from .test_reader_routes import REMOVE_READER_TOOL, blocked_dns

# The deployment answers at the audience the owner's acts name.
ORIGIN = AUDIENCE
CONSOLE = "https://console.app.example.com"


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
    smtp: SmtpServer
    agent: httpx.AsyncClient
    console: httpx.AsyncClient
    looked_up: list[str]
    # The installed manifest: logs' version 3, which declares its reader role.
    manifest: bytes
    server_db: Any
    db: Any
    humans: HumanNamespace
    devices: dict[str, SoftAuthenticator] = field(default_factory=dict)


async def install(server_db, team_id: str, data: bytes) -> dict:
    manifest = load_manifest(data)
    fetched = FetchedManifest(
        origin=ORIGIN,
        url=ORIGIN + f"/manifests/v{manifest.manifest_version}.json",
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
async def deployment(
    request: pytest.FixtureRequest, coordination, test_db_factory, tmp_path
) -> AsyncIterator[Deployment]:
    member = Member(team_id=f"logs-{uuid4().hex[:12]}:readers.example")
    await coordination.add_member(member)
    await coordination.publish_server(member)
    await coordination.connect(member)
    db = await test_db_factory.create_db(suffix="logs_reader_service")
    key_files = {
        entry["kid"]: write_key_file(tmp_path / f"key-{index}")
        for index, entry in enumerate(template()["app_keys"])
    }
    server_db = coordination.server.db.get_manager("aweb")
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
        **getattr(request, "param", {}),
    )
    with blocked_dns() as looked_up, SmtpServer(tmp_path / "smtp") as smtp:
        service = create_app(
            settings,
            email=email_settings(smtp, tmp_path),
            awid_transport=coordination.registry.transport,
            team_server_transport=coordination.server.transport,
            resolver=Unresolved(),
        )
        # Installed at the version 3 logs publishes, as an owner who designates
        # readers pins it.
        manifest = service.api_app.state.runtime.manifest_bytes
        installation = await install(server_db, member.team_id, manifest)
        async with (
            service.api_app.router.lifespan_context(service.api_app),
            human_namespace(coordination.registry, member.team_id.split(":", 1)[1]) as humans,
        ):
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
                    # The owner addresses its human-role acts to the console origin.
                    owner=TeamOwner(
                        team_key=member.team_key,
                        verifier=None,  # type: ignore[arg-type]
                        team_id=member.team_id,
                        audience=CONSOLE,
                    ),
                    installation_id=installation["installation_id"],
                    smtp=smtp,
                    agent=agent,
                    console=human,
                    looked_up=looked_up,
                    manifest=manifest,
                    server_db=server_db,
                    db=db,
                    humans=humans,
                )


async def member_post(deployment: Deployment, path: str, value: dict) -> httpx.Response:
    body = json.dumps(value).encode()
    headers = deployment.member.headers(aud=ORIGIN, method="POST", path=path, body=body)
    return await deployment.agent.post(
        path, content=body, headers={**headers, "Content-Type": "application/json"}
    )


async def human(deployment: Deployment, alias: str) -> HumanMember:
    """A human member of the deployment's team, registered on AWID."""
    return await deployment.humans.register(
        Member(
            team_id=deployment.member.team_id,
            team_key=deployment.member.team_key,
            alias=alias,
            certificate_id=f"cert-{alias}",
        )
    )


async def designate(
    deployment: Deployment, reader: HumanMember, *, installation_id: str | None = None
) -> httpx.Response:
    """The owner designates ``reader`` as a reader of the installation, binding a
    new passkey, by a human-role act delivered to the console origin."""
    installation_id = installation_id or deployment.installation_id
    device = SoftAuthenticator(CONSOLE)
    credential = device.bind(urlsplit(CONSOLE).hostname or "")
    signing, signature = deployment.owner.sign(
        "human-role.designate",
        {
            "app_id": TEST_APP_ID,
            "installation_id": installation_id,
            "role": READER_ROLE,
            "principal": reader.principal,
            "credential_sha256": HumanCredential.parse(credential).sha256,
        },
    )
    certificate = json.dumps(reader.member.certificate()).encode()
    response = await deployment.console.post(
        OWNER_ACT_PATH,
        json={
            "signing": base64.b64encode(signing).decode(),
            "signature": signature,
            "credential": credential,
            "certificate": base64.b64encode(certificate).decode(),
        },
    )
    scope = holding_scope(installation_id, deployment.member.team_id, READER_ROLE, reader.principal)
    deployment.devices[scope] = device
    return response


async def designated_reader(deployment: Deployment, alias: str = "reader") -> str:
    """A human member the owner designated as a reader: its holding's scope."""
    reader = await human(deployment, alias)
    designated = await designate(deployment, reader)
    assert designated.status_code == 200, designated.text
    return holding_scope(
        deployment.installation_id, deployment.member.team_id, READER_ROLE, reader.principal
    )


async def log_in(deployment: Deployment, scope: str) -> httpx.Response:
    """The reader's passkey login on the console origin, for its holding's scope."""
    options = await deployment.console.post("/login/options", json={"scope": scope})
    assert options.status_code == 200, options.text
    return await deployment.console.post(
        "/login", json={"scope": scope, "assertion": deployment.devices[scope].get(options.json())}
    )


async def test_an_owner_designated_reader_logs_in_with_its_bound_passkey_and_reads(
    deployment: Deployment,
):
    scope = await designated_reader(deployment)
    session = await log_in(deployment, scope)
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
    # The owner's act bound the credential: no enrolment follows it.
    assert [e["event_type"] for e in events.json()["events"]] == ["role.designated"]
    assert verified.json()["intact"] is True
    assert deployment.looked_up == []


async def test_the_agent_origin_serves_no_console_route_and_no_owner_act_delivery(
    deployment: Deployment,
):
    for path in (OWNER_ACT_PATH, "/enrolment/options", "/login/options"):
        assert (await deployment.agent.post(path, json={})).status_code == 404, path
    for path in ("/v1/events", "/v1/verify"):
        assert (await deployment.agent.get(path)).status_code == 404, path
    # A reader is designated only through the owner-act delivery.
    response = await deployment.console.post("/readers/designations", json={})
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
        "/logs-viewer/filters.js",
        f"/css/aweb.{CSS_SHA256[:12]}.css",
    ):
        assert (await deployment.console.get(path)).status_code == 200, path
        assert (await deployment.agent.get(path)).status_code == 404, path


@pytest.mark.parametrize("deployment", [{"client_address_header": "X-Real-IP"}], indirect=True)
async def test_the_login_limit_is_kept_per_address_the_proxy_reports(deployment: Deployment):
    scope = await designated_reader(deployment)

    async def login_options(address: str) -> int:
        response = await deployment.console.post(
            "/login/options", json={"scope": scope}, headers={"X-Real-IP": address}
        )
        return response.status_code

    # Both clients reach the app from the proxy's one peer address.
    statuses = [await login_options("198.51.100.7") for _ in range(20)]
    assert statuses[0] == 200 and statuses[-1] == 429
    assert await login_options("198.51.100.8") == 200


async def test_a_member_removes_a_reader_but_never_the_last(deployment: Deployment):
    kept = await designated_reader(deployment, "reader")
    removed = await designated_reader(deployment, "second-reader")
    path = REMOVE_READER_TOOL["path"]

    response = await member_post(deployment, path, {"scope": removed})
    assert response.status_code == 200, response.text
    assert response.json() == {"scope": removed}

    # The removed reader no longer counts: the one kept is the last.
    last = await member_post(deployment, path, {"scope": kept})
    assert (last.status_code, last.json()["detail"]) == (409, "last_reader_protected")
    assert (await log_in(deployment, kept)).status_code == 200
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


@pytest.fixture
def prompt_installation_status(monkeypatch: pytest.MonkeyPatch) -> float:
    """The coordination server lets logs reuse an installation status for one
    second, so logs sees a reinstall promptly; the seconds to wait past it."""
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", "1")
    return 1.1


async def reinstall(deployment: Deployment) -> str:
    """The team uninstalls logs and installs it again: a new installation, whose id it returns."""
    team_id = deployment.member.team_id
    async with deployment.server_db.transaction() as tx:
        current = await tx.fetch_one(
            "SELECT generation FROM {{tables.team_app_installs}} WHERE team_id=$1 AND app_id=$2",
            team_id,
            TEST_APP_ID,
        )
        await uninstall_installation_on(
            tx, team_id=team_id, app_id=TEST_APP_ID, expected_generation=current["generation"]
        )
    return (await install(deployment.server_db, team_id, deployment.manifest))["installation_id"]


async def live_credentials(deployment: Deployment, scope: str) -> int:
    return await deployment.db.fetch_value(
        "SELECT count(*) FROM {{tables.passkey_credentials}} c"
        " JOIN {{tables.passkey_approvers}} a USING (subject)"
        " WHERE a.scope = $1 AND c.revoked_at IS NULL",
        scope,
    )


async def test_a_reinstalled_logs_ends_the_old_readers_and_the_owner_designates_them_afresh(
    prompt_installation_status: float, deployment: Deployment
):
    reader = await human(deployment, "reader")
    assert (await designate(deployment, reader)).status_code == 200
    old = holding_scope(
        deployment.installation_id, deployment.member.team_id, READER_ROLE, reader.principal
    )
    assert (await log_in(deployment, old)).status_code == 200
    assert await live_credentials(deployment, old) == 1

    reinstalled = await reinstall(deployment)
    assert reinstalled != deployment.installation_id
    await asyncio.sleep(prompt_installation_status)

    # Admitting the new installation retires the old one, and its readers end
    # with it, in the same transaction, before the owner's act takes effect.
    designated = await designate(deployment, reader, installation_id=reinstalled)
    assert designated.status_code == 200, designated.text
    assert (
        await read_holding(
            deployment.db,
            installation_id=deployment.installation_id,
            team_id=deployment.member.team_id,
            role=READER_ROLE,
            principal=reader.principal,
        )
        is None
    )
    assert await live_credentials(deployment, old) == 0
    assert (await deployment.console.get("/v1/events")).status_code == 401

    new = holding_scope(reinstalled, deployment.member.team_id, READER_ROLE, reader.principal)
    assert (await log_in(deployment, new)).status_code == 200
    assert (await deployment.console.get("/v1/events")).status_code == 200
